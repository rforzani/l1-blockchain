//src/chain.rs

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::codec::{header_bytes, header_signing_bytes, qc_commitment};
use crate::crypto::vrf::{build_vrf_msg, vrf_eligible, SchnorrkelVrf, VrfPubkey, VrfVerifier};
use crate::crypto::{addr_from_pubkey, addr_hex, hash_bytes_sha256, verify_ed25519};
use crate::crypto::bls::verify_qc;
use crate::fees::{update_commit_base, update_exec_base, FeeState, FEE_PARAMS};
use crate::pos::registry::{StakingConfig, ValidatorSet, ValidatorStatus, ValidatorId};
use crate::pos::schedule::{AliasSchedule, ProposerSchedule};
use crate::pos::slots::SlotClock;
use crate::stf::{process_block, BlockError};
use crate::mempool::{BatchStore, ThresholdEngine};
use crate::state::{Available, Balances, Commitments, Nonces, DECRYPTION_DELAY, REVEAL_WINDOW};
use crate::types::{Block, BlockHeader, Event, Hash, Receipt};
use crate::verify::verify_block_roots;
use std::collections::{HashMap, HashSet, BTreeMap};
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_SLOT_MS: u64 = 1_000;     // 1s slots for dev;
const DEFAULT_EPOCH_SLOTS: u64 = 1_024; // power-of-two for easy math
pub const DEFAULT_BUNDLE_LEN: u8 = 4;
pub const DEFAULT_TAU: f64 = 0.5;

pub struct Chain {
    pub tip_hash: Hash,
    pub height: u64,
    pub fee_state: FeeState,
    pub burned_total: u64,
    commit_included_at: HashMap<Hash, u64>,
    avail_included: HashSet<Hash>,
    avail_due: BTreeMap<u64, Vec<Hash>>,
    commit_deadline: HashMap<Hash, u64>,
    pub clock: SlotClock,
    pub epoch_seed: [u8; 32],
    pub validator_set: ValidatorSet,
    pub schedule: AliasSchedule,
    pub epoch_accumulator: [u8; 32],
    pub batch_store: BatchStore,
    /// VRF tie-break cache: maps bundle_start to (proposer_id, vrf_output)
    bundle_winners: HashMap<u64, (ValidatorId, [u8; 32])>,
    pub tau: f64,
    /// Threshold encryption engine for decrypting committed transactions
    pub threshold_engine: ThresholdEngine,
    /// Pending threshold shares by commitment hash
    pending_shares: HashMap<Hash, Vec<crate::mempool::encrypted::ThresholdShare>>,
}

#[derive(Clone)]
pub struct ApplyResult {
    pub receipts: Vec<Receipt>,
    pub gas_total: u64,
    pub events: Vec<Event>,
    pub exec_reveals_used: u32,
    pub commits_used: u32,
    pub burned_total: u64,
}

impl Chain {
    pub fn new() -> Self {
        // 1) Clock: deterministic start at unix 0 keeps tests stable.
        let clock = SlotClock {
            genesis_unix_ms: 0,
            slot_ms: DEFAULT_SLOT_MS,
            epoch_slots: DEFAULT_EPOCH_SLOTS,
        };

        // 2) Epoch seed: real, deterministic seed (no randomness-in-codepath).
        let epoch_seed = {
            // bind to a fixed, namespaced tag so it can’t collide accidentally
            hash_bytes_sha256(b"l1-blockchain/epoch-seed:genesis")
        };

        // 3) Empty validator set at epoch 0 (no proposers yet).
        let staking_cfg = StakingConfig {
            min_stake: 1,              // cannot activate with 0
            unbonding_epochs: 1,       // safe baseline
            max_validators: u32::MAX,  // no cap until governance sets one
        };
        let validator_set = ValidatorSet::from_genesis(0, &staking_cfg, Vec::new());

        // 4) Prebuild alias schedule for epoch 0 with the current (empty) set.
        let mut schedule = AliasSchedule { epoch: 0, epoch_slots: DEFAULT_EPOCH_SLOTS, leaders: Vec::new() };
        schedule.rebuild(0, DEFAULT_EPOCH_SLOTS, &validator_set, epoch_seed);

        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(b"l1-blockchain/epoch-accum/start:v1");
        buf.extend_from_slice(&epoch_seed);
        let epoch_accumulator = hash_bytes_sha256(&buf);

        // 5) Return fully initialized Chain (PoS fields included)
        Self {
            tip_hash: [0u8; 32],
            height: 0,
            fee_state: FeeState::from_defaults(),
            burned_total: 0,
            commit_included_at: HashMap::new(),
            avail_included: HashSet::new(),
            avail_due: BTreeMap::new(),
            commit_deadline: HashMap::new(),
            clock,
            epoch_seed,
            validator_set,
            schedule,
            epoch_accumulator,
            batch_store: BatchStore::new(),
            bundle_winners: HashMap::new(),
            tau: DEFAULT_TAU,
            threshold_engine: ThresholdEngine::new(),
            pending_shares: HashMap::new(),
        }
    }

    pub fn now_ts(&self) -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    }

    pub fn current_slot_at(&self, now_ms: u128) -> u64 {
        self.clock.current_slot(now_ms)
    }


    pub fn current_slot(&self) -> u64 {
        self.current_slot_at(self.now_ts())
    }

    /// Install the initial validator set and seed at genesis.
    /// Must be called before the first block (height == 0) and only once in production.
    pub fn init_genesis(&mut self, set: ValidatorSet, seed: [u8; 32]) {
        // Ensure we're truly at genesis and not re-initializing.
        assert!(
            self.height == 0,
            "init_genesis: height must be 0 (got {})", self.height
        );
        assert!(
            self.validator_set.validators.is_empty()
                && self.validator_set.total_stake == 0
                && self.validator_set.epoch == 0,
            "init_genesis: validator set already initialized"
        );
        // The provided set can be any epoch (commonly 0). No “must advance” check here.
        self.validator_set = set;
        self.epoch_seed = seed;

        // Build the proposer schedule for the provided epoch.
        let epoch_slots = self.clock.epoch_slots;
        self.schedule
            .rebuild(self.validator_set.epoch, epoch_slots, &self.validator_set, self.epoch_seed);

        // Initialize the per-epoch accumulator deterministically.
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(b"l1-blockchain/epoch-accum/start:v1");
        buf.extend_from_slice(&self.epoch_seed);
        self.epoch_accumulator = hash_bytes_sha256(&buf);
    }

    pub fn verify_header_proposer(&mut self, header: &crate::types::BlockHeader) -> Result<(), BlockError> {
        // 1) Height/slot policy: strictly the next block (adjust if your policy differs)
        if header.height != self.height + 1 {
            return Err(BlockError::WrongSlot);
        }
    
        // 2) Epoch must match the clock for the given slot
        let expected_epoch = self.clock.current_epoch(header.slot);
        if header.epoch != expected_epoch {
            return Err(BlockError::WrongEpoch);
        }
    
        // 3) (Dev policy) enforce slot == height; relax/remove if you allow gaps
        let expected_slot = header.height;
        if header.slot != expected_slot {
            return Err(BlockError::WrongSlot);
        }
    
        // 4) Proposer must exist and be Active
        let v = match self.validator_set.get(header.proposer_id) {
            Some(v) => v,
            None => return Err(BlockError::NotScheduledLeader),
        };
        if v.status != crate::pos::registry::ValidatorStatus::Active {
            return Err(BlockError::NotScheduledLeader);
        }
    
        // (a) Sanity on bundle_len (enforce your configured default)
        let r = header.bundle_len;
        if r == 0 || r != DEFAULT_BUNDLE_LEN {
            return Err(BlockError::WrongSlot);
        }

        // (b) Recompute bundle_start deterministically
        let bundle_start = self.clock.bundle_start(header.slot, r);

        if header.vrf_proof.is_empty() {
            // VRF path produced no winner; fall back to alias schedule.
            let expected = self
                .schedule
                .fallback_leader_for_bundle(bundle_start)
                .ok_or(BlockError::NotScheduledLeader)?;
            if header.proposer_id != expected {
                return Err(BlockError::NotScheduledLeader);
            }
        } else {
            // (c) Build VRF message (must match Node exactly)
            let msg = build_vrf_msg(&self.epoch_seed, bundle_start, header.proposer_id);

            // (d) Verify VRF proof against the validator's VRF public key
            if !SchnorrkelVrf::vrf_verify(
                &VrfPubkey(v.vrf_pubkey),
                &msg,
                &header.vrf_output,
                &header.vrf_preout,
                &header.vrf_proof,
            ) {
                return Err(BlockError::BadSignature); // or BadVrf if you distinguish
            }

            // (e) Stake-weighted threshold check using shared helper
            let total = self.validator_set.total_stake();
            if !vrf_eligible(v.stake, total, &header.vrf_output, self.tau) {
                // Not eligible this bundle → reject
                return Err(BlockError::NotScheduledLeader);
            }

            // (f) Tie-break if multiple VRF winners exist for this bundle.
            self.bundle_winners.retain(|&k, _| k >= bundle_start);
            match self.bundle_winners.get(&bundle_start) {
                Some((winner_id, winner_out)) => {
                    if &header.vrf_output < winner_out {
                        self.bundle_winners
                            .insert(bundle_start, (header.proposer_id, header.vrf_output));
                    } else if &header.vrf_output == winner_out && header.proposer_id == *winner_id {
                        // same winner; OK
                    } else {
                        return Err(BlockError::NotScheduledLeader);
                    }
                }
                None => {
                    self.bundle_winners
                        .insert(bundle_start, (header.proposer_id, header.vrf_output));
                }
            }
        }
    
        // 6) Verify the ed25519 header signature (over the UPDATED preimage with Vortex fields)
        let preimage = crate::codec::header_signing_bytes(header);
        let vk = VerifyingKey::from_bytes(&v.ed25519_pubkey)
            .map_err(|_| BlockError::BadSignature)?;
        let sig = Signature::from_bytes(&header.signature);
        vk.verify(&preimage, &sig).map_err(|_| BlockError::BadSignature)?;
    
        Ok(())
    }
    
    /// Advance the chain to a new epoch with a new validator snapshot and epoch seed.
    /// Rebuilds the alias schedule deterministically for the new epoch and resets the
    /// per-epoch randomness accumulator.
    pub fn on_epoch_transition(&mut self, new_set: ValidatorSet, new_seed: [u8; 32]) {
        // Sanity: epochs must advance monotonically by at least 1.
        let prev_epoch = self.validator_set.epoch;
        assert!(
            new_set.epoch >= prev_epoch + 1,
            "on_epoch_transition: epoch must advance (got {}, prev {})",
            new_set.epoch,
            prev_epoch
        );

        // Install the new validator set and seed.
        self.validator_set = new_set;
        self.epoch_seed = new_seed;

        // Rebuild the proposer schedule for the new epoch.
        // Note: schedule is epoch-local; global slot → leader lookup uses modulo epoch_slots.
        let epoch_slots = self.clock.epoch_slots;
        self.schedule
            .rebuild(self.validator_set.epoch, epoch_slots, &self.validator_set, self.epoch_seed);

        // Reset the per-epoch accumulator (used to derive the NEXT epoch seed).
        // Domain-separated to avoid cross-protocol collisions.
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(b"l1-blockchain/epoch-accum/start:v1");
        buf.extend_from_slice(&self.epoch_seed);
        self.epoch_accumulator = hash_bytes_sha256(&buf);
    }

    /// Derive the next epoch's seed from the current epoch's seed and its final accumulator.
    /// This is called at the epoch boundary, after processing the last block of the epoch.
    /// The accumulator should have been updated via `update_randomness_with_block` each block.
    pub fn next_epoch_seed(&self, last_epoch_accumulator: [u8; 32]) -> [u8; 32] {
        // Mix in a few stable, ungameable values to prevent seed grinding:
        //  - previous epoch seed (binds continuity)
        //  - last epoch accumulator (binds to block/reveal outcomes)
        //  - tip_hash and height (chain state commitment)
        // Domain-separated label ensures uniqueness across uses.
        let mut buf = Vec::with_capacity(1 + 32 + 32 + 32 + 8);
        buf.extend_from_slice(b"l1-blockchain/epoch-seed/derive:v1");
        buf.extend_from_slice(&self.epoch_seed);
        buf.extend_from_slice(&last_epoch_accumulator);
        buf.extend_from_slice(&self.tip_hash);
        buf.extend_from_slice(&self.height.to_le_bytes());
        hash_bytes_sha256(&buf)
    }

    /// Update the per-epoch randomness accumulator with data from the newly applied block header.
    /// Call this *after* a block is verified/applied. The accumulator is later used to derive
    /// the next epoch’s seed via `next_epoch_seed`.
    pub fn update_randomness_with_block(&mut self, header: &crate::types::BlockHeader) {
        // Mix multiple header commitments to reduce manipulatability:
        //  - previous accumulator (chaining)
        //  - reveal_set_root (commit–reveal outcomes)
        //  - header.randomness (your per-block randomness input)
        //  - txs_root and receipts_root (binds to executed contents)
        //  - il_root (inclusion list / ordering constraint commitment)
        //  - (optionally) gas_used and base fees to bind fee schedule evolution
        let mut buf = Vec::with_capacity(1 + 32 * 6 + 8 * 4);
        buf.extend_from_slice(b"l1-blockchain/epoch-accum/update:v1");
        buf.extend_from_slice(&self.epoch_accumulator);
        buf.extend_from_slice(&header.reveal_set_root);
        buf.extend_from_slice(&header.randomness);
        buf.extend_from_slice(&header.txs_root);
        buf.extend_from_slice(&header.receipts_root);
        buf.extend_from_slice(&header.il_root);

        // Lightly bind fee evolution and gas tally to the accumulator (opaque to adversaries).
        buf.extend_from_slice(&header.gas_used.to_le_bytes());
        buf.extend_from_slice(&header.exec_base_fee.to_le_bytes());
        buf.extend_from_slice(&header.commit_base_fee.to_le_bytes());
        buf.extend_from_slice(&header.avail_base_fee.to_le_bytes());

        self.epoch_accumulator = hash_bytes_sha256(&buf);
    }

    pub fn apply_block(
        &mut self,
        block: &Block,
        balances: &mut Balances,
        nonces: &mut Nonces,
        commitments: &mut Commitments,
        available: &mut Available,
    ) -> Result<ApplyResult, BlockError> {
        // basic height check
        if block.header.height != self.height + 1 {
            return Err(BlockError::BadHeight {
                expected: self.height + 1,
                got: block.header.height,
            });
        }

        // Parent guard: the block we just built must link to our tip
        if block.header.parent_hash != self.tip_hash {
            return Err(BlockError::HeaderMismatch(
                format!(
                    "parent mismatch: expected {}, got {}",
                    hex::encode(self.tip_hash),
                    hex::encode(block.header.parent_hash),
                )
            ));
        }

        // Signature verification via validator set
        let v = self
            .validator_set
            .get(block.header.proposer_id)
            .ok_or(BlockError::NotScheduledLeader)?;
        let preimage = header_signing_bytes(&block.header);
        let ok = verify_ed25519(&v.ed25519_pubkey, &block.header.signature, &preimage);
        if !ok {
            return Err(BlockError::IntrinsicInvalid("bad block signature".into()));
        }

        // QC verification: all active validators must have BLS keys
        let active_bls_pks = self.collect_active_bls_pubkeys()?;
        let computed_qc_hash = qc_commitment(
            block.justify_qc.view,
            &block.justify_qc.block_id,
            &block.justify_qc.agg_sig,
            &block.justify_qc.bitmap,
        );

        // Check that justify_qc_hash in header matches computed QC commitment
        if block.header.justify_qc_hash != computed_qc_hash {
            return Err(BlockError::IntrinsicInvalid(
                "justify_qc_hash mismatch".into()
            ));
        }

        // Verify the QC BLS signature against active validator keys
        verify_qc(
            &block.justify_qc.block_id,
            block.justify_qc.view,
            &block.justify_qc.agg_sig,
            &block.justify_qc.bitmap,
            &active_bls_pks,
        ).map_err(|_| BlockError::IntrinsicInvalid("QC signature verification failed".into()))?;

        let mut sim_balances = balances.clone();
        let mut sim_nonces = nonces.clone();
        let mut sim_commitments = commitments.clone();
        let mut sim_available = available.clone();

        let proposer_addr = addr_hex(&addr_from_pubkey(&v.ed25519_pubkey));

        // process with current tip as parent
        let mut sim_burned_total = self.burned_total;
        let res = process_block(
            block,
            &self.batch_store,
            &mut sim_balances,
            &mut sim_nonces,
            &mut sim_commitments,
            &mut sim_available,
            &self.fee_state,
            &proposer_addr,
            &mut sim_burned_total,
            &self.threshold_engine,
            self,
        )?;

        verify_block_roots(&block.header, block, &self.batch_store, &res.receipts)
            .map_err(BlockError::RootMismatch)?;

        *balances = sim_balances;
        *nonces = sim_nonces;
        *commitments = sim_commitments;
        *available = sim_available;
        self.burned_total = sim_burned_total;

        for ev in &res.events {
            match ev {
                Event::CommitStored { commitment, .. } => {
                    self.commit_included_at.insert(*commitment, block.header.height);
                }
                Event::AvailabilityRecorded { commitment } => {
                    if let Some(&inc) = self.commit_included_at.get(commitment) {
                        let ready_at = inc + DECRYPTION_DELAY;
                        let deadline = ready_at + REVEAL_WINDOW;
                        self.avail_included.insert(*commitment);
                        self.commit_deadline.insert(*commitment, deadline);
                        self.avail_due.entry(deadline).or_default().push(*commitment);
                    }
                }
                Event::CommitConsumed { commitment } | Event::CommitExpired { commitment } => {
                    if let Some(deadline) = self.commit_deadline.remove(commitment) {
                        if let Some(vec) = self.avail_due.get_mut(&deadline) {
                            vec.retain(|c| c != commitment);
                            if vec.is_empty() {
                                self.avail_due.remove(&deadline);
                            }
                        }
                    }
                }
                Event::ThresholdShareReceived { commitment, validator_id: _ } => {
                    // Handle threshold share received - could trigger decryption attempts
                    // For now, just log or track the event
                }
                Event::ThresholdDecryptionComplete { commitment: _ } => {
                    // Handle completed threshold decryption
                    // This could trigger reveal processing or other consensus actions
                }
            }
        }

        let next_exec = update_exec_base(
            self.fee_state.exec_base,
            res.exec_reveals_used,
            FEE_PARAMS.exec_target_reveals_per_block,
            FEE_PARAMS.exec_max_change_denominator,
            FEE_PARAMS.exec_min_base,
            FEE_PARAMS.exec_damping_bps,
        );

        // 3) update self state
        self.tip_hash = hash_bytes_sha256(&header_bytes(&block.header));
        self.height = block.header.height;
        self.fee_state.exec_base = next_exec;
        self.fee_state.commit_base = update_commit_base(
            self.fee_state.commit_base,
            res.commits_used,
        );
        Ok(ApplyResult { receipts: res.receipts, gas_total: res.gas_total, events: res.events, exec_reveals_used: res.exec_reveals_used, commits_used: res.commits_used, burned_total: self.burned_total })
    }

    pub fn commit_simulated_block(
        &mut self,
        block: &Block,
        apply: ApplyResult,
        _balances: Balances,
        _nonces: Nonces,
        _commitments: Commitments,
        _available: Available,
    ) -> Result<ApplyResult, BlockError> {
        if block.header.height != self.height + 1 {
            return Err(BlockError::BadHeight { expected: self.height + 1, got: block.header.height });
        }

        if block.header.parent_hash != self.tip_hash {
            return Err(BlockError::HeaderMismatch(
                format!(
                    "parent mismatch: expected {}, got {}",
                    hex::encode(self.tip_hash),
                    hex::encode(block.header.parent_hash),
                )
            ));
        }

        self.verify_header_proposer(&block.header)?;

        {
            let v = self
                .validator_set
                .get(block.header.proposer_id)
                .ok_or(BlockError::NotScheduledLeader)?;
            let preimage = header_signing_bytes(&block.header);
            let ok = verify_ed25519(&v.ed25519_pubkey, &block.header.signature, &preimage);
            if !ok {
                return Err(BlockError::IntrinsicInvalid("bad block signature".into()));
            }
        }

        // QC verification: all active validators must have BLS keys
        let active_bls_pks = self.collect_active_bls_pubkeys()?;
        let computed_qc_hash = qc_commitment(
            block.justify_qc.view,
            &block.justify_qc.block_id,
            &block.justify_qc.agg_sig,
            &block.justify_qc.bitmap,
        );

        // Check that justify_qc_hash in header matches computed QC commitment
        if block.header.justify_qc_hash != computed_qc_hash {
            return Err(BlockError::IntrinsicInvalid(
                "justify_qc_hash mismatch".into()
            ));
        }

        // Verify the QC BLS signature against active validator keys
        verify_qc(
            &block.justify_qc.block_id,
            block.justify_qc.view,
            &block.justify_qc.agg_sig,
            &block.justify_qc.bitmap,
            &active_bls_pks,
        ).map_err(|_| BlockError::IntrinsicInvalid("QC signature verification failed".into()))?;

        verify_block_roots(&block.header, block, &self.batch_store, &apply.receipts)
            .map_err(BlockError::RootMismatch)?;

        for ev in &apply.events {
            match ev {
                Event::CommitStored { commitment, .. } => {
                    self.commit_included_at.insert(*commitment, block.header.height);
                }
                Event::AvailabilityRecorded { commitment } => {
                    if let Some(&inc) = self.commit_included_at.get(commitment) {
                        let ready_at = inc + DECRYPTION_DELAY;
                        let deadline = ready_at + REVEAL_WINDOW;
                        self.avail_included.insert(*commitment);
                        self.commit_deadline.insert(*commitment, deadline);
                        self.avail_due.entry(deadline).or_default().push(*commitment);
                    }
                }
                Event::CommitConsumed { commitment } | Event::CommitExpired { commitment } => {
                    if let Some(deadline) = self.commit_deadline.remove(commitment) {
                        if let Some(vec) = self.avail_due.get_mut(&deadline) {
                            vec.retain(|c| c != commitment);
                            if vec.is_empty() {
                                self.avail_due.remove(&deadline);
                            }
                        }
                    }
                }
                Event::ThresholdShareReceived { commitment, validator_id: _ } => {
                    // Handle threshold share received - could trigger decryption attempts
                    // For now, just log or track the event
                }
                Event::ThresholdDecryptionComplete { commitment: _ } => {
                    // Handle completed threshold decryption
                    // This could trigger reveal processing or other consensus actions
                }
            }
        }

        let next_exec = update_exec_base(
            self.fee_state.exec_base,
            apply.exec_reveals_used,
            FEE_PARAMS.exec_target_reveals_per_block,
            FEE_PARAMS.exec_max_change_denominator,
            FEE_PARAMS.exec_min_base,
            FEE_PARAMS.exec_damping_bps,
        );

        self.tip_hash = hash_bytes_sha256(&header_bytes(&block.header));
        self.height = block.header.height;
        self.fee_state.exec_base = next_exec;
        self.fee_state.commit_base = update_commit_base(
            self.fee_state.commit_base,
            apply.commits_used,
        );
        self.burned_total = self.burned_total.saturating_add(apply.gas_total);
        Ok(apply)
    }

    /// Check if a commitment has been included on-chain.
    pub fn commit_on_chain(&self, c: &Hash) -> bool {
        self.commit_included_at.contains_key(c)
    }

    /// Check if an Avail for the commitment has been included.
    pub fn avail_on_chain(&self, c: &Hash) -> bool {
        self.avail_included.contains(c)
    }

    /// Whether an Avail is allowed at `height` for commitment `c`.
    pub fn avail_allowed_at(&self, height: u64, c: &Hash) -> bool {
        if let Some(&included_at) = self.commit_included_at.get(c) {
            let ready_at = included_at + DECRYPTION_DELAY;
            let deadline = ready_at + REVEAL_WINDOW;
            height >= ready_at && height <= deadline
        } else {
            false
        }
    }

    /// Commitments that are due (deadline == `height`) and already available.
    pub fn commitments_due_and_available(&self, height: u64) -> Vec<Hash> {
        self.avail_due.get(&height).cloned().unwrap_or_default()
    }

    /// Add a threshold share for a commitment from a validator
    pub fn add_threshold_share(
        &mut self, 
        commitment: Hash, 
        share: crate::mempool::encrypted::ThresholdShare
    ) -> Result<bool, String> {
        // Validate the validator is in the current active set
        if !self.validator_set.validators.iter().any(|v| v.id == share.validator_id && v.status == ValidatorStatus::Active) {
            return Err(format!("Share from invalid validator: {}", share.validator_id));
        }

        // Get or create the shares collection for this commitment
        let shares = self.pending_shares.entry(commitment).or_insert_with(Vec::new);
        
        // Check if we already have a share from this validator for this commitment
        if shares.iter().any(|s| s.validator_id == share.validator_id) {
            return Err(format!("Duplicate share from validator {}", share.validator_id));
        }

        // Validate the share epoch matches current validator set epoch
        if share.epoch != self.validator_set.epoch {
            return Err(format!("Share epoch {} does not match current epoch {}", 
                share.epoch, self.validator_set.epoch));
        }

        // Add the share
        shares.push(share);
        
        // Check if we now have enough shares to decrypt
        let threshold = (self.validator_set.validators.len() * 2) / 3 + 1; // Byzantine fault tolerance
        Ok(shares.len() >= threshold)
    }

    /// Get the collected threshold shares for a commitment
    pub fn get_threshold_shares(&self, commitment: &Hash) -> Option<&Vec<crate::mempool::encrypted::ThresholdShare>> {
        self.pending_shares.get(commitment)
    }

    /// Remove threshold shares for a commitment (after processing)
    pub fn remove_threshold_shares(&mut self, commitment: &Hash) {
        self.pending_shares.remove(commitment);
    }

    /// Check if a commitment has enough threshold shares for decryption
    pub fn can_decrypt_commitment(&self, commitment: &Hash) -> bool {
        if let Some(shares) = self.pending_shares.get(commitment) {
            let threshold = (self.validator_set.validators.len() * 2) / 3 + 1;
            shares.len() >= threshold
        } else {
            false
        }
    }

    /// Clean up old threshold shares that are no longer needed
    pub fn cleanup_old_shares(&mut self, commitments: &crate::state::Commitments) {
        self.pending_shares.retain(|commitment, _| {
            // Keep shares for commitments that still exist and aren't consumed
            commitments.get(commitment).map(|meta| !meta.consumed).unwrap_or(false)
        });
    }

    /// Collect BLS public keys from active validators in stable order.
    /// Returns an error if any active validator is missing a BLS key.
    fn collect_active_bls_pubkeys(&self) -> Result<Vec<[u8; 48]>, BlockError> {
        let mut out = Vec::new();
        for v in &self.validator_set.validators {
            if v.status == ValidatorStatus::Active {
                match v.bls_pubkey {
                    Some(pk) => out.push(pk),
                    None => {
                        return Err(BlockError::IntrinsicInvalid(
                            "active validator missing BLS key".into(),
                        ))
                    }
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]

mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use ed25519_dalek::{SigningKey, Signer};
    use crate::codec::{
        header_bytes, header_signing_bytes, tx_bytes, access_list_bytes, string_bytes,
    };
    use crate::crypto::vrf::{SchnorrkelVrfSigner, VrfSigner};
    use crate::crypto::{
        hash_bytes_sha256, addr_from_pubkey, addr_hex, commitment_hash,
        commit_signing_preimage, avail_signing_preimage,
    };
    use crate::state::{Balances, Nonces, Commitments, Available, CHAIN_ID, MAX_AVAILS_PER_BLOCK, MAX_PENDING_COMMITS_PER_ACCOUNT};
    use crate::types::{
        Block, BlockHeader, Tx, CommitTx, AvailTx, RevealTx, Transaction, Hash, QC,
    };
    use crate::crypto::bls::{BlsSignatureBytes, BlsSigner, BlsAggregate, vote_msg};
    use bitvec::vec::BitVec;
    use crate::pos::registry::{StakingConfig, Validator, ValidatorSet, ValidatorStatus};

    fn fake_vrf_fields(proposer_id: u64) -> ([u8; 32], [u8; 32], Vec<u8>) {
        let mut m = Vec::with_capacity(16 + 8);
        m.extend_from_slice(b"fake-vrf-preout");
        m.extend_from_slice(&proposer_id.to_be_bytes());
        let preout = hash_bytes_sha256(&m);
    
        let out = hash_bytes_sha256(&preout);
    
        let mut proof = Vec::with_capacity(33);
        proof.extend_from_slice(&preout);
        proof.push(0x01);
    
        (out, preout, proof)
    }

    fn build_block(
        chain: &Chain,
        signer: &SigningKey,
        bls_signer: &BlsSigner,
        balances: &Balances,
        nonces: &Nonces,
        commitments: &Commitments,
        available: &Available,
        transactions: Vec<Tx>,
        reveals: Vec<RevealTx>,
    ) -> Block {
        // Derive deterministic time/slot/epoch for this block
        let now_ms  = (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()) as u128;
        let slot    = chain.clock.current_slot(now_ms);
        let epoch   = chain.clock.current_epoch(slot);
        let ts_sec  = (chain.clock.slot_start_unix(slot) / 1000) as u64;
    
        // Proposer identity: map ed25519 pubkey -> validator id from the active set
        let ed_pk   = signer.verifying_key().to_bytes();
        let proposer_id = chain
            .validator_set
            .validators
            .iter()
            .find(|v| v.ed25519_pubkey == ed_pk)
            .map(|v| v.id)
            .unwrap_or(1); // fallback for tests if not present
    
        // Alias path only here: leave VRF empty but include bundle_len for completeness
        let bundle_len = DEFAULT_BUNDLE_LEN;
        let vrf_output = [0u8; 32];
        let vrf_preout = [0u8; 32];
        let vrf_proof: Vec<u8> = Vec::new();
    
        // Build QC for current tip
        let (qc, qc_hash) = make_qc(&chain, &bls_signer);

        let mut block = Block {
            header: BlockHeader {
                // consensus lineage
                parent_hash:   chain.tip_hash,
                height:        chain.height + 1,
    
                // execution roots (filled after STF simulation)
                txs_root:        [0u8; 32],
                receipts_root:   [0u8; 32],
                gas_used:        0,
                randomness:      chain.tip_hash, // ok for tests; production uses per-block derivation
                reveal_set_root: [0u8; 32],
                il_root:         [0u8; 32],
    
                // fee bases
                exec_base_fee:   chain.fee_state.exec_base,
                commit_base_fee: chain.fee_state.commit_base,
                avail_base_fee:  chain.fee_state.avail_base,
    
                // timing & identity
                timestamp:       ts_sec,
                slot,
                epoch,
                proposer_id,

                // Vortex PoS fields (alias fallback: empty VRF)
                bundle_len,
                vrf_output,
                vrf_proof,
                vrf_preout,

                // HotStuff fields
                view: 0,
                justify_qc_hash: qc_hash,

                // signature filled after STF + preimage build
                signature:       [0u8; 64],
            },
            transactions,
            reveals,
            batch_digests: Vec::new(),
            justify_qc: qc,
        };
    
        // Simulate STF to compute canonical roots/gas
        let mut sim_balances    = balances.clone();
        let mut sim_nonces      = nonces.clone();
        let mut sim_commitments = commitments.clone();
        let mut sim_available   = available.clone();
    
        let proposer_addr = addr_hex(&addr_from_pubkey(&ed_pk));
        let mut burned = 0u64;

        let body = process_block(
            &block,
            &chain.batch_store,
            &mut sim_balances,
            &mut sim_nonces,
            &mut sim_commitments,
            &mut sim_available,
            &chain.fee_state,
            &proposer_addr,
            &mut burned,
            &chain.threshold_engine,
            chain,
        ).expect("process_block");
    
        // Fill header with computed roots/gas
        block.header.txs_root        = body.txs_root;
        block.header.receipts_root   = body.receipts_root;
        block.header.reveal_set_root = body.reveal_set_root;
        block.header.il_root         = body.il_root;
        block.header.gas_used        = body.gas_total;
    
        // Sign header (include new fields in preimage)
        let preimage = header_signing_bytes(&block.header);
        let sig = signer.sign(&preimage).to_bytes();
        block.header.signature = sig;
    
        block
    }

    fn build_empty_block(
        chain: &Chain,
        signer: &SigningKey,
        bls_signer: &BlsSigner,
        balances: &Balances,
        nonces: &Nonces,
        commitments: &Commitments,
        available: &Available,
    ) -> Block {
        build_block(
            chain,
            signer,
            bls_signer,
            balances,
            nonces,
            commitments,
            available,
            Vec::new(),
            Vec::new(),
        )
    }

    fn build_block_vortex_ok(
        chain: &Chain,
        signer: &SigningKey,
        bls_signer: &BlsSigner,
        balances: &Balances,
        nonces: &Nonces,
        commitments: &Commitments,
        available: &Available,
        txs: Vec<Tx>,
        reveals: Vec<RevealTx>,
    ) -> Block {
        let height = chain.height + 1;
        let slot = height; // dev policy: one block per slot
        let epoch = chain.clock.current_epoch(slot);
        let bundle_len = DEFAULT_BUNDLE_LEN;
        let proposer_id: u64 = 1;
        let (vrf_output, vrf_preout, vrf_proof) = fake_vrf_fields(proposer_id);
        let (qc, qc_hash) = make_qc(chain, bls_signer);

        let mut block = Block {
            header: BlockHeader {
                parent_hash: chain.tip_hash,
                height,
                txs_root: [0u8; 32],
                receipts_root: [0u8; 32],
                gas_used: 0,
                randomness: chain.tip_hash,
                reveal_set_root: [0u8; 32],
                il_root: [0u8; 32],
                exec_base_fee: chain.fee_state.exec_base,
                commit_base_fee: chain.fee_state.commit_base,
                avail_base_fee: chain.fee_state.avail_base,
                timestamp: 0,
                slot,
                epoch,
                proposer_id,
                bundle_len,
                vrf_output,
                vrf_proof,
                vrf_preout,
                view: 0,
                justify_qc_hash: qc_hash,
                signature: [0u8; 64],
            },
            transactions: txs,
            reveals,
            batch_digests: Vec::new(),
            justify_qc: qc,
        };

        let mut sim_balances = balances.clone();
        let mut sim_nonces = nonces.clone();
        let mut sim_commitments = commitments.clone();
        let mut sim_available = available.clone();
        let proposer_addr = addr_hex(&addr_from_pubkey(&signer.verifying_key().to_bytes()));
        let mut sim_burned = 0u64;

        let body = process_block(
            &block,
            &chain.batch_store,
            &mut sim_balances,
            &mut sim_nonces,
            &mut sim_commitments,
            &mut sim_available,
            &chain.fee_state,
            &proposer_addr,
            &mut sim_burned,
            &chain.threshold_engine,
            chain,
        )
        .expect("process_block should succeed for valid blocks");

        block.header.txs_root = body.txs_root;
        block.header.receipts_root = body.receipts_root;
        block.header.reveal_set_root = body.reveal_set_root;
        block.header.il_root = body.il_root;
        block.header.gas_used = body.gas_total;

        let preimage = header_signing_bytes(&block.header);
        block.header.signature = signer.sign(&preimage).to_bytes();
        block
    }

    fn addr(i: u8) -> String {
        format!(
            "0x{:02x}{:02x}000000000000000000000000000000000000",
            i, i
        )
    }

    fn make_commit(
        signer: &SigningKey,
        tx: &Transaction,
        salt: Hash,
    ) -> (CommitTx, Hash) {
        let tx_ser = tx_bytes(tx);
        let al_bytes = access_list_bytes(&tx.access_list);
        let commitment = commitment_hash(&tx_ser, &al_bytes, &salt, CHAIN_ID);
        // Create mock encrypted payload for testing
        let mock_encrypted_payload = crate::mempool::encrypted::ThresholdCiphertext {
            ephemeral_pk: [0x42u8; 48],
            encrypted_data: b"mock encrypted transaction data".to_vec(),
            tag: [0x24u8; 32],
            epoch: 0,
        };
        let encrypted_payload_hash = mock_encrypted_payload.commitment_hash();
        let sender = addr_hex(&addr_from_pubkey(&signer.verifying_key().to_bytes()));
        let sender_bytes = string_bytes(&sender);
        let preimage = commit_signing_preimage(
            &commitment,
            &encrypted_payload_hash,
            &sender_bytes,
            &al_bytes,
            CHAIN_ID,
        );
        let sig = signer.sign(&preimage).to_bytes();
        (
            CommitTx {
                commitment,
                sender,
                access_list: tx.access_list.clone(),
                encrypted_payload: mock_encrypted_payload,
                pubkey: signer.verifying_key().to_bytes(),
                sig,
            },
            commitment,
        )
    }

    fn make_avail(
        signer: &SigningKey,
        commitment: Hash,
        ciphertext: crate::mempool::encrypted::ThresholdCiphertext,
    ) -> AvailTx {
        let sender = addr_hex(&addr_from_pubkey(&signer.verifying_key().to_bytes()));
        let sender_bytes = string_bytes(&sender);
        let preimage = avail_signing_preimage(&commitment, &sender_bytes, CHAIN_ID);
        let sig = signer.sign(&preimage).to_bytes();
        AvailTx {
            commitment,
            sender,
            payload_hash: ciphertext.commitment_hash(),
            payload_size: ciphertext.encrypted_data.len() as u64,
            pubkey: signer.verifying_key().to_bytes(),
            sig,
        }
    }

    fn make_reveal(tx: Transaction, salt: Hash, sender: &str) -> RevealTx {
        RevealTx {
            tx,
            salt,
            sender: sender.to_string(),
        }
    }

    #[cfg(test)]
    pub fn init_chain_with_validator(chain: &mut Chain, signer: &SigningKey) -> BlsSigner {
        use crate::crypto::vrf::SchnorrkelVrfSigner;

        let cfg = StakingConfig { min_stake: 1, unbonding_epochs: 1, max_validators: u32::MAX };

        // Deterministic VRF key for tests (DO NOT use this pattern for prod key mgmt)
        let vrf_seed = hash_bytes_sha256(b"l1-blockchain/test-vrf-seed:v1");
        let vrf      = SchnorrkelVrfSigner::from_deterministic_seed(vrf_seed);

        let bls_signer = BlsSigner::from_sk_bytes(&[1u8;32]).unwrap();
        let v = Validator {
            id: 1,
            ed25519_pubkey: signer.verifying_key().to_bytes(),
            bls_pubkey: Some(bls_signer.public_key_bytes()),
            vrf_pubkey: vrf.public_bytes(),   // <-- REQUIRED
            stake: 1,
            status: ValidatorStatus::Active,
        };

        let set  = ValidatorSet::from_genesis(0, &cfg, vec![v]);
        let seed = hash_bytes_sha256(b"l1-blockchain/test-epoch-seed:v1");
        chain.init_genesis(set, seed);

        bls_signer
    }

    fn make_qc(chain: &Chain, bls_signer: &BlsSigner) -> (QC, [u8;32]) {
        let msg = vote_msg(&chain.tip_hash, chain.height);
        let mut agg = BlsAggregate::new();
        let sig = bls_signer.sign(&msg);
        agg.push(&sig.0);
        let agg_sig = agg.finalize().unwrap();
        let mut bitmap = BitVec::repeat(false, 1);
        bitmap.set(0, true);
        let qc = QC { view: chain.height, block_id: chain.tip_hash, agg_sig, bitmap };
        let qc_hash = qc_commitment(qc.view, &qc.block_id, &qc.agg_sig, &qc.bitmap);
        (qc, qc_hash)
    }

    #[test]
    fn apply_block1_advances_tip() {
        let signer = SigningKey::from_bytes(&[1u8; 32]);
        let mut chain = Chain::new();
        let bls_signer = init_chain_with_validator(&mut chain, &signer);
        let mut balances = Balances::default();
        let mut nonces = Nonces::default();
        let mut commitments = Commitments::default();
        let mut available = Available::default();

        let block = build_empty_block(&chain, &signer, &bls_signer, &balances, &nonces, &commitments, &available);
        chain
            .apply_block(&block, &mut balances, &mut nonces, &mut commitments, &mut available)
            .unwrap();

        assert_eq!(chain.height, 1);
        let expected_tip = hash_bytes_sha256(&header_bytes(&block.header));
        assert_eq!(chain.tip_hash, expected_tip);
    }

    #[test]
    fn vrf_tie_break_lexicographic_smallest_wins() {
        use crate::codec::header_signing_bytes;
        use crate::crypto::vrf::{SchnorrkelVrfSigner, VrfSigner, build_vrf_msg};
        use crate::pos::registry::{Validator, ValidatorSet, ValidatorStatus, StakingConfig};
        use ed25519_dalek::SigningKey;
        use crate::types::BlockHeader;
        use crate::stf::BlockError;

        let mut chain = Chain::new();
        let seed = [1u8;32];

        // two validators with deterministic VRF keys
        let vrf1 = SchnorrkelVrfSigner::from_deterministic_seed([5u8;32]);
        let vrf2 = SchnorrkelVrfSigner::from_deterministic_seed([6u8;32]);
        let sk1 = SigningKey::from_bytes(&[1u8;32]);
        let sk2 = SigningKey::from_bytes(&[2u8;32]);

        let v1 = Validator { id:1, ed25519_pubkey: sk1.verifying_key().to_bytes(), bls_pubkey: None, vrf_pubkey: vrf1.public_bytes(), stake:1, status: ValidatorStatus::Active };
        let v2 = Validator { id:2, ed25519_pubkey: sk2.verifying_key().to_bytes(), bls_pubkey: None, vrf_pubkey: vrf2.public_bytes(), stake:1, status: ValidatorStatus::Active };
        let cfg = StakingConfig { min_stake:1, unbonding_epochs:1, max_validators:u32::MAX };
        let set = ValidatorSet::from_genesis(0, &cfg, vec![v1, v2]);
        chain.init_genesis(set, seed);

        let slot = 1u64;
        let epoch = chain.clock.current_epoch(slot);
        let bundle_len = DEFAULT_BUNDLE_LEN;
        let bundle_start = chain.clock.bundle_start(slot, bundle_len);

        let msg1 = build_vrf_msg(&chain.epoch_seed, bundle_start, 1);
        let (out1, pre1, proof1) = vrf1.vrf_prove(&msg1);
        let msg2 = build_vrf_msg(&chain.epoch_seed, bundle_start, 2);
        let (out2, pre2, proof2) = vrf2.vrf_prove(&msg2);

        let mk_header = |pid: u64, out: [u8;32], pre: [u8;32], proof: Vec<u8>| -> BlockHeader {
            BlockHeader {
                parent_hash: chain.tip_hash,
                height: 1,
                txs_root: [0u8;32],
                receipts_root: [0u8;32],
                gas_used: 0,
                randomness: [0u8;32],
                reveal_set_root: [0u8;32],
                il_root: [0u8;32],
                exec_base_fee: chain.fee_state.exec_base,
                commit_base_fee: chain.fee_state.commit_base,
                avail_base_fee: chain.fee_state.avail_base,
                timestamp: 0,
                slot,
                epoch,
                proposer_id: pid,
                bundle_len,
                vrf_preout: pre,
                vrf_output: out,
                vrf_proof: proof,
                view: 0,
                justify_qc_hash: [0u8;32],
                signature: [0u8;64],
            }
        };

        // header from validator with smaller VRF output (id=2)
        let mut header_small = mk_header(2, out2, pre2, proof2.clone());
        let pre_small = header_signing_bytes(&header_small);
        header_small.signature = sk2.sign(&pre_small).to_bytes();
        // header from validator with larger VRF output (id=1)
        let mut header_large = mk_header(1, out1, pre1, proof1.clone());
        let pre_large = header_signing_bytes(&header_large);
        header_large.signature = sk1.sign(&pre_large).to_bytes();

        // accept smaller VRF output first
        assert!(chain.verify_header_proposer(&header_small).is_ok());
        // larger output should now be rejected for this bundle
        assert!(matches!(chain.verify_header_proposer(&header_large), Err(BlockError::NotScheduledLeader)));
    }

    #[test]
    fn applying_same_height_fails() {
        let signer = SigningKey::from_bytes(&[2u8; 32]);
        let mut chain = Chain::new();
        let bls_signer = init_chain_with_validator(&mut chain, &signer);
        let mut balances = Balances::default();
        let mut nonces = Nonces::default();
        let mut commitments = Commitments::default();
        let mut available = Available::default();

        let block1 = build_empty_block(&chain, &signer, &bls_signer, &balances, &nonces, &commitments, &available);
        chain
            .apply_block(&block1, &mut balances, &mut nonces, &mut commitments, &mut available)
            .unwrap();

        let err = chain
            .apply_block(&block1, &mut balances, &mut nonces, &mut commitments, &mut available)
            .err()
            .unwrap();
        match err {
            BlockError::BadHeight { expected, got } => {
                assert_eq!(expected, 2);
                assert_eq!(got, 1);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn applying_2_blocks_works_correctly() {
        let signer = SigningKey::from_bytes(&[3u8; 32]);
        let mut chain = Chain::new();
        let bls_signer = init_chain_with_validator(&mut chain, &signer);
        let mut balances = Balances::default();
        let mut nonces = Nonces::default();
        let mut commitments = Commitments::default();
        let mut available = Available::default();

        let block1 = build_empty_block(&chain, &signer, &bls_signer, &balances, &nonces, &commitments, &available);
        chain
            .apply_block(&block1, &mut balances, &mut nonces, &mut commitments, &mut available)
            .unwrap();
        assert_eq!(chain.height, 1);

        let block2 = build_empty_block(&chain, &signer, &bls_signer, &balances, &nonces, &commitments, &available);
        chain
            .apply_block(&block2, &mut balances, &mut nonces, &mut commitments, &mut available)
            .unwrap();

        assert_eq!(chain.height, 2);
        let expected_tip = hash_bytes_sha256(&header_bytes(&block2.header));
        assert_eq!(chain.tip_hash, expected_tip);
        assert_ne!(
            chain.tip_hash,
            hash_bytes_sha256(&header_bytes(&block1.header))
        );
    }

    #[test]
    fn tamper_block_no_state_change() {
        let signer = SigningKey::from_bytes(&[4u8; 32]);
        let mut chain = Chain::new();
        let bls_signer = init_chain_with_validator(&mut chain, &signer);
        let mut balances = Balances::default();
        let mut nonces = Nonces::default();
        let mut commitments = Commitments::default();
        let mut available = Available::default();

        let sender = addr_hex(&addr_from_pubkey(&signer.verifying_key().to_bytes()));
        balances.insert(sender.clone(), 1000);

        let tx1 = Transaction::transfer(&sender, &addr(1), 10, 0);
        let salt1 = [1u8; 32];
        let (commit1, _c1) = make_commit(&signer, &tx1, salt1);

        let block = build_block(
            &chain,
            &signer,
            &bls_signer,
            &balances,
            &nonces,
            &commitments,
            &available,
            vec![Tx::Commit(commit1.clone())],
            vec![],
        );

        let tx2 = Transaction::transfer(&sender, &addr(2), 5, 1);
        let salt2 = [2u8; 32];
        let (commit2, _c2) = make_commit(&signer, &tx2, salt2);
        let mut tampered = block.clone();
        tampered.transactions.push(Tx::Commit(commit2));

        let burned_before = chain.burned_total;
        let res = chain.apply_block(
            &tampered,
            &mut balances,
            &mut nonces,
            &mut commitments,
            &mut available,
        );
        assert!(matches!(res, Err(BlockError::RootMismatch(_))));
        assert_eq!(chain.height, 0);
        assert_eq!(chain.burned_total, burned_before);
        assert!(commitments.is_empty());
        assert_eq!(*balances.get(&sender).unwrap(), 1000);
    }

    #[test]
    fn inclusion_list_due_must_be_included() {
        let signer = SigningKey::from_bytes(&[5u8; 32]);
        let mut chain = Chain::new();
        let bls_signer = init_chain_with_validator(&mut chain, &signer);
        let mut balances = Balances::default();
        let mut nonces = Nonces::default();
        let mut commitments = Commitments::default();
        let mut available = Available::default();

        let sender = addr_hex(&addr_from_pubkey(&signer.verifying_key().to_bytes()));
        let receiver = addr(1);
        balances.insert(sender.clone(), 1000);
        balances.insert(receiver.clone(), 0);

        let tx = Transaction::transfer(&sender, &receiver, 10, 0);
        let salt = [1u8; 32];
        let (commit, c_hash) = make_commit(&signer, &tx, salt);
        let ciphertext = commit.encrypted_payload.clone();
        let block1 = build_block(
            &chain,
            &signer,
            &bls_signer,
            &balances,
            &nonces,
            &commitments,
            &available,
            vec![Tx::Commit(commit)],
            vec![],
        );
        chain
            .apply_block(&block1, &mut balances, &mut nonces, &mut commitments, &mut available)
            .unwrap();

        let avail_tx = make_avail(&signer, c_hash, ciphertext);
        let block2 = build_block(
            &chain,
            &signer,
            &bls_signer,
            &balances,
            &nonces,
            &commitments,
            &available,
            vec![Tx::Avail(avail_tx)],
            vec![],
        );
        chain
            .apply_block(&block2, &mut balances, &mut nonces, &mut commitments, &mut available)
            .unwrap();

        for _ in 0..2 {
            let b = build_block(
                &chain,
                &signer,
                &bls_signer,
                &balances,
                &nonces,
                &commitments,
                &available,
                vec![],
                vec![],
            );
            chain
                .apply_block(&b, &mut balances, &mut nonces, &mut commitments, &mut available)
                .unwrap();
        }
        assert_eq!(chain.height, 4);

        let block5 = build_block(
            &chain,
            &signer,
            &bls_signer,
            &Balances::default(),
            &Nonces::default(),
            &Commitments::default(),
            &Available::default(),
            vec![],
            vec![],
        );
        let res = chain.apply_block(
            &block5,
            &mut balances,
            &mut nonces,
            &mut commitments,
            &mut available,
        );
        assert!(matches!(res, Err(BlockError::IntrinsicInvalid(msg)) if msg.contains("missing required reveal")));
        assert_eq!(chain.height, 4);
    }

    #[test]
    fn reveal_bundle_executes_multiple_reveals_and_satisfies_inclusion_list() {
        let signer = SigningKey::from_bytes(&[6u8; 32]);
        let mut chain = Chain::new();
        let bls_signer = init_chain_with_validator(&mut chain, &signer);
        let mut balances = Balances::default();
        let mut nonces = Nonces::default();
        let mut commitments = Commitments::default();
        let mut available = Available::default();

        let sender = addr_hex(&addr_from_pubkey(&signer.verifying_key().to_bytes()));
        let recv1 = addr(1);
        let recv2 = addr(2);
        balances.insert(sender.clone(), 1000);
        balances.insert(recv1.clone(), 0);
        balances.insert(recv2.clone(), 0);

        let tx1 = Transaction::transfer(&sender, &recv1, 10, 0);
        let salt1 = [11u8; 32];
        let (commit1, c1) = make_commit(&signer, &tx1, salt1);
        let tx2 = Transaction::transfer(&sender, &recv2, 20, 1);
        let salt2 = [22u8; 32];
        let (commit2, c2) = make_commit(&signer, &tx2, salt2);

        let block1 = build_block(
            &chain,
            &signer,
            &bls_signer,
            &balances,
            &nonces,
            &commitments,
            &available,
            vec![Tx::Commit(commit1.clone()), Tx::Commit(commit2.clone())],
            vec![],
        );
        chain
            .apply_block(&block1, &mut balances, &mut nonces, &mut commitments, &mut available)
            .unwrap();

        let avail1 = make_avail(&signer, c1, commit1.encrypted_payload.clone());
        let avail2 = make_avail(&signer, c2, commit2.encrypted_payload.clone());
        let block2 = build_block(
            &chain,
            &signer,
            &bls_signer,
            &balances,
            &nonces,
            &commitments,
            &available,
            vec![Tx::Avail(avail1), Tx::Avail(avail2)],
            vec![],
        );
        chain
            .apply_block(&block2, &mut balances, &mut nonces, &mut commitments, &mut available)
            .unwrap();

        for _ in 0..2 {
            let b = build_block(
                &chain,
                &signer,
                &bls_signer,
                &balances,
                &nonces,
                &commitments,
                &available,
                vec![],
                vec![],
            );
            chain
                .apply_block(&b, &mut balances, &mut nonces, &mut commitments, &mut available)
                .unwrap();
        }

        let r1 = make_reveal(tx1.clone(), salt1, &sender);
        let r2 = make_reveal(tx2.clone(), salt2, &sender);
        let block5 = build_block(
            &chain,
            &signer,
            &bls_signer,
            &balances,
            &nonces,
            &commitments,
            &available,
            vec![],
            vec![r1, r2],
        );
        let res = chain
            .apply_block(&block5, &mut balances, &mut nonces, &mut commitments, &mut available)
            .unwrap();
        assert_eq!(chain.height, 5);
        assert_eq!(res.receipts.len(), 2);
        assert_eq!(balances.get(&recv1).copied().unwrap(), 10);
        assert_eq!(balances.get(&recv2).copied().unwrap(), 20);
        assert!(chain.commitments_due_and_available(5).is_empty());
    }

    #[test]
    fn too_many_avails_in_block_is_invalid() {
        use crate::crypto::{hash_bytes_sha256, addr_from_pubkey, addr_hex};
        use crate::crypto::vrf::{SchnorrkelVrfSigner, VrfSigner, build_vrf_msg};
        use crate::chain::DEFAULT_BUNDLE_LEN;
    
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        let mut chain = Chain::new();
        let bls_signer = init_chain_with_validator(&mut chain, &signer); // sets validator id=1 with a deterministic VRF pubkey
    
        let mut balances    = Balances::default();
        let mut nonces      = Nonces::default();
        let mut commitments = Commitments::default();
        let mut available   = Available::default();
    
        // Build MAX_AVAILS_PER_BLOCK + 1 Avail txs to trigger the intrinsic error
        let mut txs = Vec::with_capacity(MAX_AVAILS_PER_BLOCK + 1);
        for _ in 0..=MAX_AVAILS_PER_BLOCK {
            txs.push(Tx::Avail(AvailTx {
                commitment: [0u8; 32],
                sender: String::new(),
                payload_hash: [0u8; 32],
                payload_size: 100,
                pubkey: [0u8; 32],
                sig: [0u8; 64],
            }));
        }
    
        // --- Vortex (VRF) path setup ---
    
        // Your policy enforces: slot == height
        let height = chain.height + 1; // 1
        let slot   = height;           // 1
        let epoch  = chain.clock.current_epoch(slot);
    
        let bundle_len   = DEFAULT_BUNDLE_LEN;
        let proposer_id  = 1;
    
        let (vrf_output, vrf_preout, vrf_proof) = fake_vrf_fields(proposer_id);
    
        // --- Build header with Vortex fields filled (non-empty proof == VRF path) ---
        let msg = vote_msg(&chain.tip_hash, chain.height);
        let mut agg = BlsAggregate::new();
        let sig = bls_signer.sign(&msg);
        agg.push(&sig.0);
        let agg_sig = agg.finalize().unwrap();
        let mut bitmap = BitVec::repeat(false, 1);
        bitmap.set(0, true);
        let qc = QC { view: chain.height, block_id: chain.tip_hash, agg_sig, bitmap };
        let qc_hash = qc_commitment(qc.view, &qc.block_id, &qc.agg_sig, &qc.bitmap);

        let mut block = Block {
            header: BlockHeader {
                parent_hash:     chain.tip_hash,
                height,
                txs_root:        [0u8; 32],
                receipts_root:   [0u8; 32],
                gas_used:        0,
                randomness:      chain.tip_hash,
                reveal_set_root: [0u8; 32],
                il_root:         [0u8; 32],
                exec_base_fee:   chain.fee_state.exec_base,
                commit_base_fee: chain.fee_state.commit_base,
                avail_base_fee:  chain.fee_state.avail_base,
                timestamp:       0, // not checked in this test

                // proposer/time metadata
                slot,
                epoch,
                proposer_id,

                // Vortex PoS fields
                bundle_len,
                vrf_preout,
                vrf_output,
                vrf_proof,
                view: 0,
                justify_qc_hash: qc_hash,
                signature: [0u8; 64],
            },
            transactions: txs,
            reveals: vec![],
            batch_digests: Vec::new(),
            justify_qc: qc,
        };
    
        // Sign the header
        let preimage = header_signing_bytes(&block.header);
        block.header.signature = signer.sign(&preimage).to_bytes();
    
        // Apply and expect intrinsic invalid (too many Avails)
        let res = chain.apply_block(
            &block,
            &mut balances,
            &mut nonces,
            &mut commitments,
            &mut available
        );
    
        assert!(matches!(res, Err(BlockError::IntrinsicInvalid(msg)) if msg.contains("too many Avails in block")));
        assert_eq!(chain.height, 0);
    }

    #[test]
    fn too_many_pending_commits_for_owner_is_rejected() {
        let signer = SigningKey::from_bytes(&[8u8; 32]);
        let mut chain = Chain::new();
        let bls_signer = init_chain_with_validator(&mut chain, &signer);
    
        let mut balances    = Balances::default();
        let mut nonces      = Nonces::default();
        let mut commitments = Commitments::default();
        let mut available   = Available::default();
    
        let sender = addr_hex(&addr_from_pubkey(&signer.verifying_key().to_bytes()));
        balances.insert(sender.clone(), 2_000);
    
        let tx = Transaction::transfer(&sender, &addr(1), 1, 0);
        let mut txs = Vec::with_capacity(MAX_PENDING_COMMITS_PER_ACCOUNT + 1);
        for i in 0..=MAX_PENDING_COMMITS_PER_ACCOUNT {
            let mut salt = [0u8; 32];
            salt[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let (c, _ch) = make_commit(&signer, &tx, salt);
            txs.push(Tx::Commit(c));
        }
    
        // --- VORTEX (VRF) header fields ---
        let height = chain.height + 1;
        let slot   = height; // dev policy: one block per slot
        let epoch  = chain.clock.current_epoch(slot);
    
        let bundle_len: u8 = DEFAULT_BUNDLE_LEN;
    
        let proposer_id: u64 = 1;
        let (vrf_output, vrf_preout, vrf_proof) = fake_vrf_fields(proposer_id);
    
        let (qc, qc_hash) = make_qc(&chain, &bls_signer);
        let mut block = Block {
            header: BlockHeader {
                parent_hash:     chain.tip_hash,
                height,
                txs_root:        [0u8; 32],
                receipts_root:   [0u8; 32],
                gas_used:        0,
                randomness:      chain.tip_hash,
                reveal_set_root: [0u8; 32],
                il_root:         [0u8; 32],
                exec_base_fee:   chain.fee_state.exec_base,
                commit_base_fee: chain.fee_state.commit_base,
                avail_base_fee:  chain.fee_state.avail_base,
                timestamp:       0,
                slot,
                epoch,
                proposer_id,
                bundle_len,
                vrf_output,
                vrf_proof,
                vrf_preout,
                view: 0,
                justify_qc_hash: qc_hash,
                signature: [0u8; 64],
            },
            transactions: txs,
            reveals: vec![],
            batch_digests: Vec::new(),
            justify_qc: qc,
        };
    
        // Sign after all header fields are set (including VRF fields)
        let preimage = header_signing_bytes(&block.header);
        block.header.signature = signer.sign(&preimage).to_bytes();
    
        let res = chain.apply_block(
            &block,
            &mut balances,
            &mut nonces,
            &mut commitments,
            &mut available,
        );
    
        assert!(matches!(res, Err(BlockError::IntrinsicInvalid(msg)) if msg.contains("too many pending commits for owner")));
        assert!(commitments.is_empty());
        assert_eq!(chain.height, 0);
    }

    #[test]
    fn duplicate_commit_in_same_block_is_rejected() {
        let signer = SigningKey::from_bytes(&[9u8; 32]);
        let mut chain = Chain::new();
        let bls_signer = init_chain_with_validator(&mut chain, &signer);
    
        let mut balances    = Balances::default();
        let mut nonces      = Nonces::default();
        let mut commitments = Commitments::default();
        let mut available   = Available::default();
    
        let sender = addr_hex(&addr_from_pubkey(&signer.verifying_key().to_bytes()));
        balances.insert(sender.clone(), 100);
    
        let tx = Transaction::transfer(&sender, &addr(1), 1, 0);
        let salt = [1u8; 32];
        let (commit, _c_hash) = make_commit(&signer, &tx, salt);
    
        // --- VORTEX (VRF) header fields ---
        let height = chain.height + 1;
        let slot   = height; // dev policy: one block per slot
        let epoch  = chain.clock.current_epoch(slot);
    
        let bundle_len: u8 = DEFAULT_BUNDLE_LEN;
    
        let proposer_id: u64 = 1;
        let (vrf_output, vrf_preout, vrf_proof) = fake_vrf_fields(proposer_id);
    
        let (qc, qc_hash) = make_qc(&chain, &bls_signer);
        let mut block = Block {
            header: BlockHeader {
                parent_hash:     chain.tip_hash,
                height,
                txs_root:        [0u8; 32],
                receipts_root:   [0u8; 32],
                gas_used:        0,
                randomness:      chain.tip_hash,
                reveal_set_root: [0u8; 32],
                il_root:         [0u8; 32],
                exec_base_fee:   chain.fee_state.exec_base,
                commit_base_fee: chain.fee_state.commit_base,
                avail_base_fee:  chain.fee_state.avail_base,
                timestamp:       0,
                slot,
                epoch,
                proposer_id,
                bundle_len,
                vrf_output,
                vrf_proof,
                vrf_preout,
                view: 0,
                justify_qc_hash: qc_hash,
                signature: [0u8; 64],
            },
            transactions: vec![Tx::Commit(commit.clone()), Tx::Commit(commit.clone())],
            reveals: vec![],
            batch_digests: Vec::new(),
            justify_qc: qc,
        };
    
        // Sign after all header fields are set (including VRF fields)
        let preimage = header_signing_bytes(&block.header);
        block.header.signature = signer.sign(&preimage).to_bytes();
    
        let res = chain.apply_block(
            &block,
            &mut balances,
            &mut nonces,
            &mut commitments,
            &mut available,
        );
    
        assert!(matches!(res, Err(BlockError::IntrinsicInvalid(msg)) if msg.contains("duplicate commitment")));
        assert!(commitments.is_empty());
        assert_eq!(chain.height, 0);
    }

    #[test]
    fn inclusion_list_due_but_missing_reveal_rejects_block() {
        let signer = SigningKey::from_bytes(&[10u8; 32]);
        let mut chain = Chain::new();
        let bls_signer = init_chain_with_validator(&mut chain, &signer);
    
        let mut balances    = Balances::default();
        let mut nonces      = Nonces::default();
        let mut commitments = Commitments::default();
        let mut available   = Available::default();
    
        let sender   = addr_hex(&addr_from_pubkey(&signer.verifying_key().to_bytes()));
        let receiver = addr(1);
        balances.insert(sender.clone(), 1000);
        balances.insert(receiver.clone(), 0);
    
        let proposer_id: u64 = 1;
    
        // local helper: build a Vortex-only block (fills VRF fields & signs header)
        // helper A: simulate + fill roots (for valid blocks)
        let mut build_block_vortex_ok = |chain: &Chain,
                                        signer: &SigningKey,
                                        balances: &Balances,
                                        nonces: &Nonces,
                                        commitments: &Commitments,
                                        available: &Available,
                                        txs: Vec<Tx>,
                                        reveals: Vec<RevealTx>| -> Block {
            let height      = chain.height + 1;
            let slot        = height;
            let epoch       = chain.clock.current_epoch(slot);
            let bundle_len  = DEFAULT_BUNDLE_LEN;
            let proposer_id: u64 = 1;
            let (vrf_output, vrf_preout, vrf_proof) = fake_vrf_fields(proposer_id);
            let (qc, qc_hash) = make_qc(chain, &bls_signer);

            let mut block = Block {
                header: BlockHeader {
                    parent_hash:     chain.tip_hash,
                    height,
                    txs_root:        [0u8; 32],
                    receipts_root:   [0u8; 32],
                    gas_used:        0,
                    randomness:      chain.tip_hash,
                    reveal_set_root: [0u8; 32],
                    il_root:         [0u8; 32],
                    exec_base_fee:   chain.fee_state.exec_base,
                    commit_base_fee: chain.fee_state.commit_base,
                    avail_base_fee:  chain.fee_state.avail_base,
                    timestamp:       0,
                    slot,
                    epoch,
                    proposer_id,
                    bundle_len,
                    vrf_output,
                    vrf_proof,
                    vrf_preout,
                    view: 0,
                    justify_qc_hash: qc_hash,
                    signature: [0u8; 64],
                },
                transactions: txs,
                reveals,
                batch_digests: Vec::new(),
                justify_qc: qc,
            };

            // simulate STF to compute roots/gas
            let mut sim_balances    = balances.clone();
            let mut sim_nonces      = nonces.clone();
            let mut sim_commitments = commitments.clone();
            let mut sim_available   = available.clone();
            let proposer_addr = addr_hex(&addr_from_pubkey(&signer.verifying_key().to_bytes()));
            let mut sim_burned = 0u64;

            let body = process_block(
                &block,
                &chain.batch_store,
                &mut sim_balances,
                &mut sim_nonces,
                &mut sim_commitments,
                &mut sim_available,
                &chain.fee_state,
                &proposer_addr,
                &mut sim_burned,
                &chain.threshold_engine,
                chain,
            ).expect("process_block should succeed for valid blocks");

            block.header.txs_root        = body.txs_root;
            block.header.receipts_root   = body.receipts_root;
            block.header.reveal_set_root = body.reveal_set_root;
            block.header.il_root         = body.il_root;
            block.header.gas_used        = body.gas_total;

            let preimage = header_signing_bytes(&block.header);
            block.header.signature = signer.sign(&preimage).to_bytes();
            block
        };

        // helper B: NO simulation (for blocks expected to be intrinsically invalid)
        let mut build_block_vortex_raw = |chain: &Chain,
                                        signer: &SigningKey,
                                        txs: Vec<Tx>,
                                        reveals: Vec<RevealTx>| -> Block {
            let height      = chain.height + 1;
            let slot        = height;
            let epoch       = chain.clock.current_epoch(slot);
            let bundle_len  = DEFAULT_BUNDLE_LEN;
            let proposer_id: u64 = 1;
            let (vrf_output, vrf_preout, vrf_proof) = fake_vrf_fields(proposer_id);
            let (qc, qc_hash) = make_qc(chain, &bls_signer);

            let mut block = Block {
                header: BlockHeader {
                    parent_hash:     chain.tip_hash,
                    height,
                    txs_root:        [0u8; 32],
                    receipts_root:   [0u8; 32],
                    gas_used:        0,
                    randomness:      chain.tip_hash,
                    reveal_set_root: [0u8; 32],
                    il_root:         [0u8; 32],
                    exec_base_fee:   chain.fee_state.exec_base,
                    commit_base_fee: chain.fee_state.commit_base,
                    avail_base_fee:  chain.fee_state.avail_base,
                    timestamp:       0,
                    slot,
                    epoch,
                    proposer_id,
                    bundle_len,
                    vrf_output,
                    vrf_proof,
                    vrf_preout,
                    view: 0,
                    justify_qc_hash: qc_hash,
                    signature: [0u8; 64],
                },
                transactions: txs,
                reveals,
                batch_digests: Vec::new(),
                justify_qc: qc,
            };

            // Sign as usual; STF will run inside apply_block and return IntrinsicInvalid
            let preimage = header_signing_bytes(&block.header);
            block.header.signature = signer.sign(&preimage).to_bytes();
            block
        };
    
        let tx = Transaction::transfer(&sender, &receiver, 10, 0);
        let salt = [1u8; 32];
        let (commit, c_hash) = make_commit(&signer, &tx, salt);
        let ciphertext = commit.encrypted_payload.clone();
        let avail_tx = make_avail(&signer, c_hash, ciphertext);

        // 1) commit
        let block1 = build_block_vortex_ok(&chain, &signer, &balances, &nonces, &commitments, &available,
            vec![Tx::Commit(commit)], vec![]);
        chain.apply_block(&block1, &mut balances, &mut nonces, &mut commitments, &mut available).unwrap();

        // 2) avail
        let block2 = build_block_vortex_ok(&chain, &signer, &balances, &nonces, &commitments, &available,
            vec![Tx::Avail(avail_tx)], vec![]);
        chain.apply_block(&block2, &mut balances, &mut nonces, &mut commitments, &mut available).unwrap();

        // 3) advance two empty blocks
        for _ in 0..2 {
        let b = build_block_vortex_ok(&chain, &signer, &balances, &nonces, &commitments, &available,
        vec![], vec![]);
        chain.apply_block(&b, &mut balances, &mut nonces, &mut commitments, &mut available).unwrap();
        }
        assert_eq!(chain.height, 4);

        // 4) missing reveal block — use RAW helper (no STF simulation)
        let block5 = build_block_vortex_raw(&chain, &signer, vec![], vec![]);
        let res = chain.apply_block(&block5, &mut balances, &mut nonces, &mut commitments, &mut available);
        assert!(matches!(res, Err(BlockError::IntrinsicInvalid(msg)) if msg.contains("missing required reveal")));
        assert_eq!(chain.height, 4);
    }

    #[test]
    fn availability_same_block_not_allowed() {
        let signer = SigningKey::from_bytes(&[11u8; 32]);
        let mut chain = Chain::new();
        let bls_signer = init_chain_with_validator(&mut chain, &signer);
    
        let mut balances    = Balances::default();
        let mut nonces      = Nonces::default();
        let mut commitments = Commitments::default();
        let mut available   = Available::default();
    
        let sender = addr_hex(&addr_from_pubkey(&signer.verifying_key().to_bytes()));
        balances.insert(sender.clone(), 1_000);
    
        let tx = Transaction::transfer(&sender, &addr(1), 10, 0);
        let salt = [2u8; 32];
        let (commit, c_hash) = make_commit(&signer, &tx, salt);
        let ciphertext = commit.encrypted_payload.clone();
        let avail = make_avail(&signer, c_hash, ciphertext);
    
        let height = chain.height + 1;
        let slot = height;
        let epoch = chain.clock.current_epoch(slot);
        let bundle_len = DEFAULT_BUNDLE_LEN;
        let proposer_id: u64 = 1;
        let (vrf_output, vrf_preout, vrf_proof) = fake_vrf_fields(proposer_id);
        let (qc, qc_hash) = make_qc(&chain, &bls_signer);

        let mut block = Block {
            header: BlockHeader {
                parent_hash: chain.tip_hash,
                height,
                txs_root: [0u8; 32],
                receipts_root: [0u8; 32],
                gas_used: 0,
                randomness: chain.tip_hash,
                reveal_set_root: [0u8; 32],
                il_root: [0u8; 32],
                exec_base_fee: chain.fee_state.exec_base,
                commit_base_fee: chain.fee_state.commit_base,
                avail_base_fee: chain.fee_state.avail_base,
                timestamp: 0,
                slot,
                epoch,
                proposer_id,
                bundle_len,
                vrf_output,
                vrf_proof,
                vrf_preout,
                view: 0,
                justify_qc_hash: qc_hash,
                signature: [0u8; 64],
            },
            transactions: vec![Tx::Commit(commit), Tx::Avail(avail)],
            reveals: vec![],
            batch_digests: vec![],
            justify_qc: qc,
        };
        let preimage = header_signing_bytes(&block.header);
        block.header.signature = signer.sign(&preimage).to_bytes();

        let res = chain.apply_block(
            &block,
            &mut balances,
            &mut nonces,
            &mut commitments,
            &mut available,
        );

        assert!(matches!(res, Err(BlockError::IntrinsicInvalid(msg)) if msg.contains("avail too early")));
        assert_eq!(available.len(), 0);
        assert_eq!(chain.height, 0);
    }
}