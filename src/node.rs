use crate::consensus::dev_loop::DevNode;
use crate::consensus::HotStuff;
use crate::crypto::bls::{verify_qc, BlsSigner, BlsSignatureBytes, BlsAggregate, vote_msg};
use crate::fees::FeeState;
use crate::p2p::{ConsensusNetwork, ConsensusMessage};
use crate::types::Vote;
// src/node.rs
use crate::mempool::{BalanceView, BlockSelectionLimits, CommitmentId, Mempool, MempoolImpl, SelectError, StateView, TxId, Batch, AdmissionError};
use crate::state::{Balances, Nonces, Commitments, Available};
use crate::chain::{ApplyResult, Chain, DEFAULT_BUNDLE_LEN};
use crate::stf::process_block;
use crate::types::{Block, Hash, HotStuffState, Pacemaker, QC, RevealTx, AvailTx, CommitTx, Tx};
use crate::mempool::encrypted::ThresholdCiphertext;
use bitvec::vec::BitVec;
use std::sync::Arc;
use std::collections::{HashMap, HashSet};
use ed25519_dalek::{SigningKey, Signer};
use crate::crypto::{addr_from_pubkey, addr_hex, hash_bytes_sha256};
use crate::codec::{header_signing_bytes, qc_commitment};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::pos::registry::{StakingConfig, Validator, ValidatorId, ValidatorSet, ValidatorStatus};
use crate::pos::schedule::ProposerSchedule;
use crate::crypto::vrf::{build_vrf_msg, vrf_eligible, SchnorrkelVrfSigner, VrfSigner, SchnorrkelVrf, VrfPubkey, VrfVerifier};
use anyhow::{Result, anyhow, bail};

#[derive(Clone)]
struct PendingVoteRetry {
    vote: Vote,
    leader_id: ValidatorId,
    due_ms: u128,
    retries: u8,
}

pub struct StateBalanceView<'a> {
    balances: &'a Balances,
}

impl<'a> BalanceView for StateBalanceView<'a> {
    fn balance_of(&self, who: &crate::types::Address) -> u64 {
        *self.balances.get(who).unwrap_or(&0)
    }
}

/// The TxIds that were selected for this block, per lane.
pub struct SelectedIds {
    pub commit: Vec<TxId>,
    pub avail:  Vec<TxId>,
    pub reveal: Vec<TxId>,
}

/// The product of block production: a block plus the IDs needed for mark_included.
pub struct BuiltBlock {
    pub block: Block,
    pub selected_ids: SelectedIds,
}

#[derive(Debug)]
pub enum ProduceError {
    Selection(SelectError),
    HeaderBuild(String),
    NotProposer {
        slot: u64,
        leader: Option<ValidatorId>,
        mine: Option<ValidatorId>,
    },
}


#[derive(Clone)]
pub struct PacemakerConfig {
    pub base_timeout_ms: u64,
    pub max_timeout_ms: u64,
    pub backoff_num: u64,
    pub backoff_den: u64,
    pub safety_num: u64,
    pub safety_den: u64,
}

#[derive(Clone)]
pub struct ConsensusConfig {
    pub genesis_qc: QC,
    pub pacemaker: PacemakerConfig,
    pub genesis_block_id: Hash,
    pub tau: f64,
}

pub struct Node {
    chain: Chain,
    balances: Balances,
    nonces: Nonces,
    commitments: Commitments,
    available: Available,
    mempool: Arc<MempoolImpl>,
    signer: SigningKey,
    proposer_pubkey: [u8; 32],
    vrf_signer: Option<SchnorrkelVrfSigner>,
    bls_signer: Option<BlsSigner>,
    hotstuff: Option<HotStuff>,
    consensus_network: Option<ConsensusNetwork>,
    /// Ephemeral store of proposed blocks by header id for commit on QC
    block_store: HashMap<Hash, Block>,
    /// Last view this node proposed in (to avoid multi-proposing per view)
    last_proposed_view: Option<u64>,
    /// Pending commit targets (header ids) awaiting prerequisites (block/parent)
    pending_commits: HashSet<Hash>,
    /// Last error when trying to apply a committed block (for debug)
    last_apply_error: Option<String>,
    /// Pending vote retries (single fast retry)
    pending_vote_retries: Vec<PendingVoteRetry>,
    /// Last observed proposal view (from any proposer)
    last_observed_proposal_view: Option<u64>,
    /// Per-leader miss counters within a sliding window (ms since epoch)
    leader_miss: HashMap<ValidatorId, (u32, u128)>,
    /// Avoid repeating early-skip within the same view
    last_early_skip_view: Option<u64>,
    /// Debug: last reason we skipped voting on a proposal, and at which view
    last_vote_skip_reason: Option<String>,
    last_vote_skip_view: Option<u64>,
    /// Buffered QCs waiting for their certified block header
    pending_qcs: HashMap<Hash, Vec<QC>>,
    /// Tracks which block_ids we've already requested from peers
    requested_blocks: HashSet<Hash>,
}

struct NodeStateView<'a> {
    chain: &'a Chain,
    nonces: &'a Nonces,
    mempool: &'a MempoolImpl,
}

impl<'a> StateView for NodeStateView<'a> {
    fn current_height(&self) -> u64 {
        self.chain.height
    }

    fn commitments_due_and_available(&self, h: u64) -> Vec<CommitmentId> {
        self
            .chain
            .commitments_due_and_available(h)
            .into_iter()
            .map(CommitmentId)
            .collect()
    }

    fn reveal_nonce_required(&self, sender: &str) -> u64 {
        *self.nonces.get(sender).unwrap_or(&0)
    }

    fn commit_on_chain(&self, c: CommitmentId) -> bool {
        self.chain.commit_on_chain(&c.0)
    }

    fn avail_on_chain(&self, c: CommitmentId) -> bool {
        self.chain.avail_on_chain(&c.0)
    }

    fn avail_allowed_at(&self, height: u64, c: CommitmentId) -> bool {
        self.chain.avail_allowed_at(height, &c.0)
    }

    fn pending_commit_room(&self, sender: &str) -> u32 {
        let used = self.mempool.pending_commits_for_sender(sender);
        self.mempool.config().max_pending_commits_per_account.saturating_sub(used)
    }
}

impl Node {
    /// Stake-weighted leader for a HotStuff view. Uses the epoch proposer schedule
    /// indexed by `view`; falls back to simple round-robin over validator ids by `view`.
    pub(crate) fn leader_for_view(&self, view: u64) -> ValidatorId {
        if let Some(vid) = self.chain.schedule.leader_for_view(view) { return vid; }
        let n = self.chain.validator_set.validators.len();
        if n == 0 { 0 } else { (view as usize % n) as ValidatorId }
    }
    #[inline]
    fn now_ms() -> u128 { (Self::now_ts() as u128) * 1000 }

    fn schedule_vote_retry(&mut self, vote: Vote, leader_id: ValidatorId, delay_ms: u64) {
        let due = Self::now_ms().saturating_add(delay_ms as u128);
        self.pending_vote_retries.push(PendingVoteRetry { vote, leader_id, due_ms: due, retries: 0 });
    }

    fn process_pending_vote_retries(&mut self) {
        if self.pending_vote_retries.is_empty() { return; }
        let now = Self::now_ms();
        let mut next: Vec<PendingVoteRetry> = Vec::with_capacity(self.pending_vote_retries.len());
        let high_view = self.hotstuff.as_ref().map(|h| h.state.high_qc.view).unwrap_or(0);
        // Move out the current retry queue to avoid borrowing self during iteration
        let current = std::mem::take(&mut self.pending_vote_retries);
        for mut pv in current.into_iter() {
            // Drop if QC for this view has been observed
            if high_view >= pv.vote.view { continue; }
            // Retry schedule: ~100ms, 250ms, 500ms (cap total retries to 3)
            const DELAYS: [u64; 3] = [100, 250, 500];
            if now >= pv.due_ms && (pv.retries as usize) < DELAYS.len() {
                // Refresh leader in case schedule changed for this view+1
                let target_leader = self.leader_for_view(pv.vote.view + 1);
                if let Some(net) = self.consensus_network.as_ref() {
                    let _ = net.send_vote(pv.vote.clone(), target_leader);
                }
                pv.leader_id = target_leader;
                // Schedule next retry if any remain
                pv.retries += 1;
                if (pv.retries as usize) < DELAYS.len() {
                    pv.due_ms = now.saturating_add(DELAYS[pv.retries as usize] as u128);
                }
            }
            next.push(pv);
        }
        self.pending_vote_retries = next;
    }
    pub fn new(mempool: Arc<MempoolImpl>, signer: SigningKey) -> Self {
        let proposer_pubkey = signer.verifying_key().to_bytes();
        Self {
            chain: Chain::new(),
            balances: Default::default(),
            nonces: Default::default(),
            commitments: Default::default(),
            available: Default::default(),
            mempool,
            signer,
            proposer_pubkey,
            vrf_signer: None,
            bls_signer: None,
            hotstuff: None,
            consensus_network: None,
            block_store: HashMap::new(),
            last_proposed_view: None,
            pending_commits: HashSet::new(),
            last_apply_error: None,
            pending_vote_retries: Vec::new(),
            last_observed_proposal_view: None,
            leader_miss: HashMap::new(),
            last_early_skip_view: None,
            last_vote_skip_reason: None,
            last_vote_skip_view: None,
            pending_qcs: HashMap::new(),
            requested_blocks: HashSet::new(),
        }
    }

    pub fn new_with_consensus(
        mempool: Arc<MempoolImpl>,
        ed25519: SigningKey,
        consensus_cfg: ConsensusConfig,
        bls_sk: Option<[u8; 32]>,
        my_validator_id: Option<ValidatorId>,
    ) -> Result<Self> {
        let mut node = Self::new(mempool, ed25519);
        node.chain.tau = consensus_cfg.tau;

        // Active-set BLS pubkeys (stable index order)
        let active_bls_pks: Vec<[u8; 48]> = node
            .collect_active_bls_pubkeys_in_order()
            .map_err(|e| anyhow!("failed to collect active BLS pubkeys: {e}"))?;
        if active_bls_pks.is_empty() {
            bail!("active validator set is empty");
        }

        // Resolve my id
        let my_id: ValidatorId = if let Some(id) = my_validator_id {
            id
        } else {
            node.resolve_my_validator_id()
                .map_err(|e| anyhow!("unable to resolve this node's ValidatorId: {e}"))?
        };
        if (my_id as usize) >= active_bls_pks.len() {
            bail!("my_validator_id {} out of range (n={})", my_id, active_bls_pks.len());
        }

        // Optional BLS signer
        let bls_signer: Option<BlsSigner> = match bls_sk {
            Some(sk) => BlsSigner::from_sk_bytes(&sk),
            None => None,
        };

        // --- Membership check (implemented) ---
        // Consider this node "active" if its id is within the active set
        // and the advertised pubkey at that index is not the all-zero default.
        let i_am_active = {
            let idx = my_id as usize;
            let pk = active_bls_pks[idx];
            pk != [0u8; 48]
        };
        if i_am_active && bls_signer.is_none() {
            bail!("node is in active set (id={}) but has no BLS secret key", my_id);
        }

        // Seed from SlotClock/time (uses Chain helpers implemented below)
        let current_view: u64 = node.chain.current_slot();
        let tip_hash: Hash = node.chain.tip_hash;
        let locked_block: (Hash, u64) = (tip_hash, current_view);

        // Genesis binding & QC verification
        if consensus_cfg.genesis_qc.block_id != consensus_cfg.genesis_block_id || consensus_cfg.genesis_qc.view != 0 {
            bail!("genesis_qc does not certify the configured genesis_block_id/view=0");
        }
        verify_qc(
            &consensus_cfg.genesis_qc.block_id,
            consensus_cfg.genesis_qc.view,
            &consensus_cfg.genesis_qc.agg_sig,
            &consensus_cfg.genesis_qc.bitmap,
            &active_bls_pks,
        ).map_err(|e| anyhow!("invalid genesis_qc: {:?}", e))?;

        // Prefer persisted high_qc if available (and valid)
        let mut high_qc = consensus_cfg.genesis_qc.clone();
        if let Some(best) = node.load_best_qc_from_store()? {
            verify_qc(&best.block_id, best.view, &best.agg_sig, &best.bitmap, &active_bls_pks)
                .map_err(|e| anyhow!("persisted high_qc failed verification: {:?}", e))?;
            if best.view > high_qc.view {
                high_qc = best;
            }
        }

        // Pacemaker from config; start timer from Chain clock
        let pmc = &consensus_cfg.pacemaker;
        let mut pacemaker = Pacemaker::new(
            pmc.base_timeout_ms,
            pmc.max_timeout_ms,
            pmc.backoff_num,
            pmc.backoff_den,
            pmc.safety_num,
            pmc.safety_den,
        );
        pacemaker.on_enter_view(node.chain.now_ts()); // ms since epoch as u128

        let hs_state = HotStuffState { current_view, locked_block, high_qc, pacemaker };

        let hs = HotStuff::new(hs_state, active_bls_pks, my_id, bls_signer.clone());
        node.hotstuff = Some(hs);
        node.bls_signer = bls_signer;

        Ok(node)
    }

    /// Return BLS pubkeys of the *active* validator set in **stable index order**.
    fn collect_active_bls_pubkeys_in_order(&self) -> Result<Vec<[u8;48]>> {
        let vs = &self.chain.validator_set;
        let mut out = Vec::with_capacity(vs.validators.len());
        for (idx, v) in vs.validators.iter().enumerate() {
            // Consider active if `status` is Active; else skip.
            let active = v.status == ValidatorStatus::Active;
            if !active { continue; }

            let pk = v.bls_pubkey.ok_or_else(|| {
                anyhow!("active validator at index {} missing bls_pubkey", idx)
            })?;
            out.push(pk);
        }
        Ok(out)
    }

    /// Resolve my ValidatorId from the registry, e.g., by matching my Ed25519 pubkey.
    fn resolve_my_validator_id(&self) -> Result<ValidatorId> {
        let me = self.proposer_pubkey; // [u8;32]
        let vs = &self.chain.validator_set;

        for (idx, v) in vs.validators.iter().enumerate() {
            if v.ed25519_pubkey == me {
                return Ok(idx as ValidatorId);
            }
        }
        Err(anyhow!("local Ed25519 pubkey not found in validator set").into())
    }

    fn load_best_qc_from_store(&self) -> Result<Option<QC>> {
        Ok(None)
    }

    pub fn align_clock_for_test(&mut self) {
        // Use chain-level millisecond clock to avoid second-boundary drift in tests
        let now_ms: u128 = self.chain.now_ts();
        let slot_ms = self.chain.clock.slot_ms as u128;
        let desired_slot = self.chain.height + 1;
        self.chain.clock.genesis_unix_ms = now_ms.saturating_sub(slot_ms * desired_slot as u128);
    }

    /// Production: set a real VRF signer (sr25519) loaded from secure storage.
    pub fn set_vrf_signer(&mut self, vrf: SchnorrkelVrfSigner) {
        self.vrf_signer = Some(vrf);
    }

    /// Convenience: builder-style hook if you prefer chaining.
    pub fn with_vrf_signer(mut self, vrf: SchnorrkelVrfSigner) -> Self {
        self.vrf_signer = Some(vrf);
        self
    }

    /// Set the consensus network for this node
    pub fn set_consensus_network(&mut self, network: ConsensusNetwork) {
        self.consensus_network = Some(network);
    }

    /// Get the consensus network (if set)
    pub fn consensus_network(&self) -> Option<&ConsensusNetwork> {
        self.consensus_network.as_ref()
    }

    /// Get mutable reference to HotStuff state (for testing)
    pub fn hotstuff_mut(&mut self) -> Option<&mut HotStuff> {
        self.hotstuff.as_mut()
    }

    /// Get reference to HotStuff state (for testing)
    pub fn hotstuff(&self) -> Option<&HotStuff> {
        self.hotstuff.as_ref()
    }

    /// Set HotStuff instance (for testing)
    pub fn set_hotstuff(&mut self, hotstuff: HotStuff) {
        self.hotstuff = Some(hotstuff);
    }

    /// Apply a committed block identified by its header id (as returned by HotStuff 2-chain rule)
    fn apply_committed_block(&mut self, commit_id: Hash) -> Result<(), String> {
        if commit_id == [0u8; 32] {
            // No-op: genesis has no concrete block to apply.
            return Ok(());
        }
        let block = match self.block_store.get(&commit_id) {
            Some(b) => b.clone(),
            None => {
                // We have not yet received the proposal for this block; defer.
                self.pending_commits.insert(commit_id);
                return Ok(());
            }
        };

        // If this block's height is already applied (or older), discard any pending entry.
        if block.header.height <= self.chain.height {
            self.pending_commits.remove(&commit_id);
            return Ok(());
        }

        // Apply only in-order and on the current tip.
        if block.header.parent_hash != self.chain.tip_hash {
            self.pending_commits.insert(commit_id);
            return Ok(()); // wait until parent is applied
        }
        if block.header.height != self.chain.height + 1 {
            self.pending_commits.insert(commit_id);
            return Ok(()); // not the next height, wait
        }

        // Ensure the batch payload referenced by this block exists locally.
        if !block.batch_digests.is_empty() {
            let parent_count = block.batch_digests.len().saturating_sub(1);
            let parents = if parent_count > 0 {
                block.batch_digests[..parent_count].to_vec()
            } else { Vec::new() };
            if let Some(&expected_id) = block.batch_digests.last() {
                if self.chain.batch_store.get(&expected_id).is_none() {
                    let batch = Batch::new(block.transactions.clone(), parents, block.header.proposer_id, [0u8; 64]);
                    if batch.id == expected_id {
                        self.chain.batch_store.insert(batch);
                    } else {
                        // Batch payload mismatch; cannot apply yet.
                        self.pending_commits.insert(commit_id);
                        return Ok(());
                    }
                }
            }
        }

        // Apply and verify. This mutates chain.tip_hash, height, fees, and writes to balances/nonces/etc.
        match self
            .chain
            .apply_block(&block, &mut self.balances, &mut self.nonces, &mut self.commitments, &mut self.available)
        {
            Ok(_res) => {
                self.last_apply_error = None;
            }
            Err(e) => {
                let msg = format!("apply_block failed: {:?}", e);
                self.last_apply_error = Some(msg.clone());
                return Err(msg);
            }
        }

        // Best-effort mempool maintenance: mark included txs and revalidate
        let mut included: Vec<TxId> = Vec::new();
        for tx in &block.transactions {
            match tx {
                Tx::Commit(c) => {
                    let enc = crate::codec::tx_enum_bytes(&Tx::Commit(c.clone()));
                    included.push(TxId(crate::crypto::hash_bytes_sha256(&enc)));
                }
                Tx::Avail(a) => {
                    let enc = crate::codec::tx_enum_bytes(&Tx::Avail(a.clone()));
                    included.push(TxId(crate::crypto::hash_bytes_sha256(&enc)));
                }
                _ => {}
            }
        }
        for r in &block.reveals {
            let mut buf = crate::codec::tx_bytes(&r.tx);
            buf.extend_from_slice(&r.salt);
            included.push(TxId(crate::crypto::hash_bytes_sha256(&buf)));
        }
        if !included.is_empty() {
            self.mempool.mark_included(&included, self.chain.height);
        }
        let view = StateBalanceView { balances: &self.balances };
        self.mempool.revalidate_affordability(&view, &self.chain.fee_state);
        self.mempool.evict_stale(self.chain.height);
        // Applied successfully; remove from pending and try cascade
        self.pending_commits.remove(&commit_id);
        self.try_apply_pending_commits();
        Ok(())
    }

    /// Ask peers for a missing block (best-effort). Deduplicated per block id.
    fn request_block(&mut self, block_id: Hash) {
        if self.requested_blocks.contains(&block_id) { return; }
        if let Some(net) = self.consensus_network.as_ref() {
            let _ = net.broadcast_block_request(block_id);
            self.requested_blocks.insert(block_id);
        }
    }

    /// Lightweight proposer eligibility check that returns a debug reason.
    fn header_eligibility_check(&self, header: &crate::types::BlockHeader) -> Result<(), String> {
        // Epoch must match the clock for the given slot
        let expected_epoch = self.chain.clock.current_epoch(header.slot);
        if header.epoch != expected_epoch { return Err("wrong_epoch".into()); }

        // Bundle length sanity (bound to our configured default)
        if header.bundle_len == 0 || header.bundle_len != crate::chain::DEFAULT_BUNDLE_LEN { return Err("bad_bundle_len".into()); }

        let bundle_start = self.chain.clock.bundle_start(header.slot, header.bundle_len);

        // Lookup proposer in current validator set
        let v = match self.chain.validator_set.get(header.proposer_id) {
            Some(v) => v,
            None => return Err("unknown_proposer".into()),
        };

        if header.vrf_proof.is_empty() {
            // Alias fallback path: proposer must match schedule
            match self.chain.schedule.fallback_leader_for_bundle(bundle_start) {
                Some(expected) if expected == header.proposer_id => Ok(()),
                _ => Err("fallback_mismatch".into()),
            }
        } else {
            // VRF path: verify proof and threshold eligibility
            let msg = build_vrf_msg(&self.chain.epoch_seed, bundle_start, header.proposer_id);
            if !SchnorrkelVrf::vrf_verify(&VrfPubkey(v.vrf_pubkey), &msg, &header.vrf_output, &header.vrf_preout, &header.vrf_proof) {
                return Err("bad_vrf".into());
            }
            let total = self.chain.validator_set.total_stake();
            if vrf_eligible(v.stake, total, &header.vrf_output, self.chain.tau) { Ok(()) } else { Err("vrf_not_eligible".into()) }
        }
    }

    /// Convenience wrapper used by tests: returns true if the header passes eligibility checks.
    pub fn header_is_eligible(&self, header: &crate::types::BlockHeader) -> bool {
        self.header_eligibility_check(header).is_ok()
    }

    /// Attempt to apply any pending commits that have become applicable.
    fn try_apply_pending_commits(&mut self) {
        // First: drop any stale commit ids whose blocks we now know are at/below current height.
        let cur_h = self.chain.height;
        let stale: Vec<Hash> = self
            .pending_commits
            .iter()
            .copied()
            .filter(|h| self.block_store.get(h).map_or(false, |b| b.header.height <= cur_h))
            .collect();
        for h in stale { self.pending_commits.remove(&h); }

        loop {
            let pend: Vec<Hash> = self.pending_commits.iter().copied().collect();
            let mut progressed = false;
            for h in pend {
                let before = self.pending_commits.contains(&h);
                let _ = self.apply_committed_block(h);
                let after = self.pending_commits.contains(&h);
                if before && !after {
                    progressed = true;
                }
            }
            if !progressed { break; }
        }
    }

    /// Process incoming consensus messages from the network
    pub fn process_consensus_messages(&mut self) -> Result<Vec<Hash>, String> {
        let mut committed_blocks = Vec::new();
        
        // Collect all messages first to avoid borrowing conflicts
        let mut messages = Vec::new();
        if let Some(network) = self.consensus_network.as_ref() {
            while let Some(msg) = network.try_recv_message() {
                messages.push(msg);
            }
        }
        
        // Process any due vote retries first to reduce tails
        self.process_pending_vote_retries();

        // Now process all collected messages
        for msg in messages {
            match msg {
                ConsensusMessage::Proposal { block, parent, sender_id } => {
                    // If sender included the parent block, store/validate it first
                    if let Some(ref pb) = parent {
                        if let Err(e) = self.handle_proposal(pb, sender_id) {
                            eprintln!("Error handling parent proposal from {}: {}", sender_id, e);
                        }
                    }
                    if let Err(e) = self.handle_proposal(&block, sender_id) {
                        eprintln!("Error handling proposal from {}: {}", sender_id, e);
                    }
                }
                ConsensusMessage::Vote { vote, leader_id: _ , sender_id } => {
                    if let Some(committed) = self.handle_vote(vote, sender_id)? {
                        if let Err(e) = self.apply_committed_block(committed) {
                            eprintln!("Failed to apply committed block: {}", e);
                        }
                        self.try_apply_pending_commits();
                        committed_blocks.push(committed);
                    }
                }
                ConsensusMessage::QC { qc, sender_id } => {
                    if let Some(committed) = self.handle_qc(qc, sender_id)? {
                        if let Err(e) = self.apply_committed_block(committed) {
                            eprintln!("Failed to apply committed block from QC: {}", e);
                        }
                        self.try_apply_pending_commits();
                        committed_blocks.push(committed);
                    }
                }
                ConsensusMessage::BlockRequest { block_id, sender_id: _ } => {
                    if let Some(b) = self.block_store.get(&block_id).cloned() {
                        if let Some(net) = self.consensus_network.as_ref() {
                            let _ = net.broadcast_block_response(b);
                        }
                    }
                }
                ConsensusMessage::BlockResponse { block, sender_id: _ } => {
                    let bid = crate::codec::header_id(&block.header);
                    self.block_store.entry(bid).or_insert_with(|| block.clone());
                    if let Some(hs) = self.hotstuff.as_mut() { hs.observe_block_header(&block.header); }
                    if let Some(mut qcs) = self.pending_qcs.remove(&bid) {
                        let mut commits: Vec<Hash> = Vec::new();
                        if let Some(hs) = self.hotstuff.as_mut() {
                            let now_ms = (Self::now_ts() as u128) * 1000;
                            for qc in qcs.drain(..) {
                                if let Ok(Some(committed)) = hs.on_qc_self(qc, now_ms) { commits.push(committed); }
                            }
                        }
                        for committed in commits {
                            if let Err(e) = self.apply_committed_block(committed) {
                                eprintln!("Failed to apply committed block from buffered QC: {}", e);
                            }
                            self.try_apply_pending_commits();
                            committed_blocks.push(committed);
                        }
                    }
                }
                ConsensusMessage::ViewChange { view, sender_id, timeout_qc } => {
                    self.handle_view_change(view, sender_id, timeout_qc)?;
                }
                ConsensusMessage::SlashEvidence(e) => {
                    // Validate and apply slashing
                    let cfg = StakingConfig { min_stake: 1, unbonding_epochs: 1, max_validators: u32::MAX };
                    if let Err(err) = self.chain.apply_slash(&e, &cfg) {
                        eprintln!("Ignoring invalid slashing evidence: {}", err);
                    }
                }
            }
        }
        
        Ok(committed_blocks)
    }

    /// Process a single consensus message (new async-driven path)
    pub fn process_consensus_message(&mut self, msg: crate::p2p::ConsensusMessage) -> Result<Vec<Hash>, String> {
        let mut committed_blocks = Vec::new();
        match msg {
            crate::p2p::ConsensusMessage::Proposal { block, parent, sender_id } => {
                if let Some(ref pb) = parent {
                    if let Err(e) = self.handle_proposal(pb, sender_id) {
                        eprintln!("Error handling parent proposal from {}: {}", sender_id, e);
                    }
                }
                if let Err(e) = self.handle_proposal(&block, sender_id) {
                    eprintln!("Error handling proposal from {}: {}", sender_id, e);
                }
            }
            crate::p2p::ConsensusMessage::Vote { vote, leader_id: _, sender_id } => {
                if let Some(committed) = self.handle_vote(vote, sender_id)? {
                    if let Err(e) = self.apply_committed_block(committed) {
                        eprintln!("Failed to apply committed block: {}", e);
                    }
                    self.try_apply_pending_commits();
                    committed_blocks.push(committed);
                }
            }
            crate::p2p::ConsensusMessage::QC { qc, sender_id } => {
                if let Some(committed) = self.handle_qc(qc, sender_id)? {
                    if let Err(e) = self.apply_committed_block(committed) {
                        eprintln!("Failed to apply committed block from QC: {}", e);
                    }
                    self.try_apply_pending_commits();
                    committed_blocks.push(committed);
                }
            }
            crate::p2p::ConsensusMessage::BlockRequest { block_id, sender_id: _ } => {
                if let Some(b) = self.block_store.get(&block_id).cloned() {
                    if let Some(net) = self.consensus_network.as_ref() {
                        let _ = net.broadcast_block_response(b);
                    }
                }
            }
            crate::p2p::ConsensusMessage::BlockResponse { block, sender_id: _ } => {
                let bid = crate::codec::header_id(&block.header);
                self.block_store.entry(bid).or_insert_with(|| block.clone());
                if let Some(hs) = self.hotstuff.as_mut() { hs.observe_block_header(&block.header); }
                if let Some(mut qcs) = self.pending_qcs.remove(&bid) {
                    let mut commits: Vec<Hash> = Vec::new();
                    if let Some(hs) = self.hotstuff.as_mut() {
                        let now_ms = (Self::now_ts() as u128) * 1000;
                        for qc in qcs.drain(..) {
                            if let Ok(Some(committed)) = hs.on_qc_self(qc, now_ms) { commits.push(committed); }
                        }
                    }
                    for committed in commits {
                        if let Err(e) = self.apply_committed_block(committed) {
                            eprintln!("Failed to apply committed block from buffered QC: {}", e);
                        }
                        self.try_apply_pending_commits();
                        committed_blocks.push(committed);
                    }
                }
            }
            crate::p2p::ConsensusMessage::ViewChange { view, sender_id, timeout_qc } => {
                self.handle_view_change(view, sender_id, timeout_qc)?;
            }
            crate::p2p::ConsensusMessage::SlashEvidence(e) => {
                let cfg = StakingConfig { min_stake: 1, unbonding_epochs: 1, max_validators: u32::MAX };
                if let Err(err) = self.chain.apply_slash(&e, &cfg) {
                    eprintln!("Ignoring invalid slashing evidence: {}", err);
                }
            }
        }
        Ok(committed_blocks)
    }

    /// Handle an incoming block proposal
    fn handle_proposal(&mut self, block: &Block, sender_id: ValidatorId) -> Result<(), String> {
        // 1) HotStuff header observation and validation
        if let Some(hs) = self.hotstuff.as_mut() {
            let now_ms = (Self::now_ts() as u128) * 1000;
            hs.observe_block_header(&block.header);
            if let Err(e) = hs.on_block_proposal(block, now_ms) {
                // Broadcast any accumulated evidence even on error
                if let Some(net) = self.consensus_network.as_ref() {
                    for ev in hs.drain_evidence() {
                        let _ = net.broadcast_slash_evidence(ev);
                    }
                } else {
                    // Drain even if no network to avoid duplication
                    let _ = hs.drain_evidence();
                }
                return Err(format!("Block proposal validation failed: {:?}", e));
            }
            // Broadcast any evidence collected during validation
            if let Some(net) = self.consensus_network.as_ref() {
                for ev in hs.drain_evidence() {
                    let _ = net.broadcast_slash_evidence(ev);
                }
            } else {
                let _ = hs.drain_evidence();
            }
        }
        // Track observed proposals to suppress early-skip
        self.last_observed_proposal_view = Some(block.header.view);

        // 2) Store the block and ensure batch payloads exist locally
        let bid = crate::codec::header_id(&block.header);
        self.block_store.insert(bid, block.clone());
        if !block.batch_digests.is_empty() {
            let parent_count = block.batch_digests.len().saturating_sub(1);
            let parents = if parent_count > 0 { block.batch_digests[..parent_count].to_vec() } else { Vec::new() };
            if let Some(&expected_id) = block.batch_digests.last() {
                let batch = Batch::new(block.transactions.clone(), parents, block.header.proposer_id, [0u8; 64]);
                if batch.id == expected_id {
                    if self.chain.batch_store.get(&batch.id).is_none() {
                        self.chain.batch_store.insert(batch);
                    }
                } else {
                    eprintln!(
                        "Warning: batch id mismatch for proposed block: expected {}, computed {}",
                        hex::encode(expected_id),
                        hex::encode(batch.id)
                    );
                }
            }
        }

        // 3) If any QCs were buffered for this block, replay them now that we have the header
        if let Some(mut qcs) = self.pending_qcs.remove(&bid) {
            let mut commits: Vec<Hash> = Vec::new();
            if let Some(hs) = self.hotstuff.as_mut() {
                let now_ms = (Self::now_ts() as u128) * 1000;
                for qc in qcs.drain(..) {
                    if let Ok(Some(committed)) = hs.on_qc_self(qc, now_ms) {
                        commits.push(committed);
                    }
                }
            }
            for committed in commits {
                if let Err(e) = self.apply_committed_block(committed) {
                    eprintln!("Failed to apply committed block via buffered QC: {}", e);
                }
                self.try_apply_pending_commits();
            }
        }

        // Additionally, now that we've indexed the header, try to commit using the best QC
        if let Some(hs) = self.hotstuff.as_mut() {
            let now_ms = (Self::now_ts() as u128) * 1000;
            if let Ok(Some(committed)) = hs.on_qc_self(hs.state.high_qc.clone(), now_ms) {
                if let Err(e) = self.apply_committed_block(committed) {
                    eprintln!("Failed to apply committed block via high_qc refresh: {}", e);
                }
                self.try_apply_pending_commits();
            }
        }

        // 4) Generate and send vote if we should vote on this proposal
        // Before voting, ensure the header is proposer-eligible under VRF/schedule rules.
        // Perform this check BEFORE mutably borrowing HotStuff to avoid borrow conflicts.
        if let Err(reason) = self.header_eligibility_check(&block.header) {
            // Do not vote for ineligible proposals; they would create QCs that
            // cannot be applied, stalling height under load.
            self.last_vote_skip_reason = Some(reason.clone());
            self.last_vote_skip_view = Some(block.header.view);
            return Ok(());
        }
        if let Some(hs) = self.hotstuff.as_mut() {
            if let Some(vote) = hs.maybe_vote_self(&block) {
                if let Some(qc) = hs.on_vote(vote.clone()) {
                    if let Some(network) = self.consensus_network.as_ref() {
                        if let Err(e) = network.broadcast_qc(qc.clone()) {
                            eprintln!("Failed to broadcast QC: {}", e);
                        }
                    }
                    let now_ms = (Self::now_ts() as u128) * 1000;
                    let _ = hs.on_qc_self(qc, now_ms);
                }
                let next_leader = self.leader_for_view(vote.view + 1);
                if let Some(network) = self.consensus_network.as_ref() {
                    if let Err(e) = network.send_vote(vote.clone(), next_leader) {
                        eprintln!("Failed to send vote: {}", e);
                    }
                    // Schedule one fast retry (~100ms) if no QC yet
                    self.schedule_vote_retry(vote, next_leader, 100);
                }
            }
        }
        // Now that any borrows have ended, try cascading pending commits
        self.try_apply_pending_commits();
        Ok(())
    }

    /// Handle an incoming vote (only leaders aggregate votes)
    fn handle_vote(&mut self, vote: Vote, sender_id: ValidatorId) -> Result<Option<Hash>, String> {
        if let Some(hotstuff) = self.hotstuff.as_mut() {
            // Aggregate votes regardless of whether we believe we are the leader.
            // In this devnet, any node that reaches quorum will broadcast the QC.
            let qc_opt = hotstuff.on_vote(vote);
            // Broadcast any slashing evidence generated by duplicate-vote detection
            if let Some(net) = self.consensus_network.as_ref() {
                for ev in hotstuff.drain_evidence() {
                    let _ = net.broadcast_slash_evidence(ev);
                }
            } else {
                let _ = hotstuff.drain_evidence();
            }
            if let Some(qc) = qc_opt {
                if let Some(network) = self.consensus_network.as_ref() {
                    network.broadcast_qc(qc.clone())
                        .map_err(|e| format!("Failed to broadcast QC: {}", e))?;
                }
                let now_ms = (Self::now_ts() as u128) * 1000;
                return Ok(hotstuff.on_qc_self(qc, now_ms)
                    .map_err(|e| format!("Failed to process QC: {:?}", e))?);
            }
        }
        Ok(None)
    }

    /// Handle an incoming QC
    fn handle_qc(&mut self, qc: QC, sender_id: ValidatorId) -> Result<Option<Hash>, String> {
        if let Some(hs) = self.hotstuff.as_mut() {
            let now_ms = (Self::now_ts() as u128) * 1000;
            // Measure elapsed time in the view we are leaving (before pacemaker resets)
            let prev_view_start = hs.state.pacemaker.view_start_ms;
            let measured = now_ms.saturating_sub(prev_view_start) as u64;

            // Ensure HotStuff knows the parent link for the certified block if we have it locally.
            // This allows the 2-chain commit rule to produce a commit target even if the QC arrives
            // before we processed the corresponding proposal message.
            if let Some(b) = self.block_store.get(&qc.block_id) {
                hs.observe_block_header(&b.header);
            } else {
                // Missing certified block: request from peers and buffer the QC for retry
                self.request_block(qc.block_id);
                self.pending_qcs.entry(qc.block_id).or_default().push(qc);
                return Ok(None);
            }

            let res = hs
                .on_qc_self(qc, now_ms)
                .map_err(|e| format!("Failed to process QC: {:?}", e))?;

            // Snapshot leader info for the new view and drop the borrow
            let next_view = hs.state.current_view;
            let my_id = hs.validator_id;
            let n = hs.validator_pks.len();
            // Feed observed latency into pacemaker (will affect subsequent views)
            hs.state.pacemaker.observe_qc_latency(measured);
            drop(hs);

            // If I'm the leader for the current view and haven't proposed yet, propose immediately
            let leader = self.leader_for_view(next_view);
            if my_id == leader && self.last_proposed_view != Some(next_view) {
                // Ignore errors here; even if selection fails, regular producer will try soon.
                let _ = self.produce_block(crate::consensus::dev_loop::DEFAULT_LIMITS);
            }

            return Ok(res);
        }
        Ok(None)
    }

    /// Handle a view change message
    fn handle_view_change(&mut self, view: u64, sender_id: ValidatorId, timeout_qc: Option<QC>) -> Result<(), String> {
        if let Some(hotstuff) = self.hotstuff.as_mut() {
            // If we receive a valid timeout QC, we might need to advance our view
            if let Some(qc) = timeout_qc {
                let now_ms = (Self::now_ts() as u128) * 1000;
                let _ = hotstuff.on_qc_self(qc, now_ms);
            }
            // View synchronization: adopt next view if peers timed out at >= our current view
            let now_ms = (Self::now_ts() as u128) * 1000;
            let cur = hotstuff.state.current_view;
            if view >= cur {
                // Advance to view+1 and reset pacemaker
                hotstuff.state.current_view = view + 1;
                hotstuff.state.pacemaker.on_enter_view(now_ms);
                // If we're the leader for the new view and haven't proposed, do it now
                let next_view = hotstuff.state.current_view;
                let my_id = hotstuff.validator_id;
                // Drop borrow before computing leader/proposing
                drop(hotstuff);
                let leader = self.leader_for_view(next_view);
                if my_id == leader && self.last_proposed_view != Some(next_view) {
                    let _ = self.produce_block(crate::consensus::dev_loop::DEFAULT_LIMITS);
                }
            }
        }
        Ok(())
    }

    /// Check for pacemaker timeouts and advance view if necessary
    pub fn check_pacemaker_timeout(&mut self) -> Result<(), String> {
        if self.hotstuff.is_none() { return Ok(()); }
        let now_ms = (Self::now_ts() as u128) * 1000;
        // Snapshot readonly fields for early-skip evaluation
        let (view_start, cur_timeout, base_timeout, cur_view, my_id_snapshot, high_qc_snapshot) = {
            let hs = self.hotstuff.as_ref().unwrap();
            (
                hs.state.pacemaker.view_start_ms,
                hs.state.pacemaker.current_timeout_ms,
                hs.state.pacemaker.base_timeout_ms,
                hs.state.current_view,
                hs.validator_id,
                hs.state.high_qc.clone(),
            )
        };

        // Early leader-skip hint: if no proposal observed halfway through the timeout,
        // record a miss and, on repeated misses within a short window, advance view early.
        let elapsed = now_ms.saturating_sub(view_start);
        let half = (cur_timeout / 2) as u128;
        if elapsed >= half {
            if self.last_observed_proposal_view != Some(cur_view) && self.last_early_skip_view != Some(cur_view) {
                let leader = self.leader_for_view(cur_view);
                // Sliding window: base_timeout * 4
                let window_ms = (base_timeout.saturating_mul(4)) as u128;
                let entry = self.leader_miss.entry(leader).or_insert((0, now_ms));
                if now_ms.saturating_sub(entry.1) > window_ms { *entry = (0, now_ms); }
                entry.0 = entry.0.saturating_add(1);
                if entry.0 >= 2 {
                    if self.my_validator_id().is_some() {
                        if let Some(network) = self.consensus_network.as_ref() {
                            let _ = network.broadcast_view_change(cur_view, Some(high_qc_snapshot.clone()));
                        }
                    }
                    // Advance view immediately without backoff
                    if let Some(hs2) = self.hotstuff.as_mut() {
                        let next_view = cur_view + 1;
                        hs2.state.current_view = next_view;
                        hs2.state.pacemaker.on_enter_view(now_ms);
                        self.last_early_skip_view = Some(cur_view);
                        hs2.state.pacemaker.observe_qc_latency(base_timeout);
                        let my_id = my_id_snapshot;
                        drop(hs2);
                        self.chain.record_leader_miss(leader);
                        // If we are the new leader, propose immediately
                        let leader2 = self.leader_for_view(next_view);
                        if my_id == leader2 && self.last_proposed_view != Some(next_view) {
                            let _ = self.produce_block(crate::consensus::dev_loop::DEFAULT_LIMITS);
                        }
                        return Ok(());
                    }
                }
            }
        }

        // Expiry handling and regular view advance
        let expired = {
            let hs = self.hotstuff.as_ref().unwrap();
            hs.state.pacemaker.expired(now_ms)
        };
        if expired {
            if self.my_validator_id().is_some() {
                if let Some(network) = self.consensus_network.as_ref() {
                    let (view, qc) = {
                        let hs = self.hotstuff.as_ref().unwrap();
                        (hs.state.current_view, hs.state.high_qc.clone())
                    };
                    let _ = network.broadcast_view_change(view, Some(qc));
                }
            }
        }
        let prev_view = { self.hotstuff.as_ref().unwrap().state.current_view };
        { self.hotstuff.as_mut().unwrap().on_new_slot(now_ms); }
        let next_view = { self.hotstuff.as_ref().unwrap().state.current_view };
        if next_view > prev_view {
            let my_id = { self.hotstuff.as_ref().unwrap().validator_id };
            let leader = self.leader_for_view(next_view);
            if my_id == leader && self.last_proposed_view != Some(next_view) {
                let _ = self.produce_block(crate::consensus::dev_loop::DEFAULT_LIMITS);
            }
        }
        Ok(())
    }


    /// Helper used by genesis init to fetch our VRF pubkey.
    fn my_vrf_pubkey(&self) -> [u8; 32] {
        self.vrf_signer
            .as_ref()
            .expect("VRF signer not set on Node; call set_vrf_signer() before genesis")
            .public_bytes()
    }

    pub fn install_self_as_genesis_validator(&mut self, id: ValidatorId, stake: u128) -> BlsSigner {
        // Create unique BLS key for each validator for testing
        let mut bls_key = [1u8; 32];
        bls_key[0] = (id + 10) as u8; // Make each validator have a unique key
        self.install_self_as_genesis_validator_with_key(id, stake, &bls_key)
    }

    pub fn install_self_as_genesis_validator_with_key(&mut self, id: ValidatorId, stake: u128, bls_key: &[u8; 32]) -> BlsSigner {
        let cfg = StakingConfig {
            min_stake: 1,
            unbonding_epochs: 1,
            max_validators: u32::MAX,
        };

        let bls_signer = BlsSigner::from_sk_bytes(bls_key).unwrap();
        let v = Validator {
            id,
            ed25519_pubkey: self.proposer_pubkey,
            bls_pubkey: Some(bls_signer.public_key_bytes()),
            vrf_pubkey: self.my_vrf_pubkey(),
            stake,
            status: ValidatorStatus::Active,
        };

        let set = ValidatorSet::from_genesis(0, &cfg, vec![v]);
        let seed = hash_bytes_sha256(b"l1-blockchain/test-epoch-seed:v1");
        self.chain.init_genesis(set, seed);
        self.bls_signer = Some(bls_signer.clone());
        bls_signer
    }

    /// Initialize a node with a multi-validator genesis set for testing
    pub fn init_with_shared_validator_set(&mut self, validators: Vec<Validator>, my_bls_signer: BlsSigner) {
        let cfg = StakingConfig {
            min_stake: 1,
            unbonding_epochs: 1,
            max_validators: u32::MAX,
        };

        let set = ValidatorSet::from_genesis(0, &cfg, validators);
        let seed = hash_bytes_sha256(b"l1-blockchain/test-epoch-seed:v1");
        self.chain.init_genesis(set, seed);
        self.bls_signer = Some(my_bls_signer);
    }

    #[inline]
    fn now_ts() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    /// Look up our ValidatorId in the current validator set by matching the ed25519 pubkey.
    /// Returns None if we are not part of the active snapshot.
    fn my_validator_id(&self) -> Option<ValidatorId> {
        // validator_set.validators is sorted by id; pubkeys are unique by construction
        self.chain.validator_set.validators.iter()
            .find(|v| v.ed25519_pubkey == self.proposer_pubkey)
            .map(|v| v.id)
    }

    /// Build a deterministic per-block randomness value bound to epoch seed, tip hash, height and slot.
    #[inline]
    fn derive_block_randomness(&self, next_height: u64, slot: u64) -> [u8; 32] {
        let mut buf = Vec::with_capacity(32 + 32 + 8 + 8 + 24);
        buf.extend_from_slice(b"l1-blockchain/block-randomness:v1");
        buf.extend_from_slice(&self.chain.epoch_seed);
        buf.extend_from_slice(&self.chain.tip_hash);
        buf.extend_from_slice(&next_height.to_le_bytes());
        buf.extend_from_slice(&slot.to_le_bytes());
        hash_bytes_sha256(&buf)
    }

    pub fn height(&self) -> u64 {
        self.chain.height
    }

    pub fn tip_hash(&self) -> Hash {
        self.chain.tip_hash
    }

    pub fn proposer_pubkey(&self) -> [u8; 32] {
        self.proposer_pubkey
    }

    pub fn fee_state(&self) -> &FeeState {
        &self.chain.fee_state
    }

    /// Expose the current global slot (production clock) for coordination in tests/integration.
    pub fn current_slot(&self) -> u64 { self.chain.current_slot() }

    /// Expose the configured slot duration in milliseconds.
    pub fn slot_ms(&self) -> u64 { self.chain.clock.slot_ms }

    /// Set the slot duration (milliseconds) for local/dev networks.
    pub fn set_slot_ms(&mut self, ms: u64) { self.chain.clock.slot_ms = ms; }

    /// Determine the deterministic fallback leader for the next block's bundle start.
    /// This reflects production alias scheduling and does not consider VRF winners.
    pub fn expected_leader_for_next_block(&self) -> Option<ValidatorId> {
        // Predict strictly based on chain height, not wall-clock.
        let next_slot = self.chain.height + 1;
        let bundle_start = self.chain.clock.bundle_start(next_slot, DEFAULT_BUNDLE_LEN);
        self.chain.schedule.fallback_leader_for_bundle(bundle_start)
    }

    pub fn set_commit_fee_base(&mut self, base: u64) {
        self.chain.fee_state.commit_base = base;
    }

    pub fn burned_total(&self) -> u64 {
        self.chain.burned_total
    }

    pub fn balance_of(&self, who: &str) -> u64 {
        *self.balances.get(who).unwrap_or(&0)
    }

    pub fn set_balance(&mut self, who: String, amount: u64) {
        self.balances.insert(who, amount);
    }

    pub fn rpc_insert_commit(&self, commit: CommitTx, fee_bid: u128) -> Result<TxId, AdmissionError> {
        let view = StateBalanceView { balances: &self.balances };
        self.mempool.insert_commit(
            Tx::Commit(commit),
            self.chain.height,
            fee_bid,
            &view,
            &self.chain.fee_state,
        )
    }

    pub fn rpc_insert_avail(&self, avail: AvailTx, fee_bid: u128) -> Result<TxId, AdmissionError> {
        let view = StateBalanceView { balances: &self.balances };
        self.mempool.insert_avail(
            Tx::Avail(avail),
            self.chain.height,
            fee_bid,
            &view,
            &self.chain.fee_state,
        )
    }

    pub fn rpc_insert_reveal(&self, reveal: RevealTx, fee_bid: u128) -> Result<TxId, AdmissionError> {
        let view = StateBalanceView { balances: &self.balances };
        self.mempool.insert_reveal(
            reveal,
            self.chain.height,
            fee_bid,
            &view,
            &self.chain.fee_state,
        )
    }

    // Credits `amount` directly to `addr` balance (DEV/FAUCET ONLY).
    // Returns the new balance.
    pub fn credit_balance_direct(&mut self, addr: &str, amount: u64) -> u64 {
        use std::collections::hash_map::Entry;
        match self.balances.entry(addr.to_string()) {
            Entry::Occupied(mut e) => {
                let v = e.get_mut();
                *v = v.saturating_add(amount);
                *v
            }
            Entry::Vacant(e) => {
                e.insert(amount);
                amount
            }
        }
    }

    fn simulate_block(
        &mut self,
        limits: BlockSelectionLimits,
    ) -> Result<(BuiltBlock, ApplyResult, Balances, Nonces, Commitments, Available, u64), ProduceError> {
        // ---- VORTEX: PoS gating & deterministic metadata ----
        let now_ms = self.chain.now_ts();
        let _slot_now   = self.chain.clock.current_slot(now_ms);

        // Choose parent based on consensus state if enabled; otherwise use local tip.
        // In consensus mode, we must know the parent header locally to derive a
        // deterministic child height. If we don't, skip proposing this slot and
        // wait for the parent proposal to arrive via the network.
        let (parent_hash, parent_height) = if let Some(hs) = self.hotstuff.as_ref() {
            let ph = hs.state.high_qc.block_id;
            if ph == self.chain.tip_hash {
                (ph, self.chain.height)
            } else if let Some(b) = self.block_store.get(&ph) {
                (ph, b.header.height)
            } else {
                // Parent header missing: request it and skip proposing this slot.
                // Once the block arrives (via BlockResponse/Proposal), buffered QCs
                // will allow progress.
                self.request_block(ph);
                return Err(ProduceError::HeaderBuild(
                    "awaiting high_qc parent header fetch".into()
                ));
            }
        } else {
            (self.chain.tip_hash, self.chain.height)
        };

        let next_height = parent_height.saturating_add(1);
        // Production policy: block at height h must be labeled with slot h.
        let slot   = next_height;
        let epoch  = self.chain.clock.current_epoch(slot);
    
        // Bundle start (leader elected per bundle of R slots)
        let r: u8 = DEFAULT_BUNDLE_LEN;
        let bundle_start = self.chain.clock.bundle_start(slot, r);
    
        // We must know our validator id and have a VRF signer
        let Some(proposer_id) = self.my_validator_id() else {
            return Err(ProduceError::NotProposer { slot, leader: None, mine: None });
        };
        let Some(_vrf) = &self.vrf_signer else {
            return Err(ProduceError::NotProposer { slot, leader: None, mine: Some(proposer_id) });
        };
        // Check if we are the consensus (HotStuff) leader for the current view; if so,
        // we allow proposing regardless of VRF threshold eligibility (we will include
        // a valid VRF proof so Chain verification passes). This avoids empty views.
        let am_consensus_leader: bool = if let Some(hs) = self.hotstuff.as_ref() {
            let v = hs.state.current_view;
            let my = hs.validator_id;
            let leader = self.leader_for_view(v);
            my == leader
        } else { false };

        // Build VRF message and check stake-weighted threshold
        let msg = build_vrf_msg(&self.chain.epoch_seed, bundle_start, proposer_id);
        let (mut vrf_out, mut vrf_pre, mut vrf_proof) = self
            .vrf_signer
            .as_ref()
            .map(|s| s.vrf_prove(&msg))
            .unwrap_or(([0u8; 32], [0u8; 32], Vec::new()));
        
        let me = self.chain
            .validator_set
            .get(proposer_id)
            .expect("proposer_id present in active set");
        let total = self.chain.validator_set.total_stake();

        let fallback = self
            .chain
            .schedule
            .fallback_leader_for_bundle(bundle_start);
        // Only propose if VRF-eligible OR we are the deterministic fallback leader for this bundle.
        // Do NOT rely on being the HotStuff leader alone; proposing otherwise can create
        // QCs for blocks that will later fail Chain verification and stall height.
        if !vrf_eligible(me.stake, total, &vrf_out, self.chain.tau) {
            if fallback == Some(proposer_id) {
                // Signal alias fallback by clearing VRF fields (chain will verify against schedule).
                vrf_out = [0u8; 32];
                vrf_pre = [0u8; 32];
                vrf_proof.clear();
            } else {
                // Not eligible and not fallback → don't propose this slot/view.
                return Err(ProduceError::NotProposer { slot, leader: fallback, mine: Some(proposer_id) });
            }
        }
    
        // 0) Prune stale items before building any view or selecting.
        if self.chain.height > 0 {
            self.mempool.evict_stale(self.chain.height);
        }
    
        // 1) State view for selection
        let sv = NodeStateView {
            chain:   &self.chain,
            nonces:  &self.nonces,
            mempool: &self.mempool,
        };
    
        // 2) Select candidates from mempool
        let cand = self
            .mempool
            .select_block(&sv, limits)
            .map_err(ProduceError::Selection)?;
    
        // Deterministic timestamp: start of the targeted slot
        let ts_ms  = self.chain.clock.slot_start_unix(slot);
        let ts_sec = (ts_ms / 1000) as u64;
    
        // Per-block randomness committed in header
        let randomness = self.derive_block_randomness(next_height, slot);
    
        // HotStuff view/QC: use current consensus state if enabled
        let view = self
            .hotstuff
            .as_ref()
            .map(|h| h.state.current_view)
            .unwrap_or(0);
        let (justify_qc, justify_qc_hash) = if let Some(h) = self.hotstuff.as_ref() {
            let qc = h.state.high_qc.clone();
            let hash = qc_commitment(qc.view, &qc.block_id, &qc.agg_sig, &qc.bitmap);
            (qc, hash)
        } else {
            let bls = self
                .bls_signer
                .as_ref()
                .expect("BLS signer required when HotStuff disabled");
            let msg = vote_msg(&self.chain.tip_hash, self.chain.height);
            let mut agg = BlsAggregate::new();
            let sig = bls.sign(&msg);
            agg.push(&sig.0);
            let agg_sig = agg.finalize().unwrap();
            let mut bitmap = BitVec::repeat(false, 1);
            bitmap.set(0, true);
            let qc = QC { view: self.chain.height, block_id: self.chain.tip_hash, agg_sig, bitmap };
            let hash = qc_commitment(qc.view, &qc.block_id, &qc.agg_sig, &qc.bitmap);
            (qc, hash)
        };

        // Parent chosen earlier (parent_hash)

        // 3) Build a block with an unsigned header; STF computes roots/gas then we sign
        let mut header = crate::types::BlockHeader {
            parent_hash:     parent_hash,
            height:          next_height,
            txs_root:        [0u8; 32], // filled after STF run
            receipts_root:   [0u8; 32], // filled after STF run
            gas_used:        0,         // filled after STF run
            randomness,
            reveal_set_root: [0u8; 32], // filled after STF run
            il_root:         [0u8; 32], // filled after STF run
            exec_base_fee:   self.chain.fee_state.exec_base,
            commit_base_fee: self.chain.fee_state.commit_base,
            avail_base_fee:  self.chain.fee_state.avail_base,
            timestamp:       ts_sec,

            // proposer identity / schedule
            slot,
            epoch,
            proposer_id,

            // Vortex PoS fields
            bundle_len: r,
            vrf_preout: vrf_pre,
            vrf_output: vrf_out,
            vrf_proof:  vrf_proof.clone(),

            // HotStuff/consensus fields
            view,
            justify_qc_hash: justify_qc_hash,

            signature: [0u8; 64], // filled after signing below
        };
        let mut block = crate::types::Block::new_with_reveals(
            cand.txs.clone(),
            cand.reveals.clone(),
            header,
            justify_qc,
        );
        // Package selected transactions into a batch referenced by digest.
        // The batch references the current DAG frontier as its parents so the
        // batch store maintains proper parent/child relationships.
        let parents = self.chain.batch_store.frontier();
        let batch = Batch::new(cand.txs.clone(), parents.clone(), proposer_id, [0u8; 64]);
        self.chain.batch_store.insert(batch.clone());

        // Record the digest list for this block: include parents so replicas can
        // fetch any missing batches before executing the new one.
        let mut digests = parents;
        digests.push(batch.id);
        block.batch_digests = digests;
    
        // 4) Simulate execution to compute canonical roots/gas/receipts (does not mutate Chain)
        let mut sim_balances    = self.balances.clone();
        let mut sim_nonces      = self.nonces.clone();
        let mut sim_commitments = self.commitments.clone();
        let mut sim_available   = self.available.clone();
    
        // Fee recipient: derive once from our pubkey
        let proposer_addr = addr_hex(&addr_from_pubkey(&self.proposer_pubkey));
        let mut sim_burned_total = self.chain.burned_total;
    
        let body = process_block(
            &block,
            &self.chain.batch_store,
            &mut sim_balances,
            &mut sim_nonces,
            &mut sim_commitments,
            &mut sim_available,
            &self.chain.fee_state,
            &proposer_addr,
            &mut sim_burned_total,
            &self.chain.threshold_engine,
            &self.chain,
        ).map_err(|e| ProduceError::HeaderBuild(format!("body simulation failed: {e:?}")))?;
    
        // 5) Fill header with the computed roots and gas
        block.header.txs_root        = body.txs_root;
        block.header.receipts_root   = body.receipts_root;
        block.header.reveal_set_root = body.reveal_set_root;
        block.header.il_root         = body.il_root;
        block.header.gas_used        = body.gas_total;
    
        // 6) Sign the header and attach signature
        let preimage = header_signing_bytes(&block.header);
        let sig      = self.signer.sign(&preimage).to_bytes();
        block.header.signature = sig;
    
        let apply = ApplyResult {
            receipts: body.receipts,
            gas_total: body.gas_total,
            events: body.events,
            exec_reveals_used: body.exec_reveals_used,
            commits_used: body.commits_used,
            burned_total: sim_burned_total
        };
    
        Ok((
            BuiltBlock {
                block,
                selected_ids: SelectedIds {
                    commit: cand.commit_ids,
                    avail:  cand.avail_ids,
                    reveal: cand.reveal_ids,
                },
            },
            apply,
            sim_balances,
            sim_nonces,
            sim_commitments,
            sim_available,
            sim_burned_total,
        ))
    }

    pub fn produce_block(
        &mut self,
        limits: BlockSelectionLimits,
    ) -> Result<(BuiltBlock, ApplyResult), ProduceError> {
        // In networked mode, propose at most once per view, and only if leader.
        if self.consensus_network.is_some() {
            if let Some(hs) = self.hotstuff.as_ref() {
                // In HotStuff mode, leaders are view-based; however, our production
                // alias schedule may also specify an expected proposer for the next
                // slot. Allow proposing if we match either to avoid stalls.
                let expected_view = self.leader_for_view(hs.state.current_view);
                let expected_alias = self.expected_leader_for_next_block();
                let am_view_leader = hs.validator_id == expected_view;
                let am_alias_leader = expected_alias.map_or(false, |id| id == hs.validator_id);
                if !am_view_leader && !am_alias_leader {
                    // Prefer reporting alias leader if available, else the view leader
                    let report = expected_alias.or(Some(expected_view));
                    return Err(ProduceError::NotProposer {
                        slot: self.chain.height + 1,
                        leader: report,
                        mine: Some(hs.validator_id),
                    });
                }
                if self.last_proposed_view == Some(hs.state.current_view) {
                    return Err(ProduceError::HeaderBuild("already proposed in this view".into()));
                }
                // Note: Do not require a QC for the previous view before proposing.
                // HotStuff leaders can always propose using their highest QC.
            }
        }
        let (
            built,
            apply,
            balances,
            nonces,
            commitments,
            available,
            burned_total,
        ) = self.simulate_block(limits)?;
        // In consensus (networked) mode, do NOT locally commit.
        // Let HotStuff decide commits via QCs so all replicas advance together.
        let res = if self.consensus_network.is_none() {
            self.chain
                .commit_simulated_block(
                    &built.block,
                    &apply,
                )
                .map_err(|e| ProduceError::HeaderBuild(format!("commit failed: {e:?}")))?;

            self.balances = balances;
            self.nonces = nonces;
            self.commitments = commitments;
            self.available = available;
            let _ = burned_total; // state already applied via commit_simulated_block

            let all_ids: Vec<TxId> = built
                .selected_ids
                .commit.iter()
                .chain(&built.selected_ids.avail)
                .chain(&built.selected_ids.reveal)
                .cloned()
                .collect();
            self.mempool.mark_included(&all_ids, self.chain.height);

            let view = StateBalanceView { balances: &self.balances };
            self.mempool.revalidate_affordability(&view, &self.chain.fee_state);
            self.mempool.evict_stale(self.chain.height);

            apply
        } else {
            // Networked mode: skip local commit and return the simulated ApplyResult.
            apply
        };

        // HotStuff: broadcast proposal and handle consensus
        if self.hotstuff.is_some() {
            // Validate and index header lineage before broadcast
            let now_ms = (Self::now_ts() as u128) * 1000;
            if let Some(hs) = self.hotstuff.as_mut() {
                hs.observe_block_header(&built.block.header);
                let _ = hs.on_block_proposal(&built.block, now_ms);
            }

            // Store our own proposed block so we can commit it on QC later
            let bid = crate::codec::header_id(&built.block.header);
            let stored_block = built.block.clone();
            self.block_store.insert(bid, stored_block.clone());

            // Broadcast the proposal to all validators (include parent block if available)
            if let Some(network) = self.consensus_network.as_ref() {
                let parent_opt = self.block_store.get(&built.block.header.parent_hash).cloned();
                if let Err(e) = network.broadcast_proposal(stored_block.clone(), parent_opt) {
                    eprintln!("Failed to broadcast proposal: {}", e);
                }

                // Additionally, run the standard proposal handler locally so we:
                //  - generate and count our self-vote in the local aggregator,
                //  - broadcast that vote using the same path as non-leaders.
                if let Some(hs) = self.hotstuff.as_ref() {
                    let my_id = hs.validator_id;
                    // Ignore errors here to avoid blocking liveness on local validation quirks; peers will vet too.
                    let _ = self.handle_proposal(&stored_block, my_id);
                }
            } else if let Some(hs) = self.hotstuff.as_mut() {
                // Single-process fallback: vote and drive QC locally
                if let Some(vote) = hs.maybe_vote_self(&built.block) {
                    if let Some(qc) = hs.on_vote(vote) {
                        let _ = hs.on_qc_self(qc, now_ms);
                    }
                }
                // Drain any evidence in single-process mode (no network broadcast here)
                let _ = hs.drain_evidence();
            }
        }

        // Record that we proposed in this view (networked mode)
        if self.consensus_network.is_some() {
            if let Some(hs) = self.hotstuff.as_ref() {
                self.last_proposed_view = Some(hs.state.current_view);
            }
        }
        Ok((built, res))
    }

    // ---------- Debug helpers (for RPC) ----------
    /// Snapshot HotStuff aggregators: (view, block_id, votes, quorum)
    pub fn debug_hotstuff_aggregators(&self) -> Option<Vec<(u64, Hash, usize, usize)>> {
        let hs = self.hotstuff.as_ref()?;
        let n = hs.validator_pks.len();
        let quorum = (2 * n) / 3 + 1;
        Some(hs.debug_aggregators().into_iter().map(|(v, bid, votes)| (v, bid, votes, quorum)).collect())
    }

    /// Snapshot HotStuff parent index size.
    pub fn debug_parent_index_len(&self) -> Option<usize> {
        self.hotstuff.as_ref().map(|hs| hs.debug_parent_index_len())
    }

    /// Snapshot a sample of parent links (up to `limit`).
    pub fn debug_parent_index_sample(&self, limit: usize) -> Option<Vec<(Hash, Hash)>> {
        self.hotstuff.as_ref().map(|hs| hs.debug_parent_index_sample(limit))
    }

    /// Snapshot of stored blocks (up to `limit`). Returns (id, height, view, parent, justify_view).
    pub fn debug_block_store_sample(&self, limit: usize) -> Vec<(Hash, u64, u64, Hash, u64)> {
        let mut out = Vec::new();
        for (id, b) in self.block_store.iter().take(limit) {
            out.push((*id, b.header.height, b.header.view, b.header.parent_hash, b.justify_qc.view));
        }
        out
    }

    /// Snapshot of pending commit targets.
    pub fn debug_pending_commits(&self) -> Vec<Hash> {
        self.pending_commits.iter().cloned().collect()
    }

    /// Last view we proposed in (if any).
    pub fn debug_last_proposed_view(&self) -> Option<u64> { self.last_proposed_view }

    /// Mempool counts snapshot (commits, avails, reveals)
    pub fn debug_mempool_counts(&self) -> (usize, usize, usize) {
        let (c, a, r) = self.mempool.debug_read();
        (c.by_id.len(), a.by_id.len(), r.by_id.len())
    }

    pub fn debug_last_apply_error(&self) -> Option<String> { self.last_apply_error.clone() }

    pub fn debug_last_vote_skip_reason(&self) -> Option<String> { self.last_vote_skip_reason.clone() }
    pub fn debug_last_vote_skip_view(&self) -> Option<u64> { self.last_vote_skip_view }

    /// Total number of blocks currently stored in the ephemeral block_store
    pub fn debug_block_store_len(&self) -> usize { self.block_store.len() }

}

impl DevNode for Node {
    fn height(&self) -> u64 { self.height() }

    fn produce_block(&mut self, limits: BlockSelectionLimits) -> Result<(BuiltBlock, ApplyResult), ProduceError> { Node::produce_block(self, limits) }
    
    fn now_unix(&self) -> u64 { Node::now_ts() } 
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mempool::{MempoolConfig, BlockSelectionLimits, BalanceView};
    use crate::fees::FeeState;
    use crate::types::{Transaction, Tx, CommitTx, RevealTx, Address};
    use crate::stf::PROCESS_BLOCK_CALLS;
    use crate::codec::{tx_bytes, access_list_bytes, string_bytes, header_id};
    use crate::crypto::{commitment_hash, commit_signing_preimage, addr_from_pubkey, addr_hex};
    use crate::crypto::bls::{BlsSigner, BlsAggregate, vote_msg};

    struct TestBalanceView;
    impl BalanceView for TestBalanceView {
        fn balance_of(&self, _who: &Address) -> u64 { u64::MAX }
    }

    fn addr(i: u8) -> String {
        format!("0x{:02x}{:02x}000000000000000000000000000000000000", i, i)
    }

    fn fake_vrf_fields(proposer_id: u64) -> ([u8; 32], Vec<u8>) {
        let mut out = [0u8; 32];
        // just encode proposer_id in big-endian into the first 8 bytes
        out[..8].copy_from_slice(&proposer_id.to_be_bytes());
        // "proof" is any non-empty vec; make it depend on proposer_id too
        let mut proof = Vec::with_capacity(9);
        proof.extend_from_slice(b"proof-id");
        proof.push((proposer_id & 0xFF) as u8);
        (out, proof)
    }

    fn make_pair(signer: &SigningKey, nonce: u64) -> (CommitTx, RevealTx) {
        let sender = addr_hex(&addr_from_pubkey(&signer.verifying_key().to_bytes()));
        let tx = Transaction::transfer(&sender, &addr(200), 1, nonce);
        let mut salt = [0u8; 32];
        salt[0] = 7; salt[1] = 7;
        let tx_ser = tx_bytes(&tx);
        let al_bytes = access_list_bytes(&tx.access_list);
        let commitment = commitment_hash(&tx_ser, &al_bytes, &salt, crate::state::CHAIN_ID);
        let ephemeral_pk = BlsSigner::from_sk_bytes(&[1u8; 32])
            .expect("valid sk")
            .public_key_bytes();
        let encrypted_payload = ThresholdCiphertext {
            ephemeral_pk,
            encrypted_data: vec![0u8; 32],
            tag: [0u8; 32],
            epoch: 1,
        };
        let sender_bytes = string_bytes(&sender);
        let payload_hash = encrypted_payload.commitment_hash();
        let preimage = commit_signing_preimage(
            &commitment,
            &payload_hash,
            &sender_bytes,
            &al_bytes,
            crate::state::CHAIN_ID,
        );
        let sig = signer.sign(&preimage).to_bytes();
        let commit = CommitTx {
            commitment,
            sender: sender.clone(),
            access_list: tx.access_list.clone(),
            encrypted_payload,
            pubkey: signer.verifying_key().to_bytes(),
            sig,
        };
        let reveal = RevealTx { tx, salt, sender };
        (commit, reveal)
    }

    #[test]
    fn stale_entries_not_selected() {
        let cfg = MempoolConfig {
            max_avails_per_block: 10,
            max_reveals_per_block: 10,
            max_commits_per_block: 10,
            max_pending_commits_per_account: 10,
            commit_ttl_blocks: 2,
            reveal_window_blocks: 2,
        };
        let mp = MempoolImpl::new(cfg);
        let mut node = Node::new(mp.clone(), SigningKey::from_bytes(&[1u8; 32]));

        let bv = TestBalanceView;

        // stale pair at height 0
        let sk1 = SigningKey::from_bytes(&[2u8; 32]);
        let _sender1 = addr_hex(&addr_from_pubkey(&sk1.verifying_key().to_bytes()));
        let (c1, r1) = make_pair(&sk1, 0);
        mp.insert_commit(Tx::Commit(c1), 0, 1, &bv, &FeeState::from_defaults()).unwrap();
        mp.insert_reveal(r1, 0, 1, &bv, &FeeState::from_defaults()).unwrap();

        // fresh pair at height 2
        let sk2 = SigningKey::from_bytes(&[3u8; 32]);
        let sender2 = addr_hex(&addr_from_pubkey(&sk2.verifying_key().to_bytes()));
        let (c2, r2) = make_pair(&sk2, 0);
        mp.insert_commit(Tx::Commit(c2.clone()), 2, 1, &bv, &FeeState::from_defaults()).unwrap();
        mp.insert_reveal(r2.clone(), 2, 1, &bv, &FeeState::from_defaults()).unwrap();

        // chain height so first pair is stale
        node.chain.height = 3;
        node.mempool.evict_stale(node.chain.height);

        let sv = NodeStateView { chain: &node.chain, nonces: &node.nonces, mempool: &node.mempool };
        let limits = BlockSelectionLimits { max_avails: 10, max_reveals: 10, max_commits: 10 };
        let cand = node.mempool.select_block(&sv, limits).expect("select");
        assert_eq!(cand.txs.len(), 1);
        assert_eq!(cand.reveals.len(), 1);
        match &cand.txs[0] {
            Tx::Commit(c) => assert_eq!(c.sender, sender2),
            _ => panic!("unexpected tx variant"),
        }
        assert_eq!(cand.reveals[0].sender, sender2);
    }

    #[test]
    fn commit_simulated_block_updates_state() {
        use std::time::{SystemTime, UNIX_EPOCH};
    
        let cfg = MempoolConfig {
            max_avails_per_block: 10,
            max_reveals_per_block: 10,
            max_commits_per_block: 10,
            max_pending_commits_per_account: 10,
            commit_ttl_blocks: 2,
            reveal_window_blocks: 2,
        };
        let mp = MempoolImpl::new(cfg);
        let mut node = Node::new(mp.clone(), SigningKey::from_bytes(&[2u8; 32]));
    
        // VRF signer so we can be eligible (with single validator we’re always eligible).
        let test_vrf = SchnorrkelVrfSigner::from_deterministic_seed([7u8; 32]);
        node.set_vrf_signer(test_vrf);
    
        // Make this node the genesis validator with 100% stake (always eligible).
        let _bls = node.install_self_as_genesis_validator(1, 1_000_000);
    
        // ---- Align the slot with the dev policy: slot == height + 1 ----
        // Height is 0, so we need current_slot(now) == 1.
        // Node::now_unix() floors to seconds, matching simulate_block's time source.
        let now_ms: u128 = (node.now_unix() as u128) * 1000;
        let slot_ms = node.chain.clock.slot_ms as u128;
        // Choose genesis so that current_slot(now) = (now_ms - genesis) / slot_ms = 1.
        node.chain.clock.genesis_unix_ms = now_ms.saturating_sub(slot_ms * 1);
    
        // Prepare a payable commit
        let bv = TestBalanceView;
        let tx_sk = SigningKey::from_bytes(&[4u8; 32]);
        let sender = addr_hex(&addr_from_pubkey(&tx_sk.verifying_key().to_bytes()));
        node.set_balance(sender.clone(), 1000);
        let (c, _r) = make_pair(&tx_sk, 0);
        mp.insert_commit(
            Tx::Commit(c.clone()),
            /*included_at*/ 0,
            /*priority*/ 1,
            &bv,
            &FeeState::from_defaults(),
        )
        .unwrap();
    
        let limits = BlockSelectionLimits { max_avails: 10, max_reveals: 10, max_commits: 10 };
    
        // This will now pass proposer verification (slot==height+1 and valid VRF)
        node.produce_block(limits).expect("produce");
    
        assert_eq!(node.height(), 1);
        assert_eq!(node.balance_of(&sender), 999);
        assert!(node.chain.commit_on_chain(&c.commitment));
    }        


    #[test]
    fn process_block_called_once() {
        let cfg = MempoolConfig {
            max_avails_per_block: 10,
            max_reveals_per_block: 10,
            max_commits_per_block: 10,
            max_pending_commits_per_account: 10,
            commit_ttl_blocks: 2,
            reveal_window_blocks: 2,
        };
        let mp = MempoolImpl::new(cfg);
        let mut node = Node::new(mp.clone(), SigningKey::from_bytes(&[3u8; 32]));
    
        let test_vrf = SchnorrkelVrfSigner::from_deterministic_seed([7u8; 32]);
        node.set_vrf_signer(test_vrf);

        // NEW: make this node an active validator in the chain's validator set.
        let _bls = node.install_self_as_genesis_validator(1, 1_000_000);

        // Align the slot with the chain's height policy (slot == 1 at height 0)
        let now_ms: u128 = (node.now_unix() as u128) * 1000;
        let slot_ms = node.chain.clock.slot_ms as u128;
        node.chain.clock.genesis_unix_ms = now_ms.saturating_sub(slot_ms * 1);
    
        let bv = TestBalanceView;
        let tx_sk = SigningKey::from_bytes(&[5u8; 32]);
        let sender = addr_hex(&addr_from_pubkey(&tx_sk.verifying_key().to_bytes()));
        node.set_balance(sender.clone(), 1000);
        let (c, _r) = make_pair(&tx_sk, 0);
        mp.insert_commit(Tx::Commit(c), 0, 1, &bv, &FeeState::from_defaults()).unwrap();
    
        PROCESS_BLOCK_CALLS.with(|c| c.set(0));
        let limits = BlockSelectionLimits { max_avails: 10, max_reveals: 10, max_commits: 10 };
    
        node.produce_block(limits).unwrap();
    
        PROCESS_BLOCK_CALLS.with(|c| assert_eq!(c.get(), 1));
    }

    #[test]
    fn leader_changes_with_view_even_if_height_constant() {
        use crate::pos::registry::{Validator, ValidatorStatus};
        use crate::crypto::bls::BlsSigner;

        // Build a node and install a 2-validator set
        let cfg = MempoolConfig {
            max_avails_per_block: 10,
            max_reveals_per_block: 10,
            max_commits_per_block: 10,
            max_pending_commits_per_account: 10,
            commit_ttl_blocks: 2,
            reveal_window_blocks: 2,
        };
        let mp = MempoolImpl::new(cfg);
        let mut node = Node::new(mp.clone(), SigningKey::from_bytes(&[9u8; 32]));

        // Two deterministic validators (ids 0 and 1)
        let ed0 = SigningKey::from_bytes(&[1u8; 32]).verifying_key().to_bytes();
        let ed1 = SigningKey::from_bytes(&[2u8; 32]).verifying_key().to_bytes();
        let bls0 = BlsSigner::from_sk_bytes(&[10u8; 32]).unwrap();
        let bls1 = BlsSigner::from_sk_bytes(&[11u8; 32]).unwrap();
        let v0 = Validator { id: 0, ed25519_pubkey: ed0, bls_pubkey: Some(bls0.public_key_bytes()), vrf_pubkey: [3u8; 32], stake: 1_000, status: ValidatorStatus::Active };
        let v1 = Validator { id: 1, ed25519_pubkey: ed1, bls_pubkey: Some(bls1.public_key_bytes()), vrf_pubkey: [4u8; 32], stake: 1_000, status: ValidatorStatus::Active };
        node.init_with_shared_validator_set(vec![v0, v1], bls0);

        // Disable schedule leaders to force fallback to round-robin by view
        node.chain.schedule.epoch_slots = 0;
        node.chain.schedule.leaders.clear();

        // Keep height constant and verify leader depends on view
        node.chain.height = 0;
        let l1 = node.leader_for_view(1);
        let l2 = node.leader_for_view(2);
        assert_ne!(l1, l2, "leader should change with view when schedule is empty");
    }

    #[test]
    fn hotstuff_updates_high_qc() {
        let cfg = MempoolConfig {
            max_avails_per_block: 10,
            max_reveals_per_block: 10,
            max_commits_per_block: 10,
            max_pending_commits_per_account: 10,
            commit_ttl_blocks: 2,
            reveal_window_blocks: 2,
        };
        let mp = MempoolImpl::new(cfg);
        let mut node = Node::new(mp.clone(), SigningKey::from_bytes(&[1u8;32]));
        node.set_vrf_signer(SchnorrkelVrfSigner::from_deterministic_seed([7u8;32]));
        let _my_bls = node.install_self_as_genesis_validator(0, 100);

        let bls_signer = BlsSigner::from_sk_bytes(&[2u8;32]).unwrap();
        let bls_pk = bls_signer.public_key_bytes();
        node.chain.validator_set.validators[0].bls_pubkey = Some(bls_pk);

        let genesis_id = node.chain.tip_hash;
        let msg = vote_msg(&genesis_id, 0);
        let sig = bls_signer.sign(&msg);
        let mut agg = BlsAggregate::new();
        agg.push(&sig.0);
        let agg_sig = agg.finalize().unwrap();
        let mut bitmap = BitVec::repeat(false, 1);
        bitmap.set(0, true);
        let qc0 = QC { view: 0, block_id: genesis_id, agg_sig, bitmap };

        let mut pm = Pacemaker::new(1000, 10000, 2, 1, 1, 1);
        pm.on_enter_view(node.chain.now_ts());
        let hs_state = HotStuffState { current_view: 1, locked_block: (genesis_id, 0), high_qc: qc0, pacemaker: pm };
        node.hotstuff = Some(HotStuff::new(hs_state, vec![bls_pk], 0, Some(bls_signer)));

        node.align_clock_for_test();
        let limits = BlockSelectionLimits { max_avails: 10, max_reveals: 10, max_commits: 10 };
        let (built, _) = node.produce_block(limits).expect("block");

        let hs = node.hotstuff.as_ref().unwrap();
        let bid = header_id(&built.block.header);
        assert_eq!(hs.state.high_qc.block_id, bid);
        assert_eq!(hs.state.high_qc.view, built.block.header.view);
    }

    #[test]
    fn header_eligibility_checks_fallback_leader() {
        // Build a simple node with two validators and default schedule/seed
        let cfg = MempoolConfig {
            max_avails_per_block: 10,
            max_reveals_per_block: 10,
            max_commits_per_block: 10,
            max_pending_commits_per_account: 10,
            commit_ttl_blocks: 2,
            reveal_window_blocks: 2,
        };
        let mp = MempoolImpl::new(cfg);
        let mut node = Node::new(mp.clone(), SigningKey::from_bytes(&[1u8;32]));

        // Two active validators (ids 0,1) with deterministic keys
        let ed0 = SigningKey::from_bytes(&[1u8; 32]).verifying_key().to_bytes();
        let ed1 = SigningKey::from_bytes(&[2u8; 32]).verifying_key().to_bytes();
        let bls0 = BlsSigner::from_sk_bytes(&[10u8; 32]).unwrap();
        let bls1 = BlsSigner::from_sk_bytes(&[11u8; 32]).unwrap();
        let v0 = Validator { id: 0, ed25519_pubkey: ed0, bls_pubkey: Some(bls0.public_key_bytes()), vrf_pubkey: [3u8; 32], stake: 1_000, status: ValidatorStatus::Active };
        let v1 = Validator { id: 1, ed25519_pubkey: ed1, bls_pubkey: Some(bls1.public_key_bytes()), vrf_pubkey: [4u8; 32], stake: 1_000, status: ValidatorStatus::Active };
        node.init_with_shared_validator_set(vec![v0, v1], bls0);

        // Next block will have slot/height = 1
        let slot = 1u64;
        let epoch = node.chain.clock.current_epoch(slot);
        let bundle_start = node.chain.clock.bundle_start(slot, DEFAULT_BUNDLE_LEN);
        let expected = node.chain.schedule.fallback_leader_for_bundle(bundle_start).expect("leader");

        // Build a header using the non-leader and no VRF proof → ineligible
        let non_leader = 1 - (expected as i64) as i64; // 0 or 1 other side
        let non_leader = if non_leader < 0 { 0 } else { non_leader as u64 };
        let h_bad = crate::types::BlockHeader {
            parent_hash: node.chain.tip_hash,
            height: 1,
            txs_root: [0u8;32],
            receipts_root: [0u8;32],
            gas_used: 0,
            randomness: [0u8;32],
            reveal_set_root: [0u8;32],
            il_root: [0u8;32],
            exec_base_fee: node.chain.fee_state.exec_base,
            commit_base_fee: node.chain.fee_state.commit_base,
            avail_base_fee: node.chain.fee_state.commit_base,
            timestamp: 0,
            slot,
            epoch,
            proposer_id: non_leader,
            signature: [0u8;64],
            bundle_len: DEFAULT_BUNDLE_LEN,
            vrf_preout: [0u8;32],
            vrf_output: [0u8;32],
            vrf_proof: vec![],
            view: 1,
            justify_qc_hash: [0u8;32],
        };
        assert_eq!(node.header_is_eligible(&h_bad), false);

        // Same but with the expected fallback leader → eligible
        let mut h_ok = h_bad.clone();
        h_ok.proposer_id = expected;
        assert_eq!(node.header_is_eligible(&h_ok), true);
    }
}
