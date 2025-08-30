use crate::consensus::dev_loop::DevNode;
use crate::consensus::HotStuff;
use crate::crypto::bls::{verify_qc, BlsSigner, BlsSignatureBytes, BlsAggregate, vote_msg};
use crate::fees::FeeState;
use crate::p2p::{ConsensusNetwork, ConsensusMessage, simple_leader_election};
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
use crate::crypto::vrf::{build_vrf_msg, vrf_eligible, SchnorrkelVrfSigner, VrfSigner};
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
        for mut pv in self.pending_vote_retries.drain(..) {
            // Drop if QC for this view has been observed
            if high_view >= pv.vote.view { continue; }
            if pv.retries == 0 && now >= pv.due_ms {
                if let Some(net) = self.consensus_network.as_ref() {
                    let _ = net.send_vote(pv.vote.clone(), pv.leader_id);
                }
                pv.retries = 1;
                // No more retries; keep until QC advances (to avoid endless resends)
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
        let mut pacemaker = Pacemaker::new(pmc.base_timeout_ms, pmc.max_timeout_ms, pmc.backoff_num, pmc.backoff_den);
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

    /// Attempt to apply any pending commits that have become applicable.
    fn try_apply_pending_commits(&mut self) {
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
                    if let Some(pb) = parent {
                        if let Err(e) = self.handle_proposal(pb, sender_id) {
                            eprintln!("Error handling parent proposal from {}: {}", sender_id, e);
                        }
                    }
                    if let Err(e) = self.handle_proposal(block, sender_id) {
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
                ConsensusMessage::ViewChange { view, sender_id, timeout_qc } => {
                    self.handle_view_change(view, sender_id, timeout_qc)?;
                }
            }
        }
        
        Ok(committed_blocks)
    }

    /// Handle an incoming block proposal
    fn handle_proposal(&mut self, block: Block, sender_id: ValidatorId) -> Result<(), String> {
        // 1) HotStuff header observation and validation
        if let Some(hs) = self.hotstuff.as_mut() {
            let now_ms = (Self::now_ts() as u128) * 1000;
            hs.observe_block_header(&block.header);
            hs.on_block_proposal(block.clone(), now_ms)
                .map_err(|e| format!("Block proposal validation failed: {:?}", e))?;
        }

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

        // 3) Now that we've indexed the header, try to commit using the best QC
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
                let num_validators = hs.validator_pks.len();
                let next_leader = simple_leader_election(vote.view + 1, num_validators);
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
            if let Some(qc) = hotstuff.on_vote(vote) {
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
            let res = hs
                .on_qc_self(qc, now_ms)
                .map_err(|e| format!("Failed to process QC: {:?}", e))?;

            // Snapshot leader info for the new view and drop the borrow
            let next_view = hs.state.current_view;
            let my_id = hs.validator_id;
            let n = hs.validator_pks.len();
            drop(hs);

            // If I'm the leader for the current view and haven't proposed yet, propose immediately
            let leader = crate::p2p::simple_leader_election(next_view, n);
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
            
            // Could implement view synchronization logic here
            // For now, we rely on timeouts to drive view changes
        }
        Ok(())
    }

    /// Check for pacemaker timeouts and advance view if necessary
    pub fn check_pacemaker_timeout(&mut self) -> Result<(), String> {
        if let Some(hotstuff) = self.hotstuff.as_mut() {
            let now_ms = (Self::now_ts() as u128) * 1000;
            hotstuff.on_new_slot(now_ms);
            
            // If we advanced view due to timeout, broadcast a view change
            // This is a simplified version - production would be more sophisticated
            if let Some(network) = self.consensus_network.as_ref() {
                let current_view = hotstuff.state.current_view;
                // Only broadcast if we think we should (could add more logic here)
                if hotstuff.state.pacemaker.expired(now_ms) {
                    let _ = network.broadcast_view_change(current_view, Some(hotstuff.state.high_qc.clone()));
                }
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
        let now_ms = self.chain.now_ts();
        let slot_now = self.chain.clock.current_slot(now_ms);
        let next_slot = core::cmp::max(slot_now, self.chain.height + 1);
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
        &self,
        limits: BlockSelectionLimits,
    ) -> Result<(BuiltBlock, ApplyResult, Balances, Nonces, Commitments, Available, u64), ProduceError> {
        // ---- VORTEX: PoS gating & deterministic metadata ----
        let now_ms = self.chain.now_ts();
        let _slot_now   = self.chain.clock.current_slot(now_ms);

        // Choose parent based on consensus state if enabled; otherwise use local tip.
        // Compute height relative to the parent's known height to avoid drift in
        // networked mode where local chain.height lags committed state.
        let (parent_hash, parent_height) = if let Some(hs) = self.hotstuff.as_ref() {
            let ph = hs.state.high_qc.block_id;
            let ph_height = if ph == self.chain.tip_hash {
                self.chain.height
            } else if let Some(b) = self.block_store.get(&ph) {
                b.header.height
            } else {
                // Fallback to local height if we don't have the parent block yet
                self.chain.height
            };
            (ph, ph_height)
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
        if !vrf_eligible(me.stake, total, &vrf_out, self.chain.tau) {
            // Not elected via VRF. Only continue if we're the deterministic fallback leader.
            if fallback != Some(proposer_id) {
                return Err(ProduceError::NotProposer { slot, leader: fallback, mine: Some(proposer_id) });
            }
            // Use empty VRF fields to signal alias fallback.
            vrf_out = [0u8; 32];
            vrf_pre = [0u8; 32];
            vrf_proof.clear();
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
            receipts: body.receipts.clone(),
            gas_total: body.gas_total,
            events: body.events.clone(),
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
                // Only the expected leader for the upcoming block should propose.
                // Use the chain's proposer schedule (fallback or VRF-aware) when available.
                if let Some(exp) = self.expected_leader_for_next_block() {
                    if hs.validator_id != exp {
                        return Err(ProduceError::NotProposer {
                            slot: self.chain.height + 1,
                            leader: Some(exp),
                            mine: Some(hs.validator_id),
                        });
                    }
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
            let res = self.chain
                .commit_simulated_block(
                    &built.block,
                    apply.clone(),
                    balances.clone(),
                    nonces.clone(),
                    commitments.clone(),
                    available.clone(),
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

            res
        } else {
            // Networked mode: skip local commit and return a dummy ApplyResult copy for callers that log it.
            apply.clone()
        };

        // HotStuff: broadcast proposal and handle consensus
        if self.hotstuff.is_some() {
            // Validate and index header lineage before broadcast
            let now_ms = (Self::now_ts() as u128) * 1000;
            if let Some(hs) = self.hotstuff.as_mut() {
                hs.observe_block_header(&built.block.header);
                let _ = hs.on_block_proposal(built.block.clone(), now_ms);
            }

            // Store our own proposed block so we can commit it on QC later
            let bid = crate::codec::header_id(&built.block.header);
            self.block_store.insert(bid, built.block.clone());

            // Broadcast the proposal to all validators (include parent block if available)
            if let Some(network) = self.consensus_network.as_ref() {
                let parent_opt = self.block_store.get(&built.block.header.parent_hash).cloned();
                if let Err(e) = network.broadcast_proposal(built.block.clone(), parent_opt) {
                    eprintln!("Failed to broadcast proposal: {}", e);
                }

                // Additionally, run the standard proposal handler locally so we:
                //  - generate and count our self-vote in the local aggregator,
                //  - broadcast that vote using the same path as non-leaders.
                if let Some(hs) = self.hotstuff.as_ref() {
                    let my_id = hs.validator_id;
                    // Ignore errors here to avoid blocking liveness on local validation quirks; peers will vet too.
                    let _ = self.handle_proposal(built.block.clone(), my_id);
                }
            } else if let Some(hs) = self.hotstuff.as_mut() {
                // Single-process fallback: vote and drive QC locally
                if let Some(vote) = hs.maybe_vote_self(&built.block) {
                    if let Some(qc) = hs.on_vote(vote) {
                        let _ = hs.on_qc_self(qc, now_ms);
                    }
                }
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

        let mut pm = Pacemaker::new(1000, 10000, 2, 1);
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
}
