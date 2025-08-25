use std::collections::HashMap;

use crate::{
    codec::{header_id, qc_commitment}, crypto::bls::{
        has_quorum, verify_qc, verify_sig, vote_msg, BlsAggregate, BlsSignatureBytes, BlsSigner, SignerBitmap
    }, pos::registry::ValidatorId, types::{Block, BlockHeader, Hash, HotStuffState, Vote, QC} 
};

pub mod dev_loop;

#[derive(Debug)]
struct VoteAggregator {
    agg: BlsAggregate,
    bitmap: SignerBitmap,
    seen: Vec<bool>,
    block_id: Hash,
    view: u64,
}

impl VoteAggregator {
    fn new(n: usize, block_id: Hash, view: u64) -> Self {
        Self {
            agg: BlsAggregate::new(),
            bitmap: SignerBitmap::repeat(false, n),
            seen: vec![false; n],
            block_id,
            view,
        }
    }
    fn add(&mut self, voter_idx: usize, sig: &BlsSignatureBytes) {
        if !self.seen[voter_idx] {
            self.agg.push(&sig.0);
            self.bitmap.set(voter_idx, true);
            self.seen[voter_idx] = true;
        }
    }
}

pub struct HotStuff {
    pub state: HotStuffState,               
    pub validator_pks: Vec<[u8; 48]>,       
    pub validator_id: ValidatorId,          
    pub bls_signer: Option<BlsSigner>,    
    parent_index: HashMap<Hash, Hash>,
    aggregators: HashMap<(u64, Hash), VoteAggregator>,  
}

#[derive(Debug)]
pub enum Error {
    QcCommitmentMismatch,
    QcInvalid,
    Unimplemented,
}

pub trait BlockStore {
    /// Return true if `candidate_parent` is a (strict) descendant of `ancestor`.
    fn is_descendant(&self, candidate_parent: &Hash, ancestor: &Hash) -> bool;

     /// Return the parent id of `block_id` if known.
     fn get_parent(&self, block_id: &Hash) -> Option<Hash>;
}

fn safe_to_vote<S: BlockStore>(
    store: &S,
    state: &HotStuffState,
    proposal_parent: &Hash,
    justify_qc: &QC,
) -> bool {
    // must not vote below our lock
    if justify_qc.view < state.locked_block.1 {
        return false;
    }
    // proposal must extend the locked block
    store.is_descendant(proposal_parent, &state.locked_block.0)
}

impl HotStuff {
    pub fn new(state: HotStuffState, validator_pks: Vec<[u8;48]>, validator_id: ValidatorId, bls_signer: Option<BlsSigner>) -> Self {
        Self {
            state,
            validator_pks,
            validator_id,
            bls_signer,
            parent_index: HashMap::new(),
            aggregators: HashMap::new(),
        }
    }

    pub fn observe_block_header(&mut self, header: &BlockHeader) {
        let id = header_id(header);
        self.parent_index.insert(id, header.parent_hash);
    }

    pub fn on_new_slot(&mut self, _now_ms: u128) {
        // next step (later): pacemaker timeout handling & view increment
    }

    pub fn on_block_proposal(&mut self, _block: Block, _now_ms: u128) -> Result<(), Error> {
        // next step (later)
        Err(Error::Unimplemented)
    }

    pub fn on_qc<S: BlockStore>(
        &mut self,
        store: &S,
        qc: QC,
        now_ms: u128,
    ) -> Result<Option<Hash>, Error> {
        // 1) Verify the QC against the active-set BLS pubkeys.
        verify_qc(&qc.block_id, qc.view, &qc.agg_sig, &qc.bitmap, &self.validator_pks)
            .map_err(|_| Error::QcInvalid)?;

        // 2) Adopt higher QC if applicable.
        if qc.view > self.state.high_qc.view {
            self.state.high_qc = qc.clone();
        }

        // 3) Advance lock to the certified block (Jolteon 2-chain).
        self.state.locked_block = (qc.block_id, qc.view);

        // 4) Pacemaker: move to next view and reset timer.
        if self.state.current_view < qc.view + 1 {
            self.state.current_view = qc.view + 1;
        }
        self.state.pacemaker.on_enter_view(now_ms);

        // 5) 2-chain commit rule: commit the parent of the certified block (if we know it).
        let commit_target = store.get_parent(&qc.block_id);
        Ok(commit_target)
    }

    pub fn maybe_propose(
        &mut self,
        leader: bool,
        build_block: impl FnOnce(&QC) -> Block,
    ) -> Option<Block> {
        if !leader { return None; }

        let view = self.state.current_view;
        let justify = self.state.high_qc.clone();

        let mut block = build_block(&justify);

        // Ensure header view matches this view.
        if block.header.view != view {
            block.header.view = view;
        }

        // Ensure header.justify_qc_hash binds exactly this QC.
        let committed = qc_commitment(
            block.justify_qc.view,
            &block.justify_qc.block_id,
            &block.justify_qc.agg_sig,
            &block.justify_qc.bitmap,
        );
        if block.header.justify_qc_hash != committed {
            block.header.justify_qc_hash = committed;
        }

        Some(block) // Node will sign next
    }

    /// === THIS STEP: validator-side vote path ===
    ///
    /// Preconditions: header (Ed25519) already verified by your existing path.
    /// This function:
    ///  - checks the QC commitment matches the header,
    ///  - verifies the QC (BLS) against the active set,
    ///  - runs HotStuff safety,
    ///  - if OK, signs a BLS vote and returns it.
    pub fn maybe_vote<S: BlockStore>(&mut self, store: &S, block: &Block) -> Option<Vote> {
        // 0) must be a validator with a BLS signer
        let signer = self.bls_signer.as_ref()?;

        // 1) header must commit to the attached QC exactly
        let committed = qc_commitment(
            block.justify_qc.view,
            &block.justify_qc.block_id,
            &block.justify_qc.agg_sig,
            &block.justify_qc.bitmap,
        );
        if block.header.justify_qc_hash != committed {
            return None; // commitment mismatch
        }

        // 2) verify the QC once (BLS fast-aggregate verify)
        if verify_qc(
            &block.justify_qc.block_id,
            block.justify_qc.view,
            &block.justify_qc.agg_sig,
            &block.justify_qc.bitmap,
            &self.validator_pks,         // active set PKs in index order
        )
        .is_err()
        {
            return None; // bad QC
        }

        // 3) adopt higher high_qc if applicable (helps liveness)
        if block.justify_qc.view > self.state.high_qc.view {
            self.state.high_qc = block.justify_qc.clone();
        }

        // 4) HotStuff safety: only vote if proposal extends our locked block
        if !safe_to_vote(store, &self.state, &block.header.parent_hash, &block.justify_qc) {
            return None;
        }

        // 5) build canonical vote message and sign with BLS
        // NOTE: use your canonical header-id bytes for block_id
        let bid = header_id(&block.header);
        let msg = vote_msg(&bid, block.header.view);
        let bls_sig: BlsSignatureBytes = signer.sign(&msg);

        Some(Vote {
            view: block.header.view,
            block_id: bid,
            voter_id: self.validator_id,
            bls_sig,
        })
    }

    pub fn on_vote(&mut self, vote: Vote) -> Option<QC> {
        // Only meaningful if I'm the leader for this (policy: we can still aggregate even if not)
        let n = self.validator_pks.len();
        if (vote.voter_id as usize) >= n { return None; }
    
        // 1) Verify the *individual* vote quickly (single BLS verify).
        let pk = &self.validator_pks[vote.voter_id as usize];
        let msg = vote_msg(&vote.block_id, vote.view);
        if !verify_sig(pk, &msg, &vote.bls_sig) {
            return None; // bad partial
        }
    
        // 2) Get/create the aggregator for (view, block_id).
        let key = (vote.view, vote.block_id);
        let entry = self.aggregators.entry(key).or_insert_with(|| {
            VoteAggregator::new(n, vote.block_id, vote.view)
        });
    
        // 3) Add vote if not a duplicate from this validator.
        entry.add(vote.voter_id as usize, &vote.bls_sig);
    
        // 4) If quorum reached, finalize to QC and return it.
        if has_quorum(n, &entry.bitmap) {
            if let Some(agg_sig) = entry.agg.finalize() {
                let qc = QC {
                    view: entry.view,
                    block_id: entry.block_id,
                    agg_sig,
                    bitmap: entry.bitmap.clone(),
                };
                // Optional: keep the aggregator or remove it to free memory.
                // self.aggregators.remove(&key);
                return Some(qc);
            }
        }
        None
    }    
}

impl BlockStore for HotStuff {
    fn is_descendant(&self, candidate_parent: &Hash, ancestor: &Hash) -> bool {
        let mut cur: Hash = *candidate_parent;

        while let Some(p) = self.parent_index.get(&cur) {
            if p == ancestor {
                return true;
            }
            cur = *p;
        }
        false
    }

    fn get_parent(&self, block_id: &Hash) -> Option<Hash> {
        self.parent_index.get(block_id).cloned()
    }
}