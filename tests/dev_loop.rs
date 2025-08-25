use std::sync::{Arc, Mutex};
use l1_blockchain::consensus::dev_loop::{DevLoop, DevLoopConfig, DEFAULT_LIMITS, DevNode};
use l1_blockchain::crypto::hash_bytes_sha256;
use l1_blockchain::crypto::vrf::{build_vrf_msg, SchnorrkelVrfSigner, VrfSigner};
use l1_blockchain::mempool::{BlockSelectionLimits, MempoolConfig, MempoolImpl};
use l1_blockchain::node::{BuiltBlock, SelectedIds, ProduceError, Node};
use l1_blockchain::chain::{ApplyResult, Chain, DEFAULT_BUNDLE_LEN};
use l1_blockchain::state::{Balances, Nonces, Commitments, Available};
use l1_blockchain::types::{Block, BlockHeader, Tx, RevealTx, QC};
use l1_blockchain::crypto::bls::BlsSignatureBytes;
use bitvec::vec::BitVec;
use ed25519_dalek::SigningKey;

fn dummy_qc() -> QC {
    QC { view: 0, block_id: [0u8;32], agg_sig: BlsSignatureBytes([0u8;96]), bitmap: BitVec::new() }
}

#[derive(Default)]
struct FakeState {
    height: u64,
    ticks: u64,
    heights: Vec<u64>,
}

struct FakeNode {
    state: Arc<Mutex<FakeState>>,
}

impl FakeNode {
    fn new(state: Arc<Mutex<FakeState>>) -> Self { Self { state } }
}

impl DevNode for FakeNode {
    fn height(&self) -> u64 { self.state.lock().unwrap().height }

    fn produce_block(&mut self, _limits: BlockSelectionLimits) -> Result<(BuiltBlock, ApplyResult), ProduceError> {
        let mut st = self.state.lock().unwrap();
        st.height += 1;
        st.ticks += 1;
        let h = st.height;
        st.heights.push(h);

        // Vortex-only header fields
        let slot        = h;                  // dev policy: one block per slot
        let epoch       = 0;                  // keep 0 for fake/test node
        let proposer_id = 1;                  // single fake validator
        let bundle_len  = DEFAULT_BUNDLE_LEN; // constant used across codebase
        let vrf_output = [0xAAu8; 32];
        let vrf_preout = [0xAAu8; 32];
        let vrf_proof  = vec![0xBB];

        let header = BlockHeader {
            parent_hash:     [0u8;32],
            height:          h,
            txs_root:        [0u8;32],
            receipts_root:   [0u8;32],
            gas_used:        0,
            randomness:      [0u8;32],
            reveal_set_root: [0u8;32],
            il_root:         [0u8;32],
            exec_base_fee:   0,
            commit_base_fee: 0,
            avail_base_fee:  0,
            timestamp:       0,
            slot,
            epoch,
            proposer_id,
            bundle_len,
            vrf_output,
            vrf_proof,
            vrf_preout,
            view: 0,
            justify_qc_hash: [0u8; 32],
            signature: [0u8;64],
        };

        let block = Block {
            transactions: Vec::<Tx>::new(),
            reveals:      Vec::<RevealTx>::new(),
            header,
            justify_qc: dummy_qc(),
        };

        let built = BuiltBlock {
            block,
            selected_ids: SelectedIds { commit: vec![], avail: vec![], reveal: vec![] }
        };

        let apply = ApplyResult {
            receipts: vec![],
            gas_total: 0,
            events: vec![],
            exec_reveals_used: 0,
            commits_used: 0,
            burned_total: 0,
        };

        Ok((built, apply))
    }

    fn now_unix(&self) -> u64 { 0 }
}

#[test]
fn run_for_slots_produces_exact_blocks() {
    let state = Arc::new(Mutex::new(FakeState::default()));
    let node = FakeNode::new(state.clone());
    let cfg = DevLoopConfig { slot_ms: 1, limits: DEFAULT_LIMITS };
    let mut dl = DevLoop::new(node, cfg);
    dl.run_for_slots(5);
    let st = state.lock().unwrap();
    assert_eq!(st.height, 5);
    assert_eq!(st.ticks, 5);
    assert_eq!(st.heights, vec![1,2,3,4,5]);
}

#[test]
fn run_until_height_stops_exactly() {
    let state = Arc::new(Mutex::new(FakeState::default()));
    let node = FakeNode::new(state.clone());
    let cfg = DevLoopConfig { slot_ms: 1, limits: DEFAULT_LIMITS };
    let mut dl = DevLoop::new(node, cfg);
    dl.run_until_height(7);
    let st = state.lock().unwrap();
    assert_eq!(st.height, 7);
    assert_eq!(st.ticks, 7);
}

#[test]
fn run_for_duration_ticks_expected() {
    use std::ops::RangeInclusive;
    let state = Arc::new(Mutex::new(FakeState::default()));
    let node = FakeNode::new(state.clone());
    let cfg = DevLoopConfig { slot_ms: 100, limits: DEFAULT_LIMITS };
    let mut dl = DevLoop::new(node, cfg);
    dl.run_for_duration(450);
    let st = state.lock().unwrap();
    let range: RangeInclusive<u64> = 4..=5;
    assert!(range.contains(&st.ticks), "ticks={} outside 4-5", st.ticks);
    assert_eq!(st.height, st.ticks);
    assert_eq!(st.heights, (1..=st.ticks).collect::<Vec<_>>());
}

struct RecordingNode {
    inner: Node,
    blocks: Arc<Mutex<Vec<(usize, usize, u64)>>>,
}

impl DevNode for RecordingNode {
    fn height(&self) -> u64 { self.inner.height() }

    fn produce_block(&mut self, limits: BlockSelectionLimits) -> Result<(BuiltBlock, ApplyResult), ProduceError> {
        self.inner.align_clock_for_test();
        let (built, apply) = self.inner.produce_block(limits)?;
        let txc = built.block.transactions.len();
        let revc = built.block.reveals.len();
        let h = built.block.header.height;
        self.blocks.lock().unwrap().push((txc, revc, h));
        Ok((built, apply))
    }

    fn now_unix(&self) -> u64 { self.inner.now_unix() }
}

#[test]
fn empty_mempool_produces_empty_blocks() {
    let cfg = MempoolConfig {
        max_avails_per_block: 10,
        max_reveals_per_block: 10,
        max_commits_per_block: 10,
        max_pending_commits_per_account: 10,
        commit_ttl_blocks: 2,
        reveal_window_blocks: 2,
    };
    let mp = MempoolImpl::new(cfg);
    let signer = SigningKey::from_bytes(&[1u8;32]);

    // make this node a valid proposer at genesis
    let mut node = Node::new(mp, signer);

    let test_vrf = SchnorrkelVrfSigner::from_deterministic_seed([7u8; 32]);
    node.set_vrf_signer(test_vrf);

    node.install_self_as_genesis_validator(1, 1_000_000); // production path via init_genesis

    let blocks = Arc::new(Mutex::new(Vec::new()));
    let rec = RecordingNode { inner: node, blocks: blocks.clone() };

    let cfg = DevLoopConfig { slot_ms: 1, limits: DEFAULT_LIMITS };
    let mut dl = DevLoop::new(rec, cfg);

    dl.run_for_slots(3);

    let b = blocks.lock().unwrap();
    assert_eq!(b.len(), 3);
    for (i, (txc, revc, h)) in b.iter().enumerate() {
        assert_eq!(*txc, 0);
        assert_eq!(*revc, 0);
        assert_eq!(*h as usize, i + 1);
    }
}

struct SlowNode {
    inner: FakeNode,
    delay_ms: u64,
}

impl SlowNode {
    fn new(state: Arc<Mutex<FakeState>>, delay_ms: u64) -> Self {
        Self { inner: FakeNode::new(state), delay_ms }
    }
}

impl DevNode for SlowNode {
    fn height(&self) -> u64 { self.inner.height() }

    fn produce_block(&mut self, limits: BlockSelectionLimits) -> Result<(BuiltBlock, ApplyResult), ProduceError> {
        std::thread::sleep(std::time::Duration::from_millis(self.delay_ms));
        self.inner.produce_block(limits)
    }

    fn now_unix(&self) -> u64 { self.inner.now_unix() }
}

#[test]
fn sleeps_remainder_of_slot() {
    use std::time::{Duration, Instant};

    let state = Arc::new(Mutex::new(FakeState::default()));
    let node = FakeNode::new(state);
    let slot_ms = 10;
    let cfg = DevLoopConfig { slot_ms, limits: DEFAULT_LIMITS };
    let mut dl = DevLoop::new(node, cfg);
    let slots = 5;
    let start = Instant::now();
    dl.run_for_slots(slots);
    let elapsed = start.elapsed();
    let expected = Duration::from_millis(slot_ms * slots);
    let tolerance = Duration::from_millis(5);
    assert!(elapsed >= expected - tolerance, "elapsed {:?} < {:?}", elapsed, expected - tolerance);
}

#[test]
fn no_busy_wait_under_heavy_block_assembly() {
    use std::time::{Duration, Instant};

    let state = Arc::new(Mutex::new(FakeState::default()));
    let delay_ms = 40; // greater than slot duration
    let node = SlowNode::new(state.clone(), delay_ms);
    let slot_ms = 10;
    let cfg = DevLoopConfig { slot_ms, limits: DEFAULT_LIMITS };
    let mut dl = DevLoop::new(node, cfg);
    let slots = 3;
    let start = Instant::now();
    dl.run_for_slots(slots);
    let elapsed = start.elapsed();
    let min = Duration::from_millis(delay_ms * slots);
    let tolerance = Duration::from_millis(25); // allow some scheduling overhead
    assert!(elapsed >= min, "elapsed {:?} < min {:?}", elapsed, min);
    assert!(elapsed <= min + tolerance, "elapsed {:?} > max {:?}", elapsed, min + tolerance);
    let st = state.lock().unwrap();
    assert_eq!(st.height, slots);
}

struct ErrOnceNode {
    inner: FakeNode,
    errored: bool,
}

impl ErrOnceNode {
    fn new(state: Arc<Mutex<FakeState>>) -> Self {
        Self { inner: FakeNode::new(state), errored: false }
    }
}

impl DevNode for ErrOnceNode {
    fn height(&self) -> u64 { self.inner.height() }

    fn produce_block(&mut self, limits: BlockSelectionLimits) -> Result<(BuiltBlock, ApplyResult), ProduceError> {
        if !self.errored {
            self.errored = true;
            Err(ProduceError::HeaderBuild("injected".into()))
        } else {
            self.inner.produce_block(limits)
        }
    }

    fn now_unix(&self) -> u64 { self.inner.now_unix() }
}

#[test]
fn skip_slot_on_production_error() {
    let state = Arc::new(Mutex::new(FakeState::default()));
    let node = ErrOnceNode::new(state.clone());
    let cfg = DevLoopConfig { slot_ms: 1, limits: DEFAULT_LIMITS };
    let mut dl = DevLoop::new(node, cfg);
    dl.run_for_slots(1);
    assert_eq!(state.lock().unwrap().height, 0);
    dl.run_for_slots(2);
    let st = state.lock().unwrap();
    assert_eq!(st.height, 2);
    assert_eq!(st.ticks, 2);
}

struct BadSigNode {
    chain: Arc<Mutex<Chain>>,
}

impl BadSigNode {
    fn new(chain: Arc<Mutex<Chain>>) -> Self { Self { chain } }
}

impl DevNode for BadSigNode {
    fn height(&self) -> u64 { self.chain.lock().unwrap().height }

    fn produce_block(&mut self, _limits: BlockSelectionLimits) -> Result<(BuiltBlock, ApplyResult), ProduceError> {
        let mut chain = self.chain.lock().unwrap();

        // Vortex-only header fields
        let height       = chain.height + 1;
        let slot: u64    = height; // strict dev policy
        let epoch: u64   = chain.clock.current_epoch(slot);
        let bundle_len: u8 = DEFAULT_BUNDLE_LEN;
        let bundle_start = chain.clock.bundle_start(slot, bundle_len);
        let proposer_id: u64 = 1;

        // Produce VRF fields that match the validator set’s deterministic vrf_pubkey
        // (same seed used by init_chain_with_validator)
        let vrf_seed = hash_bytes_sha256(b"l1-blockchain/test-vrf-seed:v1");
        let vrf_signer = SchnorrkelVrfSigner::from_deterministic_seed(vrf_seed);
        let (vrf_output, vrf_preout, vrf_proof) = {
            let msg = build_vrf_msg(&chain.epoch_seed, bundle_start, proposer_id);
            vrf_signer.vrf_prove(&msg)
        };

        // Intentionally INVALID ed25519 signature (all zeros)
        let bad_sig = [0u8; 64];

        let header = BlockHeader {
            parent_hash:     chain.tip_hash,
            height,
            txs_root:        [0u8;32],
            receipts_root:   [0u8;32],
            gas_used:        0,
            randomness:      [0u8;32],
            reveal_set_root: [0u8;32],
            il_root:         [0u8;32],
            exec_base_fee:   0,
            commit_base_fee: 0,
            avail_base_fee:  0,
            timestamp:       0,
            slot,
            epoch,
            proposer_id,
            bundle_len,
            vrf_output,
            vrf_proof,
            vrf_preout,
            view: 0,
            justify_qc_hash: [0u8;32],
            // invalid signature on purpose
            signature: bad_sig,
        };
        let block = Block { header, transactions: vec![], reveals: vec![], justify_qc: dummy_qc() };
        let built  = BuiltBlock {
            block: block.clone(),
            selected_ids: SelectedIds { commit: vec![], avail: vec![], reveal: vec![] }
        };

        // Apply should fail at header signature verification
        let mut balances    = Balances::default();
        let mut nonces      = Nonces::default();
        let mut commitments = Commitments::default();
        let mut available   = Available::default();

        chain
            .apply_block(&block, &mut balances, &mut nonces, &mut commitments, &mut available)
            .map(|apply| (built, apply))
            .map_err(|_| ProduceError::HeaderBuild("apply failed".into()))
    }

    fn now_unix(&self) -> u64 { 0 }
}

#[test]
fn bad_header_signature_rejected() {
    let chain = Arc::new(Mutex::new(Chain::new()));
    let node = BadSigNode::new(chain.clone());
    let cfg = DevLoopConfig { slot_ms: 1, limits: DEFAULT_LIMITS };
    let mut dl = DevLoop::new(node, cfg);
    dl.run_for_slots(1);
    assert_eq!(chain.lock().unwrap().height, 0);
}

struct WrongParentNode {
    chain: Arc<Mutex<Chain>>,
}

impl WrongParentNode {
    fn new(chain: Arc<Mutex<Chain>>) -> Self { Self { chain } }
}

impl DevNode for WrongParentNode {
    fn height(&self) -> u64 { self.chain.lock().unwrap().height }

    fn produce_block(&mut self, _limits: BlockSelectionLimits) -> Result<(BuiltBlock, ApplyResult), ProduceError> {
        let mut chain = self.chain.lock().unwrap();

        // Vortex-only timing/identity
        let height       = chain.height + 1;
        let slot: u64    = height; // dev: one block per slot
        let epoch: u64   = chain.clock.current_epoch(slot);
        let bundle_len: u8 = DEFAULT_BUNDLE_LEN;
        let bundle_start = chain.clock.bundle_start(slot, bundle_len);
        let proposer_id: u64 = 1;

        // VRF fields consistent with the validator set used by init_chain_with_validator()
        let vrf_seed   = hash_bytes_sha256(b"l1-blockchain/test-vrf-seed:v1");
        let vrf        = SchnorrkelVrfSigner::from_deterministic_seed(vrf_seed);
        let (vrf_output, vrf_preout, vrf_proof) = {
            let msg = build_vrf_msg(&chain.epoch_seed, bundle_start, proposer_id);
            vrf.vrf_prove(&msg)
        };

        // Intentionally wrong parent hash
        let header = BlockHeader {
            parent_hash:     [1u8;32], // WRONG parent on purpose
            height,
            txs_root:        [0u8;32],
            receipts_root:   [0u8;32],
            gas_used:        0,
            randomness:      [0u8;32],
            reveal_set_root: [0u8;32],
            il_root:         [0u8;32],
            exec_base_fee:   0,
            commit_base_fee: 0,
            avail_base_fee:  0,
            timestamp:       0,
            slot,
            epoch,
            proposer_id,
            bundle_len,
            vrf_output,
            vrf_proof,
            vrf_preout,
            view: 0,
            justify_qc_hash: [0u8;32],
            signature: [0u8;64],
        };
        let block = Block { header, transactions: vec![], reveals: vec![], justify_qc: dummy_qc() };
        let built = BuiltBlock {
            block: block.clone(),
            selected_ids: SelectedIds { commit: vec![], avail: vec![], reveal: vec![] }
        };

        // Try to apply; expect failure due to wrong parent
        let mut balances    = Balances::default();
        let mut nonces      = Nonces::default();
        let mut commitments = Commitments::default();
        let mut available   = Available::default();

        chain
            .apply_block(&block, &mut balances, &mut nonces, &mut commitments, &mut available)
            .map(|apply| (built, apply))
            .map_err(|_| ProduceError::HeaderBuild("apply failed".into()))
    }

    fn now_unix(&self) -> u64 { 0 }
}

#[test]
fn wrong_parent_linkage_rejected() {
    let chain = Arc::new(Mutex::new(Chain::new()));
    let node = WrongParentNode::new(chain.clone());
    let cfg = DevLoopConfig { slot_ms: 1, limits: DEFAULT_LIMITS };
    let mut dl = DevLoop::new(node, cfg);
    dl.run_for_slots(1);
    assert_eq!(chain.lock().unwrap().height, 0);
}

struct PanicOnceNode {
    inner: FakeNode,
    panicked: bool,
}

impl PanicOnceNode {
    fn new(state: Arc<Mutex<FakeState>>) -> Self {
        Self { inner: FakeNode::new(state), panicked: false }
    }
}

impl DevNode for PanicOnceNode {
    fn height(&self) -> u64 { self.inner.height() }

    fn produce_block(&mut self, limits: BlockSelectionLimits) -> Result<(BuiltBlock, ApplyResult), ProduceError> {
        if !self.panicked {
            self.panicked = true;
            panic!("boom");
        }
        self.inner.produce_block(limits)
    }

    fn now_unix(&self) -> u64 { self.inner.now_unix() }
}

#[test]
fn panic_safety_no_state_corruption() {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    let state = Arc::new(Mutex::new(FakeState::default()));
    let node = PanicOnceNode::new(state.clone());
    let cfg = DevLoopConfig { slot_ms: 1, limits: DEFAULT_LIMITS };
    let mut dl = DevLoop::new(node, cfg);
    let res = catch_unwind(AssertUnwindSafe(|| dl.run_for_slots(1)));
    assert!(res.is_err());
    assert_eq!(state.lock().unwrap().height, 0);
    dl.run_for_slots(2);
    let st = state.lock().unwrap();
    assert_eq!(st.height, 2);
    assert_eq!(st.ticks, 2);
}
