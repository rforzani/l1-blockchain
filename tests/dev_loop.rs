use std::sync::{Arc, Mutex};
use l1_blockchain::consensus::dev_loop::{DevLoop, DevLoopConfig, DEFAULT_LIMITS, DevNode};
use l1_blockchain::mempool::{BlockSelectionLimits, MempoolConfig, MempoolImpl};
use l1_blockchain::node::{BuiltBlock, SelectedIds, ProduceError, Node};
use l1_blockchain::chain::ApplyResult;
use l1_blockchain::types::{Block, BlockHeader, Tx, RevealTx};
use ed25519_dalek::SigningKey;

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
        let header = BlockHeader {
            parent_hash: [0u8;32],
            height: st.height,
            proposer_pubkey: [0u8;32],
            txs_root: [0u8;32],
            receipts_root: [0u8;32],
            gas_used: 0,
            randomness: [0u8;32],
            reveal_set_root: [0u8;32],
            il_root: [0u8;32],
            exec_base_fee: 0,
            commit_base_fee: 0,
            avail_base_fee: 0,
            timestamp: 0,
            signature: [0u8;64],
        };
        let block = Block { transactions: Vec::<Tx>::new(), reveals: Vec::<RevealTx>::new(), header };
        let built = BuiltBlock { block, selected_ids: SelectedIds { commit: vec![], avail: vec![], reveal: vec![] } };
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
    let node = Node::new(mp, signer);
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
