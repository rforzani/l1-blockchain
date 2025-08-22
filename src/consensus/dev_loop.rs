use crate::{chain::ApplyResult, mempool::BlockSelectionLimits, node::{BuiltBlock, ProduceError}};
use std::{thread, time::{Duration, Instant}};

pub const DEFAULT_SLOT_MS: u64 = 1000;

pub const DEFAULT_LIMITS: BlockSelectionLimits = BlockSelectionLimits { max_commits: 1024, max_avails: 1024, max_reveals: 1024 };

pub struct DevLoopConfig { 
    pub slot_ms: u64, 
    pub limits: BlockSelectionLimits
}

// Generic over a concrete Node type so tests can swap fakes later
pub struct DevLoop<N> { 
    pub node: N, 
    cfg: DevLoopConfig 
}

pub trait DevNode {
    fn height(&self) -> u64;
    fn produce_block(&mut self, limits: BlockSelectionLimits) -> Result<(BuiltBlock, ApplyResult), ProduceError>;
    fn now_unix(&self) -> u64;
}

impl<N> DevLoop<N> where N: DevNode {
    pub fn new(node: N, cfg: DevLoopConfig) -> Self {
        assert!(cfg.slot_ms > 0, "slot_ms must be > 0");
        Self { node: node, cfg: cfg }
    }

    fn tick_once(&mut self) -> bool {
        let start = Instant::now();
        let before = self.node.height();
        println!("Height Before Block Build: {}", before);
        
        let res : Result<(BuiltBlock, ApplyResult), ProduceError> = self.node.produce_block(self.cfg.limits.clone());

        match &res {
            Ok((_built, _apply)) => {
                println!("Built Block: {:?}", _built.block);
            }
            Err(e) => {
                println!("slot failed: {:?}", e);
            }
        }

        let advanced = self.node.height() > before;

        // Sleep the remainder of the slot
        let slot = Duration::from_millis(self.cfg.slot_ms);
        let elapsed = start.elapsed();
        if elapsed < slot {
            thread::sleep(slot - elapsed);
        }

        advanced
    }

    pub fn run_for_slots(&mut self, n: u64) {
        for _ in 0..n {
            self.tick_once();
        }
    }
    
    pub fn run_until_height(&mut self, h: u64) {
        while self.node.height() < h {
            self.tick_once();
        }
    }
    
    pub fn run_for_duration(&mut self, millis: u64) {
        let start = Instant::now();
        let total = Duration::from_millis(millis);
        while start.elapsed() < total {
            self.tick_once();
        }
    }
}
