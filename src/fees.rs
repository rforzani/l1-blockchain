// src/fees.rs
use crate::state::{COMMIT_FEE, AVAIL_FEE};
use crate::gas::BASE_FEE_PER_TX;          

#[derive(Clone, Copy, Debug)]
pub struct FeeParams {
    pub exec_base: u64,    // reveal/execution base fee
    pub commit_base: u64,  // commit fee
    pub avail_base: u64,   // avail fee
    pub exec_target: u32,
    pub commit_target: u32,
    pub avail_target: u32,
    pub max_change_bps: u16,
    pub damping: u16,
    pub min_exec: u64,
    pub min_commit: u64,
    pub min_avail: u64,
}

pub const FEE_PARAMS: FeeParams = FeeParams {
    exec_base:   BASE_FEE_PER_TX,
    commit_base: COMMIT_FEE,
    avail_base:  AVAIL_FEE,
    exec_target: 70,
    commit_target: 50,
    avail_target: 50,
    max_change_bps: 1250, // ±12.5% cap per block (future)
    damping: 8,
    min_exec:   BASE_FEE_PER_TX,
    min_commit: COMMIT_FEE,
    min_avail:  AVAIL_FEE,
};

#[derive(Clone, Copy, Debug)] 
pub struct FeeState { 
    pub exec_base: u64, 
    pub commit_base: u64, 
    pub avail_base: u64 
}

impl FeeState { 
    pub fn from_defaults() -> Self {
        Self { 
            exec_base: FEE_PARAMS.exec_base, 
            commit_base: FEE_PARAMS.commit_base, 
            avail_base: FEE_PARAMS.avail_base 
        }
    }
}