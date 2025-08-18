// src/fees.rs
use crate::state::{COMMIT_FEE, AVAIL_FEE};
use crate::gas::BASE_FEE_PER_TX;          

#[derive(Clone, Copy, Debug)]
pub struct FeeParams {
    // Initial (genesis) bases; live values are in FeeState
    pub exec_base_init: u64,
    pub commit_base_init: u64,
    pub avail_base_init: u64,

    // Targets (units: items per block)
    pub exec_target_reveals_per_block: u32,
    pub commit_target_commits: u32,
    pub avail_target_avails: u32,

    // Per-lane tuning (for Point 2 we ONLY use the exec ones)
    pub exec_max_change_denominator: u16,   // e.g. 1250 = ±12.5% per block
    pub exec_damping_bps: u16,      // 10_000 = no extra damping

    // Floors
    pub exec_min_base: u64,
    pub min_commit: u64,
    pub min_avail: u64,
}

pub const FEE_PARAMS: FeeParams = FeeParams {
    exec_base_init:   BASE_FEE_PER_TX,
    commit_base_init: COMMIT_FEE,
    avail_base_init:  AVAIL_FEE,

    exec_target_reveals_per_block:    70,
    commit_target_commits:  50,
    avail_target_avails:    50,

    exec_max_change_denominator: 1250,
    exec_damping_bps: 10_000, // start with no damping; tune later

    exec_min_base:   BASE_FEE_PER_TX,
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
            exec_base: FEE_PARAMS.exec_base_init, 
            commit_base: FEE_PARAMS.commit_base_init, 
            avail_base: FEE_PARAMS.avail_base_init 
        }
    }
}

/// EIP-1559 style update on *execution* lane using reveal count.
pub fn update_exec_base(
    prev_base: u64,
    reveals_used: u32,
    target_reveals: u32,
    max_change_denominator: u16, // e.g., 8  => max step = prev/8
    min_base: u64,
    damping_bps: u16,            // 10_000 = no damping
) -> u64 {
    // Guard rails
    if target_reveals == 0 {
        return prev_base.max(min_base);
    }
    let prev = prev_base.max(min_base);

    // diff/target in signed integer math
    let diff = (reveals_used as i128) - (target_reveals as i128);
    if diff == 0 { return prev; }

    // base step = prev / max_change_denominator
    let base_step = (prev as i128) / (max_change_denominator as i128);
    if base_step == 0 { return prev.max(min_base); }

    // proportional factor = |diff| / target
    let prop = (diff.abs() * 10_000i128) / (target_reveals as i128); // in bps

    // apply damping if any
    let effective_bps = if damping_bps == 0 { 10_000 } else { (10_000i128 * 10_000i128 / damping_bps as i128).min(20_000) };
    let prop_bps = (prop * effective_bps) / 10_000i128; // still in bps

    // step = base_step * prop_bps / 10_000, at least 1
    let mut step = (base_step * prop_bps) / 10_000i128;
    if step == 0 { step = 1; }

    let next = if diff > 0 {
        (prev as i128).saturating_add(step)
    } else {
        (prev as i128).saturating_sub(step)
    };

    next.max(min_base as i128) as u64
}