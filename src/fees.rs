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

pub struct FeeSplitBps {
    pub burn_bps: u16,
    pub proposer_bps: u16,
    pub treasury_bps: u16,
}

pub const FEE_SPLIT: FeeSplitBps = FeeSplitBps {
    burn_bps: 9_500, proposer_bps: 500, treasury_bps: 0
};

/// Split a fee `amount` into (burn, proposer, treasury) portions
/// according to `FEE_SPLIT`. Totals are conserved; any rounding
/// remainder is added to burn.
pub fn split_amount(amount: u64) -> (u64 /*burn*/, u64 /*proposer*/, u64 /*treasury*/) {
    let total_bps: u64 = 10_000; // 100% in basis points

    let proposer = amount.saturating_mul(FEE_SPLIT.proposer_bps as u64) / total_bps;
    let treasury = amount.saturating_mul(FEE_SPLIT.treasury_bps as u64) / total_bps;

    // Burn is “what’s left” after proposer+treasury; ensures exact conservation
    let used = proposer + treasury;
    let burn = amount.saturating_sub(used);

    (burn, proposer, treasury)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cap_step(prev: u64) -> u64 {
        let base = prev.max(FEE_PARAMS.exec_min_base);
        let step = base / FEE_PARAMS.exec_max_change_denominator as u64;
        if step == 0 { 1 } else { step }
    }

    #[test]
    fn stays_same_at_target() {
        let prev = 100;
        let target = FEE_PARAMS.exec_target_reveals_per_block;
        let next = update_exec_base(
            prev,
            target,
            target,
            FEE_PARAMS.exec_max_change_denominator,
            FEE_PARAMS.exec_min_base,
            FEE_PARAMS.exec_damping_bps,
        );
        assert_eq!(next, prev);
    }

    #[test]
    fn increases_when_over_target() {
        let prev = FEE_PARAMS.exec_max_change_denominator as u64;
        let reveals = FEE_PARAMS.exec_target_reveals_per_block * 2;
        let next = update_exec_base(
            prev,
            reveals,
            FEE_PARAMS.exec_target_reveals_per_block,
            FEE_PARAMS.exec_max_change_denominator,
            FEE_PARAMS.exec_min_base,
            FEE_PARAMS.exec_damping_bps,
        );
        assert!(next > prev);
        assert!(next <= prev + cap_step(prev));
    }

    #[test]
    fn decreases_when_under_target() {
        let prev = FEE_PARAMS.exec_max_change_denominator as u64;
        let reveals = 0;
        let next = update_exec_base(
            prev,
            reveals,
            FEE_PARAMS.exec_target_reveals_per_block,
            FEE_PARAMS.exec_max_change_denominator,
            FEE_PARAMS.exec_min_base,
            FEE_PARAMS.exec_damping_bps,
        );
        assert!(next < prev);
        assert!(next >= FEE_PARAMS.exec_min_base);
        assert!(prev - next <= cap_step(prev));
    }

    #[test]
    fn respects_floor() {
        let prev = FEE_PARAMS.exec_min_base;
        let reveals = 0;
        let next = update_exec_base(
            prev,
            reveals,
            FEE_PARAMS.exec_target_reveals_per_block,
            FEE_PARAMS.exec_max_change_denominator,
            FEE_PARAMS.exec_min_base,
            FEE_PARAMS.exec_damping_bps,
        );
        assert_eq!(next, FEE_PARAMS.exec_min_base);
    }

    #[test]
    fn target_zero_guard() {
        let prev = 100;
        let next = update_exec_base(
            prev,
            10,
            0,
            FEE_PARAMS.exec_max_change_denominator,
            FEE_PARAMS.exec_min_base,
            FEE_PARAMS.exec_damping_bps,
        );
        assert!(next >= FEE_PARAMS.exec_min_base);
    }

    #[test]
    fn damping_effect_smoke_test() {
        let prev = 100;
        let reveals = FEE_PARAMS.exec_target_reveals_per_block * 2;
        let next_nodamp = update_exec_base(
            prev,
            reveals,
            FEE_PARAMS.exec_target_reveals_per_block,
            FEE_PARAMS.exec_max_change_denominator,
            FEE_PARAMS.exec_min_base,
            10_000,
        );
        let next_damped = update_exec_base(
            prev,
            reveals,
            FEE_PARAMS.exec_target_reveals_per_block,
            FEE_PARAMS.exec_max_change_denominator,
            FEE_PARAMS.exec_min_base,
            FEE_PARAMS.exec_damping_bps,
        );
        assert!(next_damped - prev <= next_nodamp - prev);
    }

    #[test]
    fn split_amount_sends_share_to_proposer() {
        let amount = 1000;
        let (burn, proposer, treasury) = split_amount(amount);
        assert_eq!(burn + proposer + treasury, amount);
        assert_eq!(proposer, 50);   // 5% of 1000
        assert_eq!(treasury, 0);
        assert_eq!(burn, 950);
    }

    #[test]
    fn split_amount_with_shares() {
        // verify math with a hypothetical split (burn=8000, proposer=1500, treasury=500)
        let cfg = FeeSplitBps { burn_bps: 8_000, proposer_bps: 1_500, treasury_bps: 500 };
        let amount = 1_000u64;
        let proposer = amount.saturating_mul(cfg.proposer_bps as u64) / 10_000;
        let treasury = amount.saturating_mul(cfg.treasury_bps as u64) / 10_000;
        let burn = amount - proposer - treasury;
        assert_eq!(burn + proposer + treasury, amount);
        assert_eq!(proposer, 150);
        assert_eq!(treasury, 50);
        assert_eq!(burn, 800);
    }
}