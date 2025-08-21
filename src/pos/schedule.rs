// src/pos/schedule.rs

use crate::pos::registry::{ValidatorId, ValidatorSet, ValidatorStatus};
use crate::crypto::hash_bytes_sha256;

/// Proposer schedule interface: rebuild once per epoch, O(1) leader lookup per slot.
pub trait ProposerSchedule {
    /// Rebuild the schedule for an epoch using the validator set snapshot and an epoch seed.
    fn rebuild(
        &mut self,
        epoch: u64,
        epoch_slots: u64,
        set: &ValidatorSet,
        epoch_seed: [u8; 32],
    );

    /// Return the scheduled leader for a given *global* slot, or None when no leader is eligible.
    fn leader_for_slot(&self, global_slot: u64) -> Option<ValidatorId>;

    fn epoch(&self) -> u64;
    fn epoch_slots(&self) -> u64;
}

/// Deterministic, stake-weighted leader schedule built with a fixed-point alias table.
/// - Rebuild: O(n_active + epoch_slots)
/// - Lookup: O(1)
pub struct AliasSchedule {
    pub epoch: u64,
    pub epoch_slots: u64,
    pub leaders: Vec<ValidatorId>, // length == epoch_slots (or 0 if no active stake)
}

impl Default for AliasSchedule {
    fn default() -> Self {
        Self { epoch: 0, epoch_slots: 0, leaders: Vec::new() }
    }
}

impl AliasSchedule {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ProposerSchedule for AliasSchedule {
    fn rebuild(
        &mut self,
        epoch: u64,
        epoch_slots: u64,
        set: &ValidatorSet,
        epoch_seed: [u8; 32],
    ) {
        self.epoch = epoch;
        self.epoch_slots = epoch_slots;

        // If the epoch has zero slots, there is nothing to schedule.
        if epoch_slots == 0 {
            self.leaders.clear();
            return;
        }

        // 0) Gather active validators and their stakes.
        let mut ids: Vec<ValidatorId> = Vec::new();
        let mut weights: Vec<u128> = Vec::new();
        for v in &set.validators {
            if v.status == ValidatorStatus::Active {
                // Only count strictly positive stake; zero stake means ineligible.
                if v.stake > 0 {
                    ids.push(v.id);
                    weights.push(v.stake);
                }
            }
        }

        // If no active validators with positive stake, schedule is empty.
        let n = ids.len();
        if n == 0 {
            self.leaders.clear();
            return;
        }

        // 1) Build the alias table (fixed-point integer method).
        // Scale S defines the "1.0" threshold for bucket probabilities.
        const S: u128 = 1u128 << 64;

        let total: u128 = weights.iter().copied().sum();
        if total == 0 {
            // Defensive: if all active stakes somehow sum to zero, treat as no leader.
            self.leaders.clear();
            return;
        }

        let n_u128 = n as u128;

        // prob[i] ~= (weights[i] / total) * n  in fixed-point space (scaled by S).
        let mut prob: Vec<u128> = Vec::with_capacity(n);
        prob.extend(weights.iter().map(|&w| w.saturating_mul(n_u128).saturating_mul(S) / total));

        let mut alias: Vec<usize> = vec![0; n];

        // Partition into "small" (< S) and "large" (>= S).
        let mut small: Vec<usize> = Vec::new();
        let mut large: Vec<usize> = Vec::new();
        small.reserve(n);
        large.reserve(n);

        for i in 0..n {
            if prob[i] < S {
                small.push(i);
            } else {
                large.push(i);
            }
        }

        // Construct the alias table.
        while let (Some(l), Some(g)) = (small.pop(), large.pop()) {
            alias[l] = g;

            // prob[g] = prob[g] + prob[l] - S
            // This preserves total mass while assigning l's deficit to g.
            let new_pg = prob[g].saturating_add(prob[l]).saturating_sub(S);
            prob[g] = new_pg;

            if new_pg < S {
                small.push(g);
            } else {
                large.push(g);
            }
        }

        // Any remaining buckets have prob == S (i.e., always choose themselves).
        for i in small.into_iter().chain(large.into_iter()) {
            prob[i] = S;
            alias[i] = i;
        }

        // 2) Deterministic hash-based PRNG seeded by epoch_seed.
        struct HashRng {
            state: [u8; 32],
            ctr: u64,
        }
        impl HashRng {
            fn new(seed: [u8; 32]) -> Self { Self { state: seed, ctr: 0 } }
            #[inline]
            fn bump(&mut self) {
                // Derive next state = H(state || counter)
                let mut buf = [0u8; 40];
                buf[0..32].copy_from_slice(&self.state);
                buf[32..40].copy_from_slice(&self.ctr.to_le_bytes());
                self.state = hash_bytes_sha256(&buf);
                self.ctr = self.ctr.wrapping_add(1);
            }
            #[inline]
            fn next_u64(&mut self) -> u64 {
                self.bump();
                u64::from_le_bytes(self.state[0..8].try_into().unwrap())
            }
            #[inline]
            fn next_u128(&mut self) -> u128 {
                let lo = self.next_u64() as u128;
                let hi = self.next_u64() as u128;
                (hi << 64) | lo
            }
        }

        let mut rng = HashRng::new(epoch_seed);

        // 3) Sample leaders for each slot using the alias table.
        // Leaders length must equal epoch_slots; convert carefully.
        let slots_usize: usize = match usize::try_from(epoch_slots) {
            Ok(v) => v,
            Err(_) => {
                // On 32-bit usize targets, absurdly large epoch_slots would overflow.
                // Fail safely by capping to usize::MAX.
                usize::MAX
            }
        };
        let mut leaders: Vec<ValidatorId> = Vec::with_capacity(slots_usize);

        for _ in 0..slots_usize {
            // Candidate bucket: uniform over buckets 0..n-1
            let i = (rng.next_u64() as usize) % n;
            // Fixed-point toss in [0, S)
            let r = (rng.next_u128() % S) as u128;

            let idx = if r < prob[i] { i } else { alias[i] };
            leaders.push(ids[idx]);
        }

        self.leaders = leaders;
    }

    fn leader_for_slot(&self, global_slot: u64) -> Option<ValidatorId> {
        if self.leaders.is_empty() || self.epoch_slots == 0 {
            return None;
        }
        let idx = (global_slot % self.epoch_slots) as usize;
        // idx is always within bounds because leaders.len() == epoch_slots
        Some(self.leaders[idx])
    }

    #[inline]
    fn epoch(&self) -> u64 {
        self.epoch
    }

    #[inline]
    fn epoch_slots(&self) -> u64 {
        self.epoch_slots
    }
}
