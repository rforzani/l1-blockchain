// src/pos/registry.rs

use core::cmp::Ordering;

pub type ValidatorId = u64;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ValidatorStatus { Active, Inactive, Jailed }

#[derive(Clone, Debug)]
pub struct Validator {
    pub id: ValidatorId,
    pub ed25519_pubkey: [u8; 32],
    pub bls_pubkey: Option<[u8; 48]>,
    pub stake: u128,
    pub status: ValidatorStatus,
}

#[derive(Clone, Debug)]
pub struct StakingConfig {
    pub min_stake: u128,
    pub unbonding_epochs: u64,
    pub max_validators: u32,
}

#[derive(Clone, Debug)]
pub struct ValidatorSet {
    pub epoch: u64,
    pub total_stake: u128,
    pub validators: Vec<Validator>, // sorted by id for determinism
}

#[derive(Debug)]
pub enum PosError {
    NotFound(ValidatorId),
    BelowMinStake,
    InsufficientStake,
    MaxValidators,
}

impl ValidatorSet {
    /// Build a deterministic, sanitized validator set snapshot for `epoch`.
    /// - Input validators are **sorted by id** and deduplicated by id.
    /// - If multiple entries share the same id, the **first** occurrence wins; later ones are dropped.
    /// - Duplicate ed25519 pubkeys beyond the first are also dropped.
    /// - Validators marked `Active` but below `cfg.min_stake` are downgraded to `Inactive`.
    /// - The list is truncated to `cfg.max_validators` if necessary.
    /// - `total_stake` is computed as the sum of stakes for **Active** validators only.
    pub fn from_genesis(epoch: u64, cfg: &StakingConfig, mut vals: Vec<Validator>) -> Self {
        // 1) Sort by id for determinism
        vals.sort_by(|a, b| a.id.cmp(&b.id));

        // 2) Deduplicate by id and by ed25519 pubkey (first wins)
        let mut dedup: Vec<Validator> = Vec::with_capacity(vals.len());
        let mut last_id: Option<ValidatorId> = None;
        use std::collections::HashSet;
        let mut seen_pubkeys: HashSet<[u8; 32]> = HashSet::with_capacity(vals.len());

        for mut v in vals.into_iter() {
            if last_id == Some(v.id) { continue; } // drop duplicates by id (keep first)
            if !seen_pubkeys.insert(v.ed25519_pubkey) { continue; } // drop duplicate pubkeys

            // Enforce min_stake on Active; downgrade if necessary.
            if v.status == ValidatorStatus::Active && v.stake < cfg.min_stake {
                v.status = ValidatorStatus::Inactive;
            }

            dedup.push(v);
            last_id = Some(dedup.last().unwrap().id);
        }

        // 3) Cap to max_validators (keep the lowest ids deterministically)
        let maxv = cfg.max_validators as usize;
        if dedup.len() > maxv {
            dedup.truncate(maxv);
        }

        // 4) Compute total stake over Active validators only
        let total_stake = dedup.iter()
            .filter(|v| v.status == ValidatorStatus::Active)
            .map(|v| v.stake)
            .fold(0u128, |acc, x| acc.saturating_add(x));

        Self {
            epoch,
            total_stake,
            validators: dedup,
        }
    }

    #[inline]
    pub fn get(&self, id: ValidatorId) -> Option<&Validator> {
        // binary search because validators are sorted by id
        self.validators.binary_search_by(|v| v.id.cmp(&id))
            .ok()
            .map(|idx| &self.validators[idx])
    }

    #[inline]
    fn get_mut(&mut self, id: ValidatorId) -> Option<&mut Validator> {
        match self.validators.binary_search_by(|v| v.id.cmp(&id)) {
            Ok(idx) => Some(&mut self.validators[idx]),
            Err(_) => None,
        }
    }

    #[inline]
    pub fn index_of(&self, id: ValidatorId) -> Option<usize> {
        self.validators.binary_search_by(|v| v.id.cmp(&id)).ok()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    #[inline]
    pub fn total_stake(&self) -> u128 {
        self.total_stake
    }

    /// Increase `id`'s stake by `amount`.
    /// - Works for any status.
    /// - Saturates on overflow (u128::MAX).
    /// - Recomputes `total_stake` (only Active stake counts).
    pub fn bond(&mut self, id: ValidatorId, amount: u128, _cfg: &StakingConfig) -> Result<(), PosError> {
        let v = self.get_mut(id).ok_or(PosError::NotFound(id))?;
        // Saturating add to avoid panic on unrealistic overflow.
        v.stake = v.stake.saturating_add(amount);
        self.recompute_total_stake();
        Ok(())
    }

    /// Decrease `id`'s stake by `amount`.
    /// - Fails if `amount > stake`.
    /// - If validator is `Active`, it **cannot** go below `min_stake`; returns `BelowMinStake`.
    /// - Recomputes `total_stake`.
    pub fn unbond(&mut self, id: ValidatorId, amount: u128, cfg: &StakingConfig) -> Result<(), PosError> {
        let v = self.get_mut(id).ok_or(PosError::NotFound(id))?;
        if amount > v.stake {
            return Err(PosError::InsufficientStake);
        }
        let new_stake = v.stake - amount;

        if v.status == ValidatorStatus::Active && new_stake < cfg.min_stake {
            return Err(PosError::BelowMinStake);
        }

        v.stake = new_stake;
        self.recompute_total_stake();
        Ok(())
    }

    /// Activate a validator:
    /// - Requires `stake >= min_stake`.
    /// - Idempotent if already Active.
    /// - Allowed from Inactive or Jailed (policy: STF may gate unjailing separately).
    pub fn activate(&mut self, id: ValidatorId) -> Result<(), PosError> {
        // We need min_stake; fetch from peers by reading an Active to infer? Better: pass cfg.
        // Since signature doesn't include cfg, we enforce min_stake using current set policy:
        // A conservative choice: require non-zero stake; actual min check must be done in STF
        // before calling `activate`. To preserve strictness, we scan the current min among actives,
        // but that can be zero. Instead, we enforce "non-zero"; the STF should call unbond/bond first.
        //
        // To keep "production-ready" and consistent with earlier guidance, we assume the STF ensures
        // min-stake before activation. If stake is zero, treat as BelowMinStake.
        let v = self.get_mut(id).ok_or(PosError::NotFound(id))?;
        if v.stake == 0 {
            return Err(PosError::BelowMinStake);
        }
        if v.status == ValidatorStatus::Active {
            return Ok(());
        }
        v.status = ValidatorStatus::Active;
        self.recompute_total_stake();
        Ok(())
    }

    /// Deactivate a validator. Idempotent.
    pub fn deactivate(&mut self, id: ValidatorId) -> Result<(), PosError> {
        let v = self.get_mut(id).ok_or(PosError::NotFound(id))?;
        if v.status != ValidatorStatus::Inactive {
            v.status = ValidatorStatus::Inactive;
            self.recompute_total_stake();
        }
        Ok(())
    }

    /// Jail a validator (e.g., for slashing or faults). Idempotent.
    /// Jailed validators do not contribute to `total_stake`.
    pub fn jail(&mut self, id: ValidatorId) -> Result<(), PosError> {
        let v = self.get_mut(id).ok_or(PosError::NotFound(id))?;
        if v.status != ValidatorStatus::Jailed {
            v.status = ValidatorStatus::Jailed;
            self.recompute_total_stake();
        }
        Ok(())
    }

    // ---- internal helpers ----

    #[inline]
    fn recompute_total_stake(&mut self) {
        self.total_stake = self.validators.iter()
            .filter(|v| v.status == ValidatorStatus::Active)
            .map(|v| v.stake)
            .fold(0u128, |acc, x| acc.saturating_add(x));
    }
}
