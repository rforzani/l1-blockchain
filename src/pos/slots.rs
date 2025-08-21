// src/pos/slots.rs

/// Slot/epoch timekeeping used by the chain and nodes.
/// - `genesis_unix_ms` is the UNIX timestamp (milliseconds) at which slot 0 starts.
/// - `slot_ms` is the fixed slot duration in milliseconds (must be > 0).
/// - `epoch_slots` is the fixed number of slots per epoch (must be > 0).
#[derive(Clone, Copy, Debug)]
pub struct SlotClock {
    pub genesis_unix_ms: u128, // fixed at genesis
    pub slot_ms: u64,
    pub epoch_slots: u64,
}

impl SlotClock {
    /// Returns the current global slot index for a given `now_unix_ms`.
    /// Behavior:
    /// - If `now_unix_ms < genesis_unix_ms`, returns 0 (pre-genesis clamps to slot 0).
    /// - Uses floor division; slot changes exactly at multiples of `slot_ms`.
    /// - Saturates at `u64::MAX` if the computed slot would overflow `u64`.
    #[inline]
    pub fn current_slot(&self, now_unix_ms: u128) -> u64 {
        let slot_ms = self.slot_ms;
        if slot_ms == 0 {
            // Misconfiguration: treat as slot 0 to avoid panic; prefer to validate at construction.
            return 0;
        }
        let delta_ms = now_unix_ms.saturating_sub(self.genesis_unix_ms);
        let slot = delta_ms / (slot_ms as u128);
        // Saturate to u64::MAX for extremely distant futures.
        if slot > u64::MAX as u128 {
            u64::MAX
        } else {
            slot as u64
        }
    }

    /// Returns the epoch index for a given `slot`.
    /// Behavior:
    /// - If `epoch_slots == 0`, returns 0 (misconfiguration guard).
    /// - Otherwise `slot / epoch_slots` (integer division).
    #[inline]
    pub fn current_epoch(&self, slot: u64) -> u64 {
        let es = self.epoch_slots;
        if es == 0 {
            0
        } else {
            slot / es
        }
    }

    /// Returns the UNIX time (ms) at which the given `slot` starts:
    /// `genesis_unix_ms + slot * slot_ms`.
    /// Uses saturating math to avoid overflow.
    #[inline]
    pub fn slot_start_unix(&self, slot: u64) -> u128 {
        let step = (slot as u128).saturating_mul(self.slot_ms as u128);
        self.genesis_unix_ms.saturating_add(step)
    }

    /// Returns the slot index within the current epoch: `slot % epoch_slots`.
    /// Behavior:
    /// - If `epoch_slots == 0`, returns 0 (misconfiguration guard).
    #[inline]
    pub fn slot_in_epoch(&self, slot: u64) -> u64 {
        let es = self.epoch_slots;
        if es == 0 { 0 } else { slot % es }
    }

    #[inline]
    pub fn bundle_start(&self, slot: u64, bundle_len: u8) -> u64 {
        let r = bundle_len.max(1) as u64;
        slot - (slot % r)
    }
}
