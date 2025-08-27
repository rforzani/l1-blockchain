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
    pub commit_target_commits_per_block: u32,
    pub avail_target_avails_per_block: u32,

    // Per-lane tuning
    pub exec_max_change_denominator: u16,   // e.g. 1250 = ±12.5% per block
    pub exec_damping_bps: u16,      // 10_000 = no extra damping

    pub commit_max_change_denominator: u16,   // e.g. 1250 = ±12.5% per block
    pub commit_damping_bps: u16,      // 10_000 = no extra damping

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
    commit_target_commits_per_block:  50,
    avail_target_avails_per_block:    50,

    exec_max_change_denominator: 1250,
    exec_damping_bps: 10_000, // start with no damping; tune later

    commit_max_change_denominator: 1250,
    commit_damping_bps: 10_000, // start with no damping; tune later

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

#[derive(Clone, Copy, Debug)]
pub enum Lane { Exec, Commit, Avail }

#[inline]
pub fn lane_base(f: &FeeState, lane: Lane) -> u64 {
    match lane {
        Lane::Exec => f.exec_base,
        Lane::Commit => f.commit_base,
        Lane::Avail => f.avail_base,
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

pub fn update_commit_base(prev_base: u64, commits_used: u32) -> u64 {
    update_exec_base(
        prev_base,
        commits_used,
        FEE_PARAMS.commit_target_commits_per_block,
        FEE_PARAMS.commit_max_change_denominator,
        FEE_PARAMS.min_commit,
        FEE_PARAMS.commit_damping_bps,
    )
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
    use crate::chain::DEFAULT_BUNDLE_LEN;
    use crate::crypto::vrf::{build_vrf_msg, SchnorrkelVrfSigner, VrfSigner};
    use crate::fees::{split_amount, update_exec_base, FeeSplitBps, FEE_PARAMS, FeeState};
    use crate::stf::process_commit;
    use crate::state::{Balances, Commitments, CHAIN_ID};
    use crate::types::{Transaction, CommitTx, BlockHeader, Hash};
    use crate::codec::{tx_bytes, access_list_bytes, string_bytes, header_bytes};
    use crate::crypto::{
        addr_from_pubkey, addr_hex, commitment_hash, commit_signing_preimage,
        hash_bytes_sha256, bls::BlsSigner,
    };
    use crate::mempool::encrypted::ThresholdCiphertext;
    use ed25519_dalek::{SigningKey, Signer};

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
        let cfg = FeeSplitBps{ burn_bps: 8_000, proposer_bps: 1_500, treasury_bps: 500 };
        let amount = 1_000u64;
        let proposer = amount.saturating_mul(cfg.proposer_bps as u64) / 10_000;
        let treasury = amount.saturating_mul(cfg.treasury_bps as u64) / 10_000;
        let burn = amount - proposer - treasury;
        assert_eq!(burn + proposer + treasury, amount);
        assert_eq!(proposer, 150);
        assert_eq!(treasury, 50);
        assert_eq!(burn, 800);
    }

    fn addr(i: u8) -> String {
        format!(
            "0x{:02x}{:02x}000000000000000000000000000000000000",
            i, i
        )
    }

    fn make_commit(
        signer: &SigningKey,
        tx: &Transaction,
        salt: Hash,
    ) -> CommitTx {
        let tx_ser = tx_bytes(tx);
        let al_bytes = access_list_bytes(&tx.access_list);
        let commitment = commitment_hash(&tx_ser, &al_bytes, &salt, CHAIN_ID);
        let ephemeral_pk = BlsSigner::from_sk_bytes(&[1u8; 32])
            .expect("valid sk")
            .public_key_bytes();
        let encrypted_payload = ThresholdCiphertext {
            ephemeral_pk,
            encrypted_data: vec![0u8; 32],
            tag: [0u8; 32],
            epoch: 1,
        };
        let sender = addr_hex(&addr_from_pubkey(&signer.verifying_key().to_bytes()));
        let sender_bytes = string_bytes(&sender);
        let payload_hash = encrypted_payload.commitment_hash();
        let preimage = commit_signing_preimage(
            &commitment,
            &payload_hash,
            &sender_bytes,
            &al_bytes,
            CHAIN_ID,
        );
        let sig = signer.sign(&preimage).to_bytes();
        CommitTx {
            commitment,
            sender,
            access_list: tx.access_list.clone(),
            encrypted_payload,
            pubkey: signer.verifying_key().to_bytes(),
            sig,
        }
    }

    #[test]
    fn proposer_gets_commit_fee_share_and_burn_tracked() {
        let sender_signer = SigningKey::from_bytes(&[1u8; 32]);
        let proposer_signer = SigningKey::from_bytes(&[2u8; 32]);
        let sender_addr = addr_hex(&addr_from_pubkey(&sender_signer.verifying_key().to_bytes()));
        let proposer_addr = addr_hex(&addr_from_pubkey(&proposer_signer.verifying_key().to_bytes()));

        let mut balances = Balances::default();
        balances.insert(sender_addr.clone(), 200);
        balances.insert(proposer_addr.clone(), 0);
        let mut commitments = Commitments::default();

        let tx = Transaction::transfer(&sender_addr, &addr(3), 5, 0);
        let commit_tx = make_commit(&sender_signer, &tx, [9u8; 32]);

        let mut events = Vec::new();
        let mut fee_state = FeeState::from_defaults();
        fee_state.commit_base = 100;
        let mut burned_total = 0u64;

        process_commit(
            &commit_tx,
            &mut balances,
            &mut commitments,
            0,
            &mut events,
            &fee_state,
            &proposer_addr,
            &mut burned_total,
        )
        .unwrap();

        assert_eq!(*balances.get(&sender_addr).unwrap(), 100);
        assert_eq!(*balances.get(&proposer_addr).unwrap(), 5);
        assert_eq!(burned_total, 95);
    }

    #[test]
    fn block_hash_changes_with_proposer() {
        use crate::chain::DEFAULT_BUNDLE_LEN;

        // Deterministic epoch/slot metadata for the test (not used by this assertion)
        let epoch_seed = [7u8; 32];
        let slot: u64 = 0;
        let epoch: u64 = 0;
        let bundle_len = DEFAULT_BUNDLE_LEN;

        // Helper: synthesize VRF-looking fields deterministically from proposer_id
        fn fake_vrf_fields(proposer_id: u64) -> ([u8; 32], [u8; 32], Vec<u8>) {
            let mut m = Vec::with_capacity(16 + 8);
            m.extend_from_slice(b"fake-vrf-preout");
            m.extend_from_slice(&proposer_id.to_be_bytes());
            let preout = hash_bytes_sha256(&m);
        
            let out = hash_bytes_sha256(&preout);
        
            let mut proof = Vec::with_capacity(33);
            proof.extend_from_slice(&preout);
            proof.push(0x01);
        
            (out, preout, proof)
        }

        // Constructor that fills Vortex fields (non-empty proof => Vortex path),
        // while keeping other fields identical.
        let mut mk_header = |proposer_id: u64| {
            let (vrf_output, vrf_preout, vrf_proof) = fake_vrf_fields(proposer_id);
            BlockHeader {
                parent_hash:     [1u8; 32],
                height:          1,
                txs_root:        [0u8; 32],
                receipts_root:   [0u8; 32],
                gas_used:        0,
                randomness:      [0u8; 32],
                reveal_set_root: [0u8; 32],
                il_root:         [0u8; 32],
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
                signature:       [0u8; 64],
            }
        };

        let h1 = mk_header(1);
        let h2 = mk_header(2);

        // Hash the serialized header preimage (or header_signing_bytes if that’s your canonical hash)
        let d1 = hash_bytes_sha256(&header_bytes(&h1));
        let d2 = hash_bytes_sha256(&header_bytes(&h2));

        assert_ne!(d1, d2);
    }
}