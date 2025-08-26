// src/devnet.rs
use ed25519_dalek::{SigningKey, Signer};
use bitvec::vec::BitVec;

use crate::chain::{Chain, DEFAULT_BUNDLE_LEN};
use crate::codec::header_signing_bytes;
use crate::crypto::{addr_from_pubkey, addr_hex, hash_bytes_sha256};
use crate::crypto::bls::BlsSignatureBytes;
use crate::crypto::vrf::SchnorrkelVrfSigner;
use crate::pos::registry::{StakingConfig, Validator, ValidatorSet, ValidatorStatus};
use crate::state::{Available, Balances, Commitments, Nonces};
use crate::types::{Block, BlockHeader, RevealTx, Tx, QC};

fn dummy_qc() -> QC {
    QC { view: 0, block_id: [0u8; 32], agg_sig: BlsSignatureBytes([0u8; 96]), bitmap: BitVec::new() }
}

fn build_empty_alias_block(
    chain: &Chain,
    signer: &SigningKey,
    balances: &Balances,
    nonces: &Nonces,
    commitments: &Commitments,
    available: &Available,
) -> Block {
    // dev policy: slot == height
    let height = chain.height + 1;
    let slot   = height;
    let epoch  = chain.clock.current_epoch(slot);

    // alias path: empty VRF fields but still set bundle_len
    let bundle_len = DEFAULT_BUNDLE_LEN;
    let vrf_output = [0u8; 32];
    let vrf_preout = [0u8; 32];
    let vrf_proof: Vec<u8> = Vec::new();

    let mut block = Block {
        header: BlockHeader {
            // lineage
            parent_hash: chain.tip_hash,
            height,

            // execution roots (filled after STF simulation)
            txs_root: [0u8; 32],
            receipts_root: [0u8; 32],
            gas_used: 0,
            randomness: chain.tip_hash,
            reveal_set_root: [0u8; 32],
            il_root: [0u8; 32],

            // base fees
            exec_base_fee: chain.fee_state.exec_base,
            commit_base_fee: chain.fee_state.commit_base,
            avail_base_fee: chain.fee_state.avail_base,

            // timing & identity
            timestamp: (chain.clock.slot_start_unix(slot) / 1000) as u64,
            slot,
            epoch,
            // proposer is the single validator (id=1) we put into the set
            proposer_id: 1,

            // PoS/Vortex fields (alias fallback)
            bundle_len,
            vrf_output,
            vrf_proof,
            vrf_preout,

            // HotStuff header fields
            view: 0,
            justify_qc_hash: [0u8; 32],

            // ed25519 signature filled below
            signature: [0u8; 64],
        },
        transactions: Vec::<Tx>::new(),
        reveals: Vec::<RevealTx>::new(),
        batch_digests: Vec::new(),
        justify_qc: dummy_qc(),
    };

    // Simulate STF to compute canonical roots/gas (same flow your code uses)
    let mut sim_balances    = balances.clone();
    let mut sim_nonces      = nonces.clone();
    let mut sim_commitments = commitments.clone();
    let mut sim_available   = available.clone();

    let proposer_addr = addr_hex(&addr_from_pubkey(&signer.verifying_key().to_bytes()));
    let mut burned = 0u64;

    let body = crate::stf::process_block(
        &block,
        &chain.batch_store,
        &mut sim_balances,
        &mut sim_nonces,
        &mut sim_commitments,
        &mut sim_available,
        &chain.fee_state,
        &proposer_addr,
        &mut burned,
    ).expect("process_block");

    // fill in the roots and gas
    block.header.txs_root        = body.txs_root;
    block.header.receipts_root   = body.receipts_root;
    block.header.reveal_set_root = body.reveal_set_root;
    block.header.il_root         = body.il_root;
    block.header.gas_used        = body.gas_total;

    // sign the header (your verifier checks this)
    let preimage = header_signing_bytes(&block.header);
    block.header.signature = signer.sign(&preimage).to_bytes();

    block
}

/// Start a one-validator localnet and produce `n_blocks` empty blocks.
pub fn start_single_validator_localnet(n_blocks: u64) {
    // 1) Chain + single validator at genesis (mirrors your test helper)
    let mut chain = Chain::new();

    // DO NOT use deterministic keys like this in production; this is for localnet/dev only.
    let ed25519 = SigningKey::from_bytes(&[1u8; 32]);

    // Deterministic VRF just for devnet; required so the validator has a vrf_pubkey
    let vrf_seed = hash_bytes_sha256(b"devnet/vrf-seed:v1");
    let vrf      = SchnorrkelVrfSigner::from_deterministic_seed(vrf_seed);

    let cfg = StakingConfig { min_stake: 1, unbonding_epochs: 1, max_validators: u32::MAX };
    let v = Validator {
        id: 1,
        ed25519_pubkey: ed25519.verifying_key().to_bytes(),
        bls_pubkey: None,
        vrf_pubkey: vrf.public_bytes(),
        stake: 1,
        status: ValidatorStatus::Active,
    };
    let set  = ValidatorSet::from_genesis(0, &cfg, vec![v]);
    let seed = hash_bytes_sha256(b"devnet/epoch-seed:v1");

    chain.init_genesis(set, seed);

    // 2) In-memory state
    let mut balances    = Balances::default();
    let mut nonces      = Nonces::default();
    let mut commitments = Commitments::default();
    let mut available   = Available::default();

    // 3) Produce blocks
    for _ in 0..n_blocks {
        let block = build_empty_alias_block(&chain, &ed25519, &balances, &nonces, &commitments, &available);

        // apply block (same checks/roots path your chain applies)
        let _res = chain
            .apply_block(&block, &mut balances, &mut nonces, &mut commitments, &mut available)
            .expect("apply_block");

        println!("height={} tip={}", chain.height, hex::encode(chain.tip_hash));
    }
}