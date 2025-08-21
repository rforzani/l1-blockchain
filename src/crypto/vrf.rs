// src/crypto/vrf.rs

use schnorrkel::{Keypair, PublicKey, SecretKey, signing_context};
use schnorrkel::vrf::{VRFProof, VRFPreOut};

/// Fixed-size VRF output we commit to on-chain: we use schnorrkel's VRFPreOut bytes (32).
pub const VRF_OUTPUT_BYTES: usize = 32;
pub type VrfOutput = [u8; VRF_OUTPUT_BYTES];

/// Scheme-dependent proof bytes (schnorrkel serializes to ~80-96 bytes).
pub type VrfProof = Vec<u8>;

/// Opaque VRF public key (sr25519, 32 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VrfPubkey(pub [u8; 32]);

/// Signer API: produce (output, proof) for a message + reveal pubkey.
pub trait VrfSigner {
    fn vrf_prove(&self, msg: &[u8]) -> (VrfOutput, VrfProof);
    fn vrf_pubkey(&self) -> VrfPubkey;
}

/// Verifier API: check (output, proof) for (pk, msg).
pub trait VrfVerifier {
    fn vrf_verify(pk: &VrfPubkey, msg: &[u8], out: &VrfOutput, proof: &VrfProof) -> bool;
}

/// Domain-separated message used for Vortex bundle selection.
/// msg = domain || epoch_seed || bundle_start_slot || proposer_id
#[inline]
pub fn build_vrf_msg(
    epoch_seed: &[u8; 32],
    bundle_start_slot: u64,
    proposer_id: u64
) -> [u8; 32 + 1 + 8 + 8] {
    let mut buf = [0u8; 32 + 1 + 8 + 8];
    buf[0] = 0xA7; // small domain tag for fixed-size message
    buf[1..33].copy_from_slice(epoch_seed);
    buf[33..41].copy_from_slice(&bundle_start_slot.to_le_bytes());
    buf[41..49].copy_from_slice(&proposer_id.to_le_bytes());
    buf
}

// ---------------- schnorrkel-backed implementation (always on) ----------------

const DS: &[u8] = b"vortex/vrf-bundle:v1";

/// Our signer backed by schnorrkel Keypair (sr25519).
pub struct SchnorrkelVrfSigner {
    kp: Keypair,
}

impl SchnorrkelVrfSigner {
    /// Construct from a 32-byte sr25519 secret. In production, load from secure storage/HSM.
    pub fn from_secret_key(sk_bytes: [u8; 32]) -> Self {
        let sk = SecretKey::from_bytes(&sk_bytes).expect("invalid sr25519 secret key");
        let pk: PublicKey = sk.to_public();
        Self { kp: Keypair { secret: sk, public: pk } }
    }

    /// Deterministic helper (tests/dev only): derive sr25519 from a 32-byte seed.
    pub fn from_deterministic_seed(seed32: [u8; 32]) -> Self {
        Self::from_secret_key(seed32)
    }

    #[cfg(test)]
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        Self { kp: Keypair::generate_with(&mut OsRng) }
    }

    pub fn public_bytes(&self) -> [u8; 32] { self.kp.public.to_bytes() }
}

impl VrfSigner for SchnorrkelVrfSigner {
    fn vrf_prove(&self, msg: &[u8]) -> (VrfOutput, VrfProof) {
        let ctx = signing_context(DS);
        // schnorrkel 0.11 returns (VRFInOut, VRFProof, VRFProofBatchable)
        let (inout, proof, _batchable) = self.kp.vrf_sign(ctx.bytes(msg));
        let preout = inout.to_preout();            // public pre-output
        let out: VrfOutput = preout.to_bytes();    // 32 bytes
        let proof_bytes: VrfProof = proof.to_bytes().to_vec();
        (out, proof_bytes)
    }

    fn vrf_pubkey(&self) -> VrfPubkey {
        VrfPubkey(self.kp.public.to_bytes())
    }
}

pub struct SchnorrkelVrf;

impl VrfVerifier for SchnorrkelVrf {
    fn vrf_verify(pk: &VrfPubkey, msg: &[u8], out: &VrfOutput, proof: &VrfProof) -> bool {
        // Parse pk
        let pk = match PublicKey::from_bytes(&pk.0) {
            Ok(p) => p,
            Err(_) => return false,
        };
        // Parse proof
        let proof = match VRFProof::from_bytes(proof) {
            Ok(p) => p,
            Err(_) => return false,
        };
        // Parse preout from the provided output bytes
        let preout = match VRFPreOut::from_bytes(out) {
            Ok(po) => po,
            Err(_) => return false,
        };
        // Verify
        let ctx = signing_context(DS);
        pk.vrf_verify(ctx.bytes(msg), &preout, &proof).is_ok()
    }
}
