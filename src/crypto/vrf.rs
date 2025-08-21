use schnorrkel::{Keypair, PublicKey, MiniSecretKey, ExpansionMode, signing_context};
use crate::crypto::hash_bytes_sha256;

pub const VRF_OUTPUT_BYTES: usize = 32;
pub type VrfOutput = [u8; VRF_OUTPUT_BYTES];
pub type VrfPreOut = [u8; VRF_OUTPUT_BYTES];
pub type VrfProof  = Vec<u8>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VrfPubkey(pub [u8; 32]);

pub trait VrfSigner {
    fn vrf_prove(&self, msg: &[u8]) -> (VrfOutput, VrfPreOut, VrfProof);
}

pub trait VrfVerifier {
    fn vrf_verify(
        pk: &VrfPubkey,
        msg: &[u8],
        out: &VrfOutput,
        preout: &VrfPreOut,
        proof: &VrfProof,
    ) -> bool;
}

pub struct SchnorrkelVrfSigner {
    pub(crate) kp: Keypair,
}

pub struct SchnorrkelVrf;

impl SchnorrkelVrfSigner {
    pub fn from_deterministic_seed(seed32: [u8; 32]) -> Self {
        let mini = MiniSecretKey::from_bytes(&seed32).expect("bad mini secret");
        let kp = mini.expand_to_keypair(ExpansionMode::Uniform);
        Self { kp }
    }
    pub fn public_bytes(&self) -> [u8; 32] { self.kp.public.to_bytes() }
}

const CTX: &[u8] = b"l1-vortex/vrf";

/// ===== Production path: real schnorrkel VRF (uses OS randomness) =====
#[cfg(not(feature = "vrf_deterministic"))]
impl VrfSigner for SchnorrkelVrfSigner {
    fn vrf_prove(&self, msg: &[u8]) -> (VrfOutput, VrfPreOut, VrfProof) {
        use schnorrkel::signing_context;
        let (inout, proof, _) = self.kp.vrf_sign(signing_context(b"l1-vortex/vrf").bytes(msg));
        let preout = inout.to_preout().to_bytes();
        let out32  = crate::crypto::hash_bytes_sha256(&preout);
        (out32, preout, proof.to_bytes().to_vec())
    }
}

#[cfg(not(feature = "vrf_deterministic"))]
impl VrfVerifier for SchnorrkelVrf {
    fn vrf_verify(
        pk: &VrfPubkey,
        msg: &[u8],
        out: &VrfOutput,
        preout: &VrfPreOut,
        proof: &VrfProof,
    ) -> bool {
        use schnorrkel::{keys::PublicKey, signing_context};
        use schnorrkel::vrf::{VRFPreOut, VRFProof};

        let Ok(pk) = PublicKey::from_bytes(&pk.0) else { return false; };

        // parse preout
        let Ok(preout_obj) = VRFPreOut::from_bytes(preout) else { return false; };

        // parse proof (short, 64 bytes)
        if proof.len() != schnorrkel::vrf::VRF_PROOF_LENGTH { return false; }
        let mut pbytes = [0u8; schnorrkel::vrf::VRF_PROOF_LENGTH];
        pbytes.copy_from_slice(&proof[..]);
        let Ok(proof_obj) = VRFProof::from_bytes(&pbytes) else { return false; };

        // pair output with transcript and verify DLEQ
        let Ok(inout) = pk.vrf_attach_hash(preout_obj, signing_context(b"l1-vortex/vrf").bytes(msg)) else { return false; };
        if pk.dleq_verify(signing_context(b"l1-vortex/vrf").bytes(msg), &inout, &proof_obj, /*kusama=*/false).is_err() {
            return false;
        }

        // check our 32-byte digest matches what the protocol stores
        let expect = crate::crypto::hash_bytes_sha256(preout);
        &expect == out
    }
}

#[cfg(feature = "vrf_deterministic")]
impl VrfSigner for SchnorrkelVrfSigner {
    fn vrf_prove(&self, msg: &[u8]) -> (VrfOutput, VrfPreOut, VrfProof) {
        // preout = H( pk || H(msg) ), out = H(preout), proof = preout||0x01
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&self.kp.public.to_bytes());
        let mh = crate::crypto::hash_bytes_sha256(msg);
        buf[32..].copy_from_slice(&mh);
        let preout = crate::crypto::hash_bytes_sha256(&buf);
        let out32  = crate::crypto::hash_bytes_sha256(&preout);
        let mut proof = Vec::with_capacity(33);
        proof.extend_from_slice(&preout);
        proof.push(0x01);
        (out32, preout, proof)
    }
}

#[cfg(feature = "vrf_deterministic")]
impl VrfVerifier for SchnorrkelVrf {
    fn vrf_verify(
        pk: &VrfPubkey,
        msg: &[u8],
        out: &VrfOutput,
        preout: &VrfPreOut,
        proof: &VrfProof,
    ) -> bool {
        // recompute deterministic preout
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&pk.0);
        let mh = crate::crypto::hash_bytes_sha256(msg);
        buf[32..].copy_from_slice(&mh);
        let expect_pre = crate::crypto::hash_bytes_sha256(&buf);
        let expect_out = crate::crypto::hash_bytes_sha256(&expect_pre);
        preout == &expect_pre && out == &expect_out && proof.starts_with(&expect_pre)
    }
}

// Canonical message used by Node/Chain
pub fn build_vrf_msg(epoch_seed: &[u8; 32], bundle_start_slot: u64, proposer_id: u64) -> Vec<u8> {
    let mut m = Vec::with_capacity(32 + 8 + 8);
    m.extend_from_slice(epoch_seed);
    m.extend_from_slice(&bundle_start_slot.to_be_bytes());
    m.extend_from_slice(&proposer_id.to_be_bytes());
    m
}