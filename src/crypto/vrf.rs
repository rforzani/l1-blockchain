// src/crypto/vrf.rs
#![allow(dead_code)]

pub const VRF_OUTPUT_BYTES: usize = 32;  // opaque hash-sized output
pub const VRF_PROOF_MAX: usize   = 96;   // fits common schemes (ECVRF ~80-96)

pub type VrfOutput = [u8; VRF_OUTPUT_BYTES];
pub type VrfProof  = [u8; VRF_PROOF_MAX];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VrfPubkey(pub [u8; 32]); // adapt to your chosen scheme later

pub trait VrfSigner {
    fn vrf_prove(&self, msg: &[u8]) -> (VrfOutput, VrfProof);
}

pub trait VrfVerifier {
    fn vrf_verify(pk: &VrfPubkey, msg: &[u8], out: &VrfOutput, proof: &VrfProof) -> bool;
}