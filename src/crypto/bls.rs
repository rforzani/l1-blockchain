//! BLS helpers for Vortex HotStuff/Jolteon voting.
//!
//! - Uses blst::min_pk (PK=48B G1, SIG=96B G2).
//! - QC stores only compressed signature bytes + signer bitmap (Serde friendly).
//! - Leader aggregates partial votes in one shot at finalize()
//!   via `AggregateSignature::aggregate_serialized`, which is widely available
//!   across blst versions (no reliance on ::new / ::default / add_signature).
//! - All votes MUST sign the same canonical message bytes produced by `vote_msg()`.
//!
//! Security invariants to keep in mind elsewhere in consensus:
//! - A bitmap MUST be interpreted against a stable validator index ordering.
//! - Always verify the QC with `fast_aggregate_verify()` before using it.
//! - Enable slashing using the bitmap and per-view vote logs.

use blst::min_pk as mpk;
use blst::BLST_ERROR;
use bitvec::vec::BitVec;
use serde_with::serde_as;

/// Domain separation tag for all consensus BLS signatures (<=255 bytes).
/// Change only with a network upgrade.
pub const BLS_DST: &[u8] = b"VORTEX-BLS-QUORUM-v1";

/// Versioned vote message domain (part of the *message* bytes).
pub const VOTE_MSG_VERSION: u8 = 1;

// -----------------------------------------------------------------------------
// Public types used by consensus (Serde-friendly)
// -----------------------------------------------------------------------------

/// Finalized BLS signature bytes (min_pk: G2 compressed = 96 bytes).
#[serde_as]
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlsSignatureBytes(#[serde_as(as = "[_; 96]")] pub [u8; 96]);

/// Compact signer bitmap for QCs (index-aligned with validator registry order).
pub type SignerBitmap = BitVec;

// -----------------------------------------------------------------------------
// Leader-side aggregation (not serialized)
// -----------------------------------------------------------------------------

/// Aggregator that collects partial 96-byte signatures and builds a BLST aggregate at finalize().
#[derive(Clone, Debug, Default)]
pub struct BlsAggregate {
    sigs: Vec<[u8; 96]>,
}

impl BlsAggregate {
    pub fn new() -> Self {
        Self { sigs: Vec::new() }
    }

    /// Push a single 96-byte signature into the collection.
    pub fn push(&mut self, sig_bytes: &[u8; 96]) {
        self.sigs.push(*sig_bytes);
    }

    /// Finalize into a compressed aggregate signature suitable for putting in a QC.
    pub fn finalize(&self) -> Option<BlsSignatureBytes> {
        if self.sigs.is_empty() {
            return None;
        }
        // Build the &[&[u8]] slice required by aggregate_serialized.
        let sig_refs: Vec<&[u8]> = self.sigs.iter().map(|s| &s[..]).collect();

        // Aggregate all serialized signatures at once (groupcheck true).
        let agg_opt = mpk::AggregateSignature::aggregate_serialized(&sig_refs, true).ok();
        let agg = match agg_opt {
            Some(a) => a,
            None => return None,
        };

        // Convert to compressed G2 signature (96 bytes).
        let sig = agg.to_signature();
        Some(BlsSignatureBytes(sig.to_bytes()))
    }

    /// Convenience: clear collected partials after finalize/broadcast.
    pub fn clear(&mut self) {
        self.sigs.clear();
    }

    pub fn len(&self) -> usize {
        self.sigs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sigs.is_empty()
    }
}

// -----------------------------------------------------------------------------
// Canonical vote message encoding
// -----------------------------------------------------------------------------

/// Build the *exact* message bytes that validators sign and verifiers check.
/// This MUST be stable across all nodes / platforms.
///
/// Format:
///   0:    version (u8) = VOTE_MSG_VERSION
///   1..9: view (u64, big-endian)
///   9..9+N: block_id bytes (as given; treat as opaque)
///
/// NOTE: Domain separation is provided to blst via `BLS_DST`. Do not hash here;
/// blst will hash-to-curve internally. Just provide canonical bytes.
pub fn vote_msg(block_id: &[u8], view: u64) -> Vec<u8> {
    let mut msg = Vec::with_capacity(1 + 8 + block_id.len());
    msg.push(VOTE_MSG_VERSION);
    msg.extend_from_slice(&view.to_be_bytes());
    msg.extend_from_slice(block_id);
    msg
}

// -----------------------------------------------------------------------------
// Validator-side signer (used to produce votes)
// -----------------------------------------------------------------------------

/// Validator BLS signer (keeps SecretKey in memory).
/// Use only in validator processes; do NOT serialize/ship the secret key.
pub struct BlsSigner(mpk::SecretKey);

impl BlsSigner {
    /// Create from 32-byte secret key.
    pub fn from_sk_bytes(sk: &[u8; 32]) -> Option<Self> {
        mpk::SecretKey::from_bytes(sk).map(Self).ok()
    }

    /// Derive 48-byte public key bytes (min_pk).
    pub fn public_key_bytes(&self) -> [u8; 48] {
        self.0.sk_to_pk().to_bytes()
    }

    /// Sign a message (canonical vote_msg bytes) and return compressed 96-byte signature.
    pub fn sign(&self, msg: &[u8]) -> BlsSignatureBytes {
        // Sign with DST; aug is empty.
        let sig = self.0.sign(msg, BLS_DST, &[]);
        BlsSignatureBytes(sig.to_bytes())
    }
}

// -----------------------------------------------------------------------------
// Verification helpers
// -----------------------------------------------------------------------------

/// Verify a single signature against one public key on `msg`.
pub fn verify_sig(pk_bytes: &[u8; 48], msg: &[u8], sig: &BlsSignatureBytes) -> bool {
    let pk = match mpk::PublicKey::from_bytes(pk_bytes).ok() {
        Some(pk) => pk,
        None => return false,
    };
    let sig = match mpk::Signature::from_bytes(&sig.0).ok() {
        Some(sig) => sig,
        None => return false,
    };

    // verify(sig_groupcheck, msg, dst, aug, &pk, pk_validate)
    sig.verify(true, msg, BLS_DST, &[], &pk, true) == BLST_ERROR::BLST_SUCCESS
}

/// Verify an aggregated signature where all voters signed the SAME `msg`.
/// (HotStuff/Jolteon votes do sign the same `(block_id || view)` bytes.)
pub fn fast_aggregate_verify(sig: &BlsSignatureBytes, msg: &[u8], signer_pks: &[[u8; 48]]) -> bool {
    let sig = match mpk::Signature::from_bytes(&sig.0).ok() {
        Some(sig) => sig,
        None => return false,
    };

    // Build public keys and refs slice
    let mut pks = Vec::with_capacity(signer_pks.len());
    for pkb in signer_pks {
        match mpk::PublicKey::from_bytes(pkb).ok() {
            Some(pk) => pks.push(pk),
            None => return false,
        }
    }
    let pk_refs: Vec<&mpk::PublicKey> = pks.iter().collect();

    // fast_aggregate_verify(sig_groupcheck, msg, dst, &[&PublicKey], pk_validate)
    sig.fast_aggregate_verify(true, msg, BLS_DST, &pk_refs) == BLST_ERROR::BLST_SUCCESS
}

// -----------------------------------------------------------------------------
// Utilities for consensus plumbing
// -----------------------------------------------------------------------------

/// Collect the `[u8;48]` pubkeys of all signers set in `bitmap`,
/// using `all_pks` as the validator index order. Returns `None` if
/// bitmap length doesn't match `all_pks.len()`.
pub fn collect_signer_pks_from_bitmap(
    all_pks: &[[u8; 48]],
    bitmap: &SignerBitmap,
) -> Option<Vec<[u8; 48]>> {
    if bitmap.len() != all_pks.len() {
        return None;
    }
    let mut out = Vec::with_capacity(bitmap.count_ones());
    for (i, bit) in bitmap.iter().by_vals().enumerate() {
        if bit {
            out.push(all_pks[i]);
        }
    }
    Some(out)
}

/// Quick quorum check (≥2f+1) given total `n` and a signer bitmap.
pub fn has_quorum(n: usize, bitmap: &SignerBitmap) -> bool {
    let ones = bitmap.count_ones();
    // n = 3f + 1 ⇒ quorum = 2f + 1 = floor(2n/3) + 1
    let quorum = (2 * n) / 3 + 1;
    ones >= quorum
}

/// Verification errors for quorum certificates
#[derive(Debug)]
pub enum BlsQcError {
    BitmapLength { bitmap: usize, pks: usize },
    EmptyBitmap,
    QuorumNotMet { have: usize, need: usize },
    PublicKeyDecode { index: usize },
    FastAggregateVerifyFailed,
}

/// Verify a QC (agg sig + bitmap) for `(block_id, view)` against the active set's
/// BLS pubkeys (`all_pks`) in **stable validator index order**.
pub fn verify_qc(
    block_id: &[u8],
    view: u64,
    agg_sig: &BlsSignatureBytes,
    bitmap: &SignerBitmap,
    all_pks: &[[u8; 48]],
) -> Result<(), BlsQcError> {
    // Length must match active set
    if bitmap.len() != all_pks.len() {
        return Err(BlsQcError::BitmapLength { bitmap: bitmap.len(), pks: all_pks.len() });
    }

    // Basic quorum checks
    let signers = bitmap.count_ones();
    if signers == 0 {
        return Err(BlsQcError::EmptyBitmap);
    }
    let n = all_pks.len();
    let need = (2 * n) / 3 + 1;
    if signers < need {
        return Err(BlsQcError::QuorumNotMet { have: signers, need });
    }

    // Collect signer pubkeys (validate bytes early so we can return a precise error).
    let mut signer_pks: Vec<[u8; 48]> = Vec::with_capacity(signers);
    for (i, bit) in bitmap.iter().by_vals().enumerate() {
        if bit {
            if mpk::PublicKey::from_bytes(&all_pks[i]).ok().is_none() {
                return Err(BlsQcError::PublicKeyDecode { index: i });
            }
            signer_pks.push(all_pks[i]);
        }
    }

    // Build canonical vote message and run fast aggregate verify.
    let msg = vote_msg(block_id, view);
    if !fast_aggregate_verify(agg_sig, &msg, &signer_pks) {
        return Err(BlsQcError::FastAggregateVerifyFailed);
    }
    Ok(())
}