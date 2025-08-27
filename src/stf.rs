// src/stf.rs

use crate::codec::access_list_bytes;
use crate::crypto::commitment_hash;
use crate::crypto::merkle_root;
use crate::crypto::hash_bytes_sha256;
use crate::fees::{FeeState, split_amount};
use crate::state::Available;
use crate::state::Commitments;
use crate::state::{CHAIN_ID, DECRYPTION_DELAY, MAX_AVAILS_PER_BLOCK, MAX_PENDING_COMMITS_PER_ACCOUNT, MAX_REVEALS_PER_BLOCK, REVEAL_WINDOW, TREASURY_ADDRESS};
use crate::state::{Balances, Nonces};
use crate::crypto::{addr_from_pubkey, addr_hex};
use crate::codec::{tx_enum_bytes, receipt_bytes, header_bytes, tx_bytes};
use crate::mempool::BatchStore;
use crate::types::AvailTx;
use crate::types::CommitmentMeta;
use crate::types::{Block, Receipt, ExecOutcome, Hash, BlockHeader, Transaction, StateKey, Tx, Event, RevealTx, CommitTx, AccessList, Address};
use hex;
use std::collections::HashSet;
use std::fmt;
#[cfg(test)]
use std::cell::Cell;
#[cfg(test)]
use std::thread_local;

#[cfg(test)]
thread_local! {
    pub static PROCESS_BLOCK_CALLS: Cell<usize> = Cell::new(0);
}

#[derive(Debug)]
pub enum TxError {
    IntrinsicInvalid(String),
}

impl From<TxError> for BlockError {
    fn from(e: TxError) -> Self {
        match e {
            TxError::IntrinsicInvalid(msg) => BlockError::IntrinsicInvalid(msg),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum BlockError {
    IntrinsicInvalid(String),
    HeaderMismatch(String),
    BadHeight { expected: u64, got: u64 },
    RootMismatch(String),
    WrongParent,
    WrongSlot,
    WrongEpoch,
    NotScheduledLeader,
    ProposerKeyMismatch,
    BadSignature,
    MissingBatch(Hash),
}

impl fmt::Display for BlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockError::IntrinsicInvalid(e)            => write!(f, "Intrinsic invalid: {}", e),
            BlockError::HeaderMismatch(e)              => write!(f, "Header mismatch: {}", e),
            BlockError::RootMismatch(e)                => write!(f, "Root mismatch: {}", e),
            BlockError::BadHeight { expected, got } => write!(f, "Bad height: expected {}, got {}", expected, got),
            BlockError::WrongParent                             => write!(f, "Wrong parent"),
            BlockError::WrongSlot                               => write!(f, "Wrong slot"),
            BlockError::WrongEpoch                              => write!(f, "Wrong epoch"),
            BlockError::NotScheduledLeader                      => write!(f, "Not Scheduled Leader"),
            BlockError::ProposerKeyMismatch                     => write!(f, "Proposer Key Mismatch"),
            BlockError::BadSignature                            => write!(f, "Bad Signature"),
            BlockError::MissingBatch(h)                         => write!(f, "Missing batch: {}", hex::encode(h)),
        }
    }
}

impl std::error::Error for BlockError {}

#[derive(Debug)]
pub struct BlockResult { 
    pub receipts: Vec<Receipt>, 
    pub gas_total: u64,
    pub txs_root: Hash,
    pub receipts_root: Hash,
    pub header: BlockHeader,
    pub block_hash: Hash,
    pub events: Vec<Event>,
    pub exec_reveals_used: u32,
    pub commits_used: u32,
}

pub struct BodyResult {
    pub receipts: Vec<Receipt>,
    pub gas_total: u64,
    pub txs_root: Hash,
    pub receipts_root: Hash,
    pub reveal_set_root: Hash,
    pub il_root: Hash,
    pub events: Vec<Event>,
    pub exec_reveals_used: u32,
    pub commits_used: u32,
}

pub fn process_transaction(
    tx: &Transaction,
    balances: &mut Balances,
    nonces:   &mut Nonces,
    fee_state: &FeeState,
    proposer: &Address,
    burned_total: &mut u64,
) -> Result<Receipt, TxError>
{
    use crate::types::{ExecOutcome, Receipt, StateKey};
    use crate::crypto::is_hex_addr;
    use crate::state::{MAX_AL_READS, MAX_AL_WRITES};

    // 0) Address format checks
    if !is_hex_addr(&tx.from) || !is_hex_addr(&tx.to) {
        return Err(TxError::IntrinsicInvalid("sender/recipient not a valid address".into()));
    }

    // 1) Nonce must match exactly
    let expected_nonce = *nonces.get(&tx.from).unwrap_or(&0);
    if tx.nonce != expected_nonce {
        return Err(TxError::IntrinsicInvalid(format!(
            "bad nonce: expected {}, got {}", expected_nonce, tx.nonce
        )));
    }

    // 2) Access list (assumed canonical already)
    let al = &tx.access_list;

    // Cheap caps (DoS guard)
    if al.reads.len()  > MAX_AL_READS || al.writes.len() > MAX_AL_WRITES {
        return Err(TxError::IntrinsicInvalid("access list too large".into()));
    }

    // Keys must be addresses (defense-in-depth)
    for k in al.reads.iter().chain(al.writes.iter()) {
        match k {
            StateKey::Balance(a) | StateKey::Nonce(a) => {
                if !is_hex_addr(a) {
                    return Err(TxError::IntrinsicInvalid("access list contains non-address key".into()));
                }
            }
        }
    }

    println!("{:?}", al);
    println!("{}", &tx.from);

    // Must include: Balance(from) R+W and Nonce(from) R+W
    if !al.require_sender_balance_rw(&tx.from) {
        return Err(TxError::IntrinsicInvalid("access list missing sender balance read/write".into()));
    }
    if !al.require_sender_nonce_rw(&tx.from) {
        return Err(TxError::IntrinsicInvalid("access list missing sender nonce read/write".into()));
    }

    // Must include: Balance(to) WRITE
    let mut has_bal_to_write = false;
    for k in &al.writes {
        if matches!(k, StateKey::Balance(a) if a == &tx.to) { has_bal_to_write = true; break; }
    }
    if !has_bal_to_write {
        return Err(TxError::IntrinsicInvalid("access list missing recipient balance write".into()));
    }

    // 3) Charge gas up front (fail early)

    let base = fee_state.exec_base;

    {
        let sb = balances.entry(tx.from.clone()).or_insert(0);
        if *sb < base {
            return Err(TxError::IntrinsicInvalid("insufficient funds to pay gas fee".into()));
        }
        *sb -= base;
    } // sender borrow ends

    let (burn, prop, tres) = split_amount(base);
    *burned_total += burn;
    if prop > 0 {
        let pb = balances.entry(proposer.clone()).or_insert(0);
        *pb = pb.saturating_add(prop);
    }
    if tres > 0 {
        let tb = balances.entry(TREASURY_ADDRESS.to_string()).or_insert(0);
        *tb = tb.saturating_add(tres);
    }

    // 4) Execute transfer (no overlapping &mut borrows)
    let mut outcome = ExecOutcome::Success;
    let mut error: Option<String> = None;

    // Debit sender
    let debited = {
        let sb = balances.get_mut(&tx.from).unwrap(); // exists after gas charge
        if *sb >= tx.amount {
            *sb -= tx.amount;
            true
        } else {
            false
        }
    }; // sender borrow ends

    if debited {
        // Credit receiver, guard overflow
        let cur_to = *balances.get(&tx.to).unwrap_or(&0);
        if let Some(new_to) = cur_to.checked_add(tx.amount) {
            balances.insert(tx.to.clone(), new_to);
        } else {
            // overflow → rollback amount (gas stays burned)
            let sb = balances.get_mut(&tx.from).unwrap();
            *sb += tx.amount;
            outcome = ExecOutcome::Revert;
            error = Some("balance overflow on recipient".into());
        }
    } else {
        outcome = ExecOutcome::Revert;
        error = Some("insufficient funds for transfer".into());
    }

    // 5) Bump nonce with overflow guard
    if expected_nonce == u64::MAX {
        return Err(TxError::IntrinsicInvalid("nonce overflow".into()));
    }
    nonces.insert(tx.from.clone(), expected_nonce + 1);

    // 6) Receipt
    Ok(Receipt { outcome, gas_used: base, error })
}

fn process_avail(
    a: &AvailTx,
    commitments: &Commitments,
    available: &mut Available,
    current_height: u64,
    events: &mut Vec<Event>,
    balances: &mut Balances,
    fee_state: &FeeState,
    proposer: &Address,
    burned_total: &mut u64,
) -> Result<Receipt, TxError> {
    use crate::codec::string_bytes;
    use crate::crypto::{avail_signing_preimage, verify_ed25519};
    
    // sanity: commitment exists & not consumed
    let meta = commitments.get(&a.commitment)
        .ok_or_else(|| TxError::IntrinsicInvalid("no such commitment".into()))?;
    if meta.consumed {
        return Err(TxError::IntrinsicInvalid("already consumed".into()));
    }

    // --- owner binding: a.sender must match the commitment owner you stored at commit time ---
    let Some(meta) = commitments.get(&a.commitment) else {
        return Err(TxError::IntrinsicInvalid("unknown commitment".into()));
    };
    if a.sender != meta.owner {
        return Err(TxError::IntrinsicInvalid("avail sender mismatch with commitment owner".into()));
    }

    // --- signature check (avail) ---
    let sender_bytes = string_bytes(&a.sender);
    let preimage     = avail_signing_preimage(&a.commitment, &sender_bytes, CHAIN_ID);

    if !verify_ed25519(&a.pubkey, &a.sig, &preimage) {
        return Err(TxError::IntrinsicInvalid("bad avail signature".into()));
    }

    let derived = addr_hex(&addr_from_pubkey(&a.pubkey));
    if a.sender != derived {
        return Err(TxError::IntrinsicInvalid("sender/pubkey mismatch".into()));
    }


    // owner-only Avail (v1)   ------ TO BE CHANGED LATER: It now avoids griefing where a third party could force you to pay an Avail fee. Later, when we move to TE, “Avail” becomes a committee root and this logic naturally disappears.
    let owner = meta.owner.clone();
    
    // timing window [ready_at .. deadline]
    let ready_at = meta.included_at + DECRYPTION_DELAY;
    let deadline = ready_at + REVEAL_WINDOW;
    if current_height < ready_at || current_height > deadline {
        return Err(TxError::IntrinsicInvalid("avail outside valid window".into()));
    }

    // fee paid by owner (v1)  --- TO BE CHANGED LATER
    let avail_fee = fee_state.avail_base;
    let bal = balances.entry(owner).or_insert(0);
    if *bal < avail_fee {
        return Err(TxError::IntrinsicInvalid("insufficient funds for avail fee".into()));
    }
    *bal -= avail_fee;

    let (burn, prop, tres) = split_amount(avail_fee);
    *burned_total += burn;
    if prop > 0 {
        let pb = balances.entry(proposer.clone()).or_insert(0);
        *pb = pb.saturating_add(prop);
    }
    if tres > 0 {
        let tb = balances.entry(TREASURY_ADDRESS.to_string()).or_insert(0);
        *tb = tb.saturating_add(tres);
    }

    available.insert(a.commitment);

    // idempotent insert
    let first_time = available.insert(a.commitment);
    if first_time {
        events.push(Event::AvailabilityRecorded { commitment: a.commitment });
    }

    Ok(Receipt { outcome: ExecOutcome::Success, gas_used: 0, error: None })
}

fn pending_for_owner(commitments: &Commitments, owner: &str) -> usize {
    commitments.values()
        .filter(|m| !m.consumed && m.owner == owner)
        .count()
}

pub fn process_commit(
    c: &CommitTx,
    balances: &mut Balances,
    commitments: &mut Commitments,
    current_height: u64,
    events: &mut Vec<Event>,
    fee_state: &FeeState,
    proposer: &Address,
    burned_total: &mut u64,
) -> Result<Receipt, TxError> {
    use crate::codec::{string_bytes, access_list_bytes};
    use crate::crypto::{commit_signing_preimage, verify_ed25519, addr_from_pubkey, addr_hex, is_hex_addr};
    use crate::types::{AccessList, StateKey};
    use crate::state::{MAX_AL_READS, MAX_AL_WRITES};

    // --- 1) Signature + identity ---
    let sender_bytes = string_bytes(&c.sender);
    let al_bytes_for_sig = access_list_bytes(&c.access_list); // canonical bytes for signing
    let preimage = commit_signing_preimage(
        &c.commitment,
        &c.ciphertext_hash,
        &sender_bytes,
        &al_bytes_for_sig,
        CHAIN_ID,
    );
    if !verify_ed25519(&c.pubkey, &c.sig, &preimage) {
        return Err(TxError::IntrinsicInvalid("bad commit signature".into()));
    }

    let derived = addr_hex(&addr_from_pubkey(&c.pubkey));
    if c.sender != derived {
        return Err(TxError::IntrinsicInvalid("sender/pubkey mismatch".into()));
    }
    if !is_hex_addr(&c.sender) {
        return Err(TxError::IntrinsicInvalid("sender not a valid address".into()));
    }

    // --- 2) AccessList sanity (complete but safe) ---
    // 2a) size caps
    if c.access_list.reads.len()  > MAX_AL_READS
        || c.access_list.writes.len() > MAX_AL_WRITES
    {
        return Err(TxError::IntrinsicInvalid("access list too large".into()));
    }

    // 2b) all keys must be addresses (reject human names)
    for k in c.access_list.reads.iter().chain(c.access_list.writes.iter()) {
        match k {
            StateKey::Balance(a) | StateKey::Nonce(a) => {
                if !is_hex_addr(a) {
                    return Err(TxError::IntrinsicInvalid("access list contains non-address key".into()));
                }
            }
        }
    }

    // 2c) canonicalize (sort + dedup) for deterministic membership checks
    let mut al = c.access_list.clone();
    al.canonicalize();

    // 2d) must include sender Balance R+W (commit fee burn)
    if !al.require_sender_balance_rw(&c.sender) {
        return Err(TxError::IntrinsicInvalid("access list must include Balance(sender) read+write".into()));
    }

    // 2e) (recommended) include sender Nonce R+W (reveal path will need it)
    if !al.require_sender_nonce_rw(&c.sender) {
        return Err(TxError::IntrinsicInvalid("access list must include Nonce(sender) read+write".into()));
    }

    // --- 3) Economics / anti-abuse ---
    let sender = c.sender.clone();
    let bal = balances.entry(sender.clone()).or_insert(0);
    
    let commit_fee = fee_state.commit_base;

    if *bal < commit_fee {
        return Err(TxError::IntrinsicInvalid("insufficient funds to pay commit fee".into()));
    }
    if pending_for_owner(commitments, &c.sender) >= MAX_PENDING_COMMITS_PER_ACCOUNT {
        return Err(TxError::IntrinsicInvalid("too many pending commits for owner".into()));
    }
    if let Some(meta) = commitments.get(&c.commitment) {
        if !meta.consumed {
            return Err(TxError::IntrinsicInvalid("duplicate commitment".into()));
        }
    }
    *bal = bal.saturating_sub(commit_fee);

    let (burn, prop, tres) = split_amount(commit_fee);
    *burned_total += burn;
    if prop > 0 {
        let pb = balances.entry(proposer.clone()).or_insert(0);
        *pb = pb.saturating_add(prop);
    }
    if tres > 0 {
        let tb = balances.entry(TREASURY_ADDRESS.to_string()).or_insert(0);
        *tb = tb.saturating_add(tres);
    }

    // --- 4) Time bounds & record ---
    let ready_at = current_height + DECRYPTION_DELAY;
    let deadline = ready_at + REVEAL_WINDOW;

    commitments.insert(
        c.commitment,
        CommitmentMeta {
            owner: sender.clone(),
            expires_at: deadline,
            consumed: false,
            included_at: current_height,
            access_list: al.clone(),
        },
    );

    events.push(Event::CommitStored {
        commitment: c.commitment,
        owner: sender,
        expires_at: deadline,
    });

    Ok(Receipt {
        outcome: ExecOutcome::Success,
        gas_used: commit_fee,
        error: None,
    })
}

fn process_reveal(
    r: &RevealTx,
    balances: &mut Balances,
    nonces: &mut Nonces,
    current_height: u64,
    commitments: &mut Commitments,
    events: &mut Vec<Event>,
    fee_state: &FeeState,
    proposer: &Address,
    burned_total: &mut u64,
) -> Result<Receipt, TxError> {
    // Sender sanity
    if r.sender != r.tx.from {
        return Err(TxError::IntrinsicInvalid("reveal sender != tx.from".to_string()));
    }

    let tx_ser = tx_bytes(&r.tx);
    let reveal_al_bytes = access_list_bytes(&r.tx.access_list);
    let cmt = commitment_hash(&tx_ser, &reveal_al_bytes, &r.salt, CHAIN_ID);

    // Prepare executable transaction with access list from commitment metadata
    let mut exec_tx = Transaction {
        from: r.tx.from.clone(),
        to: r.tx.to.clone(),
        amount: r.tx.amount,
        nonce: r.tx.nonce,
        access_list: AccessList { reads: vec![], writes: vec![] },
    };

    {
        let meta = commitments.get_mut(&cmt)
            .ok_or_else(|| TxError::IntrinsicInvalid("no such commitment".to_string()))?;

        if meta.owner != r.sender {
            return Err(TxError::IntrinsicInvalid("owner mismatch".to_string()));
        }
        if meta.consumed {
            return Err(TxError::IntrinsicInvalid("commit already consumed".to_string()));
        }

        // -----  delay + window -----
        let ready_at = meta.included_at + DECRYPTION_DELAY;
        if current_height < ready_at {
            return Err(TxError::IntrinsicInvalid("reveal too early".to_string()));
        }

        let deadline = ready_at + REVEAL_WINDOW;
        if current_height > deadline {
            return Err(TxError::IntrinsicInvalid("reveal outside window".to_string()));
        }
        // --------------------------------

        // verify commitment using stored access list
        let meta_al_bytes = access_list_bytes(&meta.access_list);
        let expected = commitment_hash(&tx_ser, &meta_al_bytes, &r.salt, CHAIN_ID);
        if expected != cmt {
            return Err(TxError::IntrinsicInvalid("commitment/access list mismatch".to_string()));
        }

        exec_tx.access_list = meta.access_list.clone();
        meta.consumed = true; // mark as used
    }

    events.push(Event::CommitConsumed { commitment: cmt });

    process_transaction(&exec_tx, balances, nonces, fee_state, proposer, burned_total)
}

pub fn process_block(
    block: &Block,
    batch_store: &BatchStore,
    balances: &mut Balances,
    nonces: &mut Nonces,
    commitments: &mut Commitments,
    available: &mut Available,
    fee_state: &FeeState,
    proposer: &Address,
    burned_total: &mut u64,
) -> Result<BodyResult, BlockError> {
    #[cfg(test)]
    PROCESS_BLOCK_CALLS.with(|c| c.set(c.get() + 1));
    let mut receipts: Vec<Receipt> = Vec::new();
    let mut gas_total: u64 = 0;
    let mut reveals_included: u32 = 0;
    let mut commits_included: u32 = 0;

    let mut txs_hashes: Vec<Hash> = Vec::new();
    let mut receipt_hashes: Vec<Hash> = Vec::new();
    let mut events: Vec<Event> = Vec::new();
    let mut revealed_pairs: Vec<(Hash, Hash)> = Vec::new();

    // Track reveals included in THIS block, and build IL for "due AND available"
    let mut revealed_this_block: HashSet<Hash> = HashSet::new();
    let mut il_due: Vec<Hash> = Vec::new();

    // Gather all transactions: those directly in the block plus those fetched via batch digests.
    let mut all_txs: Vec<Tx> = block.transactions.clone();
    for d in &block.batch_digests {
        let batch = batch_store
            .get(d)
            .ok_or(BlockError::MissingBatch(*d))?;
        all_txs.extend(batch.txs);
    }

    let avail_count = all_txs.iter().filter(|t| matches!(t, Tx::Avail(_))).count();
    if avail_count > MAX_AVAILS_PER_BLOCK {
        return Err(BlockError::IntrinsicInvalid("too many Avails in block".into()));
    }

    if block.reveals.len() > MAX_REVEALS_PER_BLOCK {
        return Err(BlockError::IntrinsicInvalid("too many Reveals in block".into()));
    }

    for (cmt, meta) in commitments.iter() {
        if meta.consumed { continue; }
        let ready_at = meta.included_at + DECRYPTION_DELAY;
        let deadline = ready_at + REVEAL_WINDOW;
        if block.header.height == deadline && available.contains(cmt) {
            il_due.push(*cmt);
        }
    }
    il_due.sort(); // deterministic IL root

    // 1) Process "transactions" (commit/avail only)
    for (i, tx) in all_txs.iter().enumerate() {
        let is_commit = matches!(tx, Tx::Commit(_));

        let rcpt_res = match tx {
            Tx::Commit(c) => process_commit(c, balances, commitments, block.header.height, &mut events, fee_state, proposer, burned_total),
            Tx::Avail(a)  => process_avail(a, commitments, available, block.header.height, &mut events, balances, fee_state, proposer, burned_total),
        };

        match rcpt_res {
            Ok(receipt) => {
                if is_commit { 
                    commits_included += 1; 
                }
                gas_total += receipt.gas_used;
                txs_hashes.push(hash_bytes_sha256(&tx_enum_bytes(tx)));
                receipt_hashes.push(hash_bytes_sha256(&receipt_bytes(&receipt)));
                receipts.push(receipt);
            }
            Err(TxError::IntrinsicInvalid(e)) => {
                return Err(BlockError::IntrinsicInvalid(format!(
                    "block={} tx_index={} error={}", block.header.height, i + 1, e
                )));
            }
        }
    }

    // 2) Process block-level reveals (sorted for deterministic nonce progression)
    let mut reveals_sorted = block.reveals.clone();
    reveals_sorted.sort_by(|a, b| a.sender.cmp(&b.sender).then(a.tx.nonce.cmp(&b.tx.nonce)));

    for r in &reveals_sorted {
        let rcpt = process_reveal(r, balances, nonces, block.header.height, commitments, &mut events, fee_state, proposer, burned_total)?;
        reveals_included += 1;
        gas_total += rcpt.gas_used;
        receipt_hashes.push(hash_bytes_sha256(&receipt_bytes(&rcpt)));
        receipts.push(rcpt);

        // pair for reveal_set_root
        let tx_ser = tx_bytes(&r.tx);
        let al_bytes = access_list_bytes(&r.tx.access_list);
        let cmt    = commitment_hash(&tx_ser, &al_bytes, &r.salt, CHAIN_ID);
        let txh    = hash_bytes_sha256(&tx_ser);
        revealed_pairs.push((cmt, txh));
        revealed_this_block.insert(cmt);
    }

    // 3) Roots
    revealed_pairs.sort_by(|(c1,_),(c2,_)| c1.cmp(c2)); // canonical order
    let reveal_leaves: Vec<Hash> = revealed_pairs.into_iter().map(|(cmt, txh)| {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&cmt);
        buf.extend_from_slice(&txh);
        hash_bytes_sha256(&buf)
    }).collect();

    let reveal_set_root = merkle_root(&reveal_leaves);
    let txs_root        = merkle_root(&txs_hashes);
    let receipts_root   = merkle_root(&receipt_hashes);

    // 4) IL enforcement: all due must be revealed in this block
    for c in &il_due {
        if !revealed_this_block.contains(c) {
            return Err(BlockError::IntrinsicInvalid("missing required reveal from inclusion list".into()));
        }
    }
    let il_leaves: Vec<Hash> = il_due.iter().map(|c| hash_bytes_sha256(c)).collect();
    let il_root = merkle_root(&il_leaves);

    Ok(BodyResult { receipts, il_root, reveal_set_root, gas_total, txs_root, receipts_root, events, exec_reveals_used: reveals_included, commits_used: commits_included })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use crate::codec::{access_list_bytes, string_bytes, tx_bytes};
    use crate::crypto::{addr_from_pubkey, addr_hex, commit_signing_preimage, commitment_hash};
    use crate::state::{Balances, Commitments, Nonces};
    use crate::types::{AccessList, Address, CommitTx, RevealTx, StateKey, Transaction};

    fn derive_address(sk: &SigningKey) -> Address {
        let pk = sk.verifying_key().to_bytes();
        addr_hex(&addr_from_pubkey(&pk))
    }

    fn build_commit_and_reveal(
        sk: &SigningKey,
        tx: Transaction,
        salt: Hash,
        sender: &Address,
    ) -> (CommitTx, RevealTx) {
        let tx_ser = tx_bytes(&tx);
        let al_bytes = access_list_bytes(&tx.access_list);
        let cmt = commitment_hash(&tx_ser, &al_bytes, &salt, CHAIN_ID);
        let pre = commit_signing_preimage(&cmt, &[0u8; 32], &string_bytes(sender), &al_bytes, CHAIN_ID);
        let sig = sk.sign(&pre);
        let commit_tx = CommitTx {
            commitment: cmt,
            sender: sender.clone(),
            access_list: tx.access_list.clone(),
            ciphertext_hash: [0u8; 32],
            pubkey: sk.verifying_key().to_bytes(),
            sig: sig.to_bytes(),
        };
        let reveal_tx = RevealTx { tx, salt, sender: sender.clone() };
        (commit_tx, reveal_tx)
    }

    #[test]
    fn transfer_via_commit_reveal_success() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let sender = derive_address(&sk);
        let receiver = "0x00000000000000000000000000000000000000aa".to_string();
        let proposer = "0x00000000000000000000000000000000000000bb".to_string();

        let mut tx = Transaction::transfer(&sender, &receiver, 5, 0);
        tx.access_list.canonicalize();
        let salt = [9u8; 32];
        let (commit_tx, reveal_tx) = build_commit_and_reveal(&sk, tx, salt, &sender);

        let mut balances: Balances = Balances::new();
        balances.insert(sender.clone(), 10);
        let mut nonces: Nonces = Nonces::new();
        let mut commitments: Commitments = Commitments::new();
        let mut events = Vec::new();
        let fee_state = FeeState::from_defaults();
        let mut burned_total = 0u64;

        process_commit(
            &commit_tx,
            &mut balances,
            &mut commitments,
            0,
            &mut events,
            &fee_state,
            &proposer,
            &mut burned_total,
        )
        .unwrap();

        let receipt = process_reveal(
            &reveal_tx,
            &mut balances,
            &mut nonces,
            1,
            &mut commitments,
            &mut events,
            &fee_state,
            &proposer,
            &mut burned_total,
        )
        .unwrap();

        assert_eq!(receipt.outcome, ExecOutcome::Success);
        assert_eq!(balances.get(&sender).copied(), Some(3));
        assert_eq!(balances.get(&receiver).copied(), Some(5));
        assert_eq!(nonces.get(&sender).copied(), Some(1));
    }

    #[test]
    fn transfer_gas_paid_no_balance_revert() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let sender = derive_address(&sk);
        let receiver = "0x00000000000000000000000000000000000000aa".to_string();
        let proposer = "0x00000000000000000000000000000000000000bb".to_string();

        let mut tx = Transaction::transfer(&sender, &receiver, 2, 0);
        tx.access_list.canonicalize();
        let salt = [9u8; 32];
        let (commit_tx, reveal_tx) = build_commit_and_reveal(&sk, tx, salt, &sender);

        let mut balances: Balances = Balances::new();
        balances.insert(sender.clone(), 3);
        let mut nonces: Nonces = Nonces::new();
        let mut commitments: Commitments = Commitments::new();
        let mut events = Vec::new();
        let fee_state = FeeState::from_defaults();
        let mut burned_total = 0u64;

        process_commit(
            &commit_tx,
            &mut balances,
            &mut commitments,
            0,
            &mut events,
            &fee_state,
            &proposer,
            &mut burned_total,
        )
        .unwrap();

        let receipt = process_reveal(
            &reveal_tx,
            &mut balances,
            &mut nonces,
            1,
            &mut commitments,
            &mut events,
            &fee_state,
            &proposer,
            &mut burned_total,
        )
        .unwrap();

        assert_eq!(receipt.outcome, ExecOutcome::Revert);
        assert_eq!(receipt.error.as_deref(), Some("insufficient funds for transfer"));
        assert_eq!(balances.get(&sender).copied(), Some(1));
        assert_eq!(balances.get(&receiver).copied().unwrap_or(0), 0);
        assert_eq!(nonces.get(&sender).copied(), Some(1));
    }

    #[test]
    fn intrinsic_invalid_when_cannot_pay_fee() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let sender = derive_address(&sk);
        let receiver = "0x00000000000000000000000000000000000000aa".to_string();
        let proposer = "0x00000000000000000000000000000000000000bb".to_string();

        let mut tx = Transaction::transfer(&sender, &receiver, 1, 0);
        tx.access_list.canonicalize();
        let salt = [9u8; 32];
        let (commit_tx, reveal_tx) = build_commit_and_reveal(&sk, tx, salt, &sender);

        let mut balances: Balances = Balances::new();
        balances.insert(sender.clone(), 1); // only enough for commit
        let mut nonces: Nonces = Nonces::new();
        let mut commitments: Commitments = Commitments::new();
        let mut events = Vec::new();
        let fee_state = FeeState::from_defaults();
        let mut burned_total = 0u64;

        process_commit(
            &commit_tx,
            &mut balances,
            &mut commitments,
            0,
            &mut events,
            &fee_state,
            &proposer,
            &mut burned_total,
        )
        .unwrap();

        let err = process_reveal(
            &reveal_tx,
            &mut balances,
            &mut nonces,
            1,
            &mut commitments,
            &mut events,
            &fee_state,
            &proposer,
            &mut burned_total,
        )
        .unwrap_err();

        match err {
            TxError::IntrinsicInvalid(e) => assert_eq!(e, "insufficient funds to pay gas fee"),
        }
        assert_eq!(balances.get(&sender).copied(), Some(0));
        assert!(nonces.get(&sender).is_none());
    }

    #[test]
    fn underdeclared_accesslist_fails() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let sender = derive_address(&sk);
        let receiver = "0x00000000000000000000000000000000000000aa".to_string();
        let proposer = "0x00000000000000000000000000000000000000bb".to_string();

        let mut al = AccessList {
            reads: vec![
                StateKey::Balance(sender.clone()),
                StateKey::Nonce(sender.clone()),
            ],
            writes: vec![
                StateKey::Balance(sender.clone()),
                StateKey::Nonce(sender.clone()),
            ],
        };
        al.canonicalize();

        let tx = Transaction::new(sender.clone(), receiver.clone(), 5, 0, al.clone());
        let salt = [9u8; 32];
        let (commit_tx, reveal_tx) = build_commit_and_reveal(&sk, tx, salt, &sender);

        let mut balances: Balances = Balances::new();
        balances.insert(sender.clone(), 10);
        let mut nonces: Nonces = Nonces::new();
        let mut commitments: Commitments = Commitments::new();
        let mut events = Vec::new();
        let fee_state = FeeState::from_defaults();
        let mut burned_total = 0u64;

        process_commit(
            &commit_tx,
            &mut balances,
            &mut commitments,
            0,
            &mut events,
            &fee_state,
            &proposer,
            &mut burned_total,
        )
        .unwrap();

        let err = process_reveal(
            &reveal_tx,
            &mut balances,
            &mut nonces,
            1,
            &mut commitments,
            &mut events,
            &fee_state,
            &proposer,
            &mut burned_total,
        )
        .unwrap_err();

        match err {
            TxError::IntrinsicInvalid(e) => {
                assert_eq!(e, "access list missing recipient balance write")
            }
        }
        assert_eq!(balances.get(&sender).copied(), Some(9));
        assert!(nonces.get(&sender).is_none());
    }

    #[test]
    fn overdeclared_accesslist_succeeds() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let sender = derive_address(&sk);
        let receiver = "0x00000000000000000000000000000000000000aa".to_string();
        let extra = "0x00000000000000000000000000000000000000cc".to_string();
        let proposer = "0x00000000000000000000000000000000000000bb".to_string();

        let mut al = AccessList::for_transfer(&sender, &receiver);
        al.reads.push(StateKey::Balance(extra.clone()));
        al.writes.push(StateKey::Balance(extra.clone()));
        al.canonicalize();

        let tx = Transaction::new(sender.clone(), receiver.clone(), 5, 0, al.clone());
        let salt = [9u8; 32];
        let (commit_tx, reveal_tx) = build_commit_and_reveal(&sk, tx, salt, &sender);

        let mut balances: Balances = Balances::new();
        balances.insert(sender.clone(), 10);
        let mut nonces: Nonces = Nonces::new();
        let mut commitments: Commitments = Commitments::new();
        let mut events = Vec::new();
        let fee_state = FeeState::from_defaults();
        let mut burned_total = 0u64;

        process_commit(
            &commit_tx,
            &mut balances,
            &mut commitments,
            0,
            &mut events,
            &fee_state,
            &proposer,
            &mut burned_total,
        )
        .unwrap();

        let receipt = process_reveal(
            &reveal_tx,
            &mut balances,
            &mut nonces,
            1,
            &mut commitments,
            &mut events,
            &fee_state,
            &proposer,
            &mut burned_total,
        )
        .unwrap();

        assert_eq!(receipt.outcome, ExecOutcome::Success);
        assert_eq!(balances.get(&sender).copied(), Some(3));
        assert_eq!(balances.get(&receiver).copied(), Some(5));
        assert_eq!(nonces.get(&sender).copied(), Some(1));
    }
}