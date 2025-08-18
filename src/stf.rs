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
use crate::types::AvailTx;
use crate::types::CommitmentMeta;
use crate::types::{Block, Receipt, ExecOutcome, Hash, BlockHeader, Transaction, StateKey, Tx, Event, RevealTx, CommitTx, AccessList, Address};
use std::collections::HashSet;
use std::fmt;

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
    RootMismatch(String)
}

impl fmt::Display for BlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockError::IntrinsicInvalid(e) => write!(f, "Intrinsic invalid: {}", e),
            BlockError::HeaderMismatch(e)   => write!(f, "Header mismatch: {}", e),
            BlockError::RootMismatch(e)     => write!(f, "Root mismatch: {}", e),
            BlockError::BadHeight { expected, got } =>
                write!(f, "Bad height: expected {}, got {}", expected, got),
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
    balances: &mut Balances,
    nonces: &mut Nonces,
    commitments: &mut Commitments,
    available: &mut Available,
    parent_hash: &Hash,
    fee_state: &FeeState,
    proposer: &Address,
    burned_total: &mut u64,
) -> Result<BlockResult, BlockError> {
    let mut receipts: Vec<Receipt> = Vec::new();
    let mut gas_total: u64 = 0;
    let mut reveals_included: u32 = 0;

    let mut txs_hashes: Vec<Hash> = Vec::new();
    let mut receipt_hashes: Vec<Hash> = Vec::new();
    let mut events: Vec<Event> = Vec::new();
    let mut revealed_pairs: Vec<(Hash, Hash)> = Vec::new();

    // Track reveals included in THIS block, and build IL for "due AND available"
    let mut revealed_this_block: HashSet<Hash> = HashSet::new();
    let mut il_due: Vec<Hash> = Vec::new();

    let avail_count = block.transactions.iter().filter(|t| matches!(t, Tx::Avail(_))).count();
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
        if block.block_number == deadline && available.contains(cmt) {
            il_due.push(*cmt);
        }
    }
    il_due.sort(); // deterministic IL root

    // 1) Process "transactions" (commit/avail only)
    for (i, tx) in block.transactions.iter().enumerate() {
        let rcpt_res = match tx {
            Tx::Commit(c) => process_commit(c, balances, commitments, block.block_number, &mut events, fee_state, proposer, burned_total),
            Tx::Avail(a)  => process_avail(a, commitments, available, block.block_number, &mut events, balances, fee_state, proposer, burned_total),
        };

        match rcpt_res {
            Ok(receipt) => {
                gas_total += receipt.gas_used;
                txs_hashes.push(hash_bytes_sha256(&tx_enum_bytes(tx)));
                receipt_hashes.push(hash_bytes_sha256(&receipt_bytes(&receipt)));
                receipts.push(receipt);
            }
            Err(TxError::IntrinsicInvalid(e)) => {
                return Err(BlockError::IntrinsicInvalid(format!(
                    "block={} tx_index={} error={}", block.block_number, i + 1, e
                )));
            }
        }
    }

    // 2) Process block-level reveals (sorted for deterministic nonce progression)
    let mut reveals_sorted = block.reveals.clone();
    reveals_sorted.sort_by(|a, b| a.sender.cmp(&b.sender).then(a.tx.nonce.cmp(&b.tx.nonce)));

    for r in &reveals_sorted {
        let rcpt = process_reveal(r, balances, nonces, block.block_number, commitments, &mut events, fee_state, proposer, burned_total)?;
        reveals_included = reveals_included + 1;
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

    // 5) Header & hash
    let header = BlockHeader {
        parent_hash: *parent_hash,
        height: block.block_number,
        proposer: proposer.clone(),
        txs_root,
        receipts_root,
        gas_used: gas_total,
        randomness: *parent_hash,
        reveal_set_root,
        il_root,
        exec_base_fee: fee_state.exec_base,
        commit_base_fee: fee_state.commit_base,
        avail_base_fee: fee_state.avail_base
    };
    let block_hash = hash_bytes_sha256(&header_bytes(&header));

    Ok(BlockResult { receipts, gas_total, txs_root, receipts_root, header, block_hash, events, exec_reveals_used: reveals_included })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{codec::access_list_bytes, types::Transaction};
    use std::collections::HashMap;

    const ALICE: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const BOB: &str = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn transfer_via_commit_reveal_success() {
        use std::collections::HashMap;
        use ed25519_dalek::{SigningKey, VerifyingKey, Signer as _};
        use crate::chain::Chain;
        use crate::codec::{tx_bytes, string_bytes, access_list_bytes};
        use crate::crypto::{commitment_hash, commit_signing_preimage, avail_signing_preimage, addr_from_pubkey, addr_hex};
        use crate::state::{Balances, Nonces, Commitments, Available, DECRYPTION_DELAY, REVEAL_WINDOW};
        use crate::types::{CommitTx, RevealTx, AvailTx, Block, ExecOutcome, Hash, AccessList, StateKey, Transaction};
    
        // helper: fill chain with empty blocks up to (but not including) `target`
        fn advance_to(
            chain: &mut Chain,
            balances: &mut Balances,
            nonces: &mut Nonces,
            comms: &mut Commitments,
            avail: &mut Available,
            target: u64,
        ) {
            while chain.height + 1 < target {
                let b = Block::new(Vec::new(), chain.height + 1);
                chain.apply_block(&b, balances, nonces, comms, avail).expect("advance");
            }
        }

        let fee_state = FeeState::from_defaults();

        let commit_fee = fee_state.commit_base;
        let base = fee_state.exec_base;
        let avail_fee = fee_state.avail_base;
    
        // Deterministic keypair for signing
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = VerifyingKey::from(&sk);
        let pk_bytes = vk.to_bytes();

        let sender = addr_hex(&addr_from_pubkey(&pk_bytes));
        let bob = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string();

        // Initial state
        let mut balances: Balances = HashMap::from([
            (sender.clone(), 100),
            (bob.clone(), 50),
        ]);
        let mut nonces: Nonces = Default::default();
        let mut commitments: Commitments = Default::default();
        let mut available:   Available   = Default::default();
        let mut chain = Chain::new();

        // Access list for commit matches the transfer's requirements
        let al = AccessList::for_transfer(&sender, &bob);
        let sender_bytes = string_bytes(&sender);
        let al_bytes     = access_list_bytes(&al);

        // Inner plaintext transfer (to be revealed later)
        let tx = Transaction::transfer(&sender, &bob, 30, 0);

        // Salt and commitment
        let salt: Hash = [7u8; 32];
        let tx_ser = tx_bytes(&tx);
        let tx_al_bytes = access_list_bytes(&tx.access_list);
        let cmt = commitment_hash(&tx_ser, &tx_al_bytes, &salt, CHAIN_ID);
    
        // ---- Block 1: Commit (SIGNED) ----
        let ciphertext_hash = [0u8; 32];
        let pre_commit = commit_signing_preimage(&cmt, &ciphertext_hash, &sender_bytes, &al_bytes, CHAIN_ID);
        let sig_commit = sk.sign(&pre_commit).to_bytes();
    
        let b1 = Block::new(
            vec![Tx::Commit(CommitTx {
                commitment: cmt,
                sender: sender.clone(),
                ciphertext_hash,
                access_list: al,
                pubkey: pk_bytes,
                sig: sig_commit,
            })],
            1,
        );
        chain
            .apply_block(&b1, &mut balances, &mut nonces, &mut commitments, &mut available)
            .expect("block 1 (commit) should apply");
    
        // After commit: only commit fee is burned, nonce unchanged
        assert_eq!(balances[&sender], 100 - commit_fee);
        assert_eq!(balances[&bob], 50);
        assert_eq!(*nonces.get(&sender).unwrap_or(&0), 0);
    
        // Compute ready/due heights
        let ready_at = 1 + DECRYPTION_DELAY;
        let deadline = ready_at + REVEAL_WINDOW;
    
        // Advance sequentially up to ready_at
        advance_to(&mut chain, &mut balances, &mut nonces, &mut commitments, &mut available, ready_at);
    
        // ---- Block ready_at: Avail (SIGNED, in transactions) + Reveal (in block body) ----
        let pre_avail = avail_signing_preimage(&cmt, &sender_bytes, CHAIN_ID);
        let sig_avail = sk.sign(&pre_avail).to_bytes();
    
        // Reveal must provide the same access list so the commitment can be recomputed
        let reveals = vec![
            RevealTx { tx: tx.clone(), salt, sender: sender.clone() }
        ];
        let b_ready = Block::new_with_reveals(
            vec![ Tx::Avail(AvailTx {
                commitment: cmt,
                sender: sender.clone(),
                pubkey: pk_bytes,
                sig: sig_avail,
            }) ],
            reveals,
            ready_at,
        );
    
        let res2 = chain
            .apply_block(&b_ready, &mut balances, &mut nonces, &mut commitments, &mut available)
            .expect("block ready_at (avail + reveal) should apply");
    
        // Receipt checks (Avail + Reveal => 2 receipts)
        assert_eq!(res2.receipts.len(), 2);
        let rcpt_reveal = res2.receipts.last().unwrap();
        assert_eq!(rcpt_reveal.outcome, ExecOutcome::Success);
        assert_eq!(rcpt_reveal.gas_used, base);
    
        // Final balances:
        // Alice: 100 - COMMIT_FEE - BASE_FEE - 30 - AVAIL_FEE
        // Bob:   50 + 30
        assert_eq!(balances[&sender], 100 - commit_fee - base - 30 - avail_fee);
        assert_eq!(balances[&bob], 80);
    
        // Nonce consumed on reveal (not on commit)
        assert_eq!(*nonces.get(&sender).unwrap(), 1);
    
        // Optionally advance to deadline and apply an empty block (no dues remain)
        if deadline > ready_at {
            advance_to(&mut chain, &mut balances, &mut nonces, &mut commitments, &mut available, deadline);
            let b_deadline = Block::new(Vec::new(), deadline);
            chain
                .apply_block(&b_deadline, &mut balances, &mut nonces, &mut commitments, &mut available)
                .expect("deadline block should apply (no due reveals left)");
        }
    }

    #[test]
    fn transfer_gas_paid_no_balance_revert() {
        let mut balances = HashMap::from([
            (ALICE.to_string(), 20),
            (BOB.to_string(), 50),
        ]);
        let mut nonces = Default::default();

        let fee_state = FeeState::from_defaults();

        let tx = Transaction::transfer(ALICE, BOB, 30,0);
        let proposer = crate::state::ZERO_ADDRESS.to_string();
        let mut burned_total = 0;
        let rcpt = process_transaction(&tx, &mut balances, &mut nonces, &fee_state, &proposer, &mut burned_total).expect("valid but reverts");
        assert_eq!(rcpt.outcome, ExecOutcome::Revert);
        assert!(rcpt.error.is_some());
        assert_eq!(balances[ALICE], 19);
        assert_eq!(balances[BOB], 50);
        assert_eq!(*nonces.get(ALICE).unwrap(), 1);
    }

    #[test]
    fn intrinsic_invalid_when_cannot_pay_fee() {
        let mut balances = HashMap::from([
            (ALICE.to_string(), 0),
            (BOB.to_string(), 50),
        ]);
        let mut nonces: HashMap<String, u64> = Default::default();

        let tx = Transaction::transfer(ALICE, BOB, 1, 0);
    
        let fee_state = FeeState::from_defaults();
        let proposer = crate::state::ZERO_ADDRESS.to_string();
        let mut burned_total = 0;

        match process_transaction(&tx, &mut balances, &mut nonces, &fee_state, &proposer, &mut burned_total) {
            Err(TxError::IntrinsicInvalid(msg)) => {
                assert!(msg.contains("insufficient funds"));
            }
            _ => panic!("Expected intrinsic invalid error"),
        }
    
        // Balances unchanged
        assert_eq!(balances[ALICE], 0);
        assert_eq!(balances[BOB], 50);
    
        // Nonces unchanged
        assert_eq!(nonces.get(ALICE), None);
    }

    #[test]
    fn underdeclared_accesslist_fails() {
        use crate::types::AccessList;

        let mut balances = HashMap::from([
            (ALICE.to_string(), 100),
            (BOB.to_string(), 50),
        ]);
        let mut nonces: HashMap<String, u64> = Default::default();
        let al = AccessList {
            reads: vec![ StateKey::Balance(ALICE.into()), StateKey::Nonce(ALICE.into()) ],
            writes: vec![ StateKey::Balance(ALICE.into()), StateKey::Nonce(ALICE.into()) ],
        };

        let tx = Transaction::new(ALICE, BOB, 1, 0, al);

        let fee_state = FeeState::from_defaults();
        let proposer = crate::state::ZERO_ADDRESS.to_string();
        let mut burned_total = 0;

        match process_transaction(&tx, &mut balances, &mut nonces, &fee_state, &proposer, &mut burned_total) {
            Err(TxError::IntrinsicInvalid(msg)) => {
                assert!(msg.contains("recipient balance write"));
            }
            _ => panic!("Expected intrinsic invalid error"),
        }

           // Balances unchanged
           assert_eq!(balances[ALICE], 100);
           assert_eq!(balances[BOB], 50);
       
           // Nonces unchanged
           assert_eq!(nonces.get(ALICE), None);
    }

    #[test]
    fn overdeclared_accesslist_succeeds() {
        use crate::types::AccessList;

        let mut balances = HashMap::from([
            (ALICE.to_string(), 100),
            (BOB.to_string(), 50),
        ]);
        let mut nonces: HashMap<String, u64> = Default::default();
        let al = AccessList {
            reads: vec![ StateKey::Balance(ALICE.into()), StateKey::Balance(BOB.into()), StateKey::Nonce(ALICE.into()), StateKey::Nonce(BOB.into()) ],
            writes: vec![ StateKey::Balance(ALICE.into()), StateKey::Balance(BOB.into()), StateKey::Nonce(ALICE.into()), StateKey::Nonce(BOB.into()) ],
        };

        let tx = Transaction::new(ALICE, BOB, 1, 0, al);

        let fee_state = FeeState::from_defaults();
        let proposer = crate::state::ZERO_ADDRESS.to_string();
        let mut burned_total = 0;

        match process_transaction(&tx, &mut balances, &mut nonces, &fee_state, &proposer, &mut burned_total) {
            Err(_) => {
                panic!("Unexpected Error")
            },
            Ok(receipt) => {
                assert_eq!(receipt.outcome, ExecOutcome::Success)
            }
        }

           // Balances unchanged
           assert_eq!(balances[ALICE], 98);
           assert_eq!(balances[BOB], 51);
       
           // Nonces unchanged
           assert_eq!(nonces.get(ALICE), Some(1).as_ref());
    }
    
    #[test]
    fn avail_outside_window_is_rejected() {
        use std::collections::{HashMap, HashSet};
        use ed25519_dalek::{SigningKey, VerifyingKey, Signer as _};
        use crate::state::{
            Balances, Commitments, Available, DECRYPTION_DELAY, REVEAL_WINDOW, CHAIN_ID
        };
        use crate::types::{Transaction, Hash, AvailTx};
        use crate::codec::{tx_bytes, string_bytes};
        use crate::crypto::{commitment_hash, avail_signing_preimage, addr_from_pubkey, addr_hex};

        // Deterministic keypair and sender address
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = VerifyingKey::from(&sk);
        let pk_bytes = vk.to_bytes();
        let sender = addr_hex(&addr_from_pubkey(&pk_bytes));

        // Minimal state
        let mut balances: Balances = HashMap::from([(sender.clone(), 10_000)]);
        let mut commitments: Commitments = Default::default();
        let mut available:   Available   = HashSet::new();
        let mut events: Vec<crate::types::Event> = Vec::new();

        // Create a commitment by simulating a commit included at height=5
        let inner = Transaction::transfer(&sender, BOB, 1, 0);
        let salt: Hash = [2u8; 32];
        let inner_ser = tx_bytes(&inner);
        let inner_al_bytes = access_list_bytes(&inner.access_list);
        let cmt  = commitment_hash(&inner_ser, &inner_al_bytes, &salt, CHAIN_ID);

        let ready_at = 5 + DECRYPTION_DELAY;
        let deadline = ready_at + REVEAL_WINDOW;

        // Insert commitment meta as if process_commit ran at height 5
        commitments.insert(cmt, CommitmentMeta {
            owner: sender.clone(),
            expires_at: deadline,
            included_at: 5,
            consumed: false,
            access_list: inner.access_list.clone(),
        });

        // Signed Avail for sender
        let sender_bytes = string_bytes(&sender);
        let pre = avail_signing_preimage(&cmt, &sender_bytes, CHAIN_ID);
        let sig = sk.sign(&pre).to_bytes();

        let a = AvailTx {
            commitment: cmt,
            sender: sender.clone(),
            pubkey: pk_bytes,
            sig,
        };

        let fee_state = FeeState::from_defaults();
    
        // Early: height = ready_at - 1
        let early_h = ready_at - 1;
        let proposer = crate::state::ZERO_ADDRESS.to_string();
        let mut burned_total = 0;
        let err1 = crate::stf::process_avail(
            &a,
            &mut commitments,
            &mut available,
            early_h,
            &mut events,
            &mut balances,
            &fee_state,
            &proposer,
            &mut burned_total,
        ).expect_err("early avail must be rejected");
        match err1 {
            crate::stf::TxError::IntrinsicInvalid(m) => {
                assert!(m.contains("avail outside valid window"), "got: {m}");
            }
        }
    
        // Late: height = deadline + 1
        let late_h = deadline + 1;
        let err2 = crate::stf::process_avail(
            &a,
            &mut commitments,
            &mut available,
            late_h,
            &mut events,
            &mut balances,
            &fee_state,
            &proposer,
            &mut burned_total,
        ).expect_err("late avail must be rejected");
        match err2 {
            crate::stf::TxError::IntrinsicInvalid(m) => {
                assert!(m.contains("avail outside valid window"), "got: {m}");
            }
        }
    }
}