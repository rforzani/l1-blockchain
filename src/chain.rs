//src/chain.rs

use crate::codec::{header_bytes, header_signing_bytes};
use crate::crypto::{addr_from_pubkey, addr_hex, hash_bytes_sha256, verify_ed25519};
use crate::fees::{update_commit_base, update_exec_base, FeeState, FEE_PARAMS};
use crate::stf::{process_block, BlockError};
use crate::state::{Available, Balances, Commitments, Nonces, DECRYPTION_DELAY, REVEAL_WINDOW};
use crate::types::{Block, Event, Hash, Receipt};
use crate::verify::verify_block_roots;
use std::collections::{HashMap, HashSet, BTreeMap};

pub struct Chain {
    pub tip_hash: Hash,
    pub height: u64,
    pub fee_state: FeeState,
    pub burned_total: u64,
    commit_included_at: HashMap<Hash, u64>,
    avail_included: HashSet<Hash>,
    avail_due: BTreeMap<u64, Vec<Hash>>,
    commit_deadline: HashMap<Hash, u64>,
}

pub struct ApplyResult {
    pub receipts: Vec<Receipt>,
    pub gas_total: u64,
    pub events: Vec<Event>,
    pub exec_reveals_used: u32,
    pub commits_used: u32,
}

impl Chain {
    pub fn new() -> Self {
        Self {
            tip_hash: [0u8;32],
            height: 0,
            fee_state: FeeState::from_defaults(),
            burned_total: 0,
            commit_included_at: HashMap::new(),
            avail_included: HashSet::new(),
            avail_due: BTreeMap::new(),
            commit_deadline: HashMap::new(),
        }
    }

    pub fn apply_block(
        &mut self,
        block: &Block,
        balances: &mut Balances,
        nonces: &mut Nonces,
        commitments: &mut Commitments,
        available: &mut Available,
    ) -> Result<ApplyResult, BlockError> {
        // basic height check
        if block.header.height != self.height + 1 {
            return Err(BlockError::BadHeight {
                expected: self.height + 1,
                got: block.header.height,
            });
        }

        // Parent guard: the block we just built must link to our tip
        if block.header.parent_hash != self.tip_hash {
            return Err(BlockError::HeaderMismatch(
                format!(
                    "parent mismatch: expected {}, got {}",
                    hex::encode(self.tip_hash),
                    hex::encode(block.header.parent_hash),
                )
            ));
        }

        // Signature verification
        {
            let preimage = header_signing_bytes(&block.header);
            let ok = verify_ed25519(
                &block.header.proposer_pubkey,
                &block.header.signature,
                &preimage,
            );
            if !ok {
                return Err(BlockError::IntrinsicInvalid("bad block signature".into()));
            }
        }

        let mut sim_balances = balances.clone();
        let mut sim_nonces = nonces.clone();
        let mut sim_commitments = commitments.clone();
        let mut sim_available = available.clone();

        let proposer_addr = addr_hex(&addr_from_pubkey(&block.header.proposer_pubkey));

        // process with current tip as parent
        let mut sim_burned_total = self.burned_total;
        let res = process_block(
            block,
            &mut sim_balances,
            &mut sim_nonces,
            &mut sim_commitments,
            &mut sim_available,
            &self.fee_state,
            &proposer_addr,
            &mut sim_burned_total,
        )?;

        verify_block_roots(&block.header, block, &res.receipts)
            .map_err(BlockError::RootMismatch)?;

        *balances = sim_balances;
        *nonces = sim_nonces;
        *commitments = sim_commitments;
        *available = sim_available;
        self.burned_total = sim_burned_total;

        for ev in &res.events {
            match ev {
                Event::CommitStored { commitment, .. } => {
                    self.commit_included_at.insert(*commitment, block.header.height);
                }
                Event::AvailabilityRecorded { commitment } => {
                    if let Some(&inc) = self.commit_included_at.get(commitment) {
                        let ready_at = inc + DECRYPTION_DELAY;
                        let deadline = ready_at + REVEAL_WINDOW;
                        self.avail_included.insert(*commitment);
                        self.commit_deadline.insert(*commitment, deadline);
                        self.avail_due.entry(deadline).or_default().push(*commitment);
                    }
                }
                Event::CommitConsumed { commitment } | Event::CommitExpired { commitment } => {
                    if let Some(deadline) = self.commit_deadline.remove(commitment) {
                        if let Some(vec) = self.avail_due.get_mut(&deadline) {
                            vec.retain(|c| c != commitment);
                            if vec.is_empty() {
                                self.avail_due.remove(&deadline);
                            }
                        }
                    }
                }
            }
        }

        let next_exec = update_exec_base(
            self.fee_state.exec_base,
            res.exec_reveals_used,
            FEE_PARAMS.exec_target_reveals_per_block,
            FEE_PARAMS.exec_max_change_denominator,
            FEE_PARAMS.exec_min_base,
            FEE_PARAMS.exec_damping_bps,
        );

        // 3) update self state
        self.tip_hash = hash_bytes_sha256(&header_bytes(&block.header));
        self.height = block.header.height;
        self.fee_state.exec_base = next_exec;
        self.fee_state.commit_base = update_commit_base(
            self.fee_state.commit_base,
            res.commits_used,
        );
        Ok(ApplyResult { receipts: res.receipts, gas_total: res.gas_total, events: res.events, exec_reveals_used: res.exec_reveals_used, commits_used: res.commits_used })
    }

    /// Check if a commitment has been included on-chain.
    pub fn commit_on_chain(&self, c: &Hash) -> bool {
        self.commit_included_at.contains_key(c)
    }

    /// Check if an Avail for the commitment has been included.
    pub fn avail_on_chain(&self, c: &Hash) -> bool {
        self.avail_included.contains(c)
    }

    /// Whether an Avail is allowed at `height` for commitment `c`.
    pub fn avail_allowed_at(&self, height: u64, c: &Hash) -> bool {
        if let Some(&included_at) = self.commit_included_at.get(c) {
            let ready_at = included_at + DECRYPTION_DELAY;
            let deadline = ready_at + REVEAL_WINDOW;
            height >= ready_at && height <= deadline
        } else {
            false
        }
    }

    /// Commitments that are due (deadline == `height`) and already available.
    pub fn commitments_due_and_available(&self, height: u64) -> Vec<Hash> {
        self.avail_due.get(&height).cloned().unwrap_or_default()
    }
}

#[cfg(test)]

mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, Signer};
    use crate::codec::{
        header_bytes, header_signing_bytes, tx_bytes, access_list_bytes, string_bytes,
    };
    use crate::crypto::{
        hash_bytes_sha256, addr_from_pubkey, addr_hex, commitment_hash,
        commit_signing_preimage, avail_signing_preimage,
    };
    use crate::state::{Balances, Nonces, Commitments, Available, CHAIN_ID, MAX_AVAILS_PER_BLOCK, MAX_PENDING_COMMITS_PER_ACCOUNT};
    use crate::types::{
        Block, BlockHeader, Tx, CommitTx, AvailTx, RevealTx, Transaction, Hash,
    };

    fn build_block(
        chain: &Chain,
        signer: &SigningKey,
        balances: &Balances,
        nonces: &Nonces,
        commitments: &Commitments,
        available: &Available,
        transactions: Vec<Tx>,
        reveals: Vec<RevealTx>,
    ) -> Block {
        let mut block = Block {
            header: BlockHeader {
                parent_hash: chain.tip_hash,
                height: chain.height + 1,
                proposer_pubkey: signer.verifying_key().to_bytes(),
                txs_root: [0u8; 32],
                receipts_root: [0u8; 32],
                gas_used: 0,
                randomness: chain.tip_hash,
                reveal_set_root: [0u8; 32],
                il_root: [0u8; 32],
                exec_base_fee: chain.fee_state.exec_base,
                commit_base_fee: chain.fee_state.commit_base,
                avail_base_fee: chain.fee_state.avail_base,
                timestamp: 0,
                signature: [0u8; 64],
            },
            transactions,
            reveals,
        };

        let mut sim_balances = balances.clone();
        let mut sim_nonces = nonces.clone();
        let mut sim_commitments = commitments.clone();
        let mut sim_available = available.clone();
        let proposer_addr = addr_hex(&addr_from_pubkey(&block.header.proposer_pubkey));
        let mut burned = 0u64;
        let body = process_block(
            &block,
            &mut sim_balances,
            &mut sim_nonces,
            &mut sim_commitments,
            &mut sim_available,
            &chain.fee_state,
            &proposer_addr,
            &mut burned,
        ).expect("process_block");

        block.header.txs_root = body.txs_root;
        block.header.receipts_root = body.receipts_root;
        block.header.reveal_set_root = body.reveal_set_root;
        block.header.il_root = body.il_root;
        block.header.gas_used = body.gas_total;

        let preimage = header_signing_bytes(&block.header);
        let sig = signer.sign(&preimage).to_bytes();
        block.header.signature = sig;

        block
    }

    fn build_empty_block(
        chain: &Chain,
        signer: &SigningKey,
        balances: &Balances,
        nonces: &Nonces,
        commitments: &Commitments,
        available: &Available,
    ) -> Block {
        build_block(
            chain,
            signer,
            balances,
            nonces,
            commitments,
            available,
            Vec::new(),
            Vec::new(),
        )
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
    ) -> (CommitTx, Hash) {
        let tx_ser = tx_bytes(tx);
        let al_bytes = access_list_bytes(&tx.access_list);
        let commitment = commitment_hash(&tx_ser, &al_bytes, &salt, CHAIN_ID);
        let ciphertext_hash = hash_bytes_sha256(b"ciphertext");
        let sender = addr_hex(&addr_from_pubkey(&signer.verifying_key().to_bytes()));
        let sender_bytes = string_bytes(&sender);
        let preimage = commit_signing_preimage(
            &commitment,
            &ciphertext_hash,
            &sender_bytes,
            &al_bytes,
            CHAIN_ID,
        );
        let sig = signer.sign(&preimage).to_bytes();
        (
            CommitTx {
                commitment,
                sender,
                access_list: tx.access_list.clone(),
                ciphertext_hash,
                pubkey: signer.verifying_key().to_bytes(),
                sig,
            },
            commitment,
        )
    }

    fn make_avail(signer: &SigningKey, commitment: Hash) -> AvailTx {
        let sender = addr_hex(&addr_from_pubkey(&signer.verifying_key().to_bytes()));
        let sender_bytes = string_bytes(&sender);
        let preimage = avail_signing_preimage(&commitment, &sender_bytes, CHAIN_ID);
        let sig = signer.sign(&preimage).to_bytes();
        AvailTx {
            commitment,
            sender,
            pubkey: signer.verifying_key().to_bytes(),
            sig,
        }
    }

    fn make_reveal(tx: Transaction, salt: Hash, sender: &str) -> RevealTx {
        RevealTx {
            tx,
            salt,
            sender: sender.to_string(),
        }
    }

    #[test]
    fn apply_block1_advances_tip() {
        let signer = SigningKey::from_bytes(&[1u8; 32]);
        let mut chain = Chain::new();
        let mut balances = Balances::default();
        let mut nonces = Nonces::default();
        let mut commitments = Commitments::default();
        let mut available = Available::default();

        let block = build_empty_block(&chain, &signer, &balances, &nonces, &commitments, &available);
        chain
            .apply_block(&block, &mut balances, &mut nonces, &mut commitments, &mut available)
            .unwrap();

        assert_eq!(chain.height, 1);
        let expected_tip = hash_bytes_sha256(&header_bytes(&block.header));
        assert_eq!(chain.tip_hash, expected_tip);
    }

    #[test]
    fn applying_same_height_fails() {
        let signer = SigningKey::from_bytes(&[2u8; 32]);
        let mut chain = Chain::new();
        let mut balances = Balances::default();
        let mut nonces = Nonces::default();
        let mut commitments = Commitments::default();
        let mut available = Available::default();

        let block1 = build_empty_block(&chain, &signer, &balances, &nonces, &commitments, &available);
        chain
            .apply_block(&block1, &mut balances, &mut nonces, &mut commitments, &mut available)
            .unwrap();

        let err = chain
            .apply_block(&block1, &mut balances, &mut nonces, &mut commitments, &mut available)
            .err()
            .unwrap();
        match err {
            BlockError::BadHeight { expected, got } => {
                assert_eq!(expected, 2);
                assert_eq!(got, 1);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn applying_2_blocks_works_correctly() {
        let signer = SigningKey::from_bytes(&[3u8; 32]);
        let mut chain = Chain::new();
        let mut balances = Balances::default();
        let mut nonces = Nonces::default();
        let mut commitments = Commitments::default();
        let mut available = Available::default();

        let block1 = build_empty_block(&chain, &signer, &balances, &nonces, &commitments, &available);
        chain
            .apply_block(&block1, &mut balances, &mut nonces, &mut commitments, &mut available)
            .unwrap();
        assert_eq!(chain.height, 1);

        let block2 = build_empty_block(&chain, &signer, &balances, &nonces, &commitments, &available);
        chain
            .apply_block(&block2, &mut balances, &mut nonces, &mut commitments, &mut available)
            .unwrap();

        assert_eq!(chain.height, 2);
        let expected_tip = hash_bytes_sha256(&header_bytes(&block2.header));
        assert_eq!(chain.tip_hash, expected_tip);
        assert_ne!(
            chain.tip_hash,
            hash_bytes_sha256(&header_bytes(&block1.header))
        );
    }

    #[test]
    fn tamper_block_no_state_change() {
        let signer = SigningKey::from_bytes(&[4u8; 32]);
        let mut chain = Chain::new();
        let mut balances = Balances::default();
        let mut nonces = Nonces::default();
        let mut commitments = Commitments::default();
        let mut available = Available::default();

        let sender = addr_hex(&addr_from_pubkey(&signer.verifying_key().to_bytes()));
        balances.insert(sender.clone(), 1000);

        let tx1 = Transaction::transfer(&sender, &addr(1), 10, 0);
        let salt1 = [1u8; 32];
        let (commit1, _c1) = make_commit(&signer, &tx1, salt1);

        let block = build_block(
            &chain,
            &signer,
            &balances,
            &nonces,
            &commitments,
            &available,
            vec![Tx::Commit(commit1.clone())],
            vec![],
        );

        let tx2 = Transaction::transfer(&sender, &addr(2), 5, 1);
        let salt2 = [2u8; 32];
        let (commit2, _c2) = make_commit(&signer, &tx2, salt2);
        let mut tampered = block.clone();
        tampered.transactions.push(Tx::Commit(commit2));

        let burned_before = chain.burned_total;
        let res = chain.apply_block(
            &tampered,
            &mut balances,
            &mut nonces,
            &mut commitments,
            &mut available,
        );
        assert!(matches!(res, Err(BlockError::RootMismatch(_))));
        assert_eq!(chain.height, 0);
        assert_eq!(chain.burned_total, burned_before);
        assert!(commitments.is_empty());
        assert_eq!(*balances.get(&sender).unwrap(), 1000);
    }

    #[test]
    fn inclusion_list_due_must_be_included() {
        let signer = SigningKey::from_bytes(&[5u8; 32]);
        let mut chain = Chain::new();
        let mut balances = Balances::default();
        let mut nonces = Nonces::default();
        let mut commitments = Commitments::default();
        let mut available = Available::default();

        let sender = addr_hex(&addr_from_pubkey(&signer.verifying_key().to_bytes()));
        let receiver = addr(1);
        balances.insert(sender.clone(), 1000);
        balances.insert(receiver.clone(), 0);

        let tx = Transaction::transfer(&sender, &receiver, 10, 0);
        let salt = [1u8; 32];
        let (commit, c_hash) = make_commit(&signer, &tx, salt);
        let block1 = build_block(
            &chain,
            &signer,
            &balances,
            &nonces,
            &commitments,
            &available,
            vec![Tx::Commit(commit)],
            vec![],
        );
        chain
            .apply_block(&block1, &mut balances, &mut nonces, &mut commitments, &mut available)
            .unwrap();

        let avail_tx = make_avail(&signer, c_hash);
        let block2 = build_block(
            &chain,
            &signer,
            &balances,
            &nonces,
            &commitments,
            &available,
            vec![Tx::Avail(avail_tx)],
            vec![],
        );
        chain
            .apply_block(&block2, &mut balances, &mut nonces, &mut commitments, &mut available)
            .unwrap();

        for _ in 0..2 {
            let b = build_block(
                &chain,
                &signer,
                &balances,
                &nonces,
                &commitments,
                &available,
                vec![],
                vec![],
            );
            chain
                .apply_block(&b, &mut balances, &mut nonces, &mut commitments, &mut available)
                .unwrap();
        }
        assert_eq!(chain.height, 4);

        let block5 = build_block(
            &chain,
            &signer,
            &Balances::default(),
            &Nonces::default(),
            &Commitments::default(),
            &Available::default(),
            vec![],
            vec![],
        );
        let res = chain.apply_block(
            &block5,
            &mut balances,
            &mut nonces,
            &mut commitments,
            &mut available,
        );
        assert!(matches!(res, Err(BlockError::IntrinsicInvalid(msg)) if msg.contains("missing required reveal")));
        assert_eq!(chain.height, 4);
    }

    #[test]
    fn reveal_bundle_executes_multiple_reveals_and_satisfies_inclusion_list() {
        let signer = SigningKey::from_bytes(&[6u8; 32]);
        let mut chain = Chain::new();
        let mut balances = Balances::default();
        let mut nonces = Nonces::default();
        let mut commitments = Commitments::default();
        let mut available = Available::default();

        let sender = addr_hex(&addr_from_pubkey(&signer.verifying_key().to_bytes()));
        let recv1 = addr(1);
        let recv2 = addr(2);
        balances.insert(sender.clone(), 1000);
        balances.insert(recv1.clone(), 0);
        balances.insert(recv2.clone(), 0);

        let tx1 = Transaction::transfer(&sender, &recv1, 10, 0);
        let salt1 = [11u8; 32];
        let (commit1, c1) = make_commit(&signer, &tx1, salt1);
        let tx2 = Transaction::transfer(&sender, &recv2, 20, 1);
        let salt2 = [22u8; 32];
        let (commit2, c2) = make_commit(&signer, &tx2, salt2);

        let block1 = build_block(
            &chain,
            &signer,
            &balances,
            &nonces,
            &commitments,
            &available,
            vec![Tx::Commit(commit1.clone()), Tx::Commit(commit2.clone())],
            vec![],
        );
        chain
            .apply_block(&block1, &mut balances, &mut nonces, &mut commitments, &mut available)
            .unwrap();

        let avail1 = make_avail(&signer, c1);
        let avail2 = make_avail(&signer, c2);
        let block2 = build_block(
            &chain,
            &signer,
            &balances,
            &nonces,
            &commitments,
            &available,
            vec![Tx::Avail(avail1), Tx::Avail(avail2)],
            vec![],
        );
        chain
            .apply_block(&block2, &mut balances, &mut nonces, &mut commitments, &mut available)
            .unwrap();

        for _ in 0..2 {
            let b = build_block(
                &chain,
                &signer,
                &balances,
                &nonces,
                &commitments,
                &available,
                vec![],
                vec![],
            );
            chain
                .apply_block(&b, &mut balances, &mut nonces, &mut commitments, &mut available)
                .unwrap();
        }

        let r1 = make_reveal(tx1.clone(), salt1, &sender);
        let r2 = make_reveal(tx2.clone(), salt2, &sender);
        let block5 = build_block(
            &chain,
            &signer,
            &balances,
            &nonces,
            &commitments,
            &available,
            vec![],
            vec![r1, r2],
        );
        let res = chain
            .apply_block(&block5, &mut balances, &mut nonces, &mut commitments, &mut available)
            .unwrap();
        assert_eq!(chain.height, 5);
        assert_eq!(res.receipts.len(), 2);
        assert_eq!(balances.get(&recv1).copied().unwrap(), 10);
        assert_eq!(balances.get(&recv2).copied().unwrap(), 20);
        assert!(chain.commitments_due_and_available(5).is_empty());
    }

    #[test]
    fn too_many_avails_in_block_is_invalid() {
        let signer = SigningKey::from_bytes(&[7u8; 32]);
        let mut chain = Chain::new();
        let mut balances = Balances::default();
        let mut nonces = Nonces::default();
        let mut commitments = Commitments::default();
        let mut available = Available::default();

        let mut txs = Vec::with_capacity(MAX_AVAILS_PER_BLOCK + 1);
        for _ in 0..=MAX_AVAILS_PER_BLOCK {
            txs.push(Tx::Avail(AvailTx {
                commitment: [0u8; 32],
                sender: String::new(),
                pubkey: [0u8; 32],
                sig: [0u8; 64],
            }));
        }

        let mut block = Block {
            header: BlockHeader {
                parent_hash: chain.tip_hash,
                height: chain.height + 1,
                proposer_pubkey: signer.verifying_key().to_bytes(),
                txs_root: [0u8; 32],
                receipts_root: [0u8; 32],
                gas_used: 0,
                randomness: chain.tip_hash,
                reveal_set_root: [0u8; 32],
                il_root: [0u8; 32],
                exec_base_fee: chain.fee_state.exec_base,
                commit_base_fee: chain.fee_state.commit_base,
                avail_base_fee: chain.fee_state.avail_base,
                timestamp: 0,
                signature: [0u8; 64],
            },
            transactions: txs,
            reveals: vec![],
        };

        let preimage = header_signing_bytes(&block.header);
        block.header.signature = signer.sign(&preimage).to_bytes();

        let res = chain.apply_block(&block, &mut balances, &mut nonces, &mut commitments, &mut available);
        assert!(matches!(res, Err(BlockError::IntrinsicInvalid(msg)) if msg.contains("too many Avails in block")));
        assert_eq!(chain.height, 0);
    }

    #[test]
    fn too_many_pending_commits_for_owner_is_rejected() {
        let signer = SigningKey::from_bytes(&[8u8; 32]);
        let mut chain = Chain::new();
        let mut balances = Balances::default();
        let mut nonces = Nonces::default();
        let mut commitments = Commitments::default();
        let mut available = Available::default();

        let sender = addr_hex(&addr_from_pubkey(&signer.verifying_key().to_bytes()));
        balances.insert(sender.clone(), 2_000);

        let tx = Transaction::transfer(&sender, &addr(1), 1, 0);
        let mut txs = Vec::with_capacity(MAX_PENDING_COMMITS_PER_ACCOUNT + 1);
        for i in 0..=MAX_PENDING_COMMITS_PER_ACCOUNT {
            let mut salt = [0u8; 32];
            salt[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let (c, _ch) = make_commit(&signer, &tx, salt);
            txs.push(Tx::Commit(c));
        }

        let mut block = Block {
            header: BlockHeader {
                parent_hash: chain.tip_hash,
                height: chain.height + 1,
                proposer_pubkey: signer.verifying_key().to_bytes(),
                txs_root: [0u8; 32],
                receipts_root: [0u8; 32],
                gas_used: 0,
                randomness: chain.tip_hash,
                reveal_set_root: [0u8; 32],
                il_root: [0u8; 32],
                exec_base_fee: chain.fee_state.exec_base,
                commit_base_fee: chain.fee_state.commit_base,
                avail_base_fee: chain.fee_state.avail_base,
                timestamp: 0,
                signature: [0u8; 64],
            },
            transactions: txs,
            reveals: vec![],
        };

        let preimage = header_signing_bytes(&block.header);
        block.header.signature = signer.sign(&preimage).to_bytes();

        let res = chain.apply_block(&block, &mut balances, &mut nonces, &mut commitments, &mut available);
        assert!(matches!(res, Err(BlockError::IntrinsicInvalid(msg)) if msg.contains("too many pending commits for owner")));
        assert!(commitments.is_empty());
        assert_eq!(chain.height, 0);
    }

    #[test]
    fn duplicate_commit_in_same_block_is_rejected() {
        let signer = SigningKey::from_bytes(&[9u8; 32]);
        let mut chain = Chain::new();
        let mut balances = Balances::default();
        let mut nonces = Nonces::default();
        let mut commitments = Commitments::default();
        let mut available = Available::default();

        let sender = addr_hex(&addr_from_pubkey(&signer.verifying_key().to_bytes()));
        balances.insert(sender.clone(), 100);

        let tx = Transaction::transfer(&sender, &addr(1), 1, 0);
        let salt = [1u8; 32];
        let (commit, _c_hash) = make_commit(&signer, &tx, salt);

        let mut block = Block {
            header: BlockHeader {
                parent_hash: chain.tip_hash,
                height: chain.height + 1,
                proposer_pubkey: signer.verifying_key().to_bytes(),
                txs_root: [0u8; 32],
                receipts_root: [0u8; 32],
                gas_used: 0,
                randomness: chain.tip_hash,
                reveal_set_root: [0u8; 32],
                il_root: [0u8; 32],
                exec_base_fee: chain.fee_state.exec_base,
                commit_base_fee: chain.fee_state.commit_base,
                avail_base_fee: chain.fee_state.avail_base,
                timestamp: 0,
                signature: [0u8; 64],
            },
            transactions: vec![Tx::Commit(commit.clone()), Tx::Commit(commit.clone())],
            reveals: vec![],
        };

        let preimage = header_signing_bytes(&block.header);
        block.header.signature = signer.sign(&preimage).to_bytes();

        let res = chain.apply_block(&block, &mut balances, &mut nonces, &mut commitments, &mut available);
        assert!(matches!(res, Err(BlockError::IntrinsicInvalid(msg)) if msg.contains("duplicate commitment")));
        assert!(commitments.is_empty());
        assert_eq!(chain.height, 0);
    }

    #[test]
    fn inclusion_list_due_but_missing_reveal_rejects_block() {
        let signer = SigningKey::from_bytes(&[10u8; 32]);
        let mut chain = Chain::new();
        let mut balances = Balances::default();
        let mut nonces = Nonces::default();
        let mut commitments = Commitments::default();
        let mut available = Available::default();

        let sender = addr_hex(&addr_from_pubkey(&signer.verifying_key().to_bytes()));
        let receiver = addr(1);
        balances.insert(sender.clone(), 1000);
        balances.insert(receiver.clone(), 0);

        // include a commit
        let tx = Transaction::transfer(&sender, &receiver, 10, 0);
        let salt = [1u8; 32];
        let (commit, c_hash) = make_commit(&signer, &tx, salt);
        let block1 = build_block(
            &chain,
            &signer,
            &balances,
            &nonces,
            &commitments,
            &available,
            vec![Tx::Commit(commit)],
            vec![],
        );
        chain
            .apply_block(&block1, &mut balances, &mut nonces, &mut commitments, &mut available)
            .unwrap();

        // include availability
        let avail_tx = make_avail(&signer, c_hash);
        let block2 = build_block(
            &chain,
            &signer,
            &balances,
            &nonces,
            &commitments,
            &available,
            vec![Tx::Avail(avail_tx)],
            vec![],
        );
        chain
            .apply_block(&block2, &mut balances, &mut nonces, &mut commitments, &mut available)
            .unwrap();

        // advance chain until reveal is due
        for _ in 0..2 {
            let b = build_block(
                &chain,
                &signer,
                &balances,
                &nonces,
                &commitments,
                &available,
                vec![],
                vec![],
            );
            chain
                .apply_block(&b, &mut balances, &mut nonces, &mut commitments, &mut available)
                .unwrap();
        }
        assert_eq!(chain.height, 4);

        // build a block without the required reveal
        let mut block5 = Block {
            header: BlockHeader {
                parent_hash: chain.tip_hash,
                height: chain.height + 1,
                proposer_pubkey: signer.verifying_key().to_bytes(),
                txs_root: [0u8; 32],
                receipts_root: [0u8; 32],
                gas_used: 0,
                randomness: chain.tip_hash,
                reveal_set_root: [0u8; 32],
                il_root: [0u8; 32],
                exec_base_fee: chain.fee_state.exec_base,
                commit_base_fee: chain.fee_state.commit_base,
                avail_base_fee: chain.fee_state.avail_base,
                timestamp: 0,
                signature: [0u8; 64],
            },
            transactions: vec![],
            reveals: vec![],
        };

        let preimage = header_signing_bytes(&block5.header);
        block5.header.signature = signer.sign(&preimage).to_bytes();

        let res = chain.apply_block(
            &block5,
            &mut balances,
            &mut nonces,
            &mut commitments,
            &mut available,
        );
        assert!(matches!(res, Err(BlockError::IntrinsicInvalid(msg)) if msg.contains("missing required reveal")));
        assert_eq!(chain.height, 4);
    }

    #[test]
    fn availability_outside_window_rejected() {
        let signer = SigningKey::from_bytes(&[11u8; 32]);
        let mut chain = Chain::new();
        let mut balances = Balances::default();
        let mut nonces = Nonces::default();
        let mut commitments = Commitments::default();
        let mut available = Available::default();

        let sender = addr_hex(&addr_from_pubkey(&signer.verifying_key().to_bytes()));
        balances.insert(sender.clone(), 1_000);

        let tx = Transaction::transfer(&sender, &addr(1), 10, 0);
        let salt = [2u8; 32];
        let (commit, c_hash) = make_commit(&signer, &tx, salt);
        let avail = make_avail(&signer, c_hash);

        // commit and avail included in the same block (avail too early)
        let mut block = Block {
            header: BlockHeader {
                parent_hash: chain.tip_hash,
                height: chain.height + 1,
                proposer_pubkey: signer.verifying_key().to_bytes(),
                txs_root: [0u8; 32],
                receipts_root: [0u8; 32],
                gas_used: 0,
                randomness: chain.tip_hash,
                reveal_set_root: [0u8; 32],
                il_root: [0u8; 32],
                exec_base_fee: chain.fee_state.exec_base,
                commit_base_fee: chain.fee_state.commit_base,
                avail_base_fee: chain.fee_state.avail_base,
                timestamp: 0,
                signature: [0u8; 64],
            },
            transactions: vec![Tx::Commit(commit), Tx::Avail(avail)],
            reveals: vec![],
        };

        let preimage = header_signing_bytes(&block.header);
        block.header.signature = signer.sign(&preimage).to_bytes();

        let res = chain.apply_block(
            &block,
            &mut balances,
            &mut nonces,
            &mut commitments,
            &mut available,
        );
        assert!(matches!(res, Err(BlockError::IntrinsicInvalid(msg)) if msg.contains("avail outside valid window")));
        assert!(available.is_empty());
        assert_eq!(chain.height, 0);
    }
}