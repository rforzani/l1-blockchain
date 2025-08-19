//src/chain.rs

use crate::fees::{update_commit_base, update_exec_base, FeeState, FEE_PARAMS};
use crate::stf::{process_block, BlockResult, BlockError};
use crate::state::{Available, Balances, Commitments, Nonces, DECRYPTION_DELAY, REVEAL_WINDOW, ZERO_ADDRESS};
use crate::types::{Block, Hash, Event};
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

    // Returns BlockResult on success (so caller can inspect roots, receipts, etc.)
    pub fn apply_block(
        &mut self,
        block: &Block,
        balances: &mut Balances,
        nonces: &mut Nonces,
        commitments: &mut Commitments,
        available: &mut Available,
    ) -> Result<BlockResult, BlockError> {
        // 1) basic height check
        if block.block_number != self.height + 1 {
            return Err(BlockError::BadHeight {
                expected: self.height + 1,
                got: block.block_number,
            });
        }

        let mut sim_balances = balances.clone();
        let mut sim_nonces = nonces.clone();
        let mut sim_commitments = commitments.clone();
        let mut sim_available = available.clone();

        // 2) process with current tip as parent
        let proposer = ZERO_ADDRESS.to_string();
        let res = process_block(
            block,
            &mut sim_balances,
            &mut sim_nonces,
            &mut sim_commitments,
            &mut sim_available,
            &self.tip_hash,
            &self.fee_state,
            &proposer,
            &mut self.burned_total,
        )?;

        // Parent guard: the block we just built must link to our tip
        if res.header.parent_hash != self.tip_hash {
            return Err(BlockError::HeaderMismatch(
                format!(
                    "parent mismatch: expected {}, got {}",
                    hex::encode(self.tip_hash),
                    hex::encode(res.header.parent_hash),
                )
            ));
        }

        verify_block_roots(&res.header, block, &res.receipts).map_err(|e| BlockError::RootMismatch(e))?;

        *balances = sim_balances;
        *nonces = sim_nonces;
        *commitments = sim_commitments;
        *available = sim_available;

        for ev in &res.events {
            match ev {
                Event::CommitStored { commitment, .. } => {
                    self.commit_included_at.insert(*commitment, block.block_number);
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

        // 3) updsate self state
        self.tip_hash = res.block_hash;
        self.height = block.block_number;
        self.fee_state.exec_base = next_exec;
        self.fee_state.commit_base = update_commit_base(
            self.fee_state.commit_base,
            res.commits_used,
        );
        Ok(res)
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
    use crate::state::CHAIN_ID;
    
    #[test]
    fn apply_block1_advances_tip() {
        use std::collections::HashMap;
        use crate::chain::Chain;
        use crate::state::{Balances, Nonces, Commitments, Available};
        use crate::types::{Block, Tx, CommitTx, Hash, AccessList, StateKey};
        use crate::crypto::{addr_from_pubkey, addr_hex};
        use ed25519_dalek::{SigningKey, VerifyingKey, Signer as _};
        use crate::codec::{string_bytes, access_list_bytes};
        use crate::crypto::{commit_signing_preimage};
        
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = VerifyingKey::from(&sk);
        let pk_bytes = vk.to_bytes();

        let sender = addr_hex(&addr_from_pubkey(&pk_bytes));

        // 1) state
        let mut balances: Balances = HashMap::from([
            (sender.clone().into(), 100), // enough to pay COMMIT_FEE
        ]);
        let mut nonces: Nonces = Default::default();
        let mut comm: Commitments = Default::default();
        let mut avail: Available  = Default::default();

        // 2) chain (genesis)
        let mut chain = Chain::new();
        assert_eq!(chain.height, 0);
        assert_eq!(chain.tip_hash, [0u8; 32]);

        let al = AccessList {
            reads:  vec![ StateKey::Balance(sender.clone().into()), StateKey::Nonce(sender.clone().into()) ],
            writes: vec![ StateKey::Balance(sender.clone().into()), StateKey::Nonce(sender.clone().into()) ],
        };

        // 3) block #1 with a single Commit
        let commitment: Hash = [1u8; 32];

        let sender_bytes = string_bytes(&sender.clone());
        let al_bytes     = access_list_bytes(&al);
        let pre_c = commit_signing_preimage(
            &commitment, &[0u8; 32], &sender_bytes, &al_bytes, CHAIN_ID
        );
        let sig_c = sk.sign(&pre_c).to_bytes();

        let b1 = Block::new(
            vec![Tx::Commit(CommitTx {
                commitment,
                sender: sender,
                ciphertext_hash: [0u8; 32],
                access_list: al,
                pubkey: pk_bytes,
                sig: sig_c
            })],
            1,
        );

        // 4) apply
        let res = chain
            .apply_block(&b1, &mut balances, &mut nonces, &mut comm, &mut avail)
            .expect("block 1 should apply");

        // 5) asserts
        assert_eq!(chain.height, 1);
        assert_eq!(chain.tip_hash, res.block_hash);
        assert_eq!(res.header.height, 1);
        assert_eq!(res.header.parent_hash, [0u8; 32]);
    }

    #[test]
    fn applying_same_height_fails() {
        use crate::chain::Chain;
        use crate::state::{Balances, Nonces, Commitments, Available};
        use crate::types::Block;
        use crate::stf::BlockError;

        let mut balances: Balances = Default::default();
        let mut nonces: Nonces = Default::default();
        let mut comm: Commitments = Default::default();
        let mut avail: Available  = Default::default();
        let mut chain = Chain::new();

        // apply block 1
        let b1 = Block::new(Vec::new(), 1);
        chain
            .apply_block(&b1, &mut balances, &mut nonces, &mut comm, &mut avail)
            .expect("b1 ok");

        // try another block numbered 1
        let b1_again = Block::new(Vec::new(), 1);
        let err = chain
            .apply_block(&b1_again, &mut balances, &mut nonces, &mut comm, &mut avail)
            .expect_err("should fail on bad height");

        match err {
            BlockError::BadHeight { expected, got } => {
                assert_eq!(expected, 2);
                assert_eq!(got, 1);
            }
            other => panic!("expected BadHeight, got {:?}", other),
        }
    }

    #[test]
    fn applying_2_blocks_works_correctly() {
        use std::collections::HashMap;
        use crate::chain::Chain;
        use crate::state::{
            Balances, Nonces, Commitments, Available,
            DECRYPTION_DELAY, REVEAL_WINDOW, CHAIN_ID
        };
        use crate::types::{
            Block, Transaction, Tx, CommitTx, RevealTx, Hash, StateKey, AccessList, AvailTx
        };
        use crate::crypto::{addr_from_pubkey, addr_hex};
        use crate::codec::tx_bytes;
        use crate::crypto::commitment_hash;
        use ed25519_dalek::{SigningKey, VerifyingKey, Signer as _};
        use crate::codec::{string_bytes, access_list_bytes};
        use crate::crypto::{commit_signing_preimage, avail_signing_preimage};
        
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let vk = VerifyingKey::from(&sk);
        let pk_bytes = vk.to_bytes();

        let sk2 = SigningKey::from_bytes(&[3u8; 32]);
        let vk2 = VerifyingKey::from(&sk2);
        let pk_bytes2 = vk2.to_bytes();

        let sender = addr_hex(&addr_from_pubkey(&pk_bytes));
        let receiver = addr_hex(&addr_from_pubkey(&pk_bytes2));

        // helper: advance chain to `target` (exclusive) with empty blocks
        fn advance_to(
            chain: &mut Chain,
            balances: &mut Balances,
            nonces: &mut Nonces,
            comm: &mut Commitments,
            avail: &mut Available,
            target: u64,
        ) {
            while chain.height + 1 < target {
                let b = Block::new(Vec::new(), chain.height + 1);
                chain.apply_block(&b, balances, nonces, comm, avail).expect("advance");
            }
        }

        // Inner tx to be revealed
        let tx = Transaction::transfer(sender.clone(), receiver.clone(), 10, 0);
        let salt: Hash = [3u8; 32];
        let tx_ser = tx_bytes(&tx);
        let tx_al_bytes = access_list_bytes(&tx.access_list);
        let cmt = commitment_hash(&tx_ser, &tx_al_bytes, &salt, CHAIN_ID);

        let al = AccessList {
            reads:  vec![ StateKey::Balance(sender.clone().into()), StateKey::Nonce(sender.clone().into()), StateKey::Balance(receiver.clone().into()) ],
            writes: vec![ StateKey::Balance(sender.clone().into()), StateKey::Nonce(sender.clone().into()), StateKey::Balance(receiver.clone().into()) ],
        };

        let sender_bytes = string_bytes(&sender.clone());
        let al_bytes     = access_list_bytes(&al);
        let pre_c = commit_signing_preimage(
            &cmt, &[0u8; 32], &sender_bytes, &al_bytes, CHAIN_ID
        );
        let sig_c = sk.sign(&pre_c).to_bytes();

        // Block 1: commit
        let b1 = Block::new(
            vec![Tx::Commit(CommitTx {
                commitment: cmt,
                sender: sender.clone().into(),
                ciphertext_hash: [0u8; 32],
                access_list: al,
                pubkey: pk_bytes, 
                sig: sig_c
            })],
            1,
        );

        // Chain/state
        let mut chain = Chain::new();
        let mut balances: Balances = HashMap::from([
            (sender.clone(), 100),
            (receiver.clone(), 50),
        ]);
        let mut nonces: Nonces = Default::default();
        let mut comm: Commitments = Default::default();
        let mut avail: Available  = Default::default();

        let res1 = chain
            .apply_block(&b1, &mut balances, &mut nonces, &mut comm, &mut avail)
            .expect("b1 ok");

        // Compute the earliest reveal height
        let ready_at = 1 + DECRYPTION_DELAY;

        // Advance sequentially up to ready_at
        advance_to(&mut chain, &mut balances, &mut nonces, &mut comm, &mut avail, ready_at);

        // Block ready_at: Avail in transactions + Reveal in the block body
        let reveals = vec![
            RevealTx { tx: tx.clone(), salt, sender: sender.clone().into() }
        ];

        let pre_a = avail_signing_preimage(&cmt, &sender_bytes, CHAIN_ID);
        let sig_a = sk.sign(&pre_a).to_bytes();

        let b2 = Block::new_with_reveals(
            vec![ Tx::Avail(AvailTx { commitment: cmt, pubkey: pk_bytes, sig: sig_a, sender: sender.clone().into() }) ],
            reveals,
            ready_at,
        );

        let res2 = chain
            .apply_block(&b2, &mut balances, &mut nonces, &mut comm, &mut avail)
            .expect("b2 ok");

        assert_eq!(chain.height, ready_at);
        assert_eq!(res2.header.parent_hash, res1.block_hash);

        let _deadline = ready_at + REVEAL_WINDOW;
    }

    #[test]
    fn tamper_block_no_state_change() {
        use std::collections::HashMap;
        use ed25519_dalek::{SigningKey, VerifyingKey, Signer as _};
        use crate::state::{Balances, Nonces, Commitments, Available, COMMIT_FEE, CHAIN_ID};
        use crate::types::{Block, Tx, CommitTx, Hash, AccessList, StateKey};
        use crate::stf::process_block;
        use crate::verify::verify_block_roots;
        use crate::codec::{string_bytes, access_list_bytes};
        use crate::crypto::commit_signing_preimage;
        use crate::crypto::{addr_from_pubkey, addr_hex};

        // Genesis parent
        let parent: Hash = [0u8; 32];

        // Deterministic keypair for signing
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = VerifyingKey::from(&sk);
        let pk_bytes = vk.to_bytes();

        
        let sender = addr_hex(&addr_from_pubkey(&pk_bytes));

        let al = AccessList {
            reads:  vec![
                StateKey::Balance(sender.clone()),
                StateKey::Nonce(sender.clone()),
            ],
            writes: vec![
                StateKey::Balance(sender.clone()),
                StateKey::Nonce(sender.clone()),
            ],
        };

        // Canonical bytes for signing
        let sender_bytes = string_bytes(&sender);
        let al_bytes     = access_list_bytes(&al);

        // Block #1 with a single Commit (signed)
        let commitment: Hash = [9u8; 32];
        let ciphertext_hash: Hash = [0u8; 32];

        let pre_c = commit_signing_preimage(
            &commitment,
            &ciphertext_hash,
            &sender_bytes,
            &al_bytes,
            CHAIN_ID,
        );
        let sig_c = sk.sign(&pre_c).to_bytes();

        let block = Block::new(
            vec![Tx::Commit(CommitTx {
                commitment,
                sender: sender.clone(),
                ciphertext_hash,
                access_list: al,
                pubkey: pk_bytes,
                sig: sig_c,
            })],
            1,
        );

        // Local state
        let mut balances: Balances = HashMap::from([(sender.clone(), 100)]);
        let mut nonces: Nonces = Default::default();
        let mut commitments: Commitments = Default::default();
        let mut available:   Available   = Default::default();

        let fee_state = FeeState::from_defaults();

        // Build (builder path)
        let proposer = ZERO_ADDRESS.to_string();
        let mut burned_total = 0;
        let res = process_block(
            &block,
            &mut balances,
            &mut nonces,
            &mut commitments,
            &mut available,
            &parent,
            &fee_state,
            &proposer,
            &mut burned_total,
        ).expect("ok");

        // Sanity: commit fee burned, nonce unchanged
        assert_eq!(balances[&sender], 100 - COMMIT_FEE);
        assert_eq!(*nonces.get(&sender).unwrap_or(&0), 0);

        // Tamper header
        let mut bad_header = res.header.clone();
        bad_header.receipts_root[0] ^= 1;

        // Verify should fail
        let err = verify_block_roots(&bad_header, &block, &res.receipts)
            .expect_err("verification must fail on header tamper");
        assert!(err.contains("mismatch"));
    }

    #[test]
    fn inclusion_list_due_must_be_included() {
        use std::collections::HashMap;
        use ed25519_dalek::{SigningKey, VerifyingKey, Signer as _};
        use crate::chain::Chain;
        use crate::state::{
            Balances, Nonces, Commitments, Available, DECRYPTION_DELAY, REVEAL_WINDOW, CHAIN_ID
        };
        use crate::types::{
            Block, Tx, CommitTx, RevealTx, AvailTx, Transaction, AccessList, StateKey, Hash
        };
        use crate::codec::{tx_bytes, string_bytes, access_list_bytes};
        use crate::crypto::{commitment_hash, commit_signing_preimage, avail_signing_preimage};
        use crate::stf::BlockError;
        use crate::crypto::{addr_from_pubkey, addr_hex};

        // deterministic test keypair
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = VerifyingKey::from(&sk);
        let pk_bytes = vk.to_bytes();

        let sk2 = SigningKey::from_bytes(&[7u8; 32]);
        let vk2 = VerifyingKey::from(&sk2);
        let pk_bytes2 = vk2.to_bytes();

        use crate::types::Address;
        let sender: Address = addr_hex(&addr_from_pubkey(&pk_bytes));
        let recipient = addr_hex(&addr_from_pubkey(&pk_bytes2));

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

        // --- State ---
        let mut balances: Balances = HashMap::from([(sender.clone().into(), 100)]);
        let mut nonces: Nonces = Default::default();
        let mut comm: Commitments = Default::default();
        let mut avail: Available  = Default::default();

        // --- Chain ---
        let mut chain = Chain::new();

        let al = AccessList {
            reads:  vec![ StateKey::Balance(sender.clone()), StateKey::Nonce(sender.clone()), StateKey::Balance(recipient.clone()) ],
            writes: vec![ StateKey::Balance(sender.clone()), StateKey::Nonce(sender.clone()), StateKey::Balance(recipient.clone()) ],
        };

        // canonical bytes for signing
        let sender_bytes = string_bytes(&sender);
        let al_bytes     = access_list_bytes(&al);

        // Build inner tx + salt so we can compute the matching commitment
        let inner = Transaction::transfer(&sender, recipient.clone(), 10, 0);
        let salt: Hash = [9u8; 32];
        let inner_ser = tx_bytes(&inner);
        let inner_al_bytes = access_list_bytes(&inner.access_list);
        let cmt  = commitment_hash(&inner_ser, &inner_al_bytes, &salt, CHAIN_ID);

        // ---- Block 1: Commit (signed) ----
        let ciphertext_hash = [2u8; 32];
        let pre_commit = commit_signing_preimage(&cmt, &ciphertext_hash, &sender_bytes, &al_bytes, CHAIN_ID);
        let sig_commit = sk.sign(&pre_commit).to_bytes();

        let b1 = Block::new(vec![
            Tx::Commit(CommitTx {
                commitment: cmt,
                sender: sender.clone(),
                ciphertext_hash,
                access_list: al.clone(),
                pubkey: pk_bytes,
                sig: sig_commit,
            })
        ], 1);
        chain.apply_block(&b1, &mut balances, &mut nonces, &mut comm, &mut avail)
            .expect("b1 applies");

        // Compute heights from params
        let ready_at = 1 + DECRYPTION_DELAY;
        let due      = ready_at + REVEAL_WINDOW;

        // If ready_at < due, post availability earlier; otherwise, include it in the due block.
        if ready_at < due {
            advance_to(&mut chain, &mut balances, &mut nonces, &mut comm, &mut avail, ready_at);

            // signed Avail
            let pre_avail = avail_signing_preimage(&cmt, &sender_bytes, CHAIN_ID);
            let sig_avail = sk.sign(&pre_avail).to_bytes();

            let b_ready = Block::new(
                vec![ Tx::Avail(AvailTx {
                    commitment: cmt,
                    sender: sender.clone(),
                    pubkey: pk_bytes,
                    sig: sig_avail,
                }) ],
                ready_at
            );
            chain.apply_block(&b_ready, &mut balances, &mut nonces, &mut comm, &mut avail)
                .expect("availability block applies");
        }

        // ---- Block due: WITHOUT Reveal → must fail ----
        advance_to(&mut chain, &mut balances, &mut nonces, &mut comm, &mut avail, due);

        // txs for due block (may contain Avail if ready_at == due)
        let mut due_txs = Vec::new();
        if ready_at == due {
            // signed Avail in the due block (still no reveal)
            let pre_avail = avail_signing_preimage(&cmt, &sender_bytes, CHAIN_ID);
            let sig_avail = sk.sign(&pre_avail).to_bytes();

            due_txs.push(Tx::Avail(AvailTx {
                commitment: cmt,
                sender: sender.clone(),
                pubkey: pk_bytes,
                sig: sig_avail,
            }));
        }

        let b_due_missing = Block::new_with_reveals(due_txs.clone(), Vec::new(), due);
        let err = chain
            .apply_block(&b_due_missing, &mut balances, &mut nonces, &mut comm, &mut avail)
            .expect_err("must fail due to missing reveal");

        match err {
            BlockError::IntrinsicInvalid(msg) => assert!(msg.contains("missing required reveal")),
            other => panic!("expected IntrinsicInvalid, got {:?}", other),
        }

        // ---- Block due: WITH Reveal → success ----
        // height hasn't advanced after the failed apply, so we can reuse `due`
        let reveals = vec![
            RevealTx { tx: inner.clone(), salt, sender: sender.clone() }
        ];
        let b_due_with = Block::new_with_reveals(due_txs, reveals, due);
        chain.apply_block(&b_due_with, &mut balances, &mut nonces, &mut comm, &mut avail)
            .expect("due block applies with reveal");
    }


    #[test]
    fn reveal_bundle_executes_multiple_reveals_and_satisfies_il() {
        use std::collections::HashMap;
        use ed25519_dalek::{SigningKey, VerifyingKey, Signer as _};
        use crate::chain::Chain;
        use crate::state::{
            Balances, Nonces, Commitments, Available,
            DECRYPTION_DELAY, REVEAL_WINDOW, CHAIN_ID
        };
        use crate::types::{
            Block, Tx, CommitTx, RevealTx, Transaction, AccessList, StateKey, Hash, AvailTx
        };
        use crate::codec::{tx_bytes, string_bytes, access_list_bytes};
        use crate::crypto::{commitment_hash, commit_signing_preimage, avail_signing_preimage};
        use crate::crypto::{addr_from_pubkey, addr_hex};

        // helper: advance chain with empty blocks up to (but not including) `target`
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

        // deterministic keypair for tests
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = VerifyingKey::from(&sk);
        let pk_bytes = vk.to_bytes();

        let sk2 = SigningKey::from_bytes(&[8u8; 32]);
        let vk2 = VerifyingKey::from(&sk2);
        let pk_bytes2 = vk2.to_bytes();

        let sender = addr_hex(&addr_from_pubkey(&pk_bytes));
        let recipient = addr_hex(&addr_from_pubkey(&pk_bytes2));

        let mut balances: Balances = HashMap::from([(sender.clone().into(), 1_000)]);
        let mut nonces: Nonces = Default::default();
        let mut comms: Commitments = Default::default();
        let mut avail: Available   = Default::default();
        let mut chain = Chain::new();

        let al = AccessList {
            reads:  vec![ StateKey::Balance(sender.clone()), StateKey::Balance(recipient.clone()), StateKey::Nonce(sender.clone()) ],
            writes: vec![ StateKey::Balance(sender.clone()), StateKey::Balance(recipient.clone()), StateKey::Nonce(sender.clone()) ],
        };
        let sender_bytes = string_bytes(&sender);
        let al_bytes     = access_list_bytes(&al);

        // two inner transfers (use sequential nonces per sender)
        let t1 = Transaction::transfer(&sender, &recipient, 10, 0);
        let s1: Hash = [1u8; 32];
        let t1_ser = tx_bytes(&t1);
        let t1_al_bytes = access_list_bytes(&t1.access_list);
        let c1 = commitment_hash(&t1_ser, &t1_al_bytes, &s1, CHAIN_ID);

        let t2 = Transaction::transfer(&sender, &recipient, 20, 1);
        let s2: Hash = [2u8; 32];
        let t2_ser = tx_bytes(&t2);
        let t2_al_bytes = access_list_bytes(&t2.access_list);
        let c2 = commitment_hash(&t2_ser, &t2_al_bytes, &s2, CHAIN_ID);

        // block 1: commits (two) — both signed
        let ciphertext_hash = [0u8; 32];

        let pre_c1 = commit_signing_preimage(&c1, &ciphertext_hash, &sender_bytes, &al_bytes, CHAIN_ID);
        let sig_c1 = sk.sign(&pre_c1).to_bytes();

        let pre_c2 = commit_signing_preimage(&c2, &ciphertext_hash, &sender_bytes, &al_bytes, CHAIN_ID);
        let sig_c2 = sk.sign(&pre_c2).to_bytes();

        let b1 = Block::new(vec![
            Tx::Commit(CommitTx {
                commitment: c1,
                sender: sender.clone(),
                ciphertext_hash,
                access_list: al.clone(),
                pubkey: pk_bytes,
                sig: sig_c1,
            }),
            Tx::Commit(CommitTx {
                commitment: c2,
                sender: sender.clone(),
                ciphertext_hash,
                access_list: al.clone(),
                pubkey: pk_bytes,
                sig: sig_c2,
            }),
        ], 1);
        chain.apply_block(&b1, &mut balances, &mut nonces, &mut comms, &mut avail).expect("b1");

        // compute times
        let ready_at = 1 + DECRYPTION_DELAY;
        let due      = ready_at + REVEAL_WINDOW;

        // availability claims (either at ready_at, or in due if equal) — signed
        if ready_at < due {
            advance_to(&mut chain, &mut balances, &mut nonces, &mut comms, &mut avail, ready_at);

            let pre_a1 = avail_signing_preimage(&c1, &sender_bytes, CHAIN_ID);
            let sig_a1 = sk.sign(&pre_a1).to_bytes();

            let pre_a2 = avail_signing_preimage(&c2, &sender_bytes, CHAIN_ID);
            let sig_a2 = sk.sign(&pre_a2).to_bytes();

            let b_ready = Block::new(vec![
                Tx::Avail(AvailTx { commitment: c1, sender: sender.clone(), pubkey: pk_bytes, sig: sig_a1 }),
                Tx::Avail(AvailTx { commitment: c2, sender: sender.clone(), pubkey: pk_bytes, sig: sig_a2 }),
            ], ready_at);
            chain.apply_block(&b_ready, &mut balances, &mut nonces, &mut comms, &mut avail).expect("b_ready");
        }

        // advance to due
        advance_to(&mut chain, &mut balances, &mut nonces, &mut comms, &mut avail, due);

        // due block: both reveals live in the block body; include Avail(s) too if ready_at == due
        let reveals = vec![
            RevealTx { tx: t1.clone(), salt: s1, sender: sender.clone() },
            RevealTx { tx: t2.clone(), salt: s2, sender: sender.clone() },
        ];
        let txs = if ready_at == due {
            let pre_a1 = avail_signing_preimage(&c1, &sender_bytes, CHAIN_ID);
            let sig_a1 = sk.sign(&pre_a1).to_bytes();

            let pre_a2 = avail_signing_preimage(&c2, &sender_bytes, CHAIN_ID);
            let sig_a2 = sk.sign(&pre_a2).to_bytes();

            vec![
                Tx::Avail(AvailTx { commitment: c1, sender: sender.clone(), pubkey: pk_bytes, sig: sig_a1 }),
                Tx::Avail(AvailTx { commitment: c2, sender: sender.clone(), pubkey: pk_bytes, sig: sig_a2 }),
            ]
        } else {
            Vec::new()
        };
        let b_due = Block::new_with_reveals(txs, reveals, due);

        let res = chain.apply_block(&b_due, &mut balances, &mut nonces, &mut comms, &mut avail).expect("b_due");

        // receipts: two reveals
        assert_eq!(res.receipts.len(), 2);
        println!("{:?}", res.receipts[0]);

        let fee_state = FeeState::from_defaults();

        // balances: commit fees + reveal gas + transfers + avail fees
        // Alice started 1000; paid 2*COMMIT_FEE at b1; then pays 2*BASE_FEE and transfers 30 total; plus 2 * AVAIL_FEE
        let expected_alice = 1_000 - 2*fee_state.commit_base - 2*fee_state.exec_base - 10 - 20 - 2*fee_state.avail_base;
        assert_eq!(balances[&sender], expected_alice);
    }

    #[test]
    fn too_many_avails_in_block_is_invalid() {
        use crate::chain::Chain;
        use crate::state::{Balances, Nonces, Commitments, Available, MAX_AVAILS_PER_BLOCK};
        use crate::types::{Block, Tx, AvailTx, Hash};
        use crate::stf::BlockError;

        let mut balances: Balances = Default::default();
        let mut nonces: Nonces = Default::default();
        let mut comms: Commitments = Default::default();
        let mut avail: Available   = Default::default();
        let mut chain = Chain::new();

        // Build a block with MAX_AVAILS_PER_BLOCK + 1 Avails.
        // (We rely on the cap check happening before per-item execution.)
        let mut txs = Vec::with_capacity(MAX_AVAILS_PER_BLOCK + 1);
        for i in 0..(MAX_AVAILS_PER_BLOCK + 1) {
            let mut c: Hash = [0u8; 32];
            c[0] = (i & 0xFF) as u8;
            txs.push(Tx::Avail(AvailTx { commitment: c, pubkey: [0; 32], sig: [0; 64], sender: "Alice".into() }));
        }

        let b = Block::new(txs, 1);
        let err = chain.apply_block(&b, &mut balances, &mut nonces, &mut comms, &mut avail)
            .expect_err("block must be invalid due to too many Avails");

        match err {
            BlockError::IntrinsicInvalid(msg) => assert!(msg.contains("too many Avails")),
            other => panic!("expected IntrinsicInvalid, got {:?}", other),
        }
    }

    #[test]
    fn too_many_pending_commits_for_owner_is_rejected() {
        use ed25519_dalek::{SigningKey, VerifyingKey, Signer as _};
        use crate::chain::Chain;
        use crate::state::{
            Balances, Nonces, Commitments, Available,
            COMMIT_FEE, MAX_PENDING_COMMITS_PER_ACCOUNT, CHAIN_ID
        };
        use crate::types::{Block, Tx, CommitTx, AccessList, StateKey};
        use crate::stf::BlockError;
        use crate::codec::{string_bytes, access_list_bytes};
        use crate::crypto::commit_signing_preimage;
        use crate::crypto::{addr_from_pubkey, addr_hex};

        // deterministic keypair + canonical bytes used for every Commit
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = VerifyingKey::from(&sk);
        let pk_bytes = vk.to_bytes();
        let sender = addr_hex(&addr_from_pubkey(&pk_bytes));

        let mut balances: Balances = std::collections::HashMap::from([
            (sender.clone().into(), (MAX_PENDING_COMMITS_PER_ACCOUNT as u64 + 10) * COMMIT_FEE),
        ]);
        let mut nonces: Nonces = Default::default();
        let mut comms: Commitments = Default::default();
        let mut avail: Available   = Default::default();
        let mut chain = Chain::new();

        let al = AccessList {
            reads:  vec![
                StateKey::Balance(sender.clone()),
                StateKey::Nonce(sender.clone()),
            ],
            writes: vec![
                StateKey::Balance(sender.clone()),
                StateKey::Nonce(sender.clone()),
            ],
        };

        let sender_bytes = string_bytes(&sender);
        let al_bytes     = access_list_bytes(&al);
        let ciphertext_hash = [0u8; 32];

        // Build a single block containing MAX_PENDING + 1 commits from Alice (all signed)
        let mut txs = Vec::with_capacity(MAX_PENDING_COMMITS_PER_ACCOUNT + 1);
        for i in 0..(MAX_PENDING_COMMITS_PER_ACCOUNT + 1) {
            // distinct commitments
            let mut c = [0u8; 32];
            c[..8].copy_from_slice(&(i as u64).to_le_bytes());

            // sign this specific Commit (binds commitment + ciphertext_hash + sender + AL + chain_id)
            let pre = commit_signing_preimage(&c, &ciphertext_hash, &sender_bytes, &al_bytes, CHAIN_ID);
            let sig = sk.sign(&pre).to_bytes();

            txs.push(Tx::Commit(CommitTx {
                commitment: c,
                sender: sender.clone(),
                ciphertext_hash,
                access_list: al.clone(),
                pubkey: pk_bytes,
                sig,
            }));
        }

        let b = Block::new(txs, 1);
        let err = chain
            .apply_block(&b, &mut balances, &mut nonces, &mut comms, &mut avail)
            .expect_err("block must be invalid on the (MAX+1)th commit");

        match err {
            BlockError::IntrinsicInvalid(msg) => {
                assert!(msg.contains("too many pending commits"), "got msg: {msg}");
            }
            other => panic!("expected IntrinsicInvalid, got {:?}", other),
        }
    }

    #[test]
    fn duplicate_commit_in_same_block_is_rejected() {
        use crate::{chain::Chain, state::{Balances, Nonces, Commitments, Available, COMMIT_FEE},
            types::{Block, Tx, CommitTx, AccessList, StateKey}, stf::BlockError};
        use crate::crypto::{addr_from_pubkey, addr_hex};
        use crate::crypto::commit_signing_preimage;
        use ed25519_dalek::{SigningKey, VerifyingKey, Signer as _};
        use crate::codec::{string_bytes, access_list_bytes};

        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = VerifyingKey::from(&sk);
        let pk_bytes = vk.to_bytes();
        let sender = addr_hex(&addr_from_pubkey(&pk_bytes));

        let mut balances: Balances = [(sender.clone().into(), 2 * COMMIT_FEE)].into_iter().collect();
        let mut nonces: Nonces = Default::default();
        let mut comms: Commitments = Default::default();
        let mut avail: Available   = Default::default();
        let mut chain = Chain::new();

        // deterministic keypair + canonical bytes used for every Commit

        let al = AccessList {
            reads:  vec![ StateKey::Balance(sender.clone().into()), StateKey::Nonce(sender.clone().into()) ],
            writes: vec![ StateKey::Balance(sender.clone().into()), StateKey::Nonce(sender.clone().into()) ],
        };

        let commitment = [7u8; 32];

        let sender_bytes = string_bytes(&sender);
        let al_bytes     = access_list_bytes(&al);
        let ciphertext_hash = [0u8; 32];

        let pre = commit_signing_preimage(&commitment, &ciphertext_hash, &sender_bytes, &al_bytes, CHAIN_ID);
        let sig = sk.sign(&pre).to_bytes();

        let txs = vec![
            Tx::Commit(CommitTx { commitment, sender: sender.clone().into(), ciphertext_hash: ciphertext_hash.clone(), access_list: al.clone(), pubkey: pk_bytes.clone(), sig: sig.clone() }),
            Tx::Commit(CommitTx { commitment, sender: sender.clone().into(), ciphertext_hash: ciphertext_hash, access_list: al, pubkey: pk_bytes, sig: sig }),
        ];

        let b = Block::new(txs, 1);
        let err = chain.apply_block(&b, &mut balances, &mut nonces, &mut comms, &mut avail)
            .expect_err("block must be invalid due to duplicate commitment");

        match err {
            BlockError::IntrinsicInvalid(msg ) => assert!(msg.contains("duplicate commitment"), "got: {msg}"),
            other => panic!("expected TxInvalid duplicate, got {:?}", other),
        }
    }

    #[test]
    fn inclusion_list_due_but_missing_reveal_rejects_block() {
        use std::collections::HashMap;
        use ed25519_dalek::{SigningKey, VerifyingKey, Signer as _};
        use crate::chain::Chain;
        use crate::state::{
            Balances, Nonces, Commitments, Available, DECRYPTION_DELAY, REVEAL_WINDOW, CHAIN_ID
        };
        use crate::types::{
            Block, Tx, CommitTx, RevealTx, AvailTx, Transaction, AccessList, StateKey, Hash
        };
        use crate::codec::{tx_bytes, string_bytes, access_list_bytes};
        use crate::crypto::{commitment_hash, commit_signing_preimage, avail_signing_preimage};
        use crate::stf::BlockError;
        use crate::crypto::{addr_from_pubkey, addr_hex};

        // --- deterministic test keypair ---
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = VerifyingKey::from(&sk);
        let pk_bytes = vk.to_bytes();

        let sk2 = SigningKey::from_bytes(&[7u8; 32]);
        let vk2 = VerifyingKey::from(&sk2);
        let pk_bytes2 = vk2.to_bytes();


        let sender = addr_hex(&addr_from_pubkey(&pk_bytes));
        let recipient = addr_hex(&addr_from_pubkey(&pk_bytes2));

        // helper: advance chain with empty blocks up to (but not including) `target`
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

        // --- State/chain ---
        let mut balances: Balances = HashMap::from([(sender.clone().into(), 100)]);
        let mut nonces: Nonces = Default::default();
        let mut comm: Commitments = Default::default();
        let mut avail: Available  = Default::default();
        let mut chain = Chain::new();

        let al = AccessList {
            reads:  vec![ StateKey::Balance(sender.clone()), StateKey::Balance(recipient.clone()), StateKey::Nonce(sender.clone()) ],
            writes: vec![ StateKey::Balance(sender.clone()), StateKey::Balance(recipient.clone()), StateKey::Nonce(sender.clone()) ],
        };

        // canonical bytes for signing
        let sender_bytes = string_bytes(&sender);
        let al_bytes     = access_list_bytes(&al);

        // Build inner tx + salt → commitment
        let inner = Transaction::transfer(&sender, &recipient, 10, 0);
        let salt: Hash = [9u8; 32];
        let inner_ser = tx_bytes(&inner);
        let inner_al_bytes = access_list_bytes(&inner.access_list);
        let cmt  = commitment_hash(&inner_ser, &inner_al_bytes, &salt, CHAIN_ID);

        // Block 1: commit (signed)
        let ciphertext_hash = [2u8; 32];
        let pre_commit = commit_signing_preimage(&cmt, &ciphertext_hash, &sender_bytes, &al_bytes, CHAIN_ID);
        let sig_commit = sk.sign(&pre_commit).to_bytes();

        let b1 = Block::new(vec![
            Tx::Commit(CommitTx {
                commitment: cmt,
                sender: sender.clone(),
                ciphertext_hash,
                access_list: al.clone(),
                pubkey: pk_bytes,
                sig: sig_commit,
            })
        ], 1);
        chain.apply_block(&b1, &mut balances, &mut nonces, &mut comm, &mut avail).expect("b1 applies");

        // Heights
        let ready_at = 1 + DECRYPTION_DELAY;       // e.g., 2
        let due      = ready_at + REVEAL_WINDOW;   // e.g., 5

        // If ready_at < due, post Avail earlier (so it's eligible and will be in IL)
        if ready_at < due {
            advance_to(&mut chain, &mut balances, &mut nonces, &mut comm, &mut avail, ready_at);

            // signed Avail
            let pre_avail = avail_signing_preimage(&cmt, &sender_bytes, CHAIN_ID);
            let sig_avail = sk.sign(&pre_avail).to_bytes();

            let b_ready = Block::new(
                vec![ Tx::Avail(AvailTx {
                    commitment: cmt,
                    sender: sender.clone(),
                    pubkey: pk_bytes,
                    sig: sig_avail,
                }) ],
                ready_at
            );
            chain.apply_block(&b_ready, &mut balances, &mut nonces, &mut comm, &mut avail)
                .expect("availability block applies");
        }

        // Advance to due
        advance_to(&mut chain, &mut balances, &mut nonces, &mut comm, &mut avail, due);

        // Build due block WITHOUT the reveal → must fail
        let due_txs = if ready_at == due {
            // If availability is due at the same height, include a signed Avail here (still no reveal)
            let pre_avail = avail_signing_preimage(&cmt, &sender_bytes, CHAIN_ID);
            let sig_avail = sk.sign(&pre_avail).to_bytes();
            vec![ Tx::Avail(AvailTx {
                commitment: cmt,
                sender: sender.clone(),
                pubkey: pk_bytes,
                sig: sig_avail,
            }) ]
        } else {
            Vec::new()
        };
        let b_due_missing = Block::new_with_reveals(due_txs, Vec::new(), due);

        let err = chain.apply_block(&b_due_missing, &mut balances, &mut nonces, &mut comm, &mut avail)
            .expect_err("must fail due to missing reveal");
        match err {
            BlockError::IntrinsicInvalid(msg) => {
                assert!(msg.contains("missing required reveal"), "got: {msg}");
            }
            other => panic!("expected IntrinsicInvalid, got {:?}", other),
        }

        // (Optional) Now include the reveal at the same height → should pass
        let reveals = vec![ RevealTx { tx: inner.clone(), salt, sender: sender.clone() } ];
        let b_due_with = Block::new_with_reveals(Vec::new(), reveals, due);
        chain.apply_block(&b_due_with, &mut balances, &mut nonces, &mut comm, &mut avail)
            .expect("due block applies with reveal");
    }


    #[test]
    fn availability_outside_window_rejected() {
        use ed25519_dalek::{SigningKey, VerifyingKey, Signer as _};
        use crate::chain::Chain;
        use crate::state::{Balances, Nonces, Commitments, Available, COMMIT_FEE, DECRYPTION_DELAY, REVEAL_WINDOW, CHAIN_ID};
        use crate::types::{Block, Tx, CommitTx, AvailTx, AccessList, StateKey};
        use crate::stf::BlockError;
        use crate::codec::{string_bytes, access_list_bytes};
        use crate::crypto::{commit_signing_preimage, avail_signing_preimage};
        use crate::crypto::{addr_from_pubkey, addr_hex};

        // --- deterministic keypair for tests ---
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = VerifyingKey::from(&sk);
        let pk_bytes = vk.to_bytes();

        let sender = addr_hex(&addr_from_pubkey(&pk_bytes));

        // --- state ---
        let mut balances: Balances = [(sender.clone().into(), 2 * COMMIT_FEE)].into_iter().collect();
        let mut nonces: Nonces = Default::default();
        let mut comms: Commitments = Default::default();
        let mut avail: Available   = Default::default();
        let mut chain = Chain::new();

        // --- access list + canonical bytes for signing ---
        let al = AccessList {
            reads:  vec![StateKey::Balance(sender.clone()), StateKey::Nonce(sender.clone())],
            writes: vec![StateKey::Balance(sender.clone()), StateKey::Nonce(sender.clone())],
        };
        let sender_bytes = string_bytes(&sender);
        let al_bytes     = access_list_bytes(&al);

        // --- Commit at height 1 (we use a fixed commitment as in the original test) ---
        let commitment = [2u8; 32];
        let ciphertext_hash = [0u8; 32];

        // sign the Commit fields
        let pre_c = commit_signing_preimage(&commitment, &ciphertext_hash, &sender_bytes, &al_bytes, CHAIN_ID);
        let sig_c = sk.sign(&pre_c).to_bytes();

        let b1 = Block::new(vec![
            Tx::Commit(CommitTx {
                commitment,
                sender: sender.clone(),
                ciphertext_hash,
                access_list: al.clone(),
                pubkey: pk_bytes,
                sig: sig_c,
            }),
        ], 1);
        chain
            .apply_block(&b1, &mut balances, &mut nonces, &mut comms, &mut avail)
            .expect("commit ok");

        // --- Compute window ---
        let ready_at = 1 + DECRYPTION_DELAY;     // e.g., 2
        let deadline = ready_at + REVEAL_WINDOW; // e.g., 5

        // --- Advance to deadline (inclusive) ---
        for h in 2..=deadline {
            let empty = Block::new(Vec::new(), h);
            chain
                .apply_block(&empty, &mut balances, &mut nonces, &mut comms, &mut avail)
                .expect("advance");
        }

        // --- Avail too late (deadline + 1) ---
        // sign the Avail fields
        let pre_a = avail_signing_preimage(&commitment, &sender_bytes, CHAIN_ID);
        let sig_a = sk.sign(&pre_a).to_bytes();

        let late_block = Block::new(
            vec![Tx::Avail(AvailTx {
                commitment,
                sender: sender.clone(),
                pubkey: pk_bytes,
                sig: sig_a,
            })],
            deadline + 1,
        );

        let err = chain
            .apply_block(&late_block, &mut balances, &mut nonces, &mut comms, &mut avail)
            .expect_err("block must be rejected for late availability");

        match err {
            BlockError::IntrinsicInvalid(msg) => {
                assert!(
                    msg.contains("avail outside valid window"),
                    "got: {msg}"
                )
            }
            other => panic!("expected IntrinsicInvalid for late avail, got {:?}", other),
        }
    }

    #[test]
    fn commit_base_tracks_commits_and_avails_static() {
        use std::collections::HashMap;

        use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};

        use crate::{
            chain::Chain,
            codec::{access_list_bytes, string_bytes},
            crypto::{addr_from_pubkey, addr_hex, commit_signing_preimage},
            fees::FEE_PARAMS,
            state::{Balances, Nonces, Commitments, Available, CHAIN_ID},
            types::{Block, CommitTx, Tx, AccessList, StateKey},
        };
        // Setup signer and sender address
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let vk = VerifyingKey::from(&sk);
        let pk_bytes = vk.to_bytes();
        let sender = addr_hex(&addr_from_pubkey(&pk_bytes));

        // Chain with elevated commit base so adjustments are visible
        let mut chain = Chain::new();
        chain.fee_state.commit_base = 2_000;
        let initial_commit_base = chain.fee_state.commit_base;
        let initial_avail_base = chain.fee_state.avail_base;

        // State with enough balance to cover many commits
        let mut balances: Balances = HashMap::from([(sender.clone(), 300_000u64)]);
        let mut nonces: Nonces = Default::default();
        let mut commits: Commitments = Default::default();
        let mut avail: Available = Default::default();

        // Access list required for commit transactions
        let al = AccessList {
            reads: vec![
                StateKey::Balance(sender.clone()),
                StateKey::Nonce(sender.clone()),
            ],
            writes: vec![
                StateKey::Balance(sender.clone()),
                StateKey::Nonce(sender.clone()),
            ],
        };

        // Block 1: no commits
        let b1 = Block::new(Vec::new(), 1);
        let res1 = chain
            .apply_block(&b1, &mut balances, &mut nonces, &mut commits, &mut avail)
            .expect("block 1 should apply");

        assert_eq!(res1.commits_used, 0);
        assert!(chain.fee_state.commit_base < initial_commit_base);
        assert!(chain.fee_state.commit_base >= FEE_PARAMS.min_commit);
        assert_eq!(chain.fee_state.avail_base, initial_avail_base);

        let after_b1 = chain.fee_state.commit_base;

        // Prepare many commit transactions for block 2
        let mut txs = Vec::new();
        let sender_bytes = string_bytes(&sender);
        let al_bytes = access_list_bytes(&al);
        let high_commits = 2 * FEE_PARAMS.commit_target_commits_per_block;
        for i in 0..high_commits {
            let mut commitment = [0u8; 32];
            commitment[0] = i as u8;
            let pre = commit_signing_preimage(&commitment, &[0u8; 32], &sender_bytes, &al_bytes, CHAIN_ID);
            let sig = sk.sign(&pre).to_bytes();
            txs.push(Tx::Commit(CommitTx {
                commitment,
                sender: sender.clone(),
                ciphertext_hash: [0u8; 32],
                access_list: al.clone(),
                pubkey: pk_bytes,
                sig,
            }));
        }

        // Block 2: many commits
        let b2 = Block::new(txs, 2);
        let res2 = chain
            .apply_block(&b2, &mut balances, &mut nonces, &mut commits, &mut avail)
            .expect("block 2 should apply");

        assert_eq!(res2.commits_used, high_commits as u32);
        assert!(chain.fee_state.commit_base > after_b1);
        let max_cap = after_b1 + (after_b1 / FEE_PARAMS.commit_max_change_denominator as u64).max(1);
        assert!(chain.fee_state.commit_base <= max_cap);
        assert_eq!(chain.fee_state.avail_base, initial_avail_base);
    }
}