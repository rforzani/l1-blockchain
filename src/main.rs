// src/main.rs

mod types;
mod state;
mod stf;
mod crypto;
mod gas;
mod codec;
mod chain;
mod verify;

use crate::state::{Balances, print_balances, Nonces};
use crate::types::{Transaction, Block};
use crate::types::Hash;
use crate::chain::Chain;

use hex;

fn hex32(h: &Hash) -> String { hex::encode(h) }

fn main() {
    // 1) bootstrap balances
    let mut balances: Balances = [
        ("Alice".to_string(), 100_u64),
        ("Bob".to_string(), 50_u64),
    ]
    .into_iter()
    .collect();

    let mut nonces: Nonces = Default::default();

    println!("Initial:");
    print_balances(&balances);

    let mut chain: Chain = Chain::new();

    // 2) successful tx: Alice -> Bob (30)
    let tx1 = Transaction::new("Alice", "Bob", 20, 0);

    // 3) failing tx: Alice -> Bob (200)    
    let tx2 = Transaction::new("Bob", "Alice", 10, 0);

    let transactions1 = vec![tx1];

    let transactions2 = vec![tx2];

    let block1 = Block::new(transactions1, 1);

    let block2 = Block::new(transactions2, 2);

    match chain.apply_block(&block1, &mut balances, &mut nonces) {
        Ok(block_result) => {
            println!("gas_total={}", block_result.gas_total);
            println!("txs_root={}", hex32(&block_result.txs_root));
            println!("receipts_root={}", hex32(&block_result.receipts_root));
            for (i, receipt) in block_result.receipts.iter().enumerate() {
                println!("{}, {:?}, {:?}", i + 1, receipt.outcome, receipt.error);
            }
            println!("block_hash={}", hex::encode(block_result.block_hash));
        }
        Err(msg ) => {println!("{}", msg)}
    }

    match chain.apply_block(&block2, &mut balances, &mut nonces) {
        Ok(block_result) => {
            println!("gas_total={}", block_result.gas_total);
            println!("txs_root={}", hex32(&block_result.txs_root));
            println!("receipts_root={}", hex32(&block_result.receipts_root));
            for (i, receipt) in block_result.receipts.iter().enumerate() {
                println!("{}, {:?}, {:?}", i + 1, receipt.outcome, receipt.error);
            }
            println!("block_hash={}", hex::encode(block_result.block_hash));
        }
        Err(msg ) => {println!("{}", msg)}
    }

    println!("\nAfter txs:");
    print_balances(&balances);
}
