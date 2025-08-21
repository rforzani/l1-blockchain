// src/main.rs

mod types;
mod state;
mod stf;
mod crypto;
mod gas;
mod codec;
mod mempool;
mod consensus;
mod fees;
mod node;
mod chain;
mod verify;
mod pos;

use crate::state::{Balances, print_balances};
use crate::types::Hash;

use hex;

fn hex32(h: &Hash) -> String { hex::encode(h) }

fn main() {
    // 1) bootstrap balances
    let balances: Balances = [
        ("Alice".to_string(), 100_u64),
        ("Bob".to_string(), 50_u64),
    ]
    .into_iter()
    .collect();

    println!("Initial:");
    print_balances(&balances);
}