// src/state.rs

use std::collections::HashMap;
use crate::types::{Hash, CommitmentMeta};

pub const COMMIT_FEE: u64 = 1;
pub const EXPIRY_WINDOW: u64 = 3;
pub const MAX_PENDING_PER_ACCT: usize = 32;

pub type Balances = HashMap<String, u64>;
pub type Nonces = HashMap<String, u64>;
pub type Commitments = HashMap<Hash, CommitmentMeta>;

pub fn print_balances(balances: &Balances) {
    println!("--- balances ---");
    for (addr, bal) in balances {
        println!("{addr}: {bal}");
    }
    println!("----------------");
}
