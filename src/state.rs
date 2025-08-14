// src/state.rs

use std::collections::{HashMap, HashSet};
use crate::types::{Hash, CommitmentMeta};

pub const COMMIT_FEE: u64 = 1;
pub const REVEAL_WINDOW: u64 = 3;
pub const DECRYPTION_DELAY: u64 = 1;   // blocks after commit before reveals may start
pub const MAX_PENDING_PER_ACCT: usize = 32;

pub type Balances = HashMap<String, u64>;
pub type Nonces = HashMap<String, u64>;
pub type Commitments = HashMap<Hash, CommitmentMeta>; 
pub type Available = HashSet<Hash>;

pub fn print_balances(balances: &Balances) {
    println!("--- balances ---");
    for (addr, bal) in balances {
        println!("{addr}: {bal}");
    }
    println!("----------------");
}
