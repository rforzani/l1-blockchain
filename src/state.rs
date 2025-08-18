// src/state.rs

use std::collections::{HashMap, HashSet};
use crate::types::{Hash, CommitmentMeta, Address};

pub const CHAIN_ID: u64 = 1;
pub const COMMIT_FEE: u64 = 1;
pub const REVEAL_WINDOW: u64 = 3;
pub const DECRYPTION_DELAY: u64 = 1;   // blocks after commit before reveals may start

pub const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";
pub const TREASURY_ADDRESS: &str = "0x0000000000000000000000000000000000000001";

pub const AVAIL_FEE: u64 = 1;
pub const MAX_AVAILS_PER_BLOCK: usize = 50_000;
pub const MAX_REVEALS_PER_BLOCK: usize = 50_000;
pub const MAX_PENDING_COMMITS_PER_ACCOUNT: usize = 1_000;

pub const MAX_AL_READS: usize = 256;
pub const MAX_AL_WRITES: usize = 256;

pub type Balances = HashMap<Address, u64>;
pub type Nonces = HashMap<Address, u64>;
pub type Commitments = HashMap<Hash, CommitmentMeta>; 
pub type Available = HashSet<Hash>;

pub fn print_balances(balances: &Balances) {
    println!("--- balances ---");
    for (addr, bal) in balances {
        println!("{addr}: {bal}");
    }
    println!("----------------");
}