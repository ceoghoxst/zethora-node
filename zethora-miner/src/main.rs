//! Zethora devnet CPU miner (prototype).
//!
//! Connects to a local Zethora node, asks it for a block template, searches for a
//! valid nonce on all CPU threads with RandomX (fast mode), and submits the block.
//! Repeats forever. Needs about 2.5 GB of RAM.
//!
//! Usage:  cargo run --release --bin zethora-miner
//! The node must be running with:  --devnet --enable-unsynced-mining
//!
//! The miner keeps its key in `zethora-miner-key.txt` (devnet test coins only).

use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus_core::{header::Header, network::NetworkType};
use kaspa_grpc_client::GrpcClient;
use kaspa_rpc_core::api::rpc::RpcApi;
use secp256k1::{Keypair, SecretKey, SECP256K1};
use std::{
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

const NODE_URL: &str = "grpc://127.0.0.1:26610";
const KEY_FILE: &str = "zethora-miner-key.txt";
/// Get a fresh template this often, so we always build on the newest blocks.
const TEMPLATE_REFRESH: Duration = Duration::from_millis(1000);
const ZETS_PER_ZTHR: f64 = 10_000_000_000.0;

fn load_or_create_key() -> Keypair {
    if let Ok(hex) = std::fs::read_to_string(KEY_FILE) {
        let bytes: Vec<u8> = (0..64).step_by(2).map(|i| u8::from_str_radix(&hex.trim()[i..i + 2], 16).unwrap()).collect();
        let sk = SecretKey::from_slice(&bytes).expect("bad key file");
        return Keypair::from_secret_key(SECP256K1, &sk);
    }
    let kp = Keypair::new(SECP256K1, &mut secp256k1::rand::thread_rng());
    let hex: String = kp.secret_key().secret_bytes().iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(KEY_FILE, hex).expect("cannot write key file");
    println!("Created new devnet mining key in {KEY_FILE}");
    kp
}

#[tokio::main]
async fn main() {
    let kp = load_or_create_key();
    let address = Address::new(Prefix::from(NetworkType::Devnet), Version::PubKey, &kp.x_only_public_key().0.serialize());
    println!("Zethora devnet miner");
    println!("Paying rewards to: {address}");

    println!("Preparing RandomX dataset (about 2 GB, takes a minute)...");
    let t0 = Instant::now();
    let dataset = kaspa_pow::randomz::new_mining_dataset();
    println!("Dataset ready in {:.0}s", t0.elapsed().as_secs_f64());

    let client = GrpcClient::connect(NODE_URL.to_string()).await.expect("Cannot reach the node. Is it running with --devnet?");
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    println!("Mining on {threads} threads. Press Ctrl+C to stop.\n");

    let mut mined: u64 = 0;
    let mut total_reward: u64 = 0;
    let hashes = Arc::new(AtomicU64::new(0));
    let start = Instant::now();

    loop {
        let template = match client.get_block_template(address.clone(), b"zethora-miner".to_vec()).await {
            Ok(t) => t,
            Err(e) => {
                println!("Waiting for node: {e}");
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
        };
        let header: Header = (&template.block.header).try_into().expect("bad template header");
        let state = Arc::new(kaspa_pow::State::new(&header));

        // Search nonces on all threads until one wins or the template gets old.
        let found = Arc::new(AtomicBool::new(false));
        let winner = Arc::new(AtomicU64::new(0));
        let deadline = Instant::now() + TEMPLATE_REFRESH;
        let base: u64 = secp256k1::rand::random();
        let workers: Vec<_> = (0..threads as u64)
            .map(|t| {
                let (state, found, winner, hashes, dataset) =
                    (state.clone(), found.clone(), winner.clone(), hashes.clone(), dataset.clone());
                std::thread::spawn(move || {
                    let hasher = kaspa_pow::randomz::FastHasher::new(&dataset);
                    let target = state.target();
                    let mut nonce = base.wrapping_add(t);
                    let mut n = 0u64;
                    while !found.load(Ordering::Relaxed) && Instant::now() < deadline {
                        for _ in 0..16 {
                            if hasher.pow_value(&state.pow_input(nonce)) <= target {
                                if !found.swap(true, Ordering::Relaxed) {
                                    winner.store(nonce, Ordering::Relaxed);
                                }
                                break;
                            }
                            nonce = nonce.wrapping_add(threads as u64);
                            n += 1;
                        }
                    }
                    hashes.fetch_add(n, Ordering::Relaxed);
                })
            })
            .collect();
        for w in workers {
            w.join().unwrap();
        }

        if found.load(Ordering::Relaxed) {
            let mut block = template.block;
            block.header.nonce = winner.load(Ordering::Relaxed);
            let daa = block.header.daa_score;
            // Zethora pool state after this block: coinbase payload bytes 16..24 (pool) and 24..32 (burned)
            let cb = &block.transactions[0].payload;
            let read = |i: usize| cb.get(i..i + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap())).unwrap_or(0);
            let (pool_balance, total_burned) = (read(16), read(24));
            match client.submit_block(block, false).await {
                Ok(r) if r.report.is_success() => {
                    mined += 1;
                    // Reward for this block's DAA score (ZTH-SPEC-001 §5); the node enforces it.
                    let reward = header_reward_hint(daa);
                    total_reward += reward;
                    let rate = hashes.load(Ordering::Relaxed) as f64 / start.elapsed().as_secs_f64();
                    println!(
                        "Block #{mined} | DAA {daa} | reward ~{:.10} | mined ~{:.4} ZTHR | pool {} zets | burned {} zets | {:.0} H/s",
                        reward as f64 / ZETS_PER_ZTHR,
                        total_reward as f64 / ZETS_PER_ZTHR,
                        pool_balance,
                        total_burned,
                        rate
                    );
                }
                Ok(r) => println!("Block rejected: {:?}", r.report),
                Err(e) => println!("Submit error: {e}"),
            }
        }
    }
}

/// Display-only estimate of the subsidy for a DAA score, using the same rule as consensus.
fn header_reward_hint(daa_score: u64) -> u64 {
    const D: u64 = 364_223_944;
    let mut remaining: u64 = 100_000_000 * 10_000_000_000 - 1_000 * 10_000_000_000;
    for _ in 0..daa_score.min(10_000_000) {
        remaining -= remaining / D;
    }
    remaining / D
}
