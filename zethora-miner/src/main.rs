//! Zethora CPU miner (prototype). Devnet by default; pass --testnet for testnet.
//!
//! Connects to a local Zethora node, asks it for a block template, searches for a
//! valid nonce on all CPU threads with RandomZ (fast mode), and submits the block.
//! Repeats forever. Needs about 2.5 GB of RAM. The mining key changes every 2^20 DAA
//! scores (about 12 days); the miner then rebuilds its dataset (about half a minute).
//!
//! Usage:
//!   zethora-miner             devnet (node must run with: --devnet --enable-unsynced-mining)
//!   zethora-miner --testnet   testnet (node must run with: --testnet --enable-unsynced-mining)
//!   zethora-miner bench       RandomZ speed test; no node needed, stop the real miner first
//!
//! Key files: zethora-miner-key.txt (devnet) and zethora-miner-key-testnet.txt (testnet).
//! Keys are never shared between networks.

use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus_core::{header::Header, network::NetworkType};
use kaspa_grpc_client::GrpcClient;
use kaspa_rpc_core::api::rpc::RpcApi;
use secp256k1::{Keypair, SECP256K1, SecretKey};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

const DEVNET_NODE_URL: &str = "grpc://127.0.0.1:26610";
const TESTNET_NODE_URL: &str = "grpc://127.0.0.1:26210";
const DEVNET_KEY_FILE: &str = "zethora-miner-key.txt";
const TESTNET_KEY_FILE: &str = "zethora-miner-key-testnet.txt";
/// Get a fresh template this often, so we always build on the newest blocks.
const TEMPLATE_REFRESH: Duration = Duration::from_millis(1000);
const ZETS_PER_ZTHR: f64 = 10_000_000_000.0;

fn load_or_create_key(key_file: &str) -> Keypair {
    if let Ok(hex) = std::fs::read_to_string(key_file) {
        let bytes: Vec<u8> = (0..64).step_by(2).map(|i| u8::from_str_radix(&hex.trim()[i..i + 2], 16).unwrap()).collect();
        let sk = SecretKey::from_slice(&bytes).expect("bad key file");
        return Keypair::from_secret_key(SECP256K1, &sk);
    }
    let kp = Keypair::new(SECP256K1, &mut secp256k1::rand::thread_rng());
    let hex: String = kp.secret_key().secret_bytes().iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(key_file, hex).expect("cannot write key file");
    println!("Created new mining key in {key_file}");
    kp
}

/// RandomZ speed test (step 6): what checking mining work costs a node, and how fast this PC mines.
fn bench() {
    use kaspa_pow::randomz::{FastHasher, new_mining_dataset, pow_input, pow_value_light};
    const RUN: Duration = Duration::from_secs(10);
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    println!("RandomZ speed test on this PC ({threads} CPU threads). Takes about 2-3 minutes; stop the node and the miner first.\n");

    // 1. Node side: light mode (256 MB), one hash per block to check
    println!("1. NODE: preparing light mode (256 MB, done once at node start)...");
    let t = Instant::now();
    let first = pow_value_light(0, &pow_input(&[1; 32], 0, 0));
    let setup = t.elapsed().as_secs_f64();
    println!("   ready in {setup:.2} s");
    println!("   checking mining work, one block at a time, for {} s...", RUN.as_secs());
    let t = Instant::now();
    let mut checked = 0u64;
    while t.elapsed() < RUN {
        let _ = pow_value_light(0, &pow_input(&[2; 32], checked, checked));
        checked += 1;
    }
    let check_ms = t.elapsed().as_secs_f64() * 1000.0 / checked as f64;
    println!("   {check_ms:.1} ms per block");

    // 2. Miner side: fast mode (about 2 GB dataset), many hashes per second
    println!("\n2. MINER: building the fast-mode dataset (about 2 GB, on one thread like the miner does today)...");
    let t = Instant::now();
    let dataset = new_mining_dataset(0);
    let dataset_secs = t.elapsed().as_secs_f64();
    println!("   ready in {dataset_secs:.0} s");
    // Sanity: fast and light mode must agree on the same input
    let same = FastHasher::new(&dataset).pow_value(&pow_input(&[1; 32], 0, 0)) == first;
    println!("   fast mode and light mode give the same hash: {}", if same { "YES" } else { "NO (send this to Claude)" });

    let mut rates = Vec::new();
    // RandomX usually peaks around 8 threads on 6-core desktop chips (2 MB of CPU cache per thread)
    let mut counts = vec![1, threads / 2, threads.min(8), threads];
    counts.retain(|&n| n > 0);
    counts.sort_unstable();
    counts.dedup();
    for n in counts {
        println!("   mining on {n} thread(s) for {} s...", RUN.as_secs());
        let t = Instant::now();
        let total: u64 = std::thread::scope(|s| {
            let workers: Vec<_> = (0..n)
                .map(|i| {
                    let dataset = &dataset;
                    s.spawn(move || {
                        let hasher = FastHasher::new(dataset);
                        let mut nonce = (i as u64) << 40;
                        let mut done = 0u64;
                        while t.elapsed() < RUN {
                            let _ = hasher.pow_value(&pow_input(&[3; 32], 0, nonce));
                            nonce += 1;
                            done += 1;
                        }
                        done
                    })
                })
                .collect();
            workers.into_iter().map(|w| w.join().unwrap()).sum()
        });
        let rate = total as f64 / t.elapsed().as_secs_f64();
        println!("   {rate:.0} H/s");
        rates.push((n, rate));
    }

    let block_secs = 1.0; // devnet and planned mainnet: 1 block per second (ZTH-SPEC-005)
    println!("\nRESULT");
    println!("  Node: light mode ready in {setup:.2} s; checking one block's mining work takes {check_ms:.1} ms");
    println!(
        "        = {:.1}% of one CPU thread at 1 block per second (a full sync re-checks {:.0} blocks per second per thread)",
        100.0 * check_ms / 1000.0 / block_secs,
        1000.0 / check_ms
    );
    println!(
        "  Miner: dataset ready in {dataset_secs:.0} s (one thread); fast and light mode agree: {}",
        if same { "YES" } else { "NO" }
    );
    for (n, rate) in &rates {
        println!("  Mining speed on {n:>2} thread(s): {rate:>7.0} H/s");
    }
    println!("  (No large pages and no hash pipelining yet: dedicated miners like XMRig get more on the same PC.)");
    println!("\nSend Claude this RESULT block.");
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = "Usage:\n  zethora-miner             devnet (node: --devnet --enable-unsynced-mining)\n  zethora-miner --testnet   testnet (node: --testnet --enable-unsynced-mining)\n  zethora-miner bench       RandomZ speed test (no node)";
    let (testnet, is_bench) = match args.as_slice() {
        [] => (false, false),
        [a] if a == "--testnet" => (true, false),
        [a] if a == "bench" => (false, true),
        _ => {
            eprintln!("{usage}");
            std::process::exit(2);
        }
    };
    if is_bench {
        return tokio::task::spawn_blocking(bench).await.expect("speed test");
    }
    let network = if testnet { NetworkType::Testnet } else { NetworkType::Devnet };
    let node_url = if testnet { TESTNET_NODE_URL } else { DEVNET_NODE_URL };
    let key_file = if testnet { TESTNET_KEY_FILE } else { DEVNET_KEY_FILE };
    let network_name = if testnet { "testnet" } else { "devnet" };
    let kp = load_or_create_key(key_file);
    let address = Address::new(Prefix::from(network), Version::PubKey, &kp.x_only_public_key().0.serialize());
    println!("Zethora {network_name} miner");
    println!("Network:  {network_name}");
    println!("Key file: {key_file}");
    println!("Node URL: {node_url}");
    println!("Paying rewards to: {address}");
    // Defensive check: refuse to mine if the address prefix does not match the network.
    let addr_str = address.to_string();
    let expected_prefix = if testnet { "zethoratest:" } else { "zethoradev:" };
    if !addr_str.starts_with(expected_prefix) {
        eprintln!("BUG: {network_name} address does not start with {expected_prefix} (got {addr_str}). Exiting to avoid paying to the wrong network.");
        std::process::exit(3);
    }

    let client = GrpcClient::connect(node_url.to_string()).await.expect("Cannot reach the node. Is it running with the matching network flag (--devnet or --testnet)?");
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    println!("Mining on {threads} threads. Press Ctrl+C to stop.\n");

    let mut mined: u64 = 0;
    let mut total_reward: u64 = 0;
    let hashes = Arc::new(AtomicU64::new(0));
    let start = Instant::now();
    // The fast-mode dataset and the key epoch it was built for (rebuilt when the key changes)
    let mut dataset: Option<(u64, kaspa_pow::randomz::SharedDataset)> = None;
    let mut next_dataset: Option<(u64, kaspa_pow::randomz::SharedDataset)> = None;
    let mut prebuild_task: Option<tokio::task::JoinHandle<(u64, Option<kaspa_pow::randomz::SharedDataset>)>> = None;

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
        let epoch = state.epoch();

        // B8: Prebuild the next epoch dataset in the background if we are close.
        // Epoch boundaries are every 1,048,576 DAA scores (1 << 20).
        let next_boundary = (epoch + 1) << 20;
        let blocks_left = next_boundary.saturating_sub(header.daa_score);

        if blocks_left < 2000 && prebuild_task.is_none() && next_dataset.is_none() {
            let next_epoch = epoch + 1;
            println!("Approaching epoch change. Prebuilding dataset for epoch {next_epoch} in the background...");
            prebuild_task =
                Some(tokio::task::spawn_blocking(move || (next_epoch, kaspa_pow::randomz::try_new_mining_dataset(next_epoch))));
        }

        // Check if the background prebuild finished
        if let Some(task) = &prebuild_task {
            if task.is_finished() {
                let task = prebuild_task.take().unwrap();
                match task.await {
                    Ok((built_epoch, Some(built_dataset))) => {
                        println!("Background dataset for epoch {built_epoch} is ready.");
                        next_dataset = Some((built_epoch, built_dataset));
                    }
                    Ok((built_epoch, None)) => {
                        println!("Prebuild for epoch {built_epoch} failed (low memory). Will build synchronously later.");
                    }
                    Err(e) => println!("Background dataset task failed: {e}"),
                }
            }
        }

        if dataset.as_ref().is_none_or(|(built_for, _)| *built_for != epoch) {
            // Try to swap in the prebuilt one first
            if let Some((built_epoch, built_dataset)) = next_dataset.take() {
                if built_epoch == epoch {
                    println!("Swapped in prebuilt dataset for epoch {epoch} instantly.");
                    dataset = Some((built_epoch, built_dataset));
                    continue;
                } else {
                    println!("Prebuilt epoch {built_epoch} did not match current epoch {epoch}. Discarding.");
                }
            }

            // Fallback: build it synchronously
            let first = dataset.is_none();
            drop(dataset.take()); // free the old 2 GB first
            if first {
                println!("Preparing the RandomZ dataset for mining key {epoch} (about 2 GB, takes about half a minute)...");
            } else {
                println!("Mining key changed to {epoch} at DAA {}: rebuilding the dataset (about half a minute)...", header.daa_score);
            }
            let t0 = Instant::now();
            let built = tokio::task::block_in_place(|| kaspa_pow::randomz::new_mining_dataset(epoch));
            println!("Dataset ready in {:.0}s", t0.elapsed().as_secs_f64());
            dataset = Some((epoch, built));
            continue; // the template is old by now
        }
        let mining_dataset = dataset.as_ref().map(|(_, d)| d.clone()).expect("built above");

        // Search nonces on all threads until one wins or the template gets old.
        let found = Arc::new(AtomicBool::new(false));
        let winner = Arc::new(AtomicU64::new(0));
        let deadline = Instant::now() + TEMPLATE_REFRESH;
        let base: u64 = secp256k1::rand::random();
        let workers: Vec<_> = (0..threads as u64)
            .map(|t| {
                let (state, found, winner, hashes, dataset) =
                    (state.clone(), found.clone(), winner.clone(), hashes.clone(), mining_dataset.clone());
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
            // Zethora supply ledger after this block, from the coinbase payload (ZTH-SPEC-006 §7.2):
            // bytes 16 pool, 24 burned, 32 issued, 40 visible supply, 48 private pool
            let cb = &block.transactions[0].payload;
            let read = |i: usize| cb.get(i..i + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap())).unwrap_or(0);
            let (pool_balance, total_burned) = (read(16), read(24));
            let (issued, visible, private) = (read(32), read(40), read(48));
            let balanced = visible as u128 + pool_balance as u128 + total_burned as u128 + private as u128 == issued as u128;
            // Private coin list fingerprint (bytes 56..88): first 4 bytes are enough to see it change
            let coin_list: String = cb.get(56..60).map(|b| b.iter().map(|x| format!("{x:02x}")).collect()).unwrap_or_default();
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
                    println!(
                        "    Supply check: visible {visible} + pool {pool_balance} + burned {total_burned} + private {private} = {} | issued {issued} zets | {} | coin list {coin_list}",
                        visible as u128 + pool_balance as u128 + total_burned as u128 + private as u128,
                        if balanced { "BALANCED" } else { "MISMATCH" }
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