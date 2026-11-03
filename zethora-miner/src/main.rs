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
//!   zethora-miner --shielded <zs...>  pay rewards to a private (Orchard) address instead of the key's address
//!   zethora-miner bench       RandomZ speed test; no node needed, stop the real miner first
//!
//! Key files: zethora-miner-key.txt (devnet) and zethora-miner-key-testnet.txt (testnet).
//! Keys are never shared between networks.
//!
//! Pillar 2 (shielded coinbase): a `zs...` address is accepted, and its bytes are put into the coinbase the miner
//! asks the node for, but the node does not route the reward into the private pool yet (that is a consensus change,
//! tracked separately). Until then a shielded run still credits the key's ordinary address and says so on screen.

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

/// Seam review P4-10: reads a key file's 64 hex characters, with a clear error instead of a crash on a short or damaged
/// file.
fn parse_key_hex(text: &str) -> Result<SecretKey, String> {
    let hex = text.trim();
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("expected 64 hex characters, found {} characters", hex.len()));
    }
    let bytes: Vec<u8> = (0..64).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("checked hex")).collect();
    SecretKey::from_slice(&bytes).map_err(|e| format!("not a valid secret key ({e})"))
}

fn load_or_create_key(key_file: &str) -> Keypair {
    if let Ok(text) = std::fs::read_to_string(key_file) {
        match parse_key_hex(&text) {
            Ok(sk) => return Keypair::from_secret_key(SECP256K1, &sk),
            Err(e) => {
                eprintln!("The mining key file {key_file} is damaged: {e}.");
                eprintln!("It holds the key to your mined coins, so the miner will not replace it. Restore it from a backup.");
                std::process::exit(5);
            }
        }
    }
    let kp = Keypair::new(SECP256K1, &mut secp256k1::rand::thread_rng());
    let hex: String = kp.secret_key().secret_bytes().iter().map(|b| format!("{b:02x}")).collect();
    write_private_file(key_file, &hex).unwrap_or_else(|e| {
        eprintln!("Cannot write the key file {key_file}: {e}");
        std::process::exit(5);
    });
    println!("Created new mining key in {key_file}");
    kp
}

/// Seam review P4-10: creates the key file readable by its owner only (Unix mode 0600; on Windows the file gets the
/// folder's permissions, which for a folder under the user's profile means that user only). Never overwrites a file.
fn write_private_file(path: &str, contents: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(contents.as_bytes())
}

// --- Pillar 2: shielded coinbase addresses ---

/// First bytes of the miner tag in the coinbase payload when the reward goes to a private address:
/// `SHD1`, then the private pool version (ZTH-SPEC-006 §7.4), then the raw Orchard address.
const SHIELDED_TAG_PREFIX: [u8; 4] = *b"SHD1";
const SHIELDED_POOL_ORCHARD1: u8 = 1;
/// An Orchard address is a diversifier (11 bytes) plus a diversified transmission key (32 bytes).
const ORCHARD_ADDRESS_LEN: usize = 43;
/// A `zs...` string longer than this cannot be an Orchard address, so a stray word is never mined to.
const MAX_SHIELDED_ALIAS_LEN: usize = 256;
/// Characters of a private address shown in the startup banner (the rest would only add noise on screen).
const SHIELDED_ADDRESS_SHOWN: usize = 26;

/// The `zs...` aliases this miner accepts. `zs1...` is Zcash's own form; `zs...` is the native form in
/// docs/ARCHITECTURE.md. In both, everything after the alias is the address itself. This miner, not the address
/// crate, owns these names, so nothing here touches consensus. The longest alias comes first, so a `zs1...` text is
/// never read as `zs` followed by a payload starting with `1`.
fn shielded_addresses() -> [&'static str; 2] {
    ["zs1", "zs"]
}

/// The raw Orchard address bytes behind a `zs...` address.
///
/// Returns `None` when the text is not an Orchard address, so the caller can refuse it instead of crediting a
/// damaged string. The text is read exactly the way the address crate writes a `zethoratest:` address: 5-bit
/// groups, a one-byte version and an 8-character (40-bit) checksum. For a private address the version is
/// `ORCHARD_ADDRESS_LEN`, so a typed `zs...` string is checked even though the alias is not a network prefix.
/// The 5-bit encoding gives the last data group 2 spare bits; they must be zero, otherwise two different strings
/// would mean the same address and a typo could pass unnoticed.
fn payload_from_shielded_address(text: &str) -> Option<[u8; ORCHARD_ADDRESS_LEN]> {
    const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    const CHECKSUM_CHARS: usize = 8;

    /// Bech32's 5-bit checksum, the same one the address crate uses.
    fn polymod(chars: &[u8]) -> u32 {
        const GEN: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
        let mut c: u32 = 1;
        for &ch in chars {
            let top = c >> 25;
            c = ((c & 0x1ff_ffff) << 5) ^ u32::from(ch);
            for (i, g) in GEN.iter().enumerate() {
                if (top >> i) & 1 == 1 {
                    c ^= g;
                }
            }
        }
        c
    }

    // A `zs` address is mostly lowercase; an uppercase spelling is accepted the way the address crate accepts it.
    let lowered = text.to_ascii_lowercase();
    let (alias, rest) = shielded_addresses().into_iter().find_map(|alias| {
        let rest = lowered.strip_prefix(alias)?;
        (rest.len() <= MAX_SHIELDED_ALIAS_LEN).then_some((alias, rest))
    })?;

    let mut groups = Vec::with_capacity(rest.len());
    for ch in rest.bytes() {
        groups.push(CHARSET.iter().position(|&c| c == ch)? as u8);
    }
    let (payload_groups, _checksum) = groups.split_at(groups.len().checked_sub(CHECKSUM_CHARS)?);

    let mut checksum_input: Vec<u8> = alias.as_bytes().iter().map(|c| c & 0x1f).collect();
    checksum_input.extend_from_slice(&groups);
    // A checksum of 1 is bech32; anything else is bech32m, which marks a payload that was upgraded exactly
    // because the old encoding was ambiguous. A miner must never guess between the two.
    if polymod(&checksum_input) != 1 {
        return None;
    }

    let mut bytes = Vec::with_capacity(payload_groups.len() * 5 / 8 + 1);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &group in payload_groups {
        acc = (acc << 5) | u32::from(group);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            bytes.push((acc >> bits) as u8);
        }
    }
    // Leftover bits must be zero padding, or the string is not a canonical address.
    if bits >= 5 || (acc & ((1 << bits) - 1)) != 0 {
        return None;
    }

    let (version, payload) = bytes.split_first()?;
    if usize::from(*version) != ORCHARD_ADDRESS_LEN {
        return None;
    }
    payload.try_into().ok()
}

/// A 32-byte commitment to a private address, for the `zethoratest:` address the node insists on. The private
/// address itself travels in the coinbase tag (miner extra data), never in this transparent anchor.
fn shielded_reward_anchor(address: &[u8; ORCHARD_ADDRESS_LEN]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"ZethoraShieldCb1")
        .to_state()
        .update(address)
        .finalize();
    hash.as_bytes().try_into().expect("32-byte hash")
}

/// Where this run's rewards go, and what the miner asks the node for.
struct RewardRoute {
    /// The `zethoratest:` address sent to the node: the key's own address, or the commitment to a private one.
    pay_address: Address,
    /// Miner tag (`extra_data`) the node copies into the coinbase payload.
    coinbase_tag: Vec<u8>,
    /// Printed at startup, so the screen never suggests a privacy that is not there yet.
    banner: Vec<String>,
    /// The private address being mined to, when there is one.
    shielded: Option<[u8; ORCHARD_ADDRESS_LEN]>,
}

/// Builds the reward route. `shielded` is the parsed `--shielded` address, if any.
fn reward_route(key_address: Address, network: NetworkType, shielded: Option<[u8; ORCHARD_ADDRESS_LEN]>) -> RewardRoute {
    let mut banner = vec![format!("Paying rewards to: {key_address}")];
    let Some(private) = shielded else {
        return RewardRoute { pay_address: key_address, coinbase_tag: b"zethora-miner".to_vec(), banner, shielded: None };
    };
    let shown: String = private.iter().take(SHIELDED_ADDRESS_SHOWN).map(|b| format!("{b:02x}")).collect();
    banner.push("Mining to shielded address (Note: privacy is currently disabled on the network)".to_string());
    banner.push(format!("                  {shown}... ({} bytes; the whole address goes into the coinbase)", private.len()));
    banner.push(
        "                  The node still credits the key file's address above until the shielded-coinbase \
         consensus change lands."
            .to_string(),
    );
    let mut coinbase_tag = Vec::with_capacity(SHIELDED_TAG_PREFIX.len() + 1 + ORCHARD_ADDRESS_LEN);
    coinbase_tag.extend_from_slice(&SHIELDED_TAG_PREFIX);
    coinbase_tag.push(SHIELDED_POOL_ORCHARD1);
    coinbase_tag.extend_from_slice(&private);
    let pay_address = Address::new(Prefix::from(network), Version::PubKey, &shielded_reward_anchor(&private));
    RewardRoute { pay_address, coinbase_tag, banner, shielded: Some(private) }
}

/// The shielded tag a node actually sealed into a coinbase payload, if any.
///
/// The node writes the payload as `blue-score(8) | subsidy(8) | pool(40) | note root(32) | private state(32) |
/// script-public-key version(2) | script-public-key length(1) | script public key | miner tag`
/// (consensus/src/processes/coinbase.rs), with the node's own version string at the start of the miner tag. The tag is
/// found by its `SHD1` first bytes instead of a fixed offset, so a node that adds fields to the payload only moves the
/// window. Searching the bytes, rather than trusting the length byte to find the window, is also what keeps this side
/// honest about a payload whose declared script length does not match the script it carries: the miner still reads the
/// tag it asked the node for.
fn coinbase_shielded_tag(payload: &[u8]) -> Option<Vec<u8>> {
    let start = payload.windows(SHIELDED_TAG_PREFIX.len()).position(|w| w == SHIELDED_TAG_PREFIX)?;
    // The pool byte must be one this miner understands; other versions are a different format, not a typo.
    if payload.get(start + SHIELDED_TAG_PREFIX.len()).copied() != Some(SHIELDED_POOL_ORCHARD1) {
        return None;
    }
    let span = SHIELDED_TAG_PREFIX.len() + 1 + ORCHARD_ADDRESS_LEN;
    payload.get(start..start + span).map(<[u8]>::to_vec)
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
    let usage = "Usage:\n  zethora-miner             devnet (node: --devnet --enable-unsynced-mining)\n  zethora-miner --testnet   testnet (node: --testnet --enable-unsynced-mining)\n  zethora-miner --shielded <zs...>   devnet, paying rewards to a private address\n  zethora-miner --testnet --shielded <zs...>   testnet, paying rewards to a private address\n  zethora-miner bench       RandomZ speed test (no node)\n  zethora-miner balance     devnet balance of your transparent mining address (node needs --utxoindex)\n  zethora-miner --testnet balance   testnet balance (node needs --testnet --utxoindex)";
    #[derive(PartialEq)]
    enum Mode {
        Mine,
        Bench,
        Balance,
    }
    // `--shielded <address>` may sit before or after `--testnet`; everything else must match exactly.
    let mut rest: Vec<&str> = Vec::with_capacity(args.len());
    let mut shielded_arg: Option<String> = None;
    let mut remaining = args.iter().map(String::as_str);
    while let Some(arg) = remaining.next() {
        match arg {
            "--shielded" => shielded_arg = remaining.next().map(str::to_string),
            _ if arg.starts_with("--shielded=") => shielded_arg = Some(arg["--shielded=".len()..].to_string()),
            _ => rest.push(arg),
        }
    }
    // Exit codes: usage and a private address the miner cannot read are both "the caller asked for something the
    // tool does not do", so they share code 2, exactly as every other bad argument does today.
    let usage_or_exit = |problem: Option<String>| {
        if let Some(problem) = problem {
            eprintln!("{problem}");
        }
        eprintln!("{usage}");
        std::process::exit(2);
    };
    if shielded_arg.is_none() && args.iter().any(|a| a.starts_with("--shielded")) {
        usage_or_exit(Some("--shielded needs a private address after it, for example: zethora-miner --shielded zs...".into()));
    }
    let shielded = match shielded_arg {
        None => None,
        Some(text) => match payload_from_shielded_address(text.trim()) {
            Some(bytes) => Some(bytes),
            None => usage_or_exit(Some(format!(
                "That is not a readable private address: \"{text}\". A private address starts with zs... (or zs1...) \
                 and carries an Orchard address. Check for a missing or extra character and try again."
            ))),
        },
    };
    let (testnet, mode) = match rest.as_slice() {
        [] => (false, Mode::Mine),
        ["--testnet"] => (true, Mode::Mine),
        ["bench"] => (false, Mode::Bench),
        ["balance"] => (false, Mode::Balance),
        ["--testnet", "balance"] => (true, Mode::Balance),
                _ => {
            usage_or_exit(None);
            (false, Mode::Mine) // unreachable, satisfies the compiler
        }
    };
    // `balance` asks the node for the coins of a transparent address; a private balance needs the private wallet,
    // which the miner does not carry. Refuse before touching the node or the key file.
    if mode == Mode::Balance && shielded.is_some() {
        eprintln!(
            "balance works on a transparent (zethoratest:) address, so it cannot be combined with --shielded. \
             A private balance is read with the private wallet tools."
        );
        std::process::exit(2);
    }
    if mode == Mode::Bench {
        return tokio::task::spawn_blocking(bench).await.expect("speed test");
    }
    let network = if testnet { NetworkType::Testnet } else { NetworkType::Devnet };
    let node_url = if testnet { TESTNET_NODE_URL } else { DEVNET_NODE_URL };
    let key_file = if testnet { TESTNET_KEY_FILE } else { DEVNET_KEY_FILE };
    let network_name = if testnet { "testnet" } else { "devnet" };
    // G13: never create a key just to show a balance
    if mode == Mode::Balance && !std::path::Path::new(key_file).exists() {
        eprintln!("No mining key yet ({key_file} not found in this folder). Start mining first, then check the balance.");
        std::process::exit(4);
    }
    let kp = load_or_create_key(key_file);
    let address = Address::new(Prefix::from(network), Version::PubKey, &kp.x_only_public_key().0.serialize());
    // Pillar 2: with `--shielded` the coinbase carries the private address instead of the key's own.
    let route = reward_route(address.clone(), network, shielded);
    println!("Zethora {network_name} miner");
    println!("Network:  {network_name}");
    println!("Key file: {key_file}");
    println!("Node URL: {node_url}");
    for line in &route.banner {
        println!("{line}");
    }
    // Defensive check: refuse to mine if the address prefix does not match the network.
    let addr_str = route.pay_address.to_string();
    let expected_prefix = if testnet { "zethoratest:" } else { "zethoradev:" };
    if !addr_str.starts_with(expected_prefix) {
        eprintln!(
            "BUG: {network_name} address does not start with {expected_prefix} (got {addr_str}). Exiting to avoid paying to the wrong network."
        );
        std::process::exit(3);
    }

    let client = GrpcClient::connect(node_url.to_string())
        .await
        .expect("Cannot reach the node. Is it running with the matching network flag (--devnet or --testnet)?");
    // G13: show the balance of the mining address and exit
    if mode == Mode::Balance {
        match client.get_balance_by_address(address.clone()).await {
            Ok(zets) => {
                println!("Balance: {:.10} ZTHR ({zets} zets)", zets as f64 / ZETS_PER_ZTHR);
                println!("(New mining rewards show up after the next block and can be spent only after they mature.)");
            }
            Err(e) => {
                eprintln!("Could not read the balance: {e}");
                eprintln!("Start the node with --utxoindex (it keeps the address index that balances need).");
                std::process::exit(4);
            }
        }
        return;
    }
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

    let mut warned_unsynced: Option<Instant> = None;
    let mut warned_shielded_route = false;
    loop {
        let template = match client.get_block_template(route.pay_address.clone(), route.coinbase_tag.clone()).await {
            Ok(t) => t,
            Err(e) => {
                println!("Waiting for node: {e}");
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
        };
        // Pillar 2: the private address now travels in the coinbase the node builds. Saying it once, next to the
        // block we actually asked for, keeps the screen honest: the node still pays the transparent address.
        if route.shielded.is_some() && !warned_shielded_route {
            let seal = coinbase_shielded_tag(&template.block.transactions[0].payload);
            match seal {
                Some(tag) if tag == route.coinbase_tag => println!(
                    "Coinbase carries the shielded address ({} bytes of miner tag). The reward is still credited to \
                     {addr_str}.",
                    tag.len()
                ),
                _ => println!(
                    "Note: this node does not put the shielded address into the coinbase (shielded coinbase is not \
                     implemented in consensus yet), so the reward stays with {addr_str}."
                ),
            }
            warned_shielded_route = true;
        }
        // Seam review P4-10: say so when the node is not synced (mining then builds on a chain that may be stale). The
        // miner still mines: a brand-new network starts "not synced" until its first blocks, and refusing would stall it.
        if !template.is_synced && warned_unsynced.is_none_or(|t| t.elapsed() > Duration::from_secs(60)) {
            println!("Warning: the node says it is not synced; blocks mined now may build on an old chain.");
            warned_unsynced = Some(Instant::now());
        }
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
        if let Some(task) = &prebuild_task
            && task.is_finished()
        {
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
            // This block's subsidy for its DAA score (ZTH-SPEC-001 §5), as the node computed it and sealed it in the
            // coinbase payload (bytes 8..16); seam review P5-7: no separate (capped) walk in the miner.
            let reward = read(8);
            let balanced = visible as u128 + pool_balance as u128 + total_burned as u128 + private as u128 == issued as u128;
            // Private coin list fingerprint (bytes 56..88): first 4 bytes are enough to see it change
            let coin_list: String = cb.get(56..60).map(|b| b.iter().map(|x| format!("{x:02x}")).collect()).unwrap_or_default();
            match client.submit_block(block, false).await {
                Ok(r) if r.report.is_success() => {
                    mined += 1;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Seam review P4-10: a damaged key file gives an error, not a crash; a good one still loads.
    #[test]
    fn key_files_are_parsed_without_panicking() {
        let good = "11".repeat(32);
        assert!(parse_key_hex(&good).is_ok());
        assert!(parse_key_hex(&format!("  {good}\n")).is_ok());
        assert!(parse_key_hex("").is_err());
        assert!(parse_key_hex("abc").is_err());
        assert!(parse_key_hex(&"1".repeat(63)).is_err());
        assert!(parse_key_hex(&format!("{}zz", "1".repeat(62))).is_err());
        // Multi-byte characters must not panic the slicing either
        assert!(parse_key_hex(&"é".repeat(32)).is_err());
        // All zeros is not a valid secp256k1 key
        assert!(parse_key_hex(&"0".repeat(64)).is_err());
    }

    /// Seam review P4-10: the key file is created owner-only and never overwritten.
    #[test]
    fn key_file_is_private_and_never_overwritten() {
        let dir = std::env::temp_dir().join(format!("zethora-miner-key-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("key.txt");
        let path = path.to_str().unwrap();
        let _ = std::fs::remove_file(path);
        write_private_file(path, "first").unwrap();
        assert!(write_private_file(path, "second").is_err());
        assert_eq!(std::fs::read_to_string(path).unwrap(), "first");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
