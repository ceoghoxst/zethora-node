//! The L1 → L2 treasury relayer: who mined, and how much of the L2 fee pool is theirs.
//!
//! `ZefTreasury` pays the L2 fee slice out by *weight*, and states in its own
//! documentation that the only writer of a weight is
//! `oracleUpdateShares(address[] miners_, uint256[] shares_)`, callable by the
//! contract owner — "the L1 relayer, in practice a multisig". This binary is that
//! relayer: it reads Zethora L1, works out which accounts mined the blocks, and
//! publishes the weights the treasury distributes by.
//!
//! # What it reads on L1
//!
//! Only the coinbase. A block's coinbase transaction is the one whose
//! `subnetwork_id` is [`SUBNETWORK_ID_COINBASE`]; its outputs pay the block
//! producer, so the coinbase outputs of a window of blocks are exactly the record
//! of who mined what. Nothing else on L1 is consulted: no UTXO set, no mempool, no
//! address index, so the relayer works against a node started with no extra flags.
//!
//! The window is the last `--window` blocks (60 by default) ending at the node's
//! sink. A rolling window, not a running total, is what a *weight* wants: the
//! treasury replaces the whole set of weights on every call, so re-reporting the
//! last N blocks keeps the split proportional to recent work and lets a miner who
//! stopped mining decay out of the set without anybody having to track history.
//!
//! # What it writes on L2
//!
//! One `oracleUpdateShares` call per pass, carrying the same weights the window
//! implies. The unit is *sompi of coinbase reward*, summed per miner over the
//! window: `ZefTreasury` divides its balance by `totalShares` and multiplies by
//! each weight, so only the ratios matter and no unit conversion (and no rounding)
//! is needed on this side.
//!
//! An address has to be *registered* before it can carry a weight — the contract
//! reverts `NotRegistered` otherwise — so the relayer also sends one permissionless
//! `registerMiner(address)` for each miner it has not registered in this process.
//! `registerMiner` reverts `AlreadyRegistered` for an address that is already in
//! the set, which is indistinguishable from any other revert without an `eth_call`
//! this node does not offer; it is therefore treated as success, because the
//! outcome it stands for ("this miner is registered") is the outcome the relayer
//! wanted. If the `oracleUpdateShares` call itself reverts, the relayer forgets
//! what it believed about registration and re-registers everything next pass,
//! which is what repairs it after the L2 node's state is wiped.
//!
//! # Which L2 address a miner gets
//!
//! A `zethoradev:`/`zethoratest:` address is a 32-byte x-only public key (or a
//! script hash), not a 20-byte EVM address, and the treasury only handles the
//! latter. The relayer derives it the way Ethereum derives an address from a key,
//! so that *the same secret key owns the L1 and the L2 identity*:
//!
//! * a pay-to-pub-key coinbase output (`OP_DATA_32 <x-only key> OP_CHECKSIG`, the
//!   script a `zethora-miner` builds from `--address`) is lifted to the full
//!   secp256k1 point with even `y` — the parity BIP-340 fixes for an x-only key —
//!   and hashed as `keccak256(x || y)[12..]`, the Ethereum address of that key;
//! * a pay-to-pub-key output carrying a 33-byte compressed key is read as that
//!   point directly;
//! * anything else (pay-to-script-hash, bare data, a non-zero script version) is
//!   *skipped and counted*, never invented: a weight paid to an address nobody
//!   holds the key for is unrecoverable, and the contract says so.
//!
//! Because an x-only key does not record the parity it was serialised from, the
//! even-`y` convention is the whole rule: a miner whose key produces an odd-`y`
//! public key would map to the address of its negation. Such a key can be
//! normalised (`d := n - d`) before it is ever used, and `--dry-run` prints the
//! mapping so the operator can check it against the miner's own wallet first.
//!
//! # Trust and failure model
//!
//! * L1 is read, never written; a relayer holding the treasury's owner key cannot
//!   spend an L1 coin that way.
//! * Every pass is independent. A failed pass (L1 down, L2 refusing, a reorg under
//!   the window) is logged and the loop tries again; nothing is queued, so a
//!   stalled relayer publishes a *stale window*, never a wrong one.
//! * `--once` runs one pass and exits, for a cron job or a smoke test; `--dry-run`
//!   signs and sends nothing and prints the calldata instead.
//! * The transaction hash returned by `eth_sendRawTransaction` is not taken as
//!   success: the receipt of that hash is read and its `status` is what decides,
//!   because this L2 seals a reverted transaction just like a successful one.
//! * A call to an address that holds no code *succeeds* on an EVM and does
//!   nothing, and this L2 offers no `eth_getCode` to check first. Pointing
//!   `--treasury` at a wrong or undeployed address therefore looks exactly like a
//!   successful pass, so the first `weights published` line is worth confirming
//!   against the contract itself.
//!
//! # Usage
//!
//! ```text
//! zethora-relayer --treasury 0x1111...1111 --key 0xabc...   # reads ZETHORA_RELAYER_KEY if --key is absent
//! ```

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy_consensus::{SignableTransaction, Signed, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, B256, Bytes, TxKind, U256, hex, keccak256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{SolCall, sol};
use kaspa_consensus_core::subnets::SUBNETWORK_ID_COINBASE;
use kaspa_consensus_core::tx::ScriptPublicKey;
use kaspa_grpc_client::GrpcClient;
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_rpc_core::{RpcBlock, RpcHash};
use secp256k1::PublicKey;
use serde_json::{Value, json};

// The two calls this binary makes on the treasury.
//
// Declared as free functions rather than an `interface` block because the binary
// needs the ABI, not a typed contract handle: it builds the calldata itself and
// posts it with `eth_sendRawTransaction`, so the selector and the argument
// encoding are the only artefacts it uses from here.
sol! {
    // Adds `l1MinerAddress` to the treasury's miner set. Permissionless; the
    // contract reverts `AlreadyRegistered` if it is already in the set.
    function registerMiner(address l1MinerAddress) external;

    // Replaces the yield weight of every address in `miners` with the matching
    // entry of `shares`. Owner-only, index-aligned, all-or-nothing.
    function oracleUpdateShares(address[] miners, uint256[] shares) external;
}

/// The L1 gRPC endpoint of the devnet node, which is the one the miner in this
/// crate talks to by default.
const L1_URL: &str = "grpc://127.0.0.1:26210";

/// The L2 JSON-RPC endpoint, i.e. `zethora-rpc-l2`'s default port.
const L2_URL: &str = "http://127.0.0.1:8545";

/// Where the relayer key is read from when `--key` is not given.
///
/// An environment variable rather than a file on purpose: the key is the treasury
/// owner's, and a file next to the binary is the way it ends up in a backup or a
/// container image. `--key` still exists for a one-off run.
const KEY_ENV: &str = "ZETHORA_RELAYER_KEY";

/// Blocks per window. One hour of devnet blocks at the miner's ~15 s cadence.
const DEFAULT_WINDOW: usize = 60;

/// The largest window worth asking for.
///
/// `get_blocks` answers with at most `mergeset_size_limit + 1` blocks (about a
/// thousand on every network this node runs), so a larger window would silently
/// be truncated to that and the totals would stop matching the flag.
const MAX_WINDOW: usize = 1_000;

/// Seconds between passes. One L2 block is sealed per accepted transaction, and a
/// fee slice only accrues when somebody transacts, so a sub-minute cadence keeps
/// the weights fresh without publishing empty windows.
const DEFAULT_INTERVAL: u64 = 15;

/// Gas limit used if `eth_estimateGas` cannot be asked (the node reports its whole
/// block budget anyway, which no accepted transaction can exceed).
const FALLBACK_GAS_LIMIT: u64 = 30_000_000;

const USAGE: &str = "Usage:
  zethora-relayer --treasury <0x...> [--key <0x...>] [options]

Publishes the L1 mining weights of the last --window blocks to the L2 treasury
(ZefTreasury.oracleUpdateShares), registering newly seen miners on the way.

  --treasury <address>   the ZefTreasury contract on the L2 (required)
  --key <0x...>          32-byte secp256k1 key of the treasury owner
                         (default: the ZETHORA_RELAYER_KEY environment variable)
  --l1 <url>             L1 gRPC endpoint (default: grpc://127.0.0.1:26210)
  --l2 <url>             L2 JSON-RPC endpoint (default: http://127.0.0.1:8545)
  --window <blocks>      blocks per pass, 1..=1000 (default: 60)
  --interval <seconds>   seconds between passes (default: 15)
  --once                 run one pass and exit
  --dry-run              print the weights and the calldata, sign nothing
  --help                 this text";

// ---------------------------------------------------------------------------
// The relayer loop
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let config = match Config::parse(std::env::args().skip(1).collect()) {
        Ok(Some(config)) => config,
        // `--help` asked for the text and got it; that run succeeded.
        Ok(None) => return,
        Err(problem) => fail(&format!("{problem}\n\n{USAGE}")),
    };

    let signer = match PrivateKeySigner::from_bytes(&config.key) {
        Ok(signer) => signer,
        Err(error) => fail(&format!("the relayer key is not a secp256k1 private key: {error}")),
    };

    let l1 = match GrpcClient::connect(config.l1_url.clone()).await {
        Ok(l1) => l1,
        Err(error) => fail(&format!(
            "cannot reach the L1 node at {} ({error}). Is zethorad running, and does --l1 name its gRPC port?",
            config.l1_url
        )),
    };

    // One connection pool for the whole run: every pass is a handful of small
    // JSON-RPC posts, and a fresh client per call would re-dial the node each time.
    let http = match reqwest::Client::builder().timeout(Duration::from_secs(30)).build() {
        Ok(http) => http,
        Err(error) => fail(&format!("cannot build the HTTP client for the L2: {error}")),
    };

    let mut l2 = L2::new(http, config.l2_url.clone(), signer, config.treasury);
    if let Err(problem) = l2.discover().await {
        fail(&format!("the L2 node at {} is not usable: {problem}", config.l2_url));
    }

    println!("Zethora L1 -> L2 treasury relayer");
    println!("  L1 node    {}", config.l1_url);
    println!("  L2 node    {} (chain id {})", config.l2_url, l2.chain_id());
    println!("  treasury   {}", config.treasury);
    println!("  relayer    {} ({})", l2.signer_address(), config.key_source);
    println!("  window     {} block(s), a pass every {}s", config.window, config.interval.as_secs());
    if l2.gas_price() == 0 {
        println!("  gas        the L2 charges nothing per gas, so the relayer needs no balance");
    } else {
        println!("  gas        {} wei per gas, gas limit {}", l2.gas_price(), l2.gas_limit());
    }
    if config.dry_run {
        println!("  mode       dry run: nothing is signed or sent");
    }

    let mut state = State::default();
    loop {
        if let Err(problem) = relay_once(&l1, &l2, &config, &mut state).await {
            eprintln!("[{}] pass failed: {problem}", timestamp());
        }
        if config.once {
            return;
        }
        tokio::time::sleep(config.interval).await;
    }
}

/// Prints `message` and exits non-zero: every startup problem is terminal,
/// because a relayer that cannot read L1 or reach L2 has nothing to wait for.
fn fail(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(1)
}

/// One block's coinbase payouts, kept so the rolling window can drop it again.
struct MinedBlock {
    hash: RpcHash,
    /// Every coinbase output that names a miner key, as `(L2 account, sompi)`.
    payouts: Vec<(Address, u64)>,
    /// Coinbase outputs in this block that name no key this relayer can derive.
    ignored: u32,
}

/// What one pass learns that the next pass can build on.
#[derive(Default)]
struct State {
    /// The sink of the previous pass, i.e. the block the next pass must start
    /// reading from. `None` until the first pass has filled the window.
    cursor: Option<RpcHash>,
    /// The window: one entry per block, oldest first, at most `--window` long.
    history: VecDeque<MinedBlock>,
    /// Miners this process has registered. Cleared when a weight update is
    /// refused, because that refusal is the only evidence available here that
    /// the treasury does not know an address it is supposed to.
    registered: HashSet<Address>,
    /// Whether the weights currently in `history` are known to be published.
    /// False after a failed pass, so a chain that stops producing blocks cannot
    /// leave a refusal unpublished forever.
    published: bool,
}

/// The wall clock as `HH:MM:SS` in UTC, for log lines.
///
/// Seconds since the epoch are the only clock the standard library offers, and
/// a date would need a calendar crate; a time of day is enough to correlate a
/// relayer line with a node's own log.
fn timestamp() -> String {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH).map(|since| since.as_secs()).unwrap_or_default();
    let since_midnight = seconds % 86_400;
    format!("{:02}:{:02}:{:02}", since_midnight / 3_600, (since_midnight % 3_600) / 60, since_midnight % 60)
}

/// One pass: read what L1 mined since the last pass, then tell L2 about it.
async fn relay_once(l1: &GrpcClient, l2: &L2, config: &Config, state: &mut State) -> Result<(), String> {
    let sink = l1.get_sink().await.map_err(|error| format!("cannot read the L1 sink: {error}"))?.sink;
    let start = match state.cursor {
        Some(cursor) => cursor,
        // First pass: walk a window's worth of selected parents so the first
        // window is the same size as every later one, instead of growing into
        // shape over the first `--window` passes.
        None => window_low(l1, sink, config.window).await?,
    };

    let fetched = blocks_from(l1, start).await?;
    let mut fresh = 0;
    for block in &fetched {
        // `get_blocks` returns `start` itself, and after the first pass `start`
        // is the previous sink, whose coinbase is already in the history.
        // Counting it twice would double that miner's weight for as long as the
        // block stays in the window.
        if state.history.back().is_some_and(|last| last.hash == block.header.hash) {
            continue;
        }
        let (payouts, ignored) = coinbase_payouts(block);
        state.history.push_back(MinedBlock { hash: block.header.hash, payouts, ignored });
        fresh += 1;
    }
    while state.history.len() > config.window {
        state.history.pop_front();
    }
    state.cursor = Some(sink);

    let (weights, ignored) = window_weights(&state.history);
    let mut line = format!(
        "[{}] L1 {}: {} new block(s), window of {}, {} miner(s)",
        timestamp(),
        sink,
        fresh,
        state.history.len(),
        weights.len()
    );
    if ignored > 0 {
        line.push_str(&format!(", {ignored} coinbase output(s) naming no miner key"));
    }
    println!("{line}");

    if weights.is_empty() {
        println!("  no coinbase output in the window names a miner key; nothing to publish");
        return Ok(());
    }
    if fresh == 0 && state.published {
        println!("  no new block since the last pass; the published weights still hold");
        return Ok(());
    }

    publish(l2, config, state, &weights).await
}

/// Registers whichever miners are new and then publishes `weights`.
///
/// Registration first is not optional: `oracleUpdateShares` is all-or-nothing and
/// reverts `NotRegistered` if a single address in it is unknown to the treasury,
/// so an unregistered miner would otherwise block every other miner's update.
async fn publish(l2: &L2, config: &Config, state: &mut State, weights: &BTreeMap<Address, U256>) -> Result<(), String> {
    for miner in weights.keys() {
        if state.registered.contains(miner) {
            continue;
        }
        if config.dry_run {
            println!("  would register {miner}");
            continue;
        }
        let calldata = registerMinerCall { l1MinerAddress: *miner }.abi_encode();
        match l2.send(config.treasury, calldata).await {
            Ok(hash) => match l2.sealed(hash).await {
                Ok(sealed) => {
                    if sealed {
                        println!("  registered {miner} in {hash}");
                    } else {
                        // `AlreadyRegistered`: the miner is in the set, which is
                        // what the relayer wanted. The revert is indistinguishable
                        // from any other without `eth_call`, and the weight update
                        // that follows is the real test of whether it went in.
                        println!("  {miner} is already registered ({hash})");
                    }
                    state.registered.insert(*miner);
                }
                Err(problem) => eprintln!("  registering {miner}: {problem}"),
            },
            Err(problem) => eprintln!("  registering {miner}: {problem}"),
        }
    }

    let miners: Vec<Address> = weights.keys().copied().collect();
    let shares: Vec<U256> = weights.values().copied().collect();
    let total = shares.iter().copied().fold(U256::ZERO, |sum, share| sum + share);
    let calldata = oracleUpdateSharesCall { miners: miners.clone(), shares }.abi_encode();

    if config.dry_run {
        println!("  would publish {} miner(s) worth {total} sompi of coinbase reward", miners.len());
        println!("  oracleUpdateShares calldata: 0x{}", hex::encode(&calldata));
        return Ok(());
    }

    let hash = l2.send(config.treasury, calldata).await?;
    if !l2.sealed(hash).await? {
        // At least one miner in this update is not registered, and this node's
        // reverts carry no reason string to say which. Forget every registration
        // so the next pass registers them all again: that is what repairs the set
        // after the L2 state was wiped under a running relayer.
        state.registered.clear();
        state.published = false;
        return Err(format!(
            "the treasury rejected the weight update in {hash}; every miner will be registered again on the next pass"
        ));
    }

    println!("  weights published in {hash}: {} miner(s), {total} sompi of coinbase reward", miners.len());
    state.published = true;
    Ok(())
}

// ---------------------------------------------------------------------------
// Reading L1
// ---------------------------------------------------------------------------

/// Newest first push of a 32-byte key, i.e. `OpData32`. The value is pinned by a
/// test against the txscript crate rather than being taken on faith here; it is a
/// consensus constant, so it cannot change without changing the chain.
const OP_DATA_32: u8 = 0x20;

/// Push of a 33-byte compressed key, i.e. `OpData33`.
const OP_DATA_33: u8 = 0x21;

/// `OpCheckSig`: the schnorr verifier closing a pay-to-pub-key script.
const OP_CHECK_SIG: u8 = 0xac;

/// `OpCheckSigECDSA`: the ECDSA verifier closing a pay-to-pub-key-ecdsa script.
const OP_CHECK_SIG_ECDSA: u8 = 0xab;

/// How far back the first pass reaches, so that the first window is already full
/// instead of growing into shape over the first `--window` passes.
async fn window_low(l1: &GrpcClient, sink: RpcHash, window: usize) -> Result<RpcHash, String> {
    let mut low = sink;
    for _ in 1..window {
        // One block at a time, because the only way back from a hash is
        // `verbose_data.selected_parent_hash`: this node answers `get_headers`
        // with `NotImplemented`, and `get_blocks` only walks forwards from a hash
        // the caller already holds. A window of local blocks is a few round trips.
        let Ok(block) = l1.get_block(low, false).await else {
            // The walk reached the pruning point, or the node dropped the call.
            // Either way what has been walked so far is a usable window, and the
            // pass reports the range it actually reads.
            break;
        };
        let Some(data) = block.verbose_data else { break };
        if data.selected_parent_hash == low || data.blue_score == 0 {
            // The genesis block is its own selected parent: the chain is shorter
            // than the window and there is nothing further back to reach.
            break;
        }
        low = data.selected_parent_hash;
    }
    Ok(low)
}

/// The selected-chain blocks from `low` up to the sink, bodies included.
async fn blocks_from(l1: &GrpcClient, low: RpcHash) -> Result<Vec<RpcBlock>, String> {
    let mut blocks =
        l1.get_blocks(Some(low), true, true).await.map_err(|error| format!("cannot read blocks from {low}: {error}"))?.blocks;

    // `get_blocks` appends the sink's anticone: blocks that are tips and not on the
    // selected chain. Their coinbase is not what the chain settled, and the chain
    // reaches them later, so counting them now would count them twice. Only
    // selected-chain blocks are kept.
    blocks.retain(|block| block.verbose_data.as_ref().is_some_and(|data| data.is_chain_block));

    // `get_blocks` answers with at most `mergeset_size_limit + 1` blocks however
    // wide the range is, and then silently drops the middle of it: the first entry
    // is `low` and the rest are the newest blocks. Keep `low` only if it really is
    // the parent of the block after it, so that a long catch-up cannot glue two
    // unrelated ends of the chain into one window.
    if blocks.len() > 1 && !blocks[1].header.direct_parents().contains(&low) {
        blocks.remove(0);
    }
    Ok(blocks)
}

/// The coinbase payouts of one block: `(L2 account, sompi)` per output that names
/// a miner key, plus the number of outputs that name none.
fn coinbase_payouts(block: &RpcBlock) -> (Vec<(Address, u64)>, u32) {
    let mut payouts = Vec::new();
    let mut ignored = 0;

    // The coinbase is the first transaction of every block and the only one that
    // pays a miner. A block whose first transaction is not a coinbase is a block
    // this relayer does not understand, so it contributes nothing instead of
    // something guessed.
    let Some(coinbase) = block.transactions.first() else { return (payouts, ignored) };
    if coinbase.subnetwork_id != SUBNETWORK_ID_COINBASE {
        return (payouts, ignored);
    }

    for output in &coinbase.outputs {
        match miner_account(&output.script_public_key) {
            Some(miner) => payouts.push((miner, output.value)),
            None => ignored += 1,
        }
    }
    (payouts, ignored)
}

/// The L2 account a coinbase output pays, if its script names a key.
fn miner_account(script: &ScriptPublicKey) -> Option<Address> {
    // A non-zero version is a script format this node cannot check, so its bytes
    // are not a key that may be reinterpreted as one.
    if script.version() != 0 {
        return None;
    }

    // For a public key the address encoder writes exactly one of these two
    // scripts. Anything else - pay-to-script-hash, an `OP_RETURN`, bare data -
    // names no miner, and is reported as skipped rather than forced into a key.
    let point = match script.script() {
        [OP_DATA_32, key @ .., OP_CHECK_SIG] if key.len() == 32 => {
            // An x-only key records no parity, so the even-`y` point of the pair is
            // the one it means: the convention BIP-340 signs with, and the one the
            // module docs spell out for the miner side.
            let mut compressed = [0x02; 33];
            compressed[1..].copy_from_slice(key);
            PublicKey::from_slice(&compressed).ok()?
        }
        [OP_DATA_33, key @ .., OP_CHECK_SIG_ECDSA] if key.len() == 33 => PublicKey::from_slice(key).ok()?,
        _ => return None,
    };
    Some(account_of(point))
}

/// `keccak256(x || y)[12..]`: the Ethereum account of a secp256k1 point.
fn account_of(point: PublicKey) -> Address {
    // The uncompressed form is `0x04 || x || y`, so the 64 bytes the hash covers
    // are exactly its tail and no coordinate has to be re-serialised by hand.
    let uncompressed = point.serialize_uncompressed();
    let digest = keccak256(&uncompressed[1..]);
    Address::from_slice(&digest[12..])
}

/// Totals over the window: every miner's sompi, plus how many outputs were skipped.
fn window_weights(history: &VecDeque<MinedBlock>) -> (BTreeMap<Address, U256>, u32) {
    let mut totals: BTreeMap<Address, u64> = BTreeMap::new();
    let mut ignored = 0;
    for block in history {
        ignored += block.ignored;
        for (miner, sompi) in &block.payouts {
            // A whole window of coinbase rewards is orders of magnitude below
            // `u64::MAX` (the entire supply is 2.9e15 sompi), so this cannot
            // saturate on any real chain; `U256` is only the ABI's width.
            let total = totals.entry(*miner).or_default();
            *total = total.saturating_add(*sompi);
        }
    }
    (totals.into_iter().map(|(miner, sompi)| (miner, U256::from(sompi))).collect(), ignored)
}

// ---------------------------------------------------------------------------
// Talking to the L2
// ---------------------------------------------------------------------------

/// How many times a receipt is asked for before the transaction is given up on.
const SEAL_POLLS: u32 = 20;

/// How long to wait between two receipt requests.
///
/// `eth_sendRawTransaction` on this L2 executes the transaction before it answers,
/// so the first request almost always finds a receipt; the wait only covers the
/// moment the node is still writing the block out.
const SEAL_POLL: Duration = Duration::from_millis(250);

/// The relayer's view of the L2: an endpoint, a key, and what startup learned.
struct L2 {
    http: reqwest::Client,
    url: String,
    signer: PrivateKeySigner,
    treasury: Address,
    chain_id: u64,
    gas_price: u128,
    gas_limit: u64,
    /// The JSON-RPC id of the next request. Not a correlation channel the relayer
    /// uses — every request is answered in order on its own connection — but the
    /// protocol wants one, and a counter keeps the log of a debugger readable.
    request_id: AtomicU64,
}

impl L2 {
    fn new(http: reqwest::Client, url: String, signer: PrivateKeySigner, treasury: Address) -> Self {
        Self {
            http,
            url,
            signer,
            treasury,
            // Zero until `discover` has asked; nothing signs before that.
            chain_id: 0,
            gas_price: 0,
            gas_limit: FALLBACK_GAS_LIMIT,
            request_id: AtomicU64::new(1),
        }
    }

    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    fn gas_price(&self) -> u128 {
        self.gas_price
    }

    fn gas_limit(&self) -> u64 {
        self.gas_limit
    }

    /// The account the relayer key signs for, i.e. the treasury owner it must be.
    fn signer_address(&self) -> Address {
        self.signer.address()
    }

    /// Reads the numbers a signed transaction needs, once per run.
    ///
    /// The chain id is not assumed: signing against the wrong one produces a
    /// transaction the node rejects, and a rejection read as "the treasury said no"
    /// would send an operator looking in the wrong place.
    async fn discover(&mut self) -> Result<(), String> {
        self.chain_id = self.quantity("eth_chainId", json!([])).await? as u64;
        self.gas_price = self.quantity("eth_gasPrice", json!([])).await?;
        // `eth_estimateGas` checks the shape of the call object without executing
        // it and answers the whole block budget. A limit nothing can exceed is
        // exactly right here: this L2 does not refund an over-estimate out of the
        // sender's pocket, because there is no fee market to pay.
        let probe = json!([{ "from": address_hex(self.signer_address()), "to": address_hex(self.treasury), "data": "0x" }]);
        self.gas_limit = self.quantity("eth_estimateGas", probe).await.map(|limit| limit as u64).unwrap_or(FALLBACK_GAS_LIMIT);
        if self.gas_limit == 0 {
            self.gas_limit = FALLBACK_GAS_LIMIT;
        }
        Ok(())
    }

    /// One JSON-RPC call, answering with the `result` or the error message.
    async fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let id = self.request_id.fetch_add(1, Ordering::Relaxed);
        let body = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        let response = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .map_err(|error| format!("{method} could not be posted to {}: {error}", self.url))?;
        let status = response.status();
        let text = response.text().await.map_err(|error| format!("{method}: the reply body could not be read: {error}"))?;

        // The error object is read before the status: a JSON-RPC failure is
        // answered with HTTP 200, and a transport-level failure that does carry a
        // body puts the useful sentence in the same place.
        let reply: Value = serde_json::from_str(&text)
            .map_err(|error| format!("{method}: the reply is not JSON (HTTP {status}, {error}): {text}"))?;
        if let Some(error) = reply.get("error") {
            let message = error.get("message").and_then(Value::as_str).unwrap_or("no message");
            return Err(format!("{method} was refused: {message}"));
        }
        if !status.is_success() {
            return Err(format!("{method}: the L2 answered HTTP {status}: {text}"));
        }
        reply.get("result").cloned().ok_or_else(|| format!("{method}: the reply carries neither a result nor an error: {text}"))
    }

    /// A call that answers with a hex quantity, widened so that a gas price can
    /// hold more than a `u64` and a chain id can be narrowed when it is read.
    async fn quantity(&self, method: &str, params: Value) -> Result<u128, String> {
        let result = self.call(method, params).await?;
        let text = result.as_str().ok_or_else(|| format!("{method} answered {result}, which is not a hex quantity"))?;
        u128::from_str_radix(text.trim_start_matches("0x"), 16)
            .map_err(|error| format!("{method} answered {text}, which is not a hex quantity: {error}"))
    }

    /// Signs one call to the treasury and submits it; returns the hash it was given.
    ///
    /// The nonce is read from the L2 immediately before each signature instead of
    /// being counted here. A counter in this process would go wrong on the first
    /// restart (the node remembers the nonce, the process would not) and, because
    /// revm enforces exact nonces, every later transaction would be refused until
    /// somebody reset the relayer.
    async fn send(&self, to: Address, input: Vec<u8>) -> Result<B256, String> {
        let nonce = self.quantity("eth_getTransactionCount", json!([address_hex(self.signer.address()), "latest"])).await?;
        let nonce = u64::try_from(nonce).map_err(|_| format!("the L2 reports nonce {nonce}, which is not a nonce"))?;

        let transaction = TxEip1559 {
            chain_id: self.chain_id,
            nonce,
            gas_limit: self.gas_limit,
            // This L2 has no base fee, so the whole price is tip. Asking for the
            // price it reports keeps the transaction acceptable if a fee market is
            // ever switched on, and costs nothing while the price is zero.
            max_fee_per_gas: self.gas_price,
            max_priority_fee_per_gas: self.gas_price,
            to: TxKind::Call(to),
            value: U256::ZERO,
            input: Bytes::from(input),
            access_list: Default::default(),
        };
        let hash = transaction.signature_hash();
        let signature = self.signer.sign_hash_sync(&hash).map_err(|error| format!("the relayer key cannot sign: {error}"))?;
        let envelope = TxEnvelope::Eip1559(Signed::new_unchecked(transaction, signature, hash));

        let mut encoded = Vec::new();
        Encodable2718::encode_2718(&envelope, &mut encoded);
        let raw = format!("0x{}", hex::encode(&encoded));

        let result = self.call("eth_sendRawTransaction", json!([raw])).await?;
        let text =
            result.as_str().ok_or_else(|| format!("eth_sendRawTransaction answered {result}, which is not a transaction hash"))?;
        text.parse::<B256>()
            .map_err(|error| format!("eth_sendRawTransaction answered {text}, which is not a transaction hash: {error}"))
    }

    /// Whether the transaction `hash` was sealed as a success.
    ///
    /// This L2 seals a reverted transaction exactly like a successful one and
    /// answers `eth_sendRawTransaction` with a hash either way, so `status` in the
    /// receipt is the only place the outcome is written down.
    async fn sealed(&self, hash: B256) -> Result<bool, String> {
        let hash_hex = format!("0x{}", hex::encode(hash));
        for _ in 0..SEAL_POLLS {
            let receipt = self.call("eth_getTransactionReceipt", json!([hash_hex])).await?;
            // `null` means "not found", which is the node's answer while it is
            // still writing the block out, not a failure.
            if !receipt.is_null() {
                return match receipt.get("status").and_then(Value::as_str) {
                    Some("0x1") => Ok(true),
                    Some("0x0") => Ok(false),
                    other => Err(format!("the receipt for {hash_hex} reports status {other:?}, which is neither 0x1 nor 0x0")),
                };
            }
            tokio::time::sleep(SEAL_POLL).await;
        }
        Err(format!("no receipt for {hash_hex} after {SEAL_POLLS} polls: the L2 took the transaction but never sealed it"))
    }
}

/// The lowercase `0x`-prefixed hex of an address, which is what the RPC takes.
fn address_hex(address: Address) -> String {
    format!("0x{}", hex::encode(address.as_slice()))
}

// ---------------------------------------------------------------------------
// The command line
// ---------------------------------------------------------------------------

/// Everything one run needs, resolved from the flags and the environment.
struct Config {
    treasury: Address,
    key: B256,
    /// Where `key` came from, printed at startup so an operator can see that a
    /// stale `--key` did not quietly win over the environment.
    key_source: &'static str,
    l1_url: String,
    l2_url: String,
    window: usize,
    interval: Duration,
    once: bool,
    dry_run: bool,
}

impl Config {
    /// Reads the flags in `arguments`, one at a time.
    ///
    /// `Ok(None)` means the run was asked to stop before doing anything, which is
    /// what `--help` does: it prints the usage and exits successfully.
    fn parse(arguments: Vec<String>) -> Result<Option<Self>, String> {
        let mut treasury = None;
        let mut key = None;
        let mut l1_url = L1_URL.to_string();
        let mut l2_url = L2_URL.to_string();
        let mut window = DEFAULT_WINDOW;
        let mut interval = Duration::from_secs(DEFAULT_INTERVAL);
        let mut once = false;
        let mut dry_run = false;

        let mut arguments = arguments.into_iter();
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--treasury" => treasury = Some(parse_address(&value_of(&mut arguments, "--treasury")?)?),
                "--key" => key = Some(parse_key(&value_of(&mut arguments, "--key")?)?),
                "--l1" => l1_url = value_of(&mut arguments, "--l1")?,
                "--l2" => l2_url = value_of(&mut arguments, "--l2")?,
                "--window" => window = parse_window(&value_of(&mut arguments, "--window")?)?,
                "--interval" => interval = parse_interval(&value_of(&mut arguments, "--interval")?)?,
                "--once" => once = true,
                "--dry-run" => dry_run = true,
                "--help" | "-h" => {
                    println!("{USAGE}");
                    return Ok(None);
                }
                other => return Err(format!("{other} is not a flag this relayer knows")),
            }
        }

        let Some(treasury) = treasury else {
            return Err("--treasury is required: the relayer has to be told which contract to publish to".to_string());
        };
        // `--key` first, then the environment: a one-off run should not have to
        // export anything, and a long-lived one should not have the key in `ps`.
        let (key, key_source) = match key {
            Some(key) => (key, "--key"),
            None => match std::env::var(KEY_ENV) {
                Ok(text) => (parse_key(&text)?, KEY_ENV),
                Err(_) => return Err(format!("no relayer key: pass --key or set {KEY_ENV}")),
            },
        };

        Ok(Some(Self { treasury, key, key_source, l1_url, l2_url, window, interval, once, dry_run }))
    }
}

/// The value that follows `flag`, or an error naming the flag that lacks one.
fn value_of(arguments: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    arguments.next().ok_or_else(|| format!("{flag} needs a value"))
}

/// Parses the `0x`-prefixed 20-byte address of the treasury contract.
fn parse_address(text: &str) -> Result<Address, String> {
    text.parse::<Address>().map_err(|error| format!("--treasury: {text} is not a 20-byte address: {error}"))
}

/// Parses the 32-byte secp256k1 key the relayer signs with.
fn parse_key(text: &str) -> Result<B256, String> {
    text.parse::<B256>().map_err(|error| format!("--key: {text} is not a 32-byte hex key: {error}"))
}

/// Parses the window width, which has to stay inside what `get_blocks` can serve.
fn parse_window(text: &str) -> Result<usize, String> {
    let window = text.parse::<usize>().map_err(|error| format!("--window: {text} is not a block count: {error}"))?;
    if !(1..=MAX_WINDOW).contains(&window) {
        return Err(format!("--window: {window} is outside 1..={MAX_WINDOW}"));
    }
    Ok(window)
}

/// Parses the pause between passes.
fn parse_interval(text: &str) -> Result<Duration, String> {
    let seconds = text.parse::<u64>().map_err(|error| format!("--interval: {text} is not a number of seconds: {error}"))?;
    if seconds == 0 {
        // One pass is far more than a millisecond of work, and a zero pause would
        // turn the loop into a spin that hammers both nodes and prints without end.
        return Err("--interval: 0 would busy-loop; ask for one second or more".to_string());
    }
    Ok(Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_txscript::opcodes::codes;
    use kaspa_txscript::script_class::ScriptClass;
    use secp256k1::{Secp256k1, SecretKey};

    /// The point of private key `1`: the one key whose Ethereum account everybody
    /// can look up, so the derivation is checked against an outside number rather
    /// than against itself.
    fn key_of_one() -> PublicKey {
        let mut secret = [0u8; 32];
        secret[31] = 1;
        let secret = SecretKey::from_slice(&secret).expect("one is a valid scalar");
        PublicKey::from_secret_key(&Secp256k1::new(), &secret)
    }

    /// A point with an odd `y`, which is what makes the x-only rule visible: its
    /// x-only spelling names the account of the *negated* point.
    fn point_with_odd_y() -> PublicKey {
        let secp = Secp256k1::new();
        (1u8..=32)
            .map(|scalar| {
                let mut secret = [0u8; 32];
                secret[31] = scalar;
                PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&secret).expect("a valid scalar"))
            })
            .find(|point| point.serialize()[0] == 0x03)
            .expect("an odd-y point within the first 32 scalars")
    }

    /// The script a `zethora-miner` builds from a 32-byte address: the x-only key
    /// pushed, then `OP_CHECKSIG`.
    fn x_only_script(point: &PublicKey) -> ScriptPublicKey {
        let compressed = point.serialize();
        let mut bytes = vec![OP_DATA_32];
        bytes.extend_from_slice(&compressed[1..]);
        bytes.push(OP_CHECK_SIG);
        ScriptPublicKey::from_vec(0, bytes)
    }

    /// The same shape, carrying the full 33-byte compressed key instead.
    fn compressed_script(point: &PublicKey) -> ScriptPublicKey {
        let mut bytes = vec![OP_DATA_33];
        bytes.extend_from_slice(&point.serialize());
        bytes.push(OP_CHECK_SIG_ECDSA);
        ScriptPublicKey::from_vec(0, bytes)
    }

    /// `keccak256(x || y)[12..]` is Ethereum's own address derivation, so key `1`
    /// has to land on the account every wallet shows for it.
    #[test]
    fn a_miners_key_maps_to_the_account_ethereum_would_give_it() {
        assert_eq!(address_hex(account_of(key_of_one())), "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf");
    }

    /// The script an address encoder writes for a 32-byte address is read as its
    /// key, and nothing else about it is invented.
    #[test]
    fn an_x_only_coinbase_script_names_its_key_account() {
        let point = key_of_one();
        assert_eq!(point.serialize()[0], 0x02, "key 1 has an even y, so the fixture is the convention's own case");
        assert_eq!(miner_account(&x_only_script(&point)), Some(account_of(point)));
        assert_eq!(address_hex(miner_account(&x_only_script(&point)).expect("a key")), "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf");
    }

    /// A 33-byte compressed key records its parity, so it is read as the point it
    /// spells — even when that is the opposite of what the x-only rule would pick.
    #[test]
    fn a_compressed_coinbase_script_names_the_point_it_carries() {
        let point = point_with_odd_y();
        assert_eq!(miner_account(&compressed_script(&point)), Some(account_of(point)));
        // The x-only encoding of the same x lifts to the even point, i.e. the
        // negation, and therefore to a different account: the caveat the module
        // documentation states, kept honest by this assertion.
        assert_ne!(miner_account(&x_only_script(&point)), Some(account_of(point)));
    }

    /// A coinbase output that names no key contributes nothing, and is never
    /// guessed at: a weight paid to an account nobody holds is unrecoverable.
    #[test]
    fn coinbase_scripts_without_a_key_name_no_account() {
        // Pay to script hash, the other standard class a miner can be paid to.
        let mut p2sh = vec![codes::OpBlake2b, OP_DATA_32];
        p2sh.extend_from_slice(&[0x11; 32]);
        p2sh.push(codes::OpEqual);
        let p2sh = ScriptPublicKey::from_vec(0, p2sh);
        assert_eq!(ScriptClass::from_script(&p2sh), ScriptClass::ScriptHash, "the fixture is a real script-hash output");
        assert_eq!(miner_account(&p2sh), None);

        // A key script whose version this node cannot check is not reinterpreted.
        let mut bytes = vec![OP_DATA_32];
        bytes.extend_from_slice(&key_of_one().serialize()[1..]);
        bytes.push(OP_CHECK_SIG);
        assert_eq!(miner_account(&ScriptPublicKey::from_vec(1, bytes)), None);

        // And the empty script pays nobody.
        assert_eq!(miner_account(&ScriptPublicKey::from_vec(0, Vec::new())), None);
    }

    /// The scripts this relayer accepts are exactly the ones the node classifies
    /// as pay-to-pubkey, so the two definitions of "a miner's output" cannot drift.
    #[test]
    fn an_accepted_script_is_one_the_node_calls_pay_to_pubkey() {
        let even = key_of_one();
        let odd = point_with_odd_y();
        for script in [x_only_script(&even), compressed_script(&even), x_only_script(&odd), compressed_script(&odd)] {
            assert_ne!(ScriptClass::from_script(&script), ScriptClass::NonStandard);
            assert!(miner_account(&script).is_some());
        }

        // One byte short of a key, so the node does not call it a key script either.
        let mut truncated = vec![OP_DATA_32];
        truncated.extend_from_slice(&[0x11; 31]);
        truncated.push(OP_CHECK_SIG);
        let truncated = ScriptPublicKey::from_vec(0, truncated);
        assert_eq!(ScriptClass::from_script(&truncated), ScriptClass::NonStandard);
        assert_eq!(miner_account(&truncated), None);
    }

    /// The opcode bytes are consensus values the relayer spells itself, so they are
    /// pinned against the script engine's constants instead of being trusted.
    #[test]
    fn the_opcodes_are_the_ones_the_script_engine_uses() {
        assert_eq!(OP_DATA_32, codes::OpData32);
        assert_eq!(OP_DATA_33, codes::OpData33);
        assert_eq!(OP_CHECK_SIG, codes::OpCheckSig);
        assert_eq!(OP_CHECK_SIG_ECDSA, codes::OpCheckSigECDSA);
    }

    /// A block to sum over, with a hash that only has to be distinct.
    fn mined_block(tag: u8, payouts: Vec<(Address, u64)>, ignored: u32) -> MinedBlock {
        MinedBlock { hash: RpcHash::from_bytes([tag; 32]), payouts, ignored }
    }

    /// Weights are the sum over the window, per miner, and blocks that name no key
    /// are carried in the total so a pass can report them.
    #[test]
    fn the_window_sums_each_miner_over_every_block() {
        let alice = Address::repeat_byte(0x0a);
        let bob = Address::repeat_byte(0x0b);
        let history = VecDeque::from(vec![
            mined_block(1, vec![(alice, 10)], 0),
            mined_block(2, vec![(alice, 5), (bob, 7)], 1),
            mined_block(3, Vec::new(), 2),
        ]);

        let (weights, ignored) = window_weights(&history);
        assert_eq!(weights.len(), 2, "only the two miners that were paid carry a weight");
        assert_eq!(weights[&alice], U256::from(15), "alice's two rewards are summed");
        assert_eq!(weights[&bob], U256::from(7));
        assert_eq!(ignored, 3, "every skipped output in the window is reported");
    }

    /// An empty window is not an error: a fresh chain has nothing to publish yet.
    #[test]
    fn an_empty_window_has_no_weights() {
        let (weights, ignored) = window_weights(&VecDeque::new());
        assert!(weights.is_empty());
        assert_eq!(ignored, 0);
    }

    /// The flags a run needs are read, defaulted and validated, and `--help` is a
    /// successful run that does nothing else.
    #[test]
    fn the_command_line_is_read_and_checked() {
        let treasury = "0x00000000000000000000000000000000000000aa";
        let key = format!("0x{}", "11".repeat(32));

        let config = Config::parse(
            ["--treasury", treasury, "--key", &key, "--window", "5", "--once", "--dry-run"]
                .iter()
                .map(|argument| argument.to_string())
                .collect(),
        )
        .expect("the flags are well formed")
        .expect("and they ask for a run");
        assert_eq!(address_hex(config.treasury), treasury);
        assert_eq!(config.key, B256::repeat_byte(0x11));
        assert_eq!(config.key_source, "--key");
        assert_eq!(config.window, 5);
        assert_eq!(config.interval, Duration::from_secs(DEFAULT_INTERVAL));
        assert!(config.once && config.dry_run);
        assert_eq!(config.l1_url, L1_URL);
        assert_eq!(config.l2_url, L2_URL);

        assert!(Config::parse(vec!["--help".to_string()]).expect("--help is not an error").is_none());

        let error = |arguments: &[&str]| {
            // Matched rather than `expect_err`ed: `Config` deliberately has no
            // `Debug` impl, so a failed assertion cannot print the relayer key.
            match Config::parse(arguments.iter().map(|argument| argument.to_string()).collect()) {
                Ok(_) => panic!("{} was accepted", arguments.join(" ")),
                Err(problem) => problem,
            }
        };
        assert!(error(&[]).contains("--treasury is required"));
        assert!(error(&["--treasury", treasury, "--window", "0"]).contains("outside 1..=1000"));
        assert!(error(&["--treasury", treasury, "--window", "1001"]).contains("outside 1..=1000"));
        assert!(error(&["--treasury", treasury, "--interval", "0"]).contains("busy-loop"));
        assert!(error(&["--treasury", "0x11"]).contains("not a 20-byte address"));
        assert!(error(&["--treasury", treasury, "--key", "0x22"]).contains("not a 32-byte hex key"));
        assert!(error(&["--treasury", treasury, "--window"]).contains("--window needs a value"));
        assert!(error(&["--treasury", treasury, "--nonsense"]).contains("is not a flag this relayer knows"));
    }
}
