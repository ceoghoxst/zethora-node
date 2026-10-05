//! zethora-shield: devnet tool for Zethora's private pool (ZTH-SPEC-006).
//!
//! Run from the zethora-node folder, with the node running with --devnet --utxoindex:
//!
//!     cargo run --release -p zethora-shield -- 0.1             shield 0.1 ZTHR (visible -> your private wallet)
//!     cargo run --release -p zethora-shield -- balance         show your and your friend's private coins
//!     cargo run --release -p zethora-shield -- send 0.05       send 0.05 ZTHR privately to your friend's wallet
//!     cargo run --release -p zethora-shield -- unshield 0.05   move 0.05 ZTHR from private back to your visible address
//!     cargo run --release -p zethora-shield -- attack          try to cheat: spend a made-up coin, then spend a coin twice
//!
//! Both private wallets are derived from the miner's key file. The network fee is paid from a visible coin of the
//! miner for now (a later update makes fully private payments with no visible part).

use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus_core::{
    config::params::DEVNET_PARAMS,
    constants::TX_VERSION,
    hashing::tx::zethora_private_payment_digest,
    network::NetworkType,
    sign::sign,
    subnets::{SUBNETWORK_ID_COINBASE, SUBNETWORK_ID_NATIVE},
    tx::{ComputeCommit, MutableTransaction, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry},
    zethora_private::{ANCHOR_DEPTH, PRIVATE_PAYMENT_MAGIC, private_payment_bytes},
};
use kaspa_grpc_client::GrpcClient;
use kaspa_rpc_core::{RpcDataVerbosityLevel, api::rpc::RpcApi};
use kaspa_txscript::pay_to_address_script;
use secp256k1::{Keypair, SECP256K1, SecretKey};
use std::time::Duration;
use zethora_shielded::{
    orchard::Address as PrivateAddress,
    scan::{OwnedCoin, Scanner},
    wallet::{PrivateWallet, proving_key, shielding_payment},
};

const NODE_URL: &str = "grpc://127.0.0.1:26610";
const KEY_FILE: &str = "zethora-miner-key.txt";
const ZETS_PER_ZTHR: f64 = 10_000_000_000.0;
/// About 5x the minimum relay fee for a 2-action private payment (~41,000 grams of compute mass).
const FEE: u64 = 20_000_000;
/// Keep the visible change coin at least 0.01 ZTHR: a tiny change coin has a huge storage mass and is refused.
const MIN_CHANGE: u64 = 100_000_000;
/// Extra blocks on top of the network's 600 so a spend's snapshot is still deep enough when it lands in a block.
const SAFETY_MARGIN: u64 = 30;
/// Read the chain only up to blocks this many blocks deep, so the tip settling down never restarts a scan.
const SCAN_CONFIRMATIONS: u64 = 20;
/// Which scanned wallet is which
const ME: usize = 0;
const FRIEND: usize = 1;

fn zthr(zets: u64) -> String {
    format!("{:.4} ZTHR", zets as f64 / ZETS_PER_ZTHR)
}

fn parse_amount(arg: Option<&String>) -> u64 {
    let zthr: f64 = arg.map(|a| a.parse().expect("amount must be a number, e.g. 0.05")).unwrap_or(0.1);
    let zets = (zthr * ZETS_PER_ZTHR).round() as u64;
    assert!(zets > 0, "amount must be more than 0");
    zets
}

struct Miner {
    key: Keypair,
    address: Address,
    seed: [u8; 32],
}

fn load_miner() -> Miner {
    let hex = std::fs::read_to_string(KEY_FILE).expect("zethora-miner-key.txt not found: run this from the zethora-node folder");
    let bytes: Vec<u8> = (0..64).step_by(2).map(|i| u8::from_str_radix(&hex.trim()[i..i + 2], 16).unwrap()).collect();
    let key = Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&bytes).expect("bad key file"));
    let address = Address::new(Prefix::from(NetworkType::Devnet), Version::PubKey, &key.x_only_public_key().0.serialize());
    let seed = key.secret_key().secret_bytes();
    Miner { key, address, seed }
}

/// Your private wallet (index ME) and your friend's (index FRIEND), both derived from the miner's key.
fn wallets(m: &Miner) -> Vec<PrivateWallet> {
    vec![PrivateWallet::from_seed(&m.seed), PrivateWallet::friend_of(&m.seed)]
}

/// The miner's mature visible coins, largest first.
async fn visible_coins(client: &GrpcClient, address: &Address) -> Vec<(TransactionOutpoint, UtxoEntry)> {
    let virtual_daa = client.get_block_dag_info().await.expect("dag info").virtual_daa_score;
    let maturity = DEVNET_PARAMS.coinbase_maturity();
    let mut coins: Vec<_> = client
        .get_utxos_by_addresses(vec![address.clone()])
        .await
        .expect("utxos (is the node running with --utxoindex?)")
        .into_iter()
        .map(|e| (TransactionOutpoint::from(e.outpoint), UtxoEntry::from(e.utxo_entry)))
        .filter(|(_, e)| e.block_daa_score + if e.is_coinbase { 2 * maturity } else { 10 } < virtual_daa)
        .collect();
    coins.sort_by_key(|(_, e)| std::cmp::Reverse(e.amount));
    coins
}

/// A transaction spending one visible coin of the miner, with one visible output back to the miner.
fn visible_part(m: &Miner, outpoint: TransactionOutpoint, change: u64) -> Transaction {
    let input = TransactionInput {
        previous_outpoint: outpoint,
        signature_script: vec![],
        sequence: 0,
        compute_commit: ComputeCommit::SigopCount(1.into()),
    };
    let output = TransactionOutput { value: change, script_public_key: pay_to_address_script(&m.address), covenant: None };
    Transaction::new_non_finalized(TX_VERSION, vec![input], vec![output], 0, SUBNETWORK_ID_NATIVE, 0, vec![])
}

/// Attaches the private payment and signs the visible input (its signature covers the payload too).
fn finish(m: &Miner, mut tx: Transaction, entry: UtxoEntry, payment: Vec<u8>) -> Transaction {
    tx.payload = PRIVATE_PAYMENT_MAGIC.iter().copied().chain(payment).collect();
    let mut tx = sign(MutableTransaction::with_entries(tx, vec![entry]), m.key).tx;
    tx.finalize();
    tx
}

/// Builds and signs a transaction whose private part spends `coins` of `scanner`'s wallet ME into `outputs`. Whatever is
/// not sent to `outputs` leaves the private pool into the miner's visible address (`unshielded` zets).
fn private_spend_tx(
    m: &Miner,
    scanner: &Scanner,
    visible: &(TransactionOutpoint, UtxoEntry),
    coins: &[OwnedCoin],
    outputs: &[(PrivateAddress, u64)],
    unshielded: u64,
) -> Transaction {
    let (outpoint, entry) = visible.clone();
    let change = (entry.amount + unshielded)
        .checked_sub(FEE)
        .filter(|c| *c >= MIN_CHANGE)
        .unwrap_or_else(|| panic!("visible coin of {} is too small to pay the fee", zthr(entry.amount)));
    let tx = visible_part(m, outpoint, change);
    let digest = zethora_private_payment_digest(&tx);
    let payment = scanner.spend_payment(ME, coins, outputs, &digest.as_bytes()).unwrap_or_else(|e| panic!("private payment: {e}"));
    finish(m, tx, entry, payment)
}

/// Reads the whole chain and finds every private coin of both wallets. Checks the rebuilt coin list against the root
/// sealed in every coinbase, so a wallet bug can't silently produce payments the network would refuse.
async fn scan(client: &GrpcClient, m: &Miner) -> Scanner {
    for attempt in 1..=3 {
        match try_scan(client, m).await {
            Ok(s) => return s,
            Err(e) if attempt < 3 => println!("Reading the chain was interrupted ({e}), trying again..."),
            Err(e) => panic!("Could not read the chain: {e}"),
        }
    }
    unreachable!()
}

async fn try_scan(client: &GrpcClient, m: &Miner) -> Result<Scanner, String> {
    let tip = client.get_sink_blue_score().await.map_err(|e| e.to_string())?;
    let deep_enough = tip.saturating_sub(ANCHOR_DEPTH + SAFETY_MARGIN);
    let mut scanner = Scanner::new(wallets(m));
    let mut start = DEVNET_PARAMS.genesis.hash;
    let mut snapshot_taken = false;
    let mut roots_checked = 0u64;
    loop {
        let resp = client
            .get_virtual_chain_from_block_v2(start, Some(RpcDataVerbosityLevel::Full), Some(SCAN_CONFIRMATIONS))
            .await
            .map_err(|e| e.to_string())?;
        if !resp.removed_chain_block_hashes.is_empty() {
            return Err("the chain changed while reading it".to_string());
        }
        if resp.added_chain_block_hashes.is_empty() {
            break;
        }
        for (hash, block) in resp.added_chain_block_hashes.iter().zip(resp.chain_block_accepted_transactions.iter()) {
            let blue = block.chain_block_header.blue_score.ok_or("the node did not send block heights")?;
            if !snapshot_taken && blue > deep_enough {
                scanner.checkpoint()?;
                snapshot_taken = true;
            }
            let mut sealed_checked = false;
            for tx in block.accepted_transactions.iter() {
                let Some(payload) = tx.payload.as_ref() else { continue };
                if tx.subnetwork_id.as_ref() == Some(&SUBNETWORK_ID_COINBASE) {
                    // The first coinbase is the selected parent's: it seals the coin list as of the previous chain block.
                    // Genesis seals nothing (its payload has zeros there), so the first chain block is not checked.
                    if !sealed_checked && start != DEVNET_PARAMS.genesis.hash && let Some(sealed) = payload.get(56..88) {
                        if sealed != scanner.root() {
                            return Err(format!(
                                "the wallet's private coin list differs from the network's at block {hash}. Send this to Claude"
                            ));
                        }
                        roots_checked += 1;
                    }
                    sealed_checked = true;
                } else if let Some(encoded) = private_payment_bytes(payload) {
                    scanner.add_payment(encoded)?;
                }
            }
            start = *hash;
        }
    }
    if !snapshot_taken {
        scanner.checkpoint()?;
    }
    if roots_checked == 0 {
        println!("(Warning: could not compare the wallet's coin list with the network's)");
    }
    Ok(scanner)
}

fn show(scanner: &Scanner) {
    for (who, name) in [(ME, "Your private wallet"), (FRIEND, "Friend's private wallet")] {
        let h = scanner.holdings(who);
        println!(
            "{name:<24} ready: {} ({} coins)   arriving: {} ({} coins, ready ~10 min after they land)",
            zthr(h.spendable_total()),
            h.spendable.len(),
            zthr(h.maturing_total()),
            h.maturing.len()
        );
    }
    let root = scanner.root();
    let fingerprint: String = root[..4].iter().map(|x| format!("{x:02x}")).collect();
    println!("Private coin list: {} coins ever created, coin list {fingerprint}", scanner.size());
}

async fn submit(client: &GrpcClient, tx: &Transaction) -> Result<String, String> {
    client.submit_transaction(tx.into(), false).await.map(|id| id.to_string()).map_err(|e| e.to_string())
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let m = load_miner();
    let client = GrpcClient::connect(NODE_URL.to_string()).await.expect("Cannot reach the node. Is it running with --devnet --utxoindex?");

    match args.first().map(String::as_str) {
        None => shield(&client, &m, parse_amount(None)).await,
        Some("shield") => shield(&client, &m, parse_amount(args.get(1))).await,
        Some(a) if a.parse::<f64>().is_ok() => shield(&client, &m, parse_amount(args.first())).await,
        Some("balance") => {
            println!("Reading the chain...");
            show(&scan(&client, &m).await);
        }
        Some("send") => send(&client, &m, parse_amount(args.get(1))).await,
        Some("unshield") => unshield(&client, &m, parse_amount(args.get(1))).await,
        Some("attack") => attack(&client, &m).await,
        Some(other) => println!("Unknown command '{other}'. Use: 0.1 | balance | send 0.05 | unshield 0.05 | attack"),
    }
}

async fn shield(client: &GrpcClient, m: &Miner, amount: u64) {
    println!("Visible address: {}", m.address);
    let (outpoint, entry) =
        visible_coins(client, &m.address).await.into_iter().next().expect("no mature coins yet: keep mining and try again later");
    let change = entry
        .amount
        .checked_sub(amount + FEE)
        .filter(|c| *c >= MIN_CHANGE)
        .unwrap_or_else(|| panic!("largest mature coin is {}: shield a smaller amount", zthr(entry.amount)));
    let tx = visible_part(m, outpoint, change);
    println!("Making the private payment (proving key takes a few seconds the first time)...");
    let _ = proving_key();
    let digest = zethora_private_payment_digest(&tx);
    let payment = shielding_payment(PrivateWallet::from_seed(&m.seed).address(), amount, &digest.as_bytes()).expect("private payment");
    let tx = finish(m, tx, entry, payment);
    match submit(client, &tx).await {
        Ok(id) => {
            println!("Shielded {} into the private pool. Fee {}. Transaction {id}", zthr(amount), zthr(FEE));
            println!("Watch the miner's Supply check line: \"private\" should grow by {amount} zets once it's in a block.");
        }
        Err(e) => println!("Node refused the transaction: {e}"),
    }
}

async fn send(client: &GrpcClient, m: &Miner, amount: u64) {
    println!("Reading the chain...");
    let scanner = scan(client, m).await;
    show(&scanner);
    let coins = scanner.pick_coins(ME, amount).unwrap_or_else(|e| panic!("{e}"));
    let change = coins.iter().map(OwnedCoin::value).sum::<u64>() - amount;
    let w = wallets(m);
    let mut outputs = vec![(w[FRIEND].address(), amount)];
    if change > 0 {
        outputs.push((w[ME].address(), change));
    }
    let visible = visible_coins(client, &m.address).await.into_iter().next().expect("no mature visible coin to pay the fee");
    println!("Making the private payment...");
    let tx = private_spend_tx(m, &scanner, &visible, &coins, &outputs, 0);
    match submit(client, &tx).await {
        Ok(id) => {
            println!("Sent {} privately to your friend's wallet. Fee {}. Transaction {id}", zthr(amount), zthr(FEE));
            println!("On the chain it shows no amount and no receiver. \"private\" in the Supply check stays the same.");
            println!("Run balance in about 10 minutes to see it ready in your friend's wallet.");
        }
        Err(e) => println!("Node refused the transaction: {e}"),
    }
}

async fn unshield(client: &GrpcClient, m: &Miner, amount: u64) {
    println!("Reading the chain...");
    let scanner = scan(client, m).await;
    show(&scanner);
    let coins = scanner.pick_coins(ME, amount).unwrap_or_else(|e| panic!("{e}"));
    let change = coins.iter().map(OwnedCoin::value).sum::<u64>() - amount;
    let w = wallets(m);
    let outputs = if change > 0 { vec![(w[ME].address(), change)] } else { vec![] };
    let visible = visible_coins(client, &m.address).await.into_iter().next().expect("no mature visible coin to pay the fee");
    println!("Making the private payment...");
    let tx = private_spend_tx(m, &scanner, &visible, &coins, &outputs, amount);
    match submit(client, &tx).await {
        Ok(id) => {
            println!("Moved {} from the private pool to your visible address. Fee {}. Transaction {id}", zthr(amount), zthr(FEE));
            println!("Watch the Supply check: \"private\" should drop by {amount} zets and every line still says BALANCED.");
        }
        Err(e) => println!("Node refused the transaction: {e}"),
    }
}

async fn attack(client: &GrpcClient, m: &Miner) {
    let mut blocked = 0;
    println!("Reading the chain...");
    let scanner = scan(client, m).await;
    show(&scanner);
    let visible = visible_coins(client, &m.address).await;
    assert!(visible.len() >= 2, "need two mature visible coins: keep mining a bit longer");

    // Attack 1: counterfeit. Make a 0.05 ZTHR private coin out of thin air, in a coin list only we know about, with a
    // perfectly valid proof, and try to take it out of the private pool.
    println!("\nATTACK 1: spend a private coin that was never created on the chain (counterfeit)");
    let fake_amount = 500_000_000;
    let mut fake = Scanner::new(wallets(m));
    let fake_shield = shielding_payment(wallets(m)[ME].address(), fake_amount, &[0; 32]).expect("fake coin");
    fake.add_payment(&fake_shield).expect("fake list");
    fake.checkpoint().expect("fake snapshot");
    let fake_coins = fake.pick_coins(ME, fake_amount).expect("fake coin");
    let tx = private_spend_tx(m, &fake, &visible[0], &fake_coins, &[], fake_amount);
    match submit(client, &tx).await {
        Err(e) => {
            println!("  Network refused it: {e}");
            println!("  BLOCKED. A valid proof is not enough: the coin list it points to must be one the chain really had.");
            blocked += 1;
        }
        Ok(id) => println!("  NOT BLOCKED: the network accepted counterfeit transaction {id}. Stop and send this to Claude."),
    }

    // Attack 2: double spend. Spend one real private coin, wait for it to land in a block, then spend it again.
    println!("\nATTACK 2: spend the same private coin twice");
    let Some(coin) = scanner.holdings(ME).spendable.into_iter().max_by_key(OwnedCoin::value) else {
        println!("  Skipped: you have no ready private coin. Shield some, wait about 10 minutes, and run attack again.");
        return finish_attack(blocked, 2);
    };
    let w = wallets(m);
    let first = private_spend_tx(m, &scanner, &visible[0], std::slice::from_ref(&coin), &[(w[FRIEND].address(), coin.value())], 0);
    let second = private_spend_tx(m, &scanner, &visible[1], std::slice::from_ref(&coin), &[(w[ME].address(), coin.value())], 0);
    match submit(client, &first).await {
        Ok(id) => println!("  First spend sent ({} to your friend), transaction {id}.", zthr(coin.value())),
        Err(e) => {
            println!("  The first (honest) spend was refused: {e}");
            println!("  That should not happen. Send this to Claude.");
            return finish_attack(blocked, 2);
        }
    }
    println!("  Waiting for it to land in a block...");
    let mut landed = false;
    for _ in 0..60 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        if client.get_mempool_entry(first.id(), false, false).await.is_err() {
            landed = true;
            break;
        }
    }
    if !landed {
        println!("  The first spend did not land within a minute. Is the miner running? Try again.");
        return finish_attack(blocked, 2);
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
    println!("  Landed. Now sending the same coin again, this time back to yourself...");
    match submit(client, &second).await {
        Err(e) => {
            println!("  Network refused it: {e}");
            println!("  BLOCKED. Spending a private coin reveals a one-time tag, and the network remembers every tag.");
            blocked += 1;
        }
        Ok(id) => println!("  NOT BLOCKED: the network accepted the second spend {id}. Stop and send this to Claude."),
    }
    finish_attack(blocked, 2)
}

fn finish_attack(blocked: usize, tried: usize) {
    println!();
    if blocked == tried {
        println!("RESULT: {blocked} of {tried} attacks blocked. Check the miner window: every Supply check line still says BALANCED.");
    } else {
        println!("RESULT: {blocked} of {tried} attacks blocked. Send this whole window to Claude.");
    }
}
