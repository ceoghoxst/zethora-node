//! zethora-shield: moves coins from the devnet miner's visible address into the private pool (ZTH-SPEC-006).
//!
//! Usage (from the zethora-node folder, with the node running with --devnet --utxoindex):
//!     cargo run --release -p zethora-shield -- 0.1
//! shields 0.1 ZTHR (default 0.1). The private coin goes to a private wallet derived from the miner's key.
//! Spending inside the private pool is switched off on the network for now, so this only moves coins in.

use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus_core::{
    config::params::DEVNET_PARAMS,
    constants::TX_VERSION,
    hashing::tx::zethora_private_payment_digest,
    network::NetworkType,
    sign::sign,
    subnets::SUBNETWORK_ID_NATIVE,
    tx::{ComputeCommit, MutableTransaction, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry},
    zethora_private::PRIVATE_PAYMENT_MAGIC,
};
use kaspa_grpc_client::GrpcClient;
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_txscript::pay_to_address_script;
use secp256k1::{Keypair, SECP256K1, SecretKey};
use zethora_shielded::wallet::{PrivateWallet, proving_key, shielding_payment};

const NODE_URL: &str = "grpc://127.0.0.1:26610";
const KEY_FILE: &str = "zethora-miner-key.txt";
const ZETS_PER_ZTHR: f64 = 10_000_000_000.0;
/// About 5x the minimum relay fee for a 2-action private payment (~41,000 grams of compute mass).
const FEE: u64 = 20_000_000;
/// Keep the change coin at least 0.01 ZTHR: a tiny change coin has a huge storage mass and is refused.
const MIN_CHANGE: u64 = 100_000_000;

fn load_key() -> Keypair {
    let hex = std::fs::read_to_string(KEY_FILE).expect("zethora-miner-key.txt not found: run this from the zethora-node folder");
    let bytes: Vec<u8> = (0..64).step_by(2).map(|i| u8::from_str_radix(&hex.trim()[i..i + 2], 16).unwrap()).collect();
    Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&bytes).expect("bad key file"))
}

#[tokio::main]
async fn main() {
    let amount_zthr: f64 = std::env::args().nth(1).map(|a| a.parse().expect("amount must be a number, e.g. 0.1")).unwrap_or(0.1);
    let amount = (amount_zthr * ZETS_PER_ZTHR).round() as u64;
    assert!(amount > 0, "amount must be more than 0");

    let key = load_key();
    let address = Address::new(Prefix::from(NetworkType::Devnet), Version::PubKey, &key.x_only_public_key().0.serialize());
    let wallet = PrivateWallet::from_seed(&key.secret_key().secret_bytes());
    println!("Visible address: {address}");

    let client = GrpcClient::connect(NODE_URL.to_string()).await.expect("Cannot reach the node. Is it running with --devnet --utxoindex?");

    // Pick the largest mature coin the miner owns
    let virtual_daa = client.get_block_dag_info().await.expect("dag info").virtual_daa_score;
    let maturity = DEVNET_PARAMS.coinbase_maturity();
    let (outpoint, entry) = client
        .get_utxos_by_addresses(vec![address.clone()])
        .await
        .expect("utxos (is the node running with --utxoindex?)")
        .into_iter()
        .map(|e| (TransactionOutpoint::from(e.outpoint), UtxoEntry::from(e.utxo_entry)))
        .filter(|(_, e)| e.block_daa_score + if e.is_coinbase { 2 * maturity } else { 10 } < virtual_daa)
        .max_by_key(|(_, e)| e.amount)
        .expect("no mature coins yet: keep mining and try again later");
    let change = entry
        .amount
        .checked_sub(amount + FEE)
        .filter(|c| *c >= MIN_CHANGE)
        .unwrap_or_else(|| panic!("largest mature coin is {:.4} ZTHR: shield a smaller amount", entry.amount as f64 / ZETS_PER_ZTHR));

    // 1. The visible part of the transaction: spend one coin, send the change back to ourselves
    let input = TransactionInput {
        previous_outpoint: outpoint,
        signature_script: vec![],
        sequence: 0,
        compute_commit: ComputeCommit::SigopCount(1.into()),
    };
    let output = TransactionOutput { value: change, script_public_key: pay_to_address_script(&address), covenant: None };
    let mut tx = Transaction::new_non_finalized(TX_VERSION, vec![input], vec![output], 0, SUBNETWORK_ID_NATIVE, 0, vec![]);

    // 2. The private payment, signed over everything else in the transaction
    println!("Making the private payment (proving key takes a few seconds the first time)...");
    let _ = proving_key();
    let digest = zethora_private_payment_digest(&tx);
    let payment = shielding_payment(wallet.address(), amount, &digest.as_bytes()).expect("private payment");
    tx.payload = PRIVATE_PAYMENT_MAGIC.iter().copied().chain(payment).collect();

    // 3. Sign the visible input (its signature covers the payload, locking both parts together)
    let signed = sign(MutableTransaction::with_entries(tx, vec![entry]), key).tx;
    let mut tx = signed;
    tx.finalize();

    match client.submit_transaction((&tx).into(), false).await {
        Ok(id) => {
            println!("Shielded {amount_zthr} ZTHR into the private pool. Fee {:.4} ZTHR. Transaction {id}", FEE as f64 / ZETS_PER_ZTHR);
            println!("Watch the miner's Supply check line: \"private\" should grow by {amount} zets once it's in a block.");
        }
        Err(e) => println!("Node refused the transaction: {e}"),
    }
}
