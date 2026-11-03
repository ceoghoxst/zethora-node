//! zethora-wallet: the Zethora testnet wallet CLI (Testnet Phase 2).
//!
//! Run from the zethora-node folder, with the node running with `--testnet --utxoindex`:
//!
//!     zethora-wallet balance --testnet                    show your balance
//!     zethora-wallet receive --testnet                    print your zethoratest: address
//!     zethora-wallet exchange-deposit --testnet           print the transparent address to deposit from an exchange
//!     zethora-wallet send <address> <amount> --testnet    build, sign and submit a payment
//!     zethora-wallet history [--limit <n>] [--json]       list what this wallet has done
//!     zethora-wallet sync --testnet                       record incoming coins that are not in the ledger yet
//!
//! The key is read from `zethora-miner-key-testnet.txt` (64 hex characters) - the same file
//! zethora-miner uses, so the wallet controls the coins the miner earned. The wallet never
//! creates a key: a fresh key would be a different address and look like lost funds.
//!
//! `balance` and `send` need the node to run with `--utxoindex`, because they ask the node
//! for the coins of an address.
//!
//! Testnet only: without `--testnet` the tool refuses to run, so it can never be pointed at
//! mainnet by accident.

#![allow(clippy::arithmetic_side_effects)]

mod history;

use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus_core::{
    config::params::TESTNET_PARAMS,
    constants::TX_VERSION,
    sign::{Error as SignError, sign, verify},
    subnets::SUBNETWORK_ID_NATIVE,
    tx::{
        ComputeCommit, MutableTransaction, SignableTransaction, Transaction, TransactionInput, TransactionOutpoint,
        TransactionOutput, UtxoEntry, VerifiableTransaction,
    },
};
use kaspa_grpc_client::GrpcClient;
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_txscript::pay_to_address_script;
use secp256k1::{Keypair, SECP256K1, SecretKey};
use std::fmt;

/// The node the wallet talks to. Same endpoint zethora-miner uses for testnet (`--testnet`, gRPC port 26210).
const TESTNET_NODE_URL: &str = "grpc://127.0.0.1:26210";
/// The key file zethora-miner writes its testnet mining key to.
const TESTNET_KEY_FILE: &str = "zethora-miner-key-testnet.txt";
const ZETS_PER_ZTHR: f64 = 10_000_000_000.0;
/// Network fee in sompi per gram, exactly as rothschild computes it: ~1.1x the 100 sompi/gram relay minimum.
const FEE_RATE: u64 = 110;
/// A change coin smaller than this (0.01 ZTHR) has a huge storage mass and is refused, so it is folded into
/// the fee instead. Same guard zethora-shield uses.
const MIN_CHANGE: u64 = 100_000_000;
/// A regular (non-coinbase) coin is treated as spendable this many blocks after it landed.
const REGULAR_CONFIRMATIONS: u64 = 10;
/// How many records `history` prints when `--limit` is not given: the newest 50.
const DEFAULT_HISTORY_LIMIT: usize = 50;

// ---

#[derive(Debug)]
enum WalletError {
    /// The key file is missing, unreadable or damaged. Never repaired automatically.
    KeyFile(String),
    /// Bad command line.
    Usage(String),
    /// The destination address is not a usable testnet address.
    Address(String),
    /// The address holds no spendable coin.
    NoCoins(String),
    /// Not enough spendable coins for the amount plus the fee.
    InsufficientFunds { available: u64, required: u64 },
    /// The signed transaction did not pass its own signature check. This must never reach the network.
    SignatureInvalid(SignError),
    /// The node could not be reached or refused a call.
    Rpc(String),
    /// The wallet ledger could not be read or written.
    Ledger(String),
}

impl fmt::Display for WalletError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyFile(m) => write!(f, "{m}"),
            Self::Usage(m) => write!(f, "{m}"),
            Self::Address(m) => write!(f, "{m}"),
            Self::NoCoins(m) => write!(f, "{m}"),
            Self::InsufficientFunds { available, required } => write!(
                f,
                "not enough spendable coins: the amount plus the fee needs {}, only {} is spendable now",
                zthr(*required),
                zthr(*available)
            ),
            Self::SignatureInvalid(e) => write!(f, "the signed transaction failed its own signature check, so it was not sent: {e}"),
            Self::Rpc(m) => write!(f, "{m}"),
            Self::Ledger(m) => write!(f, "{m}"),
        }
    }
}

impl WalletError {
    /// 2 = usage (the caller asked for something the tool does not do), 5 = key file (matches zethora-miner),
    /// 1 = everything else.
    fn exit_code(&self) -> i32 {
        match self {
            Self::Usage(_) => 2,
            Self::KeyFile(_) => 5,
            _ => 1,
        }
    }
}

// --- key ---

/// Reads a key file's 64 hex characters. Mirrors `zethora-miner::parse_key_hex`, but here a missing file is an
/// error rather than a reason to make a new key: a new key is a different address, which looks like lost funds.
fn parse_key_hex(text: &str) -> Result<SecretKey, String> {
    let hex = text.trim();
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("expected 64 hex characters, found {} characters", hex.len()));
    }
    let bytes: Vec<u8> = (0..64).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("checked hex")).collect();
    SecretKey::from_slice(&bytes).map_err(|e| format!("not a valid secret key ({e})"))
}

fn load_key(key_file: &str) -> Result<Keypair, WalletError> {
    let text = std::fs::read_to_string(key_file).map_err(|e| {
        WalletError::KeyFile(format!(
            "cannot read the key file {key_file}: {e}. Run `zethora-miner --testnet` once to create it, and restore \
             it from a backup if this wallet ever held coins."
        ))
    })?;
    let sk = parse_key_hex(&text).map_err(|e| {
        WalletError::KeyFile(format!(
            "the key file {key_file} is damaged: {e}. It holds the key to your coins, so the wallet will not replace \
             it. Restore it from a backup."
        ))
    })?;
    Ok(Keypair::from_secret_key(SECP256K1, &sk))
}

/// The wallet's visible address on testnet (`zethoratest:...`), derived from the key the same way zethora-miner
/// derives its payout address.
fn testnet_address(key: &Keypair) -> Address {
    Address::new(Prefix::Testnet, Version::PubKey, &key.x_only_public_key().0.serialize())
}

fn zthr(zets: u64) -> String {
    format!("{:.8} ZTHR", zets as f64 / ZETS_PER_ZTHR)
}

// --- fee ---

/// The fee a transaction needs, in zets: rothschild's estimate (fee rate times the larger of the compute mass and
/// twice the serialized size). It is an estimate that errs high, so the node never refuses the result for a low
/// fee; an exact figure would mean pulling `MassCalculator` and the whole kaspa-consensus crate into this CLI.
fn required_fee(num_inputs: usize, num_outputs: u64) -> u64 {
    let serialized_bytes = 94 // plain tx: version [2] + counts [16] + locktime [8] + subnetwork id [20] + gas [8] + payload hash [32] + payload length [8]
        + 118 * (num_inputs as u64) // std input: outpoint [36] + signature script length [8] + single-signature script [66] + sequence [8]
        + 53 * num_outputs; // std output: value [8] + script public key version [2] + length [8] + max std script public key [35]
    let compute_mass = serialized_bytes
        + 1000 * (num_inputs as u64) // std input script mass (1 sigop)
        + 370 * num_outputs; // std output spk mass
    FEE_RATE * compute_mass.max(serialized_bytes * 2)
}

// --- building and signing (no network, so it can be tested) ---

/// Builds a payment to `to` out of `coins`, sends the change to `change_address` and signs with `key`.
/// The signature is checked before the result is handed back, so no unsigned or wrongly signed transaction can
/// reach the network. Nothing in here touches the network, which is what makes the tests below possible.
///
/// Returns the signed transaction and the fee it pays, in sompi. The caller must not work that fee out a second
/// time: the number here already includes any dust change folded into the fee, so it is the only figure that
/// matches the transaction that was signed. `cmd_send` prints it and writes it into the ledger unchanged.
fn build_send(
    key: &Keypair,
    change_address: &Address,
    to: &Address,
    amount: u64,
    coins: &[(TransactionOutpoint, UtxoEntry)],
) -> Result<(SignableTransaction, u64), WalletError> {
    if coins.is_empty() {
        return Err(WalletError::NoCoins(format!(
            "{} holds no spendable coin. Wait for the coins to mature, and check that the node runs with --utxoindex",
            String::from(change_address)
        )));
    }
    // Biggest coins first: that is the fewest inputs, and every input costs fee.
    let mut sorted: Vec<&(TransactionOutpoint, UtxoEntry)> = coins.iter().collect();
    sorted.sort_by_key(|coin| std::cmp::Reverse(coin.1.amount));

    let mut total: u64 = 0;
    for count in 1..=sorted.len() {
        total += sorted[count - 1].1.amount;
        let fee_with_change = required_fee(count, 2);
        let Some(needed) = amount.checked_add(fee_with_change) else {
            return Err(WalletError::InsufficientFunds { available: total, required: u64::MAX });
        };
        if total < needed {
            continue;
        }
        let spare = total - needed;
        // Dust change costs more in storage mass than it is worth, so it goes to the network instead.
        let (fee, change) = if spare >= MIN_CHANGE { (fee_with_change, spare) } else { (total - amount, 0) };

        let mut outputs =
            vec![TransactionOutput { value: amount, script_public_key: pay_to_address_script(to), covenant: None }];
        if change > 0 {
            outputs.push(TransactionOutput {
                value: change,
                script_public_key: pay_to_address_script(change_address),
                covenant: None,
            });
        }
        let chosen = &sorted[..count];
        let inputs: Vec<TransactionInput> = chosen
            .iter()
            .map(|coin| TransactionInput {
                previous_outpoint: coin.0,
                signature_script: vec![],
                sequence: 0,
                compute_commit: ComputeCommit::SigopCount(1.into()),
            })
            .collect();
        let entries: Vec<UtxoEntry> = chosen.iter().map(|coin| coin.1.clone()).collect();
        let unsigned = Transaction::new_non_finalized(TX_VERSION, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, vec![]);

        let signed = sign(MutableTransaction::with_entries(unsigned, entries), *key);
        check_signatures(&signed.as_verifiable())?;
        return Ok((signed, fee));
    }
    Err(WalletError::InsufficientFunds {
        available: total,
        required: amount.saturating_add(required_fee(sorted.len(), 2)),
    })
}

/// The last thing that happens before a transaction is handed to the node: every input must carry a signature
/// that matches its coin's public key. Deleting this call is what `send_with_mismatched_key_is_rejected` catches.
fn check_signatures(tx: &impl VerifiableTransaction) -> Result<(), WalletError> {
    verify(tx).map_err(WalletError::SignatureInvalid)
}

// --- network ---

async fn connect(node_url: &str) -> Result<GrpcClient, WalletError> {
    GrpcClient::connect(node_url.to_string()).await.map_err(|e| {
        WalletError::Rpc(format!("cannot reach the node at {node_url}: {e}. Is kaspad running with --testnet?"))
    })
}

fn rpc_hint(call: &str, e: impl fmt::Display) -> String {
    format!(
        "{call} failed: {e}. Is the node running with --testnet and --utxoindex? `balance` and `send` need \
         --utxoindex, because they ask the node which coins an address holds."
    )
}

/// The coins of `address` that consensus will accept as inputs right now, the value still maturing, and the node's
/// current DAA score. A coinbase coin needs `coinbase_maturity` blocks (100 on testnet), a regular coin is treated
/// as settled after `REGULAR_CONFIRMATIONS` blocks.
async fn spendable_coins(
    client: &GrpcClient,
    address: &Address,
) -> Result<(Vec<(TransactionOutpoint, UtxoEntry)>, u64, u64), WalletError> {
    let virtual_daa_score = client
        .get_block_dag_info()
        .await
        .map_err(|e| WalletError::Rpc(rpc_hint("get_block_dag_info", e)))?
        .virtual_daa_score;
    let utxos = client
        .get_utxos_by_addresses(vec![address.clone()])
        .await
        .map_err(|e| WalletError::Rpc(rpc_hint("get_utxos_by_addresses", e)))?;

    let maturity = TESTNET_PARAMS.coinbase_maturity();
    let mut spendable = Vec::new();
    let mut maturing: u64 = 0;
    for entry in utxos {
        let utxo = UtxoEntry::from(entry.utxo_entry);
        let wait = if utxo.is_coinbase { maturity } else { REGULAR_CONFIRMATIONS };
        if utxo.block_daa_score.saturating_add(wait) <= virtual_daa_score {
            spendable.push((TransactionOutpoint::from(entry.outpoint), utxo));
        } else {
            maturing = maturing.saturating_add(utxo.amount);
        }
    }
    Ok((spendable, maturing, virtual_daa_score))
}

fn parse_amount(text: &str) -> Result<u64, WalletError> {
    let amount: f64 = text
        .parse()
        .map_err(|_| WalletError::Usage(format!("the amount must be a number of ZTHR, for example 0.5 (got \"{text}\")")))?;
    if !amount.is_finite() || amount <= 0.0 {
        return Err(WalletError::Usage(format!("the amount must be greater than zero (got \"{text}\")")));
    }
    let zets = (amount * ZETS_PER_ZTHR).round();
    if zets < 1.0 || zets > u64::MAX as f64 {
        return Err(WalletError::Usage(format!("the amount \"{text}\" is out of range")));
    }
    Ok(zets as u64)
}

fn parse_testnet_address(text: &str) -> Result<Address, WalletError> {
    let address =
        Address::try_from(text).map_err(|e| WalletError::Address(format!("not a Zethora testnet address: \"{text}\" ({e})")))?;
    if address.prefix != Prefix::Testnet {
        return Err(WalletError::Address(format!(
            "not a Zethora testnet address: \"{text}\". A Zethora testnet address starts with zethoratest:"
        )));
    }
    Ok(address)
}

// --- commands ---

async fn cmd_balance(node_url: &str, key_file: &str) -> Result<(), WalletError> {
    let key = load_key(key_file)?;
    let address = testnet_address(&key);
    println!("Network  : testnet, node {node_url}");
    println!("Address  : {address}");
    println!("Key file : {key_file}");
    println!();

    let client = connect(node_url).await?;
    let node_balance = client
        .get_balance_by_address(address.clone())
        .await
        .map_err(|e| WalletError::Rpc(rpc_hint("get_balance_by_address", e)))?;
    let (spendable, maturing, virtual_daa_score) = spendable_coins(&client, &address).await?;
    let spendable_total: u64 = spendable.iter().map(|(_, entry)| entry.amount).sum();

    println!("Balance (node)   : {:>22}    at DAA score {virtual_daa_score}", zthr(node_balance));
    println!("  spendable now  : {:>22}    {} coin(s)", zthr(spendable_total), spendable.len());
    println!(
        "  still maturing : {:>22}    coinbase coins need {} blocks",
        zthr(maturing),
        TESTNET_PARAMS.coinbase_maturity()
    );
    if spendable_total == 0 {
        println!();
        println!("Nothing to spend yet. Mined coins mature after {} blocks - keep zethora-miner running.", TESTNET_PARAMS.coinbase_maturity());
    }
    Ok(())
}

async fn cmd_receive(key_file: &str) -> Result<(), WalletError> {
    let key = load_key(key_file)?;
    let address = testnet_address(&key);
    println!("Your Zethora testnet address:");
    println!();
    println!("    {address}");
    println!();
    println!("Key file: {key_file} (keep it safe - it controls this address)");
    Ok(())
}

/// Placeholder for the exchange bridge: it prints the transparent address an exchange would pay into, and says
/// plainly that the privacy layer is off. No bridge exists yet - nothing is generated or registered anywhere, the
/// address is just this wallet's own testnet address, so coins sent to it arrive in this wallet as usual.
async fn cmd_exchange_deposit(key_file: &str) -> Result<(), WalletError> {
    let key = load_key(key_file)?;
    let address = testnet_address(&key);
    println!("Exchange Bridge generated. Your transparent deposit address is: {address}");
    println!("NOTE: Zethora privacy is currently disabled pending audit. This address is your standard transparent address.");
    Ok(())
}

async fn cmd_send(node_url: &str, key_file: &str, to: &str, amount: &str, dry_run: bool) -> Result<(), WalletError> {
    let amount_zets = parse_amount(amount)?;
    let destination = parse_testnet_address(to)?;
    let key = load_key(key_file)?;
    let change_address = testnet_address(&key);

    println!("From     : {change_address}");
    println!("To       : {destination}");
    println!("Amount   : {}", zthr(amount_zets));
    println!();

    let client = connect(node_url).await?;
    let (coins, maturing, _) = spendable_coins(&client, &change_address).await?;
    if coins.is_empty() && maturing > 0 {
        println!("note: {} is still maturing", zthr(maturing));
    }
    // The fee comes back from build_send instead of being worked out again here: a second calculation could
    // disagree with the transaction that was actually signed, and the ledger has to record the fee that was paid.
    let (signed, fee_sompi) = build_send(&key, &change_address, &destination, amount_zets, &coins)?;
    let coins_used = signed.tx.inputs.len();
    // build_send pays the recipient first and appends the change output only when the change is not dust.
    let change_sompi = signed.tx.outputs.get(1).map(|output| output.value).unwrap_or(0);
    println!("Coins    : {coins_used} spent of {} spendable", coins.len());
    println!("Fee      : {}", zthr(fee_sompi));
    println!("Change   : {}", zthr(change_sompi));

    let mut tx = signed.tx;
    // The id is only set by finalize(), so this has to happen before it is printed or sent.
    tx.finalize();
    println!("Txid     : {}", tx.id());
    if dry_run {
        println!();
        println!("Dry run: the transaction was built and signed, and its signature was checked. Nothing was sent.");
        return Ok(());
    }

    let txid = client
        .submit_transaction((&tx).into(), false)
        .await
        .map_err(|e| WalletError::Rpc(format!("the node refused the transaction: {e}")))?;
    println!();
    println!("Sent. Transaction id: {txid}");
    println!("It shows up in your balance after one confirmation (a few seconds on testnet).");

    // The amount the user asked to pay. This is recorded directly rather than summed from the transaction's outputs,
    // because a self-send pays the recipient and the change to the same address: summing the matching outputs would
    // count the change as part of the payment.
    if let Err(e) = history::record_send(&txid.to_string(), &destination.to_string(), amount_zets, fee_sompi, now_unix()) {
        eprintln!(
            "WARN: the payment was sent, but the wallet ledger could not be written ({e}). Save this transaction id: {txid}"
        );
    }
    Ok(())
}

/// Prints what the ledger holds: the newest `limit` records, oldest first. `json` prints the raw ledger lines
/// instead of the table, which is what other tools (and the tests) read.
async fn cmd_history(limit: usize, json: bool) -> Result<(), WalletError> {
    let mut records = history::read_records().map_err(|e| WalletError::Ledger(format!("{e}")))?;
    if records.is_empty() {
        println!("No history.");
        return Ok(());
    }
    // Oldest first, so the newest records are the ones a small `--limit` keeps.
    records.sort_by_key(|record| record.timestamp_unix);
    if records.len() > limit {
        records.drain(..records.len() - limit);
    }
    if json {
        for line in history::render_json_lines(&records).map_err(WalletError::Ledger)? {
            println!("{line}");
        }
    } else {
        print!("{}", history::render_table(&records).map_err(WalletError::Ledger)?);
    }
    Ok(())
}

/// Records every coin the node reports for this wallet's address that the ledger has not seen yet. Append-only: it
/// never rewrites or removes a line, so a second run in a row discovers nothing.
async fn cmd_sync(node_url: &str, key_file: &str) -> Result<(), WalletError> {
    let key = load_key(key_file)?;
    let address = testnet_address(&key);
    let client = connect(node_url).await?;
    let utxos = all_utxos(&client, &address).await?;
    let (discovered, already_known) =
        history::sync_utxos(&address.to_string(), &utxos, now_unix()).map_err(|e| WalletError::Ledger(format!("{e}")))?;
    println!("Sync: discovered {discovered} new receive(s), {already_known} already known.");
    Ok(())
}

/// Every coin the node reports for `address`, maturing or not - `sync` records what arrived, and a coin that is
/// still maturing has very much arrived.
async fn all_utxos(client: &GrpcClient, address: &Address) -> Result<Vec<history::UtxoRef>, WalletError> {
    let utxos = client
        .get_utxos_by_addresses(vec![address.clone()])
        .await
        .map_err(|e| WalletError::Rpc(rpc_hint("get_utxos_by_addresses", e)))?;
    Ok(utxos
        .into_iter()
        .map(|entry| {
            let outpoint = TransactionOutpoint::from(entry.outpoint);
            history::UtxoRef {
                txid: outpoint.transaction_id.to_string(),
                index: outpoint.index,
                amount_sompi: UtxoEntry::from(entry.utxo_entry).amount,
            }
        })
        .collect())
}

/// Seconds since the Unix epoch, the unit every timestamp in the ledger uses.
fn now_unix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|since| since.as_secs()).unwrap_or(0)
}

// --- command line ---

const USAGE: &str = "zethora-wallet - the Zethora testnet wallet (Testnet Phase 2)

USAGE:
    zethora-wallet balance --testnet [--node <url>] [--key-file <path>]
    zethora-wallet receive --testnet [--key-file <path>]
    zethora-wallet exchange-deposit --testnet [--key-file <path>]
    zethora-wallet send <address> <amount> --testnet [--node <url>] [--key-file <path>] [--dry-run]
    zethora-wallet history [--limit <n>] [--json]
    zethora-wallet sync --testnet [--node <url>] [--key-file <path>]

OPTIONS:
    --testnet           use the Zethora testnet (required - there is no mainnet wallet yet)
    --node <url>        node gRPC endpoint (default grpc://127.0.0.1:26210)
    --key-file <path>   key file with 64 hex characters (default zethora-miner-key-testnet.txt)
    --dry-run           send: build and sign the payment, then stop without sending it
    --limit <n>         history: how many of the newest records to print (default 50)
    --json              history: print the raw ledger lines instead of the table
    -h, --help          show this help
    -V, --version       show the version

The node must run with --testnet --utxoindex, because `balance`, `send` and `sync` ask it which coins an address
holds. `history` reads a local file and needs no --testnet.

The ledger is append-only JSON lines at %APPDATA%\\Zethora\\wallet-history.jsonl, or at the path in
ZETHORA_WALLET_HISTORY_PATH.

Amounts are in ZTHR, for example:

    zethora-wallet send zethoratest:qq... 1.5 --testnet
";

struct Args {
    command: String,
    positionals: Vec<String>,
    testnet: bool,
    node_url: String,
    key_file: String,
    dry_run: bool,
    json: bool,
    limit: usize,
}

fn parse_args(argv: &[String]) -> Result<Args, WalletError> {
    let mut command = String::new();
    let mut positionals = Vec::new();
    let mut testnet = false;
    let mut node_url = TESTNET_NODE_URL.to_string();
    let mut key_file = TESTNET_KEY_FILE.to_string();
    let mut dry_run = false;
    let mut json = false;
    let mut limit = DEFAULT_HISTORY_LIMIT;

    let mut index = 0;
    while index < argv.len() {
        let arg = argv[index].as_str();
        match arg {
            "--testnet" => testnet = true,
            "--dry-run" => dry_run = true,
            "--json" => json = true,
            "--node" | "--key-file" | "--limit" => {
                let value = argv.get(index + 1).ok_or_else(|| WalletError::Usage(format!("{arg} needs a value")))?;
                match arg {
                    "--node" => node_url = value.clone(),
                    "--key-file" => key_file = value.clone(),
                    _ => limit = parse_limit(value)?,
                }
                index += 1;
            }
            _ if arg.starts_with("--node=") => node_url = arg["--node=".len()..].to_string(),
            _ if arg.starts_with("--key-file=") => key_file = arg["--key-file=".len()..].to_string(),
            _ if arg.starts_with("--limit=") => limit = parse_limit(&arg["--limit=".len()..])?,
            _ if arg.starts_with('-') => return Err(WalletError::Usage(format!("unknown option \"{arg}\""))),
            _ => {
                if command.is_empty() {
                    command = arg.to_string();
                } else {
                    positionals.push(arg.to_string());
                }
            }
        }
        index += 1;
    }
    if command.is_empty() {
        return Err(WalletError::Usage(
            "no command given. Use balance, receive, exchange-deposit, send, history or sync.".to_string(),
        ));
    }
    Ok(Args { command, positionals, testnet, node_url, key_file, dry_run, json, limit })
}

/// `--limit <n>`: how many of the newest ledger records `history` prints. A plain count, so a typo is refused
/// instead of silently printing nothing.
fn parse_limit(text: &str) -> Result<usize, WalletError> {
    text.parse::<usize>().map_err(|_| {
        WalletError::Usage(format!("--limit needs a whole number of records, for example 20 (got \"{text}\")"))
    })
}

fn expect_no_positionals(args: &Args) -> Result<(), WalletError> {
    match args.positionals.first() {
        None => Ok(()),
        Some(extra) => Err(WalletError::Usage(format!("{} takes no arguments (got \"{extra}\")", args.command))),
    }
}

async fn run(argv: &[String]) -> Result<(), WalletError> {
    if argv.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("{USAGE}");
        return Ok(());
    }
    if argv.iter().any(|arg| arg == "--version" || arg == "-V") {
        println!("zethora-wallet {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    let args = parse_args(argv)?;
    // `history` reads a file in this user's profile and never talks to a node, so it is the one command that does
    // not need --testnet. Everything that can reach the network still refuses to run without it.
    if !args.testnet && args.command != "history" {
        return Err(WalletError::Usage(
            "testnet only for now: pass --testnet. The wallet refuses to run against any other network.".to_string(),
        ));
    }
    match args.command.as_str() {
        "balance" => {
            expect_no_positionals(&args)?;
            cmd_balance(&args.node_url, &args.key_file).await
        }
        "receive" => {
            expect_no_positionals(&args)?;
            cmd_receive(&args.key_file).await
        }
        "send" => {
            let [to, amount] = args.positionals.as_slice() else {
                return Err(WalletError::Usage(
                    "send needs an address and an amount, for example: zethora-wallet send zethoratest:... 1.5 --testnet"
                        .to_string(),
                ));
            };
            cmd_send(&args.node_url, &args.key_file, to, amount, args.dry_run).await
        }
        "exchange-deposit" => {
            expect_no_positionals(&args)?;
            cmd_exchange_deposit(&args.key_file).await
        }
        "history" => {
            expect_no_positionals(&args)?;
            cmd_history(args.limit, args.json).await
        }
        "sync" => {
            expect_no_positionals(&args)?;
            cmd_sync(&args.node_url, &args.key_file).await
        }
        other => Err(WalletError::Usage(format!(
            "unknown command \"{other}\". Use balance, receive, exchange-deposit, send, history or sync."
        ))),
    }
}

#[tokio::main]
async fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = run(&argv).await {
        eprintln!("zethora-wallet: {e}");
        if matches!(e, WalletError::Usage(_)) {
            eprintln!("Try `zethora-wallet --help`.");
        }
        std::process::exit(e.exit_code());
    }
}

// --- tests ---
//
// Everything below runs offline: fixed keys, hand-made coins, no node. What they cannot prove is that the node
// accepts the transaction (that needs a running node) - everything up to and including the signature check is
// covered here.
#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::tx::TransactionId;
    use std::str::FromStr;

    const OUTPOINT_TXID: &str = "880eb9819a31821d9d2399e2f35e2433b72637e393d71ecc9b8d0250f49153c3";

    /// Deterministic keys: byte 1 is the wallet under test, byte 2 is somebody else.
    fn test_key(byte: u8) -> Keypair {
        let secret = SecretKey::from_slice(&[byte; 32]).expect("valid test key");
        Keypair::from_secret_key(SECP256K1, &secret)
    }

    /// A coin worth `amount` zets that pays to `address`.
    fn coin(index: u32, address: &Address, amount: u64) -> (TransactionOutpoint, UtxoEntry) {
        let outpoint = TransactionOutpoint { transaction_id: TransactionId::from_str(OUTPOINT_TXID).unwrap(), index };
        let entry = UtxoEntry {
            amount,
            script_public_key: pay_to_address_script(address),
            block_daa_score: 1,
            is_coinbase: false,
            covenant_id: None,
        };
        (outpoint, entry)
    }

    fn wallet_coins(address: &Address) -> Vec<(TransactionOutpoint, UtxoEntry)> {
        vec![coin(0, address, 5_000_000_000), coin(1, address, 3_000_000_000), coin(2, address, 100_000_000)]
    }

    #[test]
    fn valid_transaction_passes_signature_check() {
        let key = test_key(1);
        let address = testnet_address(&key);
        let destination = testnet_address(&test_key(2));

        let (signed, _fee) = build_send(&key, &address, &destination, 2_000_000_000, &wallet_coins(&address)).expect("a valid payment");
        check_signatures(&signed.as_verifiable()).expect("the signature must verify");

        assert!(signed.tx.inputs.iter().all(|input| !input.signature_script.is_empty()), "every input must be signed");
        assert_eq!(signed.tx.outputs[0].value, 2_000_000_000);
        assert_eq!(signed.tx.outputs[0].script_public_key, pay_to_address_script(&destination));
    }

    #[test]
    fn tampered_output_fails_signature_check() {
        let key = test_key(1);
        let address = testnet_address(&key);
        let destination = testnet_address(&test_key(2));

        let (mut signed, _fee) = build_send(&key, &address, &destination, 1_000_000_000, &wallet_coins(&address)).unwrap();
        signed.tx.outputs[0].value = 999_000_000_000;

        let err = check_signatures(&signed.as_verifiable()).expect_err("a changed output must not verify");
        assert!(matches!(err, WalletError::SignatureInvalid(_)), "expected a signature error, got {err:?}");
    }

    #[test]
    fn missing_signature_fails_signature_check() {
        let key = test_key(1);
        let address = testnet_address(&key);

        let (mut signed, _fee) = build_send(&key, &address, &address, 1_000_000_000, &wallet_coins(&address)).unwrap();
        signed.tx.inputs[0].signature_script.clear();

        let err = check_signatures(&signed.as_verifiable()).expect_err("an unsigned input must not verify");
        let message = err.to_string();
        assert!(message.contains("Signature is empty for input: 0"), "unexpected message: {message}");
    }

    /// The fail-when-removed test. These coins pay to one key, but the transaction is signed with another, so no
    /// signature can match the coins' public key. `build_send` must refuse to hand such a transaction back. If the
    /// `check_signatures(&signed.as_verifiable())?` line in `build_send` is deleted, `build_send` returns Ok and this
    /// test fails - which is exactly what it is here for.
    #[test]
    fn send_with_mismatched_key_is_rejected() {
        let owner = test_key(1);
        let owner_address = testnet_address(&owner);
        let foreigner = test_key(2);
        let foreigner_address = testnet_address(&foreigner);

        let result = build_send(&foreigner, &foreigner_address, &foreigner_address, 1_000_000_000, &wallet_coins(&owner_address));
        match result {
            Err(WalletError::SignatureInvalid(_)) => {}
            Err(other) => panic!("expected the signature check to reject coins of another key, got {other:?}"),
            Ok((signed, _fee)) => panic!(
                "build_send returned a transaction signed by the wrong key ({} inputs): the signature check before \
                 submission is gone",
                signed.tx.inputs.len()
            ),
        }
    }

    #[test]
    fn finalized_transaction_has_a_real_id() {
        let key = test_key(1);
        let address = testnet_address(&key);
        let destination = testnet_address(&test_key(2));

        let (signed, _fee) = build_send(&key, &address, &destination, 1_000_000_000, &wallet_coins(&address)).unwrap();
        let mut tx = signed.tx;
        assert!(tx.id().to_string().chars().all(|c| c == '0'), "a non-finalized transaction carries the all-zero placeholder");
        // The wallet finalizes before printing the id or submitting, otherwise it would report a zero txid.
        tx.finalize();
        assert!(!tx.id().to_string().chars().all(|c| c == '0'), "a finalized transaction must have a real id");
    }

    #[test]
    fn send_conserves_value() {
        let key = test_key(1);
        let address = testnet_address(&key);
        let destination = testnet_address(&test_key(2));
        let coins = wallet_coins(&address);
        let total: u64 = coins.iter().map(|(_, entry)| entry.amount).sum();

        let (signed, fee) = build_send(&key, &address, &destination, 1_000_000_000, &coins).unwrap();
        // The wallet spends the largest coins first, so the input side is the `coins_used` largest ones.
        let coins_used = signed.tx.inputs.len();
        let change = signed.tx.outputs.get(1).map(|output| output.value).unwrap_or(0);
        let mut amounts: Vec<u64> = coins.iter().map(|(_, entry)| entry.amount).collect();
        amounts.sort_unstable_by(|a, b| b.cmp(a));
        let spent: u64 = amounts[..coins_used].iter().sum();

        assert_eq!(spent, 1_000_000_000 + fee + change, "no zet may be created or lost");
        assert!(spent <= total, "the wallet must not spend more than the address holds");
        assert!(fee >= required_fee(coins_used, 2), "the fee must cover the mass");
        assert_eq!(signed.tx.outputs.len(), 2, "a payment and a change output");
        assert!(change >= MIN_CHANGE, "change must never be dust");
    }

    #[test]
    fn dust_change_goes_to_the_fee() {
        let key = test_key(1);
        let address = testnet_address(&key);
        let destination = testnet_address(&test_key(2));
        // One coin that would leave less than MIN_CHANGE behind: the wallet must not create a dust output.
        let dust = MIN_CHANGE / 2;
        let coins = vec![coin(0, &address, 1_000_000_000 + required_fee(1, 2) + dust)];

        let (signed, fee) = build_send(&key, &address, &destination, 1_000_000_000, &coins).unwrap();
        assert_eq!(signed.tx.outputs.len(), 1, "a dust change output must not be created");
        assert_eq!(fee, required_fee(1, 2) + dust);
        assert!(fee >= required_fee(1, 1), "a single output needs less mass, so the fee still covers it");
    }

    #[test]
    fn sending_more_than_the_address_holds_is_refused() {
        let key = test_key(1);
        let address = testnet_address(&key);
        let destination = testnet_address(&test_key(2));
        let coins = wallet_coins(&address);

        let result = build_send(&key, &address, &destination, 9_000_000_000, &coins);
        assert!(matches!(result, Err(WalletError::InsufficientFunds { .. })), "expected insufficient funds, got {result:?}");
    }

    #[test]
    fn key_file_must_hold_64_hex_characters() {
        assert!(parse_key_hex(&"11".repeat(32)).is_ok());
        assert!(parse_key_hex("").is_err(), "an empty file is not a key");
        assert!(parse_key_hex(&"11".repeat(31)).is_err(), "too short");
        assert!(parse_key_hex(&"zz".repeat(32)).is_err(), "not hex");
    }

    #[test]
    fn addresses_are_zethora_testnet_addresses() {
        let key = test_key(1);
        let address = testnet_address(&key);
        assert!(String::from(&address).starts_with("zethoratest:"), "unexpected prefix: {address}");
        assert_eq!(address, parse_testnet_address(&String::from(&address)).unwrap());

        let mainnet = Address::new(Prefix::Mainnet, Version::PubKey, &key.x_only_public_key().0.serialize());
        assert!(parse_testnet_address(&String::from(&mainnet)).is_err(), "a mainnet address must be refused");
        assert!(parse_testnet_address("not an address").is_err());
    }

    #[test]
    fn amounts_are_parsed_as_zthr() {
        assert_eq!(parse_amount("1").unwrap(), 10_000_000_000);
        assert_eq!(parse_amount("0.5").unwrap(), 5_000_000_000);
        assert_eq!(parse_amount("0.0000000001").unwrap(), 1, "one zet");
        assert!(parse_amount("0").is_err());
        assert!(parse_amount("-1").is_err());
        assert!(parse_amount("soon").is_err());
    }
}







