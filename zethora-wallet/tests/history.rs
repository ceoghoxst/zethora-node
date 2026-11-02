//! Integration tests for the wallet ledger: `zethora-wallet history` and `zethora-wallet sync`.
//!
//! Every test points `ZETHORA_WALLET_HISTORY_PATH` at its own file in the temp folder, so nothing in the user's
//! profile is read or written. The variable is process-wide and the tests run on parallel threads, so each test
//! holds `LEDGER_LOCK` from the moment it sets the variable until it is done.
//!
//! Run with: cargo test -p zethora-wallet --test history -- --nocapture

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};
use zethora_wallet::{
    HISTORY_PATH_ENV, HistoryRecord, UtxoRef, append_record, history_path, read_records, record_send, sync_utxos,
};

/// Serializes the tests: the ledger path is process-wide state.
static LEDGER_LOCK: Mutex<()> = Mutex::new(());

/// A test's own ledger file, removed when the test ends.
struct Ledger {
    path: PathBuf,
    _guard: MutexGuard<'static, ()>,
}

/// Takes the process-wide ledger path for `name` and points it at an empty file. The file does not exist yet: that
/// is the state a fresh wallet is in, and `read_records` has to answer that with an empty ledger, not an error.
fn ledger(name: &str) -> Ledger {
    let guard = LEDGER_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let path = std::env::temp_dir().join(format!("zethora-wallet-history-{}-{name}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&path);
    // Safe here because LEDGER_LOCK serializes the tests and nothing else in this process touches the variable.
    unsafe {
        std::env::set_var(HISTORY_PATH_ENV, &path);
    }
    assert_eq!(history_path(), path, "the override must be the path the ledger uses");
    Ledger { path, _guard: guard }
}

impl Drop for Ledger {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// A real `zethoratest:` address for the fixtures, derived from a fixed key exactly the way the wallet derives its
/// own, so the records hold strings this network could really produce.
fn address(byte: u8) -> String {
    use kaspa_addresses::{Address, Prefix, Version};
    use secp256k1::{Keypair, SECP256K1, SecretKey};

    let secret = SecretKey::from_slice(&[byte; 32]).expect("a valid test key");
    let key = Keypair::from_secret_key(SECP256K1, &secret);
    String::from(&Address::new(Prefix::Testnet, Version::PubKey, &key.x_only_public_key().0.serialize()))
}

/// A 64 hex character transaction id built from a readable prefix. The ledger stores ids as strings, so a prefix
/// plus zero padding is enough to make a fixture that is exact and easy to spot in a failure message.
fn txid(prefix: &str) -> String {
    let mut id = prefix.to_string();
    while id.len() < 64 {
        id.push('0');
    }
    assert_eq!(id.len(), 64, "a transaction id is 64 hex characters");
    id
}

fn lines_of(ledger: &Ledger) -> usize {
    std::fs::read_to_string(&ledger.path).expect("the ledger must exist").lines().count()
}

/// TEST A, fail-when-removed.
///
/// `cmd_send` cannot run without a node, so the record is written through the exact function `cmd_send` calls the
/// moment the node accepts a payment: `history::record_send(txid, recipient, paid_sompi, fee_sompi, now)`. Delete
/// the `append_record` call inside `record_send` and this test fails with `left: 0, right: 1`.
/// `cmd_send_wiring_is_present` guards the call site itself.
#[test]
fn a_send_is_persisted_as_exactly_one_correct_record() {
    let ledger = ledger("a-send");
    let recipient = address(2);
    let send_txid = txid("aa");

    record_send(&send_txid, &recipient, 100_000_000, 500, 1_700_000_000).expect("the ledger must accept a send");

    let records = read_records().expect("the ledger must be readable");
    assert_eq!(records.len(), 1, "one payment must produce exactly one record");
    let record = &records[0];
    assert_eq!(record.v, 1);
    assert_eq!(record.kind, "send");
    assert_eq!(record.txid, send_txid);
    assert_eq!(record.address, recipient);
    assert_eq!(record.amount_sompi, "100000000");
    assert_eq!(record.fee_sompi, "500");
    assert_eq!(record.timestamp_unix, 1_700_000_000);
    assert_eq!(record.confirmed, false, "a fresh send has no confirmation yet");
    assert_eq!(record.outpoint, None, "only a receive carries an outpoint");
    assert_eq!(record.backfilled, None, "a send is written down as it happens");
    assert_eq!(lines_of(&ledger), 1, "one record is one line");
}

/// The static half of TEST A: `cmd_send` needs a live node, so its body is
/// checked here. This fails if the send is no longer written down, or if
/// `cmd_send` starts computing the fee a second time instead of using the one
/// `build_send` returned.
///
/// **Fail-when-removed proof:** comment out the `if let Err(e) =
/// history::record_send(...)` call inside `cmd_send`, save, run this test — it
/// must fail with "cmd_send must write exactly one send record (uncommented)".
/// The comment-strip below is what makes that proof real: a naive substring
/// count would still see the call in the commented-out line.
#[test]
fn cmd_send_wiring_is_present() {
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"))
        .expect("main.rs must be readable");
    let start = source.find("async fn cmd_send(").expect("cmd_send must exist");
    let rest = &source[start..];
    let end = rest.find("\nasync fn cmd_history(").expect("cmd_send must come before cmd_history");
    let body = &rest[..end];

    // Strip line comments so a commented-out call cannot count as a live one.
    let live: String = body
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    assert_eq!(
        live.matches("history::record_send(").count(),
        1,
        "cmd_send must write exactly one send record (uncommented)"
    );
    assert_eq!(
        live.matches("build_send(").count(),
        1,
        "cmd_send must take the fee from build_send"
    );
    assert_eq!(
        live.matches("required_fee(").count(),
        0,
        "cmd_send must not recompute the fee that build_send returned"
    );
}
/// TEST B, fail-when-removed. Runs the real binary (`history --json`) and counts what it prints. Make
/// `read_records` return `Vec::new()` and this test fails with `left: 0, right: 3`.
#[test]
fn history_json_prints_exactly_what_is_in_the_ledger() {
    let ledger = ledger("b-history");
    let own = address(1);
    let other = address(2);
    let send_txid = txid("aa");
    let receive_a = txid("bb");
    let receive_b = txid("cc");

    append_record(&HistoryRecord::send(&send_txid, &other, 100_000_000, 500, 1_700_000_000)).unwrap();
    append_record(&HistoryRecord::receive(&receive_a, &own, 250_000_000, 1_700_000_100, &format!("{receive_a}:1"), true)).unwrap();
    append_record(&HistoryRecord::receive(&receive_b, &own, 75_000_000, 1_700_000_200, &format!("{receive_b}:2"), true)).unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_zethora-wallet"))
        .args(["history", "--json"])
        .env(HISTORY_PATH_ENV, &ledger.path)
        .output()
        .expect("the wallet binary must start");
    assert!(output.status.success(), "history must exit 0, stderr was: {}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8(output.stdout).expect("history prints UTF-8");
    let lines: Vec<&str> = stdout.lines().filter(|line| !line.is_empty()).collect();
    assert_eq!(lines.len(), 3, "three records must print three lines, got: {stdout:?}");

    let parsed: Vec<HistoryRecord> =
        lines.iter().map(|line| serde_json::from_str(line).expect("every line must be one record")).collect();
    assert_eq!(
        parsed.iter().map(|record| record.txid.clone()).collect::<Vec<String>>(),
        vec![send_txid, receive_a, receive_b],
        "the records must come back in the order they were written"
    );
    assert_eq!(parsed.iter().map(|record| record.amount_in_sompi().unwrap()).sum::<u64>(), 425_000_000);
    assert_eq!(parsed.iter().map(|record| record.fee_in_sompi().unwrap()).sum::<u64>(), 500);
    assert_eq!(parsed.iter().filter(|record| record.kind == "send").count(), 1);
    assert_eq!(parsed.iter().filter(|record| record.kind == "receive").count(), 2);
}

/// `--limit 2` keeps the two newest records, oldest first.
#[test]
fn history_limit_keeps_the_newest_records() {
    let ledger = ledger("b-limit");
    let own = address(1);
    let send_txid = txid("aa");
    let receive_a = txid("bb");
    let receive_b = txid("cc");

    append_record(&HistoryRecord::send(&send_txid, &own, 100_000_000, 500, 1_700_000_000)).unwrap();
    append_record(&HistoryRecord::receive(&receive_a, &own, 250_000_000, 1_700_000_100, &format!("{receive_a}:1"), true)).unwrap();
    append_record(&HistoryRecord::receive(&receive_b, &own, 75_000_000, 1_700_000_200, &format!("{receive_b}:2"), true)).unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_zethora-wallet"))
        .args(["history", "--json", "--limit", "2"])
        .env(HISTORY_PATH_ENV, &ledger.path)
        .output()
        .expect("the wallet binary must start");
    assert!(output.status.success(), "history must exit 0, stderr was: {}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8(output.stdout).expect("history prints UTF-8");
    let lines: Vec<&str> = stdout.lines().filter(|line| !line.is_empty()).collect();
    assert_eq!(lines.len(), 2, "--limit 2 must print two lines, got: {stdout:?}");
    let parsed: Vec<HistoryRecord> =
        lines.iter().map(|line| serde_json::from_str(line).expect("every line must be one record")).collect();
    assert_eq!(parsed.iter().map(|record| record.txid.clone()).collect::<Vec<String>>(), vec![receive_a, receive_b]);
}

/// An empty ledger is not an error, in either command: `history` prints "No history." and exits 0, and the ledger
/// side of `sync` does nothing and succeeds. `sync` as a whole still needs the node it asks for coins.
#[test]
fn history_and_sync_succeed_on_an_empty_ledger() {
    let ledger = ledger("empty");
    let own = address(1);

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_zethora-wallet"))
        .args(["history"])
        .env(HISTORY_PATH_ENV, &ledger.path)
        .output()
        .expect("the wallet binary must start");
    assert!(output.status.success(), "history must exit 0, stderr was: {}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(String::from_utf8(output.stdout).expect("history prints UTF-8").trim_end(), "No history.");
    assert_eq!(ledger.path.exists(), false, "reading an empty ledger must not create it");

    assert_eq!(sync_utxos(&own, &[], 1_700_000_000).unwrap(), (0, 0), "no coins, nothing discovered, nothing known");
    assert_eq!(read_records().unwrap().len(), 0, "an empty sync must not write a line");
    assert_eq!(ledger.path.exists(), false, "the ledger side of sync must not create the file either");
}

/// TEST C: one record per outpoint, however often `sync` runs. The utxo list is a fixture, so no node is involved:
/// the coin the ledger already knows is only counted, the new one is written once, and the second run finds nothing.
#[test]
fn sync_dedupes_by_outpoint_with_exact_counts() {
    let _ledger = ledger("c-sync");
    let own = address(1);
    let first = txid("deadbeef");
    let second = txid("beef");
    let first_outpoint = format!("{first}:0");
    let second_outpoint = format!("{second}:3");

    append_record(&HistoryRecord::receive(&first, &own, 42_000_000, 1_700_000_000, &first_outpoint, true)).unwrap();
    assert_eq!(read_records().unwrap().len(), 1);

    let known_coin = UtxoRef { txid: first.clone(), index: 0, amount_sompi: 42_000_000 };
    assert_eq!(
        sync_utxos(&own, std::slice::from_ref(&known_coin), 1_700_000_100).unwrap(),
        (0, 1),
        "the coin is already written down"
    );
    assert_eq!(read_records().unwrap().len(), 1, "a known coin must not be written a second time");

    let new_coin = UtxoRef { txid: second.clone(), index: 3, amount_sompi: 7_500_000 };
    assert_eq!(sync_utxos(&own, &[known_coin.clone(), new_coin.clone()], 1_700_000_200).unwrap(), (1, 1));

    let records = read_records().unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[1].kind, "receive");
    assert_eq!(records[1].txid, second);
    assert_eq!(records[1].address, own);
    assert_eq!(records[1].amount_sompi, "7500000");
    assert_eq!(records[1].fee_sompi, "0");
    assert_eq!(records[1].outpoint, Some(second_outpoint));
    assert_eq!(records[1].backfilled, Some(true));
    assert_eq!(records[1].confirmed, true);
    assert_eq!(records[1].timestamp_unix, 1_700_000_200);

    assert_eq!(sync_utxos(&own, &[known_coin, new_coin], 1_700_000_300).unwrap(), (0, 2), "a second run discovers nothing");
    assert_eq!(read_records().unwrap().len(), 2, "sync never appends a coin twice");
}


