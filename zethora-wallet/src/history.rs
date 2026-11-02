//! The wallet's own ledger: one JSON object per line, append-only.
//!
//! A wallet that forgets what it sent is dangerous, because the transaction id is the only proof that a payment
//! ever left. So every payment is written here once, as a single self-contained line, and this module only ever
//! appends: nothing truncates, rewrites or deletes a record. A crash in the middle of a write can cost at most the
//! line that was being written; the lines before it stay readable.
//!
//! Path: `%APPDATA%\Zethora\wallet-history.jsonl`, or the absolute path in `ZETHORA_WALLET_HISTORY_PATH` when that
//! variable is set. The integration tests set the variable, so they never read or write a real user's ledger.
//!
//! This file is also the crate root of the `zethora_wallet` library, which is what `tests/history.rs` calls: a
//! binary target cannot be imported by an integration test, and the ledger has to be testable without a node.

#![allow(clippy::arithmetic_side_effects)]

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::Write;
use std::path::PathBuf;

/// The environment variable that overrides the ledger path. The value must be an absolute path.
pub const HISTORY_PATH_ENV: &str = "ZETHORA_WALLET_HISTORY_PATH";
/// The schema version stamped into every record this wallet writes.
pub const SCHEMA_VERSION: u32 = 1;
/// `"type"` of a payment this wallet sent.
pub const TYPE_SEND: &str = "send";
/// `"type"` of a coin that arrived at this wallet's address.
pub const TYPE_RECEIVE: &str = "receive";

/// One line of the ledger.
///
/// `amountSompi` and `feeSompi` are decimal *strings*, not JSON numbers: a u64 above 2^53 cannot survive a trip
/// through a JSON number in every reader, and the ledger is the one place where a rounded amount would be a lie.
/// Unknown fields are ignored (`deny_unknown_fields` is deliberately not set), so a record written by a newer
/// wallet still reads here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryRecord {
    /// Schema version, always [`SCHEMA_VERSION`] for records this code writes.
    pub v: u32,
    /// [`TYPE_SEND`] or [`TYPE_RECEIVE`]; serialized as `"type"`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Hex transaction id.
    pub txid: String,
    /// For a send, the recipient. For a receive, this wallet's own address.
    pub address: String,
    /// Sompi as a decimal string.
    pub amount_sompi: String,
    /// Sompi as a decimal string. Always `"0"` for a receive: the sender paid the fee.
    pub fee_sompi: String,
    pub timestamp_unix: u64,
    pub confirmed: bool,
    /// `"<txid>:<index>"`, set on receives only: it is what makes a second `sync` a no-op.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outpoint: Option<String>,
    /// `true` for a receive that `sync` found after the fact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backfilled: Option<bool>,
}

impl HistoryRecord {
    /// A payment this wallet sent. `confirmed` starts false: the node accepted it, no block has carried it yet.
    pub fn send(txid: &str, address: &str, amount_sompi: u64, fee_sompi: u64, timestamp_unix: u64) -> Self {
        Self {
            v: SCHEMA_VERSION,
            kind: TYPE_SEND.to_string(),
            txid: txid.to_string(),
            address: address.to_string(),
            amount_sompi: amount_sompi.to_string(),
            fee_sompi: fee_sompi.to_string(),
            timestamp_unix,
            confirmed: false,
            outpoint: None,
            backfilled: None,
        }
    }

    /// A coin that arrived at this wallet's address. A coin the node reports sits in a block, so `confirmed` is true.
    pub fn receive(txid: &str, address: &str, amount_sompi: u64, timestamp_unix: u64, outpoint: &str, backfilled: bool) -> Self {
        Self {
            v: SCHEMA_VERSION,
            kind: TYPE_RECEIVE.to_string(),
            txid: txid.to_string(),
            address: address.to_string(),
            amount_sompi: amount_sompi.to_string(),
            fee_sompi: 0.to_string(),
            timestamp_unix,
            confirmed: true,
            outpoint: Some(outpoint.to_string()),
            backfilled: Some(backfilled),
        }
    }

    pub fn is_receive(&self) -> bool {
        self.kind == TYPE_RECEIVE
    }

    /// The amount in sompi. A line whose `amountSompi` is not a plain u64 is damaged, and the caller has to say so
    /// rather than print a number nobody wrote.
    pub fn amount_in_sompi(&self) -> Result<u64, String> {
        self.amount_sompi
            .parse::<u64>()
            .map_err(|e| format!("amountSompi \"{}\" is not a whole number of sompi: {e}", self.amount_sompi))
    }

    /// The fee in sompi, read as strictly as [`Self::amount_in_sompi`].
    pub fn fee_in_sompi(&self) -> Result<u64, String> {
        self.fee_sompi
            .parse::<u64>()
            .map_err(|e| format!("feeSompi \"{}\" is not a whole number of sompi: {e}", self.fee_sompi))
    }
}

/// Where the ledger lives: the `ZETHORA_WALLET_HISTORY_PATH` override when it is set and non-empty, otherwise
/// `%APPDATA%\Zethora\wallet-history.jsonl`. The parent folder is created here, because every caller is about to
/// write to it. A folder that cannot be created is reported when the write is attempted: this function has no way
/// to report it, and not returning the path at all would be worse than returning one that does not work yet.
pub fn history_path() -> PathBuf {
    let path = match std::env::var_os(HISTORY_PATH_ENV) {
        Some(value) if !value.is_empty() => PathBuf::from(value),
        _ => default_history_path(),
    };
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    path
}

/// `%APPDATA%\Zethora\wallet-history.jsonl`. With no `APPDATA` (a service account, a stripped environment) the temp
/// folder is the only writable place left, so the ledger goes there instead of quietly going nowhere.
fn default_history_path() -> PathBuf {
    let base = std::env::var_os("APPDATA").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
    base.join("Zethora").join("wallet-history.jsonl")
}

/// Appends one record as one line. The file is opened append-only, so a record that is already there is never
/// touched; the flush is what makes the line survive a crash straight after the node accepted a payment.
pub fn append_record(record: &HistoryRecord) -> std::io::Result<()> {
    let path = history_path();
    let line = serde_json::to_string(record).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("cannot write the record as one JSON line: {e}"))
    })?;
    let mut file = std::fs::OpenOptions::new().create(true).append(true).open(&path).map_err(|e| {
        std::io::Error::new(e.kind(), format!("cannot open the wallet ledger {}: {e}", path.display()))
    })?;
    writeln!(file, "{line}")?;
    file.flush()?;
    Ok(())
}

/// Every record in the ledger, in the order they were written. A ledger that does not exist yet is empty, not an
/// error: a fresh wallet has simply never paid or synced. A line that is not a record is an error, because skipping
/// it would hide a payment.
pub fn read_records() -> std::io::Result<Vec<HistoryRecord>> { 
    
    let path = history_path();
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(std::io::Error::new(e.kind(), format!("cannot read the wallet ledger {}: {e}", path.display())));
        }
    };
    let mut records = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let record: HistoryRecord = serde_json::from_str(line).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{}:{}: not a wallet-history record: {e}", path.display(), index + 1),
            )
        })?;
        records.push(record);
    }
    Ok(records)
}

/// The outpoints of every receive already in the ledger: the set `sync` checks a coin against before writing it
/// down a second time.
pub fn seen_outpoints() -> std::io::Result<HashSet<String>> {
    let mut seen = HashSet::new();
    for record in read_records()? {
        if record.is_receive() {
            if let Some(outpoint) = record.outpoint {
                if !outpoint.is_empty() {
                    seen.insert(outpoint);
                }
            }
        }
    }
    Ok(seen)
}

/// Writes the one line that records a payment this wallet sent. `cmd_send` calls exactly this once the node has
/// accepted the transaction, so the arguments are already final: txid as the node reported it, the sompi that
/// actually went to the recipient, and the fee `build_send` charged.
pub fn record_send(txid: &str, address: &str, amount_sompi: u64, fee_sompi: u64, timestamp_unix: u64) -> std::io::Result<()> {
    append_record(&HistoryRecord::send(txid, address, amount_sompi, fee_sompi, timestamp_unix))
}

/// A coin the node reports for the wallet's address. Deliberately free of gRPC types, so `sync` can be tested with a
/// fixture list and no node at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtxoRef {
    pub txid: String,
    pub index: u32,
    pub amount_sompi: u64,
}

impl UtxoRef {
    /// The dedupe key, exactly the `outpoint` field of a receive record: `"<txid>:<index>"`.
    pub fn outpoint(&self) -> String {
        format!("{}:{}", self.txid, self.index)
    }
}

/// Appends one receive record for every utxo whose outpoint is not in `known`, and returns
/// `(discovered, already_known)`. Existing lines are never rewritten: a coin that is already written down is only
/// counted, never appended twice, and `known` is extended in memory as coins are written so a list that repeats a
/// coin cannot write it twice in one run.
pub fn record_new_receives(
    address: &str,
    utxos: &[UtxoRef],
    known: &HashSet<String>,
    timestamp_unix: u64,
) -> std::io::Result<(usize, usize)> {
    let mut seen = known.clone();
    let mut discovered = 0usize;
    let mut already_known = 0usize;
    for utxo in utxos {
        let outpoint = utxo.outpoint();
        if seen.contains(&outpoint) {
            already_known += 1;
            continue;
        }
        append_record(&HistoryRecord::receive(&utxo.txid, address, utxo.amount_sompi, timestamp_unix, &outpoint, true))?;
        seen.insert(outpoint);
        discovered += 1;
    }
    Ok((discovered, already_known))
}

/// The whole ledger side of the `sync` command: read what is already known, append what is missing. Nothing here
/// talks to a node, and nothing here deletes or rewrites a line.
pub fn sync_utxos(address: &str, utxos: &[UtxoRef], timestamp_unix: u64) -> std::io::Result<(usize, usize)> {
    let known = seen_outpoints()?;
    record_new_receives(address, utxos, &known, timestamp_unix)
}

/// Sompi as ZTHR text with exactly 8 decimals. Integer arithmetic, so an amount is never rounded by a float: 2^53
/// sompi is only 90 million ZTHR, and above that a float would already be printing the wrong number.
pub fn zthr_text(sompi: u64) -> String {
    format!("{}.{:08}", sompi / 100_000_000, sompi % 100_000_000)
}

/// Unix seconds as `YYYY-MM-DDTHH:MM:SSZ`, UTC. The calendar arithmetic is the civil-from-days algorithm, which is a
/// dozen lines, against a date crate the wallet does not otherwise need.
pub fn iso8601_utc(timestamp_unix: u64) -> String {
    let (year, month, day) = civil_from_days((timestamp_unix / 86_400) as i64);
    let seconds_of_day = timestamp_unix % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds_of_day / 3_600,
        (seconds_of_day % 3_600) / 60,
        seconds_of_day % 60
    )
}

/// Days since 1970-01-01 to (year, month, day): Howard Hinnant's `civil_from_days`, exact for every day a u64
/// timestamp can name.
fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let shifted = days_since_epoch + 719_468;
    let era = if shifted >= 0 { shifted } else { shifted - 146_096 } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 { month_prime + 3 } else { month_prime - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    (year, month as u32, day as u32)
}

/// One table line. The header and every row go through this, so the columns cannot drift apart.
fn history_line(time: &str, kind: &str, amount: &str, fee: &str, txid: &str, confirmed: &str) -> String {
    format!("{time:<20}  {kind:<7}  {amount:>16}  {fee:>16}  {txid:<16}  {confirmed}")
}

/// The `history` table: a header plus one line per record, in the order given.
pub fn render_table(records: &[HistoryRecord]) -> Result<String, String> {
    let mut table = String::new();
    table.push_str(&history_line("TIME", "TYPE", "AMOUNT ZTHR", "FEE ZTHR", "TXID", "CONFIRMED"));
    table.push('\n');
    for record in records {
        let txid: String = record.txid.chars().take(16).collect();
        table.push_str(&history_line(
            &iso8601_utc(record.timestamp_unix),
            &record.kind,
            &zthr_text(record.amount_in_sompi()?),
            &zthr_text(record.fee_in_sompi()?),
            &txid,
            if record.confirmed { "Y" } else { "N" },
        ));
        table.push('\n');
    }
    Ok(table)
}

/// The `--json` output: one JSON line per record, in the order given, which is what the ledger holds.
pub fn render_json_lines(records: &[HistoryRecord]) -> Result<Vec<String>, String> {
    records
        .iter()
        .map(|record| serde_json::to_string(record).map_err(|e| format!("cannot write a record as one JSON line: {e}")))
        .collect()
}



