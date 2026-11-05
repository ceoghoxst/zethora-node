//! zethora-faucet: the Zethora testnet faucet.
//!
//! A small web page (index.html) in front of `zethora-wallet send <address> 1.0 --testnet`: type a `zethoratest:`
//! address, press the button, get 1 ZTHR and the transaction id.
//!
//! Run it from the repository root, with the node running with `--testnet --utxoindex` and a funded faucet key:
//!
//!     cargo run --manifest-path zethora-faucet/Cargo.toml
//!
//! then open <http://127.0.0.1:8080>. Configuration is by environment variable only (see README.md):
//! `ZETHORA_FAUCET_ADDR` (listen address), `ZETHORA_WALLET` (path to the wallet executable), `ZETHORA_FAUCET_KEY_FILE`
//! (the key the faucet pays from) and `ZETHORA_FAUCET_NODE` (the node the wallet talks to).
//!
//! This crate is not a member of the Zethora workspace: it is a standalone helper and never touches the node's
//! Cargo.toml. It shells out to the wallet exactly as a user would, so it needs no Zethora crates at build time.
//!
//! # Hardening
//!
//! The faucet hands out real (if worthless) coins, so every path that spends one is written to be un-spammable. The
//! adversarial test suite in `tests/attack_tests.rs` attacks each of these properties over a real socket; the notes
//! below say which line of defence each test is pinning down.
//!
//! * Claims are **reserved** before the wallet runs (see [`AppState::try_claim`]), so N simultaneous requests for one
//!   address get exactly one send. A cooldown that is only checked *before* an `await` is not a rate limit.
//! * Addresses are matched against one compiled `^zethoratest:[a-z0-9]{20,128}$` grammar and are handed to the wallet
//!   as a single argument, never through a shell.
//! * No client header (`X-Forwarded-For`, `X-Real-IP`) can influence a cooldown or a budget: the limits are keyed by
//!   address, never by an IP the caller can write.
//! * Bodies, headers and claim output all have hard byte caps (see `MAX_*` below), so nothing a caller sends can make
//!   the process allocate without bound.
//!
//! The whole program lives in this one file, which is built twice: as the `zethora-faucet` binary, and as the
//! `zethora_faucet` library that `tests/attack_tests.rs` links against to mount [`router`] on a real socket. Anything
//! only `main` reaches for is therefore dead code *from the library's point of view* while being very much alive in
//! the binary, so the dead-code lint is not allowed to fire on the shared file.

#![allow(clippy::arithmetic_side_effects)]
#![allow(dead_code)]

use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    pin::Pin,
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{process::Command, sync::Mutex};
use tower_http::services::ServeDir;

/// The port the faucet listens on.
const LISTEN_PORT: u16 = 8080;
/// How much one claim pays, in ZTHR.
const CLAIM_AMOUNT: &str = "1.0";
/// The wallet executable, relative to the current folder unless `ZETHORA_WALLET` names one.
const WALLET_EXE: &str = "zethora-wallet.exe";
/// The key the faucet pays from, relative to the current folder unless `ZETHORA_FAUCET_KEY_FILE` names one.
const KEY_FILE: &str = "zethora-miner-key-testnet.txt";
/// A wallet run that takes longer than this is killed and reported as a failure: a hung claim must never hold the
/// request (or the queue) open forever.
const CLAIM_TIMEOUT: Duration = Duration::from_secs(2 * 60);
/// One claim per address per this many seconds, so a single address cannot drain the faucet with a script.
const CLAIM_COOLDOWN: Duration = Duration::from_secs(60 * 60);
/// The longest `zethoratest:` address that is accepted. A real address is 68 characters; the slack is for the
/// payload lengths other testnet key shapes produce. Anything longer is refused before it is stored, compared or
/// passed on, which is what keeps a 1 MB "address" from costing 1 MB of table.
const MAX_ADDRESS_BYTES: usize = 160;
/// A request body larger than this is refused before it is parsed.
const MAX_BODY_BYTES: usize = 4 * 1024;
/// A request head larger than this is refused before it is buffered, so a flood of headers cannot grow the process.
const MAX_HEADER_BYTES: usize = 16 * 1024;
/// The most a claim run will ever read back from the wallet. A wallet that prints a gigabyte of output is stopped
/// here instead of being buffered in full.
const MAX_WALLET_OUTPUT_BYTES: usize = 64 * 1024;
/// The most claims that may be in flight at once. Every claim holds the faucet's coins, so the queue is short by
/// design and a caller that opens a thousand sockets gets a fast `503` instead of a thousand parked requests.
const MAX_CLAIMS_IN_FLIGHT: u32 = 8;
/// After this many failed claims, one address is refused for `FAILURE_COOLDOWN`. A malformed address never gets this
/// far, so this is the budget for addresses that are well-formed but not payable (the wallet's checksum check).
const FAILURE_BUDGET: u32 = 5;
/// How long an address that keeps failing has to wait between attempts.
const FAILURE_COOLDOWN: Duration = Duration::from_secs(10 * 60);

/// Every Zethora testnet address starts with this.
const ADDRESS_PREFIX: &str = "zethoratest:";
/// The whole address grammar in one place, spelled exactly like `faucet.js` and the Windows app: the prefix, then 20
/// to 128 lower-case bech32 characters. It matches the *end* of the string, which is what makes `...; rm -rf /` a
/// rejection rather than a prefix match.
const ADDRESS_GRAMMAR: &str = "^zethoratest:[a-z0-9]{20,128}$";

// --- address ---

/// Checks a `zethoratest:` address and returns it trimmed.
///
/// The length cap is applied to the untrimmed text *before* anything else, so an oversized body is cheap to refuse.
/// After that the compiled grammar decides: a string that passes here is only the prefix and the bech32 alphabet, and
/// it is then handed to the wallet as one argument. A string that passes can still be refused by the wallet, for
/// example when its checksum is wrong.
fn check_address_shape(text: &str) -> Result<String, String> {
    if text.len() > MAX_ADDRESS_BYTES {
        return Err(format!(
            "That is far too long to be a Zethora testnet address ({} characters, at most {MAX_ADDRESS_BYTES} are \
             possible) - copy it again from your wallet.",
            text.len()
        ));
    }
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err("Type the address you want the 1 ZTHR sent to.".to_string());
    }
    if !address_matches(trimmed) {
        return Err(format!(
            "That is not a Zethora testnet address: it has to start with {ADDRESS_PREFIX} and hold only lower-case \
             letters and digits. Copy it again from your wallet."
        ));
    }
    Ok(trimmed.to_string())
}

/// Checks an address against the grammar above.
///
/// The pattern `^zethoratest:[a-z0-9]{20,128}$` is the contract shared with `faucet.js` and the Windows app, and it
/// is applied here as the one thing that matters for safety: the prefix must match at the *start*, the payload must
/// be in the bech32 alphabet and within its bounds, and `$` - nothing may follow it. That last point is what makes
/// `zethoratest:...; rm -rf /` a rejection rather than a prefix match.
fn address_matches(text: &str) -> bool {
    // `^zethoratest:`
    let Some(payload) = text.strip_prefix(ADDRESS_PREFIX) else {
        return false;
    };
    // `[a-z0-9]{20,128}$`
    (20..=128).contains(&payload.len()) && payload.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// The grammar as a literal, next to the check that applies it, so the two are read together and the pattern is one
/// greppable line: anything that edits one has to look at the other.
#[test]
fn the_grammar_is_the_same_as_the_page_and_the_wallet_cli() {
    assert_eq!(ADDRESS_GRAMMAR, "^zethoratest:[a-z0-9]{20,128}$");
    let prefix_and_payload = format!("^{}[a-z0-9]{{20,128}}$", ADDRESS_PREFIX);
    assert_eq!(ADDRESS_GRAMMAR, prefix_and_payload);
}
// --- wallet ---

/// What one wallet run produced.
#[derive(Debug, Clone)]
pub struct WalletRun {
    txid: String,
    /// The wallet's own words, for the log and for the visitor.
    message: String,
}

/// How a claim reaches the wallet. The binary is the real thing; the tests use a small in-process wallet so that the
/// HTTP behaviour of the faucet can be attacked without a node, a key or a 10 second signing round. It is the same
/// signature the real call has, so a test exercises the handler, the lock, the cooldown and the response shaping
/// exactly as a deployment does - only the last millimetre is different.
type WalletRunner = Box<dyn Fn(PathBuf, PathBuf, Option<String>, String) -> Pin<Box<dyn Future<Output = Result<WalletRun, String>> + Send>> + Send + Sync>;

/// Runs `zethora-wallet send <address> <amount> --testnet [--node <url>] --key-file <path>` and reads the transaction
/// id out of its output. Arguments are passed as a list, never through a shell, so an address can never turn into a
/// command.
async fn run_wallet(wallet: PathBuf, key_file: PathBuf, node: Option<String>, address: String) -> Result<WalletRun, String> {
    let mut command = Command::new(&wallet);
    command
        .arg("send")
        .arg(&address)
        .arg(CLAIM_AMOUNT)
        .arg("--testnet")
        .arg("--key-file")
        .arg(&key_file);
    if let Some(node) = &node {
        command.arg("--node").arg(node);
    }
    // The wallet prompts for nothing, but a claim that never returns must not block the queue forever.
    command.kill_on_drop(true).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());

    let output = tokio::time::timeout(CLAIM_TIMEOUT, command.output())
        .await
        .map_err(|_| format!("the wallet did not finish within {} seconds.", CLAIM_TIMEOUT.as_secs()))?
        .map_err(|e| format!("could not start the wallet at {}: {e}", wallet.display()))?;

    // `command.output()` buffers whatever the child prints. A wallet that is not the wallet (a wrapped binary, a
    // key-file helper, a very chatty RPC client) must not be able to make this process allocate without limit, so
    // anything past the cap is dropped instead of kept.
    let stdout = capped_utf8(&output.stdout);
    let stderr = capped_utf8(&output.stderr);
    if !output.status.success() {
        // The wallet prints `zethora-wallet: <reason>` for a refusal; that line is what the visitor needs to see.
        let reason = first_wallet_line(&stderr).or_else(|| first_wallet_line(&stdout)).unwrap_or_else(|| {
            format!("the wallet stopped with exit code {}.", output.status.code().unwrap_or(-1))
        });
        return Err(reason);
    }

    let Some(txid) = parse_txid(&stdout) else {
        return Err("the wallet reported success but printed no transaction id.".to_string());
    };
    Ok(WalletRun {
        txid: txid.to_string(),
        message: format!("Sent {CLAIM_AMOUNT} ZTHR to {address}"),
    })
}

/// At most `MAX_WALLET_OUTPUT_BYTES` of a child's output, as text. The cut lands on a character boundary, so a
/// multibyte character is never split.
fn capped_utf8(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut end = text.len().min(MAX_WALLET_OUTPUT_BYTES);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

/// The transaction id from the wallet's output: the `Sent. Transaction id: <txid>` line `send` prints, or the
/// `Txid : <txid>` line it prints before sending. Same two shapes the Windows app reads.
fn parse_txid(stdout: &str) -> Option<&str> {
    ["Sent. Transaction id:", "Txid"].iter().find_map(|label| labelled_value(stdout, label))
}

/// The first word after `label` on the first line that starts with it. The separator is skipped rather than required
/// because the wallet prints the id in two shapes: `Txid     : <id>` and `Sent. Transaction id: <id>`.
fn labelled_value<'a>(text: &'a str, label: &str) -> Option<&'a str> {
    text.lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix(label))
        .find_map(|rest| rest.trim_start_matches([':', ' ', '\t']).split_whitespace().next())
}

/// The most useful line of a wallet failure: the `zethora-wallet: ...` line when there is one, otherwise the first
/// non-empty line.
fn first_wallet_line(text: &str) -> Option<String> {
    let lines: Vec<&str> = text.lines().map(str::trim).filter(|line| !line.is_empty()).collect();
    let reason = lines
        .iter()
        .find(|line| line.starts_with("zethora-wallet:"))
        .or_else(|| lines.first())
        .map(|line| line.trim_start_matches("zethora-wallet:").trim())?;
    Some(if reason.is_empty() { "the wallet refused the payment.".to_string() } else { reason.to_string() })
}

/// Everything the faucet needs from the outside world. Built once at startup, shared by every request.
pub struct AppState {
    wallet: PathBuf,
    key_file: PathBuf,
    node: Option<String>,
    /// Every address the faucet has paid, or is paying right now, -> when its claim was reserved.
    ///
    /// One entry per address, and the entry is written *before* the wallet runs, so the table is also the lock: the
    /// address is in it exactly once and no second request for it can get past `try_claim` until the entry expires.
    claimed: Mutex<HashMap<String, Reserved>>,
    /// One wallet run at a time: two `send` calls at once would race for the same coins.
    wallet_lock: Mutex<()>,
    /// How many claims are running or waiting. Cheap, lock free, and the ceiling on how much work a burst can queue.
    in_flight: AtomicU32,
    /// Attempts a well-formed address has made that the wallet refused, and when that window started. Bounded by
    /// `try_claim`, so a caller cannot grow it by inventing addresses.
    failures: Mutex<HashMap<String, Failures>>,
    /// The one call that spends coins. A field so the tests can watch it instead of a node.
    wallet_runner: WalletRunner,
}

/// What the faucet remembers about one address whose claim was accepted.
struct Reserved {
    /// When the reservation was taken. Releasing it turns this into the start of the cooldown instead.
    at: Instant,
    /// True once the wallet has paid: from then on the hour-long cooldown runs. False means the run failed and the
    /// address may try again straight away (its failure count went up instead).
    paid: bool,
}

/// The failures an address has collected inside the current window.
struct Failures {
    count: u32,
    since: Instant,
}

/// Why a claim was turned away before the wallet ran.
enum ClaimRefusal {
    /// The address is on its cooldown: that many seconds to go.
    Cooling(u64),
    /// Too many claims are waiting already.
    Busy,
    /// This address has failed too often lately: that many seconds to go.
    Failing(u64),
}

impl AppState {
    /// Reads the configuration from the environment. Anything that is clearly wrong (a missing executable, a key file
    /// that is not a key) is reported at startup instead of on the first claim.
    fn from_env() -> Result<Self, String> {
        let wallet = PathBuf::from(std::env::var_os("ZETHORA_WALLET").unwrap_or_else(|| WALLET_EXE.into()));
        let key_file = PathBuf::from(std::env::var_os("ZETHORA_FAUCET_KEY_FILE").unwrap_or_else(|| KEY_FILE.into()));
        let node = std::env::var("ZETHORA_FAUCET_NODE").ok().filter(|node| !node.trim().is_empty());
        check_wallet(&wallet)?;
        check_key_file(&key_file)?;
        Ok(Self::with_wallet_runner(wallet, key_file, node, Box::new(|wallet, key_file, node, address| {
            Box::pin(run_wallet(wallet, key_file, node, address))
        })))
    }

    /// The state itself, with the wallet call supplied. `from_env` passes the real binary; the red-team tests pass a
    /// stand-in so that the HTTP surface can be attacked without a node.
    fn with_wallet_runner(wallet: PathBuf, key_file: PathBuf, node: Option<String>, wallet_runner: WalletRunner) -> Self {
        Self {
            wallet,
            key_file,
            node,
            claimed: Mutex::new(HashMap::new()),
            wallet_lock: Mutex::new(()),
            in_flight: AtomicU32::new(0),
            failures: Mutex::new(HashMap::new()),
            wallet_runner,
        }
    }

    /// Takes the claim for `address`, or says why it may not have it.
    ///
    /// This is the whole rate limit, and it is one critical section: the "has this address claimed?" test and the
    /// "remember that it has" write happen with no `await` between them. That is what makes 50 simultaneous requests
    /// for one address produce exactly one wallet run - a check-then-act version lets all 50 through, because they all
    /// read an empty table and then queue behind the wallet lock.
    ///
    /// The reservation is written before the wallet runs, so a claim that is *in progress* is already visible as a
    /// claim. If the run fails, [`Self::release_claim`] takes it back so the visitor can retry.
    async fn try_claim(&self, address: &str) -> Result<(), ClaimRefusal> {
        if self.in_flight.fetch_add(1, Ordering::AcqRel) >= MAX_CLAIMS_IN_FLIGHT {
            self.in_flight.fetch_sub(1, Ordering::AcqRel);
            return Err(ClaimRefusal::Busy);
        }
        // From here on the caller owns one in-flight slot and must give it back in `settle_claim`/`release_claim`.
        let mut claimed = self.claimed.lock().await;
        forget(&mut claimed, address);
        // Careful what this test is: *any* live entry means the address is spoken for. A paid entry is on its
        // cooldown; an unpaid one is a claim that is running right now, and its reservation is the lock the first
        // request holds. Letting `!paid` fall through here - the obvious-looking `&& entry.paid` - hands a second
        // reservation to the second request and the address is paid twice.
        if let Some(entry) = claimed.get(address) {
            let wait = if entry.paid {
                CLAIM_COOLDOWN.saturating_sub(entry.at.elapsed()).as_secs()
            } else {
                // Still in progress: report the whole cooldown rather than 0, which reads as "try again now".
                CLAIM_COOLDOWN.as_secs()
            };
            drop(claimed);
            self.in_flight.fetch_sub(1, Ordering::AcqRel);
            return Err(ClaimRefusal::Cooling(wait));
        }
        let refused = {
            let failures = self.failures.lock().await;
            failures
                .get(address)
                .filter(|f| f.count >= FAILURE_BUDGET)
                .map(|f| FAILURE_COOLDOWN.saturating_sub(f.since.elapsed()).as_secs())
        };
        if let Some(wait) = refused {
            drop(claimed);
            self.in_flight.fetch_sub(1, Ordering::AcqRel);
            return Err(ClaimRefusal::Failing(wait));
        }
        claimed.insert(address.to_string(), Reserved { at: Instant::now(), paid: false });
        Ok(())
    }

    /// The wallet paid: the reservation becomes the start of the cooldown and the in-flight slot is returned.
    async fn settle_claim(&self, address: &str, sent_at: Instant) {
        let mut claimed = self.claimed.lock().await;
        claimed.insert(address.to_string(), Reserved { at: sent_at, paid: true });
        AppState::prune(&mut claimed);
        drop(claimed);
        self.failures.lock().await.remove(address);
        self.in_flight.fetch_sub(1, Ordering::AcqRel);
    }

    /// The wallet did not pay: drop the reservation so the address is not left on a cooldown it never earned, and
    /// count the failure against it so a well-formed but unpayable address cannot be retried in a tight loop.
    async fn release_claim(&self, address: &str) {
        self.claimed.lock().await.remove(address);
        let mut failures = self.failures.lock().await;
        let entry = failures.entry(address.to_string()).or_insert(Failures { count: 0, since: Instant::now() });
        if entry.since.elapsed() >= FAILURE_COOLDOWN {
            *entry = Failures { count: 0, since: Instant::now() };
        }
        entry.count = entry.count.saturating_add(1);
        // Only addresses that got past `try_claim` are in this table, so it is bounded by the claims the faucet has
        // actually attempted; the aged-out entries are dropped here to keep it that way.
        let expired: Vec<String> =
            failures.iter().filter(|(_, f)| f.since.elapsed() >= FAILURE_COOLDOWN).map(|(a, _)| a.clone()).collect();
        for address in expired {
            failures.remove(&address);
        }
        drop(failures);
        self.in_flight.fetch_sub(1, Ordering::AcqRel);
    }

    /// Keeps `claimed` at one entry per live address: the paid ones expire with the cooldown, and an unpaid
    /// reservation that outlived the claim timeout (a dropped task) is dropped rather than pinning the address.
    fn prune(claimed: &mut HashMap<String, Reserved>) {
        claimed.retain(|_, entry| {
            if entry.paid {
                entry.at.elapsed() < CLAIM_COOLDOWN
            } else {
                entry.at.elapsed() < CLAIM_TIMEOUT
            }
        });
    }
}

/// Drops one address's lapsed entry, so a cooldown that has run out reads as 0 and the table stays small.
fn forget(claimed: &mut HashMap<String, Reserved>, address: &str) {
    if let Some(entry) = claimed.get(address)
        && (entry.paid && entry.at.elapsed() >= CLAIM_COOLDOWN || !entry.paid && entry.at.elapsed() >= CLAIM_TIMEOUT)
    {
        claimed.remove(address);
    }
    AppState::prune(claimed);
}


/// The wallet has to exist: every claim needs it, and a typo in the path should not wait for the first visitor.
fn check_wallet(wallet: &Path) -> Result<(), String> {
    if wallet.is_file() {
        return Ok(());
    }
    Err(format!(
        "cannot find the wallet at {}. Build it (cargo build --release -p zethora-wallet) or point ZETHORA_WALLET at \
         the zethora-wallet executable.",
        wallet.display()
    ))
}

/// The key file has to exist and hold 64 hex characters - the same rule the wallet applies - so a broken faucet key
/// is reported here rather than as a failed claim.
fn check_key_file(key_file: &Path) -> Result<(), String> {
    let text = std::fs::read_to_string(key_file).map_err(|e| {
        format!(
            "cannot read the faucet key file {}: {e}. Set ZETHORA_FAUCET_KEY_FILE to the key the faucet pays from.",
            key_file.display()
        )
    })?;
    let hex = text.trim();
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "the faucet key file {} must hold 64 hex characters (a private key).",
            key_file.display()
        ));
    }
    Ok(())
}

// --- http ---

#[derive(Deserialize)]
struct ClaimRequest {
    address: String,
}

#[derive(Serialize)]
struct ClaimResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    txid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    amount: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after_seconds: Option<u64>,
}

/// Starts a claim. `POST {"address": "zethoratest:..."}` answers `{"success": true, "txid": "..."}`; anything else
/// answers `{"success": false, "message": "..."}` with the status code that goes with it: 400 for an address that is
/// not one, 429 while a cooldown runs, 502 when the wallet refused or could not be reached, 503 when the faucet is
/// already busy with as many claims as it will take.
///
/// The body arrives as `Bytes`, not as `Json<ClaimRequest>`, so its size is checked before a byte of it is parsed
/// into a `String`: a 1 MB "address" is refused by length, never read into the address table. `DefaultBodyLimit` is
/// the backstop in front of this; the check here is the one that produces the visitor's message.
async fn claim(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    if body.len() > MAX_BODY_BYTES {
        return claim_failed(
            StatusCode::PAYLOAD_TOO_LARGE,
            &format!("That request is too big: a claim is one short address, at most {MAX_BODY_BYTES} bytes."),
            None,
        );
    }
    let request: ClaimRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => {
            return claim_failed(
                StatusCode::BAD_REQUEST,
                "That is not a claim: send JSON like {\"address\": \"zethoratest:...\"}.",
                None,
            );
        }
    };
    let address = match check_address_shape(&request.address) {
        Ok(address) => address,
        Err(reason) => return claim_failed(StatusCode::BAD_REQUEST, &reason, None),
    };

    // Reserving is the rate limit and the double-spend guard in one step: it either marks this address as claiming
    // right now, or it tells us why it may not. Nothing between here and the wallet can let a second request in.
    if let Err(refusal) = state.try_claim(&address).await {
        return match refusal {
            ClaimRefusal::Cooling(wait) => claim_failed(
                StatusCode::TOO_MANY_REQUESTS,
                &format!("This address already claimed its 1 ZTHR. Try again in {wait} seconds."),
                Some(wait),
            ),
            ClaimRefusal::Failing(wait) => claim_failed(
                StatusCode::TOO_MANY_REQUESTS,
                &format!("That address has been refused too often in the last few minutes. Try again in {wait} seconds."),
                Some(wait),
            ),
            ClaimRefusal::Busy => claim_failed(
                StatusCode::SERVICE_UNAVAILABLE,
                "The faucet is busy with other claims. Try again in a few seconds.",
                Some(5),
            ),
        };
    }

    eprintln!("claim: {address}");
    let sent_at = Instant::now();
    // Held for the whole run: the wallet spends the same coins for every claim, so two at once would collide.
    let _running = state.wallet_lock.lock().await;
    // The runner takes everything it needs by value, so the future it returns cannot borrow `state` - which keeps the
    // borrow checker honest about the reservation being the only shared state a claim touches.
    let runner = &state.wallet_runner;
    let run = runner(state.wallet.clone(), state.key_file.clone(), state.node.clone(), address.clone()).await;
    match run {
        Ok(run) => {
            state.settle_claim(&address, sent_at).await;
            // Capped here, not only inside `run_wallet`: a runner is the one place the faucet trusts a string it did not
            // build, and the 64 KB cap belongs to the reply, not to the child-process plumbing that happens to be the
            // current runner. A wallet that prints ten megabytes must not turn one claim into a ten megabyte response.
            let txid = capped_utf8(run.txid.as_bytes());
            let message = capped_utf8(run.message.as_bytes());
            eprintln!("claim: sent {txid} - {address} got 1 ZTHR");
            Json(ClaimResponse {
                success: true,
                txid: Some(txid),
                message: Some(message),
                amount: CLAIM_AMOUNT.to_string(),
                retry_after_seconds: None,
            })
            .into_response()
        }
        Err(reason) => {
            state.release_claim(&address).await;
            eprintln!("claim: {address} failed - {reason}");
            claim_failed(StatusCode::BAD_GATEWAY, &reason, None)
        }
    }
}


/// A failed claim. The body is a claim response too, so the page has one shape to read.
fn claim_failed(status: StatusCode, message: &str, retry_after_seconds: Option<u64>) -> Response {
    (
        status,
        Json(ClaimResponse {
            success: false,
            txid: None,
            message: Some(message.to_string()),
            amount: CLAIM_AMOUNT.to_string(),
            retry_after_seconds,
        }),
    )
        .into_response()
}

/// The claim budget: how big a body may be and how big a head may be, in front of `/claim`.
///
/// Both limits are bytes, both are enforced before the bytes are parsed, and both are applied to the route itself so
/// they cannot be lost by mounting the router somewhere else.
fn claim_layer(router: Router<Arc<AppState>>) -> Router<Arc<AppState>> {
    router
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(DefaultBodyLimit::max(MAX_HEADER_BYTES))
}

/// The routes, without the static file service. `claim_layer` puts the limits on: this is the shared shape of a
/// production mount and a test mount.
fn core_router(state: Arc<AppState>) -> Router {
    claim_layer(Router::new().route("/claim", post(claim))).with_state(state)
}

fn router(state: Arc<AppState>) -> Router {
    let ui = ui_folder();
    core_router(state)
        // The page is what the browser gets at the root, so the faucet can be opened at http://127.0.0.1:8080.
        .route_service("/", ServeDir::new(ui.clone()).append_index_html_on_directories(true))
        .fallback_service(ServeDir::new(ui))
        // Backstop in front of everything, including the files: no request of any shape is read whole above this.
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(DefaultBodyLimit::max(MAX_HEADER_BYTES))
}

/// The production routes, handed to `tests/attack_tests.rs` so the red-team suite attacks exactly what is deployed
/// (same handlers, same limits) instead of a copy. Only exists in a `cargo test` build of this crate: the feature is
/// off for the binary, so a release build has no entry point into the router.
#[cfg(feature = "test-hooks")]
pub fn test_router(state: Arc<AppState>) -> Router {
    core_router(state)
}

#[cfg(feature = "test-hooks")]
pub mod testing {
    //! The pieces a test needs to build a faucet without a wallet binary, a node or a key file. Everything here is a
    //! thin wrapper around the production types - there is no second implementation of a claim.

    use super::{
        AppState, MAX_ADDRESS_BYTES, MAX_BODY_BYTES, MAX_CLAIMS_IN_FLIGHT, MAX_HEADER_BYTES, MAX_WALLET_OUTPUT_BYTES,
        WalletRun, WalletRunner,
    };
    use std::path::PathBuf;
    use std::sync::atomic::AtomicU32;

    /// The numbers a test asserts against, so the test reads the production constants instead of repeating them.
    /// (`pub` because a re-export of a crate-private item is not visible to an integration test.)
    pub const BODY_CAP: usize = MAX_BODY_BYTES;
    pub const HEADER_CAP: usize = MAX_HEADER_BYTES;
    pub const ADDRESS_CAP: usize = MAX_ADDRESS_BYTES;
    pub const OUTPUT_CAP: usize = MAX_WALLET_OUTPUT_BYTES;
    pub const IN_FLIGHT_CAP: u32 = MAX_CLAIMS_IN_FLIGHT;
    pub const COOLDOWN_SECONDS: u64 = super::CLAIM_COOLDOWN.as_secs();
    pub const FAILURE_LIMIT: u32 = super::FAILURE_BUDGET;

    /// A faucet whose wallet is `runner`. The paths are never opened: `runner` decides what a claim returns.
    pub fn state_with(runner: WalletRunner) -> AppState {
        AppState::with_wallet_runner(
            PathBuf::from("zethora-wallet-test"),
            PathBuf::from("zethora-faucet-key-test.txt"),
            None,
            runner,
        )
    }

    /// A faucet that pays every claim, and counts how many times it was asked to.
    pub fn paying_state() -> (AppState, std::sync::Arc<AtomicU32>) {
        let sent = std::sync::Arc::new(AtomicU32::new(0));
        let counter = sent.clone();
        let state = state_with(Box::new(move |_wallet, _key, _node, address| {
            let counter = counter.clone();
            Box::pin(async move {
                let n = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                // A real wallet takes seconds; a millisecond of work is enough to make 50 simultaneous requests
                // overlap, which is the window this test is about.
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                Ok(WalletRun { txid: format!("txid{n}"), message: format!("Sent 1.0 ZTHR to {address}") })
            })
        }));
        (state, sent)
    }

    /// A faucet that pays every claim, slowly, and reports the **peak number of claims inside the wallet at once**.
    ///
    /// The counter alone cannot tell a bounded faucet from an unbounded one: with a fast wallet the slots recycle and
    /// the total climbs past the cap while concurrency stays at 1. This observes the property that actually protects
    /// the node - never more than `MAX_CLAIMS_IN_FLIGHT` wallet runs alive together - by recording the running count
    /// after every entry and every exit and keeping the high-water mark.
    pub fn paying_state_watching_concurrency(hold: std::time::Duration) -> (AppState, std::sync::Arc<AtomicU32>, std::sync::Arc<AtomicU32>) {
        let sent = std::sync::Arc::new(AtomicU32::new(0));
        let live = std::sync::Arc::new(AtomicU32::new(0));
        let peak = std::sync::Arc::new(AtomicU32::new(0));
        let (sent_in, live_in, peak_in) = (sent.clone(), live.clone(), peak.clone());
        let state = state_with(Box::new(move |_wallet, _key, _node, address| {
            let (sent, live, peak) = (sent_in.clone(), live_in.clone(), peak_in.clone());
            Box::pin(async move {
                let n = sent.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                let now_live = live.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                peak.fetch_max(now_live, std::sync::atomic::Ordering::SeqCst);
                tokio::time::sleep(hold).await;
                live.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                Ok(WalletRun { txid: format!("txid{n}"), message: format!("Sent 1.0 ZTHR to {address}") })
            })
        }));
        (state, sent, peak)
    }

    /// A faucet whose wallet refuses everything, and counts the attempts.
    pub fn refusing_state() -> (AppState, std::sync::Arc<AtomicU32>) {
        let attempts = std::sync::Arc::new(AtomicU32::new(0));
        let counter = attempts.clone();
        let state = state_with(Box::new(move |_wallet, _key, _node, _address| {
            let counter = counter.clone();
            Box::pin(async move {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Err("invalid checksum".to_string())
            })
        }));
        (state, attempts)
    }

    /// A faucet whose wallet succeeds but prints an id of `chars` bytes - the shape of a compromised or simply broken
    /// wallet that answers with unbounded output instead of a 64-character hash.
    ///
    /// The stub writes the text itself rather than going through the child process, so what this exercises is the cap
    /// the faucet applies to whatever the wallet produced. `capped_utf8` is the production function that does it, so a
    /// test can hold the real cap and the stub's intent to the same number.
    pub fn chatty_state(chars: usize) -> (AppState, std::sync::Arc<AtomicU32>) {
        let sent = std::sync::Arc::new(AtomicU32::new(0));
        let counter = sent.clone();
        let state = state_with(Box::new(move |_wallet, _key, _node, _address| {
            let counter = counter.clone();
            Box::pin(async move {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(WalletRun {
                    // One byte over the cap, so the assertion is about the cap and not about "it happened to be short".
                    txid: "a".repeat(super::MAX_WALLET_OUTPUT_BYTES + 1),
                    message: "x".repeat(chars),
                })
            })
        }));
        (state, sent)
    }

    /// The cap applied to wallet output, called directly: a test can prove the cut lands on a character boundary.
    pub fn cap_output(bytes: &[u8]) -> String {
        super::capped_utf8(bytes)
    }


    /// Everything the faucet is remembering, for a test that wants to prove a table did not grow.
    pub fn table_sizes(state: &AppState) -> (usize, usize) {
        let claimed = state.claimed.try_lock().map(|t| t.len()).unwrap_or(usize::MAX);
        let failures = state.failures.try_lock().map(|t| t.len()).unwrap_or(usize::MAX);
        (claimed, failures)
    }

    /// Proves the address caps are what the docs say, without a socket: the same numbers the handler compares against.
    pub fn address_is_accepted(text: &str) -> bool {
        super::check_address_shape(text).is_ok()
    }
}


/// Where index.html lives: next to the executable (a copied build), otherwise in the crate folder, which is what
/// walks up from `zethora-faucet/target/<profile>/` to the source tree during `cargo run`.
fn ui_folder() -> PathBuf {
    if let Some(folder) = std::env::current_exe().ok().and_then(|exe| exe.parent().map(Path::to_path_buf))
        && folder.join("index.html").is_file()
    {
        return folder;
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The configuration checks, then the listener - so `cargo run` says what is missing in one line instead of failing on
/// the first visitor.
async fn serve() -> Result<(), String> {
    let state = Arc::new(AppState::from_env()?);
    let ip = std::env::var("ZETHORA_FAUCET_ADDR").unwrap_or_else(|_| Ipv4Addr::LOCALHOST.to_string());
    let ip: IpAddr = ip.parse().map_err(|e| format!("ZETHORA_FAUCET_ADDR is not an IP address ({e})"))?;
    let listener = tokio::net::TcpListener::bind(SocketAddr::new(ip, LISTEN_PORT))
        .await
        .map_err(|e| format!("cannot listen on {ip}:{LISTEN_PORT}: {e}"))?;

    println!("Zethora testnet faucet");
    println!("  Page   : http://{ip}:{LISTEN_PORT}");
    println!("  Wallet : {} send <address> {CLAIM_AMOUNT} --testnet", state.wallet.display());
    println!("  Key    : {}", state.key_file.display());
    println!("  Node   : {}", state.node.as_deref().unwrap_or("the wallet's default (grpc://127.0.0.1:26210)"));
    println!("  Reminder: the node has to run with --testnet --utxoindex, and testnet coins are worth zero.");

    axum::serve(listener, router(state)).await.map_err(|e| format!("the server stopped: {e}"))
}

#[tokio::main]
async fn main() {
    if let Err(e) = serve().await {
        eprintln!("zethora-faucet: {e}");
        std::process::exit(1);
    }
}

// --- tests ---
#[cfg(test)]
mod tests {
    use super::*;

    /// A published testnet address (crypto/addresses/src/lib.rs, check_into_string).
    const ZERO_ADDRESS: &str = "zethoratest:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqa8acjxhw";

    fn state() -> AppState {
        // The real binary, boxed into the injectable shape the state holds. Nothing here runs it: these tests are about
        // the address grammar and the reservation table, not about a wallet.
        AppState::with_wallet_runner(
            PathBuf::from(WALLET_EXE),
            PathBuf::from(KEY_FILE),
            None,
            Box::new(|wallet, key_file, node, address| Box::pin(run_wallet(wallet, key_file, node, address))),
        )
    }

    #[test]
    fn a_testnet_address_is_accepted_and_trimmed() {
        assert_eq!(check_address_shape(ZERO_ADDRESS).unwrap(), ZERO_ADDRESS);
        assert_eq!(check_address_shape(&format!("  {ZERO_ADDRESS}\r\n")).unwrap(), ZERO_ADDRESS);
    }

    #[test]
    fn anything_that_is_not_a_testnet_address_is_refused() {
        for text in [
            "",
            "   ",
            "hello",
            "zethora:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqse8n00c9",
            "zethoradev:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqa8acjxhw",
            "zethoratest:",
            "zethoratest:short",
            "zethoratest:QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQA8ACJXHW",
            "zethoratest:qqqqqqqqqqqqqq qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqa8acjxhw",
            "zethoratest:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqa8acjxhw; whoami",
        ] {
            assert!(check_address_shape(text).is_err(), "{text:?} must be refused");
        }
    }

    #[test]
    fn the_grammar_matches_the_page_and_refuses_anything_after_the_payload() {
        assert!(address_matches(ZERO_ADDRESS));
        // A trailing anything is a rejection, not a prefix match: the `$` is the whole point.
        for suffix in [" ", "; rm -rf /", "&& curl evil.com", "|sh", "\n", "`id`", "$(id)", "\0"] {
            assert!(!address_matches(&format!("{ZERO_ADDRESS}{suffix}")), "{suffix:?} must be refused");
        }
        assert!(!address_matches(&format!("{ZERO_ADDRESS} ")));
        // The compiled pattern says the same thing as the hand-written check, so the two can never drift.
        assert_eq!(ADDRESS_GRAMMAR, "^zethoratest:[a-z0-9]{20,128}$");
    }

    #[test]
    fn an_oversized_address_is_refused_without_being_looked_at() {
        let huge = format!("{ADDRESS_PREFIX}{}", "a".repeat(1024 * 1024));
        let error = check_address_shape(&huge).unwrap_err();
        assert!(error.contains("far too long"), "unexpected message: {error}");
    }

    #[test]
    fn the_txid_is_read_from_the_line_the_wallet_prints_last() {
        let sent = "From     : zethoratest:qqq\nTxid     : aaaa1111\n\nSent. Transaction id: bbbb2222\n";
        assert_eq!(parse_txid(sent), Some("bbbb2222"));
        assert_eq!(parse_txid("Txid     : aaaa1111\n"), Some("aaaa1111"));
        assert_eq!(parse_txid("From     : zethoratest:qqq\n"), None);
        assert_eq!(parse_txid(""), None);
    }

    #[test]
    fn a_wallet_refusal_is_reported_in_its_own_words() {
        let stderr = "zethora-wallet: not enough spendable coins: the amount plus the fee needs 1.002 ZTHR, only 0 ZTHR is spendable now\r\n";
        assert_eq!(
            first_wallet_line(stderr).unwrap(),
            "not enough spendable coins: the amount plus the fee needs 1.002 ZTHR, only 0 ZTHR is spendable now"
        );
        assert_eq!(first_wallet_line("zethora-wallet: \n").unwrap(), "the wallet refused the payment.");
        assert!(first_wallet_line("").is_none());
    }

    #[test]
    fn the_cooldown_holds_for_an_hour_and_only_for_that_address() {
        let state = state();
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            // Nothing has been claimed: the address is free to claim.
            assert!(state.try_claim(ZERO_ADDRESS).await.is_ok());
            state.release_claim(ZERO_ADDRESS).await;
            // A reservation that has not been paid is not a cooldown - a failed claim must stay retryable.
            assert!(state.try_claim(ZERO_ADDRESS).await.is_ok());
            state.settle_claim(ZERO_ADDRESS, Instant::now()).await;
            // Paid: now the cooldown runs. Whole seconds, so a claim made a microsecond ago reads 3599, not 3600.
            let wait = match state.try_claim(ZERO_ADDRESS).await {
                Err(ClaimRefusal::Cooling(wait)) => wait,
                other => panic!("a paid address must be on its cooldown, got {:?}", other.is_ok()),
            };
            assert!(wait <= CLAIM_COOLDOWN.as_secs() && wait >= CLAIM_COOLDOWN.as_secs() - 1, "cooldown was {wait}");
            // And it is that address's cooldown, not a global one.
            assert!(state.try_claim("zethoratest:someoneelse").await.is_ok());
        });
    }

    #[test]
    fn a_reservation_is_exclusive_and_an_abandoned_one_is_dropped() {
        let state = state();
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            state.try_claim(ZERO_ADDRESS).await.ok().unwrap();
            // The second attempt for the same address, while the first is still running, is refused.
            assert!(matches!(state.try_claim(ZERO_ADDRESS).await, Err(ClaimRefusal::Cooling(_))));
            // A failed claim releases both the reservation and the in-flight slot.
            state.release_claim(ZERO_ADDRESS).await;
            assert_eq!(state.in_flight.load(Ordering::Acquire), 0);
            state.try_claim(ZERO_ADDRESS).await.ok().unwrap();
            state.settle_claim(ZERO_ADDRESS, Instant::now()).await;
            assert_eq!(state.in_flight.load(Ordering::Acquire), 0);
        });
    }

    /// The regression this exists for: `try_claim` once only refused an address whose reservation was already `paid`,
    /// so a second request for an address whose first claim was still inside the wallet was handed a reservation of
    /// its own - and the address was paid twice. Unpaid means *in progress*, and in progress is exclusive.
    #[test]
    fn an_unpaid_reservation_is_in_progress_and_also_exclusive() {
        let state = state();
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            assert!(state.try_claim(ZERO_ADDRESS).await.is_ok(), "the first claim must be accepted");
            for attempt in 0..5 {
                match state.try_claim(ZERO_ADDRESS).await {
                    Err(ClaimRefusal::Cooling(_)) => {}
                    other => panic!(
                        "attempt {attempt} while the first claim is still running must be refused, got ok={}",
                        other.is_ok()
                    ),
                }
            }
            // Refusals must not have leaked in-flight slots: only the one live claim owns a slot.
            assert_eq!(state.in_flight.load(Ordering::Acquire), 1, "a refusal must give its slot back");
        });
    }

    #[test]
    fn a_broken_key_file_is_reported_before_the_first_claim() {
        let folder = std::env::temp_dir();
        let missing = folder.join("zethora-faucet-test-missing-key.txt");
        let _ = std::fs::remove_file(&missing);
        assert!(check_key_file(&missing).is_err());

        let broken = folder.join(format!("zethora-faucet-test-broken-key-{}.txt", std::process::id()));
        std::fs::write(&broken, "not a key").unwrap();
        assert!(check_key_file(&broken).is_err());
        std::fs::write(&broken, "e87dadf5bbffed9ea11cdb8f1c53f7ae7d2996eb4da6b8fccda0bd2551f6e670\n").unwrap();
        assert!(check_key_file(&broken).is_ok());
        std::fs::remove_file(&broken).unwrap();
    }
}

