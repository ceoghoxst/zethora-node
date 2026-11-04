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

#![allow(clippy::arithmetic_side_effects)]

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
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
/// A request body larger than this is refused before it is parsed.
const MAX_BODY_BYTES: usize = 4 * 1024;

/// Every Zethora testnet address starts with this.
const ADDRESS_PREFIX: &str = "zethoratest:";

// --- address ---

/// Checks the shape of a `zethoratest:` address and returns the trimmed text.
///
/// This is a cheap first pass so an obvious typo never reaches the wallet (or uses up a cooldown). A string that
/// passes here can still be refused by the wallet, for example when its checksum is wrong.
fn check_address_shape(text: &str) -> Result<String, String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err("Type the address you want the 1 ZTHR sent to.".to_string());
    }
    let Some(payload) = trimmed.strip_prefix(ADDRESS_PREFIX) else {
        return Err(format!("That is not a Zethora testnet address: it has to start with {ADDRESS_PREFIX}"));
    };
    if payload.len() < 20 || payload.len() > 128 {
        return Err("That Zethora testnet address has the wrong length - copy it again from your wallet.".to_string());
    }
    if !payload.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()) {
        return Err(
            "That Zethora testnet address has characters that do not belong in it - copy it again from your wallet."
                .to_string(),
        );
    }
    Ok(trimmed.to_string())
}
// --- wallet ---



// --- wallet ---

/// What one wallet run produced.
struct WalletRun {
    txid: String,
    /// The wallet's own words, for the log and for the visitor.
    message: String,
}

/// Runs `zethora-wallet send <address> <amount> --testnet [--node <url>] --key-file <path>` and reads the transaction
/// id out of its output. Arguments are passed as a list, never through a shell, so an address can never turn into a
/// command.
async fn send_from_wallet(state: &AppState, address: &str) -> Result<WalletRun, String> {
    let mut command = Command::new(&state.wallet);
    command
        .arg("send")
        .arg(address)
        .arg(CLAIM_AMOUNT)
        .arg("--testnet")
        .arg("--key-file")
        .arg(&state.key_file);
    if let Some(node) = &state.node {
        command.arg("--node").arg(node);
    }
    // The wallet prompts for nothing, but a claim that never returns must not block the queue forever.
    command.kill_on_drop(true).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());

    let output = tokio::time::timeout(CLAIM_TIMEOUT, command.output())
        .await
        .map_err(|_| format!("the wallet did not finish within {} seconds.", CLAIM_TIMEOUT.as_secs()))?
        .map_err(|e| format!("could not start the wallet at {}: {e}", state.wallet.display()))?;

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
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
struct AppState {
    wallet: PathBuf,
    key_file: PathBuf,
    node: Option<String>,
    /// The address -> the time of its last accepted claim.
    last_claims: Mutex<Vec<(String, Instant)>>,
    /// One wallet run at a time: two `send` calls at once would race for the same coins.
    wallet_lock: Mutex<()>,
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
        Ok(Self {
            wallet,
            key_file,
            node,
            last_claims: Mutex::new(Vec::new()),
            wallet_lock: Mutex::new(()),
        })
    }

    /// Seconds until `address` may claim again: 0 when it may claim right now. Forgetful by design - the table lives
    /// in memory and starts empty when the faucet restarts.
    async fn cooldown(&self, address: &str) -> u64 {
        let claims = self.last_claims.lock().await;
        claims
            .iter()
            .find(|(known, _)| known == address)
            .map(|(_, when)| CLAIM_COOLDOWN.saturating_sub(when.elapsed()).as_secs())
            .unwrap_or(0)
    }

    /// Starts (or restarts) the cooldown of an address whose claim was accepted.
    async fn record_claim(&self, address: &str) {
        let mut claims = self.last_claims.lock().await;
        claims.retain(|(known, when)| known != address && when.elapsed() < CLAIM_COOLDOWN);
        claims.push((address.to_string(), Instant::now()));
    }
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
/// not one, 429 while a cooldown runs, 502 when the wallet refused or could not be reached.
async fn claim(State(state): State<Arc<AppState>>, Json(request): Json<ClaimRequest>) -> Response {
    let address = match check_address_shape(&request.address) {
        Ok(address) => address,
        Err(reason) => return claim_failed(StatusCode::BAD_REQUEST, &reason, None),
    };

    let wait = state.cooldown(&address).await;
    if wait > 0 {
        return claim_failed(
            StatusCode::TOO_MANY_REQUESTS,
            &format!("This address already claimed its 1 ZTHR. Try again in {wait} seconds."),
            Some(wait),
        );
    }

    // Held for the whole run: the wallet spends the same coins for every claim, so two at once would collide.
    let _running = state.wallet_lock.lock().await;
    eprintln!("claim: {address}");
    match send_from_wallet(&state, &address).await {
        Ok(run) => {
            state.record_claim(&address).await;
            eprintln!("claim: sent {} - {address} got 1 ZTHR", run.txid);
            Json(ClaimResponse {
                success: true,
                txid: Some(run.txid),
                message: Some(run.message),
                amount: CLAIM_AMOUNT.to_string(),
                retry_after_seconds: None,
            })
            .into_response()
        }
        Err(reason) => {
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

fn router(state: Arc<AppState>) -> Router {
    let ui = ui_folder();
    Router::new()
        .route("/claim", post(claim))
        // The page is what the browser gets at the root, so the faucet can be opened at http://127.0.0.1:8080.
        .route_service("/", ServeDir::new(ui.clone()).append_index_html_on_directories(true))
        .fallback_service(ServeDir::new(ui))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
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
        AppState {
            wallet: PathBuf::from(WALLET_EXE),
            key_file: PathBuf::from(KEY_FILE),
            node: None,
            last_claims: Mutex::new(Vec::new()),
            wallet_lock: Mutex::new(()),
        }
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
            assert_eq!(state.cooldown(ZERO_ADDRESS).await, 0);
            state.record_claim(ZERO_ADDRESS).await;
            // Whole seconds, so a claim made a microsecond ago reads 3599 rather than 3600.
            let wait = state.cooldown(ZERO_ADDRESS).await;
            assert!(wait <= CLAIM_COOLDOWN.as_secs() && wait >= CLAIM_COOLDOWN.as_secs() - 1, "cooldown was {wait}");
            assert_eq!(state.cooldown("zethoratest:someoneelse").await, 0);
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

