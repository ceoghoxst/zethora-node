//! The `zethora-dex` binary: a seeded pair, printed at startup and served over
//! HTTP.
//!
//! The AMM itself is not here. The pair, its maths and its storage live in the
//! library, so this file is only what a developer needs in order to watch a
//! market: an executor with one pair deployed and funded, and a small JSON API
//! over the pair's three mutating entry points. Every handler goes through
//! [`zethora_dex::dispatch`] — the ABI encode, dispatch, decode path a wallet
//! takes — so what `curl` returns is what the contract produced, not a second
//! implementation that could drift from it.
//!
//! ```text
//! cargo run -p zethora-dex
//! curl http://127.0.0.1:8546/state
//! curl -X POST http://127.0.0.1:8546/swap -H 'content-type: application/json' \
//!      -d '{"account":"0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1","tokenIn":"0x2121212121212121212121212121212121212121","amountIn":"10000","minAmountOut":"19700","deadline":"1000000"}'
//! ```
//!
//! Every amount crosses the wire as a string, in decimal or `0x` hex: the values
//! are 256-bit, and a JSON number cannot hold one without silently losing digits.
//!
//! `minAmountOut`, `deadline`, `amountAMin` and `amountBMin` are the pair's own
//! caller-set terms and are all optional here: a request that omits them asks for
//! no floor and no deadline, which the sandbox can afford because it has one
//! account. A real client sends them, and the pair refuses the call if they are
//! not met either way.

use std::{
    net::{IpAddr, SocketAddr},
    process::ExitCode,
    str::FromStr,
    sync::{Arc, Mutex, MutexGuard},
};

use alloy_primitives::{Address, U256};
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use clap::Parser;
use revm::primitives::hardfork::SpecId;
use serde::Deserialize;
use serde_json::{Value, json};
use zethora_dex::{
    Deployment, add_liquidity, add_liquidity_calldata, deploy, dispatch, remove_liquidity_calldata, reserves,
    swap_calldata, token, total_supply,
};
use zethora_evm::EvmExecutor;

/// The port the JSON API listens on by default.
///
/// One above the L2 JSON-RPC endpoint (8545), because the two are meant to be run
/// side by side: the RPC serves the chain, this serves the market on it.
const DEFAULT_PORT: u16 = 8546;

/// The hardfork the sandbox executes under.
///
/// Named explicitly rather than left to [`EvmExecutor::new`], so the banner can
/// report it: a price is only reproducible if the rules it executed under are
/// known.
const SPEC: SpecId = SpecId::PRAGUE;

/// How much of each token the sandbox account is funded with at genesis.
const DEFAULT_SEED: u64 = 10_000_000;

/// The opening deposit, in token0.
const DEFAULT_AMOUNT_A: u64 = 1_000_000;

/// The opening deposit, in token1.
const DEFAULT_AMOUNT_B: u64 = 2_000_000;

/// Where to listen, and what to seed.
#[derive(Debug, Parser)]
#[command(
    name = "zethora-dex",
    version,
    about = "A private DEX sandbox: one x*y=k pair, seeded, served as JSON"
)]
struct Cli {
    /// The address the JSON API binds to.
    #[arg(long, default_value = "127.0.0.1")]
    host: IpAddr,

    /// The port the JSON API binds to.
    #[arg(long, default_value_t = DEFAULT_PORT)]
    port: u16,

    /// How much of each token to fund the sandbox account with.
    #[arg(long, default_value_t = DEFAULT_SEED)]
    seed: u64,

    /// The opening deposit, in token0.
    #[arg(long, default_value_t = DEFAULT_AMOUNT_A)]
    amount_a: u64,

    /// The opening deposit, in token1.
    #[arg(long, default_value_t = DEFAULT_AMOUNT_B)]
    amount_b: u64,
}

/// Seeds the pair, reports it, then serves it until killed.
#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    let market = match seed(&cli) {
        Ok(market) => market,
        Err(err) => {
            eprintln!("zethora-dex: cannot seed the pair: {err}");
            return ExitCode::FAILURE;
        }
    };

    // Printed, not logged: the opening reserves and the account they belong to are
    // the first thing a developer needs, and they are what every later request is
    // measured against.
    print_state(&market);

    let address = SocketAddr::new(cli.host, cli.port);
    let listener = match tokio::net::TcpListener::bind(address).await {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("zethora-dex: cannot bind {address}: {err}");
            return ExitCode::FAILURE;
        }
    };

    println!();
    println!("zethora-dex: serving http://{address}");
    println!("  hardfork : {SPEC:?}");
    println!("  endpoints: GET /, GET /state, POST /add-liquidity, POST /swap, POST /remove-liquidity");
    println!("  amounts  : strings, decimal or 0x hex, e.g. \"10000\"");

    match axum::serve(listener, router(market)).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("zethora-dex: the server stopped: {err}");
            ExitCode::FAILURE
        }
    }
}

// ---------------------------------------------------------------------------
// The market
// ---------------------------------------------------------------------------

/// token0's address in the sandbox.
///
/// Two meaningless addresses far from the zero address: they are stand-ins for
/// the pair's two assets, and nothing else in the sandbox is one, so a swap with
/// any other address is refused by the pair rather than quietly accepted.
fn token_a() -> Address {
    Address::repeat_byte(0x21)
}

/// token1's address in the sandbox.
fn token_b() -> Address {
    Address::repeat_byte(0x22)
}

/// The account the sandbox seeds, deposits for and trades as.
///
/// A fixed address with no private key, because nothing here signs: the entry
/// points are driven directly through [`zethora_dex::dispatch`], the way a
/// sequencer drives them, and the server is single-user by construction.
fn sandbox_account() -> Address {
    Address::repeat_byte(0xa1)
}

/// The market the binary serves: one pair, in one executor.
struct Market {
    /// The engine the pair's state lives in.
    executor: EvmExecutor,
    /// Where the pair is, and which two assets it holds in reserve order.
    pair: Deployment,
}

/// The handle every handler takes.
type Shared = Arc<Mutex<Market>>;

/// Builds the sandbox: a pair deployed into a fresh executor, an account funded
/// with both tokens, and an opening deposit.
///
/// The funding is genesis, not a call: a devnet would reach for a faucet, but the
/// pair only ever moves tokens that already exist, so something has to create
/// them. Everything after this point goes through the pair's own entry points.
fn seed(cli: &Cli) -> Result<Shared, String> {
    let mut executor = EvmExecutor::with_spec(SPEC);
    let pair = deploy(&mut executor, token_a(), token_b())
        .map_err(|err| format!("the pair could not be deployed: {err}"))?;

    let funded = U256::from(cli.seed);
    for asset in [pair.token0, pair.token1] {
        token::mint_to(&mut executor, asset, sandbox_account(), funded)
            .map_err(|err| format!("the sandbox account could not be funded with {asset}: {err}"))?;
    }

    add_liquidity(
        &mut executor,
        pair.pair,
        sandbox_account(),
        pair.token0,
        U256::from(cli.amount_a),
        pair.token1,
        U256::from(cli.amount_b),
    )
    .map_err(|err| format!("the opening deposit was refused: {err}"))?;

    Ok(Arc::new(Mutex::new(Market { executor, pair })))
}

/// Takes the market lock, recovering from a poisoned mutex.
///
/// A handler that panicked while holding the lock cannot have left the pair
/// half-applied — every entry point plans and validates before it writes — so
/// refusing every later request would be a worse answer than serving the state
/// that is actually there.
fn lock(market: &Shared) -> MutexGuard<'_, Market> {
    market.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The market, as JSON.
///
/// The reserves are the pair's stored reserves — what the last call synced, and
/// what the next trade will be priced against — while `k` is their product, so a
/// client can watch the invariant grow with every swap instead of computing it.
fn snapshot(market: &mut Market) -> Value {
    let pair = market.pair.pair;
    let (reserve0, reserve1) = reserves(&mut market.executor, pair);
    let supply = total_supply(&mut market.executor, pair);

    json!({
        "pair": pair.to_string(),
        "token0": market.pair.token0.to_string(),
        "token1": market.pair.token1.to_string(),
        "reserve0": reserve0.to_string(),
        "reserve1": reserve1.to_string(),
        "totalSupply": supply.to_string(),
        "k": reserve0.saturating_mul(reserve1).to_string(),
        "sandboxAccount": sandbox_account().to_string(),
    })
}

/// Prints the opening state to stdout.
fn print_state(market: &Shared) {
    let mut locked = lock(market);
    let market = &mut *locked;
    let (reserve0, reserve1) = reserves(&mut market.executor, market.pair.pair);

    println!("zethora-dex: sandbox market");
    println!("  pair     : {}", market.pair.pair);
    println!("  token0   : {}  reserve {reserve0}", market.pair.token0);
    println!("  token1   : {}  reserve {reserve1}", market.pair.token1);
    println!(
        "  lp supply: {}  reserve locked forever",
        total_supply(&mut market.executor, market.pair.pair)
    );
    println!("  k        : {}", reserve0.saturating_mul(reserve1));
    println!("  account  : {}", sandbox_account());
    println!("  balances : {} token0, {} token1", token::balance_of(&mut market.executor, market.pair.token0, sandbox_account()), token::balance_of(&mut market.executor, market.pair.token1, sandbox_account()));
}

// ---------------------------------------------------------------------------
// The HTTP surface
// ---------------------------------------------------------------------------

/// The router the server is built from.
///
/// One endpoint per entry point, and no endpoint for anything the pair does not
/// do: the surface is the ABI, so a client that can call this API can call the
/// contract.
fn router(market: Shared) -> Router {
    Router::new()
        .route("/", get(health))
        .route("/state", get(state))
        .route("/add-liquidity", post(add_liquidity_handler))
        .route("/swap", post(swap_handler))
        .route("/remove-liquidity", post(remove_liquidity_handler))
        .with_state(market)
}

/// `GET /` — liveness, without taking the market lock.
async fn health() -> Json<Value> {
    Json(json!({ "service": "zethora-dex", "ok": true }))
}

/// `GET /state` — the market as it stands.
async fn state(State(market): State<Shared>) -> Json<Value> {
    let mut locked = lock(&market);
    Json(snapshot(&mut locked))
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/// `POST /add-liquidity` body.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddLiquidityRequest {
    /// The depositor, as a `0x`-prefixed hex address.
    account: String,
    /// How much token0 to deposit, as a decimal or `0x` integer string.
    amount_a: String,
    /// How much token1 to deposit, same encoding.
    amount_b: String,
}

/// `POST /swap` body.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SwapRequest {
    /// The trader, as a `0x`-prefixed hex address.
    account: String,
    /// The token being sold: one of the pair's two, or the call is refused.
    token_in: String,
    /// How much of it to sell.
    amount_in: String,
    /// The least the trader will accept back, same encoding. Absent means no
    /// floor, which is only ever right for a sandbox with one user.
    #[serde(default)]
    min_amount_out: Option<String>,
    /// The last block timestamp the trade may land in. Absent means no deadline.
    #[serde(default)]
    deadline: Option<String>,
}

/// `POST /remove-liquidity` body.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoveLiquidityRequest {
    /// The burner, as a `0x`-prefixed hex address.
    account: String,
    /// How much liquidity to burn, in the unit `addLiquidity` returns.
    lp_amount: String,
    /// The least token0 the burner will accept. Absent means no floor.
    #[serde(default)]
    amount_a_min: Option<String>,
    /// The least token1 the burner will accept. Absent means no floor.
    #[serde(default)]
    amount_b_min: Option<String>,
    /// The last block timestamp the burn may land in. Absent means no deadline.
    #[serde(default)]
    deadline: Option<String>,
}

/// A `0x`-prefixed hex address.
fn parse_address(text: &str) -> Result<Address, String> {
    Address::from_str(text.trim()).map_err(|err| format!("{text} is not an address: {err}"))
}

/// A 256-bit unsigned integer, in decimal or `0x` hex.
fn parse_uint(text: &str) -> Result<U256, String> {
    U256::from_str(text.trim()).map_err(|err| format!("{text} is not a 256-bit unsigned integer: {err}"))
}

/// An optional 256-bit integer: absent means `default`.
///
/// The pair's `minAmountOut` and `deadline` are the caller's own terms, and this
/// API leaves them out of a request that has no opinion — `U256::ZERO` for a
/// floor, `U256::MAX` for a deadline — rather than inventing a default the caller
/// did not ask for. The contract enforces whatever is passed either way; what
/// changes is that a sandbox client can say "no floor" by saying nothing.
fn parse_uint_or(text: Option<&str>, default: U256) -> Result<U256, String> {
    match text {
        Some(text) => parse_uint(text),
        None => Ok(default),
    }
}

/// Word `index` of an ABI return payload.
///
/// The pair's entry points return flat `uint256` words, so the decoder is
/// thirty-two bytes of slicing rather than a second ABI implementation:
/// `dispatch` already proved the calldata decoded, and the return is what the same
/// codec encoded.
fn word_at(returned: &[u8], index: usize) -> Result<U256, String> {
    let start = index.saturating_mul(32);
    let end = start.saturating_add(32);
    returned
        .get(start..end)
        .map(U256::from_be_slice)
        .ok_or_else(|| format!("the pair returned {} byte(s), too few to hold word {index}", returned.len()))
}

/// Runs `action` against the market under the lock, turning a refusal into a 400
/// that carries the contract's own message.
///
/// The lock is held for the whole call, which is what stops two concurrent
/// requests from interleaving a reserve read with a reserve write: a trade is one
/// critical section here for the same reason it is one transaction on chain.
fn with_market<F>(market: Shared, action: F) -> Result<Json<Value>, (StatusCode, Json<Value>)>
where
    F: FnOnce(&mut Market) -> Result<Value, String>,
{
    let mut locked = lock(&market);
    match action(&mut locked) {
        Ok(value) => Ok(Json(value)),
        Err(err) => Err((StatusCode::BAD_REQUEST, Json(json!({ "error": err })))),
    }
}

/// Mints `account` exactly the two amounts a deposit is about to need.
///
/// The faucet the sandbox does not have. It lives here, in the binary, and
/// nowhere else: the pair never mints, [`zethora_dex::token::mint_to`] is genesis
/// funding, and no entry point of the contract can reach it.
fn fund(market: &mut Market, account: Address, amount_a: U256, amount_b: U256) -> Result<(), String> {
    token::mint_to(&mut market.executor, market.pair.token0, account, amount_a)
        .map_err(|err| format!("token0 could not be funded: {err}"))?;
    token::mint_to(&mut market.executor, market.pair.token1, account, amount_b)
        .map_err(|err| format!("token1 could not be funded: {err}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /add-liquidity` — funds the caller, then deposits through the ABI.
async fn add_liquidity_handler(
    State(market): State<Shared>,
    Json(request): Json<AddLiquidityRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    with_market(market, |market| {
        let account = parse_address(&request.account)?;
        let amount_a = parse_uint(&request.amount_a)?;
        let amount_b = parse_uint(&request.amount_b)?;

        fund(market, account, amount_a, amount_b)?;

        // The two amounts are named against the tokens they are offered for, so
        // this request stays what it always was — "deposit these totals" — and the
        // pair is what decides which of them is reserve0.
        let returned = dispatch(
            &mut market.executor,
            market.pair.pair,
            account,
            &add_liquidity_calldata(market.pair.token0, amount_a, market.pair.token1, amount_b),
        )
        .map_err(|err| err.to_string())?;
        let liquidity = word_at(&returned, 0)?;

        Ok(json!({ "liquidity": liquidity.to_string(), "state": snapshot(market) }))
    })
}

/// `POST /swap` — trades `amountIn` of `tokenIn` through the ABI.
async fn swap_handler(
    State(market): State<Shared>,
    Json(request): Json<SwapRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    with_market(market, |market| {
        let account = parse_address(&request.account)?;
        let token_in = parse_address(&request.token_in)?;
        let amount_in = parse_uint(&request.amount_in)?;
        let min_amount_out = parse_uint_or(request.min_amount_out.as_deref(), U256::ZERO)?;
        let deadline = parse_uint_or(request.deadline.as_deref(), U256::MAX)?;

        let returned = dispatch(
            &mut market.executor,
            market.pair.pair,
            account,
            &swap_calldata(token_in, amount_in, min_amount_out, deadline),
        )
        .map_err(|err| err.to_string())?;
        let amount_out = word_at(&returned, 0)?;

        Ok(json!({ "amountOut": amount_out.to_string(), "state": snapshot(market) }))
    })
}

/// `POST /remove-liquidity` — burns `lpAmount` and pays both sides out.
async fn remove_liquidity_handler(
    State(market): State<Shared>,
    Json(request): Json<RemoveLiquidityRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    with_market(market, |market| {
        let account = parse_address(&request.account)?;
        let lp_amount = parse_uint(&request.lp_amount)?;
        let amount_a_min = parse_uint_or(request.amount_a_min.as_deref(), U256::ZERO)?;
        let amount_b_min = parse_uint_or(request.amount_b_min.as_deref(), U256::ZERO)?;
        let deadline = parse_uint_or(request.deadline.as_deref(), U256::MAX)?;

        let returned = dispatch(
            &mut market.executor,
            market.pair.pair,
            account,
            &remove_liquidity_calldata(lp_amount, amount_a_min, amount_b_min, deadline),
        )
        .map_err(|err| err.to_string())?;
        let amount0 = word_at(&returned, 0)?;
        let amount1 = word_at(&returned, 1)?;

        Ok(json!({
            "amount0": amount0.to_string(),
            "amount1": amount1.to_string(),
            "state": snapshot(market),
        }))
    })
}
