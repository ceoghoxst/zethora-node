//! Zethora L2 JSON-RPC endpoint.
//!
//! This crate is the outside world's door into the L2. [`zethora_evm`] executes
//! transactions but knows nothing about HTTP, JSON or browsers; this crate is the
//! layer that translates the standard Ethereum JSON-RPC vocabulary into calls on
//! [`zethora_evm::EvmExecutor`], so tooling that already speaks Ethereum —
//! MetaMask, `cast`, `viem`, the explorer — can reach Zethora without a bespoke
//! client.
//!
//! # Why the JSON-RPC envelope is written by hand
//!
//! `jsonrpsee` is not a dependency of this workspace, and adopting it would also
//! mean adopting its own server, its feature flags and its error taxonomy. The
//! envelope this endpoint has to speak is small and fixed: parse
//! `{jsonrpc, id, method, params}`, dispatch on `method`, answer with
//! `{jsonrpc, id, result | error}`. [`dispatch`] does exactly that on top of
//! `axum`, so the wire format is readable in one file instead of being derived
//! behind a macro.
//!
//! # What the endpoint exposes
//!
//! | Method | Answer |
//! | --- | --- |
//! | `eth_chainId` | [`L2_CHAIN_ID`], i.e. `0xa28` |
//! | `eth_blockNumber` | the number of the newest sealed block |
//! | `eth_getBalance` | an account's balance, in wei |
//! | `eth_sendRawTransaction` | the hash of a transaction that is already in a block |
//!
//! Batches (a JSON array of requests) are answered element by element. Every
//! request is answered with HTTP 200 carrying a JSON-RPC `error` object when the
//! call failed, which is what Ethereum nodes do and what clients such as
//! MetaMask expect; a non-200 status would be reported as a transport failure
//! and hide the error the client needs to show.
//!
//! # The state model, and what it deliberately is not
//!
//! There is no chain database behind this endpoint. [`L2Chain`] owns one
//! [`zethora_evm::EvmExecutor`] — an in-memory EVM keyed by address — plus the
//! number of the newest sealed block. Each accepted transaction is executed
//! immediately and seals one block, because the L2 sequencer has instant
//! finality: there is no window in which a transaction is mined but not yet part
//! of a block.
//!
//! The consequences are worth stating plainly, because they are the boundary of
//! what this endpoint can answer:
//!
//! * **No history.** Only current state exists, so `eth_getBalance` answers for
//!   the present whatever block tag it is given, and `eth_getBlockByNumber` does
//!   not exist. State is lost when the process exits.
//! * **No mempool.** `eth_sendRawTransaction` executes as it arrives and returns
//!   the hash of a transaction that already has a block; there is no pending
//!   pool to inspect and nothing to re-broadcast.
//! * **No nonce bookkeeping of its own.** Nonces are enforced by revm against the
//!   account state, exactly as on a real chain.
//! * **The sender is never supplied by the caller.** It is recovered from the
//!   transaction signature inside `zethora-evm`, so a client cannot spend from an
//!   address it does not hold the key for.
//!
//! Anything not listed above answers with JSON-RPC error `-32601`, which is the
//! correct answer for a method this node does not implement, rather than a
//! plausible-looking lie.

mod chain;
mod rpc;
mod types;

pub use chain::{L2Chain, L2Error, L2Rpc, SubmittedTransaction};
pub use rpc::{dispatch, handle};
pub use types::{RpcError, RpcRequest, RpcResponse};

use axum::{Router, routing::post};
use tower_http::cors::CorsLayer;

/// The chain id the L2 reports, and the id transactions must be signed for.
///
/// `2600` is Zethora's own id. It is deliberately not `777`: that id is already
/// claimed by cheapETH, and two chains sharing an id make each one's signed
/// transaction valid input on the other — replay protection is only replay
/// protection if the id is unique, so a collision has to be resolved by moving.
///
/// `zethora-evm` defaults to `1` so unmodified tooling works against it, so the
/// chain this endpoint serves is re-pointed at [`L2_CHAIN_ID`] at construction:
/// what `eth_chainId` reports and what the executor validates have to be the
/// same number, or a wallet would sign transactions the engine then refuses as
/// belonging to another chain.
pub const L2_CHAIN_ID: u64 = 2600;

/// The TCP port the endpoint listens on.
///
/// `8545` is the port every Ethereum client and every wallet defaults to for a
/// local node, which is what makes "add network → http://localhost:8545" work in
/// MetaMask without further configuration.
pub const DEFAULT_RPC_PORT: u16 = 8545;

/// The HTTP path the endpoint is mounted at.
///
/// Ethereum clients post to the root path; a JSON-RPC node serves the same
/// endpoint at every path it accepts, and `/` is the one all of them try first.
pub const RPC_PATH: &str = "/";

/// Builds the JSON-RPC router: the endpoint plus the CORS layer in front of it.
///
/// The state is a [`L2Rpc`] handle rather than a [`L2Chain`], because every
/// request has to reach the same executor and a router clones its state once per
/// connection.
pub fn router(chain: L2Rpc) -> Router {
    Router::new()
        .route(RPC_PATH, post(rpc::handle))
        // MetaMask, the explorer and any page served from another origin call this
        // endpoint from a browser, and a browser refuses to hand the response to
        // JavaScript without CORS headers — including the `OPTIONS` preflight that
        // `permissive` answers before the route is ever reached.
        //
        // `permissive` is the right level here: the endpoint carries no cookies and
        // no session, so a cross-origin caller gains nothing a plain `curl` does not
        // already have. Nothing is authorised by origin, so nothing can be escalated
        // by origin.
        .layer(CorsLayer::permissive())
        .with_state(chain)
}
