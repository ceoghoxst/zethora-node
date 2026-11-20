//! `eth_getTransactionCount`: the only way a client can learn which nonce its next
//! transaction has to carry.
//!
//! `zethora-evm` executes transactions through revm, which enforces exact nonces:
//! a transaction that guesses is refused, not queued. A client that sends more than
//! one transaction — the L1 → L2 treasury relayer sends a `registerMiner` and then
//! an `oracleUpdateShares` in the same pass — therefore has to ask for the count
//! before each signature instead of counting locally.
//!
//! These tests pin the two halves of that contract through the production router:
//! the count follows what the sender has actually sent, and a transaction at a
//! nonce the node disagrees with is refused rather than silently replacing one.

use alloy_consensus::{SignableTransaction, Signed, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, B256, Bytes, TxKind, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use axum::body::Body;
use axum::http::{Request, header};
use axum::response::Response;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::{Service, ServiceExt};
use zethora_rpc_l2::{L2_CHAIN_ID, L2Rpc, RPC_PATH, router};

/// The deterministic signing key the L2's other tests use, so no test depends on
/// randomness and every fixture address is reproducible.
const KEY: B256 = B256::repeat_byte(0x11);

/// The account every transaction in this file is signed by.
fn sender() -> Address {
    PrivateKeySigner::from_bytes(&KEY).expect("a valid scalar").address()
}

/// An address built from one repeated byte, for the fixtures below.
fn address_of(byte: u8) -> Address {
    Address::repeat_byte(byte)
}

/// Lowercase `0x`-prefixed hex of `address`, exactly as the RPC formats one.
fn address_hex(address: Address) -> String {
    format!("0x{}", alloy_primitives::hex::encode(address.as_slice()))
}

/// Builds and signs a transfer of one wei to `to` at `nonce`, and returns the
/// `0x`-prefixed raw bytes `eth_sendRawTransaction` takes.
///
/// The recipient is a parameter because the hash of a transaction covers it: two
/// transactions that differ only in recipient produce different hashes, which is
/// what lets the replay test ask for the *same* nonce twice with different bytes.
fn raw_transfer(nonce: u64, to: Address) -> String {
    let transaction = TxEip1559 {
        chain_id: L2_CHAIN_ID,
        nonce,
        gas_limit: 21_000,
        // A zero price is legal here: this L2 has no base fee and no fee market.
        max_fee_per_gas: 0,
        max_priority_fee_per_gas: 0,
        to: TxKind::Call(to),
        value: U256::from(1u64),
        input: Bytes::new(),
        access_list: Default::default(),
    };
    let signer = PrivateKeySigner::from_bytes(&KEY).expect("a valid scalar");
    let hash = transaction.signature_hash();
    let signature = SignerSync::sign_hash_sync(&signer, &hash).expect("the transaction signs");
    let envelope = TxEnvelope::Eip1559(Signed::new_unchecked(transaction, signature, hash));

    let mut encoded = Vec::new();
    Encodable2718::encode_2718(&envelope, &mut encoded);
    format!("0x{}", alloy_primitives::hex::encode(encoded))
}

/// Posts one JSON-RPC request through the production router and returns the
/// parsed response body.
async fn call<S>(app: &S, id: u64, method: &str, params: Value) -> Value
where
    S: Service<Request<Body>, Response = Response> + Clone,
    S::Error: std::fmt::Debug,
{
    let payload = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
    let request = Request::builder()
        .method("POST")
        .uri(RPC_PATH)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(payload.to_string()))
        .expect("the request is well formed");

    let response = app.clone().oneshot(request).await.expect("the router answers");
    let bytes = response.into_body().collect().await.expect("the body is readable").to_bytes();
    serde_json::from_slice(&bytes).expect("the body is a JSON-RPC response")
}

/// Reads `address`'s transaction count through the router.
async fn transaction_count<S>(app: &S, address: Address) -> u64
where
    S: Service<Request<Body>, Response = Response> + Clone,
    S::Error: std::fmt::Debug,
{
    let response = call(app, 0, "eth_getTransactionCount", json!([address_hex(address), "latest"])).await;
    let quantity = response["result"].as_str().unwrap_or_else(|| panic!("eth_getTransactionCount failed: {response}"));
    u64::from_str_radix(quantity.trim_start_matches("0x"), 16).expect("a hex quantity")
}

#[tokio::test]
async fn the_count_follows_the_transactions_the_sender_has_sent() {
    let app = router(L2Rpc::new());
    assert_eq!(transaction_count(&app, sender()).await, 0, "an account that has sent nothing counts nothing");

    // The two sends the relayer performs in one pass: ask for the count, sign with
    // it, send, repeat. Each one has to be accepted at the nonce the previous
    // answer named.
    for nonce in [0u64, 1] {
        let sent = call(&app, 1, "eth_sendRawTransaction", json!([raw_transfer(nonce, address_of(0x22))])).await;
        let hash = sent["result"].as_str().unwrap_or_else(|| panic!("the transaction at nonce {nonce} was refused: {sent}"));

        let receipt = call(&app, 2, "eth_getTransactionReceipt", json!([hash])).await;
        assert_eq!(receipt["result"]["status"], json!("0x1"), "the transaction at nonce {nonce} was sealed");

        assert_eq!(transaction_count(&app, sender()).await, nonce + 1, "the count follows the send");
    }

    // An account that has only received has still sent nothing.
    assert_eq!(transaction_count(&app, address_of(0x22)).await, 0, "receiving does not consume a nonce");
}

#[tokio::test]
async fn a_nonce_the_node_does_not_expect_is_refused() {
    let app = router(L2Rpc::new());

    let first = call(&app, 1, "eth_sendRawTransaction", json!([raw_transfer(0, address_of(0x22))])).await;
    assert!(first["result"].is_string(), "the first transaction is accepted: {first}");

    // Nonce 0 again, with a different recipient so the bytes and the hash differ:
    // this is what a client that counted locally would send after a restart, and
    // the node has to say no instead of overwriting the nonce.
    let replayed = call(&app, 2, "eth_sendRawTransaction", json!([raw_transfer(0, address_of(0x33))])).await;
    assert!(replayed.get("error").is_some(), "a replayed nonce is refused: {replayed}");

    // The count did not move, so the next honest send is still accepted.
    assert_eq!(transaction_count(&app, sender()).await, 1);
    let next = call(&app, 3, "eth_sendRawTransaction", json!([raw_transfer(1, address_of(0x33))])).await;
    assert!(next["result"].is_string(), "nonce 1 is accepted: {next}");
}

#[tokio::test]
async fn a_malformed_address_is_reported_as_an_error() {
    let app = router(L2Rpc::new());

    // `0x11` is one byte, not twenty. An answer of `0x0` would be indistinguishable
    // from "this account has sent nothing", so the call has to fail instead.
    let response = call(&app, 1, "eth_getTransactionCount", json!(["0x11", "latest"])).await;
    assert!(response.get("error").is_some(), "a short address is refused: {response}");
    assert!(response.get("result").is_none());
}
