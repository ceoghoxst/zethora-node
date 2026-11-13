//! MetaMask transaction lifecycle against the production router.
//!
//! This integration test drives [`zethora_rpc_l2::router`] over HTTP — the same
//! `Service` call `axum::serve` makes for every request, minus the socket —
//! through the steps a wallet performs when the user signs a transfer: estimate
//! gas, submit the signed raw transaction, wait for its receipt, and read the
//! recipient's balance back. It proves the RPC accepts a real EIP-1559 transfer,
//! seals it into a block with `status: 0x1`, and that the resulting balance is
//! visible to the next request (i.e. the state persisted past the transaction).

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
use zethora_rpc_l2::{L2Rpc, RPC_PATH, router};

/// Deterministic signing key, so the test never depends on randomness. It is the
/// same `0x11`-repeated key `zethora-evm` signs its own fixtures with.
const KEY: B256 = B256::repeat_byte(0x11);

/// The chain id transactions must be signed for (`zethora_rpc_l2::L2_CHAIN_ID`).
const CHAIN_ID: u64 = 2600;

/// The recipient of the test transfer.
fn recipient() -> Address {
    Address::repeat_byte(0x22)
}

/// The address that owns [`KEY`], recovered from the signature by the executor.
fn signer_address() -> Address {
    PrivateKeySigner::from_bytes(&KEY).expect("a valid scalar").address()
}

/// The amount transferred: one ether, in wei.
fn transfer_amount() -> U256 {
    U256::from(1_000_000_000_000_000_000u64)
}

/// Lowercase `0x`-prefixed hex of `address`, exactly as the RPC formats one.
fn address_hex(address: Address) -> String {
    format!("0x{}", alloy_primitives::hex::encode(address.as_slice()))
}

/// Builds and signs an EIP-1559 transfer of `value` wei to `to`, and returns the
/// `0x`-prefixed raw bytes `eth_sendRawTransaction` takes.
///
/// The gas prices are zero because the L2 has no fee market, so a transfer costs
/// nothing to send and the recipient receives exactly `value`.
fn raw_transfer(to: Address, value: U256) -> String {
    let transaction = TxEip1559 {
        chain_id: CHAIN_ID,
        nonce: 0,
        gas_limit: 21_000,
        max_fee_per_gas: 0,
        max_priority_fee_per_gas: 0,
        to: TxKind::Call(to),
        value,
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

/// Reads `address`'s balance in wei through the router.
async fn balance<S>(app: &S, address: Address) -> U256
where
    S: Service<Request<Body>, Response = Response> + Clone,
    S::Error: std::fmt::Debug,
{
    let response = call(app, 0, "eth_getBalance", json!([address_hex(address), "latest"])).await;
    let quantity = response["result"].as_str().expect("eth_getBalance returns a quantity");
    U256::from_str_radix(quantity.trim_start_matches("0x"), 16).expect("a hex quantity")
}

/// Asserts `value` is a JSON-RPC **quantity**: `0x`, no leading zeros, hex digits.
fn assert_quantity(value: &str, what: &str) {
    let digits = value.strip_prefix("0x").unwrap_or_else(|| panic!("{what}: {value:?} is not 0x-prefixed"));
    assert!(!digits.is_empty(), "{what}: {value:?} has no digits");
    assert!(digits.chars().all(|c| c.is_ascii_hexdigit()), "{what}: {value:?} is not hex");
    if digits.len() > 1 {
        assert!(!digits.starts_with('0'), "{what}: {value:?} has a leading zero");
    }
}

/// Asserts `value` is a JSON-RPC **data** string: `0x` plus a whole number of bytes.
fn assert_data(value: &str, what: &str) {
    let digits = value.strip_prefix("0x").unwrap_or_else(|| panic!("{what}: {value:?} is not 0x-prefixed"));
    assert!(digits.chars().all(|c| c.is_ascii_hexdigit()), "{what}: {value:?} is not hex");
    assert_eq!(digits.len() % 2, 0, "{what}: {value:?} is not a whole number of bytes");
}

#[tokio::test]
async fn metamask_lifecycle_sends_a_transfer_and_persists_the_balance() {
    // 1. Spin up the production router on a fresh chain.
    let app = router(L2Rpc::new());

    // 2. `eth_estimateGas` answers with a hex quantity (the block gas budget).
    let estimate = call(&app, 1, "eth_estimateGas", json!([{ "to": address_hex(recipient()) }])).await;
    let gas = estimate["result"].as_str().expect("eth_estimateGas returns a result");
    assert_quantity(gas, "eth_estimateGas");
    let gas_limit = u64::from_str_radix(&gas[2..], 16).expect("a hex gas limit");
    assert!(gas_limit > 0, "the gas estimate is non-zero");

    // 3. The recipient starts empty, so the balance check below proves a transfer.
    let before = balance(&app, recipient()).await;
    assert_eq!(before, U256::ZERO, "the recipient starts with no balance");

    // 4. Submit a signed raw transfer and read back its transaction hash.
    let raw = raw_transfer(recipient(), transfer_amount());
    let sent = call(&app, 2, "eth_sendRawTransaction", json!([raw])).await;
    let hash = sent["result"].as_str().expect("eth_sendRawTransaction returns a hash");
    assert_eq!(hash.len(), 66, "a transaction hash is 0x followed by 32 bytes");
    assert_data(hash, "eth_sendRawTransaction");

    // 5. The receipt reports the transaction succeeded and landed in a block.
    let receipt = call(&app, 3, "eth_getTransactionReceipt", json!([hash])).await;
    let receipt = receipt["result"].as_object().expect("the receipt is an object");
    assert_eq!(receipt["status"], json!("0x1"), "the transaction succeeded");
    assert_eq!(receipt["transactionHash"], json!(hash), "the hash matches");
    assert_eq!(receipt["from"], json!(address_hex(signer_address())), "the sender was recovered");
    assert_eq!(receipt["to"], json!(address_hex(recipient())), "the recipient matches");
    assert_eq!(receipt["blockNumber"], json!("0x1"), "the transfer sealed into the first block");
    assert_eq!(receipt["type"], json!("0x2"), "the transfer was EIP-1559");

    // 6. The recipient's balance increased by exactly the transferred amount.
    let after = balance(&app, recipient()).await;
    assert!(after > before, "the recipient balance increased");
    assert_eq!(after, transfer_amount(), "the recipient received the full transfer");
}

