//! Where a gas fee ends up, proved through the production router.
//!
//! `zethora-evm` splits every gas fee: the block beneficiary keeps the producer's
//! share and `MINER_TREASURY_FEE_BPS` of the tip is routed to the executor's miner
//! treasury. The split can only move what the beneficiary was credited with, so a
//! block that names no beneficiary (the zero address, which is what this node used
//! before it could be configured) routes nothing at all — see
//! `zethora_evm::EvmExecutor::route_miner_treasury_fee`.
//!
//! That is why `L2Chain::with_config` names the configured treasury as the block
//! beneficiary as well. With `basefee` at zero this L2 has no fee market, so the
//! whole gas price is tip and the account revm credits *is* the treasury: the money
//! reaches `ZefTreasury` in one move, and the executor's split reports "the
//! producer is the treasury" instead of double-counting it.
//!
//! The two tests below pin both halves of that wiring through the public JSON-RPC
//! surface: a node built with a treasury credits it with the fee of every
//! transaction it seals, and a node built without one credits nobody (the fee stays
//! at the zero address, i.e. is burned).

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
use zethora_rpc_l2::{L2_CHAIN_ID, L2ChainConfig, L2Rpc, RPC_PATH, router};

/// Deterministic signing key, so the test never depends on randomness. It is the
/// same `0x11`-repeated key `zethora-evm` signs its own fixtures with.
const KEY: B256 = B256::repeat_byte(0x11);

/// The tip every transaction in this test offers, in wei per gas.
///
/// Non-zero on purpose: a fee of zero would make "the treasury was paid" and "the
/// fee went nowhere" indistinguishable.
const GAS_PRICE: u128 = 1_000_000_000;

/// The address the node is told to pay: a stand-in for the deployed `ZefTreasury`
/// contract. It is nobody's key, which is the point — the fee is collected without
/// the treasury ever executing code.
fn treasury() -> Address {
    Address::repeat_byte(0x7e)
}

/// The recipient of the test transfer.
fn recipient() -> Address {
    Address::repeat_byte(0x22)
}

/// The amount transferred: one ether, in wei.
fn transfer_amount() -> U256 {
    U256::from(1_000_000_000_000_000_000u64)
}

/// Lowercase `0x`-prefixed hex of `address`, exactly as the RPC formats one.
fn address_hex(address: Address) -> String {
    format!("0x{}", alloy_primitives::hex::encode(address.as_slice()))
}

/// Builds and signs an EIP-1559 transfer of `value` wei to `to` that offers
/// [`GAS_PRICE`], and returns the `0x`-prefixed raw bytes
/// `eth_sendRawTransaction` takes.
///
/// The sender is not funded here: the executor tops up whatever account the
/// signature recovers to, which is what makes a fee-paying transaction testable
/// without a faucet.
fn raw_transfer(to: Address, value: U256) -> String {
    let transaction = TxEip1559 {
        chain_id: L2_CHAIN_ID,
        nonce: 0,
        gas_limit: 21_000,
        max_fee_per_gas: GAS_PRICE,
        max_priority_fee_per_gas: GAS_PRICE,
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

/// Submits one priced transfer through the router and returns the fee it paid: the
/// tip per gas times the gas its receipt reports.
///
/// The fee is derived from the receipt rather than assumed to be
/// `gas_limit * GAS_PRICE`, because an EVM refund would make the two differ and the
/// assertions in the callers are about what was actually charged.
async fn send_one_priced_transfer<S>(app: &S) -> U256
where
    S: Service<Request<Body>, Response = Response> + Clone,
    S::Error: std::fmt::Debug,
{
    let sent = call(app, 1, "eth_sendRawTransaction", json!([raw_transfer(recipient(), transfer_amount())])).await;
    let hash = sent["result"].as_str().unwrap_or_else(|| panic!("eth_sendRawTransaction failed: {sent}"));
    assert_eq!(hash.len(), 66, "a transaction hash is 0x followed by 32 bytes");

    let receipt = call(app, 2, "eth_getTransactionReceipt", json!([hash])).await;
    let receipt = receipt["result"].as_object().expect("the receipt is an object");
    assert_eq!(receipt["status"], json!("0x1"), "the transaction succeeded");

    let gas_used = receipt["gasUsed"].as_str().expect("the receipt reports gasUsed");
    let gas_used = u128::from_str_radix(gas_used.trim_start_matches("0x"), 16).expect("a hex quantity");
    assert!(gas_used > 0, "a sealed transaction consumed gas");

    U256::from(gas_used) * U256::from(GAS_PRICE)
}

#[tokio::test]
async fn a_configured_treasury_is_credited_with_the_fee_of_every_transaction() {
    // The wiring under test: `MINER_TREASURY_ADDRESS` parsed into a plain config,
    // handed to the chain, and from there to the executor.
    let app = router(L2Rpc::from_config(L2ChainConfig::new(L2_CHAIN_ID).with_miner_treasury(treasury())));
    assert_eq!(balance(&app, treasury()).await, U256::ZERO, "the treasury starts empty");

    let fee = send_one_priced_transfer(&app).await;
    assert!(fee > U256::ZERO, "a transaction paying a non-zero gas price owes a non-zero fee");

    // The fee reached the account the node was told to pay, and it is there to be
    // distributed: the treasury is a contract, and the payment was a plain balance
    // move that never executed its code.
    assert_eq!(balance(&app, treasury()).await, fee, "the treasury was credited with the fee");

    // Nothing was left at the zero address, i.e. none of the fee was burned.
    assert_eq!(balance(&app, Address::ZERO).await, U256::ZERO, "the fee did not go to the zero address");

    // `eth_getBlockByNumber` names the account that was paid, so a client can see
    // the routing without trusting this test's arithmetic.
    let block = call(&app, 3, "eth_getBlockByNumber", json!(["0x1", false])).await;
    assert_eq!(block["result"]["miner"], json!(address_hex(treasury())), "the block names the treasury as its producer");
}

#[tokio::test]
async fn a_node_without_a_treasury_leaves_the_fee_at_the_zero_address() {
    // The default configuration: no `MINER_TREASURY_ADDRESS`, therefore no
    // beneficiary and no treasury. This is the behaviour every earlier version of
    // the node had, and it must not change by accident.
    let app = router(L2Rpc::new());

    let fee = send_one_priced_transfer(&app).await;
    assert!(fee > U256::ZERO, "the transaction still paid a fee");

    assert_eq!(balance(&app, treasury()).await, U256::ZERO, "a treasury that was never configured is not paid");
    assert_eq!(balance(&app, Address::ZERO).await, fee, "the fee stays where an unconfigured node puts it");

    let block = call(&app, 3, "eth_getBlockByNumber", json!(["0x1", false])).await;
    assert_eq!(block["result"]["miner"], json!(address_hex(Address::ZERO)), "the block names no producer");
}
