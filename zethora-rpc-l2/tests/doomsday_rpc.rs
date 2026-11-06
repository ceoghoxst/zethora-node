//! Doomsday suite for the Zethora L2 public JSON-RPC endpoint.
//!
//! Every test here is an attack on the process a wallet's `fetch()` actually
//! reaches: the production router from [`zethora_rpc_l2::router`], driven through
//! the same tower `Service::call` that `axum::serve` performs for each request.
//! Nothing is stubbed and no handler is called directly, so the body limit, the
//! JSON parser, the dispatcher, the chain mutex and the CORS layer all see the
//! attacker's bytes in the order a deployment would see them.
//!
//! Four families of attack, none of which may end in a crash, a hang or a 5xx:
//!
//! * **JSON body DoS** — a ten-thousand-level nested document and a ten megabyte
//!   body. The defence is two layers deep, and both are real here: axum's
//!   `DefaultBodyLimit` refuses to buffer a body that is too large, and
//!   `serde_json`'s recursion limit refuses to recurse into one that is too deep.
//!   A nested array is parsed recursively, so a parser without that limit is a
//!   stack overflow reachable with ten kilobytes of `[`.
//! * **malformed calldata** — hex that is not hex, bytes that are not a
//!   transaction, and a transaction whose gas limit no block could ever hold.
//! * **invalid batches** — an empty batch, ten thousand refusals in a single
//!   body, and junk sitting between honest requests.
//! * **method confusion** — methods that do not exist, and parameters of the
//!   wrong JSON type where a string belongs.
//!
//! Every test ends with a health check, because "the reply was wrong" is not the
//! only failure that matters. A panic inside a handler poisons the chain mutex,
//! and [`zethora_rpc_l2::L2Rpc::with_chain`] deliberately refuses to recover from
//! a poisoned lock: every request after such a panic answers `-32603` on a
//! process that still looks alive. An `eth_chainId` that still answers `0xa28`
//! after the attack is the difference between "refused" and "wedged".

#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use zethora_rpc_l2::{L2_CHAIN_ID, L2Rpc, router};

// The JSON-RPC codes, written out rather than imported: `zethora_rpc_l2::types`
// is a private module, and an adversarial test should assert the number the
// specification fixes (`-32602`), not whatever constant the server happens to be
// built from. If the two ever disagree, this file is the one that is right.

/// The body was not JSON.
const PARSE_ERROR: i64 = -32700;
/// The body was JSON but not a request.
const INVALID_REQUEST: i64 = -32600;
/// The method does not exist on this endpoint.
const METHOD_NOT_FOUND: i64 = -32601;
/// The parameters are malformed, missing, or name something invalid.
const INVALID_PARAMS: i64 = -32602;
/// The range Ethereum nodes use for "well formed, but I will not include this".
const SERVER_ERROR: i64 = -32000;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// The endpoint under attack: one router over one chain, kept for the whole test.
///
/// The chain is shared rather than rebuilt per request, because half of these
/// attacks are about state: a refused transaction that sealed a block anyway, or
/// a panic that poisoned the executor, is only visible if the next request runs
/// against the same state.
struct Endpoint {
    app: Router,
}

impl Endpoint {
    fn new() -> Self {
        Self { app: router(L2Rpc::new()) }
    }

    /// `POST /` with `body` verbatim, exactly as a wallet would send it.
    async fn post(&self, body: impl Into<Body>) -> Reply {
        let request = Request::builder()
            .method("POST")
            .uri("/")
            .header("content-type", "application/json")
            // A browser sets this itself. A refusal must never depend on it.
            .header("origin", "http://localhost:3000")
            .body(body.into())
            .expect("a well formed HTTP request");

        // `Router` clones share the chain, so every request in one test hits the
        // same executor: this is the same `Service::call` `axum::serve` makes.
        let response = self.app.clone().oneshot(request).await.expect("the router to answer");
        let status = response.status();
        let body = response.into_body().collect().await.map(|collected| collected.to_bytes().to_vec()).unwrap_or_default();
        Reply { status, body }
    }

    /// `POST /` with a JSON payload.
    async fn post_json(&self, payload: &Value) -> Reply {
        self.post(payload.to_string()).await
    }

    /// `POST /` with a raw string payload, for bodies that must not be re-encoded
    /// (a nesting bomb, a megabyte of quotes) or that are not valid JSON at all.
    async fn post_str(&self, payload: &str) -> Reply {
        self.post(payload.to_string()).await
    }

    /// Proves the endpoint is still answering from a healthy chain.
    ///
    /// This is the assertion that catches a panic: the handler holds a `Mutex`
    /// guard across the whole call, and a panic inside it poisons the lock, after
    /// which every request answers `-32603` for the life of the process.
    async fn assert_still_serving(&self) {
        let reply = self.post_str(r#"{"jsonrpc":"2.0","id":"health","method":"eth_chainId","params":[]}"#).await;

        assert_eq!(reply.status, StatusCode::OK, "the endpoint must still answer after the attack: {}", reply.text());

        let expected = format!("0x{L2_CHAIN_ID:x}");
        assert_eq!(
            reply.json().get("result").and_then(Value::as_str),
            Some(expected.as_str()),
            "a refused request must leave the chain usable, not poison its lock: {}",
            reply.text()
        );
        assert_eq!(reply.json().get("id").and_then(Value::as_str), Some("health"), "the request id must still be echoed");
    }

    /// Proves nothing was mined. A transaction the node refused must never be
    /// reported as part of a block, so the head must still be at genesis.
    async fn assert_nothing_was_mined(&self) {
        let reply = self.post_str(r#"{"jsonrpc":"2.0","id":"head","method":"eth_blockNumber","params":[]}"#).await;

        assert_eq!(
            reply.json().get("result").and_then(Value::as_str),
            Some("0x0"),
            "a refused transaction must never seal a block: {}",
            reply.text()
        );
    }
}

/// A response reduced to what a test asserts on, so hyper's types do not leak
/// into every call.
struct Reply {
    status: StatusCode,
    body: Vec<u8>,
}

impl Reply {
    /// The body as text, lossily: a transport-level refusal is not guaranteed to
    /// be UTF-8, or to be JSON at all.
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// The body as JSON, or a panic naming what arrived instead. Every response
    /// this endpoint produces is JSON; anything else is a finding.
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|err| panic!("the reply must be JSON ({err}): {}", self.text()))
    }

    /// The `error.code` of a single (non-batched) reply.
    ///
    /// The HTTP status is checked first and the absence of `result` second: a
    /// JSON-RPC failure is HTTP 200 carrying an `error` object, and a reply that
    /// carried both would let a client that trusts `result` act on a failure.
    fn error_code(&self) -> i64 {
        assert_eq!(self.status, StatusCode::OK, "a JSON-RPC failure is HTTP 200, not {}: {}", self.status, self.text());

        let json = self.json();
        assert!(json.get("result").is_none(), "an error reply must not also carry a result: {}", self.text());
        json.pointer("/error/code")
            .and_then(Value::as_i64)
            .unwrap_or_else(|| panic!("expected a JSON-RPC error object: {}", self.text()))
    }
}

/// The numeric code of one batch answer.
fn error_code_of(answer: &Value) -> i64 {
    answer
        .pointer("/error/code")
        .and_then(Value::as_i64)
        .unwrap_or_else(|| panic!("expected a JSON-RPC error object, got {answer}"))
}

/// One `eth_sendRawTransaction` carrying `raw` verbatim.
fn send_raw_request(id: u64, raw: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "eth_sendRawTransaction", "params": [raw]})
}

/// `0x`-prefixed lowercase hex, the only form `eth_sendRawTransaction` accepts.
fn hex_data(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(2 + bytes.len() * 2);
    encoded.push_str("0x");
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

// ---------------------------------------------------------------------------
// RLP, for the one attack that has to send a *well formed* transaction.
//
// The RPC crate has no RLP codec (it delegates decoding to `zethora-evm`), and a
// transaction is nine items long, so the two encodings it needs are written out
// here rather than pulling a dependency into a test.
// ---------------------------------------------------------------------------

/// The minimal big-endian bytes of `value`, i.e. RLP's integer form: zero is the
/// empty string, never `0x00`.
fn be_uint(value: u128) -> Vec<u8> {
    let be = value.to_be_bytes();
    let first_significant = be.iter().position(|byte| *byte != 0).unwrap_or(be.len());
    be[first_significant..].to_vec()
}

/// Appends one RLP header: the short form for a payload of at most 55 bytes, the
/// long form (prefix, then the length as its own big-endian integer) above it.
fn push_rlp_header(out: &mut Vec<u8>, short_offset: u8, length: usize) {
    if length <= 55 {
        out.push(short_offset + length as u8);
        return;
    }
    let be = length.to_be_bytes();
    let first_significant = be.iter().position(|byte| *byte != 0).unwrap_or(be.len() - 1);
    let significant = &be[first_significant..];
    out.push(short_offset + 55 + significant.len() as u8);
    out.extend_from_slice(significant);
}

/// Encodes `bytes` as one RLP string item.
fn rlp_string(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + 9);
    if bytes.len() == 1 && bytes[0] < 0x80 {
        // A single byte below 0x80 is its own encoding.
        out.push(bytes[0]);
        return out;
    }
    push_rlp_header(&mut out, 0x80, bytes.len());
    out.extend_from_slice(bytes);
    out
}

/// Frames already-encoded items as one RLP list.
fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload: usize = items.iter().map(Vec::len).sum();
    let mut out = Vec::with_capacity(payload + 9);
    push_rlp_header(&mut out, 0xc0, payload);
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

/// A legacy (EIP-155) transaction with `gas_limit` as its gas limit and a junk
/// `(r, s) = (1, 1)` signature.
///
/// `v` is `chain_id * 2 + 35`, i.e. 5235 for Zethora's 2600, so the envelope is
/// shaped exactly like a real L2 transaction. Whether that signature recovers is
/// beside the point: the attacker is testing the *gas limit*, and a node that
/// lets `u64::MAX` through has a worse problem than one forged key.
fn legacy_transaction_with_gas_limit(gas_limit: &[u8]) -> Vec<u8> {
    let to = [0x11u8; 20];
    let fields: [Vec<u8>; 9] = [
        be_uint(0),                                // nonce
        be_uint(1),                                // gas price
        gas_limit.to_vec(),                        // gas limit: the attack
        to.to_vec(),                               // recipient
        be_uint(0),                                // value
        Vec::new(),                                // input
        be_uint(u128::from(L2_CHAIN_ID) * 2 + 35), // v: EIP-155 for this chain
        be_uint(1),                                // r
        be_uint(1),                                // s
    ];
    let items: Vec<Vec<u8>> = fields.iter().map(|field| rlp_string(field)).collect();
    rlp_list(&items)
}

// ---------------------------------------------------------------------------
// Attack 1: JSON body DoS.
// ---------------------------------------------------------------------------

/// How deep the nesting bomb goes. Ten thousand array levels is 20 KB of body and,
/// if the parser recursed once per level, ten thousand stack frames.
const DEPTH: usize = 10_000;

/// Ten megabytes, the size the brief names.
const TEN_MEGABYTES: usize = 10 * 1024 * 1024;

#[tokio::test]
async fn attack_1a_deeply_nested_json_is_a_parse_error_not_a_stack_overflow() {
    let endpoint = Endpoint::new();

    // A bare bomb: `[[[[ ... ]]]]`.
    let payload = format!("{}{}", "[".repeat(DEPTH), "]".repeat(DEPTH));
    assert_eq!(payload.len(), DEPTH * 2, "the bomb must really be {DEPTH} levels deep");

    let reply = endpoint.post_str(&payload).await;

    // `serde_json` refuses past its recursion limit rather than following the
    // input down, which is the whole reason a 20 KB body cannot smash the stack.
    assert_eq!(
        reply.error_code(),
        PARSE_ERROR,
        "a body deeper than the recursion limit must be -32700, never a panic: {}",
        reply.text()
    );
    // Nothing could be read out of the body, so there is no id to echo.
    assert_eq!(reply.json().get("id"), Some(&Value::Null), "an unparsable body cannot carry an id");
    endpoint.assert_still_serving().await;
}

#[tokio::test]
async fn attack_1b_deep_nesting_inside_a_valid_request_is_still_a_parse_error() {
    let endpoint = Endpoint::new();

    // The same bomb, hidden in the `params` of a request that is otherwise
    // perfectly valid. The parse fails before any method is dispatched, so
    // `eth_chainId` never runs and no half-applied request is possible.
    let payload = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_chainId\",\"params\":{}{}}}",
        "[".repeat(DEPTH),
        "]".repeat(DEPTH)
    );

    let reply = endpoint.post_str(&payload).await;

    assert_eq!(reply.error_code(), PARSE_ERROR, "a valid envelope does not buy the bomb a deeper limit: {}", reply.text());
    assert_eq!(reply.json().get("id"), Some(&Value::Null), "the request was never parsed, so its id was never read");
    endpoint.assert_still_serving().await;
}

#[tokio::test]
async fn attack_1c_a_ten_megabyte_body_is_refused_without_a_crash() {
    let endpoint = Endpoint::new();

    // A single 10 MB JSON string, in `params`. A string is valid JSON at any size,
    // so only a size limit stands between this and a 10 MB allocation per request.
    let payload = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_chainId",
        "params": ["a".repeat(TEN_MEGABYTES)],
    })
    .to_string();
    assert!(payload.len() > TEN_MEGABYTES, "the bomb must really be ten megabytes, it is {} bytes", payload.len());

    let reply = endpoint.post_str(&payload).await;

    if reply.status == StatusCode::PAYLOAD_TOO_LARGE {
        // The right answer, and the one a deployment gives: axum's `DefaultBodyLimit`
        // (2 MB) refuses to buffer the body, so the parser never sees a byte of it and
        // running out of memory is not reachable from here.
        assert!(reply.body.len() < 64 * 1024, "the refusal itself must not echo the body back: {} bytes", reply.body.len());
    } else if reply.status == StatusCode::OK {
        // If that limit is ever raised, the parser still has to answer in JSON-RPC
        // rather than truncate, panic, or hand back something that is not JSON.
        let json = reply.json();
        assert_eq!(json.get("jsonrpc").and_then(Value::as_str), Some("2.0"), "a huge body must still be answered in JSON-RPC");
        assert!(
            json.get("result").is_some() || json.get("error").is_some(),
            "a huge body must produce a result or an error, not neither: {}",
            reply.text()
        );
    } else {
        panic!("a ten megabyte body must be refused (413) or answered (200), not {}", reply.status);
    }

    // The process is still the same process: the next request is answered from
    // the same chain.
    endpoint.assert_still_serving().await;
}

#[tokio::test]
async fn attack_1d_a_one_megabyte_string_body_is_an_invalid_request() {
    // Deliberately *under* the transport limit, so this body really is parsed: a
    // megabyte of quotes has to be walked to its end and then rejected as "not a
    // request", which is the parser doing the work rather than the body limit.
    const ONE_MEGABYTE: usize = 1024 * 1024;

    let endpoint = Endpoint::new();
    let payload = format!("\"{}\"", "a".repeat(ONE_MEGABYTE));
    assert!(payload.len() > ONE_MEGABYTE);

    let reply = endpoint.post_str(&payload).await;

    assert_eq!(reply.error_code(), INVALID_REQUEST, "a JSON string is not a JSON-RPC request: {}", reply.text());
    endpoint.assert_still_serving().await;
}

// ---------------------------------------------------------------------------
// Attack 2: malformed calldata on the one method that writes.
//
// `eth_sendRawTransaction` is the only endpoint that hands attacker-controlled
// bytes to a decoder (`zethora_evm::decode_transaction`) and then to the EVM. Every
// input here is something a fuzzer or a broken wallet really sends, and every one
// of them must come back as a JSON-RPC error: a 5xx, or a panic in the decoder,
// would mean the node is answerable-with-one-packet.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn attack_2a_malformed_raw_transaction_hex_is_an_invalid_params_error() {
    let endpoint = Endpoint::new();

    let mut cases: Vec<(&str, String)> = vec![
        ("empty string", String::new()),
        ("bare prefix", "0x".to_string()),
        ("odd number of digits", "0x0".to_string()),
        ("non-hex digits", "0xzzzz".to_string()),
        ("plain text", "send me all your eth".to_string()),
        ("unicode that is not hex", "0x◊◊".to_string()),
        ("a single byte, not a transaction", "0x12".to_string()),
        ("legacy envelope with no body", "0x00".to_string()),
        ("typed envelope with no body", "0x02".to_string()),
        ("whitespace", "   ".to_string()),
        ("an address, not a transaction", hex_data(&[0x11u8; 20])),
    ];
    // 100 KB of `0xff` decodes as a legacy list whose RLP header declares a length
    // the body does not have: the decoder has to stop at the length check instead
    // of trusting it and reading past the buffer.
    cases.push(("100 KB of RLP that lies about its length", format!("0x{}", "ff".repeat(50_000))));

    for (index, (label, raw)) in cases.iter().enumerate() {
        let reply = endpoint.post_json(&send_raw_request(index as u64, raw)).await;

        assert_eq!(
            reply.error_code(),
            INVALID_PARAMS,
            "{label}: a raw transaction that cannot be decoded is -32602, never a 5xx: {}",
            reply.text()
        );
        assert_eq!(
            reply.json().get("id").and_then(Value::as_u64),
            Some(index as u64),
            "{label}: the id must be echoed so the client can match the refusal"
        );
    }

    // None of the junk above was mined or buffered as a pending transaction.
    endpoint.assert_nothing_was_mined().await;
    endpoint.assert_still_serving().await;
}

#[tokio::test]
async fn attack_2b_a_transaction_with_an_impossible_gas_limit_is_refused() {
    let endpoint = Endpoint::new();

    // Two ways to be impossible. `u64::MAX` is a *decodable* gas limit, so it gets
    // all the way to the EVM and must be refused there; 2^256-1 does not even fit
    // the field and must be refused by the decoder. Neither may be accepted, and
    // neither may take the process down.
    let cases: [(&str, Vec<u8>); 2] = [
        ("a gas limit of u64::MAX", u64::MAX.to_be_bytes().to_vec()),
        ("a gas limit of 2^256-1", vec![0xff; 32]),
    ];

    for (index, (label, gas_limit)) in cases.iter().enumerate() {
        let raw = hex_data(&legacy_transaction_with_gas_limit(gas_limit));
        let reply = endpoint.post_json(&send_raw_request(index as u64, &raw)).await;

        let code = reply.error_code();
        assert!(
            code == INVALID_PARAMS || code == SERVER_ERROR,
            "{label}: must be refused as -32602 (undecodable) or -32000 (refused by the node), got {code}: {}",
            reply.text()
        );

        let message = reply.json().pointer("/error/message").and_then(Value::as_str).unwrap_or_default().to_string();
        assert!(!message.is_empty(), "{label}: a refusal must say why, and this one said nothing");
    }

    // The point of the whole attack: a gas limit larger than any block must not
    // buy a block. If it did, a single free request would have wedged this chain.
    endpoint.assert_nothing_was_mined().await;
    endpoint.assert_still_serving().await;
}

// ---------------------------------------------------------------------------
// Attack 3: batches.
//
// A batch is the cheapest amplification a caller has: one HTTP request, N replies.
// The endpoint must still give one reply per element, in order, carrying that
// element's own id, and must not drop, duplicate or reorder answers under load.
// ---------------------------------------------------------------------------

/// Ten thousand elements, as the brief specifies: roughly 350 KB of request, well
/// inside the body limit, so this measures the dispatcher rather than the transport.
const BATCH_LEN: usize = 10_000;

#[tokio::test]
async fn attack_3a_an_empty_batch_is_an_invalid_request() {
    let endpoint = Endpoint::new();

    let reply = endpoint.post_str("[]").await;

    // Not an empty array: a client that sent a batch expects something matchable
    // back, and the specification says an empty batch is one error object.
    assert!(reply.json().is_object(), "an empty batch must be answered with one error object: {}", reply.text());
    assert_eq!(reply.error_code(), INVALID_REQUEST, "an empty batch contains no requests: {}", reply.text());
    assert_eq!(reply.json().get("id"), Some(&Value::Null), "there is no id to echo from an empty batch");
    endpoint.assert_still_serving().await;
}

#[tokio::test]
async fn attack_3b_a_batch_of_ten_thousand_invalid_requests_is_answered_element_by_element() {
    let endpoint = Endpoint::new();

    // Three different ways to be invalid, rotated so the batch exercises the method
    // table, the parameter checks and the chain refusal path, rather than one error
    // ten thousand times.
    let expected = [METHOD_NOT_FOUND, INVALID_PARAMS, INVALID_PARAMS];
    let requests: Vec<Value> = (0..BATCH_LEN)
        .map(|index| match index % 3 {
            0 => json!({"jsonrpc": "2.0", "id": index, "method": "eth_getBlockByNumber", "params": ["latest", false]}),
            1 => json!({"jsonrpc": "2.0", "id": index, "method": "eth_getBalance", "params": [index]}),
            _ => json!({"jsonrpc": "2.0", "id": index, "method": "eth_sendRawTransaction", "params": ["0xzz"]}),
        })
        .collect();

    let payload = Value::Array(requests).to_string();
    assert!(
        payload.len() < 2 * 1024 * 1024,
        "the batch must fit through the body limit or this test measures the transport: {} bytes",
        payload.len()
    );

    let reply = endpoint.post_str(&payload).await;
    assert_eq!(reply.status, StatusCode::OK, "a huge batch is answered, not dropped: {}", reply.text());

    let json = reply.json();
    let answers = json.as_array().unwrap_or_else(|| panic!("a batch must be answered with an array: {}", reply.text()));
    assert_eq!(answers.len(), BATCH_LEN, "one answer per request, none dropped and none invented");

    let mut counts = [0usize; 3];
    for (index, answer) in answers.iter().enumerate() {
        assert_eq!(
            answer.get("id").and_then(Value::as_u64),
            Some(index as u64),
            "answer {index} must be for request {index}: order is how a client matches a batch"
        );
        assert!(answer.get("result").is_none(), "answer {index} refused its request but carried a result anyway");
        assert_eq!(error_code_of(answer), expected[index % 3], "answer {index} must carry the code for its own request");
        counts[index % 3] += 1;
    }
    assert!(counts.iter().all(|count| *count > 0), "every request shape must have been answered: {counts:?}");

    endpoint.assert_still_serving().await;
}

#[tokio::test]
async fn attack_3c_junk_inside_a_batch_does_not_poison_its_neighbours() {
    let endpoint = Endpoint::new();

    // The interesting batch: one honest request surrounded by every kind of junk.
    // Each element has to be judged on its own; a single bad element must not fail
    // the batch, and must not stop the honest request from being answered.
    let payload = json!([
        {"jsonrpc": "2.0", "id": "good", "method": "eth_chainId", "params": []},
        "not a request at all",
        {"jsonrpc": "2.0", "id": "unknown", "method": "eth_getBlockByNumber", "params": ["latest", false]},
        {"jsonrpc": "2.0", "id": "bad-params", "method": "eth_getBalance", "params": []},
        42,
        {"jsonrpc": "1.0", "id": "old", "method": "eth_chainId", "params": []},
    ])
    .to_string();

    let reply = endpoint.post_str(&payload).await;
    assert_eq!(reply.status, StatusCode::OK, "a partly junk batch is still answered: {}", reply.text());

    let json = reply.json();
    let answers = json.as_array().unwrap_or_else(|| panic!("a batch must be answered with an array: {}", reply.text()));
    assert_eq!(answers.len(), 6, "one answer per element, including the junk ones: {}", reply.text());

    // The honest request among the junk still gets its answer.
    let chain_id = format!("0x{L2_CHAIN_ID:x}");
    assert_eq!(answers[0].get("result").and_then(Value::as_str), Some(chain_id.as_str()), "a good element must be served");
    assert_eq!(answers[0].get("id").and_then(Value::as_str), Some("good"), "a good element's id must be echoed");

    // A string is JSON, but not a request: there is no id to echo.
    assert_eq!(error_code_of(&answers[1]), INVALID_REQUEST, "a bare string element must be -32600");
    assert_eq!(answers[1].get("id"), Some(&Value::Null), "an unparsable element cannot carry an id");

    assert_eq!(error_code_of(&answers[2]), METHOD_NOT_FOUND, "an unknown method must be -32601");
    assert_eq!(answers[2].get("id").and_then(Value::as_str), Some("unknown"), "the id of an unknown method is still known");

    assert_eq!(error_code_of(&answers[3]), INVALID_PARAMS, "a missing parameter must be -32602");
    assert_eq!(answers[3].get("id").and_then(Value::as_str), Some("bad-params"));

    assert_eq!(error_code_of(&answers[4]), INVALID_REQUEST, "a bare number element must be -32600");
    assert_eq!(error_code_of(&answers[5]), INVALID_REQUEST, "only jsonrpc 2.0 is served");
    assert_eq!(answers[5].get("id").and_then(Value::as_str), Some("old"), "the id of a rejected version is still known");

    endpoint.assert_still_serving().await;
}

// ---------------------------------------------------------------------------
// Attack 4: method and parameter confusion.
//
// This endpoint serves a closed set of four methods. Anything else has to be
// `-32601`, and a parameter of the wrong JSON type has to be `-32602`, because
// these are the two answers a client can act on. A 5xx, a panic on a type
// mismatch, or an accidental success are all findings.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn attack_4a_an_unimplemented_method_is_method_not_found() {
    let endpoint = Endpoint::new();

    // Everything a wallet probes with on first contact, plus the near-misses: a
    // trailing space, the wrong case, and the empty string.
    let cases: [(&str, Value); 8] = [
        ("eth_getBlockByNumber", json!(["latest", false])),
        ("eth_getTransactionReceipt", json!(["0x00"])),
        ("eth_accounts", json!([])),
        ("net_version", json!([])),
        ("web3_clientVersion", json!([])),
        ("eth_chainId ", json!([])),
        ("ETH_CHAINID", json!([])),
        ("", json!([])),
    ];

    for (index, (method, params)) in cases.iter().enumerate() {
        let reply = endpoint.post_json(&json!({"jsonrpc": "2.0", "id": index, "method": method, "params": params})).await;

        assert_eq!(
            reply.error_code(),
            METHOD_NOT_FOUND,
            "{method:?} must be -32601: this endpoint serves a fixed method table and nothing else: {}",
            reply.text()
        );
        assert_eq!(
            reply.json().get("id").and_then(Value::as_u64),
            Some(index as u64),
            "{method:?}: an unknown method must still echo the id, or the client waits forever"
        );
    }

    // Parameters are only read inside the arms that take them, so an unknown method
    // called with params that are not even an array is still -32601: complaining
    // about parameters the endpoint was never going to read would tell a prober
    // which of its guesses came closer.
    let reply = endpoint
        .post_str(r#"{"jsonrpc":"2.0","id":99,"method":"eth_getBlockByNumber","params":{"number":"0x1"}}"#)
        .await;
    assert_eq!(reply.error_code(), METHOD_NOT_FOUND, "the method lookup must happen before any parameter is read");

    endpoint.assert_still_serving().await;
}

#[tokio::test]
async fn attack_4b_a_parameter_of_the_wrong_type_is_invalid_params() {
    let endpoint = Endpoint::new();
    let address = format!("0x{}", "11".repeat(20));

    // Every one of these is a shape a JSON client can accidentally send. Each must
    // be refused with -32602 and none may be coerced: an address sent as an integer
    // must not become the account number it happens to look like, and a null must
    // not become the zero address.
    let cases: Vec<(&str, &str, Value)> = vec![
        ("an integer where an address belongs", "eth_getBalance", json!([12345])),
        ("an array where an address belongs", "eth_getBalance", json!([[&address]])),
        ("an object where an address belongs", "eth_getBalance", json!([{"address": &address}])),
        ("a boolean where an address belongs", "eth_getBalance", json!([true])),
        ("null where an address belongs", "eth_getBalance", json!([null])),
        ("named parameters instead of positional", "eth_getBalance", json!({"address": &address, "block": "latest"})),
        ("a bare string instead of a parameter array", "eth_getBalance", json!(&address)),
        ("no parameter at all", "eth_getBalance", json!([])),
        ("an address of 2 bytes", "eth_getBalance", json!(["0x1234"])),
        ("an address of 21 bytes", "eth_getBalance", json!([format!("0x{}", "11".repeat(21))])),
        ("an address that is not hex", "eth_getBalance", json!([format!("0x{}", "zz".repeat(20))])),
        ("a block tag as an integer", "eth_getBalance", json!([&address, 5])),
        ("a block tag that does not exist", "eth_getBalance", json!([&address, "yesterday"])),
        ("a block tag that is not even hex", "eth_getBalance", json!([&address, "0xzz"])),
        ("an integer where calldata belongs", "eth_sendRawTransaction", json!([0])),
        ("null where calldata belongs", "eth_sendRawTransaction", json!([null])),
        ("an object where calldata belongs", "eth_sendRawTransaction", json!([{"data": "0x00"}])),
        ("an array where calldata belongs", "eth_sendRawTransaction", json!([["0x00"]])),
        ("no calldata at all", "eth_sendRawTransaction", json!([])),
    ];

    for (index, (why, method, params)) in cases.iter().enumerate() {
        let reply = endpoint.post_json(&json!({"jsonrpc": "2.0", "id": index, "method": method, "params": params})).await;

        let code = reply.error_code();
        assert_eq!(code, INVALID_PARAMS, "{why}: {method} must answer -32602, not {code}: {}", reply.text());
        assert_eq!(
            reply.json().get("id").and_then(Value::as_u64),
            Some(index as u64),
            "{why}: the id must survive a parameter error"
        );
    }

    // The control, and the reason the nineteen refusals above mean something: the
    // same method with the same address and tag, correctly typed, must answer.
    let good = endpoint
        .post_json(&json!({"jsonrpc": "2.0", "id": "control", "method": "eth_getBalance", "params": [&address, "latest"]}))
        .await;
    assert_eq!(
        good.json().get("result").and_then(Value::as_str),
        Some("0x0"),
        "the control request must succeed, or the refusals above would pass on a node that refuses everything: {}",
        good.text()
    );

    endpoint.assert_still_serving().await;
}

#[tokio::test]
async fn attack_4c_a_request_that_is_not_a_request_is_invalid_request() {
    let endpoint = Endpoint::new();

    // Shapes of JSON that a proxy, a fuzzer or a confused client sends. Each is
    // valid JSON and none of them is a request, so none may be answered with a
    // result: the dispatcher has to fail on the shape, not on the contents.
    let cases: [(&str, &str); 8] = [
        ("a method that is a number", r#"{"jsonrpc":"2.0","id":1,"method":42,"params":[]}"#),
        ("a method that is null", r#"{"jsonrpc":"2.0","id":1,"method":null,"params":[]}"#),
        ("no method at all", r#"{"jsonrpc":"2.0","id":1,"params":[]}"#),
        ("an empty object", "{}"),
        ("a bare string", r#""eth_chainId""#),
        ("a bare number", "123"),
        ("a bare boolean", "true"),
        ("a bare null", "null"),
    ];

    for (why, payload) in cases.iter() {
        let reply = endpoint.post_str(payload).await;

        let code = reply.error_code();
        assert_eq!(code, INVALID_REQUEST, "{why} ({payload}) must be -32600, not {code}");
        // Undeserialisable means the id was never read: `null`, and never the
        // caller's own payload echoed back at it.
        assert_eq!(reply.json().get("id"), Some(&Value::Null), "{why}: an unreadable request has no id to echo");
    }

    endpoint.assert_still_serving().await;
}
