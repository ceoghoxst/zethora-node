//! Integration test for the L2 JSON-RPC endpoint.
//!
//! The requests go through [`zethora_rpc_l2::router`] — the same router
//! `zethora-rpc-l2`'s `main` serves — so routing, the CORS layer and the handler
//! are all exercised, not just the dispatcher. `oneshot` is the identical tower
//! `Service::call` that `axum::serve` performs for each request; only the socket is
//! missing, because a socket would add a port to pick, a task to abort and a race
//! to lose without testing anything the router does.
//!
//! The endpoint is spoken to the way a wallet speaks to it: a `POST /` with a JSON
//! body and an `Origin` header.

use axum::http::{HeaderMap, Request, StatusCode};
use axum::{Router, body::Body};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

use zethora_rpc_l2::{L2_CHAIN_ID, L2Rpc, router};

/// Posts `payload` to a fresh endpoint and returns the response headers and body.
async fn post(payload: &str) -> (HeaderMap, Value) {
    let app: Router = router(L2Rpc::new());
    let request = Request::builder()
        .method("POST")
        .uri("/")
        .header("content-type", "application/json")
        // A browser sets this itself; the endpoint has to answer it or MetaMask
        // never sees the response.
        .header("origin", "http://localhost:3000")
        .body(Body::from(payload.to_string()))
        .expect("a well formed HTTP request");

    let response = app.oneshot(request).await.expect("the router to answer");

    // JSON-RPC answers every request with 200, including failures: a client that
    // reads the status line first would otherwise report a transport error instead
    // of the error the node actually returned.
    assert_eq!(response.status(), StatusCode::OK, "the endpoint answers with HTTP 200");

    let headers = response.headers().clone();
    let body = response.into_body().collect().await.expect("a readable body").to_bytes();
    let value = serde_json::from_slice(&body).expect("the response body to be JSON");
    (headers, value)
}

#[tokio::test]
async fn eth_chain_id_returns_2600() {
    let (_headers, response) = post(r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}"#).await;

    // The value MetaMask stores when the user types the Zethora chain id. 2600,
    // not 777: 777 belongs to cheapETH, and two chains cannot share an id without
    // making each one's transactions replayable on the other.
    assert_eq!(L2_CHAIN_ID, 2600);

    assert_eq!(response.get("jsonrpc").and_then(Value::as_str), Some("2.0"));
    assert_eq!(response.get("id").and_then(Value::as_u64), Some(1));

    let result = response.get("result").and_then(Value::as_str);
    // A JSON-RPC quantity: `0xa28` is 2600, minimally encoded. `0x0a28` or
    // `0xa28 ` would be the same number and a different string, and MetaMask
    // compares the string.
    assert_eq!(result, Some("0xa28"));

    let expected = format!("0x{L2_CHAIN_ID:x}");
    assert_eq!(result, Some(expected.as_str()));

    // A successful call must not carry an error member at all.
    assert!(response.get("error").is_none(), "a successful eth_chainId must not report an error");
}

#[tokio::test]
async fn the_endpoint_is_cors_enabled_for_browsers() {
    let (headers, _response) = post(r#"{"jsonrpc":"2.0","id":2,"method":"eth_chainId","params":[]}"#).await;

    let allow_origin = headers.get("access-control-allow-origin").and_then(|value| value.to_str().ok());
    assert_eq!(allow_origin, Some("*"), "CorsLayer::permissive must let any browser origin read the response");
}
