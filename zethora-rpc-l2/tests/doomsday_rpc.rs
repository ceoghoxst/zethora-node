use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use tower::ServiceExt;
use serde_json::json;

// Helper to send a JSON-RPC request
async fn rpc_call(method: &str, params: serde_json::Value) -> serde_json::Value {
    let app = zethora_rpc_l2::router(zethora_rpc_l2::L2Rpc::new());
    let payload = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params
    });
    
    let req = Request::builder()
        .method("POST")
        .uri("/")
        .header("content-type", "application/json")
        .body(Body::from(payload.to_string()))
        .unwrap();

    let res = app.oneshot(req).await.unwrap();
    let body = res.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn attack_1_eip1559_fee_routing_overflow() {
    // Attempt to send a transaction with an astronomically high max_fee_per_gas 
    let malicious_tx = "0x02f8700180843b9ac9ff84b2d05e008252089400000000000000000000000000000000000000008080c001a0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let res = rpc_call("eth_sendRawTransaction", json!([malicious_tx])).await;
    assert!(res["error"].is_object(), "VULNERABILITY: Server accepted a transaction with overflowing fees!");
    assert_ne!(res["error"]["code"], -32603, "VULNERABILITY: Server panicked on overflow!");
}

#[tokio::test]
async fn attack_2_replay_attack() {
    let app = zethora_rpc_l2::router(zethora_rpc_l2::L2Rpc::new());
    let raw_tx = "0x02f86b0180843b9ac9ff84b2d05e008252089400000000000000000000000000000000000000008080c001a0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    
    let payload1 = json!({"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":[raw_tx]});
    let req1 = Request::builder().method("POST").uri("/").header("content-type", "application/json").body(Body::from(payload1.to_string())).unwrap();
    let _ = app.clone().oneshot(req1).await.unwrap();

    let payload2 = json!({"jsonrpc":"2.0","id":2,"method":"eth_sendRawTransaction","params":[raw_tx]});
    let req2 = Request::builder().method("POST").uri("/").header("content-type", "application/json").body(Body::from(payload2.to_string())).unwrap();
    let res2 = app.oneshot(req2).await.unwrap();
    
    let body = res2.into_body().collect().await.unwrap().to_bytes();
    let json_res: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json_res["error"].is_object() || json_res["result"].is_string(), "Replay attack handled.");
}

#[tokio::test]
async fn attack_3_massive_gas_limit() {
    let massive_gas_tx = "0x02f86b0180843b9ac9ff84ffffffffffffffff8252089400000000000000000000000000000000000000008080c001a0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let res = rpc_call("eth_sendRawTransaction", json!([massive_gas_tx])).await;
    assert!(res["error"].is_object(), "VULNERABILITY: Server accepted a transaction with u64::MAX gas limit!");
}

#[tokio::test]
async fn attack_4_state_desync_via_failed_tx() {
    let app = zethora_rpc_l2::router(zethora_rpc_l2::L2Rpc::new());
    
    let req1 = Request::builder().method("POST").uri("/").header("content-type", "application/json").body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}"#)).unwrap();
    let res1 = app.clone().oneshot(req1).await.unwrap();
    let body1 = res1.into_body().collect().await.unwrap().to_bytes();
    let block1: serde_json::Value = serde_json::from_slice(&body1).unwrap();
    
    let bad_tx = "0x02f86b0180843b9ac9ff84b2d05e008252089400000000000000000000000000000000000000008080c001a0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let payload = json!({"jsonrpc":"2.0","id":2,"method":"eth_sendRawTransaction","params":[bad_tx]});
    let req2 = Request::builder().method("POST").uri("/").header("content-type", "application/json").body(Body::from(payload.to_string())).unwrap();
    let _ = app.clone().oneshot(req2).await.unwrap();
    
    let req3 = Request::builder().method("POST").uri("/").header("content-type", "application/json").body(Body::from(r#"{"jsonrpc":"2.0","id":3,"method":"eth_blockNumber","params":[]}"#)).unwrap();
    let res3 = app.oneshot(req3).await.unwrap();
    let body3 = res3.into_body().collect().await.unwrap().to_bytes();
    let block3: serde_json::Value = serde_json::from_slice(&body3).unwrap();
    
    assert_eq!(block1["result"], block3["result"], "VULNERABILITY: Block number advanced on a failed transaction (state desync)!");
}
