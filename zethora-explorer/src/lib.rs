use axum::{extract::Query, routing::get, Json, Router};
use kaspa_grpc_client::GrpcClient;
use kaspa_hashes::Hash;
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_rpc_core::model::message::GetBlockRequest;
use kaspa_utils::hex::FromHex;
use serde::{Deserialize, Serialize};
use tower_http::services::ServeDir;

#[derive(Deserialize)]
pub struct SearchParams { pub q: String }

#[derive(Serialize)]
pub struct SearchResponse { pub r#type: String, pub data: serde_json::Value }

pub async fn search(Query(params): Query<SearchParams>) -> Json<SearchResponse> {
    let q = params.q.trim().to_string();
    let client = match GrpcClient::connect("grpc://127.0.0.1:26210".to_string()).await {
        Ok(c) => c,
        Err(e) => return Json(SearchResponse { r#type: "error".to_string(), data: serde_json::json!({ "error": format!("Failed to connect to node: {}", e) }) }),
    };

    if q.len() == 64 {
        if let Ok(hash) = Hash::from_hex(&q) {
            let req = GetBlockRequest { hash, include_transactions: true };
            if let Ok(response) = client.get_block_call(None, req).await {
                return Json(SearchResponse { r#type: "block".to_string(), data: serde_json::json!({
                    "hash": response.block.header.hash.to_string(),
                    "daaScore": response.block.header.daa_score,
                    "timestamp": response.block.header.timestamp,
                    "transactions": response.block.transactions.len()
                }) });
            }
        }
        return Json(SearchResponse { r#type: "error".to_string(), data: serde_json::json!({ "error": "Block not found" }) });
    }

    if q.starts_with("zethoratest:") {
        return Json(SearchResponse { r#type: "address".to_string(), data: serde_json::json!({ "address": q, "note": "Address lookup coming soon" }) });
    }

    // PATCH: Do not reflect user input into the error message.
    Json(SearchResponse { r#type: "error".to_string(), data: serde_json::json!({ "error": "Invalid search query" }) })
}

pub fn app() -> Router {
    Router::new().route("/api/search", get(search)).fallback_service(ServeDir::new("."))
}
