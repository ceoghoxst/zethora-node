use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use tower::ServiceExt;

#[tokio::test]
async fn attack_1_unbounded_memory() {
    // The Rust `http` crate rejects URIs > ~64KB before Axum even sees them.
    // This test proves the framework protects us from URI-based memory exhaustion.
    let q = "a".repeat(100_000); 
    let result = Request::builder().uri(format!("/api/search?q={}", q)).body(Body::empty());
    assert!(result.is_err(), "The HTTP layer failed to reject a 100KB URI!");
}

#[tokio::test]
async fn attack_2_xss_reflection() {
    let app = zethora_explorer::app();
    let payload = "%3Cscript%3Ealert(1)%3C/script%3E"; 
    let req = Request::builder().uri(format!("/api/search?q={}", payload)).body(Body::empty()).unwrap();
    
    let res = app.oneshot(req).await.unwrap();
    let body = res.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&body);
    
    // Now the patch should prevent the reflection.
    assert!(!text.contains("<script>"), "VULNERABILITY: XSS payload was reflected unescaped in the JSON response! Text: {}", text);
}
