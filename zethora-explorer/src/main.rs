use std::net::SocketAddr;
use zethora_explorer::app;

#[tokio::main]
async fn main() {
    let app = app();
    let addr = SocketAddr::from(([0, 0, 0, 0], 8081));
    println!("Explorer listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
