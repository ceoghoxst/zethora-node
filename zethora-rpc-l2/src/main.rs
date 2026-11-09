//! The `zethora-rpc-l2` binary: the L2 JSON-RPC endpoint on port 8545.
//!
//! Nothing here but the socket. The router, the methods and the chain all live in
//! the library, so the integration test drives exactly the code this binary
//! serves instead of a test-only copy of it.

use std::{net::SocketAddr, process::ExitCode};

use zethora_rpc_l2::{DEFAULT_RPC_PORT, L2Rpc, router};

#[tokio::main]
async fn main() -> ExitCode {
    let app = router(L2Rpc::new());

    // `0.0.0.0` rather than loopback: MetaMask in a browser on another machine, a
    // page served from another origin, and a container on the same docker network
    // all have to reach this port, and to each of them the server is not
    // `127.0.0.1`.
    let address = SocketAddr::from(([0, 0, 0, 0], DEFAULT_RPC_PORT));

    let listener = match tokio::net::TcpListener::bind(address).await {
        Ok(listener) => listener,
        Err(err) => {
            // Most likely the port is taken by another node. Saying so and exiting
            // is better than retrying in a loop while a wallet waits.
            eprintln!("zethora-rpc-l2: cannot bind {address}: {err}");
            return ExitCode::FAILURE;
        }
    };

    println!("zethora-rpc-l2: JSON-RPC listening on http://{address}");
    println!("  chain id : {}", zethora_rpc_l2::L2_CHAIN_ID);
    println!("  methods  : eth_chainId, eth_blockNumber, eth_getBalance, eth_sendRawTransaction");

    match axum::serve(listener, app).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("zethora-rpc-l2: the server stopped: {err}");
            ExitCode::FAILURE
        }
    }
}
