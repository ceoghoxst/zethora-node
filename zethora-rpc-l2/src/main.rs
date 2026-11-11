//! The `zethora-rpc-l2` binary: the L2 JSON-RPC endpoint on port 8545.
//!
//! Nothing here but the socket and the state file. The router, the methods and the
//! chain all live in the library, so the integration test drives exactly the code
//! this binary serves instead of a test-only copy of it. The binary adds the one
//! thing a library cannot own — a process lifetime — and the state dump that spans
//! it: loaded once at boot, written once at shutdown.

use std::{net::SocketAddr, path::PathBuf, process::ExitCode};

use zethora_rpc_l2::{DEFAULT_RPC_PORT, L2Rpc, router};

/// The file the account state is dumped to and restored from.
///
/// A plain filename in the working directory is the simplest thing that works for
/// a local devnet: run the node from a directory it may write, and the next start
/// in the same directory sees the same balances.
const STATE_FILE: &str = "zethora-l2-state.json";

#[tokio::main]
async fn main() -> ExitCode {
    let state_path = PathBuf::from(STATE_FILE);

    // Restore the balances and nonces a previous run left behind, so a wallet that
    // funded itself yesterday still holds its balance today. A missing file is the
    // ordinary first start and restores nothing.
    let rpc = L2Rpc::new();
    match rpc.restore_from(&state_path) {
        Ok(restored) => {
            if restored != 0 {
                println!("zethora-rpc-l2: restored {restored} accounts from {}", state_path.display());
            }
        }
        Err(err) => {
            eprintln!("zethora-rpc-l2: cannot restore state: {err}");
            return ExitCode::FAILURE;
        }
    }

    let app = router(rpc.clone());

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
    println!("  state    : {}", state_path.display());

    // Serve until the process is told to stop, then fall through to the shutdown
    // dump. `with_graceful_shutdown` is what guarantees the dump below runs: the
    // next start can only see this run's balances if this run writes them.
    let served = axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()).await;

    if let Err(err) = rpc.save_to(&state_path) {
        eprintln!("zethora-rpc-l2: cannot save state: {err}");
        return ExitCode::FAILURE;
    }

    match served {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("zethora-rpc-l2: the server stopped: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Resolves when the process is asked to stop, so `main` can dump the state.
///
/// Ctrl+C is what a foreground dev node receives. SIGTERM is added behind
/// `cfg(unix)` so a container manager can stop the node cleanly too; on Windows
/// there is no SIGTERM, so that branch never resolves.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.expect("failed to install the Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install the SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
