//! Gate G5: a LIVE test that the ZTH-IMPL-020 RandomZ DoS ban works over real P2P.
//!
//! What this proves (nothing about the ban logic is mocked — the node under test is a real kaspad, and
//! the evil/honest peers only put bytes on a socket):
//!
//!   * An evil peer that repeatedly sends a bogus pruning-point proof (claiming an impossible RandomZ
//!     key epoch) is NOT banned after 1 or 2 attempts — the 3-in-10-minutes threshold is not yet met
//!     (POSITIVE CONTROL): it can reconnect each time.
//!   * On the 3rd attempt within the window the node bans it: the ban is recorded in the address
//!     manager (visible via the GetPeerAddresses RPC) AND a fresh connection from that IP is refused at
//!     the handshake.
//!   * An honest peer on a DIFFERENT address keeps connecting and syncing (HONEST CONTROL): a full
//!     honest node on 127.0.0.1 connects and relays a freshly-mined block to the banned-peer's victim,
//!     and a raw handshake from 127.0.0.3 still succeeds while 127.0.0.2 is refused.
//!
//! Why distinct loopback addresses: the address manager keys bans on the connection's remote IP. Two
//! peers sharing 127.0.0.1 would be banned together (noted in CLAUDE.md as a known devnet limitation).
//! The evil peer therefore binds its socket to 127.0.0.2 and the raw honest peer to 127.0.0.3, while
//! the honest full node dials from 127.0.0.1. --connect/--addpeer peers are exempt from bans by design,
//! so the evil peer is NOT added that way; it is a plain inbound peer.
//!
//! No real 10-minute waits: three bad attempts delivered back-to-back fall inside the real 10-minute
//! window, so the real threshold logic (unchanged) fires. Time is not injected or altered.
//!
//! NEGATIVE CONTROL (test-discipline Rule 4, verified out-of-band and recorded in the G5 report):
//! commenting out the `ctx.penalize_if_misbehaving(...)` call in
//! `protocol/flows/src/ibd/flow.rs` (`IbdFlow::start`; before seam review P4-1 the call sat in
//! `sync_and_validate_pruning_proof`) makes the
//! `evil peer must be banned after the 3rd bogus proof` assertion below FAIL (the banned set stays
//! empty and the reconnect is not refused); restoring the call makes it pass.

use std::net::IpAddr;
use std::time::Duration;

use kaspa_addresses::{Address, Version};
use kaspa_alloc::init_allocator_with_default_settings;
use kaspa_consensus_core::header::Header;
use kaspa_core::info;
use kaspa_grpc_client::GrpcClient;
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspad_lib::args::Args;

use crate::common::daemon::Daemon;
use crate::common::evil_peer::{AttackOutcome, RawPeer};

const EVIL_IP: &str = "127.0.0.2";
const HONEST_RAW_IP: &str = "127.0.0.3";

fn devnet_args(utxoindex: bool) -> Args {
    Args {
        devnet: true,
        utxoindex,
        enable_unsynced_mining: true,
        unsafe_rpc: true,
        disable_upnp: true,
        disable_dns_seeding: true,
        outbound_target: 0, // keep the node from dialing anything on its own; topology is fully controlled
        ..Default::default()
    }
}

/// True iff `ip` is currently in the node's banned-address set (per the GetPeerAddresses RPC).
async fn is_banned(rpc: &GrpcClient, ip: &str) -> bool {
    let resp = rpc.get_peer_addresses().await.unwrap();
    resp.banned_addresses.iter().any(|b| b.to_string() == ip)
}

/// Runs one full bogus-proof attack cycle from `source_ip` against the node at `p2p_port`.
async fn run_attack(p2p_port: u16, source_ip: IpAddr, network_name: &str, salt: u64) -> AttackOutcome {
    let mut peer = RawPeer::connect(p2p_port, source_ip, network_name)
        .await
        .unwrap_or_else(|e| panic!("evil peer failed to connect from {source_ip}: {e}"));
    peer.handshake().await.unwrap_or_else(|e| panic!("evil peer handshake from {source_ip} failed: {e}"));
    let outcome = peer.attack_with_bogus_pruning_proof(salt).await.unwrap_or_else(|e| panic!("attack failed: {e}"));
    // Hold the connection open briefly so the node finishes validating the delivered proof (and so
    // increments its per-IP attempt counter) before we drop the socket and move on.
    tokio::time::sleep(Duration::from_secs(2)).await;
    outcome
}

/// Mines one real devnet block (solving RandomZ PoW on the submitting node) and returns its DAA score.
async fn mine_one_block(rpc: &GrpcClient, network: kaspa_consensus_core::network::NetworkId) {
    let pay_address = Address::new(network.into(), Version::PubKey, &[0u8; 32]);
    let template = rpc.get_block_template(pay_address, vec![]).await.unwrap();
    let mut block = template.block;
    let header: Header = (&block.header).try_into().unwrap();
    let state = kaspa_pow::State::new(&header);
    // Devnet starts at ~2,000 expected hashes per block; the budget is far above that but bounded so a
    // broken PoW setup fails loudly instead of hanging.
    let mut solved = None;
    for nonce in 0u64..50_000_000 {
        if state.check_pow(nonce).0 {
            solved = Some(nonce);
            break;
        }
    }
    block.header.nonce = solved.expect("failed to solve devnet PoW within the nonce budget");
    rpc.submit_block(block, false).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn zethora_g5_randomz_dos_ban_live() {
    init_allocator_with_default_settings();
    kaspa_core::log::try_init_logger("info,kaspa_p2p_flows=debug");

    let total_fd_limit = 20;
    let evil_ip: IpAddr = EVIL_IP.parse().unwrap();
    let honest_raw_ip: IpAddr = HONEST_RAW_IP.parse().unwrap();

    // ---- The node under test ----
    let mut victim = Daemon::new_random_with_args(devnet_args(true), total_fd_limit);
    let rpc = victim.start().await;
    let p2p_port = victim.p2p_port;
    let network_name = victim.network.to_prefixed();
    info!("G5: victim node up on p2p port {p2p_port}, network {network_name}");

    // Baseline: nobody is banned, and the evil IP can complete a handshake (it is not banned yet).
    assert!(!is_banned(&rpc, EVIL_IP).await, "no address should be banned at startup");
    {
        let mut probe = RawPeer::connect(p2p_port, evil_ip, &network_name).await.expect("evil IP should connect pre-ban");
        probe.handshake().await.expect("evil IP should handshake pre-ban");
    }

    // ---- POSITIVE CONTROL: attempts 1 and 2 do NOT ban (threshold is 3) ----
    for attempt in 1u64..=2 {
        let outcome = run_attack(p2p_port, evil_ip, &network_name, attempt).await;
        assert_eq!(outcome, AttackOutcome::DeliveredBogusProof, "attempt {attempt} must reach the proof-validation path");
        assert!(!is_banned(&rpc, EVIL_IP).await, "evil IP must NOT be banned after only {attempt} bad proof(s) (threshold is 3)");
        // It can still reconnect, proving it is not yet banned.
        let mut reconnect = RawPeer::connect(p2p_port, evil_ip, &network_name)
            .await
            .unwrap_or_else(|e| panic!("evil IP should still reconnect after {attempt} attempt(s): {e}"));
        reconnect.handshake().await.unwrap_or_else(|e| panic!("evil IP should still handshake after {attempt} attempt(s): {e}"));
        info!("G5: after attempt {attempt}: not banned, reconnect OK");
    }

    // ---- The 3rd bad proof within the window: the node must ban the evil IP ----
    let outcome = run_attack(p2p_port, evil_ip, &network_name, 3).await;
    assert_eq!(outcome, AttackOutcome::DeliveredBogusProof, "3rd attempt must reach the proof-validation path");

    // The ban is applied right after the node validates the 3rd proof; poll the address manager for it.
    let mut banned = false;
    for _ in 0..100 {
        if is_banned(&rpc, EVIL_IP).await {
            banned = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(banned, "evil peer must be banned after the 3rd bogus proof (ZTH-IMPL-020 threshold reached)");
    info!("G5: evil IP {EVIL_IP} is banned after 3 bogus proofs");

    // ---- The ban is enforced: a fresh connection from the banned IP is refused at the handshake ----
    // Connect may still succeed at the TCP/gRPC layer; the refusal happens during the handshake.
    let refused = match RawPeer::connect(p2p_port, evil_ip, &network_name).await {
        Ok(mut peer) => peer.handshake().await.err(),
        Err(e) => Some(e),
    };
    assert!(refused.is_some(), "a new connection from the banned IP must be refused");
    info!("G5: banned IP refused on reconnect: {}", refused.unwrap());

    // ---- HONEST CONTROL (different address still connects AND syncs) ----
    // (a) A raw handshake from a different loopback address still succeeds while the evil IP is banned.
    assert!(!is_banned(&rpc, HONEST_RAW_IP).await, "the honest raw IP must not be banned");
    {
        let mut honest_raw =
            RawPeer::connect(p2p_port, honest_raw_ip, &network_name).await.expect("honest IP should connect while evil IP is banned");
        honest_raw.handshake().await.expect("honest IP must handshake successfully while the evil IP is banned");
    }
    info!("G5: honest raw IP {HONEST_RAW_IP} handshakes fine while {EVIL_IP} is banned");

    // (b) A full honest node (dialing from 127.0.0.1) connects and SYNCS a freshly-mined block to the
    //     victim over real P2P — proving the per-IP ban did not break honest networking.
    let mut honest = Daemon::new_random_with_args(devnet_args(false), total_fd_limit);
    let rpc_honest = honest.start().await;
    rpc_honest
        .add_peer(format!("127.0.0.1:{}", victim.p2p_port).try_into().unwrap(), true)
        .await
        .expect("honest node should add the victim as a peer");

    // Wait for the connection to establish.
    let mut connected = false;
    for _ in 0..100 {
        if rpc_honest.get_connected_peer_info().await.unwrap().peer_info.len() == 1 {
            connected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(connected, "the honest node (different IP) must connect to the victim while the evil IP is banned");

    let victim_before = rpc.get_block_dag_info().await.unwrap().block_count;
    mine_one_block(&rpc_honest, honest.network).await;
    // The block must propagate to the victim over real P2P, raising its block count.
    let mut synced = false;
    for _ in 0..150 {
        if rpc.get_block_dag_info().await.unwrap().block_count > victim_before {
            synced = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(synced, "the victim must receive the honest node's mined block (honest sync works post-ban)");
    info!("G5: honest node synced a mined block to the victim; block_count {} -> {}", victim_before, victim_before + 1);

    // And the evil IP is still banned throughout the honest activity.
    assert!(is_banned(&rpc, EVIL_IP).await, "the evil IP must remain banned while honest peers operate normally");

    honest.shutdown();
    victim.shutdown();
}
