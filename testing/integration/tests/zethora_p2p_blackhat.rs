//! Regression PoCs for three Zethora P2P attack surfaces (OBS-1, OBS-3, OBS-4), now fixed.
//!
//! These are LIVE tests, not unit tests with mocks: every test starts a real devnet `kaspad`
//! (`kaspa_testing_integration::common::daemon::Daemon`) and drives it over the real gRPC P2P
//! protocol with a hand-rolled peer ([`BlackhatPeer`]). Nothing in `protocol/` or `components/` is
//! stubbed or re-implemented by the test: the peer only puts bytes on a socket and every decision
//! under test (decode, route, cap, refuse, disconnect) is made by production code.
//!
//! Each test drives the attack that used to work and asserts the node now refuses it:
//!
//! * [`obs4_relay_block_hash_cap_refuses_amplification`] -- **OBS-4, request amplification.**
//!   `HandleRelayBlockRequests` (`protocol/flows/src/v10/blockrelay/handle_requests.rs`) turns every hash
//!   of one `RequestRelayBlocks` message into a database read plus one outbound `Block`. It used to accept
//!   any number of hashes, so ONE 3.6 MB request naming the sink 100,000 times produced 100,000 responses,
//!   repeatable on the same connection. Now a message may name at most `MAX_BLOCK_HASHES_PER_REQUEST`
//!   (128) hashes: the node refuses the request before serving a single block and disconnects the peer,
//!   while a request at the cap is still served in full (the control peer).
//!
//! * [`obs3_private_state_limiter_cannot_be_reset`] -- **OBS-3, limiter bypass.**
//!   `RequestZethoraPrivateStateFlow` limits a connection to `MAX_REQUESTS_PER_PRUNING_POINT = 3`
//!   private-state downloads per pruning point, counted in `RequestLimiter`
//!   (`protocol/flows/src/flowcontext/zethora_state_cache.rs`). That limiter used to *clear itself* when
//!   asked about a 9th distinct key, so a peer could spend its quota on the pruning point it wanted and
//!   re-arm it by naming a few unrelated ones; the 4th request was then served again. Now a full limiter
//!   refuses a new key instead of forgetting the counted ones, so the bypass request itself gets the peer
//!   disconnected and the state is never served a 4th time.
//!
//! * [`obs1_oversized_frame_is_refused`] -- **OBS-1, frame buffer.**
//!   The P2P codec's bound on a single inbound message used to be `P2P_MAX_MESSAGE_SIZE = 256 MiB`
//!   (`protocol/p2p/src/core/connection_handler.rs`), buffered and decoded whole before any flow saw it, so
//!   one frame could cost a quarter of a gigabyte. It is now 10 MiB: the frame at the new limit is refused
//!   as an oversized request (and its peer dropped) before a single block is served, one hash more than the
//!   limit is refused by the decoder, and the 268 MB frame of the original PoC is an order of magnitude
//!   over what the node will even look at.
//!
//! A note on what the peers may and may not touch: the tests only use the documented P2P surface
//! (Version/Verack/Ready handshake, then the flows' own request messages). No consensus rule is involved
//! -- these are all "how cheaply can one message make the node work" attacks.
//!
//! Tests are serialized by [`SERIAL`] because each one starts a full node; they take turns so three nodes
//! never compete for the same CPU and memory on a small CI machine.

// Test code is exempt from the arithmetic-side-effects lint (same as `src/lib.rs`).
#![allow(clippy::arithmetic_side_effects)]

use std::{
    net::IpAddr,
    sync::LazyLock,
    time::{Duration, Instant},
};

use kaspa_alloc::init_allocator_with_default_settings;
use kaspa_core::info;
use kaspa_hashes::Hash;
use kaspa_p2p_lib::pb::{
    Hash as PbHash, KaspadMessage, NetAddress, PongMessage, ReadyMessage, RequestNextZethoraPrivateStateChunkMessage,
    RequestRelayBlocksMessage, RequestZethoraPrivateStateMessage, VerackMessage, VersionMessage, kaspad_message::Payload,
    p2p_client::P2pClient,
};
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_testing_integration::common::daemon::Daemon;
use kaspad_lib::args::Args;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{
    Streaming,
    transport::{Channel, Endpoint},
};

/// The protocol version the node under test advertises (`protocol/flows/src/flow_context.rs`); a peer
/// must be at least this to be served by the v11 flow set containing every flow exercised here.
const PROTOCOL_VERSION: u32 = 11;

/// Mirrors `P2P_MAX_MESSAGE_SIZE` in `protocol/p2p/src/core/connection_handler.rs`, the tonic
/// `max_decoding_message_size` applied to both the node's server and its outbound client. It is the bound
/// the P2P codec puts on a single inbound message: OBS-1 lowered it from 256 MiB to 10 MiB.
const P2P_MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// Mirrors `MAX_BLOCK_HASHES_PER_REQUEST` in `protocol/flows/src/v10/mod.rs` (OBS-4): the most block hashes
/// one `RequestRelayBlocks`/`RequestIbdBlocks`/`RequestBlockBodies` message may name.
const MAX_BLOCK_HASHES_PER_REQUEST: usize = 128;

/// The frame the original OBS-1 PoC used: 7,456,540 hashes = 268,435,445 bytes, the largest message a
/// 256 MiB decoder limit accepted.
const OLD_POC_HASHES: usize = 7_456_540;

/// Loopback source addresses, one per peer: the node's peer/ban bookkeeping keys on the remote IP, so
/// two peers that must be judged independently need distinct addresses. Addresses only have to differ
/// inside one test -- each test starts its own node.
const BYPASS_IP: &str = "127.0.0.2"; // OBS-3: the peer that tries to reset the limiter
const CONTROL_IP: &str = "127.0.0.3"; // OBS-3: the peer that asks for the state only
const AMPLIFIER_IP: &str = "127.0.0.4"; // OBS-4: the peer that sends the amplifying request
const HONEST_IP: &str = "127.0.0.5"; // OBS-4: the peer whose request sits exactly at the cap
const FRAME_IP: &str = "127.0.0.6"; // OBS-1: the frame at the new decoder limit
const OVERSIZE_IP: &str = "127.0.0.7"; // OBS-1: the frame one hash over it

/// How long to wait for a single message from the node.
const RECV_TIMEOUT: Duration = Duration::from_secs(60);

/// OBS-4: how many copies of one known block hash the single amplifying request carries. Far above the
/// `MAX_BLOCK_HASHES_PER_REQUEST` cap, yet small enough to be a legal frame under the 10 MiB decoder limit
/// (100,000 hashes = 3.6 MB), so the attack reaches the flow instead of being stopped by the codec.
const AMPLIFY_HASHES: usize = 100_000;

/// Mirrors `MAX_REQUESTS_PER_PRUNING_POINT` in `protocol/flows/src/v10/request_zethora_private_state.rs`.
const MAX_REQUESTS_PER_PRUNING_POINT: usize = 3;

/// Mirrors `KEYS_KEPT` in `protocol/flows/src/flowcontext/zethora_state_cache.rs`: how many distinct
/// pruning points one connection's `RequestLimiter` remembers before it refuses new ones (it refuses --
/// it no longer clears the counts it holds).
const KEYS_KEPT_BY_LIMITER: usize = 8;

/// Cargo runs the test functions of one binary on parallel threads, but each one starts a full node, so the
/// PoCs take turns instead of competing for the machine.
static SERIAL: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(|| tokio::sync::Mutex::new(()));

fn devnet_args() -> Args {
    Args {
        devnet: true,
        utxoindex: false,
        enable_unsynced_mining: true,
        unsafe_rpc: true,
        disable_upnp: true,
        disable_dns_seeding: true,
        outbound_target: 0, // keep the node from dialing anything on its own; topology is fully controlled
        ..Default::default()
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64
}

fn to_pb_hash(hash: Hash) -> PbHash {
    PbHash { bytes: hash.as_bytes().to_vec() }
}

/// A hash the node cannot know: `tag` spread over all 32 bytes (so no uniform pattern can collide with
/// a real block hash).
fn junk_hash(tag: u8) -> PbHash {
    PbHash { bytes: vec![tag ^ 0x5A; 32] }
}

/// Length of the varint a protobuf length prefix of `value` encodes to.
fn varint_len(value: usize) -> usize {
    let mut len = 1;
    let mut rest = value;
    while rest >= 0x80 {
        rest >>= 7;
        len += 1;
    }
    len
}

/// Encoded size of the `KaspadMessage` frame carrying a `RequestRelayBlocks` message with `hashes` hashes:
/// one tag byte for the oneof field, the varint length of the nested message, and per hash one tag byte,
/// one length byte (the nested `Hash` is always 34 bytes) and the 34 bytes of `Hash { bytes: [u8; 32] }`
/// itself -- 36 bytes per hash. `request_id`/`response_id` are proto3 scalars encoded only when non-zero
/// and the peers here leave them at zero, so they add nothing.
fn relay_request_encoded_len(hashes: usize) -> usize {
    let nested = hashes.saturating_mul(36);
    let overhead = 1 + varint_len(nested);
    overhead.saturating_add(nested)
}

/// The largest number of hashes whose `RequestRelayBlocks` message still fits the decoder limit, i.e. the
/// largest message the node's gRPC codec will buffer and decode. tonic compares the decoded length with
/// `if len > limit` (`tonic/src/codec/decode.rs`), so equality is legal.
fn max_hashes_in_one_frame() -> usize {
    let mut hashes = P2P_MAX_MESSAGE_SIZE / 36;
    while relay_frame_exceeds(hashes) {
        hashes -= 1;
    }
    while !relay_frame_exceeds(hashes + 1) {
        hashes += 1;
    }
    hashes
}

fn relay_frame_exceeds(hashes: usize) -> bool {
    relay_request_encoded_len(hashes) > P2P_MAX_MESSAGE_SIZE
}

/// Name of a payload, for test output and for `expect`-style waiting. Only the payload types these PoCs
/// meet are named; everything else is reported generically.
fn payload_name(payload: &Payload) -> &'static str {
    match payload {
        Payload::Version(_) => "Version",
        Payload::Verack(_) => "Verack",
        Payload::Ready(_) => "Ready",
        Payload::Addresses(_) => "Addresses",
        Payload::Ping(_) => "Ping",
        Payload::Pong(_) => "Pong",
        Payload::InvRelayBlock(_) => "InvRelayBlock",
        Payload::RequestRelayBlocks(_) => "RequestRelayBlocks",
        Payload::Block(_) => "Block",
        Payload::Reject(_) => "Reject",
        Payload::UnexpectedPruningPoint(_) => "UnexpectedPruningPoint",
        Payload::RequestZethoraPrivateState(_) => "RequestZethoraPrivateState",
        Payload::ZethoraPrivateStateHeader(_) => "ZethoraPrivateStateHeader",
        Payload::ZethoraPrivateStateChunk(_) => "ZethoraPrivateStateChunk",
        Payload::RequestNextZethoraPrivateStateChunk(_) => "RequestNextZethoraPrivateStateChunk",
        _ => "some other payload",
    }
}

/// Payloads the node sends on its own and that no PoC here is asserting about: the handshake echoes, the
/// sink invitation every peer gets on connect, address gossip and keepalive answers. Pings are not
/// chatter -- they must be answered, so the read helpers treat them separately.
fn is_chatter(payload: &Payload) -> bool {
    matches!(
        payload,
        Payload::Version(_)
            | Payload::Verack(_)
            | Payload::Ready(_)
            | Payload::Addresses(_)
            | Payload::RequestAddresses(_)
            | Payload::Pong(_)
            | Payload::InvRelayBlock(_)
    )
}

/// The outcome of one read from the node's stream.
// A `Received` is never stored or collected: it is matched on immediately after the read, so the largest
// variant costs nothing but the ability to keep the enum small.
#[allow(clippy::large_enum_variant, reason = "a Received exists only inside the match that read it")]
#[derive(Debug)]
enum Received {
    /// A payload that is not part of the handshake or the keepalive.
    Payload(Payload),
    /// The node sent `Reject` (its way of reporting a protocol error) and is closing the connection.
    Rejected(String),
    /// The node closed its side of the stream.
    Closed,
    /// The stream failed, e.g. because the node's decoder refused a message.
    Failed(String),
    /// Nothing arrived in the allotted time.
    Timeout,
}

/// A raw P2P peer that says exactly what a test tells it to.
///
/// It speaks the real gRPC protocol against the real node: `Version`/`Verack`/`Ready` handshake, then
/// whatever the test sends. The socket is bound to a caller-chosen loopback source address, so each
/// peer is a distinct remote IP as far as the node's per-peer state (flow instances, request limiter,
/// ban bookkeeping) is concerned -- which is what lets one PoC compare "clean connection" against
/// "abused connection" on a single host.
struct BlackhatPeer {
    tx: mpsc::Sender<KaspadMessage>,
    incoming: Streaming<KaspadMessage>,
    network_name: String,
}

impl BlackhatPeer {
    /// Opens a P2P stream to the node's P2P port from `source_ip`.
    async fn connect(node_p2p_port: u16, source_ip: IpAddr, network_name: &str) -> Self {
        let endpoint = Endpoint::from_shared(format!("http://127.0.0.1:{node_p2p_port}"))
            .expect("a loopback endpoint URI is always valid")
            .local_address(Some(source_ip))
            .connect_timeout(Duration::from_secs(30))
            // A stream may legitimately stay open for minutes (OBS-4 asks the node for 100k blocks);
            // per-message waiting is bounded by `RECV_TIMEOUT` instead.
            .timeout(Duration::from_secs(600));
        let channel: Channel = endpoint.connect().await.unwrap_or_else(|e| panic!("connect from {source_ip}: {e}"));

        // No compression: these PoCs must exercise the plain frame path, so the node's 256 MiB decoder
        // limit applies to exactly the bytes the test builds. The node's own responses are small, but
        // the limit is mirrored here so no response can be refused on this side either.
        let mut client = P2pClient::new(channel).max_decoding_message_size(P2P_MAX_MESSAGE_SIZE);

        // A small outgoing channel: the giant-frame PoC hands the encoder a message that is already
        // built, so nothing is gained by buffering messages on this side.
        let (tx, rx) = mpsc::channel::<KaspadMessage>(8);
        let response =
            client.message_stream(ReceiverStream::new(rx)).await.unwrap_or_else(|e| panic!("open stream from {source_ip}: {e}"));
        Self { tx, incoming: response.into_inner(), network_name: network_name.to_owned() }
    }

    async fn send_payload(&self, payload: Payload) -> Result<(), String> {
        let name = payload_name(&payload);
        self.tx.send(KaspadMessage { payload: Some(payload), request_id: 0, response_id: 0 }).await.map_err(|e| format!("send {name}: {e}"))
    }

    /// Reads one message, without filtering anything.
    async fn read(&mut self, timeout: Duration) -> Received {
        match tokio::time::timeout(timeout, self.incoming.message()).await {
            Err(_) => Received::Timeout,
            Ok(Err(status)) => Received::Failed(status.to_string()),
            Ok(Ok(None)) => Received::Closed,
            Ok(Ok(Some(message))) => match message.payload {
                Some(Payload::Reject(reject)) => Received::Rejected(reject.reason),
                Some(payload) => Received::Payload(payload),
                None => Received::Failed("a message with no payload".to_owned()),
            },
        }
    }

    /// Waits for the payload named `want`, quietly answering the node's pings (a peer that never answers
    /// is dropped after the 2 minute ping interval plus the pong timeout) and dropping the handshake
    /// echoes and address gossip.
    async fn expect(&mut self, want: &str) -> Result<Payload, String> {
        loop {
            match self.read(RECV_TIMEOUT).await {
                Received::Payload(Payload::Ping(ping)) => self.send_payload(Payload::Pong(PongMessage { nonce: ping.nonce })).await?,
                Received::Payload(payload) if payload_name(&payload) == want => return Ok(payload),
                Received::Payload(other) if is_chatter(&other) => {}
                Received::Payload(other) => return Err(format!("expected {want}, got {}", payload_name(&other))),
                Received::Rejected(reason) => return Err(format!("the node rejected the connection: {reason}")),
                Received::Closed => return Err(format!("the node closed the connection while {want} was expected")),
                Received::Failed(why) => return Err(format!("the stream failed while {want} was expected: {why}")),
                Received::Timeout => return Err(format!("timed out waiting for {want}")),
            }
        }
    }

    /// Completes the documented handshake. `Err` carries the node's refusal (e.g. a banned address), so a
    /// caller can treat it as "the node said no" rather than as a test failure.
    async fn handshake(&mut self) -> Result<(), String> {
        let version = VersionMessage {
            protocol_version: PROTOCOL_VERSION,
            services: 0,
            timestamp: now_ms(),
            network: self.network_name.clone(),
            user_agent: "/zethora-p2p-blackhat:0.1.0/".to_owned(),
            disable_relay_tx: true,
            subnetwork_id: None,
            id: vec![rand::random::<u8>(); 16],
            // Not used by the node for an inbound connection; a placeholder is enough.
            address: Some(NetAddress { timestamp: 0, ip: vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1], port: 0 }),
        };
        // The node reads Version, Verack and Ready from independent routes, so all three may go up front;
        // it echoes each one when its own handshake stage reaches it.
        self.send_payload(Payload::Version(version)).await?;
        self.send_payload(Payload::Verack(VerackMessage {})).await?;
        self.expect("Verack").await?;
        self.send_payload(Payload::Ready(ReadyMessage {})).await?;
        self.expect("Ready").await?;
        Ok(())
    }

    /// Closes our side of the stream, so the node stops working on our requests.
    async fn close(self) {
        let Self { tx, incoming, .. } = self;
        drop(tx);
        drop(incoming);
    }

    /// Reads until `want` blocks have arrived, answering pings, and returns the number of blocks and of
    /// transactions they carried. Anything else the node says is checked against [`is_chatter`].
    async fn await_blocks(&mut self, want: usize) -> Result<(usize, usize), String> {
        let (mut blocks, mut transactions) = (0usize, 0usize);
        while blocks < want {
            match self.read(RECV_TIMEOUT).await {
                Received::Payload(Payload::Block(block)) => {
                    blocks += 1;
                    transactions += block.transactions.len();
                }
                Received::Payload(Payload::Ping(ping)) => {
                    self.send_payload(Payload::Pong(PongMessage { nonce: ping.nonce })).await?;
                }
                Received::Payload(other) if is_chatter(&other) => {}
                Received::Payload(other) => return Err(format!("unexpected {} after {blocks} blocks", payload_name(&other))),
                Received::Rejected(reason) => return Err(format!("the node rejected the connection after {blocks} blocks: {reason}")),
                Received::Closed => return Err(format!("the node closed the connection after {blocks} blocks")),
                Received::Failed(why) => return Err(format!("the stream failed after {blocks} blocks: {why}")),
                Received::Timeout => return Err(format!("timed out after {blocks} of {want} blocks")),
            }
        }
        Ok((blocks, transactions))
    }

    /// Reads until the node says something that decides the request just sent, skipping chatter, pings
    /// (which are answered) and the chunk payloads that merely continue an answer already being read.
    async fn read_decision(&mut self) -> Received {
        loop {
            match self.read(RECV_TIMEOUT).await {
                Received::Payload(Payload::Ping(ping)) => {
                    if let Err(e) = self.send_payload(Payload::Pong(PongMessage { nonce: ping.nonce })).await {
                        return Received::Failed(e);
                    }
                }
                // The state is streamed in windows: after every `ZETHORA_PRIVATE_STATE_FLOW_CONTROL_WINDOW`
                // chunks the node waits for the joiner's go-ahead, which is this same payload sent back
                // (`ibd::streams`). Answering keeps a large state flowing; a small one never asks.
                Received::Payload(Payload::RequestNextZethoraPrivateStateChunk(_)) => {
                    let go_ahead =
                        Payload::RequestNextZethoraPrivateStateChunk(RequestNextZethoraPrivateStateChunkMessage {});
                    if let Err(e) = self.send_payload(go_ahead).await {
                        return Received::Failed(e);
                    }
                }
                Received::Payload(Payload::ZethoraPrivateStateChunk(_)) => {}
                Received::Payload(payload) if is_chatter(&payload) => {}
                decided => return decided,
            }
        }
    }

    /// Asks for the private state of `pruning_point` and returns the node's verdict. `UnexpectedPruningPoint`
    /// means the limiter let the request through and the node is simply not at that pruning point.
    async fn request_private_state(&mut self, pruning_point: &PbHash) -> Received {
        let request = Payload::RequestZethoraPrivateState(RequestZethoraPrivateStateMessage {
            pruning_point_hash: Some(pruning_point.clone()),
        });
        if let Err(e) = self.send_payload(request).await {
            return Received::Failed(e);
        }
        self.read_decision().await
    }

    /// Reads until the node says something that decides the request just sent, **counting** the blocks it served
    /// along the way, and skipping chatter and the chunk payloads that only continue an answer. Unlike
    /// [`Self::read_decision`] nothing is hidden: how many `Block` messages came back is the amplification the
    /// tests measure, so an amplifier that is only partially capped is still caught.
    async fn read_decision_counting_blocks(&mut self) -> (usize, Received) {
        let mut blocks = 0usize;
        loop {
            match self.read(RECV_TIMEOUT).await {
                Received::Payload(Payload::Block(_)) => blocks += 1,
                Received::Payload(Payload::Ping(ping)) => {
                    if let Err(e) = self.send_payload(Payload::Pong(PongMessage { nonce: ping.nonce })).await {
                        return (blocks, Received::Failed(e));
                    }
                }
                Received::Payload(Payload::RequestNextZethoraPrivateStateChunk(_)) => {
                    let go_ahead =
                        Payload::RequestNextZethoraPrivateStateChunk(RequestNextZethoraPrivateStateChunkMessage {});
                    if let Err(e) = self.send_payload(go_ahead).await {
                        return (blocks, Received::Failed(e));
                    }
                }
                Received::Payload(Payload::ZethoraPrivateStateChunk(_)) => {}
                Received::Payload(payload) if is_chatter(&payload) => {}
                decided => return (blocks, decided),
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// The three PoCs. Each one spawns its own node, drives it over the real gRPC P2P port and asserts on
// what the node actually sends back; nothing in `protocol/` or `components/` is patched or stubbed.
// ---------------------------------------------------------------------------------------------------

/// **OBS-4 (fixed) -- one request must not produce 100,000 responses: `RequestRelayBlocks` now has a hash cap.**
///
/// `HandleRelayBlockRequests` (`protocol/flows/src/v10/blockrelay/handle_requests.rs`) walks the hashes of the
/// request it was handed and, for each, enqueues one `Block` message. It used to accept any number of hashes --
/// no count check, no deduplication -- so one 3.6 MB request naming the sink 100,000 times produced 100,000
/// responses, over and over on the same connection.
///
/// Now `MAX_BLOCK_HASHES_PER_REQUEST` (128) bounds one message: a request naming more hashes than that is a
/// protocol error, which the node answers with a `Reject` and a disconnect, *before* it serves anything. The
/// test asserts all three halves of that:
/// 1. control -- a peer whose request names exactly 128 hashes is still served in full, so the cap does not
///    break honest peers (the node itself asks for relay blocks one hash at a time, so 128 is already generous);
/// 2. the amplifying request (100,000 hashes, one message) is answered with a refusal and a disconnect, and
///    not a single `Block` is served from it: the multiplier is gone;
/// 3. there is no second round -- the connection that amplified is dead, so a follow-up request at the cap
///    produces nothing, which is what separates a cap from a mere throttle.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn obs4_relay_block_hash_cap_refuses_amplification() {
    init_allocator_with_default_settings();
    kaspa_core::log::try_init_logger("info,kaspa_p2p_flows=debug");
    let _serial = SERIAL.lock().await;

    let mut node = Daemon::new_random_with_args(devnet_args(), 20);
    let rpc = node.start().await;
    let (p2p_port, network_name) = (node.p2p_port, node.network.to_prefixed());
    // The hash the node will happily serve: its own sink, which every peer learns from the InvRelayBlock
    // the node sends on connect.
    let known = to_pb_hash(rpc.get_block_dag_info().await.expect("the node must answer get_block_dag_info").sink);
    info!("OBS-4: node up on p2p port {p2p_port}, sink {known:?}");

    // ---- Control: a request naming exactly the cap is still served in full ----
    let mut honest = BlackhatPeer::connect(p2p_port, HONEST_IP.parse().expect("127.0.0.5 is a loopback address"), &network_name).await;
    honest.handshake().await.expect("the node must accept an honest handshake");
    let control_started = Instant::now();
    honest
        .send_payload(Payload::RequestRelayBlocks(RequestRelayBlocksMessage {
            hashes: vec![known.clone(); MAX_BLOCK_HASHES_PER_REQUEST],
        }))
        .await
        .expect("a request at the cap must be accepted by the transport");
    let (control_blocks, _) = honest
        .await_blocks(MAX_BLOCK_HASHES_PER_REQUEST)
        .await
        .unwrap_or_else(|e| panic!("a request naming exactly {MAX_BLOCK_HASHES_PER_REQUEST} hashes must still be served: {e}"));
    info!(
        "OBS-4: control -- a request naming {MAX_BLOCK_HASHES_PER_REQUEST} hashes was served with {control_blocks} \
         Block messages in {:?}",
        control_started.elapsed()
    );
    assert_eq!(control_blocks, MAX_BLOCK_HASHES_PER_REQUEST, "every hash of a request at the cap must be answered");
    honest.close().await;

    // ---- The amplifying request: ONE message naming AMPLIFY_HASHES copies of the sink ----
    let mut peer = BlackhatPeer::connect(p2p_port, AMPLIFIER_IP.parse().expect("127.0.0.4 is a loopback address"), &network_name).await;
    peer.handshake().await.expect("the node must accept an honest handshake");
    let request_bytes = relay_request_encoded_len(AMPLIFY_HASHES);
    info!(
        "OBS-4: sending ONE RequestRelayBlocks of {request_bytes} bytes naming the same block {} times",
        AMPLIFY_HASHES
    );
    let started = Instant::now();
    peer.send_payload(Payload::RequestRelayBlocks(RequestRelayBlocksMessage { hashes: vec![known.clone(); AMPLIFY_HASHES] }))
        .await
        .expect("the frame is legal under the decoder limit, so the transport must take it");
    let (blocks, decision) = peer.read_decision_counting_blocks().await;
    info!("OBS-4: the amplifying request was decided after {:?} with {blocks} Block message(s)", started.elapsed());
    assert_eq!(
        blocks, 0,
        "not one block may be served from a request naming {AMPLIFY_HASHES} hashes: that is exactly the amplification the cap removes"
    );
    match decision {
        Received::Rejected(reason) => {
            assert!(
                reason.contains(&MAX_BLOCK_HASHES_PER_REQUEST.to_string()),
                "the refusal must be the hash cap's ({MAX_BLOCK_HASHES_PER_REQUEST} hashes), got: {reason}"
            );
            info!("OBS-4: the node refused the amplifying request: {reason}");
        }
        Received::Closed => {
            info!("OBS-4: the node dropped the connection on the amplifying request");
        }
        Received::Failed(why) => {
            info!("OBS-4: the stream failed on the amplifying request: {why}");
        }
        Received::Timeout => panic!("the node neither refused the amplifying request nor dropped the peer"),
        Received::Payload(other) => {
            panic!("the node answered the amplifying request with {} instead of refusing it", payload_name(&other))
        }
    }

    // ---- No second round: the connection that amplified is gone ----
    // A request at the cap *is* served on a live connection (see the control above), so if this one still
    // produces blocks the cap merely throttled the attacker instead of stopping it.
    let follow_up = peer
        .send_payload(Payload::RequestRelayBlocks(RequestRelayBlocksMessage {
            hashes: vec![known; MAX_BLOCK_HASHES_PER_REQUEST],
        }))
        .await;
    info!("OBS-4: the follow-up request at the cap was handed to the transport: {follow_up:?}");
    let (served_again, after) = peer.read_decision_counting_blocks().await;
    assert_eq!(served_again, 0, "a connection that sent an amplifying request must not be served again");
    assert!(
        matches!(after, Received::Rejected(_) | Received::Closed | Received::Failed(_)),
        "the follow-up must find the connection closed, got {after:?}"
    );
    info!("OBS-4: the follow-up found no usable connection: {after:?}");

    peer.close().await;
    node.shutdown();
}

/// **OBS-3 (fixed) -- the per-connection private-state cap can no longer be undone by naming other hashes.**
///
/// `RequestZethoraPrivateStateFlow` (`protocol/flows/src/v10/request_zethora_private_state.rs`) refuses a peer
/// that asks for the same pruning point's private state more than `MAX_REQUESTS_PER_PRUNING_POINT` (3) times,
/// using `RequestLimiter` (`protocol/flows/src/flowcontext/zethora_state_cache.rs`). That limiter remembers a
/// bounded number of keys; it used to *wipe itself* when a new key arrived while full, so the bypass was: ask
/// for the real pruning point three times, ask for `KEYS_KEPT_BY_LIMITER` hashes the node is not at (each
/// answered with the cheap `UnexpectedPruningPoint`, which does not close the connection) -- and the counter for
/// the real pruning point was gone, so the fourth request was served again, indefinitely.
///
/// Now a full limiter refuses the new key instead of forgetting the counted ones, so the filler that used to
/// flush it is itself the protocol error that disconnects the peer, and the state is never served a fourth time.
///
/// Two peers on distinct loopback source IPs (hence their own flow instance and their own limiter) show both
/// sides on one node: the control peer is refused -- and disconnected -- on request four, as before, and the peer
/// that tries the bypass cannot get a fourth answer either.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn obs3_private_state_limiter_cannot_be_reset() {
    init_allocator_with_default_settings();
    kaspa_core::log::try_init_logger("info,kaspa_p2p_flows=debug");
    let _serial = SERIAL.lock().await;

    // ---- The node under test ----
    let mut node = Daemon::new_random_with_args(devnet_args(), 20);
    let rpc = node.start().await;
    let (p2p_port, network_name) = (node.p2p_port, node.network.to_prefixed());
    // The pruning point is public: a syncing peer is told it, and the RPC reports it here.
    let pruning_point = rpc.get_block_dag_info().await.expect("the node must answer get_block_dag_info").pruning_point_hash;
    let pp = to_pb_hash(pruning_point);
    info!("OBS-3: node up on p2p port {p2p_port}, pruning point {pruning_point}");

    // ---- Control: a peer that asks for the real pruning point and nothing else ----
    let mut control = BlackhatPeer::connect(p2p_port, CONTROL_IP.parse().expect("127.0.0.3 is a loopback address"), &network_name).await;
    control.handshake().await.expect("the node must accept an honest handshake");
    for attempt in 1..=MAX_REQUESTS_PER_PRUNING_POINT {
        match control.request_private_state(&pp).await {
            Received::Payload(Payload::ZethoraPrivateStateHeader(header)) => {
                info!(
                    "OBS-3: control request #{attempt} answered: {} spent tags, {} snapshots, {} byte note tree",
                    header.spent_count,
                    header.anchor_count,
                    header.note_tree.len()
                );
            }
            other => panic!("the control peer's request #{attempt} must be answered, got {other:?}"),
        }
    }
    // The control's 4th request must be refused. The node reports a protocol error with a `Reject`, but it is
    // already tearing the connection down, so the refusal may also show up as a plain close.
    match control.request_private_state(&pp).await {
        Received::Rejected(reason) => {
            assert!(
                reason.contains("more than") && reason.contains(&MAX_REQUESTS_PER_PRUNING_POINT.to_string()),
                "the refusal must be the request limiter's, got: {reason}"
            );
            info!("OBS-3: control peer refused on request #4: {reason}");
        }
        other => {
            info!("OBS-3: control peer dropped on request #4: {other:?}");
            assert!(
                matches!(other, Received::Closed),
                "the control peer's 4th request must be refused or dropped, got {other:?}"
            );
        }
    }
    control.close().await;

    // ---- The attacker: the same three requests, then hashes the node is not at ----
    let mut attacker = BlackhatPeer::connect(p2p_port, BYPASS_IP.parse().expect("127.0.0.2 is a loopback address"), &network_name).await;
    attacker.handshake().await.expect("the node must accept an honest handshake");
    for attempt in 1..=MAX_REQUESTS_PER_PRUNING_POINT {
        match attacker.request_private_state(&pp).await {
            Received::Payload(Payload::ZethoraPrivateStateHeader(_)) => {
                info!("OBS-3: attacker request #{attempt} for the real pruning point answered");
            }
            other => panic!("the attacker's request #{attempt} must be answered, got {other:?}"),
        }
    }

    // Filler: each request names a pruning point the node is not at, which it answers with the cheap
    // `UnexpectedPruningPoint` and no disconnect. The limiter may remember only a handful of keys; the question
    // is what it does when it is full. It must refuse the new key -- refusing is what keeps the counts it already
    // holds, and one of those is the spent quota of the real pruning point.
    let filler_started = Instant::now();
    let mut refusal = None;
    for i in 0..KEYS_KEPT_BY_LIMITER {
        let filler = junk_hash(0x10_u8.wrapping_add(i as u8));
        match attacker.request_private_state(&filler).await {
            Received::Payload(Payload::UnexpectedPruningPoint(_)) => {}
            other => {
                refusal = Some((i + 1, other));
                break;
            }
        }
    }
    let Some((refused_at, refusal)) = refusal else {
        panic!(
            "the limiter must refuse a new pruning point once its {KEYS_KEPT_BY_LIMITER}-key map is full, but it \
             answered all {KEYS_KEPT_BY_LIMITER} fillers: a peer can still flush the counts it holds"
        );
    };
    info!(
        "OBS-3: after {:?} the limiter refused filler request #{refused_at} instead of forgetting the counts it held: {refusal:?}",
        filler_started.elapsed()
    );
    assert!(
        matches!(refusal, Received::Rejected(_) | Received::Closed | Received::Failed(_)),
        "a full limiter must refuse the request and get the peer disconnected, got {refusal:?}"
    );

    // ---- The request the limiter was built to refuse on this very connection ----
    match attacker.request_private_state(&pp).await {
        Received::Payload(Payload::ZethoraPrivateStateHeader(header)) => panic!(
            "request #{} for the same pruning point was served again ({} spent tags, {} snapshots): the limiter was reset",
            MAX_REQUESTS_PER_PRUNING_POINT + 1,
            header.spent_count,
            header.anchor_count
        ),
        other => {
            info!(
                "OBS-3: request #{} for the same pruning point was not served: {other:?}",
                MAX_REQUESTS_PER_PRUNING_POINT + 1
            );
        }
    }

    attacker.close().await;
    node.shutdown();
}

/// **OBS-1 (fixed) -- a 268 MB frame is no longer deliverable; the codec refuses it on the length prefix.**
///
/// The P2P codec's bound on a single inbound message is `P2P_MAX_MESSAGE_SIZE`, set as tonic's
/// `max_decoding_message_size` in `protocol/p2p/src/core/connection_handler.rs`. It used to be 256 MiB, applied
/// after the transport had taken delivery of the frame, so one `RequestRelayBlocks` message could make the node
/// buffer and decode 268,435,445 bytes (7,456,540 hashes at 36 bytes each) before any flow code saw it -- and
/// OBS-4 then meant the flow answered all of it.
///
/// It is now 10 MiB, and the flows refuse what little a frame that size can still carry:
/// 1. the frame at the new limit (10 MiB of hashes) is decoded, but its request is refused as an oversized request
///    and the peer is disconnected -- before a single block is served, even though its first hash names a block
///    the node has;
/// 2. one hash more than the limit (36 bytes of wire format) is refused by the decoder, so the bound really is the
///    constant the test computes with: nothing larger than 10 MiB can be delivered to a flow at all;
/// 3. the frame of the original PoC (268 MB) is more than an order of magnitude past that bound, i.e. it is refused
///    on the length prefix before a byte of its body is buffered.
///
/// No resident-set measurement is needed any more: the frame whose in-flight cost used to be measured cannot be
/// delivered, and the 10 MiB that can be delivered is bounded by the constant above.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn obs1_oversized_frame_is_refused() {
    init_allocator_with_default_settings();
    kaspa_core::log::try_init_logger("info,kaspa_p2p=debug,kaspa_p2p_flows=debug");
    let _serial = SERIAL.lock().await;

    let mut node = Daemon::new_random_with_args(devnet_args(), 20);
    let rpc = node.start().await;
    let (p2p_port, network_name) = (node.p2p_port, node.network.to_prefixed());
    let known = to_pb_hash(rpc.get_block_dag_info().await.expect("the node must answer get_block_dag_info").sink);

    let max_hashes = max_hashes_in_one_frame();
    let frame_bytes = relay_request_encoded_len(max_hashes);
    assert!(!relay_frame_exceeds(max_hashes), "the frame at the computed maximum must fit in the decoder limit");
    assert!(relay_frame_exceeds(max_hashes + 1), "one more hash must be over the decoder limit");
    // The frame of the original PoC is not merely over the limit, it is an order of magnitude over it.
    assert!(relay_frame_exceeds(OLD_POC_HASHES), "the 268 MB frame of the original PoC must be over the decoder limit");
    info!(
        "OBS-1: the largest frame the codec will now decode is {max_hashes} hashes = {frame_bytes} bytes ({:.1} MiB); \
         the limit is {P2P_MAX_MESSAGE_SIZE} bytes ({:.1} MiB), and the original PoC's {OLD_POC_HASHES}-hash frame is \
         {:.1}x that",
        frame_bytes as f64 / (1024.0 * 1024.0),
        P2P_MAX_MESSAGE_SIZE as f64 / (1024.0 * 1024.0),
        OLD_POC_HASHES as f64 / max_hashes as f64,
    );

    // ---- A frame at the new limit, on a connection of its own ----
    let mut peer = BlackhatPeer::connect(p2p_port, FRAME_IP.parse().expect("127.0.0.6 is a loopback address"), &network_name).await;
    peer.handshake().await.expect("the node must accept an honest handshake");

    let build_started = Instant::now();
    // The first hash names a block the node has. With the old code that made the node answer, which proved the whole
    // message had been decoded and walked; now nothing may be served from it -- the hash cap is applied before the
    // first lookup, so a frame that hides one valid request among millions of junk hashes buys the attacker nothing.
    let mut hashes = vec![junk_hash(0xEE); max_hashes];
    hashes[0] = known;
    let request = RequestRelayBlocksMessage { hashes };
    info!("OBS-1: built the {frame_bytes} byte message in {:?}", build_started.elapsed());

    let send_started = Instant::now();
    peer.send_payload(Payload::RequestRelayBlocks(request)).await.expect("a frame at the limit still fits the transport");
    let (served, decision) = peer.read_decision_counting_blocks().await;
    info!("OBS-1: the frame at the limit was decided after {:?} with {served} Block message(s)", send_started.elapsed());
    assert_eq!(served, 0, "no block may be served from a frame naming {max_hashes} hashes, not even the real one it starts with");
    match decision {
        Received::Rejected(reason) => {
            assert!(
                reason.contains(&MAX_BLOCK_HASHES_PER_REQUEST.to_string()),
                "the frame at the limit must be refused by the hash cap ({MAX_BLOCK_HASHES_PER_REQUEST} hashes), got: {reason}"
            );
            info!("OBS-1: the decoded frame at the limit was refused as an oversized request: {reason}");
        }
        Received::Closed => {
            info!("OBS-1: the node dropped the peer that sent the frame at the limit");
        }
        Received::Failed(why) => {
            info!("OBS-1: the decoder refused the frame at the limit: {why}");
        }
        Received::Timeout => panic!("the node neither served nor refused the frame at the limit"),
        Received::Payload(other) => {
            panic!("the node answered the frame at the limit with {} instead of refusing it", payload_name(&other))
        }
    }
    peer.close().await;

    // ---- The boundary: one more hash (36 bytes of wire format) is over the limit ----
    let over_hashes = max_hashes + 1;
    let over_bytes = relay_request_encoded_len(over_hashes);
    info!(
        "OBS-1: the boundary frame carries {over_hashes} hashes = {over_bytes} bytes, which is {} bytes over the limit",
        over_bytes.saturating_sub(P2P_MAX_MESSAGE_SIZE)
    );
    let mut oversize = BlackhatPeer::connect(p2p_port, OVERSIZE_IP.parse().expect("127.0.0.7 is a loopback address"), &network_name).await;
    oversize.handshake().await.expect("the node must accept an honest handshake");
    oversize
        .send_payload(Payload::RequestRelayBlocks(RequestRelayBlocksMessage { hashes: vec![junk_hash(0xF0); over_hashes] }))
        .await
        .expect("the frame must reach the transport");
    // The codec aborts as soon as it has read the length prefix, so this comes back well before the whole
    // frame would have been transferred. `read_decision` skips the chatter the node emits on its own (the
    // sink's `InvRelayBlock`, address gossip, pings), which would otherwise be mistaken for the verdict.
    match oversize.read_decision().await {
        Received::Payload(Payload::Block(block)) => {
            panic!("the node served a block from a frame over P2P_MAX_MESSAGE_SIZE ({} transactions)", block.transactions.len())
        }
        Received::Rejected(reason) => {
            info!("OBS-1: the frame one hash over the limit was refused: {reason}");
        }
        Received::Closed => {
            info!("OBS-1: the frame one hash over the limit was refused by closing the stream");
        }
        Received::Failed(why) => {
            info!("OBS-1: the frame one hash over the limit was refused by the decoder: {why}");
        }
        Received::Timeout => panic!("the node neither served nor refused a frame over P2P_MAX_MESSAGE_SIZE"),
        Received::Payload(other) => {
            info!("OBS-1: the frame one hash over the limit was not served: {} arrived instead", payload_name(&other));
        }
    }
    oversize.close().await;

    node.shutdown();
}
