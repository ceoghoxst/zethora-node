//! A raw P2P client used to live-test the ZTH-IMPL-020 RandomZ DoS ban (gate G5).
//!
//! Unlike the integration `Daemon` (a full honest node), this is a hand-rolled peer that speaks the
//! real gRPC P2P protocol directly, so the test can make it misbehave: it drives a real node through
//! a genuine IBD until the node requests a pruning-point proof, then answers with a bogus proof whose
//! RandomZ key epoch is impossible. That is the exact `PruningImportError::ZethoraPowEpochImplausible`
//! path classified as a hard error by `ProtocolError::is_implausible_pow_epoch` and banned (after the
//! 3-in-10-minutes threshold) by `FlowContext::penalize_ip_if_misbehaving`.
//!
//! Nothing here mocks the ban logic: the peer only sends bytes over a socket. The node is the real
//! kaspad under test, and every decision (classify, count, ban, refuse) is made by production code.
//!
//! The peer binds its outgoing socket to a caller-chosen loopback source address (e.g. 127.0.0.2) so
//! that the node's address manager — which keys bans on the connection's remote IP — bans only that
//! address, leaving an honest peer on a different loopback address (e.g. 127.0.0.1 / 127.0.0.3)
//! unaffected. See the test module for why this is necessary on a single host.

use std::net::IpAddr;
use std::time::Duration;

use kaspa_consensus_core::constants::BLOCK_VERSION;
use kaspa_consensus_core::header::Header;
use kaspa_consensus_core::{BlueWorkType, Hash};
use kaspa_p2p_lib::pb::{
    BlockLocatorMessage, BlockMessage, IbdChainBlockLocatorMessage, InvRelayBlockMessage, KaspadMessage, NetAddress,
    PruningPointProofChunkMessage, PruningPointProofChunksEndMessage, ReadyMessage, SubnetworkId, TransactionMessage, VerackMessage,
    VersionMessage, kaspad_message::Payload, p2p_client::P2pClient,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::codec::CompressionEncoding;
use tonic::transport::{Channel, Endpoint};

/// The P2P protocol version this peer advertises; must be the node's `PROTOCOL_VERSION` so a hard ban
/// is not suppressed by the version-aware classification (ZTH-IMPL-020 Protection 1).
const PROTOCOL_VERSION: u32 = 11;

/// A DAA score so far in the future that `kaspa_pow::randomz::epoch_of(daa_score)` is astronomically
/// higher than any epoch the time since the devnet genesis could justify. This is what makes the
/// pruning proof's claimed RandomZ epoch "implausible".
const IMPLAUSIBLE_DAA_SCORE: u64 = 1_000_000_000_000;

/// How long to wait for any single message the node sends us.
const RECV_TIMEOUT: Duration = Duration::from_secs(30);

/// Result of attempting one bogus-proof attack cycle.
#[derive(Debug, PartialEq, Eq)]
pub enum AttackOutcome {
    /// The node requested the pruning-point proof and we sent the bogus one. This is the attempt that
    /// reaches `validate_pruning_proof` and so the ban classifier/threshold.
    DeliveredBogusProof,
    /// The connection was refused or closed before we could deliver the proof. Used to detect that a
    /// reconnection from a banned address is rejected.
    Refused(String),
}

pub struct RawPeer {
    tx: mpsc::Sender<KaspadMessage>,
    incoming: tonic::Streaming<KaspadMessage>,
    network_name: String,
}

impl RawPeer {
    /// Opens a real gRPC P2P stream to `node_p2p_port` on 127.0.0.1, with the outgoing socket bound to
    /// `source_ip` (any 127.0.0.0/8 address). The node will therefore see `source_ip` as the peer's IP.
    pub async fn connect(node_p2p_port: u16, source_ip: IpAddr, network_name: &str) -> Result<Self, String> {
        let endpoint = Endpoint::from_shared(format!("http://127.0.0.1:{node_p2p_port}"))
            .map_err(|e| format!("endpoint: {e}"))?
            .local_address(Some(source_ip))
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60));
        let channel: Channel = endpoint.connect().await.map_err(|e| format!("connect from {source_ip}: {e}"))?;

        let mut client = P2pClient::new(channel)
            .send_compressed(CompressionEncoding::Gzip)
            .accept_compressed(CompressionEncoding::Gzip)
            .max_decoding_message_size(1024 * 1024 * 1024);

        let (tx, rx) = mpsc::channel::<KaspadMessage>(256);
        let outgoing = ReceiverStream::new(rx);
        let response = client.message_stream(outgoing).await.map_err(|e| format!("open stream from {source_ip}: {e}"))?;
        let incoming = response.into_inner();
        Ok(Self { tx, incoming, network_name: network_name.to_owned() })
    }

    /// Sends a message. Some node requests are matched on the response side by the request's id rather
    /// than by payload type (the node registers those routes by id); such responses must echo the
    /// request's `request_id` as their `response_id`. Pass `response_id = 0` for type-routed messages.
    async fn send(&self, payload: Payload, response_id: u32) -> Result<(), String> {
        self.tx.send(KaspadMessage { payload: Some(payload), request_id: 0, response_id }).await.map_err(|e| format!("send: {e}"))
    }

    /// Receives the next message (payload + the node's request id), or an error on timeout/close/reject.
    async fn recv(&mut self) -> Result<(Payload, u32), String> {
        match tokio::time::timeout(RECV_TIMEOUT, self.incoming.message()).await {
            Err(_) => Err("timeout waiting for node message".to_owned()),
            Ok(Err(status)) => Err(format!("stream error: {status}")),
            Ok(Ok(None)) => Err("connection closed by node".to_owned()),
            Ok(Ok(Some(msg))) => {
                let request_id = msg.request_id;
                match msg.payload {
                    // A Reject payload is how the node reports a refused handshake (e.g. "peer is banned").
                    Some(Payload::Reject(r)) => Err(format!("reject: {}", r.reason)),
                    Some(p) => Ok((p, request_id)),
                    None => Err("empty payload".to_owned()),
                }
            }
        }
    }

    /// Receives messages until one of `want` payload types arrives, ignoring the node's handshake and
    /// keepalive traffic along the way. Returns the matched payload and the node's request id for it.
    async fn recv_until(&mut self, want: &[&str]) -> Result<(Payload, u32), String> {
        loop {
            let (payload, request_id) = self.recv().await?;
            if want.contains(&payload_name(&payload)) {
                return Ok((payload, request_id));
            }
            // Ignore anything else the node volunteers (Version/Verack/Ready echoes, pings, addresses...).
        }
    }

    /// Completes the full P2P handshake (Version / Verack / Ready). Succeeds only if the node accepts
    /// the connection; returns Err (carrying the node's reject reason) if the node refuses us, which is
    /// exactly what a banned address sees.
    pub async fn handshake(&mut self) -> Result<(), String> {
        let version = VersionMessage {
            protocol_version: PROTOCOL_VERSION,
            services: 0,
            timestamp: now_ms() as i64,
            network: self.network_name.clone(),
            user_agent: "/g5-raw-peer:0.1.0/".to_owned(),
            disable_relay_tx: false,
            subnetwork_id: None,
            id: vec![rand::random::<u8>(); 16],
            address: Some(NetAddress { timestamp: 0, ip: vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1], port: 0 }),
        };
        // The node reads Version, Verack and Ready from independent routes, so we may send all three up
        // front; it answers each when its own handshake stage reaches it.
        self.send(Payload::Version(version), 0).await?;
        self.send(Payload::Verack(VerackMessage {}), 0).await?;
        self.recv_until(&["Verack"]).await?;
        self.send(Payload::Ready(ReadyMessage {}), 0).await?;
        self.recv_until(&["Ready"]).await?;
        Ok(())
    }

    /// Drives the node through a genuine IBD and, when it asks for the pruning-point proof, answers with
    /// a bogus proof whose RandomZ epoch is impossible. Returns `DeliveredBogusProof` once the proof is
    /// on the wire (the node then runs `validate_pruning_proof`, hitting the ban path).
    ///
    /// `salt` varies the fake block/hashes across attempts so repeated attempts are not deduplicated by
    /// the node's block-request or status caches.
    pub async fn attack_with_bogus_pruning_proof(&mut self, salt: u64) -> Result<AttackOutcome, String> {
        // A fake relay block that is far ahead and whose single parent is unknown. Delivering it makes
        // the node treat us as a syncer with much more chain and start IBD against us.
        let relay_header = fake_relay_header(salt);
        let relay_hash = relay_header.hash;

        // 1) Announce the block.
        self.send(Payload::InvRelayBlock(InvRelayBlockMessage { hash: Some(to_pb_hash(relay_hash)) }), 0).await?;

        // From here the node interleaves several requests. Serve each until we have delivered the proof.
        // RequestRelayBlocks and RequestBlockLocator responses are routed by the node on the request's
        // id, so we echo that id as the response_id. The two IBD requests are type-routed (id 0).
        loop {
            let (payload, request_id) = self
                .recv_until(&["RequestRelayBlocks", "RequestBlockLocator", "RequestIbdChainBlockLocator", "RequestPruningPointProof"])
                .await?;
            match payload {
                // 2) The node asks for the announced block's body; send the fake block.
                Payload::RequestRelayBlocks(_) => {
                    self.send(Payload::Block(fake_block_message(&relay_header)), request_id).await?;
                }
                // 3) Orphan-resolution probe: answer with a hash the node cannot know, so the block is
                //    treated as out of resolution range and IBD is triggered.
                Payload::RequestBlockLocator(_) => {
                    self.send(
                        Payload::BlockLocator(BlockLocatorMessage { hashes: vec![to_pb_hash(unknown_hash(salt, 0xB10C))] }),
                        request_id,
                    )
                    .await?;
                }
                // 4) IBD chain negotiation: answer with an unknown chain, so the node finds no shared
                //    block and decides it must download a headers proof.
                Payload::RequestIbdChainBlockLocator(_) => {
                    self.send(
                        Payload::IbdChainBlockLocator(IbdChainBlockLocatorMessage {
                            block_locator_hashes: vec![to_pb_hash(unknown_hash(salt, 0x1BD))],
                        }),
                        0,
                    )
                    .await?;
                }
                // 5) The node requests the pruning-point proof: deliver the bogus one and we are done.
                Payload::RequestPruningPointProof(_) => {
                    self.send_bogus_proof(salt).await?;
                    return Ok(AttackOutcome::DeliveredBogusProof);
                }
                other => return Err(format!("unexpected node request: {}", payload_name(&other))),
            }
        }
    }

    /// Sends a pruning-point proof with exactly `max_block_level + 1` = 251 levels (so it passes the
    /// structural length check) in which every header claims `IMPLAUSIBLE_DAA_SCORE`. The node's
    /// `zethora_check_pow_epochs` rejects it with `ZethoraPowEpochImplausible` before any PoW work.
    ///
    /// The node (protocol v11) receives the proof in chunks: one chunk per level, highest level first,
    /// terminated by a chunk-end message.
    async fn send_bogus_proof(&self, salt: u64) -> Result<(), String> {
        const LEVELS: u32 = 251; // devnet max_block_level (250) + 1
        for level in (0..LEVELS).rev() {
            let header = fake_proof_header(salt, level as u64);
            self.send(Payload::PruningPointProofChunk(PruningPointProofChunkMessage { chunk: vec![(&header).into()], level }), 0)
                .await?;
        }
        self.send(Payload::PruningPointProofChunksEnd(PruningPointProofChunksEndMessage {}), 0).await?;
        Ok(())
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64
}

fn to_pb_hash(hash: Hash) -> kaspa_p2p_lib::pb::Hash {
    kaspa_p2p_lib::pb::Hash { bytes: hash.as_bytes().to_vec() }
}

/// A deterministic hash the node cannot possibly know (derived from salt + tag).
fn unknown_hash(salt: u64, tag: u64) -> Hash {
    let mut bytes = [0u8; 32];
    bytes[0..8].copy_from_slice(&salt.to_le_bytes());
    bytes[8..16].copy_from_slice(&tag.to_le_bytes());
    bytes[16] = 0xA5;
    Hash::from_bytes(bytes)
}

/// Fake relay block header: far ahead (huge blue score / work so the node wants a headers proof) with a
/// single unknown parent (so the node orphans it and starts IBD). The DAA score is huge too, which only
/// means its own PoW is never computed on the relay path (it fails earlier on missing parents).
fn fake_relay_header(salt: u64) -> Header {
    Header::new_finalized(
        BLOCK_VERSION,
        vec![vec![unknown_hash(salt, 0xDEAD)]].try_into().unwrap(),
        Hash::default(),
        Hash::default(),
        Hash::default(),
        now_ms(),
        0x207fffff,
        salt,
        IMPLAUSIBLE_DAA_SCORE,
        BlueWorkType::from_u64(1_000_000_000),
        1_000_000_000,
        Hash::default(),
    )
}

/// Fake proof header: no parents (genesis-like), claiming the implausible DAA score / epoch.
fn fake_proof_header(salt: u64, level: u64) -> Header {
    Header::new_finalized(
        BLOCK_VERSION,
        Vec::<Vec<Hash>>::new().try_into().unwrap(),
        Hash::default(),
        Hash::default(),
        Hash::default(),
        0,
        0x207fffff,
        salt.wrapping_mul(251).wrapping_add(level),
        IMPLAUSIBLE_DAA_SCORE,
        BlueWorkType::from_u64(1),
        0,
        Hash::default(),
    )
}

/// A block message carrying the fake header and one minimal native transaction, so the node does not
/// reject it as header-only.
fn fake_block_message(header: &Header) -> BlockMessage {
    let tx = TransactionMessage {
        version: 0,
        inputs: vec![],
        outputs: vec![],
        lock_time: 0,
        subnetwork_id: Some(SubnetworkId { bytes: vec![0u8; 20] }),
        gas: 0,
        payload: vec![],
        storage_mass: 0,
    };
    BlockMessage { header: Some(header.into()), transactions: vec![tx] }
}

fn payload_name(p: &Payload) -> &'static str {
    match p {
        Payload::Version(_) => "Version",
        Payload::Verack(_) => "Verack",
        Payload::Ready(_) => "Ready",
        Payload::InvRelayBlock(_) => "InvRelayBlock",
        Payload::RequestRelayBlocks(_) => "RequestRelayBlocks",
        Payload::Block(_) => "Block",
        Payload::RequestBlockLocator(_) => "RequestBlockLocator",
        Payload::BlockLocator(_) => "BlockLocator",
        Payload::RequestIbdChainBlockLocator(_) => "RequestIbdChainBlockLocator",
        Payload::IbdChainBlockLocator(_) => "IbdChainBlockLocator",
        Payload::RequestPruningPointProof(_) => "RequestPruningPointProof",
        Payload::PruningPointProofChunk(_) => "PruningPointProofChunk",
        Payload::PruningPointProofChunksEnd(_) => "PruningPointProofChunksEnd",
        Payload::Reject(_) => "Reject",
        _ => "Other",
    }
}
