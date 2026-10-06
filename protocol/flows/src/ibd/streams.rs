//!
//! Logical stream abstractions used throughout the IBD negotiation protocols
//!

use kaspa_consensus_core::{
    errors::consensus::ConsensusError,
    header::Header,
    tx::{TransactionOutpoint, UtxoEntry},
};
use kaspa_core::{debug, info};
use kaspa_hashes::Hash;
use kaspa_p2p_lib::{
    IncomingRoute, Router,
    common::{DEFAULT_TIMEOUT, ProtocolError},
    convert::model::trusted::TrustedDataEntry,
    make_message,
    pb::{
        RequestNextHeadersMessage, RequestNextPruningPointAndItsAnticoneBlocksMessage, RequestNextPruningPointSmtChunkMessage,
        RequestNextPruningPointUtxoSetChunkMessage, kaspad_message::Payload,
    },
};
use std::sync::Arc;
use tokio::time::timeout;

pub const IBD_BATCH_SIZE: usize = 99;

/// Maximum number of SMT lane entries carried by a single `SmtLaneChunkMessage`.
#[cfg(not(feature = "test-smt-small-chunks"))]
pub const SMT_CHUNK_SIZE: usize = 4096;
#[cfg(feature = "test-smt-small-chunks")]
pub const SMT_CHUNK_SIZE: usize = 4;

/// After receiving every `SMT_FLOW_CONTROL_WINDOW`-th chunk the receiver asks for
/// more. Each chunk already batches thousands of lanes, so 10 is plenty of
/// round-trips while keeping the in-flight message count far below the 256
/// incoming-route capacity.
#[cfg(not(feature = "test-smt-small-chunks"))]
pub const SMT_FLOW_CONTROL_WINDOW: usize = 10;
#[cfg(feature = "test-smt-small-chunks")]
pub const SMT_FLOW_CONTROL_WINDOW: usize = 2;

pub struct TrustedEntryStream<'a, 'b> {
    router: &'a Router,
    incoming_route: &'b mut IncomingRoute,
    i: usize,
}

impl<'a, 'b> TrustedEntryStream<'a, 'b> {
    pub fn new(router: &'a Router, incoming_route: &'b mut IncomingRoute) -> Self {
        Self { router, incoming_route, i: 0 }
    }

    pub async fn next(&mut self) -> Result<Option<TrustedDataEntry>, ProtocolError> {
        let res = match timeout(DEFAULT_TIMEOUT, self.incoming_route.recv()).await {
            Ok(op) => {
                if let Some(msg) = op {
                    match msg.payload {
                        Some(Payload::BlockWithTrustedDataV4(payload)) => {
                            let entry: TrustedDataEntry = payload.try_into()?;
                            Ok(Some(entry))
                        }
                        Some(Payload::DoneBlocksWithTrustedData(_)) => {
                            debug!("trusted entry stream completed after {} items", self.i);
                            Ok(None)
                        }
                        _ => Err(ProtocolError::UnexpectedMessage(
                            stringify!(Payload::BlockWithTrustedDataV4 | Payload::DoneBlocksWithTrustedData),
                            msg.payload.as_ref().map(|v| v.into()),
                        )),
                    }
                } else {
                    Err(ProtocolError::ConnectionClosed)
                }
            }
            Err(_) => Err(ProtocolError::Timeout(DEFAULT_TIMEOUT)),
        };

        // Request the next batch only if the stream is still live
        if let Ok(Some(_)) = res {
            #[allow(clippy::arithmetic_side_effects, reason = "ARITH-SAFETY(COUNTER)")]
            {
                self.i += 1;
            }
            if self.i.is_multiple_of(IBD_BATCH_SIZE) {
                self.router
                    .enqueue(make_message!(
                        Payload::RequestNextPruningPointAndItsAnticoneBlocks,
                        RequestNextPruningPointAndItsAnticoneBlocksMessage {}
                    ))
                    .await?;
            }
        }

        res
    }
}

/// A chunk of headers
pub type HeadersChunk = Vec<Arc<Header>>;

pub struct HeadersChunkStream<'a, 'b> {
    router: &'a Router,
    incoming_route: &'b mut IncomingRoute,
    i: usize,
}

impl<'a, 'b> HeadersChunkStream<'a, 'b> {
    pub fn new(router: &'a Router, incoming_route: &'b mut IncomingRoute) -> Self {
        Self { router, incoming_route, i: 0 }
    }

    pub async fn next(&mut self) -> Result<Option<HeadersChunk>, ProtocolError> {
        let res = match timeout(DEFAULT_TIMEOUT, self.incoming_route.recv()).await {
            Ok(op) => {
                if let Some(msg) = op {
                    match msg.payload {
                        Some(Payload::BlockHeaders(payload)) => {
                            if payload.block_headers.is_empty() {
                                // The syncer should have sent a done message if the search completed, and not an empty list
                                Err(ProtocolError::Other("Received an empty headers message"))
                            } else {
                                Ok(Some(payload.try_into()?))
                            }
                        }
                        Some(Payload::DoneHeaders(_)) => {
                            debug!("headers chunk stream completed after {} chunks", self.i);
                            Ok(None)
                        }
                        _ => Err(ProtocolError::UnexpectedMessage(
                            stringify!(Payload::BlockHeaders | Payload::DoneHeaders),
                            msg.payload.as_ref().map(|v| v.into()),
                        )),
                    }
                } else {
                    Err(ProtocolError::ConnectionClosed)
                }
            }
            Err(_) => Err(ProtocolError::Timeout(DEFAULT_TIMEOUT)),
        };

        // Request the next batch only if the stream is still live
        if let Ok(Some(_)) = res {
            #[allow(clippy::arithmetic_side_effects, reason = "ARITH-SAFETY(COUNTER)")]
            {
                self.i += 1;
            }
            self.router.enqueue(make_message!(Payload::RequestNextHeaders, RequestNextHeadersMessage {})).await?;
        }

        res
    }
}

/// A chunk of UTXOs
pub type UtxosetChunk = Vec<(TransactionOutpoint, UtxoEntry)>;

pub struct PruningPointUtxosetChunkStream<'a, 'b> {
    router: &'a Router,
    incoming_route: &'b mut IncomingRoute,
    i: usize, // Chunk index
    utxo_count: usize,
}

impl<'a, 'b> PruningPointUtxosetChunkStream<'a, 'b> {
    pub fn new(router: &'a Router, incoming_route: &'b mut IncomingRoute) -> Self {
        Self { router, incoming_route, i: 0, utxo_count: 0 }
    }

    pub async fn next(&mut self) -> Result<Option<UtxosetChunk>, ProtocolError> {
        let res: Result<Option<UtxosetChunk>, ProtocolError> = match timeout(DEFAULT_TIMEOUT, self.incoming_route.recv()).await {
            Ok(op) => {
                if let Some(msg) = op {
                    match msg.payload {
                        Some(Payload::PruningPointUtxoSetChunk(payload)) => Ok(Some(payload.try_into()?)),
                        Some(Payload::DonePruningPointUtxoSetChunks(_)) => {
                            info!("Finished receiving the UTXO set. Total UTXOs: {}", self.utxo_count);
                            Ok(None)
                        }
                        Some(Payload::UnexpectedPruningPoint(_)) => {
                            // Although this can happen also to an honest syncer (if his pruning point moves during the sync),
                            // we prefer erring and disconnecting to avoid possible exploits by a syncer repeating this failure
                            Err(ProtocolError::ConsensusError(ConsensusError::UnexpectedPruningPoint))
                        }
                        _ => Err(ProtocolError::UnexpectedMessage(
                            stringify!(
                                Payload::PruningPointUtxoSetChunk
                                    | Payload::DonePruningPointUtxoSetChunks
                                    | Payload::UnexpectedPruningPoint
                            ),
                            msg.payload.as_ref().map(|v| v.into()),
                        )),
                    }
                } else {
                    Err(ProtocolError::ConnectionClosed)
                }
            }
            Err(_) => Err(ProtocolError::Timeout(DEFAULT_TIMEOUT)),
        };

        // Request the next batch only if the stream is still live
        if let Ok(Some(chunk)) = res {
            #[allow(clippy::arithmetic_side_effects, reason = "ARITH-SAFETY(COUNTER)")]
            {
                self.i += 1;
            }
            #[allow(clippy::arithmetic_side_effects, reason = "ARITH-SAFETY(COUNTER)")]
            {
                self.utxo_count += chunk.len();
            }
            if self.i.is_multiple_of(IBD_BATCH_SIZE) {
                info!("Received {} UTXO set chunks so far, totaling in {} UTXOs", self.i, self.utxo_count);
                self.router
                    .enqueue(make_message!(
                        Payload::RequestNextPruningPointUtxoSetChunk,
                        RequestNextPruningPointUtxoSetChunkMessage {}
                    ))
                    .await?;
            }
            Ok(Some(chunk))
        } else {
            res
        }
    }
}

const SMT_PROOF_INTERVAL: usize = kaspa_consensus_core::api::SMT_PROOF_INTERVAL;

/// Stream of SMT lane chunks. Flow-controlled: after every [`SMT_FLOW_CONTROL_WINDOW`]
/// chunks received the stream enqueues a [`RequestNextPruningPointSmtChunkMessage`]
/// back to the peer. The total number of lanes is conveyed via the metadata header
/// (`active_lanes_count`), so no explicit `Done` sentinel is required — both sides
/// terminate naturally once that many lanes have been transferred.
///
/// Enforces that the first and every [`SMT_PROOF_INTERVAL`]-th entry carries proof bytes.
pub struct SmtStream<'a, 'b> {
    router: &'a Router,
    incoming_route: &'b mut IncomingRoute,
    expected_count: u64,
    lane_count: u64,
    chunks_received: usize,
}

impl<'a, 'b> SmtStream<'a, 'b> {
    pub fn new(router: &'a Router, incoming_route: &'b mut IncomingRoute) -> Self {
        Self { router, incoming_route, expected_count: 0, lane_count: 0, chunks_received: 0 }
    }

    pub async fn recv_metadata(&mut self) -> Result<kaspa_consensus_core::api::SmtExportMetadata, ProtocolError> {
        match timeout(DEFAULT_TIMEOUT, self.incoming_route.recv()).await {
            Ok(Some(msg)) => match msg.payload {
                Some(Payload::SmtMetadata(payload)) => {
                    use kaspa_consensus_core::api::SmtExportMetadata;
                    // Wire: 96 bytes = lanes_root || payload_and_ctx_digest || parent_seq_commit.
                    let (chunks, rem) = payload.data.as_chunks::<32>();
                    if !rem.is_empty() {
                        return Err(ProtocolError::Other("SmtMetadata data length not a multiple of 32 bytes"));
                    }
                    self.expected_count = payload.active_lanes_count;
                    let md = match *chunks {
                        [lanes_root, payload_and_ctx_digest, parent_seq_commit] => {
                            let [lanes_root, payload_and_ctx_digest, parent_seq_commit] =
                                [lanes_root, payload_and_ctx_digest, parent_seq_commit].map(Hash::from_bytes);
                            SmtExportMetadata {
                                lanes_root,
                                payload_and_ctx_digest,
                                parent_seq_commit,
                                active_lanes_count: payload.active_lanes_count,
                            }
                        }
                        _ => return Err(ProtocolError::Other("SmtMetadata data must be 96 bytes")),
                    };
                    Ok(md)
                }
                Some(Payload::UnexpectedPruningPoint(_)) => Err(ProtocolError::ConsensusError(ConsensusError::UnexpectedPruningPoint)),
                _ => Err(ProtocolError::UnexpectedMessage(stringify!(Payload::SmtMetadata), msg.payload.as_ref().map(|v| v.into()))),
            },
            Ok(None) => Err(ProtocolError::ConnectionClosed),
            Err(_) => Err(ProtocolError::Timeout(DEFAULT_TIMEOUT)),
        }
    }

    /// Receives the next chunk of lanes from the peer. Returns `Ok(None)` once
    /// `active_lanes_count` lanes have been consumed.
    pub async fn next_chunk(&mut self) -> Result<Option<Vec<kaspa_consensus_core::api::ImportLane>>, ProtocolError> {
        if self.lane_count >= self.expected_count {
            return Ok(None);
        }

        let payload = match timeout(DEFAULT_TIMEOUT, self.incoming_route.recv()).await {
            Ok(Some(msg)) => match msg.payload {
                Some(Payload::SmtLaneChunk(payload)) => payload,
                Some(Payload::UnexpectedPruningPoint(_)) => {
                    return Err(ProtocolError::ConsensusError(ConsensusError::UnexpectedPruningPoint));
                }
                _ => {
                    return Err(ProtocolError::UnexpectedMessage(
                        stringify!(Payload::SmtLaneChunk),
                        msg.payload.as_ref().map(|v| v.into()),
                    ));
                }
            },
            Ok(None) => return Err(ProtocolError::ConnectionClosed),
            Err(_) => return Err(ProtocolError::Timeout(DEFAULT_TIMEOUT)),
        };

        if payload.entries.is_empty() {
            return Err(ProtocolError::Other("received an empty SmtLaneChunk"));
        }

        if payload.entries.len() > SMT_CHUNK_SIZE {
            return Err(ProtocolError::Other("SmtLaneChunk exceeds SMT_CHUNK_SIZE"));
        }

        #[allow(clippy::arithmetic_side_effects, reason = "next_chunk() returned above if lane_count >= expected_count.")]
        let remaining = self.expected_count - self.lane_count;
        if payload.entries.len() as u64 > remaining {
            return Err(ProtocolError::Other("received more SMT lane entries than active_lanes_count"));
        }

        let mut lanes = Vec::with_capacity(payload.entries.len());
        for entry in payload.entries {
            let Some((&key_bytes, rem)) = entry.data.split_first_chunk::<32>() else {
                return Err(ProtocolError::Other("SmtLaneEntry data too short for lane_key"));
            };
            let Some(&tip_bytes) = rem.first_chunk::<32>() else {
                return Err(ProtocolError::Other("SmtLaneEntry data too short for lane_tip"));
            };
            if rem.len() != 32 {
                return Err(ProtocolError::Other("SmtLaneEntry data must be exactly 64 bytes"));
            }
            let lane_key = Hash::from_bytes(key_bytes);
            let lane_tip = Hash::from_bytes(tip_bytes);

            let proof = if (self.lane_count as usize).is_multiple_of(SMT_PROOF_INTERVAL) {
                Some(
                    kaspa_smt::proof::OwnedSmtProof::from_bytes(&entry.proof)
                        .map_err(|e| ProtocolError::OtherOwned(format!("invalid SMT proof: {e}")))?,
                )
            } else {
                None
            };

            lanes.push(kaspa_consensus_core::api::ImportLane { lane_key, lane_tip, blue_score: entry.blue_score, proof });
            #[allow(clippy::arithmetic_side_effects, reason = "ARITH-SAFETY(LENGTH)")]
            {
                self.lane_count += 1;
            }
        }

        #[allow(clippy::arithmetic_side_effects, reason = "ARITH-SAFETY(COUNTER)")]
        {
            self.chunks_received += 1;
        }

        // Enqueue RequestNext for the next window — but only if more lanes remain.
        // When `lane_count == expected_count` the caller will stop iterating and the
        // sender's loop has already exhausted its DB iteration, so no further signal
        // is needed (and would dead-lock the sender past its last chunk).
        if self.lane_count < self.expected_count && self.chunks_received.is_multiple_of(SMT_FLOW_CONTROL_WINDOW) {
            self.router
                .enqueue(make_message!(Payload::RequestNextPruningPointSmtChunk, RequestNextPruningPointSmtChunkMessage {}))
                .await?;
        }

        Ok(Some(lanes))
    }

    pub fn lane_count(&self) -> u64 {
        self.lane_count
    }
}

/// Zethora: maximum number of items (spent private coin tags or coin list snapshots) in one
/// `ZethoraPrivateStateChunkMessage` (at most 4096 * 40 bytes = 160 KB per message).
pub const ZETHORA_PRIVATE_STATE_CHUNK_SIZE: usize = 4096;

/// Zethora: after every this many private state chunks, the receiver asks for more (as with the SMT state).
pub const ZETHORA_PRIVATE_STATE_FLOW_CONTROL_WINDOW: usize = 10;

/// Zethora: receives the private state at the pruning point (ZTH-SPEC-006 §6.4) after a `RequestZethoraPrivateState`
/// was sent: a header with the private coin list and the counts, then chunks of spent coin tags and coin list
/// snapshots. Only checks the shape here; consensus checks the contents against the pruning point's fingerprint.
pub async fn receive_zethora_private_state(
    router: &Router,
    incoming_route: &mut IncomingRoute,
) -> Result<kaspa_consensus_core::api::ZethoraPrivateState, ProtocolError> {
    use kaspa_p2p_lib::pb::RequestNextZethoraPrivateStateChunkMessage;

    let header = match timeout(DEFAULT_TIMEOUT, incoming_route.recv()).await {
        Ok(Some(msg)) => match msg.payload {
            Some(Payload::ZethoraPrivateStateHeader(header)) => header,
            Some(Payload::UnexpectedPruningPoint(_)) => {
                return Err(ProtocolError::ConsensusError(ConsensusError::UnexpectedPruningPoint));
            }
            _ => {
                return Err(ProtocolError::UnexpectedMessage(
                    stringify!(Payload::ZethoraPrivateStateHeader),
                    msg.payload.as_ref().map(|v| v.into()),
                ));
            }
        },
        Ok(None) => return Err(ProtocolError::ConnectionClosed),
        Err(_) => return Err(ProtocolError::Timeout(DEFAULT_TIMEOUT)),
    };
    let spent_count =
        usize::try_from(header.spent_count).map_err(|_| ProtocolError::Other("Zethora private state: too many spent tags"))?;
    let anchor_count =
        usize::try_from(header.anchor_count).map_err(|_| ProtocolError::Other("Zethora private state: too many snapshots"))?;
    let total = spent_count.checked_add(anchor_count).ok_or(ProtocolError::Other("Zethora private state: counts overflow"))?;

    // Never trust the announced counts for memory: grow as data actually arrives
    let mut spent: Vec<[u8; 32]> = Vec::with_capacity(spent_count.min(1 << 16));
    let mut anchors: Vec<([u8; 32], u64)> = Vec::with_capacity(anchor_count.min(1 << 16));
    let mut chunks_received = 0usize;

    while spent.len() + anchors.len() < total {
        let chunk = match timeout(DEFAULT_TIMEOUT, incoming_route.recv()).await {
            Ok(Some(msg)) => match msg.payload {
                Some(Payload::ZethoraPrivateStateChunk(chunk)) => chunk,
                _ => {
                    return Err(ProtocolError::UnexpectedMessage(
                        stringify!(Payload::ZethoraPrivateStateChunk),
                        msg.payload.as_ref().map(|v| v.into()),
                    ));
                }
            },
            Ok(None) => return Err(ProtocolError::ConnectionClosed),
            Err(_) => return Err(ProtocolError::Timeout(DEFAULT_TIMEOUT)),
        };

        let (tags, rest) = chunk.spent.as_chunks::<32>();
        if !rest.is_empty() {
            return Err(ProtocolError::Other("Zethora private state: spent tags are not 32 bytes each"));
        }
        let (snapshots, rest) = chunk.anchors.as_chunks::<40>();
        if !rest.is_empty() {
            return Err(ProtocolError::Other("Zethora private state: snapshots are not 40 bytes each"));
        }
        let items = tags.len() + snapshots.len();
        if items == 0 || items > ZETHORA_PRIVATE_STATE_CHUNK_SIZE {
            return Err(ProtocolError::Other("Zethora private state: chunk is empty or too large"));
        }
        if spent.len() + tags.len() > spent_count || anchors.len() + snapshots.len() > anchor_count {
            return Err(ProtocolError::Other("Zethora private state: more items than announced"));
        }
        spent.extend(tags.iter().copied());
        anchors.extend(snapshots.iter().map(|s| {
            let root: [u8; 32] = s[..32].try_into().expect("40-byte chunk");
            let blue_score = u64::from_le_bytes(s[32..].try_into().expect("40-byte chunk"));
            (root, blue_score)
        }));

        #[allow(clippy::arithmetic_side_effects, reason = "ARITH-SAFETY(COUNTER)")]
        {
            chunks_received += 1;
        }
        // Mirror the sender: ask for more after every window, unless everything has arrived
        if spent.len() + anchors.len() < total && chunks_received.is_multiple_of(ZETHORA_PRIVATE_STATE_FLOW_CONTROL_WINDOW) {
            router
                .enqueue(make_message!(Payload::RequestNextZethoraPrivateStateChunk, RequestNextZethoraPrivateStateChunkMessage {}))
                .await?;
        }
    }

    Ok(kaspa_consensus_core::api::ZethoraPrivateState { note_tree: header.note_tree, spent, anchors })
}
