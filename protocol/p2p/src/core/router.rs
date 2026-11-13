use crate::core::hub::HubEvent;
use crate::pb::{
    BlockGhostdagDataHashPair, BlockHeader, BlockLevelParents, BlockMessage, BluesAnticoneSizes, DaaBlock, DaaBlockV4, GhostdagData,
    Hash, KaspadMessage, NetAddress, OutpointAndUtxoEntryPair, PruningPointProofHeaderArray, RejectMessage, SmtLaneEntry,
    TransactionInput, TransactionMessage, TransactionOutput, kaspad_message::Payload as KaspadMessagePayload,
};
use crate::{KaspadMessagePayloadType, common::ProtocolError};
use crate::{Peer, make_message};
use kaspa_core::{debug, error, info, trace, warn};
use kaspa_utils::networking::PeerId;
use parking_lot::{Mutex, RwLock};
use prost::Message;
use seqlock::SeqLock;
use std::fmt::{Debug, Display};
use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Instant;
use std::{collections::HashMap, sync::Arc};
use tokio::select;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{Receiver as MpscReceiver, Sender as MpscSender, channel as mpsc_channel};
use tokio::sync::oneshot::{Sender as OneshotSender, channel as oneshot_channel};
use tonic::codec::{BufferSettings, Codec, DecodeBuf, Decoder};
use tonic::{Status, Streaming};
use prost::bytes::Buf;
use tonic_prost::{ProstCodec, ProstDecoder, ProstEncoder};

use super::connection_handler::{P2P_MAX_MESSAGE_SIZE, P2P_MAX_PRE_HANDSHAKE_MESSAGE_SIZE};
use super::peer::{PeerKey, PeerProperties};

pub struct IncomingRoute {
    rx: MpscReceiver<KaspadMessage>,
    id: u32,
}

// BLANK_ROUTE_ID is the value that is used in the p2p when no request or response IDs
// are needed. To support backward compatibility, this is set to the default gRPC value
// for uint32.
pub const BLANK_ROUTE_ID: u32 = 0;
static ROUTE_ID: AtomicU32 = AtomicU32::new(BLANK_ROUTE_ID + 1);

impl IncomingRoute {
    pub fn new(rx: MpscReceiver<KaspadMessage>) -> Self {
        let id = ROUTE_ID.fetch_add(1, Ordering::SeqCst);
        Self { rx, id }
    }

    pub fn id(&self) -> u32 {
        self.id
    }
}

impl Deref for IncomingRoute {
    type Target = MpscReceiver<KaspadMessage>;

    fn deref(&self) -> &Self::Target {
        &self.rx
    }
}

impl DerefMut for IncomingRoute {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.rx
    }
}

#[derive(Clone)]
pub struct SharedIncomingRoute(Arc<tokio::sync::Mutex<IncomingRoute>>);

impl SharedIncomingRoute {
    pub fn new(incoming_route: IncomingRoute) -> Self {
        Self(Arc::new(tokio::sync::Mutex::new(incoming_route)))
    }

    pub async fn recv(&mut self) -> Option<KaspadMessage> {
        self.0.lock().await.recv().await
    }
}

/// The policy for handling the case where route capacity is reached for a specific route type
pub enum IncomingRouteOverflowPolicy {
    /// Drop the incoming message
    Drop,

    /// Disconnect from this peer
    Disconnect,
}

impl From<KaspadMessagePayloadType> for IncomingRouteOverflowPolicy {
    fn from(msg_type: KaspadMessagePayloadType) -> Self {
        match msg_type {
            // Inv messages are unique in the sense that no harm is done if some of them are dropped
            KaspadMessagePayloadType::InvTransactions | KaspadMessagePayloadType::InvRelayBlock => IncomingRouteOverflowPolicy::Drop,
            _ => IncomingRouteOverflowPolicy::Disconnect,
        }
    }
}

#[derive(Debug, Default)]
struct RouterMutableState {
    /// Used on router init to signal the router receive loop to start listening
    start_signal: Option<OneshotSender<()>>,

    /// Used on router close to signal the router receive loop to exit
    shutdown_signal: Option<OneshotSender<()>>,

    /// Properties of the peer
    properties: Arc<PeerProperties>,

    /// Duration of the last ping to this peer
    last_ping_duration: u64,
}

impl RouterMutableState {
    fn new(start_signal: Option<OneshotSender<()>>, shutdown_signal: Option<OneshotSender<()>>) -> Self {
        Self { start_signal, shutdown_signal, ..Default::default() }
    }
}

/// A router object for managing the communication to a network peer. It is named a router because it's responsible
/// for internally routing messages to P2P flows based on registration and message types
#[derive(Debug)]
pub struct Router {
    /// Internal identity of this peer
    identity: SeqLock<PeerId>,

    /// The socket address of this peer
    net_address: SocketAddr,

    /// Indicates whether this connection is an outbound connection
    is_outbound: bool,

    /// Time of creation of this object and the connection it holds
    connection_started: Instant,

    /// Routing map for mapping messages to subscribed flows
    routing_map_by_type: RwLock<HashMap<KaspadMessagePayloadType, MpscSender<KaspadMessage>>>,

    routing_map_by_id: RwLock<HashMap<u32, MpscSender<KaspadMessage>>>,

    /// The outgoing route for sending messages to this peer
    outgoing_route: MpscSender<KaspadMessage>,

    /// A channel sender for internal event management. Used to send information from each router to a central hub object
    hub_sender: MpscSender<HubEvent>,

    /// Used for managing router mutable state
    mutable_state: Mutex<RouterMutableState>,

    /// Tracks whether the P2P handshake has completed. Until it completes, only `Version`, `Verack`
    /// and `Ready` messages are accepted (see `route_to_flow`), so a hostile peer cannot make the
    /// protobuf decoder materialize a huge object graph before any flow has subscribed to it.
    handshake_complete: AtomicBool,
}

impl Display for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.net_address)
    }
}

impl From<&Router> for PeerKey {
    fn from(value: &Router) -> Self {
        Self::new(value.identity.read(), value.net_address.ip().into())
    }
}

impl From<&Router> for Peer {
    fn from(router: &Router) -> Self {
        Self::new(
            router.identity(),
            router.net_address,
            router.is_outbound,
            router.connection_started,
            router.properties(),
            router.last_ping_duration(),
        )
    }
}

fn message_summary(msg: &KaspadMessage) -> impl Debug {
    // TODO (low priority): display a concise summary of the message. Printing full messages
    // overflows the logs and is hardly useful, hence we currently only return the type
    msg.payload.as_ref().map(std::convert::Into::<KaspadMessagePayloadType>::into)
}

/// The only message types that are legal while the P2P handshake is still in progress. `Version`,
/// `Verack` and `Ready` are the sole messages exchanged by the handshake itself, and all three are
/// tiny, so anything else arriving before the handshake completes is treated as a protocol violation.
fn is_pre_handshake_message_type(msg_type: KaspadMessagePayloadType) -> bool {
    matches!(msg_type, KaspadMessagePayloadType::Version | KaspadMessagePayloadType::Verack | KaspadMessagePayloadType::Ready)
}

// -------------------------------------------------------------------------------------------------
// Zethora: decoded-message budgets for `repeated` fields
// -------------------------------------------------------------------------------------------------
//
// `p2p.proto` declares 32 `repeated` fields, and prost decodes every one of them by pushing one
// element per wire occurrence. It exposes no knob for capping the element count or the allocation
// (`Message::decode` only takes the encoded buffer and a recursion limit), so the frame limit in
// `connection_handler` is the *only* pre-decode bound -- and a frame limit bounds bytes on the wire,
// not the object graph those bytes expand into. An empty sub-message costs two bytes on the wire and
// one full in-memory struct, which turns the 10 MiB frame limit into:
//
//   * `BlockHeadersMessage.blockHeaders`: 2 bytes -> `BlockHeader` (184 bytes), i.e. ~5.2M elements
//     and ~960 MiB from a single legal frame;
//   * `BlockBodyMessage.transactions`: 2 bytes -> `TransactionMessage` (128 bytes), i.e. ~660 MiB;
//   * `AddressesMessage.addressList`: 2 bytes -> `NetAddress` (40 bytes), i.e. ~200 MiB;
//   * `TrustedDataChunkMessage.headers`: 2 bytes -> `DaaBlockV4` (312 bytes), i.e. ~1.6 GiB.
//
// The same trick works for every other repeated field, and the cost does not end at the decode:
// `route_to_flow` hands the message to a flow queue (`try_send` clones it) and the `TryFrom`
// conversions turn each element into a consensus type owning further allocations. Refusing an
// amplified message *before* it is routed is therefore what keeps the amplification from being
// multiplied once per flow and once per conversion.
//
// Prost gives no pre-allocation hook, so the defence is layered:
//
//   1. inbound gzip is disabled and `max_decoding_message_size` is 10 MiB (`connection_handler`), so
//      a single frame can only expand by the per-element ratio above;
//   2. `Router::check_decoded_message_budget` runs as the first thing `route_to_flow` does with a
//      decoded message. It enforces a per-field element cap derived from the protocol's own chunk
//      and request limits, and charges the estimated retained size of the graph against both an
//      absolute ceiling (`MAX_DECODED_MESSAGE_SIZE`, 8x the frame limit) and a relative ceiling
//      (16x the encoded length plus 1 MiB). A message that cannot be the honest result of a peer
//      respecting those limits is a protocol violation and drops the connection.
//
// The estimator charges `size_of` once per repeated element and the length of every `bytes` field
// separately. It is deliberately a lower bound -- a `Vec` may over-allocate up to 2x while growing
// -- which the 8x absolute headroom leaves room for.
//
// Residual bound: this validation runs after prost has already materialized the graph, so it bounds
// what the node *retains* and routes, not what the decoder transiently allocates. A 10 MiB frame of
// empty `DaaBlockV4` elements still costs ~1.6 GiB for the duration of the decode. That residual is
// bounded by the frame ratio alone, which is why the frame limit is 10 MiB and inbound gzip is
// disabled in `connection_handler` -- together they keep "one message" from meaning "the whole heap".

/// Absolute ceiling on the estimated retained size of one decoded inbound P2P message.
///
/// This is 8x the transport frame limit (`P2P_MAX_MESSAGE_SIZE`): enough headroom for the largest
/// honest payloads (a 10 MiB block of transactions, an 8 MiB header or trusted-data chunk, a
/// 4096-entry SMT chunk) while keeping what one hostile frame can make the node retain bounded and
/// small compared to the 256 MiB frame the decoder used to accept.
pub const DECODED_MESSAGE_SIZE_LIMIT: usize = 8 * P2P_MAX_MESSAGE_SIZE;

/// Multiplier applied to a message's encoded length to obtain its relative decoded-size ceiling.
const DECODED_SIZE_AMPLIFICATION: usize = 16;

/// Slack added to the relative ceiling so tiny messages with a few repeated fields are never
/// rejected over a rounding error (a one-header message is 2 bytes encoded and ~200 bytes decoded).
const DECODED_SIZE_SLACK: usize = 1024 * 1024;

/// `AddressesMessage.addressList`. Honest peers send at most 1000 addresses and accept at most 2500
/// (`MAX_ADDRESSES_SEND`/`MAX_ADDRESSES_RECEIVE` in the address flow).
const MAX_ADDRESS_LIST_ELEMENTS: usize = 4_096;

/// Every header-bearing vector: `BlockHeadersMessage.blockHeaders`, `PruningPointsMessage.headers`,
/// `PruningPointProofHeaderArray.headers`, `PruningPointProofChunkMessage.chunk` and
/// `TrustedDataChunkMessage.headers`. The serving flows cut these at `HEADERS_CHUNK_SIZE` or
/// `TRUSTED_DATA_CHUNK_SIZE` (8 MiB of encoded data), which holds at most ~36k minimal real headers
/// (~230 bytes each) or ~17k trusted entries (~485 bytes each), so the cap leaves headroom while
/// empty elements are stopped far earlier by the size budget.
const MAX_HEADER_ELEMENTS: usize = 65_536;

/// `BlockMessage.transactions` and `BlockBodyMessage.transactions`. Consensus block mass allows
/// ~1.3k transactions of the smallest possible size, so 16k is already an order of magnitude above
/// anything an honest block can contain.
const MAX_TRANSACTION_ELEMENTS: usize = 16_384;

/// `TransactionMessage.inputs` / `outputs`. A transaction is bounded by block mass; the largest
/// honest transactions have a few hundred inputs and a few thousand outputs.
const MAX_TRANSACTION_INPUT_ELEMENTS: usize = 32_768;
const MAX_TRANSACTION_OUTPUT_ELEMENTS: usize = 32_768;

/// `BlockHeader.parents` (levels of the DAG) and `BlockLevelParents.parentHashes` (hashes within one
/// level). Both are bounded by `mergeset_size_limit` (180 on mainnet).
const MAX_BLOCK_PARENT_LEVELS: usize = 1_024;
const MAX_PARENT_HASHES_PER_LEVEL: usize = 1_024;

/// `BlockLocatorMessage.hashes`, `IbdBlockLocatorMessage.blockLocatorHashes`,
/// `IbdChainBlockLocatorMessage.blockLocatorHashes`, `RequestRelayBlocksMessage.hashes`,
/// `RequestIBDBlocksMessage.hashes` and `RequestBlockBodiesMessage.hashes`. Honest locators are a few
/// dozen hashes and the request flows already refuse more than 128 hashes
/// (`MAX_BLOCK_HASHES_PER_REQUEST`), so 4096 cannot reject an honest peer.
const MAX_HASH_VECTOR_ELEMENTS: usize = 4_096;

/// `InvTransactionsMessage.ids` / `RequestTransactionsMessage.ids`. Equal to the flow's own
/// `MAX_INV_PER_TX_INV_MSG` (131_072), the largest honest inv message.
const MAX_TRANSACTION_ID_ELEMENTS: usize = 131_072;

/// `PruningPointUtxoSetChunkMessage.outpointAndUtxoEntryPairs`. The serving flow sends `CHUNK_SIZE`
/// (1000) pairs per message.
const MAX_UTXO_PAIR_ELEMENTS: usize = 65_536;

/// `BlockWithTrustedDataMessage`/`TrustedDataMessage` windows and ghostdag pairs. Honest chunks are
/// cut at 8 MiB of encoded data, which holds at most ~17k trusted entries.
const MAX_TRUSTED_DATA_ELEMENTS: usize = 65_536;

/// `GhostdagData.mergeSetBlues`/`mergeSetReds`/`bluesAnticoneSizes`, all bounded by
/// `mergeset_size_limit` (180 on mainnet).
const MAX_GHOSTDAG_MERGE_SET_ELEMENTS: usize = 1_024;

/// `PruningPointProofMessage.headers`: one header array per DAG level, ~log2(pruning depth) levels.
const MAX_PROOF_LEVELS: usize = 256;

/// `BlockWithTrustedDataV4Message.daaWindowIndices`/`ghostdagDataIndices`. Legacy v4 fields that the
/// current handshake no longer sends (see the proto comments), so they get the tightened network
/// limit rather than the ~1.3M indices a 10 MiB frame of u64s would otherwise allow.
const MAX_TRUSTED_INDICES: usize = 262_144;

/// `SmtLaneChunkMessage.entries`, equal to the flow's own `SMT_CHUNK_SIZE` (4096).
const MAX_SMT_LANE_ENTRIES: usize = 4_096;

/// Running total of the estimated retained size of a decoded message, with the ceiling it is
/// charged against.
struct DecodedSizeBudget {
    limit: usize,
    used: usize,
}

impl DecodedSizeBudget {
    fn new(limit: usize) -> Self {
        Self { limit, used: 0 }
    }

    /// Charges `bytes` and fails as soon as the ceiling is crossed, so an attacker cannot make the
    /// accounting itself walk a multi-gigabyte graph before being refused.
    fn charge(&mut self, bytes: usize, field: &'static str) -> Result<(), ProtocolError> {
        self.used = self.used.saturating_add(bytes);
        if self.used > self.limit {
            return Err(ProtocolError::MisbehavingPeer(format!(
                "P2P message field {field} pushes the decoded message past the decoded-size budget of {} bytes",
                self.limit
            )));
        }
        Ok(())
    }

    /// Enforces the per-field element cap and charges `size_of::<T>()` per element. `T` must be the
    /// element type prost generates for the field; its `size_of` excludes the heap of nested
    /// `Vec`/`String` fields, which the caller charges separately.
    fn repeated<T>(&mut self, field: &'static str, len: usize, cap: usize) -> Result<(), ProtocolError> {
        if len > cap {
            return Err(ProtocolError::MisbehavingPeer(format!(
                "P2P message field {field} carries {len} elements, over the per-message limit of {cap}"
            )));
        }
        self.charge(len.saturating_mul(std::mem::size_of::<T>()), field)
    }
}

/// Charges everything a `BlockHeader` owns. The inline `size_of::<BlockHeader>()` is charged by
/// whoever owns the header (`repeated::<BlockHeader>` for header vectors, the parent message for a
/// singular header), so this function only charges the heap hanging off it.
fn account_block_header(budget: &mut DecodedSizeBudget, header: &BlockHeader) -> Result<(), ProtocolError> {
    budget.repeated::<BlockLevelParents>("BlockHeader.parents", header.parents.len(), MAX_BLOCK_PARENT_LEVELS)?;
    for level in &header.parents {
        budget.repeated::<Hash>("BlockLevelParents.parentHashes", level.parent_hashes.len(), MAX_PARENT_HASHES_PER_LEVEL)?;
        for hash in &level.parent_hashes {
            budget.charge(hash.bytes.len(), "BlockLevelParents.parentHashes")?;
        }
    }
    for (field, hash) in [
        ("BlockHeader.hashMerkleRoot", &header.hash_merkle_root),
        ("BlockHeader.acceptedIdMerkleRoot", &header.accepted_id_merkle_root),
        ("BlockHeader.utxoCommitment", &header.utxo_commitment),
        ("BlockHeader.pruningPoint", &header.pruning_point),
    ] {
        if let Some(hash) = hash {
            budget.charge(hash.bytes.len(), field)?;
        }
    }
    budget.charge(header.blue_work.len(), "BlockHeader.blueWork")
}

/// Charges one `TransactionMessage` and everything it owns.
fn account_transaction(budget: &mut DecodedSizeBudget, transaction: &TransactionMessage) -> Result<(), ProtocolError> {
    budget.repeated::<TransactionInput>("TransactionMessage.inputs", transaction.inputs.len(), MAX_TRANSACTION_INPUT_ELEMENTS)?;
    for input in &transaction.inputs {
        if let Some(outpoint) = &input.previous_outpoint
            && let Some(tx_id) = &outpoint.transaction_id
        {
            budget.charge(tx_id.bytes.len(), "Outpoint.transactionId")?;
        }
        budget.charge(input.signature_script.len(), "TransactionInput.signatureScript")?;
    }
    budget.repeated::<TransactionOutput>("TransactionMessage.outputs", transaction.outputs.len(), MAX_TRANSACTION_OUTPUT_ELEMENTS)?;
    for output in &transaction.outputs {
        if let Some(script_public_key) = &output.script_public_key {
            budget.charge(script_public_key.script.len(), "ScriptPublicKey.script")?;
        }
        if let Some(covenant) = &output.covenant
            && let Some(covenant_id) = &covenant.covenant_id
        {
            budget.charge(covenant_id.bytes.len(), "CovenantBinding.covenantId")?;
        }
    }
    if let Some(subnetwork_id) = &transaction.subnetwork_id {
        budget.charge(subnetwork_id.bytes.len(), "SubnetworkId.bytes")?;
    }
    budget.charge(transaction.payload.len(), "TransactionMessage.payload")
}

/// Charges a `repeated TransactionMessage` field and every transaction in it.
fn account_transactions(
    budget: &mut DecodedSizeBudget,
    field: &'static str,
    transactions: &[TransactionMessage],
) -> Result<(), ProtocolError> {
    budget.repeated::<TransactionMessage>(field, transactions.len(), MAX_TRANSACTION_ELEMENTS)?;
    for transaction in transactions {
        account_transaction(budget, transaction)?;
    }
    Ok(())
}

/// Charges a `BlockMessage` (`BlockMessage`, `IbdBlock` and the block embedded in the
/// trusted-data messages all share this shape).
fn account_block(budget: &mut DecodedSizeBudget, block: &BlockMessage) -> Result<(), ProtocolError> {
    if let Some(header) = &block.header {
        account_block_header(budget, header)?;
    }
    account_transactions(budget, "BlockMessage.transactions", &block.transactions)
}

/// Charges a `repeated Hash` field and the bytes of every hash in it.
fn account_hashes(budget: &mut DecodedSizeBudget, field: &'static str, hashes: &[Hash], cap: usize) -> Result<(), ProtocolError> {
    budget.repeated::<Hash>(field, hashes.len(), cap)?;
    for hash in hashes {
        budget.charge(hash.bytes.len(), field)?;
    }
    Ok(())
}

/// Charges a `repeated TransactionId` field and the bytes of every id in it.
fn account_transaction_ids(
    budget: &mut DecodedSizeBudget,
    field: &'static str,
    ids: &[crate::pb::TransactionId],
) -> Result<(), ProtocolError> {
    budget.repeated::<crate::pb::TransactionId>(field, ids.len(), MAX_TRANSACTION_ID_ELEMENTS)?;
    for id in ids {
        budget.charge(id.bytes.len(), field)?;
    }
    Ok(())
}

/// Charges everything a `GhostdagData` owns. Its inline size is charged by its owner (the
/// `repeated::<DaaBlockV4>`/`repeated::<BlockGhostdagDataHashPair>` element or the singular parent).
fn account_ghostdag_data(budget: &mut DecodedSizeBudget, ghostdag: &GhostdagData) -> Result<(), ProtocolError> {
    budget.charge(ghostdag.blue_work.len(), "GhostdagData.blueWork")?;
    if let Some(selected_parent) = &ghostdag.selected_parent {
        budget.charge(selected_parent.bytes.len(), "GhostdagData.selectedParent")?;
    }
    for (field, hashes) in
        [("GhostdagData.mergeSetBlues", &ghostdag.merge_set_blues), ("GhostdagData.mergeSetReds", &ghostdag.merge_set_reds)]
    {
        budget.repeated::<Hash>(field, hashes.len(), MAX_GHOSTDAG_MERGE_SET_ELEMENTS)?;
        for hash in hashes {
            budget.charge(hash.bytes.len(), field)?;
        }
    }
    budget.repeated::<BluesAnticoneSizes>(
        "GhostdagData.bluesAnticoneSizes",
        ghostdag.blues_anticone_sizes.len(),
        MAX_GHOSTDAG_MERGE_SET_ELEMENTS,
    )?;
    for anticone in &ghostdag.blues_anticone_sizes {
        if let Some(blue_hash) = &anticone.blue_hash {
            budget.charge(blue_hash.bytes.len(), "BluesAnticoneSizes.blueHash")?;
        }
    }
    Ok(())
}

/// Charges one `DaaBlockV4` (the trusted-header type whose 2-byte empty encoding is the worst
/// amplification in the protocol).
fn account_daa_block_v4(budget: &mut DecodedSizeBudget, entry: &DaaBlockV4) -> Result<(), ProtocolError> {
    if let Some(header) = &entry.header {
        account_block_header(budget, header)?;
    }
    if let Some(ghostdag) = &entry.ghostdag_data {
        account_ghostdag_data(budget, ghostdag)?;
    }
    Ok(())
}

/// Charges one legacy `DaaBlock` (a full `BlockMessage` plus its ghostdag data).
fn account_daa_block(budget: &mut DecodedSizeBudget, entry: &DaaBlock) -> Result<(), ProtocolError> {
    if let Some(block) = &entry.block {
        account_block(budget, block)?;
    }
    if let Some(ghostdag) = &entry.ghostdag_data {
        account_ghostdag_data(budget, ghostdag)?;
    }
    Ok(())
}

/// Charges a `repeated BlockGhostdagDataHashPair` field.
fn account_ghostdag_pairs(
    budget: &mut DecodedSizeBudget,
    field: &'static str,
    pairs: &[BlockGhostdagDataHashPair],
    cap: usize,
) -> Result<(), ProtocolError> {
    budget.repeated::<BlockGhostdagDataHashPair>(field, pairs.len(), cap)?;
    for pair in pairs {
        if let Some(hash) = &pair.hash {
            budget.charge(hash.bytes.len(), field)?;
        }
        if let Some(ghostdag) = &pair.ghostdag_data {
            account_ghostdag_data(budget, ghostdag)?;
        }
    }
    Ok(())
}

/// Charges a `PruningPointUtxoSetChunkMessage`: one `OutpointAndUtxoEntryPair` per UTXO, each owning
/// an outpoint id, a script public key and a covenant id.
fn account_utxo_pairs(budget: &mut DecodedSizeBudget, pairs: &[OutpointAndUtxoEntryPair]) -> Result<(), ProtocolError> {
    budget.repeated::<OutpointAndUtxoEntryPair>(
        "PruningPointUtxoSetChunkMessage.outpointAndUtxoEntryPairs",
        pairs.len(),
        MAX_UTXO_PAIR_ELEMENTS,
    )?;
    for pair in pairs {
        if let Some(outpoint) = &pair.outpoint
            && let Some(tx_id) = &outpoint.transaction_id
        {
            budget.charge(tx_id.bytes.len(), "Outpoint.transactionId")?;
        }
        if let Some(entry) = &pair.utxo_entry {
            if let Some(script_public_key) = &entry.script_public_key {
                budget.charge(script_public_key.script.len(), "ScriptPublicKey.script")?;
            }
            if let Some(covenant_id) = &entry.covenant_id {
                budget.charge(covenant_id.bytes.len(), "UtxoEntry.covenantId")?;
            }
        }
    }
    Ok(())
}

/// Charges an `SmtLaneChunkMessage`: one `SmtLaneEntry` per lane, each with up to
/// `SMT_CHUNK_SIZE` 64-byte lane records and a Merkle proof.
fn account_smt_entries(budget: &mut DecodedSizeBudget, entries: &[SmtLaneEntry]) -> Result<(), ProtocolError> {
    budget.repeated::<SmtLaneEntry>("SmtLaneChunkMessage.entries", entries.len(), MAX_SMT_LANE_ENTRIES)?;
    for entry in entries {
        budget.charge(entry.data.len(), "SmtLaneEntry.data")?;
        budget.charge(entry.proof.len(), "SmtLaneEntry.proof")?;
    }
    Ok(())
}

/// Walks the payload and charges every `repeated` field and every heap allocation hanging off it.
///
/// One arm per payload variant that owns a repeated field; everything else (scalar messages such as
/// `Ping`, `Pong`, `Verack`, and the single-hash messages) has nothing to amplify and is bounded by
/// the frame limit alone.
fn account_payload(budget: &mut DecodedSizeBudget, payload: &KaspadMessagePayload) -> Result<(), ProtocolError> {
    match payload {
        KaspadMessagePayload::Addresses(msg) => {
            budget.repeated::<NetAddress>("AddressesMessage.addressList", msg.address_list.len(), MAX_ADDRESS_LIST_ELEMENTS)?;
            for address in &msg.address_list {
                budget.charge(address.ip.len(), "NetAddress.ip")?;
            }
            Ok(())
        }
        KaspadMessagePayload::Block(msg) | KaspadMessagePayload::IbdBlock(msg) => account_block(budget, msg),
        KaspadMessagePayload::Transaction(msg) => account_transaction(budget, msg),
        KaspadMessagePayload::BlockLocator(msg) => {
            account_hashes(budget, "BlockLocatorMessage.hashes", &msg.hashes, MAX_HASH_VECTOR_ELEMENTS)
        }
        KaspadMessagePayload::RequestRelayBlocks(msg) => {
            account_hashes(budget, "RequestRelayBlocksMessage.hashes", &msg.hashes, MAX_HASH_VECTOR_ELEMENTS)
        }
        KaspadMessagePayload::RequestIbdBlocks(msg) => {
            account_hashes(budget, "RequestIBDBlocksMessage.hashes", &msg.hashes, MAX_HASH_VECTOR_ELEMENTS)
        }
        KaspadMessagePayload::RequestBlockBodies(msg) => {
            account_hashes(budget, "RequestBlockBodiesMessage.hashes", &msg.hashes, MAX_HASH_VECTOR_ELEMENTS)
        }
        KaspadMessagePayload::IbdBlockLocator(msg) => {
            account_hashes(budget, "IbdBlockLocatorMessage.blockLocatorHashes", &msg.block_locator_hashes, MAX_HASH_VECTOR_ELEMENTS)
        }
        KaspadMessagePayload::IbdChainBlockLocator(msg) => account_hashes(
            budget,
            "IbdChainBlockLocatorMessage.blockLocatorHashes",
            &msg.block_locator_hashes,
            MAX_HASH_VECTOR_ELEMENTS,
        ),
        KaspadMessagePayload::RequestTransactions(msg) => account_transaction_ids(budget, "RequestTransactionsMessage.ids", &msg.ids),
        KaspadMessagePayload::InvTransactions(msg) => account_transaction_ids(budget, "InvTransactionsMessage.ids", &msg.ids),
        KaspadMessagePayload::PruningPointUtxoSetChunk(msg) => account_utxo_pairs(budget, &msg.outpoint_and_utxo_entry_pairs),
        KaspadMessagePayload::BlockHeaders(msg) => {
            budget.repeated::<BlockHeader>("BlockHeadersMessage.blockHeaders", msg.block_headers.len(), MAX_HEADER_ELEMENTS)?;
            for header in &msg.block_headers {
                account_block_header(budget, header)?;
            }
            Ok(())
        }
        KaspadMessagePayload::PruningPoints(msg) => {
            budget.repeated::<BlockHeader>("PruningPointsMessage.headers", msg.headers.len(), MAX_HEADER_ELEMENTS)?;
            for header in &msg.headers {
                account_block_header(budget, header)?;
            }
            Ok(())
        }
        KaspadMessagePayload::PruningPointProof(msg) => {
            budget.repeated::<PruningPointProofHeaderArray>(
                "PruningPointProofMessage.headers",
                msg.headers.len(),
                MAX_PROOF_LEVELS,
            )?;
            for level in &msg.headers {
                budget.repeated::<BlockHeader>("PruningPointProofHeaderArray.headers", level.headers.len(), MAX_HEADER_ELEMENTS)?;
                for header in &level.headers {
                    account_block_header(budget, header)?;
                }
            }
            Ok(())
        }
        KaspadMessagePayload::PruningPointProofChunk(msg) => {
            budget.repeated::<BlockHeader>("PruningPointProofChunkMessage.chunk", msg.chunk.len(), MAX_HEADER_ELEMENTS)?;
            for header in &msg.chunk {
                account_block_header(budget, header)?;
            }
            Ok(())
        }
        KaspadMessagePayload::BlockBody(msg) => account_transactions(budget, "BlockBodyMessage.transactions", &msg.transactions),
        KaspadMessagePayload::BlockWithTrustedData(msg) => {
            if let Some(block) = &msg.block {
                account_block(budget, block)?;
            }
            budget.repeated::<DaaBlock>("BlockWithTrustedDataMessage.daaWindow", msg.daa_window.len(), MAX_TRUSTED_DATA_ELEMENTS)?;
            for entry in &msg.daa_window {
                account_daa_block(budget, entry)?;
            }
            account_ghostdag_pairs(budget, "BlockWithTrustedDataMessage.ghostdagData", &msg.ghostdag_data, MAX_TRUSTED_DATA_ELEMENTS)
        }
        KaspadMessagePayload::BlockWithTrustedDataV4(msg) => {
            if let Some(block) = &msg.block {
                account_block(budget, block)?;
            }
            budget.repeated::<u64>(
                "BlockWithTrustedDataV4Message.daaWindowIndices",
                msg.daa_window_indices.len(),
                MAX_TRUSTED_INDICES,
            )?;
            budget.repeated::<u64>(
                "BlockWithTrustedDataV4Message.ghostdagDataIndices",
                msg.ghostdag_data_indices.len(),
                MAX_TRUSTED_INDICES,
            )
        }
        KaspadMessagePayload::TrustedData(msg) => {
            budget.repeated::<DaaBlockV4>("TrustedDataMessage.daaWindow", msg.daa_window.len(), MAX_TRUSTED_DATA_ELEMENTS)?;
            for entry in &msg.daa_window {
                account_daa_block_v4(budget, entry)?;
            }
            account_ghostdag_pairs(budget, "TrustedDataMessage.ghostdagData", &msg.ghostdag_data, MAX_TRUSTED_DATA_ELEMENTS)
        }
        KaspadMessagePayload::TrustedDataChunk(msg) => {
            budget.repeated::<DaaBlockV4>("TrustedDataChunkMessage.headers", msg.headers.len(), MAX_HEADER_ELEMENTS)?;
            for entry in &msg.headers {
                account_daa_block_v4(budget, entry)?;
            }
            Ok(())
        }
        KaspadMessagePayload::SmtLaneChunk(msg) => account_smt_entries(budget, &msg.entries),
        _ => Ok(()),
    }
}

impl Router {
    /// Maximum size, in bytes, of a single P2P frame on the wire. Mirrors the transport limit
    /// (`P2P_MAX_MESSAGE_SIZE`, 10 MiB) that both the tonic server and client are built with, and is
    /// public so the adversarial decode tests can reason about the boundary.
    pub const MAX_MESSAGE_SIZE: usize = P2P_MAX_MESSAGE_SIZE;

    /// Absolute ceiling on the estimated decoded size of one inbound message (8x the frame limit,
    /// 80 MiB). A message that exceeds it cannot be the honest result of the per-field caps.
    pub const MAX_DECODED_MESSAGE_SIZE: usize = DECODED_MESSAGE_SIZE_LIMIT;

    /// Validates a freshly decoded inbound message against the decoded-size budget.
    ///
    /// This is the guard that makes `repeated`-field amplification a protocol violation instead of a
    /// memory-amplification primitive: prost has no allocation hook, so the check runs immediately
    /// after decode and rejects a message whose `repeated` fields exceed their caps or whose
    /// estimated retained size cannot be the honest result of a peer respecting them. It is public so
    /// the adversarial tests can drive the exact gate without a live connection.
    pub fn check_decoded_message_budget(msg: &KaspadMessage) -> Result<(), ProtocolError> {
        let Some(payload) = msg.payload.as_ref() else {
            return Err(ProtocolError::Other("received kaspad p2p message with empty payload"));
        };

        // Two ceilings: an absolute one so no message can ever retain more than
        // `MAX_DECODED_MESSAGE_SIZE`, and a relative one so a small frame cannot claim a large graph.
        // An honest message is bounded by the transport limit on both counts.
        let relative_limit = msg.encoded_len().saturating_mul(DECODED_SIZE_AMPLIFICATION).saturating_add(DECODED_SIZE_SLACK);
        let limit = DECODED_MESSAGE_SIZE_LIMIT.min(relative_limit);

        account_payload(&mut DecodedSizeBudget::new(limit), payload)
    }

    pub(crate) async fn new(
        net_address: SocketAddr,
        is_outbound: bool,
        hub_sender: MpscSender<HubEvent>,
        mut incoming_stream: Streaming<KaspadMessage>,
        outgoing_route: MpscSender<KaspadMessage>,
    ) -> Arc<Self> {
        let (start_sender, start_receiver) = oneshot_channel();
        let (shutdown_sender, mut shutdown_receiver) = oneshot_channel();

        let router = Arc::new(Router {
            identity: Default::default(),
            net_address,
            is_outbound,
            connection_started: Instant::now(),
            routing_map_by_type: RwLock::new(HashMap::new()),
            routing_map_by_id: RwLock::new(HashMap::new()),
            outgoing_route,
            hub_sender,
            mutable_state: Mutex::new(RouterMutableState::new(Some(start_sender), Some(shutdown_sender))),
            handshake_complete: AtomicBool::new(false),
        });

        let router_clone = router.clone();
        // Start the router receive loop
        tokio::spawn(async move {
            // Wait for a start signal before entering the receive loop
            let _ = start_receiver.await;
            loop {
                select! {
                    biased; // We use biased polling so that the shutdown signal is always checked first

                    _ = &mut shutdown_receiver => {
                        debug!("P2P, Router receive loop - shutdown signal received, exiting router receive loop, router-id: {}", router.identity());
                        break;
                    }

                    res = incoming_stream.message() => match res {
                        Ok(Some(msg)) => {
                            trace!("P2P msg: {:?}, router-id: {}, peer: {}", message_summary(&msg), router.identity(), router);
                            match router.route_to_flow(msg) {
                                Ok(()) => {},
                                Err(e) => {
                                    match e {
                                        ProtocolError::IgnorableReject(reason) => { debug!("P2P, got reject message: {} from peer: {}", reason, router); }
                                        ProtocolError::Rejected(reason) => { warn!("P2P, got reject message: {} from peer: {}", reason, router); }
                                        e => { warn!("P2P, route error: {} for peer: {}", e, router); }
                                    }
                                    break;
                                },
                            }
                        }
                        Ok(None) => {
                            info!("P2P, incoming stream ended from peer {}", router);
                            break;
                        }
                        Err(status) => {
                            if let Some(err) = match_for_io_error(&status) {
                                info!("P2P, network error: {} from peer {}", err, router);
                            } else {
                                info!("P2P, network error: {} from peer {}", status, router);
                            }
                            break;
                        }
                    }
                }
            }
            router.close().await;
            debug!("P2P, Router receive loop - exited, router-id: {}, router refs: {}", router.identity(), Arc::strong_count(&router));
        });

        router_clone
    }

    /// Internal identity of this peer
    pub fn identity(&self) -> PeerId {
        self.identity.read()
    }

    pub fn set_identity(&self, identity: PeerId) {
        *self.identity.lock_write() = identity;
    }

    /// The socket address of this peer
    pub fn net_address(&self) -> SocketAddr {
        self.net_address
    }

    pub fn key(&self) -> PeerKey {
        self.into()
    }

    /// Indicates whether this connection is an outbound connection
    pub fn is_outbound(&self) -> bool {
        self.is_outbound
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.mutable_state.lock().shutdown_signal.is_none()
    }

    pub fn connection_started(&self) -> Instant {
        self.connection_started
    }

    pub fn time_connected(&self) -> u64 {
        Instant::now().duration_since(self.connection_started).as_millis() as u64
    }

    pub fn properties(&self) -> Arc<PeerProperties> {
        self.mutable_state.lock().properties.clone()
    }

    pub fn set_properties(&self, properties: Arc<PeerProperties>) {
        self.mutable_state.lock().properties = properties;
    }

    /// Sets the duration of the last ping
    pub fn set_last_ping_duration(&self, last_ping_duration: u64) {
        self.mutable_state.lock().last_ping_duration = last_ping_duration;
    }

    pub fn last_ping_duration(&self) -> u64 {
        self.mutable_state.lock().last_ping_duration
    }

    /// Marks the connection's handshake as complete, lifting the pre-handshake message-type and
    /// size restrictions enforced by `route_to_flow`. Called by the `ConnectionInitializer` once
    /// the `Ready` messages have been exchanged.
    pub fn mark_handshake_complete(&self) {
        self.handshake_complete.store(true, Ordering::SeqCst);
    }

    pub fn is_handshake_complete(&self) -> bool {
        self.handshake_complete.load(Ordering::SeqCst)
    }

    pub fn incoming_flow_baseline_channel_size() -> usize {
        256
    }

    /// Send a signal to start this router's receive loop
    pub fn start(&self) {
        // Acquire state mutex and send the start signal
        let op = self.mutable_state.lock().start_signal.take();
        if let Some(signal) = op {
            let _ = signal.send(());
        } else {
            {
                debug!("P2P, Router start was called more than once, router-id: {}", self.identity());
            }
        }
    }

    /// Subscribe to specific message types.
    ///
    /// This should be used by `ConnectionInitializer` instances to register application-specific flows
    pub fn subscribe(&self, msg_types: Vec<KaspadMessagePayloadType>) -> IncomingRoute {
        self.subscribe_with_capacity(msg_types, Self::incoming_flow_baseline_channel_size())
    }

    /// Subscribe to specific message types with a specific channel capacity.
    ///
    /// This should be used by `ConnectionInitializer` instances to register application-specific flows.
    pub fn subscribe_with_capacity(&self, msg_types: Vec<KaspadMessagePayloadType>, capacity: usize) -> IncomingRoute {
        let (sender, receiver) = mpsc_channel(capacity);
        let incoming_route = IncomingRoute::new(receiver);
        let mut map_by_type = self.routing_map_by_type.write();
        for msg_type in msg_types {
            match map_by_type.insert(msg_type, sender.clone()) {
                Some(_) => {
                    // Overrides an existing route -- panic
                    error!(
                        "P2P, Router::subscribe overrides an existing message type: {:?}, router-id: {}",
                        msg_type,
                        self.identity()
                    );
                    panic!("P2P, Tried to subscribe to an existing route");
                }
                None => {
                    trace!("P2P, Router::subscribe - msg_type: {:?} route is registered, router-id:{:?}", msg_type, self.identity());
                }
            }
        }
        let mut map_by_id = self.routing_map_by_id.write();
        match map_by_id.insert(incoming_route.id, sender.clone()) {
            Some(_) => {
                // Overrides an existing route -- panic
                error!(
                    "P2P, Router::subscribe overrides an existing route id: {:?}, router-id: {}",
                    incoming_route.id,
                    self.identity()
                );
                panic!("P2P, Tried to subscribe to an existing route");
            }
            None => {
                trace!(
                    "P2P, Router::subscribe - route id: {:?} route is registered, router-id:{:?}",
                    incoming_route.id,
                    self.identity()
                );
            }
        }
        incoming_route
    }

    /// Routes a message coming from the network to the corresponding registered flow
    pub fn route_to_flow(&self, msg: KaspadMessage) -> Result<(), ProtocolError> {
        if msg.payload.is_none() {
            debug!("P2P, Route to flow got empty payload, peer: {}", self);
            return Err(ProtocolError::Other("received kaspad p2p message with empty payload"));
        }
        // Reject amplified `repeated` fields before the message is routed. This runs before the
        // handshake gate and before `try_send`, so an over-budget message is neither cloned into a
        // flow queue nor converted into consensus types.
        Self::check_decoded_message_budget(&msg)?;

        let msg_type: KaspadMessagePayloadType = msg.payload.as_ref().expect("payload was just verified").into();

        // Fail fast on anything that is not part of the handshake protocol while the handshake is
        // still in progress. `Streaming::message` has already fully decoded the frame into a Rust
        // object graph by the time we get here, so this gate cannot un-materialize a payload that
        // tonic already decoded -- which is exactly why pre-handshake messages are additionally
        // bounded by `P2P_MAX_PRE_HANDSHAKE_MESSAGE_SIZE` below. Together these checks drop the
        // connection before any unexpected or oversized message is ever routed to a flow.
        if !self.is_handshake_complete() {
            if !is_pre_handshake_message_type(msg_type) {
                return Err(ProtocolError::MisbehavingPeer(format!(
                    "peer sent a {:?} message before completing the handshake",
                    msg_type
                )));
            }
            let encoded_len = msg.encoded_len();
            if encoded_len > P2P_MAX_PRE_HANDSHAKE_MESSAGE_SIZE {
                return Err(ProtocolError::OtherOwned(format!(
                    "pre-handshake message is {} bytes, over the limit of {} bytes",
                    encoded_len, P2P_MAX_PRE_HANDSHAKE_MESSAGE_SIZE
                )));
            }
        }

        // Handle the special case of a reject message ending the connection
        if msg_type == KaspadMessagePayloadType::Reject {
            let Some(KaspadMessagePayload::Reject(reject)) = msg.payload else { unreachable!() };
            return Err(ProtocolError::from_reject_message(reject.reason));
        }

        let op = if msg.response_id != BLANK_ROUTE_ID {
            self.routing_map_by_id.read().get(&msg.response_id).cloned()
        } else {
            self.routing_map_by_type.read().get(&msg_type).cloned()
        };

        if let Some(sender) = op {
            match sender.try_send(msg) {
                Ok(_) => Ok(()),
                Err(TrySendError::Closed(_)) => Err(ProtocolError::ConnectionClosed),
                Err(TrySendError::Full(_)) => {
                    let overflow_policy: IncomingRouteOverflowPolicy = msg_type.into();
                    match overflow_policy {
                        IncomingRouteOverflowPolicy::Drop => Ok(()),
                        IncomingRouteOverflowPolicy::Disconnect => {
                            Err(ProtocolError::IncomingRouteCapacityReached(msg_type, self.to_string()))
                        }
                    }
                }
            }
        } else {
            Err(ProtocolError::NoRouteForMessageType(msg_type))
        }
    }

    /// Enqueues a locally-originated message to be sent to the network peer
    pub async fn enqueue(&self, msg: KaspadMessage) -> Result<(), ProtocolError> {
        assert!(msg.payload.is_some(), "Kaspad P2P message should always have a value");
        match self.outgoing_route.try_send(msg) {
            Ok(_) => Ok(()),
            Err(TrySendError::Closed(_)) => Err(ProtocolError::ConnectionClosed),
            Err(TrySendError::Full(_)) => Err(ProtocolError::OutgoingRouteCapacityReached(self.to_string())),
        }
    }

    /// Based on the type of the protocol error, tries sending a reject message before shutting down the connection
    pub async fn try_sending_reject_message(&self, err: &ProtocolError) {
        if err.can_send_outgoing_message() {
            // Send an explicit reject message for easier tracing of logical bugs causing protocol errors.
            // No need to handle errors since we are closing anyway
            let _ = self.enqueue(make_message!(KaspadMessagePayload::Reject, RejectMessage { reason: err.to_reject_message() })).await;
        }
    }

    /// Closes the router, signals exit, and cleans up all resources so that underlying connections will be aborted correctly.
    /// Returns true of this is the first call to close
    pub async fn close(self: &Arc<Router>) -> bool {
        // Acquire state mutex and send the shutdown signal
        // NOTE: Using a block to drop the lock asap
        {
            let mut state = self.mutable_state.lock();

            // Make sure start signal was fired, just in case `self.start()` was never called
            if let Some(signal) = state.start_signal.take() {
                let _ = signal.send(());
            }

            if let Some(signal) = state.shutdown_signal.take() {
                let _ = signal.send(());
            } else {
                // This means the router was already closed
                trace!("P2P, Router close was called more than once, router-id: {}", self.identity());
                return false;
            }
        }

        // Drop all flow senders
        self.routing_map_by_type.write().clear();
        self.routing_map_by_id.write().clear();

        // Send a close notification to the central Hub
        self.hub_sender.send(HubEvent::PeerClosing(self.clone())).await.expect("hub receiver should never drop before senders");

        true
    }
}

fn match_for_io_error(err_status: &tonic::Status) -> Option<&std::io::Error> {
    let mut err: &(dyn std::error::Error + 'static) = err_status;

    loop {
        if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
            return Some(io_err);
        }

        // h2::Error do not expose std::io::Error with `source()`
        // https://github.com/hyperium/h2/pull/462
        if let Some(h2_err) = err.downcast_ref::<h2::Error>()
            && let Some(io_err) = h2_err.get_io()
        {
            return Some(io_err);
        }

        err = err.source()?;
    }
}

// -------------------------------------------------------------------------------------------------
// Zethora: preflight codec (pre-allocation protobuf boundary)
// -------------------------------------------------------------------------------------------------
//
// `Router::check_decoded_message_budget` (above) bounds what a decoded message *retains and routes*,
// but it runs after prost has already materialized the whole object graph. A ~10.4 MiB frame of
// empty `TrustedDataChunkMessage.headers`/`BlockHeadersMessage.blockHeaders` elements still costs
// ~1.6 GiB for the duration of the decode, because prost exposes no knob for capping a `repeated`
// field while it decodes. This codec closes that hole at the source: it scans the raw protobuf
// frame *before* `KaspadMessage::decode` and rejects any frame carrying an amplifier-shaped
// payload, so prost never allocates the graph in the first place.
//
// The scan is a narrow, best-effort wire-format walk rather than a second decoder: if the bytes do
// not parse cleanly it simply falls through to prost, which remains the authoritative validator.
// It only needs to catch the well-formed empty-element amplification, which is exactly the shape
// that parses cleanly.

/// `KaspadMessage` oneof field carrying `TrustedDataChunkMessage` (`trustedDataChunk = 66`).
const KASPAD_MESSAGE_TRUSTED_DATA_CHUNK_FIELD: u64 = 66;

/// `KaspadMessage` oneof field carrying `BlockHeadersMessage` (`blockHeaders = 41`).
const KASPAD_MESSAGE_BLOCK_HEADERS_FIELD: u64 = 41;

/// Protobuf wire type 2 (length-delimited), the only wire type the scanned fields use.
const WIRE_TYPE_LENGTH_DELIMITED: u8 = 2;

/// A [`tonic::codec::Codec`] that runs a preflight scan on every inbound frame before prost decodes
/// it into a [`KaspadMessage`]. It delegates encoding and decoding to the default
/// [`tonic_prost::ProstCodec`] once the scan passes.
#[derive(Debug, Clone, Default)]
pub struct PreflightCodec {
    inner: ProstCodec<KaspadMessage, KaspadMessage>,
}

impl Codec for PreflightCodec {
    type Encode = KaspadMessage;
    type Decode = KaspadMessage;

    type Encoder = ProstEncoder<KaspadMessage>;
    type Decoder = PreflightDecoder;

    fn encoder(&mut self) -> Self::Encoder {
        self.inner.encoder()
    }

    fn decoder(&mut self) -> Self::Decoder {
        PreflightDecoder { inner: self.inner.decoder() }
    }
}

/// The decode half of [`PreflightCodec`]: scans the raw frame, then delegates to prost.
#[derive(Debug, Clone, Default)]
pub struct PreflightDecoder {
    inner: ProstDecoder<KaspadMessage>,
}

impl Decoder for PreflightDecoder {
    type Item = KaspadMessage;
    type Error = Status;

    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<Self::Item>, Self::Error> {
        // The buffer holds exactly one full gRPC message. Inbound gzip is disabled at the server,
        // so the on-wire length is the decoded length and `chunk()` is the whole protobuf frame.
        if src.remaining() > P2P_MAX_MESSAGE_SIZE {
            return Err(Status::resource_exhausted(format!(
                "P2P message is {} bytes, over the limit of {} bytes",
                src.remaining(),
                P2P_MAX_MESSAGE_SIZE
            )));
        }
        preflight_scan(src.chunk())?;
        self.inner.decode(src)
    }

    fn buffer_settings(&self) -> BufferSettings {
        self.inner.buffer_settings()
    }
}

/// Scans a raw `KaspadMessage` frame for amplifier-shaped payloads before prost decodes it.
fn preflight_scan(buf: &[u8]) -> Result<(), Status> {
    #[allow(clippy::arithmetic_side_effects, reason = "positions are bounds-checked against buf.len() before every advance")]
    {
        let mut pos = 0usize;
        while pos < buf.len() {
            let Some(tag) = read_varint(buf, &mut pos) else {
                // Malformed frame, not an amplifier: let prost reject it authoritatively.
                return Ok(());
            };
            let field_number = tag >> 3;
            let wire_type = (tag & 0x07) as u8;
            if wire_type == WIRE_TYPE_LENGTH_DELIMITED
                && (field_number == KASPAD_MESSAGE_TRUSTED_DATA_CHUNK_FIELD
                    || field_number == KASPAD_MESSAGE_BLOCK_HEADERS_FIELD)
            {
                let Some(len) = read_varint(buf, &mut pos) else {
                    return Ok(());
                };
                let Ok(len) = usize::try_from(len) else {
                    return Ok(());
                };
                let Some(payload) = buf.get(pos..pos.saturating_add(len)) else {
                    return Ok(());
                };
                count_nested_header_elements(payload)?;
                pos += len;
            } else if !skip_field(buf, &mut pos, wire_type) {
                return Ok(());
            }
        }
    }
    Ok(())
}

/// Counts the `repeated` elements of a `TrustedDataChunkMessage`/`BlockHeadersMessage` payload.
/// Both vectors are declared as field 1 (length-delimited), so every top-level `0x0A` tag is one
/// element. `MAX_HEADER_ELEMENTS` is the same cap the router applies to exactly these fields, so
/// this can never reject a frame `route_to_flow` would have accepted.
fn count_nested_header_elements(payload: &[u8]) -> Result<(), Status> {
    #[allow(clippy::arithmetic_side_effects, reason = "positions are bounds-checked against payload.len() before every advance")]
    {
        let mut pos = 0usize;
        let mut count = 0usize;
        while pos < payload.len() {
            let Some(tag) = read_varint(payload, &mut pos) else {
                return Ok(());
            };
            let field_number = tag >> 3;
            let wire_type = (tag & 0x07) as u8;
            if field_number == 1 && wire_type == WIRE_TYPE_LENGTH_DELIMITED {
                count += 1;
                if count > MAX_HEADER_ELEMENTS {
                    return Err(Status::resource_exhausted(format!(
                        "P2P message carries more than {MAX_HEADER_ELEMENTS} nested header/trusted-data elements"
                    )));
                }
            }
            if !skip_field(payload, &mut pos, wire_type) {
                return Ok(());
            }
        }
    }
    Ok(())
}

/// Advances past one protobuf field of `wire_type` at `*pos`. Returns `false` on a malformed or
/// truncated field, which the caller treats as "fall through to prost".
fn skip_field(buf: &[u8], pos: &mut usize, wire_type: u8) -> bool {
    #[allow(clippy::arithmetic_side_effects, reason = "advances are bounds-checked against buf.len()")]
    {
        let amount = match wire_type {
            0 => return read_varint(buf, pos).is_some(),
            1 => 8,
            2 => {
                let Some(len) = read_varint(buf, pos) else { return false };
                let Ok(len) = usize::try_from(len) else { return false };
                len
            }
            5 => 4,
            _ => return false,
        };
        match pos.checked_add(amount) {
            Some(next) if next <= buf.len() => {
                *pos = next;
                true
            }
            _ => false,
        }
    }
}

/// Reads one base-128 protobuf varint from `buf` at `*pos`, advancing `*pos` past it. Returns
/// `None` on truncation or on a varint that does not fit in 64 bits.
fn read_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    #[allow(clippy::arithmetic_side_effects, reason = "shifts are bounded by checked_shl and the position advance is bounds-checked by buf.get")]
    {
        let mut value: u64 = 0;
        let mut shift: u32 = 0;
        loop {
            let byte = *buf.get(*pos)?;
            *pos += 1;
            value |= u64::from(byte & 0x7f).checked_shl(shift)?;
            if byte & 0x80 == 0 {
                return Some(value);
            }
            shift += 7;
        }
    }
}
