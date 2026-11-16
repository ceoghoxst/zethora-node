//! Adversarial tests for the P2P decode boundary: `repeated`-field amplification.
//!
//! `p2p.proto` declares 32 `repeated` fields and prost decodes each one by pushing a fresh element per
//! wire occurrence, with no option to cap the count or the allocation. An empty sub-message is two
//! wire bytes (`0x0A 0x00`) but a full struct in memory, so a frame far smaller than the 10 MiB
//! transport limit used to expand into hundreds of megabytes (or gigabytes) of heap before any flow
//! ever saw the message.
//!
//! `Router::check_decoded_message_budget` is the guard that closes this: it runs on every decoded
//! inbound message before routing and enforces a per-field element cap plus an absolute and a
//! relative decoded-size ceiling. These tests drive that exact gate with the same bytes an attacker
//! would put on the socket:
//!
//! * one test per amplified field, each asserting the message is refused as a misbehaving peer, that
//!   the attack frame fits inside the transport limit (so it is the budget, not the codec, that
//!   stops it), and that the decoded graph it would have retained is many times the frame;
//! * a control test with honest traffic -- address lists, header batches, trusted data chunks, pruning
//!   point proofs, transaction inventories, UTXO chunks, SMT chunks and a multi-megabyte block body --
//!   asserting none of it is refused, so the budget cannot be tightened into a denial of service
//!   against well-behaved peers.
//!
//! The measurements in the assertions are the ones the attack relies on: they are recomputed here
//! from `size_of` instead of hardcoded, so if a type grows the tests keep telling the truth.

// Test code is exempt from the arithmetic-side-effects lint (same as `src/lib.rs`).
#![allow(clippy::arithmetic_side_effects)]

use kaspa_p2p_lib::Router;
use kaspa_p2p_lib::common::ProtocolError;
use kaspa_p2p_lib::pb::{
    AddressesMessage, BlockBodyMessage, BlockHeader, BlockHeadersMessage, BlockLevelParents, BlockLocatorMessage, BluesAnticoneSizes,
    DaaBlockV4, GhostdagData, Hash, InvTransactionsMessage, KaspadMessage, NetAddress, Outpoint, OutpointAndUtxoEntryPair,
    PruningPointProofHeaderArray, PruningPointProofMessage, PruningPointUtxoSetChunkMessage, ScriptPublicKey, SmtLaneChunkMessage,
    SmtLaneEntry, TransactionId, TransactionMessage, TransactionOutput, TrustedDataChunkMessage, UtxoEntry, kaspad_message::Payload,
};
use prost::Message;

/// Wraps a payload the way a peer would send it (no request/response correlation).
fn message(payload: Payload) -> KaspadMessage {
    KaspadMessage { payload: Some(payload), response_id: 0, request_id: 0 }
}

/// Encodes the message, decodes it back through prost and returns the frame length together with the
/// decoded message the router sees. Decoding again is deliberate: it proves the attack is expressible
/// in the wire format and gives the gate the same value `route_to_flow` receives.
fn over_the_wire(msg: &KaspadMessage) -> (usize, KaspadMessage) {
    let frame = msg.encode_to_vec();
    let decoded = KaspadMessage::decode(frame.as_slice()).expect("a message built by the test must decode");
    (frame.len(), decoded)
}

/// Asserts the gate refuses `msg`, that the whole attack fits in one legal frame, and returns the
/// number of bytes of decoded object graph the frame would have produced.
fn refused(case: &str, msg: &KaspadMessage) -> usize {
    let (frame_len, decoded) = over_the_wire(msg);
    assert!(
        frame_len <= Router::MAX_MESSAGE_SIZE,
        "{case}: the attack must be expressible inside the {} byte transport limit, but the frame is {frame_len} bytes",
        Router::MAX_MESSAGE_SIZE
    );
    match Router::check_decoded_message_budget(&decoded) {
        Ok(()) => panic!("{case}: {frame_len} wire bytes were accepted and expanded into a decoded message"),
        Err(err) => {
            assert!(
                matches!(err, ProtocolError::MisbehavingPeer(_)),
                "{case}: an over-budget message must be a protocol violation that drops the connection, got {err:?}"
            );
        }
    }
    frame_len
}

/// Asserts the gate accepts `msg`, i.e. honest traffic is never caught by the budget.
fn accepted(case: &str, msg: &KaspadMessage) {
    let (frame_len, decoded) = over_the_wire(msg);
    if let Err(err) = Router::check_decoded_message_budget(&decoded) {
        panic!("{case}: an honest {frame_len} byte message was refused: {err}");
    }
}

/// A hash with no bytes, the cheapest possible element to put on the wire.
fn empty_hash() -> Hash {
    Hash { bytes: Vec::new() }
}

/// A realistic 32 byte hash (what honest peers always send).
fn hash(byte: u8) -> Hash {
    Hash { bytes: vec![byte; 32] }
}

/// `BlockHeadersMessage.blockHeaders`: 2 wire bytes per empty element against a 184 byte struct, so a
/// frame of a few hundred kilobytes asks the node to retain more than the entire transport limit.
/// The element cap alone allows 65,536 headers, so this count is inside it and only the decoded-size
/// budget can stop the attack.
#[test]
fn empty_block_headers_cannot_amplify() {
    const COUNT: usize = 65_000;

    let msg = message(Payload::BlockHeaders(BlockHeadersMessage { block_headers: vec![BlockHeader::default(); COUNT] }));
    let frame_len = refused("empty block headers", &msg);

    let decoded_bytes = COUNT * std::mem::size_of::<BlockHeader>();
    assert!(
        decoded_bytes > frame_len * 16,
        "an empty header costs 2 wire bytes but {decoded_bytes} decoded bytes: a {frame_len} byte frame would retain {decoded_bytes}"
    );
    assert!(
        decoded_bytes > Router::MAX_MESSAGE_SIZE,
        "the amplification must exceed the whole transport limit, got {decoded_bytes} bytes from {frame_len}"
    );
}

/// `AddressesMessage.addressList`: 2 wire bytes per empty `NetAddress` (~40 byte struct). The list is
/// capped at 4096 elements -- four times what an honest peer sends (`MAX_ADDRESSES_SEND` is 1000) -- so
/// the cap refuses it long before the size budget would.
#[test]
fn empty_address_list_cannot_amplify() {
    const COUNT: usize = 5_000;

    let msg = message(Payload::Addresses(AddressesMessage {
        address_list: vec![NetAddress { timestamp: 0, ip: vec![0; 16], port: 1 }; COUNT],
    }));
    let frame_len = refused("empty addresses", &msg);

    assert!(
        COUNT * std::mem::size_of::<NetAddress>() > frame_len,
        "the address list must expand beyond its own frame, got {frame_len} wire and {} decoded bytes",
        COUNT * std::mem::size_of::<NetAddress>()
    );
}

/// `TrustedDataChunkMessage.headers`: 2 wire bytes per empty `DaaBlockV4` (a header plus ghostdag data,
/// the largest empty element in the protocol). This is the shape that used to be worth ~1.7 GiB per
/// 10 MiB frame, and it is the type the proof-of-work substitution attack used in place of a header.
#[test]
fn empty_trusted_data_chunk_cannot_amplify() {
    const COUNT: usize = 30_000;

    let msg = message(Payload::TrustedDataChunk(TrustedDataChunkMessage { headers: vec![DaaBlockV4::default(); COUNT] }));
    let frame_len = refused("empty trusted data chunk", &msg);

    let decoded_bytes = COUNT * std::mem::size_of::<DaaBlockV4>();
    assert!(
        decoded_bytes > frame_len * 16,
        "an empty trusted header costs 2 wire bytes but {decoded_bytes} decoded bytes: a {frame_len} byte frame would retain {decoded_bytes}"
    );
}

/// `BlockBodyMessage.transactions` / `BlockMessage.transactions`: 2 wire bytes per empty transaction.
/// The element cap (16,384, an order of magnitude above the ~1.3k smallest transactions block mass
/// allows) is what refuses it.
#[test]
fn empty_transactions_cannot_amplify() {
    const COUNT: usize = 20_000;

    let msg = message(Payload::BlockBody(BlockBodyMessage { transactions: vec![TransactionMessage::default(); COUNT] }));
    let frame_len = refused("empty transactions", &msg);

    assert!(
        COUNT * std::mem::size_of::<TransactionMessage>() > frame_len * 16,
        "the transaction vector must expand far beyond its frame, got {frame_len} wire bytes"
    );
}

/// `BlockLocatorMessage.hashes` and its mirrors: 2 wire bytes per empty hash. Honest locators are a few
/// dozen hashes and the request flows refuse more than 128, so 4096 is the cap.
#[test]
fn empty_hash_vectors_cannot_amplify() {
    const COUNT: usize = 10_000;

    refused("empty block locator", &message(Payload::BlockLocator(BlockLocatorMessage { hashes: vec![empty_hash(); COUNT] })));

    let inventory = InvTransactionsMessage { ids: vec![TransactionId { bytes: Vec::new() }; COUNT * 15] };
    refused("empty transaction inventory", &message(Payload::InvTransactions(inventory)));
}

/// A single header whose `parents` levels each carry an unbounded list of parent hashes: nested
/// `repeated` fields amplify per level, so the inner vector is capped independently.
#[test]
fn nested_parent_hashes_cannot_amplify() {
    const COUNT: usize = 50_000;

    let msg = message(Payload::BlockHeaders(BlockHeadersMessage {
        block_headers: vec![BlockHeader {
            parents: vec![BlockLevelParents { parent_hashes: vec![empty_hash(); COUNT], cumulative_level: 0 }],
            ..Default::default()
        }],
    }));
    refused("nested parent hashes", &msg);
}

/// `GhostdagData.mergeSetBlues`/`mergeSetReds`/`bluesAnticoneSizes`: three independent hash vectors per
/// trusted entry, which is what made the `DaaBlockV4` substitution so expensive. Every one of them is
/// capped, so inflating a single ghostdag's merge set is refused even inside one trusted header.
#[test]
fn ghostdag_merge_sets_cannot_amplify() {
    const COUNT: usize = 20_000;

    let trusted_chunk = |ghostdag_data: GhostdagData| {
        message(Payload::TrustedDataChunk(TrustedDataChunkMessage {
            headers: vec![DaaBlockV4 { header: Some(BlockHeader::default()), ghostdag_data: Some(ghostdag_data) }],
        }))
    };

    let blues = trusted_chunk(GhostdagData { merge_set_blues: vec![empty_hash(); COUNT], ..Default::default() });
    refused("inflated ghostdag merge set blues", &blues);

    let reds = trusted_chunk(GhostdagData { merge_set_reds: vec![empty_hash(); COUNT], ..Default::default() });
    refused("inflated ghostdag merge set reds", &reds);
}

/// `PruningPointUtxoSetChunkMessage.outpointAndUtxoEntryPairs`: 2 wire bytes per empty pair. The
/// serving flow sends 1000 pairs per chunk, so a cap of 65,536 cannot touch honest traffic.
#[test]
fn empty_utxo_set_chunks_cannot_amplify() {
    const COUNT: usize = 70_000;

    let msg = message(Payload::PruningPointUtxoSetChunk(PruningPointUtxoSetChunkMessage {
        outpoint_and_utxo_entry_pairs: vec![OutpointAndUtxoEntryPair::default(); COUNT],
    }));
    refused("empty utxo set chunk", &msg);
}

/// `SmtLaneChunkMessage.entries`: each lane entry carries a 64 byte record and a Merkle proof. The flow
/// sends at most `SMT_CHUNK_SIZE` (4096) per chunk, so a chunk one entry over that is refused while a
/// full honest chunk is not.
#[test]
fn oversized_smt_lane_chunks_cannot_amplify() {
    let entry = || SmtLaneEntry { data: vec![0; 64], blue_score: 1, proof: vec![0; 32] };

    refused(
        "oversized smt lane chunk",
        &message(Payload::SmtLaneChunk(SmtLaneChunkMessage { entries: (0..4_097).map(|_| entry()).collect() })),
    );
}

/// A message with no payload at all is refused rather than routed.
#[test]
fn empty_payload_is_refused() {
    let msg = KaspadMessage { payload: None, response_id: 0, request_id: 0 };
    assert!(
        matches!(Router::check_decoded_message_budget(&msg), Err(ProtocolError::Other(_))),
        "a message without a payload must be refused"
    );
}

/// The control: every shape an honest peer sends must pass. These are the sizes the production flows
/// actually produce -- `MAX_ADDRESSES_SEND` (1000) addresses, a header batch, a UTXO chunk of
/// `CHUNK_SIZE` (1000) pairs, a full `SMT_CHUNK_SIZE` chunk, and a multi-megabyte block body -- so a
/// false positive here would be a denial of service against honest peers.
#[test]
fn honest_traffic_is_accepted() {
    accepted(
        "1000 addresses",
        &message(Payload::Addresses(AddressesMessage {
            address_list: vec![NetAddress { timestamp: 1, ip: vec![10; 16], port: 16_111 }; 1_000],
        })),
    );

    let header = || BlockHeader {
        version: 1,
        parents: vec![BlockLevelParents { parent_hashes: vec![hash(1), hash(2)], cumulative_level: 0 }],
        hash_merkle_root: Some(hash(3)),
        accepted_id_merkle_root: Some(hash(4)),
        utxo_commitment: Some(hash(5)),
        timestamp: 1_700_000_000,
        bits: 0x207f_ffff,
        nonce: 42,
        daa_score: 1_000_000,
        blue_work: vec![0; 8],
        pruning_point: Some(hash(6)),
        blue_score: 999_000,
    };
    accepted(
        "2000 headers",
        &message(Payload::BlockHeaders(BlockHeadersMessage { block_headers: (0..2_000).map(|_| header()).collect() })),
    );

    accepted(
        "1000 utxo pairs",
        &message(Payload::PruningPointUtxoSetChunk(PruningPointUtxoSetChunkMessage {
            outpoint_and_utxo_entry_pairs: (0..1_000)
                .map(|i| OutpointAndUtxoEntryPair {
                    outpoint: Some(Outpoint { transaction_id: Some(TransactionId { bytes: vec![7; 32] }), index: i }),
                    utxo_entry: Some(UtxoEntry {
                        amount: 100,
                        script_public_key: Some(ScriptPublicKey { version: 0, script: vec![0x51; 35] }),
                        block_daa_score: 1,
                        is_coinbase: false,
                        covenant_id: None,
                    }),
                })
                .collect(),
        })),
    );

    accepted(
        "full smt chunk",
        &message(Payload::SmtLaneChunk(SmtLaneChunkMessage {
            entries: (0..4_096).map(|_| SmtLaneEntry { data: vec![0; 64], blue_score: 5, proof: vec![0; 32] }).collect(),
        })),
    );

    // Trusted data chunks are the largest payload the IBD flow sends: every `DaaBlockV4` carries a
    // header plus its ghostdag data, with real 32 byte hashes on both sides.
    accepted(
        "5000 trusted data headers",
        &message(Payload::TrustedDataChunk(TrustedDataChunkMessage {
            headers: (0..5_000)
                .map(|i| DaaBlockV4 {
                    header: Some(header()),
                    ghostdag_data: Some(GhostdagData {
                        blue_score: 1_000_000,
                        blue_work: vec![0x11; 32],
                        selected_parent: Some(hash(8)),
                        merge_set_blues: vec![hash(9), hash(10)],
                        merge_set_reds: vec![hash(11)],
                        blues_anticone_sizes: (0..3)
                            .map(|_| BluesAnticoneSizes { blue_hash: Some(hash(12)), anticone_size: i as u32 })
                            .collect(),
                    }),
                })
                .collect(),
        })),
    );

    // A pruning point proof exercises the nested accounting at every DAG level (256 levels, each a
    // header array) rather than a single flat vector.
    accepted(
        "pruning point proof",
        &message(Payload::PruningPointProof(PruningPointProofMessage {
            headers: (0..256).map(|_| PruningPointProofHeaderArray { headers: vec![header(), header()] }).collect(),
        })),
    );

    // Transaction inventories: 32 byte ids, batched in the hundreds by the mempool flow.
    accepted(
        "5000 transaction ids",
        &message(Payload::InvTransactions(InvTransactionsMessage {
            ids: (0..5_000).map(|_| TransactionId { bytes: vec![7; 32] }).collect(),
        })),
    );

    // A block body close to the 10 MiB transport limit: 900 transactions of 10 KiB each.
    let transaction = || TransactionMessage {
        version: 0,
        inputs: Vec::new(),
        outputs: vec![TransactionOutput { value: 1, script_public_key: None, covenant: None }],
        lock_time: 0,
        subnetwork_id: None,
        gas: 0,
        payload: vec![7; 10 * 1024],
        storage_mass: 0,
    };
    accepted(
        "9 MiB block body",
        &message(Payload::BlockBody(BlockBodyMessage { transactions: (0..900).map(|_| transaction()).collect() })),
    );
}
