use crate::{
    block::Block,
    header::{CompressedParents, Header},
    subnets::SUBNETWORK_ID_COINBASE,
    tx::Transaction,
};
use kaspa_hashes::{Hash, ZERO_HASH};
use kaspa_muhash::EMPTY_MUHASH;

/// The constants uniquely representing the genesis block
#[derive(Clone, Debug)]
pub struct GenesisBlock {
    pub hash: Hash,
    pub version: u16,
    pub hash_merkle_root: Hash,
    pub utxo_commitment: Hash,
    pub timestamp: u64,
    pub bits: u32,
    pub nonce: u64,
    pub daa_score: u64,
    pub coinbase_payload: &'static [u8],
}

impl GenesisBlock {
    pub fn build_genesis_transactions(&self) -> Vec<Transaction> {
        vec![Transaction::new(0, Vec::new(), Vec::new(), 0, SUBNETWORK_ID_COINBASE, 0, self.coinbase_payload.to_vec())]
    }
}

impl From<&GenesisBlock> for Header {
    fn from(genesis: &GenesisBlock) -> Self {
        Header::new_finalized(
            genesis.version,
            CompressedParents::default(),
            genesis.hash_merkle_root,
            ZERO_HASH,
            genesis.utxo_commitment,
            genesis.timestamp,
            genesis.bits,
            genesis.nonce,
            genesis.daa_score,
            0.into(),
            0,
            ZERO_HASH,
        )
    }
}

impl From<&GenesisBlock> for Block {
    fn from(genesis: &GenesisBlock) -> Self {
        Block::new(genesis.into(), genesis.build_genesis_transactions())
    }
}

impl From<(&Header, &'static [u8])> for GenesisBlock {
    fn from((header, payload): (&Header, &'static [u8])) -> Self {
        Self {
            hash: header.hash,
            version: header.version,
            hash_merkle_root: header.hash_merkle_root,
            utxo_commitment: header.utxo_commitment,
            timestamp: header.timestamp,
            bits: header.bits,
            nonce: header.nonce,
            daa_score: header.daa_score,
            coinbase_payload: payload,
        }
    }
}

/// Zethora: the genesis timestamp of the mainnet and testnet genesis blocks (Nov 4, 2026 GMT). It is unique to Zethora
/// (Kaspa's mainnet genesis timestamp was `0x1a100cdff60`), so the genesis hash can never match another network's.
pub const ZETHORA_GENESIS_TIMESTAMP: u64 = 1700000000000;

/// Zethora: the message committed to by the mainnet and testnet genesis coinbase transactions, so the genesis hash is
/// unique to Zethora. It is appended to the payload as plain UTF-8 extra data, after the miner script; the payload
/// reader treats everything past the script as extra data (`CoinbaseManager::deserialize_coinbase_payload`).
pub const ZETHORA_GENESIS_MESSAGE: &str = "Zethora: Private Execution Layer for Proof-of-Work";

/// Zethora: the genesis message as one script push: `OP_PUSHDATA1` (`0x4c`), the length (`0x32` = 50), then the message
/// itself, e.g. `4c325a6574686f72613a20...`. Testnet and mainnet append this after their miner script, so the message
/// is both visible in the genesis coinbase and committed to by the genesis hash.
const ZETHORA_GENESIS_MESSAGE_PUSH: &[u8] = concat!(
    "\x4c\x32",                                  // OP_PUSHDATA1, 50 bytes
    "Zethora: ",                                 // 5a 65 74 68 6f 72 61 3a 20
    "Private ",                                  // 50 72 69 76 61 74 65 20
    "Execution ",                                // 45 78 65 63 75 74 69 6f 6e 20
    "Layer ",                                    // 4c 61 79 65 72 20
    "for ",                                      // 66 6f 72 20
    "Proof-of-Work",                             // 50 72 6f 6f, 0x2d, 0x6f, 0x66, 0x2d, 0x57, 0x6f, 0x72, 0x6b
)
.as_bytes();

/// Zethora: a genesis payload's fixed prefix together with [`ZETHORA_GENESIS_MESSAGE_PUSH`], so the committed message
/// cannot drift out of the payloads. The message is appended, not written inline, because only the tail of these
/// payloads is the commitment (the prefix is the blue score, the balances and the miner script).
macro_rules! genesis_payload {
    ($prefix:expr) => {{
        const PREFIX: &[u8] = $prefix;
        const PAYLOAD: [u8; PREFIX.len() + ZETHORA_GENESIS_MESSAGE_PUSH.len()] = {
            let mut out = [0u8; PREFIX.len() + ZETHORA_GENESIS_MESSAGE_PUSH.len()];
            let mut i = 0;
            while i < PREFIX.len() {
                out[i] = PREFIX[i];
                i += 1;
            }
            let mut j = 0;
            while j < ZETHORA_GENESIS_MESSAGE_PUSH.len() {
                out[i + j] = ZETHORA_GENESIS_MESSAGE_PUSH[j];
                j += 1;
            }
            out
        };
        &PAYLOAD
    }};
}

/// Zethora: the genesis message as a hex string, for tooling and explorers that want to look for it on chain.
pub fn genesis_message_hex() -> String {
    ZETHORA_GENESIS_MESSAGE.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

/// The genesis block of the block-DAG which serves as the public transaction ledger for the main network.
pub const GENESIS: GenesisBlock = GenesisBlock {
    hash: Hash::from_bytes([
        0x63, 0x08, 0xd0, 0x01, 0x88, 0x2f, 0xf6, 0xb3, 0x16, 0x5f, 0x3e, 0x55, 0x33, 0x8f, 0x04, 0xfc, 0xed, 0x4f, 0x8f, 0x06, 0x1f, 0x7b, 0x49, 0x75, 0xf1, 0x2a, 0xa5, 0x26, 0x80, 0x0b, 0x45, 0xc5]),
    version: 0,
    hash_merkle_root: Hash::from_bytes([
        0x20, 0x27, 0x43, 0xce, 0xee, 0x30, 0xac, 0x23, 0x97, 0x94, 0xd9, 0xb6, 0x57, 0x54, 0xbf, 0x21, 0x2a, 0x8b, 0xf1, 0x13, 0x15,
        0x3b, 0x33, 0xd8, 0x87, 0x77, 0x3f, 0x92, 0x7a, 0x6a, 0x93, 0xe6,
    ]),
    utxo_commitment: EMPTY_MUHASH,
    timestamp: ZETHORA_GENESIS_TIMESTAMP,
    bits: 0x1f20c49b,
    nonce: 0,
    daa_score: 0,
    #[rustfmt::skip]
    coinbase_payload: genesis_payload!(&[
        // Blue score, balances and miner script; ZETHORA_GENESIS_MESSAGE_PUSH is appended by the macro.
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Blue score
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Subsidy: 0 (fair launch)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Zethora: pool balance 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Zethora: total burned 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Zethora: total issued 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Zethora: transparent supply 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Zethora: shielded balance 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Zethora: private coin list root
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Zethora: private state fingerprint
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, // Script version
        0x01,       // Varint
        0x00,       // OP-FALSE
        0x7a, 0x65, 0x74, 0x68, 0x6f, 0x72, 0x61, 0x2d, 0x6d, 0x61, 0x69, 0x6e, 0x6e, 0x65, 0x74, // zethora-mainnet
        0x20, 0x7c, 0x20, 0x57, 0x61, 0x6b, 0x65, 0x20, 0x55, 0x70, 0x20, 0x46, 0x72, 0x6f, 0x6d, 0x20, 0x54, 0x68, 0x65, 0x20, 0x44, 0x72, 0x65, 0x61, 0x6d, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, // | Wake Up From The Dream World
    ]),
};

pub const TESTNET_GENESIS: GenesisBlock = GenesisBlock {
    hash: Hash::from_bytes([
        0x9f, 0xc8, 0x0f, 0x5c, 0xcd, 0x0f, 0x33, 0x3e, 0xb5, 0xae, 0x90, 0xee, 0x68, 0xc6, 0x68, 0x0a, 0x44, 0x60, 0x97, 0xfa, 0xb5, 0xac, 0x4b, 0x93, 0x66, 0x56, 0x18, 0x64, 0x2f, 0xf7, 0xf1, 0x7b]),
    version: 0,
    hash_merkle_root: Hash::from_bytes([
        0x8d, 0x49, 0x0e, 0x71, 0xe6, 0x18, 0xed, 0xad, 0x58, 0x8a, 0xb0, 0x9d, 0x46, 0x85, 0x02, 0x7d, 0x9b, 0x90, 0x4e, 0xe9, 0xed, 0x6b, 0xf0, 0xa0, 0x4a, 0x6f, 0x23, 0xab, 0x24, 0xb3, 0xdd, 0x01]),
    utxo_commitment: EMPTY_MUHASH,
    timestamp: ZETHORA_GENESIS_TIMESTAMP,
    bits: 0x1f20c49b,
    nonce: 0,
    daa_score: 0,
    #[rustfmt::skip]
    coinbase_payload: genesis_payload!(&[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Blue score
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Subsidy: 0 (fair launch)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Zethora: pool balance 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Zethora: total burned 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Zethora: total issued 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Zethora: transparent supply 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Zethora: shielded balance 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Zethora: private coin list root
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Zethora: private state fingerprint
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, // Script version
        0x01,       // Varint
        0x00,       // OP-FALSE
        0x7a, 0x65, 0x74, 0x68, 0x6f, 0x72, 0x61, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x6e, 0x65, 0x74, // zethora-testnet
        0x20, 0x7c, 0x20, 0x57, 0x61, 0x6b, 0x65, 0x20, 0x55, 0x70, 0x20, 0x46, 0x72, 0x6f, 0x6d, 0x20, 0x54, 0x68, 0x65, 0x20, 0x44, 0x72, 0x65, 0x61, 0x6d, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, // | Wake Up From The Dream World
    ]),
};

/// Zethora private development network (prototype). 0 coins at genesis (ZTH-SPEC-001 Â§6).
/// The real mainnet genesis is created at launch and also commits to the latest Bitcoin block hash.
pub const SIMNET_GENESIS: GenesisBlock = GenesisBlock {
    hash: Hash::from_bytes([
        0x8e, 0x4a, 0x39, 0x76, 0x9b, 0x5e, 0x17, 0xd8, 0x09, 0xdf, 0xec, 0xa6, 0x86, 0x86, 0x6a, 0x93, 0x90, 0x5f, 0xed, 0x4a, 0xb4,
        0xb2, 0xef, 0x2b, 0x3e, 0xc1, 0x8e, 0x15, 0x6e, 0xc5, 0xaa, 0x42,
    ]),
    version: 0,
    hash_merkle_root: Hash::from_bytes([
        0x76, 0xa0, 0x64, 0x70, 0x9a, 0x73, 0x19, 0xf7, 0x4a, 0x1d, 0xce, 0xc6, 0x70, 0xef, 0x91, 0x82, 0x56, 0x2f, 0x47, 0x54, 0x0a,
        0x53, 0xfb, 0x15, 0xe0, 0x29, 0x52, 0x8a, 0xf9, 0x1c, 0x88, 0x4a,
    ]),
    utxo_commitment: EMPTY_MUHASH,
    timestamp: 0x17c5f62fbb6,
    bits: 0x207fffff,
    nonce: 0x2,
    daa_score: 0,
    #[rustfmt::skip]
        coinbase_payload: &[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Blue score
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Subsidy: 0 (fair launch)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Zethora: pool balance 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Zethora: total burned 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Zethora: total issued 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Zethora: transparent supply 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Zethora: shielded balance 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Zethora: private coin list root
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Zethora: private state fingerprint
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, // Script version
        0x01,       // Varint
        0x00,       // OP-FALSE
        0x7a, 0x65, 0x74, 0x68, 0x6f, 0x72, 0x61, 0x2d, 0x73, 0x69, 0x6d, 0x6e, 0x65, 0x74, // zethora-simnet
        0x20, 0x7c, 0x20, 0x57, 0x61, 0x6b, 0x65, 0x20, 0x55, 0x70, 0x20, 0x46, 0x72, 0x6f, 0x6d, 0x20, 0x54, 0x68, 0x65, 0x20, 0x44, 0x72, 0x65, 0x61, 0x6d, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, // | Wake Up From The Dream World
    ],
};
pub const DEVNET_GENESIS: GenesisBlock = GenesisBlock {
    // Computed by `print_zethora_devnet_genesis` (see tests below)
    hash: Hash::from_bytes([
        0x55, 0x63, 0xe8, 0x6a, 0xa2, 0x8f, 0x48, 0x54, 0x39, 0xed, 0x47, 0x82, 0x35, 0x69, 0xbe, 0xfd, 0x73, 0x39, 0xa2, 0x52, 0x17,
        0xa8, 0xc1, 0x5b, 0x39, 0x1c, 0xe1, 0xaf, 0xf2, 0xd2, 0x7a, 0x81,
    ]),
    version: 0,
    hash_merkle_root: Hash::from_bytes([
        0xce, 0x21, 0xa8, 0x53, 0x3c, 0x5c, 0x66, 0xa8, 0xfb, 0xbe, 0x74, 0x61, 0xa5, 0x68, 0x8b, 0x4c, 0x10, 0x52, 0x0c, 0xb3, 0x3f,
        0x1f, 0x3c, 0xc4, 0x69, 0xdd, 0x30, 0x15, 0xb9, 0xe4, 0xe0, 0x83,
    ]),
    utxo_commitment: EMPTY_MUHASH,
    timestamp: 0x1a100cdff60, // Oct 3, 2026
    bits: 0x1f20c49b,         // ~2,000 RandomX hashes per block to start; the DAA adjusts from there
    nonce: 0,
    daa_score: 0,
    #[rustfmt::skip]
    coinbase_payload: &[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Blue score
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Subsidy: 0 (fair launch)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Zethora: pool balance 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Zethora: total burned 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Zethora: total issued 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Zethora: transparent supply 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Zethora: shielded balance 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Zethora: private coin list root (genesis: none, not checked)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Zethora: private state fingerprint (genesis: not checked)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, // Script version
        0x01,       // Varint
        0x00,       // OP-FALSE
        0x7a, 0x65, 0x74, 0x68, 0x6f, 0x72, 0x61, 0x2d, 0x64, 0x65, 0x76, 0x6e, // zethora-devn
        0x65, 0x74, 0x20, 0x7c, 0x20, 0x57, 0x61, 0x6b, 0x65, 0x20, 0x55, 0x70, // et | Wake Up
        0x20, 0x46, 0x72, 0x6f, 0x6d, 0x20, 0x54, 0x68, 0x65, 0x20, 0x44, 0x72, //  From The Dr
        0x65, 0x61, 0x6d, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, // eam World
    ],
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::calc_hash_merkle_root;


    /// Zethora: the byte array spliced into the mainnet and testnet coinbase payloads is exactly one `OP_PUSHDATA1` push
    /// of [`ZETHORA_GENESIS_MESSAGE`], and those payloads are short enough for the coinbase manager to build and read
    /// (the payload cap and its reader are exercised in consensus/src/processes/coinbase.rs).
    #[test]
    fn test_genesis_commitment() {
        let message = ZETHORA_GENESIS_MESSAGE.as_bytes();
        assert!(message.len() < 76, "a {}-byte message no longer fits OP_PUSHDATA1, which pays 2 bytes of overhead here", message.len());
        assert_eq!(ZETHORA_GENESIS_MESSAGE_PUSH, [&[0x4c, message.len() as u8], message].concat(), "message push bytes out of sync");
        assert_eq!(genesis_message_hex().len(), 2 * message.len());

        // The miner script is `OP_FALSE` (0x00) followed by the network name and tagline; everything after it is extra
        // data. The message must be the payload's tail, so that the coinbase reader never mistakes it for the script.
        for (net, payload) in [("mainnet", GENESIS.coinbase_payload), ("testnet", TESTNET_GENESIS.coinbase_payload)] {
            assert!(payload.ends_with(ZETHORA_GENESIS_MESSAGE_PUSH), "{net}: the genesis message must end the payload");
            assert!(payload.len() <= 300, "{net}: genesis payload is {} bytes, above the 300-byte cap", payload.len());
        }
    }

    #[test]
    fn test_genesis_hash_diversity() {
        // The four network genesis hashes must be pairwise distinct. If two
        // ever matched, a node would treat blocks from one network as valid
        // on the other. This test fails if genesis.rs constants are ever
        // set to collide (e.g. copy/paste error during regeneration).
        let networks: [(&str, GenesisBlock); 4] =
            [("mainnet", GENESIS), ("testnet", TESTNET_GENESIS), ("simnet", SIMNET_GENESIS), ("devnet", DEVNET_GENESIS)];
        for i in 0..networks.len() {
            for j in (i + 1)..networks.len() {
                let (name_a, genesis_a) = &networks[i];
                let (name_b, genesis_b) = &networks[j];
                assert_ne!(
                    genesis_a.hash, genesis_b.hash,
                    "genesis hash collision between {} and {} -- the four network \
                     genesis hashes must be pairwise distinct.",
                    name_a, name_b,
                );
            }
        }
    }

    #[test]
    fn print_zethora_testnet_genesis() {
        let mut g = TESTNET_GENESIS;
        let block: Block = (&g).into();
        g.hash_merkle_root = calc_hash_merkle_root(block.transactions.iter());
        let block: Block = (&g).into();
        let out = format!(
            "hash_merkle_root: {}\n{:#04x?}\nhash: {}\n{:#04x?}\n",
            g.hash_merkle_root,
            g.hash_merkle_root.as_bytes(),
            block.hash(),
            block.hash().as_bytes()
        );
        println!("{out}");
        std::fs::write("zethora_testnet_genesis_values.txt", out).unwrap();
    }

    #[test]
    fn print_zethora_mainnet_genesis() {
        let mut g = GENESIS;
        let block: Block = (&g).into();
        g.hash_merkle_root = calc_hash_merkle_root(block.transactions.iter());
        let block: Block = (&g).into();
        let out = format!(
            "hash_merkle_root: {}\n{:#04x?}\nhash: {}\n{:#04x?}\n",
            g.hash_merkle_root,
            g.hash_merkle_root.as_bytes(),
            block.hash(),
            block.hash().as_bytes()
        );
        println!("{out}");
        std::fs::write("zethora_mainnet_genesis_values.txt", out).unwrap();
    }

    /// Computes Zethora devnet genesis values and writes them to zethora_genesis_values.txt
    #[test]
    fn print_zethora_devnet_genesis() {
        let mut g = DEVNET_GENESIS;
        let block: Block = (&g).into();
        g.hash_merkle_root = calc_hash_merkle_root(block.transactions.iter());
        let block: Block = (&g).into();
        let out = format!(
            "hash_merkle_root: {}\n{:#04x?}\nhash: {}\n{:#04x?}\n",
            g.hash_merkle_root,
            g.hash_merkle_root.as_bytes(),
            block.hash(),
            block.hash().as_bytes()
        );
        println!("{out}");
        std::fs::write("zethora_genesis_values.txt", out).unwrap();
    }
    #[test]
    fn print_zethora_simnet_genesis() {
        let mut g = SIMNET_GENESIS;
        let block: Block = (&g).into();
        g.hash_merkle_root = calc_hash_merkle_root(block.transactions.iter());
        let block: Block = (&g).into();
        let out = format!(
            "hash_merkle_root: {}\n{:#04x?}\nhash: {}\n{:#04x?}\n",
            g.hash_merkle_root,
            g.hash_merkle_root.as_bytes(),
            block.hash(),
            block.hash().as_bytes()
        );
        println!("{out}");
        std::fs::write("zethora_simnet_genesis_values.txt", out).unwrap();
    }

    fn assert_hashes_eq(got: Hash, expected: Hash, field: &str) {
        if got != expected {
            // Special hex print to ease changing the genesis hash according to the print if needed
            panic!("Invalid field '{}': Got hash {:#04x?} while expecting {:#04x?}", field, got.as_bytes(), expected.as_bytes());
        }
    }
}

