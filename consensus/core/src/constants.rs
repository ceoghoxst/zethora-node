/// BLOCK_VERSION represents the current block version. This denotes the use of
/// the new sequencing commit described in KIP-21.
pub const BLOCK_VERSION: u16 = 2;

/// TX_VERSION is the current latest supported transaction version.
pub const TX_VERSION: u16 = 0;

/// The transaction version activated by the Toccata hardfork.
///
/// Main changes enabled relative to [`TX_VERSION`] (0):
/// - output covenant bindings,
/// - input compute-budget mass,
/// - non-native/non-coinbase subnetworks (user lanes),
/// - gas commitments.
pub const TX_VERSION_TOCCATA: u16 = 1;

pub const LOCK_TIME_THRESHOLD: u64 = 500_000_000_000;

/// MAX_SCRIPT_PUBLIC_KEY_VERSION is the current latest supported public key script version.
pub const MAX_SCRIPT_PUBLIC_KEY_VERSION: u16 = 0;

/// Kaspa's unit: 10^8 sompi per KAS. NOT Zethora's unit (use `ZETS_PER_ZTHR`, 10^10). Kept only because inherited
/// Kaspa tests and the inherited Kaspa wallet/CLI use it (seam review P5-3: renamed so nobody reuses it by mistake).
pub const KASPA_SOMPI_PER_KAS: u64 = 100_000_000;

/// Kaspa's storage mass parameter (KIP-9), 10^12. NOT used by any Zethora network (see
/// `ZETHORA_STORAGE_MASS_PARAMETER`); kept for the inherited formula tests in `mass`.
pub const KASPA_STORAGE_MASS_PARAMETER: u64 = KASPA_SOMPI_PER_KAS * 10_000;

/// The parameter defining how much mass per byte to charge for when calculating
/// transient storage mass. Since normally the block mass limit is 500_000, this limits
/// block body byte size to 125_000 (KIP-0013).
pub const TRANSIENT_BYTE_TO_MASS_FACTOR: u64 = 4;

/// Zethora: 1 ZTHR = 10^10 zets (the base unit).
pub const ZETS_PER_ZTHR: u64 = 10_000_000_000;
/// Zethora: the hard cap, 100,000,000 ZTHR in zets (ZTH-SPEC-001 §5). Consensus never issues more
/// (`kaspa_consensus::processes::zethora_subsidy`, the coinbase cap clamp and the supply ledger's CapExceeded rule).
pub const CAP_UNITS: u64 = 100_000_000 * ZETS_PER_ZTHR;

/// Zethora: the largest amount a transaction may carry, in zets (any single output, all outputs, all inputs).
/// Seam review P5-3: the hard cap, not Kaspa's 29 billion KAS (2.9 x 10^18 sompi), which is above Zethora's whole
/// supply and so limited nothing.
pub const MAX_ZETS: u64 = CAP_UNITS;

/// Zethora: storage mass parameter (KIP-9 dust protection) for zets, 10^13 = 1,000 x ZETS_PER_ZTHR.
/// CEO/VP decision 2026-10-29 (docs/decisions/P5-3-storage-mass.md): an output of 0.01 ZTHR costs 1,000,000 mass
/// (over the 100,000 standard limit), so the smallest practical visible payment is about 0.01 ZTHR, and a home miner
/// can still pay 0.1 ZTHR straight from one block reward. Lowering it later is a planned upgrade with an activation
/// height. Takes effect from the public testnet genesis.
pub const ZETHORA_STORAGE_MASS_PARAMETER: u64 = ZETS_PER_ZTHR * 1_000;

// MAX_TX_IN_SEQUENCE_NUM is the maximum sequence number the sequence field
// of a transaction input can be.
pub const MAX_TX_IN_SEQUENCE_NUM: u64 = u64::MAX;

// SEQUENCE_LOCK_TIME_MASK is a mask that extracts the relative lock time
// when masked against the transaction input sequence number.
pub const SEQUENCE_LOCK_TIME_MASK: u64 = 0x00000000ffffffff;

// SEQUENCE_LOCK_TIME_DISABLED is a flag that if set on a transaction
// input's sequence number, the sequence number will not be interpreted
// as a relative lock time.
pub const SEQUENCE_LOCK_TIME_DISABLED: u64 = 1 << 63;

/// UNACCEPTED_DAA_SCORE is used to for UtxoEntries that were created by
/// transactions in the mempool, or otherwise not-yet-accepted transactions.
pub const UNACCEPTED_DAA_SCORE: u64 = u64::MAX;
