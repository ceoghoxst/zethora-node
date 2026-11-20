//! The L2 chain configuration this node reads from the environment.
//!
//! The chain has one economic knob that cannot be decided by the code: where the
//! producer's share of every gas fee goes. [`zethora_evm::EvmExecutor`] already
//! knows how to split a fee — [`zethora_evm::MINER_TREASURY_FEE_BPS`] of it is
//! routed to a treasury, the rest stays with the block producer — but it can only
//! do that if it is told which account the treasury is. That account is deployment
//! data, not source code: a devnet points it at a throwaway key, production points
//! it at the `ZefTreasury` contract, and neither should require a rebuild.
//!
//! So the address comes from [`MINER_TREASURY_ADDRESS_ENV`], is parsed **once** at
//! startup, and is handed to the executor's constructor. A malformed value is a
//! startup failure rather than a warning: a node that quietly ran with a treasury
//! it could not read would silently burn the revenue it exists to collect.

use alloy_primitives::Address;

use crate::L2_CHAIN_ID;
use crate::types::parse_address;

/// Environment variable naming the account that receives the treasury slice of
/// every gas fee.
///
/// The value is a 20-byte EVM address, `0x`-prefixed by convention (the prefix is
/// optional, exactly as [`crate::types::parse_address`] accepts it). Leaving the
/// variable unset — or setting it to whitespace — means "no treasury", which
/// leaves the executor's own default in place.
pub const MINER_TREASURY_ADDRESS_ENV: &str = "MINER_TREASURY_ADDRESS";

/// Everything a node needs to build the chain it serves.
///
/// Kept as plain data so it can be printed at startup, handed to
/// [`crate::L2Chain::with_config`], and built from explicit values in a test
/// without reading the process environment — a test that mutates environment
/// variables is a test that fails when the harness runs it in parallel with
/// another.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct L2ChainConfig {
    /// The chain id transactions are validated against and `eth_chainId` reports.
    pub chain_id: u64,
    /// The account that receives [`zethora_evm::MINER_TREASURY_FEE_BPS`] of every
    /// gas fee, or `None` when no treasury is configured.
    ///
    /// `None` is not the same as the zero address: `None` leaves the executor at
    /// its documented default (the slice is routed to the zero address, i.e.
    /// burned), while a configured treasury is a real account the node pays.
    pub miner_treasury: Option<Address>,
}

impl L2ChainConfig {
    /// A configuration for `chain_id` with no treasury.
    ///
    /// This is what [`crate::L2Chain::new`] uses, and it reproduces the behaviour
    /// of a node that has not been told where its fees should go: the executor's
    /// treasury stays `Address::ZERO`.
    pub const fn new(chain_id: u64) -> Self {
        Self { chain_id, miner_treasury: None }
    }

    /// A configuration with `treasury` as the account that receives the fee slice.
    pub fn with_miner_treasury(mut self, treasury: Address) -> Self {
        self.miner_treasury = Some(treasury);
        self
    }

    /// Reads the configuration of the chain this endpoint serves ([`L2_CHAIN_ID`])
    /// from the environment.
    ///
    /// Only the treasury is configurable today; the chain id is a protocol
    /// constant, so letting an operator change it would break replay protection
    /// rather than configure anything.
    pub fn from_env() -> Result<Self, String> {
        Ok(Self { chain_id: L2_CHAIN_ID, miner_treasury: miner_treasury_from_env()? })
    }
}

/// Reads and parses [`MINER_TREASURY_ADDRESS_ENV`].
///
/// Returns `Ok(None)` when the variable is absent or blank, i.e. when the operator
/// deliberately has no treasury yet.
pub fn miner_treasury_from_env() -> Result<Option<Address>, String> {
    match std::env::var(MINER_TREASURY_ADDRESS_ENV) {
        // `std::env::var` reports a missing variable and an unreadable one
        // separately, and the two need different answers: one is the ordinary
        // "not configured", the other is a value the node cannot even read.
        Ok(value) => parse_miner_treasury(Some(&value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(raw)) => Err(format!(
            "{MINER_TREASURY_ADDRESS_ENV} is not valid Unicode ({raw:?}): \
             it must be a 20-byte EVM address such as 0x1111…1111"
        )),
    }
}

/// The parsing half of [`miner_treasury_from_env`], split out so it can be tested
/// without touching the process environment.
///
/// A blank value is treated as "unset" rather than as an error, because that is
/// how an empty `MINER_TREASURY_ADDRESS=` line in a compose file or a `.env`
/// arrives, and it cannot be meant as anything else.
///
/// The zero address is refused. It is the executor's "burn the slice" default, so
/// configuring it explicitly would look like a working treasury while sending
/// every routed wei nowhere — precisely the failure an operator would not notice.
fn parse_miner_treasury(value: Option<&str>) -> Result<Option<Address>, String> {
    let Some(raw) = value.map(str::trim).filter(|raw| !raw.is_empty()) else {
        return Ok(None);
    };

    let treasury =
        parse_address(raw).map_err(|reason| format!("{MINER_TREASURY_ADDRESS_ENV}={raw:?} is not an EVM address: {reason}"))?;

    if treasury.is_zero() {
        return Err(format!(
            "{MINER_TREASURY_ADDRESS_ENV}={raw:?} is the zero address, which would burn the \
             treasury slice instead of paying it; unset the variable, or name a real account"
        ));
    }

    Ok(Some(treasury))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A well-formed address, spelled out so the test also pins the accepted
    /// format rather than round-tripping the parser's own encoder. Every byte is
    /// `aa`, so the expected value is [`Address::repeat_byte`].
    const TREASURY: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn an_absent_value_configures_no_treasury() {
        assert_eq!(parse_miner_treasury(None), Ok(None));
    }

    #[test]
    fn a_blank_value_configures_no_treasury() {
        // An empty assignment in a compose file arrives as an empty string and can
        // only mean "not configured".
        assert_eq!(parse_miner_treasury(Some("")), Ok(None));
        assert_eq!(parse_miner_treasury(Some("   ")), Ok(None));
    }

    #[test]
    fn a_prefixed_address_is_parsed() {
        assert_eq!(parse_miner_treasury(Some(TREASURY)), Ok(Some(Address::repeat_byte(0xaa))));
    }

    #[test]
    fn surrounding_whitespace_and_the_prefix_case_do_not_matter() {
        // `0X` and uppercase digits are what a copy from a block explorer can look
        // like; they must not be a reason to fail startup.
        let uppercase = "  0XAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  ";
        assert_eq!(parse_miner_treasury(Some(uppercase)), Ok(Some(Address::repeat_byte(0xaa))));
        // A bare hex string without the prefix is an address too — see
        // `crate::types::decode_hex`.
        let unprefixed = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(parse_miner_treasury(Some(unprefixed)), Ok(Some(Address::repeat_byte(0xaa))));
    }

    #[test]
    fn the_zero_address_is_refused() {
        let error = parse_miner_treasury(Some("0x0000000000000000000000000000000000000000"))
            .expect_err("the zero address must not be accepted as a treasury");
        assert!(error.contains(MINER_TREASURY_ADDRESS_ENV), "the error must name the variable: {error}");
        assert!(error.contains("zero address"), "the error must say what is wrong: {error}");
    }

    #[test]
    fn a_value_that_is_not_an_address_is_refused() {
        for value in [
            // Too short: an address is exactly 20 bytes.
            "0x1234",
            // Not hex at all.
            "not-an-address",
            // Odd number of digits.
            "0x00000000000000000000000000000000000000a",
            // 32 bytes: an L1 `zethoratest:` identity, not an EVM address. Guessing
            // at a truncation would pay the wrong account.
            "0x00000000000000000000000000000000000000000000000000000000000000aa",
        ] {
            let error = parse_miner_treasury(Some(value)).expect_err("a malformed treasury must be refused, not silently ignored");
            assert!(error.contains(MINER_TREASURY_ADDRESS_ENV), "the error must name the variable: {error}");
        }
    }

    #[test]
    fn an_explicit_treasury_is_carried_by_the_config() {
        let treasury = Address::repeat_byte(0xaa);
        let config = L2ChainConfig::new(2600).with_miner_treasury(treasury);
        assert_eq!(config.chain_id, 2600);
        assert_eq!(config.miner_treasury, Some(treasury));
    }
}
