//! The L2 side: the wZTHR token contract and its `mint` entry point.
//!
//! There is no Solidity compiler in this repository, so the contract is declared
//! with [`sol!`] and its body is written in Rust. `sol!` is the same macro that
//! parses a compiled contract's ABI, so everything a caller sees — the selector,
//! the argument encoding, the event and the errors — is derived from the
//! Solidity signature and is byte-for-byte what a deployed contract would expose.
//! Only the bytecode is mocked.
//!
//! The entry point verifies a deposit proof from the L1 watcher before it credits
//! anything: the proof is the contract's only source of truth about L1, so a
//! `mint` that does not carry a valid one is a `mint` that mints nothing. Every
//! check below is load-bearing, and the ordering is deliberate — the proof is
//! verified before the replay marker is consulted, so an invalid proof can never
//! consume a lock id.

use alloy_primitives::{Address, U256, keccak256};
use alloy_sol_types::{SolCall, SolError, SolValue, sol};
use zethora_evm::EvmExecutor;

use crate::watcher::MintProof;

sol! {
    /// The wZTHR token on L2.
    ///
    /// `balances` is the storage mapping the mint credits; `mint` is the entry
    /// point the bridge calls. Only a proof is accepted, never a caller's word:
    /// the third argument is verified, not merely carried, so calling `mint`
    /// without a valid deposit proof mints nothing.
    #[allow(missing_docs)]
    contract WZthrBridge {
        mapping(address => uint256) public balances;

        function mint(address to, uint256 amount, bytes proof) external;

        event Mint(address indexed to, uint256 amount, bytes32 lockId);

        error InvalidProof();
        error AlreadyMinted(bytes32 lockId);
        error ZeroAmount();
        error AmountTooLarge(uint256 amount);
    }
}

/// The slot a Solidity `mapping(address => uint256) balances`, declared first in
/// the contract, would occupy.
///
/// A Solidity mapping does not store its entries consecutively: entry `k` lives
/// at `keccak256(abi.encode(k, slot))`. Reproducing that rule means a reader that
/// only understands real Solidity storage still finds the balances.
pub const MINT_STORAGE_INITIAL_SLOT: U256 = U256::ZERO;

/// The slot of `balances[account]`.
pub fn mint_storage_slot(account: Address) -> U256 {
    // `abi.encode` of a mapping key and its slot is exactly two left-padded
    // 32-byte words, which is also `SolValue::abi_encode` of that pair.
    let encoded = (account, MINT_STORAGE_INITIAL_SLOT).abi_encode();
    U256::from_be_bytes::<32>(keccak256(&encoded).0)
}

/// The slot marking `lock_id` as already minted.
///
/// A second mapping of its own would collide with the balance layout, so the
/// replay markers live in their own hashed namespace: the same
/// `keccak256(abi.encode(key, slot))` rule, applied with the lock id as the key
/// and a namespace slot no declared field occupies. That keeps "was this lock
/// minted" and "what does this account own" from ever aliasing.
pub fn minted_slot(lock_id: [u8; 32]) -> U256 {
    const MINTED_NAMESPACE: U256 = U256::from_limbs([0xdead_beef, 0, 0, 0]);
    let encoded = (U256::from_be_bytes(lock_id), MINTED_NAMESPACE).abi_encode();
    U256::from_be_bytes::<32>(keccak256(&encoded).0)
}


/// The calldata of a `mint(to, amount, proof)` call.
///
/// This is what the coordinator sends to L2. It is the ABI encoding, not a
/// bespoke format, so the same bytes could be produced by `cast calldata` or by
/// any wallet talking to the contract.
pub fn mint_calldata(to: Address, amount: U256, proof: &[u8]) -> Vec<u8> {
    WZthrBridge::mintCall { to, amount, proof: proof.to_vec().into() }.abi_encode()
}

/// The selector of `mint(address,uint256,bytes)`.
///
/// Exposed because a selector is the identity of an entry point: anything
/// dispatching on calldata matches on this value.
pub fn mint_selector() -> [u8; 4] {
    WZthrBridge::mintCall::SELECTOR
}

/// The selector of the public `balances(address)` getter.
pub fn balances_selector() -> [u8; 4] {
    WZthrBridge::balancesCall::SELECTOR
}

/// wZTHR balance of `to` on L2, read straight out of the executor's state.
pub fn wzthr_balance(executor: &mut EvmExecutor, contract: Address, to: Address) -> U256 {
    executor.storage(contract, mint_storage_slot(to))
}

/// Decodes `mint` calldata back into its arguments.
///
/// Exposed so that the coordinator, a block explorer and the tests all read the
/// call the same way: through the ABI, not through byte offsets.
pub fn decode_mint_calldata(calldata: &[u8]) -> Result<(Address, U256, Vec<u8>), String> {
    let call = WZthrBridge::mintCall::abi_decode(calldata).map_err(|err| format!("cannot decode mint calldata: {err}"))?;
    Ok((call.to, call.amount, call.proof.to_vec()))
}

/// Result of a `mint` call that the contract itself rejected.
///
/// A rejected mint is not an error of the bridge software: it is the contract
/// doing its job, so it is modelled as a value carrying the revert payload
/// rather than as a `String`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MintError {
    /// The proof did not verify against the call's own arguments.
    InvalidProof,
    /// The lock behind the proof has already been minted.
    AlreadyMinted([u8; 32]),
    /// The amount was zero.
    ZeroAmount,
    /// The amount was larger than any L2 balance can represent.
    AmountTooLarge(U256),
    /// The contract could not write the state it computed.
    ///
    /// The EVM database refusing a write means the account could not be created
    /// or updated, so nothing was credited — and, because the replay marker is
    /// written first, nothing was consumed either.
    StorageWriteFailed(String),
}

impl MintError {
    /// The revert data a real contract would return for this error.
    pub fn revert_data(&self) -> Vec<u8> {
        // Each variant encodes itself through `SolError`, which prefixes the
        // payload with the error's selector: exactly the bytes a `revert` would
        // return for `error InvalidProof()`, not a bare argument list.
        use WZthrBridge::{AlreadyMinted, AmountTooLarge, InvalidProof, ZeroAmount};
        match self {
            Self::InvalidProof => InvalidProof {}.abi_encode(),
            Self::AlreadyMinted(lock_id) => AlreadyMinted { lockId: (*lock_id).into() }.abi_encode(),
            Self::ZeroAmount => ZeroAmount {}.abi_encode(),
            Self::AmountTooLarge(amount) => AmountTooLarge { amount: *amount }.abi_encode(),
            // Not a contract rejection: the contract never got to revert, so
            // there is no error selector to return.
            Self::StorageWriteFailed(_) => Vec::new(),
        }
    }
}

impl std::fmt::Display for MintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidProof => write!(f, "invalid proof: the deposit proof did not verify"),
            Self::AlreadyMinted(lock_id) => {
                write!(f, "already minted: lock 0x{} has already been minted", alloy_primitives::hex::encode(lock_id))
            }
            Self::ZeroAmount => write!(f, "zero amount: a mint must credit something"),
            Self::AmountTooLarge(amount) => write!(f, "amount {amount} is larger than an L2 balance can represent"),
            Self::StorageWriteFailed(err) => write!(f, "the contract could not write its own state: {err}"),
        }
    }
}

impl std::error::Error for MintError {}


/// The `mint(address to, uint256 amount, bytes proof)` entry point.
///
/// Returns `Ok(true)` when the balance was credited. Everything genuinely wrong
/// with the call is an `Err`; a replay is one of those, because silently doing
/// nothing would hide a double-spend attempt from the coordinator.
///
/// The checks run in this order, and the order is part of the contract:
///
/// 1. **amount** — a zero mint would only burn a lock id, and an amount that
///    cannot be a balance must be refused before any state is touched;
/// 2. **proof** — verified against `to` and `amount` *from the calldata*, so a
///    proof for one deposit can never be presented as a proof for another;
/// 3. **replay** — the lock id it names must not have been minted before;
/// 4. **credit** — the id is marked and the balance written.
///
/// Verification precedes the replay check on purpose: a forged proof must not be
/// able to probe, let alone consume, a lock id.
pub fn mint(executor: &mut EvmExecutor, contract: Address, to: Address, amount: U256, proof: &[u8]) -> Result<(), MintError> {
    if amount.is_zero() {
        return Err(MintError::ZeroAmount);
    }
    if amount > crate::AMOUNT_CEILING {
        return Err(MintError::AmountTooLarge(amount));
    }

    let proof = MintProof::decode(proof).map_err(|_| MintError::InvalidProof)?;
    proof.verify(to, amount).map_err(|_| MintError::InvalidProof)?;

    let lock_id = proof.lock_id;
    let minted = minted_slot(lock_id);
    if !executor.storage(contract, minted).is_zero() {
        return Err(MintError::AlreadyMinted(lock_id));
    }

    let slot = mint_storage_slot(to);
    let balance = executor.storage(contract, slot);
    let updated = balance.checked_add(amount).ok_or(MintError::AmountTooLarge(amount))?;

    // Mark the id before the credit lands, so a failure to write the balance can
    // never leave a lock that is credited *and* still mintable.
    executor.set_storage(contract, minted, U256::from(1)).map_err(MintError::StorageWriteFailed)?;
    executor.set_storage(contract, slot, updated).map_err(MintError::StorageWriteFailed)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Address, U256};

    use super::*;

    #[test]
    fn mint_selector_matches_the_solidity_signature() {
        // keccak256("mint(address,uint256,bytes)")[..4]. Pinned to a constant so
        // a typo in the signature cannot silently ship as a "new" selector.
        assert_eq!(mint_selector(), alloy_primitives::hex!("94d008ef"));
    }

    #[test]
    fn balance_slot_follows_the_solidity_mapping_rule() {
        // keccak256(abi.encode(address(0xaa..), uint256(0)))
        let account = Address::repeat_byte(0xaa);
        let expected = U256::from_be_bytes::<32>(keccak256((account, U256::ZERO).abi_encode()).0);
        assert_eq!(mint_storage_slot(account), expected);
    }

    #[test]
    fn calldata_round_trips() {
        let to = Address::repeat_byte(0xbb);
        let amount = U256::from(7u64);
        let calldata = mint_calldata(to, amount, &[1, 2, 3]);
        assert_eq!(&calldata[..4], &mint_selector());
        assert_eq!(decode_mint_calldata(&calldata).unwrap(), (to, amount, vec![1, 2, 3]));
    }

    #[test]
    fn minted_markers_do_not_alias_balances() {
        // A balance slot and a replay slot must live in different namespaces,
        // otherwise a mint could silently overwrite somebody's balance.
        let account = Address::repeat_byte(0xaa);
        let lock_id = [0x11u8; 32];
        assert_ne!(mint_storage_slot(account), minted_slot(lock_id));
    }
}
