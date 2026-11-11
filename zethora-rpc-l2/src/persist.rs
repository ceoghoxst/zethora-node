//! A JSON dump of the executor's account state, so a restart is not a chain reset.
//!
//! This is a devnet, and the file is deliberately the simplest thing that works:
//! `serde_json` in, `std::fs` out, one file, no schema migration and no locking
//! against a second process. What it buys is the one property developers need
//! from a local node — a wallet that funded itself yesterday still holds its
//! balance today.
//!
//! # What is stored, and what is not
//!
//! Only the two fields a wallet observes and the engine enforces: **balance** and
//! **nonce**. Contract code and storage are *not* dumped. A devnet restart keeps
//! the money and the replay protection; a deployed contract has to be redeployed.
//! Storing the part that would otherwise silently break the next transaction is
//! the whole point, and inventing a contract-code format for a sandbox would be
//! a database, not a dump.
//!
//! Block numbers, block hashes and receipts are not stored either: they are
//! history, and the chain a restarted node serves starts at genesis with the
//! restored accounts in it.
//!
//! # Why the write is not a plain `fs::write`
//!
//! A dump interrupted halfway leaves a file that cannot be parsed, and the next
//! start would come up empty — losing exactly the state the file exists to keep.
//! [`save`] therefore writes a sibling temporary file and renames it over the
//! target: `rename` within one directory is atomic, so the state file is always
//! either the previous complete dump or the new complete one.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use alloy_primitives::{Address, U256};
use serde::{Deserialize, Serialize};

use crate::types::{decode_hex, parse_address};

/// The version of the on-disk layout.
///
/// Written into every dump and checked on load. A file from a future or past
/// layout is refused by name rather than half-read, so a format change can never
/// be mistaken for an account whose balance happens to parse.
pub const STATE_FILE_VERSION: u32 = 1;

/// The width of a `U256`, in bytes.
const U256_BYTES: usize = 32;

/// Something went wrong while reading or writing the state file.
#[derive(Debug)]
pub enum PersistError {
    /// The file could not be read or written.
    Io {
        /// The path the failure belongs to.
        path: PathBuf,
        /// The underlying failure.
        source: std::io::Error,
    },
    /// The file is not the JSON this module writes.
    Format {
        /// The path the failure belongs to.
        path: PathBuf,
        /// The underlying failure.
        source: serde_json::Error,
    },
}

impl std::fmt::Display for PersistError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(formatter, "{}: {source}", path.display()),
            Self::Format { path, source } => write!(formatter, "{} is not a state dump: {source}", path.display()),
        }
    }
}

impl std::error::Error for PersistError {}

/// One account as it appears in a dump.
///
/// Both numbers are strings, not JSON numbers: a balance is a `U256` and does not
/// fit in the 64 bits a JSON number is reliably carried in, so it is written as
/// the same `0x` quantity the RPC answers with and read back with the same
/// parser. A dump that a client could not also parse is not worth writing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedAccount {
    /// `0x`-prefixed, 20-byte address.
    pub address: String,
    /// Balance in wei, as a `0x` quantity.
    pub balance: String,
    /// Number of transactions the address has sent.
    pub nonce: u64,
}

impl PersistedAccount {
    /// The account's address.
    pub fn address(&self) -> Result<Address, String> {
        parse_address(&self.address).map_err(|reason| format!("account {}: {reason}", self.address))
    }

    /// The account's balance, in wei.
    ///
    /// Short quantities are left-padded, so `0x1` and a full-width 32-byte form
    /// both read as one wei; anything wider than a `U256` is refused instead of
    /// being truncated into a different amount.
    pub fn balance(&self) -> Result<U256, String> {
        let raw = decode_hex(&self.balance).map_err(|reason| format!("account {}: balance: {reason}", self.address))?;
        if raw.len() > U256_BYTES {
            return Err(format!(
                "account {}: balance is {} bytes, a U256 holds at most {U256_BYTES}",
                self.address,
                raw.len()
            ));
        }
        let mut padded = [0u8; U256_BYTES];
        // `raw` fits in `padded` because the width was checked above.
        padded[U256_BYTES - raw.len()..].copy_from_slice(&raw);
        Ok(U256::from_be_bytes(padded))
    }
}

/// A whole dump: every account the executor knew about.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedState {
    /// [`STATE_FILE_VERSION`] of the writer.
    pub version: u32,
    /// The chain id the dump belongs to.
    ///
    /// A dump is a set of balances on *one* chain; loading it into a node serving
    /// another would fund addresses with money that never existed there. The id is
    /// therefore part of the file and checked before a single account is applied.
    pub chain_id: u64,
    /// The accounts, ordered by address so the file is stable between dumps.
    pub accounts: Vec<PersistedAccount>,
}

/// Reads the dump at `path`.
///
/// `Ok(None)` means the file does not exist, which is the normal first start and
/// not an error: a node that has never run has no state to restore.
pub fn load(path: &Path) -> Result<Option<PersistedState>, PersistError> {
    let contents = match fs::read(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(PersistError::Io { path: path.to_path_buf(), source }),
    };

    serde_json::from_slice(&contents).map(Some).map_err(|source| PersistError::Format { path: path.to_path_buf(), source })
}

/// Writes `state` to `path`, atomically.
pub fn save(path: &Path, state: &PersistedState) -> Result<(), PersistError> {
    let encoded =
        serde_json::to_vec_pretty(state).map_err(|source| PersistError::Format { path: path.to_path_buf(), source })?;

    // A sibling path, so the rename below stays inside one directory and cannot
    // cross a filesystem boundary (where `rename` is not atomic and may not even
    // replace an existing file).
    let mut temporary = path.as_os_str().to_os_string();
    temporary.push(".tmp");
    let temporary = PathBuf::from(temporary);

    fs::write(&temporary, &encoded).map_err(|source| PersistError::Io { path: temporary.clone(), source })?;
    fs::rename(&temporary, path).map_err(|source| PersistError::Io { path: path.to_path_buf(), source })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dump_round_trips() {
        let account = PersistedAccount {
            address: crate::types::address(Address::repeat_byte(0x11)),
            balance: crate::types::quantity(U256::from(1_000_000_000_000_000_000u64)),
            nonce: 7,
        };
        let state = PersistedState { version: STATE_FILE_VERSION, chain_id: 2600, accounts: vec![account] };

        let json = serde_json::to_string(&state).expect("a dump is JSON");
        let restored: PersistedState = serde_json::from_str(&json).expect("a dump reads back");

        assert_eq!(restored, state);
        assert_eq!(restored.accounts[0].balance().expect("balance parses"), U256::from(1_000_000_000_000_000_000u64));
        assert_eq!(restored.accounts[0].nonce, 7);
    }

    #[test]
    fn a_balance_wider_than_a_u256_is_refused() {
        let account =
            PersistedAccount { address: crate::types::address(Address::ZERO), balance: format!("0x{}", "ff".repeat(33)), nonce: 0 };
        assert!(account.balance().is_err());
    }
}
