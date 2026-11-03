//! The L1 lock: the script a deposit is locked under.
//!
//! The deposit side of the bridge is a UTXO script, not an account, so the whole
//! trust model of "can the bridge move this money" lives in the bytes assembled
//! here. It is kept in its own module, decoupled from the consensus crates, so the
//! rule is auditable in one place: an output is a deposit exactly when its locking
//! script requires M-of-N signatures from the federation.
//!
//! The script is the standard threshold form,
//!
//! ```text
//! M <pubkey>... N OP_CHECKMULTISIG
//! ```
//!
//! which any L1 script engine already knows how to enforce. The bridge only has
//! to *recognise* it, which is why constructing it is a local matter of opcodes
//! rather than a dependency on the transaction layer.

use crate::MAX_LOCK_SCRIPT_LEN;

// The script opcodes a lock uses. These are L1 opcode values; naming them
// locally keeps the bridge from depending on the consensus crates.
/// Pushes the next `N` bytes as a data element.
const OP_PUSHDATA1: u8 = 0x4c;
/// Pushes the next `N` bytes as a data element, `N` a little-endian `u16`.
const OP_PUSHDATA2: u8 = 0x4d;
/// Pushes the integer 1.
const OP_1: u8 = 0x51;
/// Requires `M` of the preceding `N` signatures.
const OP_CHECKMULTISIG: u8 = 0xae;

/// The most public keys a single lock may name.
///
/// The key count is pushed as a small-integer opcode, so it cannot exceed 16, and
/// a lock naming more could not be expressed as a script at all.
pub const MAX_KEYS: usize = 16;

/// An M-of-N federation that can spend a locked output.
///
/// The L1 lock is a script, not an account: it names the public keys allowed to
/// unlock it and how many of them must sign. That is the entire trust model of the
/// deposit side, so it is modelled explicitly rather than hidden in a script
/// constant somewhere.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FederationLock {
    /// The member public keys, in script order.
    ///
    /// Order is significant: `OP_CHECKMULTISIG` matches signatures to keys
    /// left-to-right, so reordering the keys yields a different script and
    /// therefore a different definition of a deposit.
    public_keys: Vec<Vec<u8>>,
    threshold: u8,
}

impl FederationLock {
    /// Creates a threshold lock.
    ///
    /// # Errors
    ///
    /// A lock that could never be satisfied, or could be satisfied by nobody, is
    /// refused here rather than shipped: a zero threshold would make every deposit
    /// spendable by anyone, and a threshold above the key count would lock funds
    /// forever. Both are silent, permanent failures of the bridge — exactly the
    /// class of bug that must not be expressible.
    pub fn new(public_keys: Vec<Vec<u8>>, threshold: u8) -> Result<Self, String> {
        if public_keys.is_empty() {
            return Err("a federation must name at least one public key".to_string());
        }
        if public_keys.len() > MAX_KEYS {
            return Err(format!("a federation may name at most {MAX_KEYS} public keys, got {}", public_keys.len()));
        }
        if threshold == 0 {
            return Err("threshold must be at least 1: a lock nobody has to sign is not a lock".to_string());
        }
        if usize::from(threshold) > public_keys.len() {
            return Err(format!(
                "threshold {threshold} exceeds the {} key(s) in the federation: it could never be met",
                public_keys.len()
            ));
        }
        if public_keys.iter().any(|key| key.is_empty()) {
            return Err("a federation may not contain an empty public key".to_string());
        }
        Ok(Self { public_keys, threshold })
    }

    /// The member public keys, in script order.
    pub fn public_keys(&self) -> &[Vec<u8>] {
        &self.public_keys
    }

    /// How many signatures a spend must carry.
    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    /// The L1 script that locks an output under this federation.
    pub fn lock_script(&self) -> Vec<u8> {
        let mut script = Vec::with_capacity(MAX_LOCK_SCRIPT_LEN);
        push_small_int(&mut script, i64::from(self.threshold));
        for key in &self.public_keys {
            push_data(&mut script, key);
        }
        push_small_int(&mut script, self.public_keys.len() as i64);
        script.push(OP_CHECKMULTISIG);
        script
    }
}

/// Pushes `data` as minimally as the encoding allows.
fn push_data(script: &mut Vec<u8>, data: &[u8]) {
    match data.len() {
        0..=75 => script.push(data.len() as u8),
        76..=255 => {
            script.push(OP_PUSHDATA1);
            script.push(data.len() as u8);
        }
        len => {
            script.push(OP_PUSHDATA2);
            script.extend_from_slice(&(len as u16).to_le_bytes());
        }
    }
    script.extend_from_slice(data);
}

/// Pushes `value` as a small-integer opcode.
///
/// Thresholds and key counts always fit `OP_1`..`OP_16`, which is why a
/// federation is limited to [`MAX_KEYS`] members.
fn push_small_int(script: &mut Vec<u8>, value: i64) {
    debug_assert!((1..=MAX_KEYS as i64).contains(&value), "only 1..=16 have a small-integer opcode");
    script.push(OP_1 + (value as u8 - 1));
}
