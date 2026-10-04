//! Zethora private payments: how they sit inside an ordinary transaction (ZTH-SPEC-006).
//!
//! A private payment travels in a normal (native subnetwork) transaction's payload:
//!
//!     payload = PRIVATE_PAYMENT_MAGIC (4 bytes) || encoded private payment
//!
//! The encoded payment format is defined in the `zethora-shielded` crate (`codec`). This module only
//! reads the few fields consensus needs without decoding the whole payment: the action count (for mass)
//! and the public value balance (for fees and the turnstile). Full decoding and proof checks happen in
//! transaction validation in isolation, before any of these helpers is relied on.

/// Marks a transaction payload as a private payment.
pub const PRIVATE_PAYMENT_MAGIC: [u8; 4] = *b"ZSHP";

/// Bytes per action in the encoded payment (must equal `zethora_shielded::codec::ACTION_SIZE`).
pub const ACTION_SIZE: usize = 820;

/// Extra compute mass charged per action for checking its share of the proof (ZTH-SPEC-006 §5).
/// About 1.85 ms per extra action on the reference PC; this price keeps a full block's proof checks
/// to a small share of a second.
pub const PROOF_MASS_PER_ACTION: u64 = 15_000;

/// If this payload is a private payment, returns the encoded payment (without the magic).
pub fn private_payment_bytes(payload: &[u8]) -> Option<&[u8]> {
    payload.strip_prefix(&PRIVATE_PAYMENT_MAGIC[..])
}

/// Number of actions declared by an encoded payment (bytes 1..3 after the pool version byte).
pub fn action_count(encoded: &[u8]) -> Option<usize> {
    let b = encoded.get(1..3)?;
    Some(u16::from_le_bytes([b[0], b[1]]) as usize)
}

/// The public value balance of an encoded payment: value leaving the private pool (positive)
/// or entering it (negative), in zets.
pub fn value_balance(encoded: &[u8]) -> Option<i64> {
    let n = action_count(encoded)?;
    let at = 1 + 2 + n.checked_mul(ACTION_SIZE)? + 1;
    let b = encoded.get(at..at + 8)?;
    Some(i64::from_le_bytes(b.try_into().ok()?))
}

/// Value moving into and out of the private pool through this transaction's payload, in zets:
/// `Some((value_in, value_out))` for a private payment, `None` for an ordinary transaction.
/// Returns `Err(())` if the payload claims to be a private payment but its value balance can't be read.
#[allow(clippy::result_unit_err)]
pub fn pool_flows(payload: &[u8]) -> Result<Option<(u64, u64)>, ()> {
    let Some(encoded) = private_payment_bytes(payload) else { return Ok(None) };
    let vb = value_balance(encoded).ok_or(())?;
    Ok(Some(if vb < 0 { (vb.unsigned_abs(), 0) } else { (0, vb as u64) }))
}

/// Extra compute mass for the proof in this payload (0 for ordinary transactions).
pub fn proof_mass(payload: &[u8]) -> u64 {
    private_payment_bytes(payload).and_then(action_count).map_or(0, |n| n as u64 * PROOF_MASS_PER_ACTION)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake encoded payment with `n` actions and value balance `vb` (only the fields read here are real).
    fn fake(n: u16, vb: i64) -> Vec<u8> {
        let mut p = PRIVATE_PAYMENT_MAGIC.to_vec();
        p.push(1); // pool version
        p.extend_from_slice(&n.to_le_bytes());
        p.extend(std::iter::repeat_n(0u8, n as usize * ACTION_SIZE));
        p.push(0x02); // flags
        p.extend_from_slice(&vb.to_le_bytes());
        p.extend_from_slice(&[0u8; 32]); // anchor (rest omitted)
        p
    }

    #[test]
    fn ordinary_payloads_are_not_private_payments() {
        assert_eq!(pool_flows(&[]), Ok(None));
        assert_eq!(pool_flows(b"hello world"), Ok(None));
        assert_eq!(pool_flows(b"ZSH"), Ok(None));
        assert_eq!(proof_mass(b"anything"), 0);
    }

    #[test]
    fn reads_flows_and_mass() {
        assert_eq!(pool_flows(&fake(2, -5_000)), Ok(Some((5_000, 0)))); // shielding
        assert_eq!(pool_flows(&fake(2, 2_000)), Ok(Some((0, 2_000)))); // unshielding
        assert_eq!(pool_flows(&fake(3, 0)), Ok(Some((0, 0))));
        assert_eq!(proof_mass(&fake(2, 0)), 30_000);
        assert_eq!(proof_mass(&fake(4, 0)), 60_000);
    }

    #[test]
    fn truncated_private_payment_is_an_error() {
        let mut p = fake(2, -5_000);
        p.truncate(4 + 1 + 2 + 2 * ACTION_SIZE + 1 + 4);
        assert_eq!(pool_flows(&p), Err(()));
        assert_eq!(pool_flows(b"ZSHP"), Err(()));
    }
}
