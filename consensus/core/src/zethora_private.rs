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

/// True if this payload is a private payment that takes value out of the private pool (positive value balance).
/// Such a payment can pay its own network fee from private coins, so its transaction needs no visible input: a fully
/// private payment (ZTH-SPEC-006 §9). Reads the declared value balance only; the full payment is checked in isolation.
pub fn pays_from_private_pool(payload: &[u8]) -> bool {
    matches!(pool_flows(payload), Ok(Some((_, value_out))) if value_out > 0)
}

/// The spent-coin tags (nullifiers) a private payment reveals, one per action, in action order.
/// Empty for ordinary transactions. Every nullifier may appear on the chain only once (ZTH-SPEC-006 §6.3):
/// that is the double-spend guard. Never panics on any payload; the tags are only trustworthy for payments already
/// checked in isolation (the mempool also reads unchecked payloads, only to refuse conflicts early).
pub fn nullifiers(payload: &[u8]) -> Vec<[u8; 32]> {
    let Some(encoded) = private_payment_bytes(payload) else { return Vec::new() };
    let Some(n) = action_count(encoded) else { return Vec::new() };
    (0..n)
        .filter_map(|i| {
            let at = 3 + i * ACTION_SIZE + 32; // value commitment (32), then the nullifier
            encoded.get(at..at + 32).map(|b| b.try_into().expect("32 bytes"))
        })
        .collect()
}

/// The private state fingerprint (ZTH-SPEC-006 §6.4): a MuHash set hash, sealed in every coinbase, over every private
/// coin tag ever spent on the chain and every coin list snapshot (anchor) the chain ever produced. A node joining from a
/// pruning point downloads both sets and checks them against this fingerprint, the way it checks the visible UTXO set
/// against the UTXO commitment. Each set member is tagged so a tag and a snapshot can never be confused.
pub fn private_state_spent_element(nullifier: &[u8; 32]) -> [u8; 33] {
    let mut e = [0u8; 33];
    e[0] = b'N';
    e[1..].copy_from_slice(nullifier);
    e
}

/// A coin list snapshot (anchor) as a member of the private state fingerprint (see `private_state_spent_element`),
/// together with the blue score of the chain block that produced it. The blue score decides when a spend may use the
/// snapshot (`ANCHOR_DEPTH`), so it is sealed too: a node joining from a pruning point gets every snapshot's age from
/// its peer and the fingerprint proves the ages are right.
pub fn private_state_anchor_element(root: &[u8; 32], blue_score: u64) -> [u8; 41] {
    let mut e = [0u8; 41];
    e[0] = b'A';
    e[1..33].copy_from_slice(root);
    e[33..].copy_from_slice(&blue_score.to_le_bytes());
    e
}

/// A spend must use a private coin list snapshot (anchor) produced at least this many blue blocks below the
/// block that accepts it (ZTH-SPEC-006 §6.2). On today's devnet (one home miner, about 1 block per second) that is
/// about 10 minutes; a reorg that deep never happens in practice, so a payment that was valid stays valid. Far inside
/// the merge depth and finality. TODO before testnet: scale with the network's real block rate (10x at 10 blocks/s).
pub const ANCHOR_DEPTH: u64 = 600;

/// Orchard flags byte: bit 0 means "this payment spends private coins".
const FLAG_SPENDS_ENABLED: u8 = 0b0000_0001;

/// If this payload is a private payment that spends private coins, returns the coin list snapshot (anchor)
/// its spends prove membership in. `None` for ordinary transactions and for payments that only add coins
/// (their anchor is not used by the proof). Never panics on any payload; the mempool also calls it on payments not yet
/// checked in isolation, only to refuse stale ones before the expensive proof check.
pub fn spend_anchor(payload: &[u8]) -> Option<[u8; 32]> {
    let encoded = private_payment_bytes(payload)?;
    let n = action_count(encoded)?;
    let flags_at = 3 + n.checked_mul(ACTION_SIZE)?;
    let flags = *encoded.get(flags_at)?;
    if flags & FLAG_SPENDS_ENABLED == 0 {
        return None;
    }
    let anchor_at = flags_at + 1 + 8; // flags, value balance, then the anchor
    encoded.get(anchor_at..anchor_at + 32).map(|b| b.try_into().expect("32 bytes"))
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
    fn reads_nullifiers_in_action_order() {
        let mut p = fake(2, -5_000);
        let base = 4 + 3; // magic + pool version + action count
        p[base + 32..base + 64].copy_from_slice(&[0xAA; 32]);
        p[base + ACTION_SIZE + 32..base + ACTION_SIZE + 64].copy_from_slice(&[0xBB; 32]);
        assert_eq!(nullifiers(&p), vec![[0xAA; 32], [0xBB; 32]]);
        assert!(nullifiers(b"ordinary payload").is_empty());
    }

    #[test]
    fn reads_the_spend_anchor_only_when_spending() {
        let mut p = fake(2, 0);
        let flags_at = 4 + 3 + 2 * ACTION_SIZE;
        p[flags_at + 9..flags_at + 41].copy_from_slice(&[0xCC; 32]);
        p[flags_at] = 0b10; // outputs only: the anchor is not used
        assert_eq!(spend_anchor(&p), None);
        p[flags_at] = 0b11; // spends and outputs
        assert_eq!(spend_anchor(&p), Some([0xCC; 32]));
        assert_eq!(spend_anchor(b"ordinary payload"), None);
    }

    #[test]
    fn only_payments_taking_value_out_of_the_pool_can_pay_their_own_fee() {
        assert!(pays_from_private_pool(&fake(2, 1_000))); // fee (and maybe an unshield) comes out of the pool
        assert!(!pays_from_private_pool(&fake(2, 0))); // nothing leaves the pool: nothing to pay a fee with
        assert!(!pays_from_private_pool(&fake(2, -5_000))); // shielding needs a visible coin
        assert!(!pays_from_private_pool(b"ordinary payload"));
        assert!(!pays_from_private_pool(b"ZSHP"));
    }

    #[test]
    fn truncated_private_payment_is_an_error() {
        let mut p = fake(2, -5_000);
        p.truncate(4 + 1 + 2 + 2 * ACTION_SIZE + 1 + 4);
        assert_eq!(pool_flows(&p), Err(()));
        assert_eq!(pool_flows(b"ZSHP"), Err(()));
    }
}
