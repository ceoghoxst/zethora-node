//! Zethora private payments: how they sit inside an ordinary transaction (ZTH-SPEC-006).
//!
//! A private payment travels in a normal (native subnetwork) transaction's payload:
//!
//! ```text
//! payload = PRIVATE_PAYMENT_MAGIC (4 bytes) || encoded private payment
//! ```
//!
//! The encoded payment format is written down once, in the `zethora-payment-layout` crate, which the
//! `zethora-shielded` codec also encodes and decodes with. This module only reads the few fields consensus needs
//! without decoding the whole payment: the action count (for mass), the public value balance (for fees and the
//! turnstile), the coin tags (nullifiers) and the snapshot (anchor). Full decoding and proof checks happen in
//! transaction validation in isolation, before any of these helpers is relied on.

pub use zethora_payment_layout as layout;

/// Marks a transaction payload as a private payment.
pub const PRIVATE_PAYMENT_MAGIC: [u8; 4] = *b"ZSHP";

/// The payload to read private payment fields from: the transaction's payload, or nothing for a coinbase.
/// A coinbase is never a private payment, but its payload starts with the blue score (u64 LE), which equals
/// "ZSHP" once every 2^32 blocks (first after ~42.7 years at 1 block per second). Every consensus and mempool
/// reader goes through this so a coinbase can never be read as a private payment (seam review pack 1, #12).
pub fn private_payload(tx: &crate::tx::Transaction) -> &[u8] {
    if tx.is_coinbase() { &[] } else { &tx.payload }
}

/// Bytes per action in the encoded payment (from the shared layout; `zethora_shielded::codec::ACTION_SIZE` is the same).
pub const ACTION_SIZE: usize = layout::ACTION_SIZE;

/// Proof mass (ZTH-SPEC-006 §5; seam review pack 1 #5): every private payment pays compute mass for checking its
/// proof, a fixed part per payment plus a part per action, priced from the measured check time
/// (zethora-shielded/tests/proof_speed.rs). Checking a proof costs about 13.8 ms + 3.0 ms per action on the cloud
/// sandbox (Intel Xeon 2.1 GHz, 2 vCPU; Oct 29, 2026: 1 action 16.8 ms, 2: 21.6, 4: 29.4, 8: 38.4, 16: 62.0) and
/// about 0.6x that on the reference PC (Ryzen 5 2600: 13 ms for 2 actions, Oct 7, 2026). At about 3,000 mass per
/// sandbox millisecond, a block full of private payments of ANY size (500,000 compute mass) takes at most ~150 ms of
/// proof checking on the sandbox, ~90 ms on the reference PC. Before the fixed part existed (15,000 per action only),
/// a block of 1-action payments took ~390 ms on the sandbox: the fixed cost of each proof was free.
/// Fixed proof mass per private payment.
pub const PROOF_MASS_BASE: u64 = 40_000;
/// Proof mass per action.
pub const PROOF_MASS_PER_ACTION: u64 = 9_000;

/// If this payload is a private payment, returns the encoded payment (without the magic).
pub fn private_payment_bytes(payload: &[u8]) -> Option<&[u8]> {
    payload.strip_prefix(&PRIVATE_PAYMENT_MAGIC[..])
}

/// Number of actions declared by an encoded payment (the u16 after the pool version byte).
pub fn action_count(encoded: &[u8]) -> Option<usize> {
    let b = encoded.get(layout::ACTION_COUNT_OFFSET..layout::ACTION_COUNT_OFFSET + 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]) as usize)
}

/// Start of the trailer (flags, value balance, anchor, ...) of an encoded payment.
fn trailer_offset(encoded: &[u8]) -> Option<usize> {
    layout::trailer_offset(action_count(encoded)?)
}

/// The public value balance of an encoded payment: value leaving the private pool (positive)
/// or entering it (negative), in zets.
pub fn value_balance(encoded: &[u8]) -> Option<i64> {
    let at = trailer_offset(encoded)? + layout::VALUE_BALANCE_OFFSET;
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
///
/// All or nothing (seam review pack 1, #13): if any declared action's tag can't be read (a truncated payload), the
/// result is empty, never a partial list, so no caller can mistake "some tags" for "all tags". Such a payload also
/// fails the in-isolation decode, which runs before anything relies on these tags.
pub fn nullifiers(payload: &[u8]) -> Vec<[u8; 32]> {
    let Some(encoded) = private_payment_bytes(payload) else { return Vec::new() };
    let Some(n) = action_count(encoded) else { return Vec::new() };
    (0..n)
        .map(|i| {
            let at = layout::action_offset(i)? + layout::NULLIFIER_OFFSET;
            encoded.get(at..at + 32).map(|b| <[u8; 32]>::try_from(b).expect("32 bytes"))
        })
        .collect::<Option<Vec<_>>>()
        .unwrap_or_default()
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
/// its peer and the fingerprint proves the ages are right. Note: consensus reads Params::anchor_depth;
/// this constant is the default used to build the network params.
pub fn private_state_anchor_element(root: &[u8; 32], blue_score: u64) -> [u8; 41] {
    let mut e = [0u8; 41];
    e[0] = b'A';
    e[1..33].copy_from_slice(root);
    e[33..].copy_from_slice(&blue_score.to_le_bytes());
    e
}

/// A spend must use a private coin list snapshot (anchor) produced at least this many blue blocks below the
/// SELECTED PARENT of the chain block that accepts it (ZTH-SPEC-006 §6.2; seam review P2-7: the mempool and the block
/// template measure from the virtual's selected parent, the merge loop from the accepting chain block's, so all three
/// agree; test anchor_depth_boundary_is_measured_from_the_selected_parent). Every network runs at 1 block per second, so that is about 10 minutes;
/// a reorg that deep never happens in practice, so a payment that was valid stays valid. Far inside the merge depth
/// and finality. Consensus reads `Params::anchor_depth` (600 on every network, not overridable); this constant is the
/// default the network params are built from.
pub const ANCHOR_DEPTH: u64 = 600;

/// Orchard flags byte: bit 0 means "this payment spends private coins".
const FLAG_SPENDS_ENABLED: u8 = 0b0000_0001;

/// If this payload is a private payment that spends private coins, returns the coin list snapshot (anchor)
/// its spends prove membership in. `None` for ordinary transactions and for payments that only add coins
/// (their anchor is not used by the proof). Never panics on any payload; the mempool also calls it on payments not yet
/// checked in isolation, only to refuse stale ones before the expensive proof check.
pub fn spend_anchor(payload: &[u8]) -> Option<[u8; 32]> {
    let encoded = private_payment_bytes(payload)?;
    let trailer = trailer_offset(encoded)?;
    let flags = *encoded.get(trailer + layout::FLAGS_OFFSET)?;
    if flags & FLAG_SPENDS_ENABLED == 0 {
        return None;
    }
    let anchor_at = trailer + layout::ANCHOR_OFFSET;
    encoded.get(anchor_at..anchor_at + 32).map(|b| b.try_into().expect("32 bytes"))
}

/// How many private coins the private coin list (the Orchard note commitment tree, depth 32) can ever hold.
pub const NOTE_TREE_CAPACITY: u64 = 1 << 32;

/// New private coins (note commitments) this payload adds to the coin list: one per action, 0 for ordinary
/// transactions (and for a payload whose action count can't be read; validation refuses such a payment anyway).
pub fn new_coin_count(payload: &[u8]) -> u64 {
    private_payment_bytes(payload).and_then(action_count).map_or(0, |n| n as u64)
}

/// Extra compute mass for the proof in this payload: `PROOF_MASS_BASE` + `PROOF_MASS_PER_ACTION` per action for a
/// private payment (the base alone if its action count can't be read; validation refuses it anyway), 0 otherwise.
pub fn proof_mass(payload: &[u8]) -> u64 {
    private_payment_bytes(payload)
        .map_or(0, |encoded| PROOF_MASS_BASE + action_count(encoded).map_or(0, |n| n as u64 * PROOF_MASS_PER_ACTION))
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
        assert_eq!(proof_mass(&fake(2, 0)), 40_000 + 18_000);
        assert_eq!(proof_mass(&fake(4, 0)), 40_000 + 36_000);
        assert_eq!(proof_mass(&fake(1, 0)), 49_000);
        assert_eq!(proof_mass(&PRIVATE_PAYMENT_MAGIC), PROOF_MASS_BASE); // unreadable count: the base only
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
    fn a_truncated_payment_gives_no_tags_at_all_never_some() {
        // Seam review pack 1, #13. Positive control: the full 2-action payment gives both tags
        let mut p = fake(2, -5_000);
        let base = 4 + 3;
        p[base + 32..base + 64].copy_from_slice(&[0xAA; 32]);
        p[base + ACTION_SIZE + 32..base + ACTION_SIZE + 64].copy_from_slice(&[0xBB; 32]);
        assert_eq!(nullifiers(&p), vec![[0xAA; 32], [0xBB; 32]]);
        // Cut inside the second action's tag: before the fix this returned [0xAA] (a partial list)
        let cut = &p[..base + ACTION_SIZE + 40];
        assert_eq!(nullifiers(cut), Vec::<[u8; 32]>::new());
        // Cut right after the first tag: still nothing, not one tag
        let cut = &p[..base + 64];
        assert_eq!(nullifiers(cut), Vec::<[u8; 32]>::new());
    }

    #[test]
    fn a_coinbase_is_never_read_as_a_private_payment() {
        // Seam review pack 1, #12: a coinbase payload starting with the blue score 0x5048535A reads "ZSHP"
        use crate::{subnets::SUBNETWORK_ID_COINBASE, subnets::SUBNETWORK_ID_NATIVE, tx::Transaction};
        // (the blue score's low 4 bytes, then bytes that look like a payment)
        let mut payload = 0x5048535A_u64.to_le_bytes()[..4].to_vec();
        payload.extend(fake(2, 1_000)[4..].iter().copied());
        assert_eq!(&payload[..4], &PRIVATE_PAYMENT_MAGIC[..]);
        assert_eq!(pool_flows(&payload), Ok(Some((0, 1_000)))); // the raw readers alone would be fooled
        let coinbase = Transaction::new(0, vec![], vec![], 0, SUBNETWORK_ID_COINBASE, 0, payload.clone());
        assert!(coinbase.is_coinbase());
        assert!(private_payload(&coinbase).is_empty());
        assert_eq!(pool_flows(private_payload(&coinbase)), Ok(None));
        assert!(nullifiers(private_payload(&coinbase)).is_empty());
        // Positive control: the same bytes in an ordinary transaction are read as a private payment
        let ordinary = Transaction::new(0, vec![], vec![], 0, SUBNETWORK_ID_NATIVE, 0, payload);
        assert_eq!(pool_flows(private_payload(&ordinary)), Ok(Some((0, 1_000))));
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

    /// Seam review P2-2: one new private coin per action; the coin list's capacity is Orchard's 2^32.
    #[test]
    fn new_coins_are_counted_per_action() {
        assert_eq!(NOTE_TREE_CAPACITY, 1u64 << 32);
        assert_eq!(new_coin_count(b"not a private payment"), 0);
        assert_eq!(new_coin_count(&fake(1, 0)), 1);
        assert_eq!(new_coin_count(&fake(16, -5)), 16);
        assert_eq!(new_coin_count(&PRIVATE_PAYMENT_MAGIC), 0); // unreadable count
    }
}
