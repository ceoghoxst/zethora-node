//! Byte layout of an encoded Zethora private payment (ZTH-SPEC-006 §7.4).
//!
//! This is the ONE place the layout is written down. `zethora-shielded::codec` encodes and decodes with it, and
//! consensus (`kaspa-consensus-core::zethora_private`) reads the few fields it needs at these offsets without decoding
//! the whole payment. A test in consensus builds real payments and checks both sides agree byte for byte.
//!
//! All integers little-endian. `n` is the action count.
//!
//! | field              | offset                             | size                         |
//! |--------------------|------------------------------------|------------------------------|
//! | pool version       | `POOL_VERSION_OFFSET`              | 1                            |
//! | action count n     | `ACTION_COUNT_OFFSET`              | 2 (u16)                      |
//! | n actions          | `action_offset(i)`                 | n x `ACTION_SIZE`            |
//! | flags              | `trailer_offset(n) + FLAGS_OFFSET` | 1                            |
//! | value balance      | `.. + VALUE_BALANCE_OFFSET`        | 8 (i64)                      |
//! | anchor             | `.. + ANCHOR_OFFSET`               | 32                           |
//! | proof length       | `.. + PROOF_LENGTH_OFFSET`         | 4 (u32)                      |
//! | proof, n spend signatures (64 each), binding signature (64) follow |  |                 |
//!
//! Inside one action (offsets from `action_offset(i)`): value commitment, nullifier, spend key (rk), new coin (cmx),
//! ephemeral key, encrypted note, encrypted note for the sender.

#![no_std]

/// Pool version byte (1 = Orchard with the fixed circuit).
pub const POOL_VERSION_OFFSET: usize = 0;
/// Action count, u16 little-endian.
pub const ACTION_COUNT_OFFSET: usize = POOL_VERSION_OFFSET + 1;
/// First action.
pub const ACTIONS_OFFSET: usize = ACTION_COUNT_OFFSET + 2;

/// Size of the fixed-size 32-byte fields of an action.
pub const FIELD_32: usize = 32;
/// Encrypted note (Orchard's `ENC_CIPHERTEXT_SIZE`).
pub const ENC_CIPHERTEXT_SIZE: usize = 580;
/// Encrypted note for the sender (Orchard's `OUT_CIPHERTEXT_SIZE`).
pub const OUT_CIPHERTEXT_SIZE: usize = 80;

/// Offsets inside one action.
pub const CV_OFFSET: usize = 0;
pub const NULLIFIER_OFFSET: usize = CV_OFFSET + FIELD_32;
pub const RK_OFFSET: usize = NULLIFIER_OFFSET + FIELD_32;
pub const CMX_OFFSET: usize = RK_OFFSET + FIELD_32;
pub const EPK_OFFSET: usize = CMX_OFFSET + FIELD_32;
pub const ENC_CIPHERTEXT_OFFSET: usize = EPK_OFFSET + FIELD_32;
pub const OUT_CIPHERTEXT_OFFSET: usize = ENC_CIPHERTEXT_OFFSET + ENC_CIPHERTEXT_SIZE;
/// Bytes per action without its signature: 820.
pub const ACTION_SIZE: usize = OUT_CIPHERTEXT_OFFSET + OUT_CIPHERTEXT_SIZE;

/// Offsets inside the trailer that follows the actions.
pub const FLAGS_OFFSET: usize = 0;
pub const VALUE_BALANCE_OFFSET: usize = FLAGS_OFFSET + 1;
pub const ANCHOR_OFFSET: usize = VALUE_BALANCE_OFFSET + 8;
pub const PROOF_LENGTH_OFFSET: usize = ANCHOR_OFFSET + 32;
pub const PROOF_OFFSET: usize = PROOF_LENGTH_OFFSET + 4;

/// Bytes per spend signature and for the binding signature.
pub const SIGNATURE_SIZE: usize = 64;

/// Start of action `i`. `None` only on arithmetic overflow (never for a u16 action count).
pub const fn action_offset(i: usize) -> Option<usize> {
    match i.checked_mul(ACTION_SIZE) {
        Some(x) => x.checked_add(ACTIONS_OFFSET),
        None => None,
    }
}

/// Start of the trailer (flags, value balance, anchor, proof, signatures) of a payment with `n` actions.
pub const fn trailer_offset(n: usize) -> Option<usize> {
    action_offset(n)
}

/// Encoded size of a payment with `n` actions whose proof is `proof_size` bytes.
pub const fn encoded_size(n: usize, proof_size: usize) -> usize {
    ACTIONS_OFFSET + n * ACTION_SIZE + PROOF_OFFSET + proof_size + n * SIGNATURE_SIZE + SIGNATURE_SIZE
}

const _: () = assert!(ACTION_SIZE == 820);
const _: () = assert!(ACTIONS_OFFSET == 3);
const _: () = assert!(PROOF_OFFSET == 45);
