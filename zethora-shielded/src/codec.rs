//! Byte format for a private payment (an Orchard bundle) inside a Zethora transaction (ZTH-SPEC-006 §7.4).
//!
//! Layout (all integers little-endian), mirroring Zcash's v5 Orchard encoding with fixed-size counts. The offsets are
//! written down once, in the `zethora-payment-layout` crate; consensus reads fields at those same offsets, and
//! `encode` / `decode` check that every field they write or read lands where the layout says:
//!
//! | field              | size                                  |
//! |--------------------|---------------------------------------|
//! | pool version       | 1 (only 1 = Orchard fixed circuit)    |
//! | action count n     | 2 (1..=MAX_ACTIONS_PER_TX)            |
//! | n actions          | n x 820 (cv, nullifier, rk, cmx, ciphertexts) |
//! | flags              | 1                                     |
//! | value balance      | 8 (i64)                               |
//! | anchor             | 32                                    |
//! | proof length       | 4 (must equal the canonical size for n actions) |
//! | proof              | 2,720 + 2,272 x n                     |
//! | n spend signatures | n x 64                                |
//! | binding signature  | 64                                    |
//!
//! Decoding rejects anything malformed: bad curve points, non-canonical proof sizes,
//! unknown pool versions, too many actions, missing or trailing bytes.

use crate::SupportedPool;
use nonempty::NonEmpty;
use orchard::{
    Action, Anchor, Bundle, Proof,
    bundle::{Authorized, Flags},
    note::{ExtractedNoteCommitment, Nullifier, TransmittedNoteCiphertext},
    note_encryption::{ENC_CIPHERTEXT_SIZE, NoteBytesData},
    primitives::redpallas::{self, Signature, SpendAuth, VerificationKey},
    value::ValueCommitment,
};
use std::fmt;
use subtle::CtOption;
use zethora_payment_layout as layout;

/// Most actions allowed in one private payment (each action is one spend and/or one output).
pub const MAX_ACTIONS_PER_TX: usize = 16;

/// Bytes per action without its signature: cv 32 + nullifier 32 + rk 32 + cmx 32 + epk 32 + enc 580 + out 80.
pub const ACTION_SIZE: usize = layout::ACTION_SIZE;

// The shared layout must match Orchard's own sizes.
const _: () = assert!(layout::ENC_CIPHERTEXT_SIZE == ENC_CIPHERTEXT_SIZE);
const _: () = assert!(ACTION_SIZE == 32 * 5 + ENC_CIPHERTEXT_SIZE + layout::OUT_CIPHERTEXT_SIZE);

/// Encoded size of a private payment with `n` actions.
pub const fn encoded_size(n: usize) -> usize {
    layout::encoded_size(n, Proof::expected_proof_size(n))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    UnknownPoolVersion(u8),
    BadActionCount(usize),
    Truncated,
    TrailingBytes(usize),
    BadPoint(&'static str),
    BadAction(String),
    BadFlags(u8),
    BadProofLength { expected: usize, actual: usize },
    BadBundle(String),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::UnknownPoolVersion(v) => write!(f, "unknown private pool version {v}"),
            DecodeError::BadActionCount(n) => write!(f, "bad action count {n} (allowed 1..={MAX_ACTIONS_PER_TX})"),
            DecodeError::Truncated => write!(f, "private payment is cut short"),
            DecodeError::TrailingBytes(n) => write!(f, "{n} unexpected bytes after the private payment"),
            DecodeError::BadPoint(what) => write!(f, "invalid {what}"),
            DecodeError::BadAction(e) => write!(f, "invalid action: {e}"),
            DecodeError::BadFlags(b) => write!(f, "invalid flags byte {b:#04x}"),
            DecodeError::BadProofLength { expected, actual } => write!(f, "proof is {actual} bytes, expected {expected}"),
            DecodeError::BadBundle(e) => write!(f, "invalid private payment: {e}"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Writes a private payment to bytes.
pub fn encode(bundle: &Bundle<Authorized, i64>, pool: SupportedPool) -> Vec<u8> {
    let n = bundle.actions().len();
    let mut out = Vec::with_capacity(encoded_size(n));
    debug_assert_eq!(out.len(), layout::POOL_VERSION_OFFSET);
    out.push(pool as u8);
    debug_assert_eq!(out.len(), layout::ACTION_COUNT_OFFSET);
    out.extend_from_slice(&(n as u16).to_le_bytes());
    for (i, a) in bundle.actions().iter().enumerate() {
        let start = layout::action_offset(i).expect("at most MAX_ACTIONS_PER_TX actions");
        debug_assert_eq!(out.len(), start + layout::CV_OFFSET);
        out.extend_from_slice(&a.cv_net().to_bytes());
        debug_assert_eq!(out.len(), start + layout::NULLIFIER_OFFSET);
        out.extend_from_slice(&a.nullifier().to_bytes());
        debug_assert_eq!(out.len(), start + layout::RK_OFFSET);
        out.extend_from_slice(&<[u8; 32]>::from(a.rk()));
        debug_assert_eq!(out.len(), start + layout::CMX_OFFSET);
        out.extend_from_slice(&a.cmx().to_bytes());
        let note = a.encrypted_note();
        debug_assert_eq!(out.len(), start + layout::EPK_OFFSET);
        out.extend_from_slice(&note.epk_bytes);
        debug_assert_eq!(out.len(), start + layout::ENC_CIPHERTEXT_OFFSET);
        out.extend_from_slice(&note.enc_ciphertext.0);
        debug_assert_eq!(out.len(), start + layout::OUT_CIPHERTEXT_OFFSET);
        out.extend_from_slice(&note.out_ciphertext);
    }
    let trailer = layout::trailer_offset(n).expect("at most MAX_ACTIONS_PER_TX actions");
    debug_assert_eq!(out.len(), trailer + layout::FLAGS_OFFSET);
    out.push(bundle.flag_byte());
    debug_assert_eq!(out.len(), trailer + layout::VALUE_BALANCE_OFFSET);
    out.extend_from_slice(&bundle.value_balance().to_le_bytes());
    debug_assert_eq!(out.len(), trailer + layout::ANCHOR_OFFSET);
    out.extend_from_slice(&bundle.anchor().to_bytes());
    let proof = bundle.authorization().proof().as_ref();
    debug_assert_eq!(out.len(), trailer + layout::PROOF_LENGTH_OFFSET);
    out.extend_from_slice(&(proof.len() as u32).to_le_bytes());
    debug_assert_eq!(out.len(), trailer + layout::PROOF_OFFSET);
    out.extend_from_slice(proof);
    for a in bundle.actions().iter() {
        out.extend_from_slice(&<[u8; 64]>::from(a.authorization()));
    }
    out.extend_from_slice(&<[u8; 64]>::from(bundle.authorization().binding_signature()));
    debug_assert_eq!(out.len(), encoded_size(n));
    out
}

struct Reader<'a> {
    bytes: &'a [u8],
    /// Length of the whole input, to know how far the reader got
    total: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, total: bytes.len() }
    }
    /// Offset of the next byte to read
    fn pos(&self) -> usize {
        self.total - self.bytes.len()
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.bytes.len() < n {
            return Err(DecodeError::Truncated);
        }
        let (head, rest) = self.bytes.split_at(n);
        self.bytes = rest;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        Ok(self.take(N)?.try_into().expect("length checked"))
    }
    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.array::<1>()?[0])
    }
}

/// Orchard's `from_bytes` functions return a constant-time option; turn it into a decode error.
fn point<T>(v: CtOption<T>, what: &'static str) -> Result<T, DecodeError> {
    Option::from(v).ok_or(DecodeError::BadPoint(what))
}

/// The new private coins (note commitments) an encoded payment creates, in action order.
/// Cheap: reads them at fixed offsets without decoding the rest. Use only on payments already checked
/// with [`decode`] (consensus checks every payment before accepting it).
pub fn note_commitments(encoded: &[u8]) -> Result<Vec<ExtractedNoteCommitment>, DecodeError> {
    let count = layout::ACTION_COUNT_OFFSET..layout::ACTION_COUNT_OFFSET + 2;
    let n = u16::from_le_bytes(encoded.get(count).ok_or(DecodeError::Truncated)?.try_into().expect("2 bytes")) as usize;
    if n == 0 || n > MAX_ACTIONS_PER_TX {
        return Err(DecodeError::BadActionCount(n));
    }
    (0..n)
        .map(|i| {
            let at = layout::action_offset(i).expect("at most MAX_ACTIONS_PER_TX actions") + layout::CMX_OFFSET;
            let bytes: [u8; 32] = encoded.get(at..at + 32).ok_or(DecodeError::Truncated)?.try_into().expect("32 bytes");
            point(ExtractedNoteCommitment::from_bytes(&bytes), "note commitment")
        })
        .collect()
}

/// Reads a private payment from bytes, rejecting anything malformed.
pub fn decode(bytes: &[u8]) -> Result<(Bundle<Authorized, i64>, SupportedPool), DecodeError> {
    let mut r = Reader::new(bytes);

    debug_assert_eq!(r.pos(), layout::POOL_VERSION_OFFSET);
    let pool = SupportedPool::from_byte(r.u8()?)?;
    debug_assert_eq!(r.pos(), layout::ACTION_COUNT_OFFSET);
    let n = u16::from_le_bytes(r.array()?) as usize;
    if n == 0 || n > MAX_ACTIONS_PER_TX {
        return Err(DecodeError::BadActionCount(n));
    }

    let mut actions_without_auth = Vec::with_capacity(n);
    for i in 0..n {
        let start = layout::action_offset(i).expect("at most MAX_ACTIONS_PER_TX actions");
        debug_assert_eq!(r.pos(), start + layout::CV_OFFSET);
        let cv_net = point(ValueCommitment::from_bytes(&r.array()?), "value commitment")?;
        debug_assert_eq!(r.pos(), start + layout::NULLIFIER_OFFSET);
        let nf = point(Nullifier::from_bytes(&r.array()?), "nullifier")?;
        debug_assert_eq!(r.pos(), start + layout::RK_OFFSET);
        let rk = VerificationKey::<SpendAuth>::try_from(r.array::<32>()?).map_err(|_| DecodeError::BadPoint("spend key"))?;
        debug_assert_eq!(r.pos(), start + layout::CMX_OFFSET);
        let cmx = point(ExtractedNoteCommitment::from_bytes(&r.array()?), "note commitment")?;
        debug_assert_eq!(r.pos(), start + layout::EPK_OFFSET);
        let epk_bytes = r.array()?;
        debug_assert_eq!(r.pos(), start + layout::ENC_CIPHERTEXT_OFFSET);
        let enc_ciphertext = NoteBytesData(r.array::<ENC_CIPHERTEXT_SIZE>()?);
        debug_assert_eq!(r.pos(), start + layout::OUT_CIPHERTEXT_OFFSET);
        let out_ciphertext = r.array::<{ layout::OUT_CIPHERTEXT_SIZE }>()?;
        let encrypted_note = TransmittedNoteCiphertext { epk_bytes, enc_ciphertext, out_ciphertext };
        let action = Action::from_parts(nf, rk, cmx, encrypted_note, cv_net, ()).map_err(|e| DecodeError::BadAction(e.to_string()))?;
        actions_without_auth.push(action);
    }

    let trailer = layout::trailer_offset(n).expect("at most MAX_ACTIONS_PER_TX actions");
    debug_assert_eq!(r.pos(), trailer + layout::FLAGS_OFFSET);
    let flags_byte = r.u8()?;
    let flags = Flags::from_byte(flags_byte, pool.bundle_version()).ok_or(DecodeError::BadFlags(flags_byte))?;
    debug_assert_eq!(r.pos(), trailer + layout::VALUE_BALANCE_OFFSET);
    let value_balance = i64::from_le_bytes(r.array()?);
    debug_assert_eq!(r.pos(), trailer + layout::ANCHOR_OFFSET);
    let anchor = point(Anchor::from_bytes(r.array()?), "anchor")?;

    debug_assert_eq!(r.pos(), trailer + layout::PROOF_LENGTH_OFFSET);
    let proof_len = u32::from_le_bytes(r.array()?) as usize;
    let expected = Proof::expected_proof_size(n);
    if proof_len != expected {
        return Err(DecodeError::BadProofLength { expected, actual: proof_len });
    }
    let proof = Proof::new(r.take(proof_len)?.to_vec());

    let mut actions = Vec::with_capacity(n);
    for action in actions_without_auth {
        let sig: Signature<SpendAuth> = Signature::from(r.array::<64>()?);
        actions.push(action.try_map(|()| Ok::<_, DecodeError>(sig))?);
    }
    let binding_signature: Signature<redpallas::Binding> = Signature::from(r.array::<64>()?);

    if !r.bytes.is_empty() {
        return Err(DecodeError::TrailingBytes(r.bytes.len()));
    }

    let actions = NonEmpty::from_vec(actions).expect("n >= 1 checked above");
    let bundle = Bundle::try_from_parts(
        actions,
        flags,
        value_balance,
        anchor,
        Authorized::from_parts(proof, binding_signature),
        pool.bundle_version(),
    )
    .map_err(|e| DecodeError::BadBundle(e.to_string()))?;
    Ok((bundle, pool))
}
