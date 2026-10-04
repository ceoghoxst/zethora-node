//! Byte format for a private payment (an Orchard bundle) inside a Zethora transaction (ZTH-SPEC-006 §7.4).
//!
//! Layout (all integers little-endian), mirroring Zcash's v5 Orchard encoding with fixed-size counts:
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

/// Most actions allowed in one private payment (each action is one spend and/or one output).
pub const MAX_ACTIONS_PER_TX: usize = 16;

/// Bytes per action without its signature: cv 32 + nullifier 32 + rk 32 + cmx 32 + epk 32 + enc 580 + out 80.
pub const ACTION_SIZE: usize = 32 * 5 + ENC_CIPHERTEXT_SIZE + 80;

/// Encoded size of a private payment with `n` actions.
pub const fn encoded_size(n: usize) -> usize {
    1 + 2 + n * ACTION_SIZE + 1 + 8 + 32 + 4 + Proof::expected_proof_size(n) + n * 64 + 64
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
    out.push(pool as u8);
    out.extend_from_slice(&(n as u16).to_le_bytes());
    for a in bundle.actions().iter() {
        out.extend_from_slice(&a.cv_net().to_bytes());
        out.extend_from_slice(&a.nullifier().to_bytes());
        out.extend_from_slice(&<[u8; 32]>::from(a.rk()));
        out.extend_from_slice(&a.cmx().to_bytes());
        let note = a.encrypted_note();
        out.extend_from_slice(&note.epk_bytes);
        out.extend_from_slice(&note.enc_ciphertext.0);
        out.extend_from_slice(&note.out_ciphertext);
    }
    out.push(bundle.flag_byte());
    out.extend_from_slice(&bundle.value_balance().to_le_bytes());
    out.extend_from_slice(&bundle.anchor().to_bytes());
    let proof = bundle.authorization().proof().as_ref();
    out.extend_from_slice(&(proof.len() as u32).to_le_bytes());
    out.extend_from_slice(proof);
    for a in bundle.actions().iter() {
        out.extend_from_slice(&<[u8; 64]>::from(a.authorization()));
    }
    out.extend_from_slice(&<[u8; 64]>::from(bundle.authorization().binding_signature()));
    out
}

struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
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
    let n = u16::from_le_bytes(encoded.get(1..3).ok_or(DecodeError::Truncated)?.try_into().expect("2 bytes")) as usize;
    if n == 0 || n > MAX_ACTIONS_PER_TX {
        return Err(DecodeError::BadActionCount(n));
    }
    (0..n)
        .map(|i| {
            let at = 3 + i * ACTION_SIZE + 96; // cv 32, nullifier 32, rk 32, then cmx
            let bytes: [u8; 32] = encoded.get(at..at + 32).ok_or(DecodeError::Truncated)?.try_into().expect("32 bytes");
            point(ExtractedNoteCommitment::from_bytes(&bytes), "note commitment")
        })
        .collect()
}

/// Reads a private payment from bytes, rejecting anything malformed.
pub fn decode(bytes: &[u8]) -> Result<(Bundle<Authorized, i64>, SupportedPool), DecodeError> {
    let mut r = Reader { bytes };

    let pool = SupportedPool::from_byte(r.u8()?)?;
    let n = u16::from_le_bytes(r.array()?) as usize;
    if n == 0 || n > MAX_ACTIONS_PER_TX {
        return Err(DecodeError::BadActionCount(n));
    }

    let mut actions_without_auth = Vec::with_capacity(n);
    for _ in 0..n {
        let cv_net = point(ValueCommitment::from_bytes(&r.array()?), "value commitment")?;
        let nf = point(Nullifier::from_bytes(&r.array()?), "nullifier")?;
        let rk = VerificationKey::<SpendAuth>::try_from(r.array::<32>()?).map_err(|_| DecodeError::BadPoint("spend key"))?;
        let cmx = point(ExtractedNoteCommitment::from_bytes(&r.array()?), "note commitment")?;
        let encrypted_note = TransmittedNoteCiphertext {
            epk_bytes: r.array()?,
            enc_ciphertext: NoteBytesData(r.array::<ENC_CIPHERTEXT_SIZE>()?),
            out_ciphertext: r.array()?,
        };
        let action =
            Action::from_parts(nf, rk, cmx, encrypted_note, cv_net, ()).map_err(|e| DecodeError::BadAction(e.to_string()))?;
        actions_without_auth.push(action);
    }

    let flags_byte = r.u8()?;
    let flags = Flags::from_byte(flags_byte, pool.bundle_version()).ok_or(DecodeError::BadFlags(flags_byte))?;
    let value_balance = i64::from_le_bytes(r.array()?);
    let anchor = point(Anchor::from_bytes(r.array()?), "anchor")?;

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
