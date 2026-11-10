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
//!
//! The public half — the keys in the script — is all the L2 ever needs: it can
//! *check* that a mint proof carries a threshold of member signatures without ever
//! holding a secret. The secret half is [`FederationSigner`], kept in this module so
//! the two definitions of "the federation" cannot drift apart: the signer derives
//! its own public keys from its secret keys, and therefore signs for exactly the
//! federation whose script the watcher recognises as a deposit.

use secp256k1::{Message, PublicKey, SECP256K1, SecretKey, ecdsa::Signature};

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
        // Two members naming one key are one member wearing two hats: a 2-of-3
        // federation that lists the same key twice is satisfiable by a single
        // signature, so the lock would authorise less than its threshold claims.
        // That is a silent loss of the exact property the threshold exists for, so
        // it is refused here rather than discovered on the day it matters.
        for (index, key) in public_keys.iter().enumerate() {
            if public_keys[..index].contains(key) {
                return Err(format!(
                    "federation member {index} repeats an earlier member's public key: a duplicated key \
                     satisfies the threshold by itself"
                ));
            }
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

    /// Checks that `signatures` are a threshold of this federation's members'
    /// signatures over `digest`.
    ///
    /// This is the L2's half of the trust model, and the reason a mint proof is
    /// authority rather than a request: a digest is public, but only a holder of a
    /// member's secret key can produce a signature this accepts. A proof that
    /// carries none — or carries signatures from keys that are not in the
    /// federation — approves nothing, however well-formed it is.
    ///
    /// A signature is counted once per *distinct member*: the same member signing
    /// twice is one approval, exactly as `OP_CHECKMULTISIG` would insist on. The
    /// `OP_CHECKMULTISIG` ordering rule is deliberately not reproduced — order is a
    /// property of the L1 spend, and what authorises an L2 mint is the set of
    /// members behind the signatures, not the bytes' left-to-right shape.
    ///
    /// Keys that are not valid secp256k1 points cannot have signed anything, so a
    /// federation containing one never collects that member's approval: the check
    /// fails closed rather than treating an unparseable key as a match.
    ///
    /// # Errors
    ///
    /// The error names how many approvals were found and how many are needed. It
    /// deliberately says nothing about *which* signature failed, because the caller
    /// is a stranger presenting bytes.
    pub fn verify_approvals(&self, digest: [u8; 32], signatures: &[[u8; 64]]) -> Result<(), String> {
        if signatures.len() > MAX_KEYS {
            return Err(format!("a proof may carry at most {MAX_KEYS} federation signatures, got {}", signatures.len()));
        }
        let message = Message::from_digest(digest);
        let mut approvals = 0usize;
        for key in &self.public_keys {
            let Ok(member) = PublicKey::from_slice(key) else {
                continue;
            };
            let signed = signatures.iter().any(|signature| {
                Signature::from_compact(signature)
                    .map(|signature| SECP256K1.verify_ecdsa(&message, &signature, &member).is_ok())
                    .unwrap_or(false)
            });
            if signed {
                approvals += 1;
                if approvals >= usize::from(self.threshold) {
                    return Ok(());
                }
            }
        }
        Err(format!("the federation requires {} signature(s) and the proof carries {approvals} from its members", self.threshold))
    }
}

/// The signing half of a federation: the secret keys behind its public keys.
///
/// [`FederationLock`] is public by construction — it *is* the script every deposit
/// is locked under — so it can only ever say "these are the members". This type
/// holds the other half, and it is what turns a statement into an authorisation: a
/// [`MintProof`](crate::MintProof) is signed with it, and the L2 accepts the proof
/// only if a threshold of the federation's members signed the same commitment.
///
/// Keeping the halves separate is the point. The watcher carries a signer; the
/// contract, the test suite and anything else that only needs to *check* a proof
/// carry a lock, and no secret ever has to travel with the proof.
///
/// The public keys are *derived* from the secret keys, so a signer cannot describe a
/// federation it cannot sign for.
#[derive(Clone, PartialEq, Eq)]
pub struct FederationSigner {
    lock: FederationLock,
    secret_keys: Vec<[u8; 32]>,
}

impl FederationSigner {
    /// Builds the signing half from the members' secret keys.
    ///
    /// # Errors
    ///
    /// Every refusal is a federation that could not work: no members, more members
    /// than a script can name, a byte string that is not a secp256k1 secret key, or a
    /// threshold the key set cannot meet — see [`FederationLock::new`], which this
    /// delegates to and which also refuses a repeated public key.
    pub fn new(secret_keys: Vec<[u8; 32]>, threshold: u8) -> Result<Self, String> {
        if secret_keys.is_empty() {
            return Err("a federation must name at least one secret key".to_string());
        }
        if secret_keys.len() > MAX_KEYS {
            return Err(format!("a federation may name at most {MAX_KEYS} members, got {}", secret_keys.len()));
        }
        let mut public_keys = Vec::with_capacity(secret_keys.len());
        for (index, secret) in secret_keys.iter().enumerate() {
            let secret_key = SecretKey::from_slice(secret)
                .map_err(|err| format!("federation member {index} is not a secp256k1 secret key: {err}"))?;
            public_keys.push(PublicKey::from_secret_key(SECP256K1, &secret_key).serialize().to_vec());
        }
        let lock = FederationLock::new(public_keys, threshold)?;
        Ok(Self { lock, secret_keys })
    }

    /// The public half: the federation this signer signs for.
    pub fn lock(&self) -> &FederationLock {
        &self.lock
    }

    /// The member public keys, in script order.
    pub fn public_keys(&self) -> &[Vec<u8>] {
        self.lock.public_keys()
    }

    /// How many signatures an approval must carry.
    pub fn threshold(&self) -> u8 {
        self.lock.threshold()
    }

    /// The L1 script that locks an output under this federation.
    pub fn lock_script(&self) -> Vec<u8> {
        self.lock.lock_script()
    }

    /// Signs `digest` with exactly the threshold number of members.
    ///
    /// Signing is ECDSA over secp256k1 with a deterministic nonce, so the same digest
    /// produces the same signature bytes every time. That is a requirement, not an
    /// accident: two coordinators proving the same deposit must produce the same
    /// proof, or a restarted coordinator would disagree with its own earlier self
    /// about a mint both consider valid.
    ///
    /// The keys were validated in [`FederationSigner::new`], so a secret key that
    /// parsed there parses here.
    pub fn sign_threshold(&self, digest: [u8; 32]) -> Vec<[u8; 64]> {
        let message = Message::from_digest(digest);
        self.secret_keys
            .iter()
            .take(usize::from(self.lock.threshold()))
            .map(|secret| {
                let secret_key = SecretKey::from_slice(secret).expect("`new` validated every secret key");
                SECP256K1.sign_ecdsa(&message, &secret_key).serialize_compact()
            })
            .collect()
    }
}

impl std::fmt::Debug for FederationSigner {
    /// Renders the federation, never the keys.
    ///
    /// A derived `Debug` would print the secret keys, and debug-printed config ends up
    /// in a log line, a panic message or a bug report — which is exactly how a member's
    /// key would leak. The public half is printed instead, because it is public already.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FederationSigner")
            .field("lock", &self.lock)
            .field("secret_keys", &format!("<{} key(s) withheld>", self.secret_keys.len()))
            .finish()
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A 2-of-3 federation with the deterministic keys the bridge test suites use, so
    /// a fixture here and a fixture there describe one and the same federation.
    fn signer() -> FederationSigner {
        FederationSigner::new(vec![[0x11; 32], [0x22; 32], [0x33; 32]], 2).expect("a 2-of-3 federation is valid")
    }

    /// A digest standing in for a proof's commitment. Its value is irrelevant: what
    /// matters is that every signature below is over one specific digest, which is the
    /// only thing `verify_approvals` is asked about.
    fn digest() -> [u8; 32] {
        [0x5a; 32]
    }

    #[test]
    fn a_signer_derives_the_lock_its_secret_keys_name() {
        // The point of holding both halves in one type: the script a deposit is locked
        // under and the keys a proof is checked against cannot drift apart, because the
        // signer derives its public keys from the same secrets it signs with.
        let signer = signer();
        let derived = FederationLock::new(signer.public_keys().to_vec(), signer.threshold()).expect("the derived keys are a lock");
        assert_eq!(&derived, signer.lock(), "the derived lock is the signer's lock");
        assert_eq!(derived.lock_script(), signer.lock_script());
        assert!(signer.lock_script().len() <= crate::MAX_LOCK_SCRIPT_LEN, "the script fits the watcher's limit");
    }

    #[test]
    fn the_lock_script_is_the_threshold_form() {
        // M <pubkey>... N OP_CHECKMULTISIG, with M and N pushed as small integers.
        let script = signer().lock_script();
        assert_eq!(script[0], OP_1 + 1, "M = 2 is pushed as OP_2");
        assert_eq!(script[script.len() - 2], OP_1 + 2, "N = 3 is pushed as OP_3");
        assert_eq!(script[script.len() - 1], OP_CHECKMULTISIG, "and the script ends in a threshold check");
    }

    #[test]
    fn a_threshold_of_distinct_members_approves_the_digest() {
        let signer = signer();
        let signatures = signer.sign_threshold(digest());
        assert_eq!(signatures.len(), usize::from(signer.threshold()), "a proof carries exactly the threshold");
        assert!(signer.lock().verify_approvals(digest(), &signatures).is_ok(), "the federation's own approval passes");

        // More than the threshold is still an approval, and the order of the signatures
        // is not part of the statement: what authorises a mint is the set of members.
        let all_three = FederationSigner::new(vec![[0x11; 32], [0x22; 32], [0x33; 32]], 3).expect("a 3-of-3 federation is valid");
        let mut reversed = all_three.sign_threshold(digest());
        reversed.reverse();
        assert!(signer.lock().verify_approvals(digest(), &reversed).is_ok(), "three approvals satisfy a 2-of-3 lock");
    }

    #[test]
    fn one_signature_is_counted_once_however_often_it_is_repeated() {
        // A member signing twice is one member, exactly as `OP_CHECKMULTISIG` insists:
        // otherwise a single key could satisfy a threshold meant for two.
        let signer = signer();
        let signature = signer.sign_threshold(digest())[0];
        let err = signer.lock().verify_approvals(digest(), &[signature, signature]).expect_err("one member cannot be two approvals");
        assert!(err.contains("carries 1"), "the error counts distinct members: {err}");
    }

    #[test]
    fn signatures_over_another_digest_approve_nothing() {
        let signer = signer();
        let signatures = signer.sign_threshold([0x5a; 32]);
        let err = signer.lock().verify_approvals([0x5b; 32], &signatures).expect_err("an approval is over one statement only");
        assert!(err.contains("carries 0"), "nothing was approved for this digest: {err}");
    }

    #[test]
    fn another_federations_signatures_approve_nothing() {
        // The prover's key set is not the verifier's. This is the seam F-3 closed: a
        // perfectly well-formed proof from some other federation is worth nothing.
        let stranger = FederationSigner::new(vec![[0x44; 32], [0x55; 32], [0x66; 32]], 2).expect("a 2-of-3 federation is valid");
        let err = signer()
            .lock()
            .verify_approvals(digest(), &stranger.sign_threshold(digest()))
            .expect_err("keys outside the federation carry no authority");
        assert!(err.contains("carries 0"), "no member of this federation signed: {err}");
    }

    #[test]
    fn a_signature_that_is_not_a_signature_fails_closed() {
        // The bytes are public, so an attacker can always write 64 of them; what they
        // cannot do is make one verify. Both shapes below must count as nothing rather
        // than as a match.
        let lock = signer().lock().clone();
        assert!(lock.verify_approvals(digest(), &[[0u8; 64]; 2]).is_err(), "zeroes are not a signature");
        assert!(lock.verify_approvals(digest(), &[[0xffu8; 64]; 2]).is_err(), "nor is 0xff filler");
    }

    #[test]
    fn a_proof_may_carry_at_most_max_keys_signatures() {
        // The count is a `u8`, so this is not about the field's width: it is about never
        // letting a proof carry more approvals than a federation can have members.
        let signatures = vec![[0u8; 64]; MAX_KEYS + 1];
        let err = signer()
            .lock()
            .verify_approvals(digest(), &signatures)
            .expect_err("more signatures than members is not a federation's approval");
        assert!(err.contains("at most"), "the refusal names the limit: {err}");
    }

    #[test]
    fn a_key_that_is_not_a_curve_point_never_collects_an_approval() {
        // `new` checks a key's shape, not whether it is on the curve — a script engine
        // makes the same distinction. Such a member can never verify anything, so the
        // count fails closed instead of matching on bytes.
        let mut not_a_point = vec![0x02u8];
        not_a_point.extend_from_slice(&[0u8; 32]);
        let lock = FederationLock::new(vec![not_a_point], 1).expect("a 33-byte key is structurally a key");
        let err = lock
            .verify_approvals(digest(), &signer().sign_threshold(digest())[..1])
            .expect_err("a key that cannot verify signed nothing");
        assert!(err.contains("carries 0"), "the unparseable key counted for nothing: {err}");
    }

    #[test]
    fn a_federation_that_could_never_be_satisfied_is_refused() {
        let key = signer().public_keys().to_vec();
        assert!(FederationLock::new(Vec::new(), 1).is_err(), "an empty federation is not a federation");
        assert!(FederationLock::new(key.clone(), 0).is_err(), "a lock nobody has to sign is not a lock");
        assert!(FederationLock::new(key.clone(), 4).is_err(), "a threshold above the key count can never be met");
        assert!(FederationLock::new(vec![Vec::new()], 1).is_err(), "an empty key is not a key");
        assert!(
            FederationLock::new(vec![key[0].clone(), key[0].clone()], 2).is_err(),
            "a duplicated key satisfies the threshold by itself"
        );
        assert!(
            FederationLock::new(vec![key[0].clone(); MAX_KEYS + 1], 1).is_err(),
            "more keys than the opcode can push cannot be encoded"
        );
    }

    #[test]
    fn signing_the_same_digest_twice_yields_the_same_bytes() {
        // Deterministic nonces, so a restarted coordinator reproduces its own proof
        // instead of disagreeing with itself about a mint both consider valid.
        let signer = signer();
        assert_eq!(signer.sign_threshold(digest()), signer.sign_threshold(digest()), "signing is a function");
        assert_ne!(signer.sign_threshold(digest()), signer.sign_threshold([0x5b; 32]), "a different statement is a different proof");
    }

    #[test]
    fn the_signer_never_renders_its_secret_keys() {
        // A derived `Debug` would print the keys into whatever log line or panic message
        // renders the signer, which is how a member's key would leak.
        let rendered = format!("{:?}", signer());
        assert!(rendered.contains("withheld"), "the keys are reported as withheld: {rendered}");
        assert!(!rendered.contains(&"11".repeat(32)), "the secret key must not reach a log line: {rendered}");
    }
}
