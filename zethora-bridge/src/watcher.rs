//! The L1 side: watching for locks and turning them into mint proofs.
//!
//! The watcher is the only component that reads L1, and the only one that can
//! authorise a mint. It therefore does both halves of the job:
//!
//! * [`L1Watcher::scan_for_locks`] decides what counts as a deposit at all;
//! * [`L1Watcher::generate_mint_proof`] produces the artifact the L2 contract
//!   accepts as authority to credit a balance.
//!
//! Splitting them is what keeps the trust model honest. Scanning is a pure
//! function of block data: no I/O, no clock, no local state, so two watchers
//! looking at the same blocks cannot disagree about what was deposited. Proof
//! generation is the only place that will ever talk to a prover, and the proof it
//! returns is verified by the contract rather than trusted.

use std::collections::HashSet;
use std::fmt::Write as _;

use alloy_primitives::{Address, B256, U256, keccak256};

use crate::contract::mint_calldata;
use crate::{FederationLock, FederationSigner, MAX_KEYS, PROOF_DOMAIN};

// ---------------------------------------------------------------------------
// Block encoding
// ---------------------------------------------------------------------------

/// Magic bytes every block passed to [`L1Watcher::scan_for_locks`] starts with.
///
/// The encoding needs a header for one reason above all others: a watcher fed
/// bytes it cannot recognise must fail rather than scan them hopefully. A wrong
/// encoding silently read as "no deposits" would stall the bridge, and a wrong
/// encoding read as *garbage* deposits would mint unbacked wZTHR; the magic makes
/// "this is not a block" an error instead of a coin flip.
pub const BLOCK_MAGIC: [u8; 4] = *b"ZBD1";
/// The most `LockEvent`s one block may cost a scan, whatever it claims.
///
/// [`MAX_OUTPUTS_PER_BLOCK`] bounds how many records a block may *contain*, which
/// bounds the work only if a record is as large as a real one. It is not: the
/// cheapest hostile record carries an empty script and occupies `MIN_OUTPUT_LEN`
/// bytes, so a block can pack several times more records than its byte size
/// suggests, and `scan_for_locks` pays a `LockEvent` and a dedupe entry for each
/// one — before the dedupe that collapses them ever runs.
///
/// The scan therefore needs a limit that is not a function of the encoding. This
/// one is expressed in records, not bytes: no block, however densely it is
/// encoded or however often it repeats the same outpoint, can make a scan do more
/// than a constant amount of work. It is deliberately equal to
/// [`MAX_OUTPUTS_PER_BLOCK`], so every block the decoder accepts can still be
/// scanned in full; the bound exists to make that constant explicit and enforced
/// at the point the per-record allocation happens, rather than inferred from a
/// record size an attacker chooses.
pub const MAX_LOCKS_PER_BLOCK: usize = 1000;
/// A single output inside a block handed to the watcher.
///
/// The fields mirror the parts of an L1 transaction output the bridge cares
/// about. Everything else about an output — its covenant, its version, the
/// transaction's other outputs — is irrelevant to the deposit: a deposit is
/// defined by *which UTXO it is* and *how much it holds*, and nothing more.
///
/// "Which UTXO" is the transaction that created it ([`BlockOutput::txid`]) plus
/// its index inside that transaction ([`BlockOutput::output_index`]). The block a
/// transaction was mined in is not part of that name: a reorg moves a transaction
/// between blocks without changing the coins it created, so an identity that has
/// to survive a reorg cannot be keyed on the block (see [`LockEvent::lock_id`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockOutput {
    /// Index of the transaction within the block.
    ///
    /// Reported, and used to name a deposit in errors, but deliberately *not* part
    /// of the deposit's identity: it is a position inside one particular block, and
    /// a reorg re-includes the same transaction at a different position.
    pub tx_index: u16,
    /// Index of the output within that transaction.
    pub output_index: u16,
    /// The id of the transaction that created the output.
    ///
    /// The reorg-invariant half of the UTXO's name: a txid commits to the
    /// transaction's contents, so every block that includes the transaction
    /// includes *this* txid, and the identity derived from it (see
    /// [`LockEvent::lock_id`]) is the same wherever the transaction lands.
    pub txid: [u8; 32],
    /// The block this output first appeared in.
    pub block_height: u64,
    /// Hash of the block this output first appeared in.
    ///
    /// Reporting only. A height is a *position* on whichever chain happens to be
    /// canonical, so it is not a stable name for a block — and a hash is not a
    /// stable name for a *deposit* either, because a reorg gives the same
    /// transaction a new block and therefore a new hash. It is carried alongside
    /// the height as a fact about the chain's current shape, and kept out of the
    /// deposit's identity for exactly that reason (see [`LockEvent::lock_id`]).
    pub block_hash: [u8; 32],
    /// The locking script, i.e. the script that must be satisfied to spend it.
    pub script: Vec<u8>,
    /// Value in the smallest unit of ZTHR.
    pub amount: U256,
    /// The L2 address that receives the wZTHR, recorded in the depositor's output
    /// so that the deposit is not merely "somebody's".
    pub recipient: Address,
    /// The bridge fee collected when the deposit was made, in the same unit.
    pub fee: U256,
    /// Whether the output has already been spent.
    ///
    /// A spent output is not a lock: the federation may have released it, so it no
    /// longer backs anything on L2. It is still reported, because "this deposit
    /// was released" is information a coordinator needs — it is what stops a
    /// second mint after a refund — and because a watcher that silently dropped
    /// spent outputs would be indistinguishable from one that had lost them.
    pub spent: bool,
}

// ---------------------------------------------------------------------------
// Lock events
// ---------------------------------------------------------------------------

/// Whether a lock still backs an L2 balance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockStatus {
    /// The output is unspent: the funds are held by the bridge.
    Live,
    /// The output has been spent: released by the federation, so it no longer
    /// backs an L2 balance.
    Spent,
}

/// One deposit found on L1.
///
/// This is the unit the whole bridge is built on: the watcher produces it, the
/// proof commits to it, and the mint credits exactly its
/// [`LockEvent::mintable_amount`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockEvent {
    /// Height of the block the lock was confirmed in.
    ///
    /// Reported and committed to by the proof, but deliberately *not* part of the
    /// deposit's identity: see [`LockEvent::lock_id`].
    pub block_height: u64,
    /// Hash of the block the lock was confirmed in.
    ///
    /// Reporting only, for the same reason as the height: a reorg rewrites the
    /// block a transaction is in, so its hash is a fact about the chain's current
    /// shape rather than about the deposit.
    pub block_hash: [u8; 32],
    /// The id of the transaction that created the locked output.
    ///
    /// The reorg-invariant half of the deposit's identity (see
    /// [`LockEvent::lock_id`]): the same transaction keeps its txid whichever block
    /// carries it, so the deposit keeps its id across a fork.
    pub txid: [u8; 32],
    /// The outpoint of the locked output, `(tx_index, output_index)`.
    ///
    /// `output_index` is the second half of the deposit's identity, being the
    /// UTXO's own index inside its transaction. `tx_index` is where that
    /// transaction sat in the block the watcher was shown, so it is reported and
    /// kept out of the identity.
    pub outpoint: (u16, u16),
    /// Value locked, in the smallest unit of ZTHR.
    pub amount: U256,
    /// The L2 account that receives the wZTHR.
    pub recipient: Address,
    /// The bridge fee withheld from the minted amount.
    pub fee: U256,
    /// Whether the output is still unspent.
    pub status: LockStatus,
}

impl LockEvent {
    /// The deposit's identity: a hash of its transaction id and output index.
    ///
    /// The id is what the L2 contract remembers to stop a deposit minting twice,
    /// so it must be unique per output and stable across watchers — and across
    /// reorganisations, which is the property that makes it a *deposit's* name
    /// rather than an event's.
    ///
    /// A UTXO is named by the transaction that created it and its index inside that
    /// transaction, so the preimage is exactly
    ///
    /// ```text
    /// keccak256( txid || output_index.to_be_bytes() )
    /// ```
    ///
    /// Nothing about the block goes in: not its height, not its hash, and not the
    /// transaction's index within it. All three describe *where a transaction was
    /// mined*, and that is precisely what a reorg rewrites — the same transaction
    /// re-included one block later, at a new height, a new position and under a new
    /// hash, is still the same coins. An id keyed on any of them therefore names an
    /// event rather than a deposit: re-inclusion produces a fresh id, the contract's
    /// replay marker looks untouched, and one L1 lock mints twice. The txid, by
    /// contrast, commits to the transaction's contents and cannot change without
    /// changing what was locked, so the pair `(txid, output_index)` is the identity
    /// of a UTXO and is reorg-invariant.
    ///
    /// The height and hash stay on [`LockEvent::block_height`] and
    /// [`LockEvent::block_hash`] for reporting and for the proof statement, where
    /// they are claims about *where* the deposit was seen rather than *which*
    /// deposit it is.
    pub fn lock_id(&self) -> [u8; 32] {
        let mut preimage = Vec::with_capacity(32 + 2);
        preimage.extend_from_slice(&self.txid);
        preimage.extend_from_slice(&self.outpoint.1.to_be_bytes());
        keccak256(&preimage).0
    }

    /// The amount actually minted to the recipient: the locked value less the
    /// bridge fee.
    ///
    /// The fee is subtracted here rather than at mint time so that the amount is
    /// part of the proof. A coordinator then cannot quietly shave a deposit by
    /// presenting a proof for a smaller amount, because the proof commits to the
    /// exact figure it was made for.
    pub fn mintable_amount(&self) -> U256 {
        self.amount.saturating_sub(self.fee)
    }
}

/// Outcome of scanning one block.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScanReport {
    /// Every lock seen, whether live or spent.
    pub locks: Vec<LockEvent>,
}

impl ScanReport {
    /// The locks that are still live, i.e. the ones that can back a mint.
    pub fn live(&self) -> impl Iterator<Item = &LockEvent> {
        self.locks.iter().filter(|lock| lock.status == LockStatus::Live)
    }
}

// ---------------------------------------------------------------------------
// Proofs
// ---------------------------------------------------------------------------

/// A mock deposit proof: the artifact that lets the L2 trust an L1 lock.
///
/// # What is mocked, and what is not
///
/// In production this is an SP1 proof about the L1 UTXO set. Here it is a
/// keccak256 commitment over the same statement, computed by the watcher and
/// re-computed by the contract:
///
/// > "deposit `lock_id`, worth `amount`, confirmed in block `block_height`, for
/// > `recipient` on chain `chain_id`, under [`PROOF_DOMAIN`]".
///
/// The chain is part of that statement but **not part of the wire format**. There is
/// no `chain_id` field for a proof to *claim*: the verifier supplies the chain id it
/// is actually running — [`zethora_evm::EvmExecutor::chain_id`] — and re-computes the
/// commitment over it. A proof is therefore good on exactly one chain, the one it was
/// made for, and it cannot be re-labelled for another, because the expected commitment
/// is derived from the running chain rather than from anything the proof carries.
///
/// Building it this way, rather than as an opaque blob, keeps the *statement* the
/// real one. Replacing the keccak hash with an SP1 proof later changes who can
/// produce the bytes, not what they claim — the contract's checks and the calldata
/// do not move.
///
/// # What authorises a mint
///
/// A commitment on its own is not authority. Its preimage is public: the deposit, the
/// amount, the height, the recipient and the chain are all visible on L1 and in the
/// calldata, so *anyone* can compute the hash for a deposit that does not exist — a
/// hand-crafted "proof" for a fictitious lock, minting a fortune to the attacker.
/// The hash says what the mint is about; it never says the federation approved it.
///
/// So the proof carries that too: [`MintProof::signatures`] holds a threshold of
/// federation members' secp256k1 signatures over the commitment itself. The contract
/// accepts a proof only when the commitment re-computes to the statement being minted
/// *and* a threshold of the federation's keys signed it. An attacker can still compute
/// any commitment they like; what they cannot do is produce a member's signature over
/// one, and the contract checks exactly that
/// ([`FederationLock::verify_approvals`]). This is what stops an unbacked mint: the
/// deposit statement is public, but the approval is not.
///
/// The signatures are over the *commitment*, not over the individual fields, so the
/// chain id, recipient, amount, height and deposit are all covered by one signature:
/// moving a proof to another chain, recipient or amount invalidates the signature as
/// well as the hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintProof {
    /// The deposit being proven.
    pub lock_id: [u8; 32],
    /// The amount minted to the recipient.
    pub amount: U256,
    /// The L1 height the deposit was confirmed at.
    pub block_height: u64,
    /// The commitment the contract checks.
    ///
    /// It commits to the chain the proof was made for even though the chain is not a
    /// field of the proof: the value is good on that one chain only, and which chain
    /// that is can only be decided by the verifier, never by the bytes.
    pub commitment: [u8; 32],
    /// The federation's signatures over [`MintProof::commitment`], in compact form.
    ///
    /// At least a threshold of them, from distinct members, or the proof authorises
    /// nothing. They are what makes the proof unforgeable rather than merely
    /// well-formed: the comment above explains why the commitment alone is not enough.
    pub signatures: Vec<[u8; 64]>,
}

/// Byte length of a [`MintProof`]'s four scalar fields.
const PROOF_FIELDS_LEN: usize = 32 + 32 + 8 + 32;

/// Byte length of the signature-count byte that prefixes the approvals.
const SIGNATURE_COUNT_LEN: usize = 1;

/// Byte length of one compact secp256k1 signature.
const SIGNATURE_LEN: usize = 64;

impl MintProof {
    /// The domain-separated commitment for one deposit on `chain_id`.
    ///
    /// Every field the mint depends on goes in, the recipient and the amount
    /// included: omitting either would let a proof made for one deposit be
    /// replayable as a proof for a bigger one, or for a different account. The chain
    /// id is in the preimage for the same reason, and it is the one input the proof
    /// does not carry: the verifier fills it in from the executor it is running
    /// under. That is what binds a proof to one chain without giving the proof a say
    /// in which one.
    pub fn commitment_for(lock_id: [u8; 32], amount: U256, block_height: u64, chain_id: u64, recipient: Address) -> [u8; 32] {
        let mut preimage = Vec::with_capacity(PROOF_DOMAIN.len() + PROOF_FIELDS_LEN);
        preimage.extend_from_slice(PROOF_DOMAIN);
        preimage.extend_from_slice(&lock_id);
        preimage.extend_from_slice(&amount.to_be_bytes::<32>());
        preimage.extend_from_slice(&block_height.to_be_bytes());
        preimage.extend_from_slice(&chain_id.to_be_bytes());
        preimage.extend_from_slice(recipient.as_slice());
        keccak256(&preimage).0
    }

    /// Builds a proof for `lock`, minting to `recipient` **on `chain_id`**, signed by
    /// `federation`.
    ///
    /// `chain_id` must be the chain the mint will be applied to — the executor's own
    /// [`zethora_evm::EvmExecutor::chain_id`], never a compile-time constant. A proof
    /// made for a different chain is not a proof on this one: the contract re-computes
    /// the commitment over *its* chain id, so a mismatch — including one a
    /// mis-configured coordinator introduces — fails closed instead of minting on the
    /// wrong network.
    ///
    /// The federation signer is what makes the result authority rather than a
    /// suggestion, and it is a parameter for the same reason: a caller that does not
    /// hold a threshold of the federation's secret keys cannot construct a proof the
    /// contract will accept. That is the whole point of the type — the commitment is
    /// computable by anyone, so the constructor asks for the one thing that is not.
    ///
    /// The signer's public keys are not checked against the deposit here. They do not
    /// need to be: `verify` checks the signatures against the federation the verifier
    /// trusts, so a proof signed by some *other* federation simply fails there.
    pub fn new(lock: &LockEvent, chain_id: u64, recipient: Address, federation: &FederationSigner) -> Self {
        let lock_id = lock.lock_id();
        let amount = lock.mintable_amount();
        let commitment = Self::commitment_for(lock_id, amount, lock.block_height, chain_id, recipient);
        Self { lock_id, amount, block_height: lock.block_height, commitment, signatures: federation.sign_threshold(commitment) }
    }

    /// The wire form of the proof: what travels in the `bytes proof` argument.
    ///
    /// A fixed layout, because the contract decodes it positionally:
    /// `domain || lock_id || amount || block_height || commitment || count || signature*`.
    ///
    /// The chain id is deliberately absent. It is committed to *inside* the
    /// commitment, so a proof carries the chain it was made for without carrying a
    /// field that could be edited to match a different one.
    ///
    /// The signature block is length-prefixed rather than fixed-width because the
    /// threshold is the federation's, not the format's: a 2-of-3 proof carries two
    /// signatures and a 3-of-5 proof three, and the verifier does not need to be told
    /// the federation separately to know how many bytes to read. The count makes the
    /// length self-describing, and [`MintProof::decode`] requires the count and the
    /// remaining bytes to agree exactly, so there is no room to smuggle trailing data.
    pub fn encode(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(PROOF_DOMAIN.len() + PROOF_FIELDS_LEN + SIGNATURE_COUNT_LEN + self.signatures.len() * SIGNATURE_LEN);
        out.extend_from_slice(PROOF_DOMAIN);
        out.extend_from_slice(&self.lock_id);
        out.extend_from_slice(&self.amount.to_be_bytes::<32>());
        out.extend_from_slice(&self.block_height.to_be_bytes());
        out.extend_from_slice(&self.commitment);
        // Real proofs never exceed `MAX_KEYS` signatures — the federation cannot have
        // more members — and a proof that did would be refused by `verify` before the
        // count mattered, so the cast cannot misdescribe an acceptable proof.
        out.push(self.signatures.len() as u8);
        for signature in &self.signatures {
            out.extend_from_slice(signature);
        }
        out
    }

    /// Parses the wire form back into a proof.
    ///
    /// The domain separator is checked, not merely skipped: a byte string that is
    /// not a proof for *this* bridge is not a proof at all.
    ///
    /// The signature block must be exactly as long as its count says, and the count
    /// must be at least one. Both refusals are about the same thing: an unsigned proof
    /// is not a proof, so a decoder that accepted one would only move the rejection
    /// further from the bytes that caused it.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let header = PROOF_DOMAIN.len() + PROOF_FIELDS_LEN;
        let minimum = header + SIGNATURE_COUNT_LEN;
        if bytes.len() < minimum {
            return Err(format!("proof must be at least {minimum} bytes, got {}", bytes.len()));
        }
        if bytes[..PROOF_DOMAIN.len()] != *PROOF_DOMAIN {
            return Err("proof is not for this bridge: domain separator mismatch".to_string());
        }
        let count = usize::from(bytes[header]);
        if count == 0 {
            return Err("proof carries no federation signature: an unsigned proof authorises nothing".to_string());
        }
        if count > MAX_KEYS {
            return Err(format!("proof carries {count} signatures, more than the {MAX_KEYS} members a federation may have"));
        }
        let expected = minimum + count * SIGNATURE_LEN;
        if bytes.len() != expected {
            return Err(format!("proof must be {expected} bytes for {count} signature(s), got {}", bytes.len()));
        }
        let mut signatures = Vec::with_capacity(count);
        for index in 0..count {
            let start = minimum + index * SIGNATURE_LEN;
            signatures.push(bytes[start..start + SIGNATURE_LEN].try_into().expect("64-byte slice"));
        }
        let fields = &bytes[PROOF_DOMAIN.len()..];
        Ok(Self {
            lock_id: fields[..32].try_into().expect("32-byte slice"),
            amount: U256::from_be_bytes::<32>(fields[32..64].try_into().expect("32-byte slice")),
            block_height: u64::from_be_bytes(fields[64..72].try_into().expect("8-byte slice")),
            commitment: fields[72..104].try_into().expect("32-byte slice"),
            signatures,
        })
    }

    /// Verifies that the proof names `recipient` for `amount` on `chain_id`, and that
    /// `federation` authorised it.
    ///
    /// This is the whole of the contract's authority check. It is deliberately a
    /// re-computation rather than a lookup: a proof is good only for the exact
    /// deposit it was made for, on the exact chain it was made for, and the contract
    /// keeps no list of valid proofs that could drift out of date.
    ///
    /// `chain_id` is the chain the *verifier* is running — `contract::mint` passes
    /// [`zethora_evm::EvmExecutor::chain_id`] — and it is not something a proof gets
    /// to assert. It is hashed into the expected commitment, so a proof made for
    /// chain `1` fails here on a chain-`2600` executor even though every field of its
    /// wire form parses, and no rewrite of those fields can relabel it, because the
    /// chain id is not one of them.
    ///
    /// Two things have to hold, and the second is the one that makes a mint
    /// unbacked-mint-proof rather than merely well-formed:
    ///
    /// * the commitment must be the one this deposit, amount, height, recipient and
    ///   chain produce — which anyone can compute, so on its own it proves nothing;
    /// * a threshold of the federation's members must have signed *that* commitment.
    ///
    /// The second check is what an attacker cannot satisfy: they can write down any
    /// statement they like and hash it exactly as this function does, but the
    /// signature over the hash requires a member's secret key. A proof missing its
    /// signatures, or carrying signatures by keys outside the federation, or signed
    /// over a different commitment, fails here and nothing is minted.
    ///
    /// The error is deliberately one message for every way the commitment can fail:
    /// the verifier can tell that the statement does not hold on this chain, but not
    /// which input was wrong, and saying more would only help an attacker probe.
    pub fn verify(&self, federation: &FederationLock, chain_id: u64, recipient: Address, amount: U256) -> Result<(), String> {
        if self.amount != amount {
            return Err(format!("proof commits to {} but the call mints {amount}", self.amount));
        }
        let expected = Self::commitment_for(self.lock_id, amount, self.block_height, chain_id, recipient);
        if expected != self.commitment {
            return Err(format!(
                "proof commitment does not match the deposit statement on chain {chain_id}: the proof \
                 commits to a different chain, recipient, height or deposit"
            ));
        }
        // Checked after the commitment, not before: a proof that does not even describe
        // this mint is rejected without spending the verification work, and the
        // signature check then only ever runs on a statement that is true.
        federation
            .verify_approvals(self.commitment, &self.signatures)
            .map_err(|err| format!("proof is not authorised by the federation: {err}"))
    }

    /// The `bytes32` key the L2 remembers the deposit under.
    pub fn lock_key(&self) -> B256 {
        B256::from(self.lock_id)
    }

    /// The calldata that mints this proof to `recipient`.
    pub fn calldata(&self, recipient: Address) -> Vec<u8> {
        mint_calldata(recipient, self.amount, &self.encode())
    }
}

// ---------------------------------------------------------------------------
// The watcher
// ---------------------------------------------------------------------------

/// Watches L1 for deposits and turns them into L2 mints.
///
/// A watcher holds no chain state: everything it needs is either in the blocks it
/// is given or in its configuration (the federation whose lock script defines a
/// deposit). That is what lets a coordinator restart one, or run three, without
/// any of them disagreeing about what was deposited.
///
/// It holds the federation's *signing* half, because producing a proof the L2 will
/// accept means signing it. Scanning needs only the public lock script — which is
/// derived from the signer — so the split costs nothing here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct L1Watcher {
    federation: FederationSigner,
    lock_script: Vec<u8>,
    contract: Address,
}

impl L1Watcher {
    /// Creates a watcher for `federation`, minting into `contract` on L2.
    ///
    /// The lock script is not a parameter: it is *derived* from the federation, so
    /// there is no way to configure a watcher that scans for a script its own
    /// federation cannot spend. A config file cannot get this wrong, because there
    /// is nothing in it to get wrong.
    ///
    /// `federation` is the signing half, because a watcher that could scan but not
    /// sign would be a watcher whose proofs the contract rejects.
    pub fn new(federation: FederationSigner, contract: Address) -> Self {
        let lock_script = federation.lock_script();
        Self { federation, lock_script, contract }
    }

    /// The script whose outputs are treated as deposits.
    pub fn lock_script(&self) -> &[u8] {
        &self.lock_script
    }

    /// The federation that can spend a locked output.
    pub fn federation(&self) -> &FederationLock {
        self.federation.lock()
    }

    /// The federation's signing half, i.e. what signs the proofs this watcher mints.
    pub fn signer(&self) -> &FederationSigner {
        &self.federation
    }

    /// The L2 contract deposits are minted into.
    pub fn contract(&self) -> Address {
        self.contract
    }

    /// Scans one L1 block for outputs locked by the federation.
    ///
    /// `block_data` is the bridge's block encoding (see [`decode_block`]): a
    /// [`BLOCK_MAGIC`] header, the block height, the block hash, an output count,
    /// then one record per output.
    ///
    /// Returns every lock found, both live and spent, because the two states mean
    /// different things to a coordinator. Nothing is filtered silently: malformed
    /// input is an error, and an output not locked by *this* federation is simply
    /// not a lock.
    pub fn scan_for_locks(&self, block_data: &[u8]) -> Result<Vec<LockEvent>, String> {
        let block = decode_block(block_data)?;
        let mut seen = HashSet::new();
        let mut locks = Vec::new();
        let mut processed = 0usize;
        for output in block {
            if locks.len() >= MAX_LOCKS_PER_BLOCK {
                return Err("memory bomb: block contains too many locks".to_string());
            }
            // A block of duplicate records is the cheapest memory bomb against a
            // scan: every copy is decoded and costed, while the dedupe collapses
            // them to one lock only *after* the memory is spent. The cap makes the
            // per-block work a constant, so no block can buy unbounded processing
            // however it is encoded. It is checked before any per-record work, and
            // exactly at the limit, so an honest block holding the maximum number
            // of real locks is never rejected.
            processed += 1;
            if processed > MAX_LOCKS_PER_BLOCK {
                return Err(format!(
                    "block holds more than the {MAX_LOCKS_PER_BLOCK}-lock scan limit: \
                     a block of repeated records is refused rather than expanded"
                ));
            }
            if output.script != self.lock_script {
                continue;
            }
            // A repeated UTXO inside one block is not two deposits. Ignoring the
            // repeat keeps a crafted block from minting the same output twice. The
            // dedupe key is the deposit's own name — its transaction and the
            // output's index inside it — rather than its position in the block, so
            // two records describing one UTXO collapse however the block is
            // ordered or however the transaction's index is reported.
            if !seen.insert((output.txid, output.output_index)) {
                continue;
            }
            // An output whose fee exceeds its value cannot be a deposit. It is
            // refused rather than clamped: `mintable_amount` would saturate to
            // zero and quietly turn a deposit into nothing.
            if output.amount < output.fee {
                return Err(format!(
                    "output {}/{}: fee {} exceeds the amount {}",
                    output.tx_index, output.output_index, output.fee, output.amount
                ));
            }
            locks.push(LockEvent {
                block_height: output.block_height,
                block_hash: output.block_hash,
                txid: output.txid,
                outpoint: (output.tx_index, output.output_index),
                amount: output.amount,
                recipient: output.recipient,
                fee: output.fee,
                status: if output.spent { LockStatus::Spent } else { LockStatus::Live },
            });
        }
        Ok(locks)
    }

    /// Produces the proof that authorises minting `lock_event` on L2.
    ///
    /// # This is the mock, and this is no longer where the soundness lives
    ///
    /// The real implementation hands the lock to the SP1 prover (`zethora-prover`)
    /// and gets back a proof that the output exists in the L1 UTXO set, is
    /// confirmed to the federation's depth, and is unspent. Until the L1 light
    /// client is wired up there is no statement to prove, so the "proof" is the
    /// commitment [`MintProof`] describes — the same statement, without the
    /// cryptographic evidence.
    ///
    /// What is *not* mocked any more is the authorisation. The proof is signed by a
    /// threshold of the federation, and the contract checks those signatures against
    /// the federation it holds, so a proof cannot be hand-crafted by someone who only
    /// knows the statement (see [`MintProof`]). The gap that remains is the size of
    /// the statement — "this deposit exists and is unspent" is asserted by the
    /// watcher rather than proven from L1 data — not the ability to mint without the
    /// federation's consent.
    ///
    /// The refusal cases are real, and they are the ones that matter: a spent lock
    /// backs nothing, a zero mint is meaningless, and an amount the L2 cannot
    /// represent is rejected here rather than at mint time.
    ///
    /// `chain_id` is the L2 the mint will be applied to, and it is a parameter rather
    /// than a constant because the node's chain id is configuration: a proof is signed
    /// for the chain it is going to, and the contract will only accept it there.
    pub fn generate_mint_proof(&self, lock_event: &LockEvent, chain_id: u64) -> Result<MintProof, String> {
        if lock_event.status != LockStatus::Live {
            return Err(format!(
                "cannot prove a spent lock: output {}/{} at height {} is no longer held by the bridge",
                lock_event.outpoint.0, lock_event.outpoint.1, lock_event.block_height
            ));
        }
        let amount = lock_event.mintable_amount();
        if amount.is_zero() {
            return Err(format!(
                "deposit {}/{} leaves nothing to mint after a fee of {}",
                lock_event.outpoint.0, lock_event.outpoint.1, lock_event.fee
            ));
        }
        if amount > crate::AMOUNT_CEILING {
            return Err(format!("deposit amount {amount} exceeds the bridge's per-mint ceiling {}", crate::AMOUNT_CEILING));
        }
        Ok(MintProof::new(lock_event, chain_id, lock_event.recipient, &self.federation))
    }
}

// ---------------------------------------------------------------------------
// Block decoding
// ---------------------------------------------------------------------------

/// Every output occupies at least this many bytes: the two indices, the
/// transaction id, the flags, a four-byte script length, amount, fee and
/// recipient, with an empty script.
const MIN_OUTPUT_LEN: usize = 2 + 2 + 32 + 1 + 4 + 8 + 8 + 20;

/// Every output occupies at most this many bytes, given the script-length limit.
///
/// `MIN_OUTPUT_LEN` alone bounds the *number* of outputs a block can claim, but
/// not the memory they cost, and it is a floor rather than a true lower bound: a
/// real lock script is 200+ bytes, so a legitimate record is four times
/// `MIN_OUTPUT_LEN`. A decoder bounded only by bytes therefore pays many times
/// its input in `BlockOutput`s.
///
/// The real bound is a count. [`MAX_OUTPUTS_PER_BLOCK`] caps the records
/// independently of how they are encoded, so no combination of script sizes and
/// counts can make one block's scan allocate without limit.
pub const MAX_OUTPUTS_PER_BLOCK: usize = 4_096;

/// The number of outputs a block of `len` bytes could hold at their smallest.
///
/// Derived from the input rather than chosen: a block carries at most
/// `len / MIN_OUTPUT_LEN` records, so this caps the `Vec` reservation at a size
/// the input itself justifies. Using the smallest record size keeps the cap
/// generous — a block of maximal scripts is capped four times higher than it
/// could ever fill — so the limit constrains hostile blocks without ever
/// rejecting or over-reserving for an honest one.
fn max_outputs_for(len: usize) -> usize {
    len / MIN_OUTPUT_LEN
}

/// The error label for one field of one record: `"output 3: script"`.
///
/// Kept in one place so every truncation error reads the same way. The label is
/// built per read, which is a small allocation per field, but it is bounded:
/// [`MAX_OUTPUTS_PER_BLOCK`] caps how many records a block may contain, so the
/// number of labels a decode can produce is capped with it.
fn record_field(index: usize, field: &str) -> String {
    let mut label = String::with_capacity(32);
    let _ = write!(label, "output {index}: {field}");
    label
}

/// Decodes the bridge's block encoding into its outputs.
///
/// # Layout
///
/// ```text
/// "ZBD1"                    magic
/// u64  block height         big-endian
/// [u8; 32] block hash       the hash of the block being described
/// u32  output count         little-endian
/// per output:
///     u16 tx index          little-endian
///     u16 output index      little-endian
///     [u8; 32] txid         the transaction that created the output
///     u8  flags             bit 0 = spent
///     u32 script length     little-endian
///     [u8; script length]   locking script
///     u64  amount           big-endian (base units)
///     u64  fee              big-endian (base units)
///     [u8; 20] recipient    L2 address
/// ```
///
/// The block hash sits in the header with the height because the two are the same
/// fact — *which* block this is — and because the proof statement reports the
/// height. It is deliberately not what a deposit is identified by: a reorg gives
/// the same transaction a new block, and therefore a new hash, so each record
/// carries its transaction id and the identity is derived from that instead (see
/// [`LockEvent::lock_id`]). Every field of the header and of the record prefix is
/// fixed-width — the txid included, with no length prefix — so that a truncated or
/// hostile block can only ever be a decode error, never a variable-length
/// reinterpretation of the bytes that follow.
///
/// The encoding is little-endian for its own bookkeeping and big-endian for the
/// two values that become money and for the height and hash. Amounts are
/// big-endian because that is how they appear in the ABI, the state root and every
/// other 32-byte quantity the L2 handles; a mixed-encoding amount is exactly the
/// kind of thing that ends up minted at the wrong scale. The script length is
/// bounded, so a malformed block cannot make the decoder allocate its way through
/// it.
pub fn decode_block(block_data: &[u8]) -> Result<Vec<BlockOutput>, String> {
    if block_data.len() < BLOCK_MAGIC.len() {
        return Err("block data is shorter than the bridge block header".to_string());
    }
    if block_data[..BLOCK_MAGIC.len()] != BLOCK_MAGIC {
        return Err("block data does not start with the bridge block magic".to_string());
    }

    let mut cursor = Cursor { bytes: block_data, offset: BLOCK_MAGIC.len() };
    let block_height = cursor.take_u64("block height")?;
    // The block hash is read before the count, and with the same bounds checking as
    // every other field: a header that stops short of 32 hash bytes is a truncated
    // block, not a block whose outputs happen to be re-aligned.
    let block_hash: [u8; 32] = cursor.take(32, "block hash")?.try_into().expect("32-byte slice");
    let count = cursor.take_u32("output count")? as usize;

    // A count that could not possibly be satisfied is refused before anything is
    // allocated for it, so a hostile header cannot reserve memory for outputs
    // that were never sent.
    if count.saturating_mul(MIN_OUTPUT_LEN) > cursor.remaining() {
        return Err(format!("output count {count} does not fit in the {} remaining byte(s)", cursor.remaining()));
    }
    // The check above bounds the count by the input's *bytes*, which is not the
    // same as bounding the work: `MIN_OUTPUT_LEN` is the size of an empty script,
    // so a block can pack far more decodable records than it has bytes for real
    // ones. One block may therefore buy at most `MAX_OUTPUTS_PER_BLOCK` records,
    // whatever it claims and however densely it encodes them.
    if count > MAX_OUTPUTS_PER_BLOCK {
        return Err(format!("output count {count} exceeds the {MAX_OUTPUTS_PER_BLOCK}-output block limit"));
    }
    // The count limit above is only as tight as `MIN_OUTPUT_LEN`, so it admits
    // four times as many real records as the input can physically hold: a record
    // carrying a maximal script occupies `MAX_OUTPUT_LEN` bytes, not
    // `MIN_OUTPUT_LEN`. The reservation is therefore clamped to what the input
    // could justify at the smallest record size. Decoding is unaffected — a block
    // that really does hold `count` records still decodes, growing the vector as
    // records are read — but a hostile block whose records are large can no
    // longer make the decoder reserve memory for records that were never sent.
    let reserve = count.min(max_outputs_for(block_data.len()));
    let mut outputs = Vec::with_capacity(reserve);

    for index in 0..count {
        let tx_index = cursor.take_u16(&record_field(index, "tx index"))?;
        let output_index = cursor.take_u16(&record_field(index, "output index"))?;
        // The txid is the deposit's identity, so it is read with the same bounds
        // checking as every other field: a record that stops short of 32 txid bytes
        // is a truncated block, not a record whose flags happen to be re-aligned.
        let txid: [u8; 32] = cursor.take(32, &record_field(index, "txid"))?.try_into().expect("32-byte slice");
        let flags = cursor.take_u8(&record_field(index, "flags"))?;
        let script_len = cursor.take_u32(&record_field(index, "script length"))? as usize;
        if script_len > crate::MAX_LOCK_SCRIPT_LEN {
            return Err(format!("output {index}: script length {script_len} exceeds the {}-byte limit", crate::MAX_LOCK_SCRIPT_LEN));
        }
        let script = cursor.take(script_len, &record_field(index, "script"))?.to_vec();
        let amount = U256::from(cursor.take_u64(&record_field(index, "amount"))?);
        let fee = U256::from(cursor.take_u64(&record_field(index, "fee"))?);
        let recipient = Address::from_slice(cursor.take(20, &record_field(index, "recipient"))?);
        outputs.push(BlockOutput {
            tx_index,
            output_index,
            block_height,
            block_hash,
            txid,
            script,
            amount,
            recipient,
            fee,
            spent: flags & 0x01 != 0,
        });
    }

    if cursor.remaining() != 0 {
        return Err(format!("{} trailing byte(s) after the last output", cursor.remaining()));
    }
    Ok(outputs)
}

/// A bounds-checked reader over a block's bytes.
///
/// Every read is fallible, so a truncated block is an error naming the field that
/// ran short instead of a panic.
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn take(&mut self, len: usize, what: &str) -> Result<&'a [u8], String> {
        if len > self.remaining() {
            return Err(format!("truncated block: {what} needs {len} byte(s) at offset {}, {} remain", self.offset, self.remaining()));
        }
        let slice = &self.bytes[self.offset..self.offset + len];
        self.offset += len;
        Ok(slice)
    }

    fn take_u8(&mut self, what: &str) -> Result<u8, String> {
        Ok(self.take(1, what)?[0])
    }

    fn take_u16(&mut self, what: &str) -> Result<u16, String> {
        Ok(u16::from_le_bytes(self.take(2, what)?.try_into().expect("2-byte slice")))
    }

    fn take_u32(&mut self, what: &str) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4, what)?.try_into().expect("4-byte slice")))
    }

    fn take_u64(&mut self, what: &str) -> Result<u64, String> {
        Ok(u64::from_be_bytes(self.take(8, what)?.try_into().expect("8-byte slice")))
    }
}
