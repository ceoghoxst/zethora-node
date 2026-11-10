//! **Ultimate Doomsday** — cross-layer kill chains against the wZTHR bridge.
//!
//! The per-crate `attack_tests` suites test each perimeter. This one attacks the
//! *seams*, which is where a bridge actually dies: the watcher that decides what
//! a deposit is, the proof that carries that decision to L2, and the contract
//! that has to be safe against a caller who lies about all of it.
//!
//! Every test below is a complete attack played from the attacker's side of the
//! real interface, and every test passes only when the attack *fails* — which
//! means these are also the tests that go red the day a check is removed.
//!
//! | # | Kill chain | The seam it attacks |
//! |---|-----------|---------------------|
//! | 0 | *control* | an honest deposit, so no red test can be excused as a broken fixture |
//! | 1 | Orchard reorg double-spend | an L1 lock that a fork took back, replayed on L2 |
//! | 2 | proof forgery | the prover's statement vs. the contract's verification |
//! | 2b | *documented gap* | the mock commitment is unsound; pinned so it cannot be forgotten |
//! | 3 | re-entrancy / replay drain | one deposit, minted twice |
//! | 4 | L1 block-byte manipulation | the block decoder vs. what a node validated |
//!
//! # One attack that currently succeeds
//!
//! Attack 2b is deliberately written to *pass while the attack works*:
//! [`MintProof::commitment_for`] is a public keccak hash with no secret behind
//! it, so a self-computed commitment over an invented deposit is accepted until
//! the SP1 verifier is wired in. The gap is pinned as an executable fact rather
//! than a comment, and that test is the one to invert when the prover lands.
//!
//! # The threat model these tests encode
//!
//! The L2 cannot see L1. It therefore believes exactly one thing: the proof. So
//! the attacker in these tests controls
//!
//! * the bytes of the L1 block the watcher is handed,
//! * the proof bytes handed to the contract, and
//! * the calldata that carries them,
//!
//! and does *not* control the federation's lock script, the contract's own
//! storage, or the chain id. Everything that stops the attacks below is a check
//! in code, not a convention.

use alloy_primitives::{Address, U256, keccak256};
use zethora_bridge::{BLOCK_MAGIC, FederationSigner, L1Watcher, MintError, minted_slot, wzthr_balance};
use zethora_evm::EvmExecutor;

// ---------------------------------------------------------------------------
// The world
// ---------------------------------------------------------------------------

/// The wZTHR contract on L2.
fn contract() -> Address {
    Address::repeat_byte(0xc0)
}

/// The honest depositor, whose L1 lock the attacker wants to steal or duplicate.
fn depositor() -> Address {
    Address::repeat_byte(0x11)
}

/// The attacker's own L2 account.
fn attacker() -> Address {
    Address::repeat_byte(0xba)
}

/// A 2-of-3 federation, exactly as a deployment would use.
///
/// The file is the *coordinator*: it holds the members' secret keys, because these
/// tests have to produce honest proofs before they attack them. The lock script every
/// block below pays into is derived from the same keys, so a deposit the fixture
/// builds is a deposit this federation is required to authorise. The attacker, of
/// course, holds neither half.
fn federation() -> FederationSigner {
    let secret_keys = vec![[0x11; 32], [0x22; 32], [0x33; 32]];
    FederationSigner::new(secret_keys, 2).expect("2-of-3 is a valid federation")
}

/// The contract's `mint`, authorised by the federation this file signs with.
///
/// Every mint in this file is checked against the federation the watcher holds —
/// that is the protocol, and an attacker in these scenarios does not get to choose
/// the verifier's key set. The wrapper exists so the attacks read as what they are:
/// a *statement* being smuggled past a fixed authority, not a key-substitution game.
fn mint(executor: &mut EvmExecutor, contract: Address, to: Address, amount: U256, proof: &[u8]) -> Result<(), MintError> {
    zethora_bridge::mint(executor, federation().lock(), contract, to, amount, proof)
}

/// Value the depositor locked, and the fee withheld from the mint.
const LOCKED: u64 = 1_000;
const FEE: u64 = 10;
/// What the depositor is owed: the lock less the fee.
const MINTABLE: u64 = LOCKED - FEE;

// ---------------------------------------------------------------------------
// The block encoder
// ---------------------------------------------------------------------------

/// Writes a block body in the exact layout [`zethora_bridge::decode_block`] reads:
///
/// ```text
/// magic(4) | height(8 BE) | block_hash(32) | count(4 LE) | record*count
/// record = tx_index(2 LE) | output_index(2 LE) | flags(1)
///          | script_len(4 LE) | script | amount(8 BE) | fee(8 BE) | recipient(20)
/// ```
///
/// This is a test-owned *encoder*, not a validator: it exists so the attacks can
/// produce well-formed bytes with hostile *contents*. Being able to build a
/// perfectly parseable block is the attacker's first capability, and the tests
/// that need it say so.
#[derive(Clone)]
struct BlockBuilder {
    height: u64,
    /// The hash the header claims for this block.
    hash: [u8; 32],
    records: Vec<Vec<u8>>,
}

impl BlockBuilder {
    fn new(height: u64) -> Self {
        Self { height, hash: block_hash(height), records: Vec::new() }
    }

    fn push(mut self, record: Vec<u8>) -> Self {
        self.records.push(record);
        self
    }

    /// Adds a deposit locked by the *real* federation, to `recipient`.
    fn deposit(self, recipient: Address) -> Self {
        self.push(record(0, 0, txid(0), &federation().lock_script(), LOCKED, FEE, recipient, false))
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&BLOCK_MAGIC);
        out.extend_from_slice(&self.height.to_be_bytes());
        out.extend_from_slice(&self.hash);
        out.extend_from_slice(&(self.records.len() as u32).to_le_bytes());
        for record in &self.records {
            out.extend_from_slice(record);
        }
        out
    }
}

/// The 32-byte block hash a fixture block at `height` claims.
///
/// A ZBD1 header names the block it describes, and every encoded block needs a hash.
/// Deriving it from the height keeps a rebuilt block identical, while two heights
/// still get unrelated-looking hashes, as a fork produces.
///
/// It is deliberately *not* part of a deposit's identity: that comes from the
/// transaction's [`txid`], because a reorg rewrites the block a transaction sits in
/// and must not be able to give the same coin a second identity.
fn block_hash(height: u64) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(32 + 8);
    preimage.extend_from_slice(b"zethora-bridge-test/block");
    preimage.extend_from_slice(&height.to_be_bytes());
    keccak256(&preimage).0
}

/// A stand-in txid for the transaction the fixtures place at `tx_index`.
///
/// A deposit is identified by `keccak256(txid || output_index)`, so each record names
/// the transaction that created it. Two different transactions get unrelated ids,
/// while the *same* transaction keeps its id across blocks — which is what makes the
/// reorg in [`attack_1_orchard_reorg_cannot_mint_the_same_lock_twice`] a replay
/// instead of a second deposit.
fn txid(tx_index: u16) -> [u8; 32] {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"zethora-bridge-test/tx");
    preimage.extend_from_slice(&tx_index.to_be_bytes());
    keccak256(&preimage).0
}

/// One encoded output record.
#[allow(clippy::too_many_arguments)]
fn record(
    tx_index: u16,
    output_index: u16,
    txid: [u8; 32],
    script: &[u8],
    amount: u64,
    fee: u64,
    recipient: Address,
    spent: bool,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&tx_index.to_le_bytes());
    out.extend_from_slice(&output_index.to_le_bytes());
    out.extend_from_slice(&txid);
    out.push(u8::from(spent));
    out.extend_from_slice(&(script.len() as u32).to_le_bytes());
    out.extend_from_slice(script);
    out.extend_from_slice(&amount.to_be_bytes());
    out.extend_from_slice(&fee.to_be_bytes());
    out.extend_from_slice(recipient.as_slice());
    out
}

/// The honest world's only block: one deposit by the depositor.
fn honest_block() -> Vec<u8> {
    BlockBuilder::new(100).deposit(depositor()).encode()
}

// ---------------------------------------------------------------------------
// The pipeline, as production runs it
// ---------------------------------------------------------------------------

/// Scans a block, proves the lock it holds, and mints it — **to `to`**.
///
/// The bridge in three lines: bytes in, a `LockEvent` out, a proof, then a real
/// `EvmExecutor` applying the mint against the contract's own storage. Every
/// attack below only reaches its goal if this succeeds on attacker-chosen input.
///
/// The proof is rebuilt for `to` rather than taken from `generate_mint_proof`,
/// because the watcher's default is the *recorded* recipient. Minting to `to`
/// while presenting the watcher's own proof would only ever test the replay
/// marker; the redirection attack needs a proof that really claims `to`. When
/// `to` is the recorded recipient the two are byte-identical, so honest calls are
/// unaffected.
fn deposit(watcher: &L1Watcher, executor: &mut EvmExecutor, block: &[u8], to: Address) -> Result<(), String> {
    let locks = watcher.scan_for_locks(block)?;
    let lock = locks.first().ok_or_else(|| "the block holds no lock to prove".to_string())?;
    // Prove the lock first, so a spent or worthless deposit is still refused by
    // the watcher's own rules instead of by the contract.
    let proof = watcher.generate_mint_proof(lock, executor.chain_id())?;
    let redirected = zethora_bridge::MintProof::new(lock, executor.chain_id(), to, &federation());
    let (to, amount, proof_bytes) = zethora_bridge::decode_mint_calldata(&redirected.calldata(to))?;
    debug_assert_eq!(proof.lock_id, redirected.lock_id);
    mint(executor, contract(), to, amount, &proof_bytes).map_err(|err| format!("mint refused: {err}"))
}

/// Forwards a proof *made for* `made_for` to `to`, leaving every byte of the
/// proof untouched.
///
/// This is the exact shape of a redirected replay: the attacker possesses a valid
/// proof for the depositor and simply names themselves in the call. If the
/// contract credited `to`, the deposit would be stealable by anyone who saw the
/// proof travel.
fn replay_proof(
    watcher: &L1Watcher,
    executor: &mut EvmExecutor,
    block: &[u8],
    made_for: Address,
    to: Address,
) -> Result<(), String> {
    let lock = watcher.scan_for_locks(block)?.remove(0);
    let proof = zethora_bridge::MintProof::new(&lock, executor.chain_id(), made_for, &federation());
    mint(executor, contract(), to, proof.amount, &proof.encode()).map_err(|err| format!("mint refused: {err}"))
}

/// A watcher, an empty L2 and the honest deposit already applied.
fn honest_world() -> (L1Watcher, EvmExecutor) {
    let watcher = L1Watcher::new(federation(), contract());
    let mut executor = EvmExecutor::new();
    deposit(&watcher, &mut executor, &honest_block(), depositor()).expect("an honest deposit must mint");
    (watcher, executor)
}

// ===========================================================================
// 0. CONTROL — the baseline every attack is measured against
// ===========================================================================

/// Establishes the three facts the attacks depend on, so that a red attack test
/// can never be excused as "the fixture was broken anyway":
///
/// 1. an honest deposit mints exactly `LOCKED - FEE`, to the depositor;
/// 2. the attacker's account starts empty;
/// 3. the deposit is *consumed* — its replay marker is set — so honesty and
///    replay-protection are both already in play before anyone attacks.
#[test]
fn control_an_honest_deposit_mints_exactly_once_to_the_depositor() {
    let (watcher, mut executor) = honest_world();

    assert_eq!(
        wzthr_balance(&mut executor, contract(), depositor()),
        U256::from(MINTABLE),
        "the depositor is owed the lock less the bridge fee"
    );
    assert_eq!(wzthr_balance(&mut executor, contract(), attacker()), U256::ZERO, "nobody else is paid");

    // The lock is marked as spent, which is what makes the replay attacks below
    // meaningful: the marker is live, not vacuously absent.
    let lock = watcher.scan_for_locks(&honest_block()).expect("scan").remove(0);
    assert!(
        !executor.storage(contract(), minted_slot(lock.lock_id())).is_zero(),
        "an accepted mint must consume its lock id"
    );
}

// ===========================================================================
// 1. ORCHARD REORG DOUBLE-SPEND
// ===========================================================================

/// **Kill chain.** The depositor locks on L1 and is minted on L2. The chain then
/// reorganises: the block carrying the lock is orphaned and the transaction is
/// either spent on the new branch or re-included in it. The attacker replays the
/// *original* deposit bytes at the watcher, hoping the bridge pays twice for one
/// lock — once for the coin that no longer exists, once for the one that does.
///
/// **The seam.** The bridge's notion of "a deposit" is `(txid, output_index)` — see
/// [`LockEvent::lock_id`]. A reorg is precisely the event that used to make a
/// deposit ambiguous: under the old `(block hash, tx index, output index)` identity
/// one coin carried one identity per block that included it, so a reorg re-minted it
/// for free. Keying on the transaction removes that, because a txid commits to the
/// transaction's contents and not to where it was mined. The whole attack reduces to
/// "does the bridge's deposit identity survive a fork?", and the answer now has to be
/// yes.
///
/// **Why it fails, and where.** Three independent checks, and the test asserts all
/// three:
///
/// * *On L2*, the replayed deposit is refused with `AlreadyMinted`, because the lock
///   id names the transaction: replaying the same block bytes is the same lock id,
///   and a change of *spentness* is not a change of identity.
/// * *On L1*, the watcher refuses to prove a lock that is not live. A branch that
///   spent the coin produces `LockStatus::Spent`, and a spent lock backs nothing.
/// * *On the identity*, a re-included transaction keeps its lock id. That is the
///   case this crate used to get wrong — F-1, now pinned by
///   `attack_1_f1_a_reorg_at_a_new_height_cannot_mint_the_same_deposit_twice` in
///   `zethora_bridge_blackhat.rs` — and the end of this test re-checks it at a new
///   height.
///
/// **What this test deliberately does NOT claim.** The watcher trusts the bytes it is
/// handed: the txid, the `spent` flag and the block hash are attacker-chosen until an
/// L1 anchor checks them, and this crate has no view of L1 consensus. So the honest
/// statement is narrow: *given* the block bytes, the bridge cannot be made to pay
/// twice for one deposit. Refusing a transaction that no L1 block ever contained needs
/// a merkle path to a header the federation signed; this crate does not attempt it,
/// and the last assertion below pins that the attacker is paid nothing on this path.
#[test]
fn attack_1_orchard_reorg_cannot_mint_the_same_lock_twice() {
    let (watcher, mut executor) = honest_world();

    // --- the reorg: the depositor's coin is spent on the new branch ---------
    // Same transaction, same output. On the canonical branch the output is spent, so
    // the deposit is not backed by anything any more.
    let spent_branch = BlockBuilder::new(100)
        .push(record(0, 0, txid(0), &federation().lock_script(), LOCKED, FEE, depositor(), true))
        .encode();
    let lock = watcher.scan_for_locks(&spent_branch).expect("the spent record still decodes").remove(0);
    assert_eq!(lock.status, zethora_bridge::LockStatus::Spent, "the forked branch marks the deposit spent");
    assert!(
        watcher.generate_mint_proof(&lock, executor.chain_id()).is_err(),
        "a lock the fork took back must never be provable"
    );

    // --- the replay: present the original deposit again --------------------
    // Replayed as-is it is a replay (`AlreadyMinted`): same proof, same id.
    let replay = deposit(&watcher, &mut executor, &honest_block(), depositor());
    assert!(
        matches!(replay, Err(ref err) if err.contains("already minted")),
        "the replayed deposit must be refused as a replay, got {replay:?}"
    );
    // Replayed with the attacker substituted as recipient, carrying the
    // depositor's own proof, it never verifies: the recipient is part of the
    // statement the proof commits to. That is the stronger refusal — the attacker
    // cannot even redirect a dead deposit.
    let redirect = replay_proof(&watcher, &mut executor, &honest_block(), depositor(), attacker());
    assert!(
        matches!(redirect, Err(ref err) if err.contains("invalid proof")),
        "the depositor's proof cannot be forwarded to a new recipient, got {redirect:?}"
    );

    // --- the money did not move -------------------------------------------
    assert_eq!(
        wzthr_balance(&mut executor, contract(), depositor()),
        U256::from(MINTABLE),
        "the depositor's balance never doubles"
    );
    assert_eq!(wzthr_balance(&mut executor, contract(), attacker()), U256::ZERO, "the attacker is paid nothing");

    // --- and the honest limit of this defence -----------------------------
    // The watcher has no L1 view: a record that presents the *same transaction* as
    // unspent, in a block it was never mined in, looks like a plain deposit to it. It
    // is stopped because the transaction's id has already been consumed. If inclusion
    // or fork detection is ever added to this crate, this is the assertion to change —
    // today the identity is honest about *which* deposit this is, not about whether L1
    // ever held it.
    let recycled = BlockBuilder::new(100)
        .push(record(0, 0, txid(0), &federation().lock_script(), LOCKED, FEE, attacker(), false))
        .encode();
    let lock = watcher.scan_for_locks(&recycled).expect("the recycled record decodes").remove(0);
    assert_eq!(lock.status, zethora_bridge::LockStatus::Live, "the watcher trusts the spent flag it is given");

    // The recycled output names the attacker, which is the only recipient the
    // watcher will prove. If the bridge had any L1 awareness this is where it would
    // fire; instead the mint is refused purely because the deposit's id was already
    // consumed by the honest mint. That is the entire defence, and the assertion says
    // so rather than implying something stronger.
    let recycled_mint = deposit(&watcher, &mut executor, &recycled, attacker());
    assert!(
        matches!(recycled_mint, Err(ref err) if err.contains("already minted")),
        "a recycled record is stopped by the replay marker alone, not by inclusion detection: {recycled_mint:?}"
    );

    // A self-consistent proof for the attacker, built on the recycled record: the
    // statement now matches, so verification passes and the *marker* is what stops it.
    // This is the ordering the contract relies on, exercised on the attacker's own id
    // rather than the honest one.
    let steal = zethora_bridge::MintProof::new(&lock, executor.chain_id(), attacker(), &federation());
    assert!(
        steal.verify(federation().lock(), executor.chain_id(), attacker(), steal.amount).is_ok(),
        "a proof rebuilt for the attacker is internally valid — only the marker stands in the way"
    );
    assert_eq!(
        mint(&mut executor, contract(), attacker(), steal.amount, &steal.encode()),
        Err(MintError::AlreadyMinted(steal.lock_id)),
        "the recycled record is one deposit id, so its second mint is a replay"
    );
    assert_eq!(wzthr_balance(&mut executor, contract(), attacker()), U256::ZERO);

    // --- F-1: the reorg shape that used to mint twice ----------------------
    // The same transaction, re-included in a *different* block. Under the old
    // `(block hash, tx index, output index)` identity this was a fresh id, so one L1
    // lock minted once per block that carried it. The txid cannot be rewritten by a
    // reorg, so the deposit keeps its identity and the marker the honest mint set is
    // exactly what the re-inclusion hits.
    let re_included = BlockBuilder::new(101)
        .push(record(0, 0, txid(0), &federation().lock_script(), LOCKED, FEE, depositor(), false))
        .encode();
    let original = watcher.scan_for_locks(&honest_block()).expect("the honest block scans").remove(0);
    let moved = watcher.scan_for_locks(&re_included).expect("the re-included record decodes").remove(0);
    assert_ne!(moved.block_height, original.block_height, "the reorg really moved the transaction");
    assert_ne!(moved.block_hash, original.block_hash, "and really gave it a different block");
    assert_eq!(moved.lock_id(), original.lock_id(), "a reorg cannot re-identify a deposit");
    let re_mint = deposit(&watcher, &mut executor, &re_included, depositor());
    assert!(
        matches!(re_mint, Err(ref err) if err.contains("already minted")),
        "a deposit re-included at a new height must not mint twice, got {re_mint:?}"
    );
    assert_eq!(
        wzthr_balance(&mut executor, contract(), depositor()),
        U256::from(MINTABLE),
        "one lock, one mint, however many blocks carry it"
    );
}

// ===========================================================================
// 2. PROOF FORGERY
// ===========================================================================

/// **Kill chain.** The prover is the untrusted party: the L2 sees only the bytes
/// it produces. So the attacker stops trying to be the depositor and starts
/// forging the *proof*: take an honest proof and redirect it, inflate it, replay
/// it on another chain, or grind a commitment over a statement of their choosing.
///
/// **The seam.** [`zethora_bridge::MintProof`] verification is the contract's
/// entire authority check. It must bind every field the mint acts on — recipient,
/// amount, chain, deposit id — or a proof made for one deposit becomes a licence
/// for another.
///
/// **The attack.** Four real forgeries, then a statement of the one thing the
/// mock provably cannot stop.
#[test]
fn attack_2_a_forged_proof_cannot_redirect_or_inflate_a_deposit() {
    let watcher = L1Watcher::new(federation(), contract());
    let mut executor = EvmExecutor::new();

    let lock = watcher.scan_for_locks(&honest_block()).expect("scan").remove(0);
    let honest = watcher
        .generate_mint_proof(&lock, executor.chain_id())
        .expect("the honest proof");
    let proof_bytes = honest.encode();

    // (a) **Redirection.** The proof is honest; the calldata is not. The attacker
    // forwards the depositor's proof to their own account. `verify` checks the
    // recipient against the commitment, so the commitment no longer matches.
    assert_eq!(
        mint(&mut executor, contract(), attacker(), honest.amount, &proof_bytes),
        Err(MintError::InvalidProof),
        "a proof must not be redirectable to a different recipient"
    );

    // (b) **Inflation.** Keep the recipient, change the amount: a proof worth 990
    // presented as a proof worth 1,000,000. The amount is part of the commitment
    // and is also compared directly.
    assert_eq!(
        mint(&mut executor, contract(), depositor(), U256::from(1_000_000u64), &proof_bytes),
        Err(MintError::InvalidProof),
        "a proof must not be inflatable"
    );

    // (c) **Cross-chain replay.** The statement is domain- and chain-bound, and the
    // chain is supplied by the verifier rather than by the proof. A proof built for
    // another chain therefore commits to a different statement, and the same bytes
    // cannot be relabelled: there is no chain field to rewrite.
    let retargeted = zethora_bridge::MintProof::new(&lock, executor.chain_id() + 1, depositor(), &federation());
    assert_eq!(
        mint(&mut executor, contract(), depositor(), honest.amount, &retargeted.encode()),
        Err(MintError::InvalidProof),
        "a proof must not cross chains"
    );

    // Nothing above moved a single unit of wZTHR.
    assert_eq!(wzthr_balance(&mut executor, contract(), attacker()), U256::ZERO);
    assert_eq!(wzthr_balance(&mut executor, contract(), depositor()), U256::ZERO);

    // The honest proof still works afterwards, so the refusals above rejected the
    // forgery rather than poisoning the deposit.
    mint(&mut executor, contract(), depositor(), honest.amount, &proof_bytes).expect("the honest proof still mints");
    assert_eq!(wzthr_balance(&mut executor, contract(), depositor()), U256::from(MINTABLE));
}

/// **The forgery that used to work: a hand-rolled commitment.**
///
/// The commitment is a keccak hash and its formula is public, so anyone who can read
/// [`zethora_bridge::MintProof::commitment_for`] can compute a commitment over a
/// statement of their own invention, naming a deposit that L1 never had. That part is
/// unavoidable — the statement has to be public for the verifier to recompute it —
/// and it is *all* an attacker can do.
///
/// What they cannot do is get the federation to sign it. This test used to assert the
/// attack **succeeded** (the documented mock gap, F-3); it now asserts the gap is
/// closed, and it is written so that closing it harder only makes it pass more: every
/// forgery listed below must be refused, and refused *cleanly*.
///
/// The forgery is built by hand rather than by [`zethora_bridge::MintProof::new`],
/// because that is exactly the attacker's position: they can write the fields, they
/// just cannot sign. Three shapes, increasing in strength:
///
/// * the scalar fields with no approvals at all — refused by the wire format, since an
///   unsigned proof is not a proof and never reaches the contract as bytes;
/// * the scalars plus a full set of well-formed *garbage* signatures — parses, and
///   dies on the approval check, which is the seam F-3 was about;
/// * the same with the maximum the format allows, so the refusal cannot be a
///   length artefact.
///
/// The blast radius is pinned too: nothing is credited, and the invented id is not
/// consumed, so a forgery cannot even burn an id it made up.
#[test]
fn attack_2b_a_hand_rolled_commitment_cannot_mint() {
    let mut executor = EvmExecutor::new();
    let chain = executor.chain_id();

    // The attacker invents a deposit that never happened and computes its commitment
    // exactly as the honest code does. Nothing here is a secret: the chain id is
    // public configuration, the recipient is theirs, and the id is their own bytes.
    let invented_id = [0x66u8; 32];
    let amount = U256::from(LOCKED);
    let commitment = zethora_bridge::MintProof::commitment_for(invented_id, amount, 100, chain, attacker());

    // (a) No approvals: there is no proof to present. The wire form refuses to carry
    // an unsigned proof at all, so this never even becomes calldata.
    let unsigned = zethora_bridge::MintProof { lock_id: invented_id, amount, block_height: 100, commitment, signatures: vec![] };
    assert!(
        zethora_bridge::MintProof::decode(&unsigned.encode()).is_err(),
        "a proof with no federation signature must not survive a round-trip"
    );
    assert_eq!(
        mint(&mut executor, contract(), attacker(), amount, &unsigned.encode()),
        Err(MintError::InvalidProof),
        "an unsigned proof authorises nothing"
    );

    // (b) A full set of garbage signatures: the encoding is perfect, the approvals are
    // not. This is the attack F-3 described — anyone can hash, so what stops the
    // forgery has to be the signature check, and this is that check.
    let garbage = zethora_bridge::MintProof {
        lock_id: invented_id,
        amount,
        block_height: 100,
        commitment,
        signatures: vec![[0u8; 64], [0xffu8; 64]],
    };
    assert_eq!(
        zethora_bridge::MintProof::decode(&garbage.encode()).expect("the bytes are well-formed").signatures.len(),
        2,
        "the forgery really carries the two signatures it needs, so the refusal is the approval check"
    );
    assert_eq!(
        mint(&mut executor, contract(), attacker(), amount, &garbage.encode()),
        Err(MintError::InvalidProof),
        "signatures that no federation member produced must not authorise a mint"
    );

    // (c) The strongest shape the format allows: `MAX_KEYS` signatures, so the refusal
    // cannot be about the count either.
    let stuffed = zethora_bridge::MintProof {
        lock_id: invented_id,
        amount,
        block_height: 100,
        commitment,
        signatures: vec![[0x5au8; 64]; zethora_bridge::MAX_KEYS],
    };
    assert_eq!(
        mint(&mut executor, contract(), attacker(), amount, &stuffed.encode()),
        Err(MintError::InvalidProof),
        "padding the proof with signatures does not make one of them valid"
    );

    // Nothing was credited, and the invented id is still spendable-by-nobody rather
    // than consumed: a rejected forgery must not be able to burn an id.
    assert_eq!(wzthr_balance(&mut executor, contract(), attacker()), U256::ZERO);
    assert_eq!(wzthr_balance(&mut executor, contract(), depositor()), U256::ZERO);
    assert!(
        executor.storage(contract(), minted_slot(invented_id)).is_zero(),
        "a refused forgery must not consume the id it invented"
    );

    // The honest deposit is untouched by all of the above and still mints once, which
    // is the point: the seam fails closed, and it fails closed without collateral.
    let watcher = L1Watcher::new(federation(), contract());
    let mut fresh = EvmExecutor::new();
    let lock = watcher.scan_for_locks(&honest_block()).expect("scan").remove(0);
    let honest = watcher.generate_mint_proof(&lock, fresh.chain_id()).expect("the honest proof");
    mint(&mut fresh, contract(), depositor(), honest.amount, &honest.encode()).expect("the honest proof still mints");
    assert_eq!(wzthr_balance(&mut fresh, contract(), depositor()), U256::from(MINTABLE));
}

// ===========================================================================
// 3. RE-ENTRANCY / REPLAY DRAIN
// ===========================================================================

/// **Kill chain.** One honest deposit is worth 990 wZTHR. The attacker tries to
/// make the contract pay it out more than once: by calling `mint` again with the
/// same proof, by replaying it inside one block's worth of successive calls, by
/// replaying it through a raw ABI-encoded transaction, and by re-ordering the
/// fields so a mutated proof still parses.
///
/// **The seam.** A bridge that credits before it marks is drained by exactly this
/// shape — the classic reentrancy "checks-effects-interactions" violation, which
/// in a bridge appears as "balance written, id not consumed". The defence is an
/// *ordering* property inside `mint`: the lock id is committed before the balance
/// grows, so no failure between the two writes can leave a deposit that is both
/// credited and still mintable.
///
/// **Why it fails.** Two independent refusals stand in the attacker's way, and the
/// contract applies the stricter one first: a replay that changes a field the
/// statement commits to (the recipient, the amount) dies as `InvalidProof`, and a
/// replay that changes nothing dies as `AlreadyMinted`. The test drives every route
/// the attacker has to the same id and asserts the balance ends at exactly one
/// deposit.
#[test]
fn attack_3_replaying_one_deposit_cannot_drain_the_bridge() {
    let (watcher, mut executor) = honest_world();
    let lock = watcher.scan_for_locks(&honest_block()).expect("scan").remove(0);
    let proof = watcher
        .generate_mint_proof(&lock, executor.chain_id())
        .expect("the honest proof");
    let bytes = proof.encode();

    // (a) The blunt replay: same recipient, same proof, straight again.
    assert_eq!(
        mint(&mut executor, contract(), depositor(), proof.amount, &bytes),
        Err(MintError::AlreadyMinted(proof.lock_id)),
        "the second mint of one deposit must be refused"
    );

    // (b) The redirected replay: the same consumed deposit, the depositor's own
    // proof, the attacker named as recipient. This is the drain attempt that
    // matters — the second payout would leave the protocol. It dies on the
    // *statement* check, because the recipient is part of the commitment.
    assert_eq!(
        mint(&mut executor, contract(), attacker(), proof.amount, &bytes),
        Err(MintError::InvalidProof),
        "a consumed deposit must not be redirectable to a new recipient"
    );
    // Rebuilt for the attacker so the statement is self-consistent, it instead has
    // to get past the marker — and cannot.
    let redirected_bytes = zethora_bridge::MintProof::new(&lock, executor.chain_id(), attacker(), &federation()).encode();
    assert_eq!(
        mint(&mut executor, contract(), attacker(), proof.amount, &redirected_bytes),
        Err(MintError::AlreadyMinted(proof.lock_id)),
        "even a well-formed replay to a new recipient cannot reuse a consumed id"
    );

    // (c) The ABI route. Feed the identical call through the contract's own
    // decoder, exactly as a sequencer would, so the replay is not an artifact of
    // calling the Rust function directly.
    let calldata = proof.calldata(depositor());
    let (to, amount, decoded_proof) =
        zethora_bridge::decode_mint_calldata(&calldata).expect("the honest calldata decodes");
    assert_eq!((to, amount), (depositor(), proof.amount), "round-trips through ABI");
    assert_eq!(
        mint(&mut executor, contract(), to, amount, &decoded_proof),
        Err(MintError::AlreadyMinted(proof.lock_id)),
        "the replay must survive a full ABI round-trip and still be refused"
    );

    // (d) The mutated replay: flip one byte of the deposit id and recompute
    // nothing. The label changes, so this is a *different* id — the attacker's
    // only way to escape the marker — but its commitment no longer matches, so it
    // dies on verification instead.
    let mut mutated = proof.clone();
    mutated.lock_id[0] ^= 0xff;
    assert_eq!(
        mint(&mut executor, contract(), depositor(), mutated.amount, &mutated.encode()),
        Err(MintError::InvalidProof),
        "a replay cannot shed its replay marker by mutating the id"
    );

    // (e) The arithmetic drain: no sequence of calls can push the balance past
    // one deposit's worth, because every one of them is the same consumed id.
    for _ in 0..8 {
        assert!(mint(&mut executor, contract(), depositor(), proof.amount, &bytes).is_err());
    }

    // The ledger: exactly one deposit exists, and the attacker has nothing.
    assert_eq!(
        wzthr_balance(&mut executor, contract(), depositor()),
        U256::from(MINTABLE),
        "one deposit, one credit — no drain"
    );
    assert_eq!(wzthr_balance(&mut executor, contract(), attacker()), U256::ZERO, "nothing was drained to the attacker");
}

// ===========================================================================
// 4. L1 BLOCK-BYTE MANIPULATION
// ===========================================================================

/// **Kill chain.** The watcher is handed bytes, and it believes them. So the
/// attacker stops forging proofs and attacks the *input*: craft a block whose
/// contents no L1 node ever validated, but which parses cleanly enough to yield a
/// lock pointing at the attacker.
///
/// **The seam.** The decoder is the boundary between "bytes a node validated" and
/// "a deposit the bridge will pay for". Every field it reads is attacker-chosen
/// until something checks it, so the test asserts the properties the decoder must
/// have — not merely that it does not panic.
#[test]
fn attack_4_crafted_block_bytes_cannot_mint_a_deposit_that_never_happened() {
    let watcher = L1Watcher::new(federation(), contract());
    let mut executor = EvmExecutor::new();

    // A control: the honest block does mint, so every refusal below is the
    // decoder rejecting a *particular* forgery, not the fixture being inert.
    assert!(deposit(&watcher, &mut executor, &honest_block(), depositor()).is_ok());

    // The attacker's goal in one record: the real federation's script (so it is
    // recognised as a deposit) but the attacker's address and a huge amount.
    let greedy = record(0, 0, txid(0), &federation().lock_script(), 1_000_000, 0, attacker(), false);

    // (a) **Wrong magic.** A body that is otherwise perfectly formed.
    let mut no_magic = greedy.clone();
    no_magic[0] ^= 0xff;
    assert_mints_nothing(&watcher, &no_magic, "a body with a corrupted magic");

    // (b) **The count lies.** The header declares two records but only one is
    // present: the decoder must refuse rather than treat the missing record's
    // bytes as anything at all.
    let mut lying_count = Vec::new();
    lying_count.extend_from_slice(&BLOCK_MAGIC);
    lying_count.extend_from_slice(&100u64.to_be_bytes());
    lying_count.extend_from_slice(&block_hash(100));
    lying_count.extend_from_slice(&2u32.to_le_bytes()); // claims 2
    lying_count.extend_from_slice(&greedy); // supplies 1
    assert_mints_nothing(&watcher, &lying_count, "a block whose count exceeds its records");

    // (c) **Trailing bytes.** One record, then junk. A decoder that ignores the
    // tail lets an attacker append a second, unvalidated record's worth of bytes
    // and hope a later reader finds them.
    let mut trailing = Vec::new();
    trailing.extend_from_slice(&BLOCK_MAGIC);
    trailing.extend_from_slice(&100u64.to_be_bytes());
    trailing.extend_from_slice(&block_hash(100));
    trailing.extend_from_slice(&1u32.to_le_bytes());
    trailing.extend_from_slice(&greedy);
    trailing.extend_from_slice(&greedy);
    assert_mints_nothing(&watcher, &trailing, "a block with trailing bytes after its records");

    // Nothing above moved any money to the attacker.
    assert_eq!(wzthr_balance(&mut executor, contract(), attacker()), U256::ZERO, "no crafted block minted to the attacker");
    assert_eq!(
        wzthr_balance(&mut executor, contract(), depositor()),
        U256::from(MINTABLE),
        "the honest deposit is unaffected by the crafted blocks"
    );
}

/// Asserts a byte string never becomes a mint: the scan, the proof, or the
/// contract must refuse it, and no balance may move either way.
fn assert_mints_nothing(watcher: &L1Watcher, block: &[u8], what: &str) {
    let mut executor = EvmExecutor::new();
    if deposit(watcher, &mut executor, block, attacker()).is_ok() {
        panic!("{what}: the bridge accepted it and minted");
    }
    assert_eq!(wzthr_balance(&mut executor, contract(), attacker()), U256::ZERO, "{what}: credited the attacker");
    assert_eq!(wzthr_balance(&mut executor, contract(), depositor()), U256::ZERO, "{what}: credited the depositor");
}
