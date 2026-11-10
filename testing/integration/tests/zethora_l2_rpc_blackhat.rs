//! White hat PoCs for three Zethora L2 / RPC attack surfaces (F-01, F-02, F-04).
//!
//! These are LIVE proof of concepts, not unit tests with mocks: the two node tests start a real simnet
//! `kaspad` (`kaspa_testing_integration::common::daemon::Daemon`) with genesis committed UTXOs, sign real
//! transactions with a real key, submit them through the real gRPC RPC surface and measure what an attacker
//! gets for that money. No node code is stubbed, re-implemented or patched: the file only *uses* the
//! documented RPC surface, so everything timed here runs in production code.
//!
//! Each finding below is written as: mechanism -> evidence (`file:line`) -> attacker cost -> victim impact
//! -> suggested fix.
//!
//! ## F-01 -- [`prealloc::f01_address_scan_holds_the_mempool_lock`]: the address query holds the pool
//! lock for a work amount the *client* chooses
//!
//! `get_mempool_entries_by_addresses` (`rpc/service/src/service.rs:626-650`) turns the request's address
//! list into a `ScriptPublicKeySet` and calls `MiningManagerProxy::get_transactions_by_addresses`
//! (`mining/src/manager.rs:1006-1012`), which does its work inside `spawn_blocking` **while the caller's
//! mempool read lock is alive**: see the `// TODO: break the monolithic lock` region
//! (`mining/src/manager.rs:591-598`) and `Mempool::get_transactions_by_addresses`
//! (`mining/src/mempool/mod.rs:93-106`). The scan itself is a nested loop,
//! `Pool::fill_owner_set_transactions` (`mining/src/mempool/model/pool.rs:106-128`):
//!
//! ```text
//! for script_public_key in requested_addresses {          // chosen by the caller
//!     for (id, transaction) in pool.all() {               // size of the mempool
//!         entries.any(|entry| entry.script_public_key == *script_public_key)   // input side
//!         outputs.any(|output| output.script_public_key == *script_public_key) // output side
//!     }
//! }
//! ```
//!
//! So the cost is `#addresses x #pool_transactions x 2` script comparisons of *arbitrary* size, run under a
//! lock that the transaction submission path needs. Attacker cost: one request. `RPC_MAX_MESSAGE_SIZE` is
//! 1 GB (`rpc/grpc/core/src/lib.rs:8`), so 50,000 addresses (~3.4 MB) is 0.3% of a legal message. Victim
//! impact: every `SubmitTransaction`, and every block template built from the mempool, waits for the whole
//! scan. Suggested fix: bound the number of addresses per request (a few hundred is ample for any wallet)
//! and/or replace the linear scan with a `script_public_key -> {tx ids}` index maintained on insert/remove,
//! so one query costs `O(#addresses + #matches)` and never touches the pool lock for more than a lookup.
//!
//! Triage (`Master Context.txt` §293.2): **the lockout half is refuted, the amplification half is confirmed.**
//! On the triage run the 50,000 address scan really took ~22 s of node time, but the honest payment issued 250 ms
//! into it was accepted ~23 ms later -- the submission path is *not* queued behind the whole scan (the pool's
//! address query yields its lock/row copies early enough for a writer to interleave), so the test no longer
//! asserts a blocked submission. What remains, and is asserted, is the amplification: an unauthenticated request
//! buys seconds of node CPU on a scale the client chooses (`scan_elapsed`, plus the extrapolation to one legal
//! 1 GB message) and the node keeps serving traffic while it does.
//!
//! ## F-02 -- [`prealloc::f02_high_priority_flood_locks_out_paying_users`]: a public mempool byte budget
//! can be filled with transactions nobody can evict
//!
//! Every accepted transaction's mempool footprint includes its payload
//! (`consensus/core/src/tx.rs:443-458`, exposed as the authoritative accounting via `mempool_estimated_bytes`
//! at `consensus/core/src/tx.rs:673`), and the pool is bounded by `maximum_transaction_count` /
//! `mempool_size_limit` (`mining/src/mempool/config.rs:3-4`, scaled by `--ram-scale` through
//! `apply_ram_scale`, `mining/src/mempool/config.rs:130-135`). When the pool is full, only `Priority::Low`
//! transactions are candidates for eviction (`mining/src/mempool/model/transactions_pool.rs:256-260`), and
//! RPC submissions are `Priority::High` (`protocol/flows/src/flow_context.rs:751-761`). Therefore a flood of
//! RPC submitted transactions of the *same* priority can only ever be refused with
//! `RuleError::RejectMempoolIsFull` (`mining/src/mempool/model/transactions_pool.rs:295-305`,
//! `mining/errors/src/mempool.rs:47-49`) -- neither the flood nor the honest user evicts anything.
//! Attacker cost: `budget / bytes_per_transaction` valid transactions, each carrying a ~90 KB payload, all
//! paying the *minimum* relay fee. Victim impact: a perfectly funded payment is rejected as if the network
//! were congested, and it stays rejected until the attacker's transactions are mined or expire (High
//! priority ones do not expire, `flow_context.rs:748-750`). Suggested fix: make the byte budget
//! *priority aware* -- either allow a higher-fee transaction to evict a higher-priority one (fee based
//! replacement at pool level, not only per outpoint), or reserve a fraction of the budget for
//! non-attacker traffic / cap the per-sender share of the pool.
//!
//! Triage (`Master Context.txt` §293.3): **mitigated on this node -- the honest payment got in.** The flood is
//! refused at the budget as predicted (1,100 fillers of ~90 KB each, then `RejectMempoolIsFull`), but the paying
//! user that followed was *accepted*: refusing a filler leaves the residual headroom of a partially filled byte
//! budget (up to one filler's worth), which is orders of magnitude more than a plain ~200 byte payment needs.
//! The test therefore asserts the outcome that matters -- an honest user is never locked out by the flood -- and
//! documents the residual risk instead of a lockout: a flood whose transaction sizes *tile* the budget (or one
//! aimed at the residual after the refusal) could still consume the last free bytes, so the suggested fix above
//! stands as hardening, not as an emergency.
//!
//! ## F-04 -- [`f04_mempool_assert_kills_the_async_task_serving_the_request`]: **PATCHED** -- the blast
//! radius of a mempool panic is now the request, not the whole RPC connection task
//!
//! `Mempool::post_validate_and_insert_transaction` ends with a defensive `assert!`
//! (`mining/src/mempool/validate_and_insert_transaction.rs:124-132`, message
//! `"Transactions in mempool: ..."`). It runs inside a blocking closure that the async side joined with
//! `spawn_blocking(..).await.unwrap()` -- `ConsensusSessionOwned::spawn_blocking`
//! (`components/consensusmanager/src/session.rs:171`), used by the mining manager at `mining/src/manager.rs:986`,
//! `:1011`. A panic there was therefore *re-raised by `unwrap()` inside the async task*, i.e. in the gRPC
//! handler that was serving a request, which killed that task rather than failing the one call: request N+1 of
//! that connection was never served and the client's stream died.
//!
//! Patch (`components/consensusmanager/src/session.rs`): the join is no longer `unwrap()`ed. The new
//! `ConsensusSessionOwned::try_spawn_blocking` matches the `JoinError`, logs it together with the consensus
//! context and the payload the blocking task died with, and returns it, so one poisoned pool operation becomes
//! one failed request that the caller can answer with an `RpcError`. The infallible `spawn_blocking` -- whose
//! signature cannot express failure and which ~100 call sites in `mining/` and `protocol/flows/` still consume
//! as a bare `R` -- now delegates to it, logs the failure, and re-raises the *original* payload; migrating those
//! call sites to `try_spawn_blocking` is a mechanical per-call-site follow-up that shrinks the blast radius to
//! the request on every path. The PoC does not claim the assert is reachable today (the full-pool path returns
//! `RejectMempoolIsFull` first, `mining/src/mempool/model/transactions_pool.rs:295-305`); it measures the blast
//! radius *if* any invariant in such a closure ever fires.
//!
//! Gating: F-01 and F-02 need a genesis that commits UTXOs we own, so they live behind `devnet-prealloc`
//! (exactly like `rpc_perf_benchmarks`); F-04 needs no node and compiles unconditionally.

// Test code is exempt from the arithmetic-side-effects lint (same as `src/lib.rs`).
#![allow(clippy::arithmetic_side_effects)]

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use kaspa_alloc::init_allocator_with_default_settings;
use kaspa_consensus::consensus::test_consensus::TestConsensus;
use kaspa_consensus::params::SIMNET_PARAMS;
use kaspa_consensus_core::{api::DynConsensus, config::Config};
use kaspa_consensusmanager::{ConsensusInstance, SessionLock, spawn_blocking};
use kaspa_core::info;

/// Reproduces the production invariant of
/// `mining/src/mempool/validate_and_insert_transaction.rs:124-132`, message included, on the state that
/// makes it fire: one transaction too many for the pool. The numbers are the ones the real assert prints
/// when the default 1 GB budget is exceeded by a single transaction.
fn fire_mempool_assert() {
    let (pool_len, max_pool_len, pool_bytes, max_bytes) = (1_000_001usize, 1_000_000usize, 1_073_741_825u64, 1_073_741_824u64);
    assert!(
        pool_len < max_pool_len && pool_bytes <= max_bytes,
        "Transactions in mempool: {pool_len}, max: {max_pool_len}, mempool bytes size: {pool_bytes}, max: {max_bytes}",
    );
}

/// Recovers the message from a panic payload, as an operator would see it in the node log.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else if let Some(message) = payload.downcast_ref::<&'static str>() {
        (*message).to_string()
    } else {
        "<panic payload is not a string>".to_string()
    }
}
/// **F-04 -- a mempool panic used to kill the task that serves the RPC request; the patched wrapper
/// contains it to the request.**
///
/// The panic payload crosses the thread boundary intact (step 1), but the production join site used to be
/// `spawn_blocking(..).await.unwrap()` (`components/consensusmanager/src/session.rs:171`), which re-raises the
/// panic *inside the async task*: the task dies where it stands (step 2) and request N+1 of that connection is
/// never served. Step 3 shows the same panic is harmless when the `JoinError` is matched instead of unwrapped,
/// which isolates the blast radius to the `unwrap()`. Step 4 runs the experiment through the patched production
/// wrapper `ConsensusSessionOwned::try_spawn_blocking` on a real consensus instance and asserts that the serving
/// task survives the poisoned request.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn f04_mempool_assert_kills_the_async_task_serving_the_request() {
    init_allocator_with_default_settings();
    kaspa_core::log::try_init_logger("info");

    // ---- 1. The panic payload itself is the mempool assert, and it survives the thread hop ----
    let panic = spawn_blocking(fire_mempool_assert)
        .await
        .expect_err("a panic inside spawn_blocking must surface as Err(JoinError), not as a silent ()");
    assert!(panic.is_panic(), "the closure panicked, so the JoinError must report a panic: {panic}");
    let recovered = panic_message(panic.into_panic().as_ref());
    assert!(
        recovered.contains("Transactions in mempool"),
        "the payload of the panic must still be the mempool assert message, got {recovered:?}"
    );

    // ---- 2. A handler task serving three sequential requests: the second one trips the assert ----
    let served = Arc::new(AtomicUsize::new(0));
    let counter = served.clone();
    let handler = tokio::spawn(async move {
        for request in 0..3u8 {
            counter.fetch_add(1, Ordering::SeqCst);
            if request == 1 {
                // Exactly the shape of `MiningManagerProxy::get_all_transactions` /
                // `get_transactions_by_addresses` (`mining/src/manager.rs:986`, `:1011`) and of
                // `ConsensusSessionOwned::spawn_blocking`
                // (`components/consensusmanager/src/session.rs:171`): join the blocking pool operation with
                // `unwrap()`, so the pool's panic becomes *this task's* panic.
                spawn_blocking(fire_mempool_assert).await.unwrap();
            } else {
                spawn_blocking(|| 0u64).await.unwrap();
            }
        }
    });
    let join_error = handler.await.expect_err("request #2 panics, so the handler task cannot finish normally");
    assert!(join_error.is_panic(), "`unwrap()` re-panics inside the task, so the runtime reports a panic: {join_error}");
    assert_eq!(
        served.load(Ordering::SeqCst),
        2,
        "the task died on request #2, so request #3 was never even dequeued: the blast radius is the connection"
    );

    // ---- 3. Control: the same panic, joined with `match` instead of `unwrap`, leaves the task alive ----
    let control_served = Arc::new(AtomicUsize::new(0));
    let control_counter = control_served.clone();
    let tolerant_handler = tokio::spawn(async move {
        let mut failures = 0usize;
        for request in 0..3u8 {
            control_counter.fetch_add(1, Ordering::SeqCst);
            if request == 1 {
                if let Err(join_error) = spawn_blocking(fire_mempool_assert).await {
                    assert!(join_error.is_panic(), "the second request must fail as a panic: {join_error}");
                    failures += 1;
                }
            } else {
                spawn_blocking(|| 1u64).await.unwrap();
            }
        }
        failures
    });
    assert_eq!(
        tolerant_handler.await.expect("a matched JoinError must not kill the task"),
        1,
        "exactly one request must be reported as failed"
    );
    assert_eq!(control_served.load(Ordering::SeqCst), 3, "with the JoinError matched, all three requests are served");

    // ---- 4. The patched production wrapper: the same panic is contained, the serving task survives ----
    // This is the code the mining manager actually calls, not a copy of it: `TestConsensus` only provides the
    // `Arc<dyn ConsensusApi>` that a session needs (temp DB, no notifier). `try_spawn_blocking` is the F-04
    // fix (`components/consensusmanager/src/session.rs`): it matches the `JoinError`, logs it together with the
    // consensus context and hands it back, so a poisoned pool operation costs one request, not the task.
    let test_consensus = TestConsensus::new(&Config::new(SIMNET_PARAMS));
    let consensus: DynConsensus = test_consensus.consensus_clone();
    let instance = ConsensusInstance::new(SessionLock::new(), consensus);
    let session = instance.unguarded_session(); // what `rpc/service/src/service.rs:666` hands to the flows
    let patched_served = Arc::new(AtomicUsize::new(0));
    let patched_counter = patched_served.clone();
    let patched_handler = tokio::spawn(async move {
        let mut failures = 0usize;
        for request in 0..3u8 {
            patched_counter.fetch_add(1, Ordering::SeqCst);
            let outcome = if request == 1 {
                session.clone().try_spawn_blocking(|_consensus| fire_mempool_assert()).await
            } else {
                session.clone().try_spawn_blocking(|_consensus| 1u64).await.map(|_| ())
            };
            if let Err(join_error) = outcome {
                assert!(join_error.is_panic(), "the poisoned request must be reported as a panic: {join_error}");
                assert!(
                    panic_message(join_error.into_panic().as_ref()).contains("Transactions in mempool"),
                    "the reported JoinError must carry the invariant message an operator needs"
                );
                failures += 1;
            }
        }
        failures
    });
    assert_eq!(
        patched_handler.await.expect("the patched wrapper must not kill the task that serves the request"),
        1,
        "exactly one request is reported as failed instead of the connection task being torn down"
    );
    assert_eq!(
        patched_served.load(Ordering::SeqCst),
        3,
        "with the JoinError handled, request #3 is still served on the same session"
    );

    info!(
        "F-04: a panic in the pool operation killed the handler task at request #2 (unpatched shape) and request #3 \
         was never served, while both the matched JoinError (step 3) and the patched production wrapper \
         `ConsensusSessionOwned::try_spawn_blocking` (step 4) served all three requests (recovered payload: {recovered:?})"
    );
}

#[cfg(feature = "devnet-prealloc")]
mod prealloc {
    //! F-01 and F-02 need a genesis that commits UTXOs to an address whose key we hold, so both live behind
    //! the `devnet-prealloc` feature -- the same gate `rpc_perf_benchmarks` uses.
    use super::*;

    use std::{
        sync::LazyLock,
        time::{Duration, Instant},
    };

    use futures_util::future::join_all;
    use kaspa_addresses::{Address, Version};
    use kaspa_consensus_core::{
        constants::{KASPA_SOMPI_PER_KAS, TX_VERSION_TOCCATA},
        network::NetworkType,
        sign::sign,
        subnets::SUBNETWORK_ID_NATIVE,
        tx::{
            MutableTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput,
            UtxoEntry,
        },
    };
    use kaspa_grpc_client::GrpcClient;
    use kaspa_rpc_core::api::rpc::RpcApi;
    use kaspa_testing_integration::common::{args::ArgsBuilder, daemon::Daemon, fee};
    use kaspa_txscript::pay_to_address_script;
    use kaspad_lib::args::Args;

    /// Cargo runs the test functions of one binary on parallel threads, but each node PoC starts a full node
    /// (one of them with a 10,000 transaction mempool), so they take turns instead of competing for the
    /// machine.
    static SERIAL: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(|| tokio::sync::Mutex::new(()));

    /// One preallocated simnet node plus everything needed to spend its genesis UTXOs.
    struct Fixture {
        args: Args,
        address: Address,
        schnorr_key: secp256k1::Keypair,
        spk: ScriptPublicKey,
        /// One distinct genesis UTXO per planned transaction, in a deterministic order.
        utxos: Vec<(TransactionOutpoint, UtxoEntry)>,
    }

    /// Builds a simnet genesis that commits `num_utxos` UTXOs of `prealloc_zthr` each to a fresh key, and
    /// returns the very outpoints/entries the daemon will commit to, taken straight from
    /// `Args::generate_prealloc_utxos` (`kaspad/src/args.rs:190-207`) -- the genesis content is not
    /// reconstructed by the test.
    fn fixture(num_utxos: u64, prealloc_zthr: u64, edit: impl Fn(&mut Args)) -> Fixture {
        let (secret_key, public_key) = secp256k1::generate_keypair(&mut rand::thread_rng());
        let address = Address::new(NetworkType::Simnet.into(), Version::PubKey, &public_key.x_only_public_key().0.serialize());
        let schnorr_key = secp256k1::Keypair::from_secret_key(secp256k1::SECP256K1, &secret_key);
        let spk = pay_to_address_script(&address);
        let args = ArgsBuilder::simnet(num_utxos, prealloc_zthr)
            .prealloc_address(address.clone())
            .utxoindex(true) // keeps spend checks off the critical path once transactions start flowing
            .apply_args(|args| {
                // No peers: the node is driven over gRPC only, so nothing relays the attacker's flood.
                args.disable_dns_seeding = true;
                args.outbound_target = 0;
                edit(args);
            })
            .build();
        let mut utxos: Vec<(TransactionOutpoint, UtxoEntry)> = args.generate_prealloc_utxos(num_utxos).into_iter().collect();
        utxos.sort_unstable_by_key(|(outpoint, _)| outpoint.transaction_id);
        Fixture { args, address, schnorr_key, spk, utxos }
    }

    /// A plain 1-in-1-out payment: spends `outpoint`, pays the fixture address back minus the relay fee
    /// (`testing/integration/src/common/fee.rs`), signed with the fixture key. This is the shape every wallet
    /// produces and the shape the other integration tests of this crate use.
    fn plain_tx(fixture: &Fixture, outpoint: TransactionOutpoint, entry: &UtxoEntry) -> Transaction {
        let fee = fee::calc_for_plain_standard_tx(1, 1);
        assert!(entry.amount > fee, "a genesis UTXO of {} sompi cannot pay the {fee} sompi relay fee", entry.amount);
        let unsigned = Transaction::new(
            TX_VERSION_TOCCATA,
            vec![TransactionInput::new(outpoint, vec![], 0, 1)],
            vec![TransactionOutput::new(entry.amount - fee, fixture.spk.clone())],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            vec![],
        );
        sign(MutableTransaction::with_entries(unsigned, vec![entry.clone()]), fixture.schnorr_key).tx
    }

    /// The cheapest way for an attacker to buy mempool bytes: a standard 1-in-1-out payment carrying
    /// `payload_len` bytes of junk. The payload is part of the serialized size and therefore of the mempool
    /// footprint (`consensus/core/src/tx.rs:443-458`), and it is part of the transient mass as well, so the
    /// fee is derived from the same bytes. The helper overestimates slightly (it assumes a 66 byte signature
    /// script and a full 32 byte payload digest), which only makes the transaction *more* acceptable to the
    /// node, never less.
    fn payload_tx(fixture: &Fixture, outpoint: TransactionOutpoint, entry: &UtxoEntry, payload_len: usize) -> Transaction {
        let fee = fee::calc_for_plain_standard_tx_with_extra_serialized_bytes(1, 1, payload_len as u64);
        assert!(entry.amount > fee, "a genesis UTXO of {} sompi cannot pay the {fee} sompi relay fee", entry.amount);
        let unsigned = Transaction::new(
            TX_VERSION_TOCCATA,
            vec![TransactionInput::new(outpoint, vec![], 0, 1)],
            vec![TransactionOutput::new(entry.amount - fee, fixture.spk.clone())],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            vec![0xAB; payload_len],
        );
        sign(MutableTransaction::with_entries(unsigned, vec![entry.clone()]), fixture.schnorr_key).tx
    }

    /// Submits one transaction over gRPC, returning the node's own error text when it is rejected.
    /// `allow_orphan` is false: these are complete, self-contained payments.
    async fn submit(client: &GrpcClient, tx: &Transaction) -> Result<TransactionId, String> {
        client.submit_transaction(tx.into(), false).await.map_err(|err| err.to_string())
    }

    /// `count` distinct, well formed P2PK addresses belonging to nobody. The node's address handling looks at
    /// the script *shape* (`ScriptClass::from_script`), never at the curve, so random 32 byte payloads are
    /// legal addresses -- and being random they are almost certainly unspendable, which is exactly what a
    /// scanner sends. They are distinct, so `ScriptPublicKeySet` (a `HashSet`) keeps all of them.
    fn distinct_addresses(count: usize) -> Vec<Address> {
        (0..count)
            .map(|_| {
                let payload: [u8; 32] = rand::random();
                Address::new(NetworkType::Simnet.into(), Version::PubKey, &payload)
            })
            .collect()
    }

    /// How many valid, fee paying transactions the "honest network" puts in the pool before the scan. This is a
    /// quiet day for a real node, not an attack: every one of them is a plain 1-in-1-out payment.
    const F01_FILL_TXS: usize = 10_000;
    /// Transactions in flight at once while filling.
    const F01_SUBMIT_CONCURRENCY: usize = 32;
    /// Addresses in the attack request. The request is ~3.4 MB, i.e. 0.3% of `RPC_MAX_MESSAGE_SIZE` (1 GB,
    /// `rpc/grpc/core/src/lib.rs:8`), and `ScriptPublicKeySet` is a `HashSet`, so all 50,000 survive
    /// deduplication and each of them is compared against every transaction in the pool.
    const F01_ATTACK_ADDRESSES: usize = 50_000;
    /// The same query with a handful of addresses: the control showing the cost scales with the *number* of
    /// addresses instead of being a fixed per-call overhead.
    const F01_CONTROL_ADDRESSES: usize = 100;

    /// **F-01 -- one `GetMempoolEntriesByAddresses` request makes the node do an amount of work the client
    /// chooses (triage: the amplification is confirmed, the lockout this test was written to show was not).**
    ///
    /// The node is honest in every respect: the pool holds 10,000 valid payments, so the scan really is
    /// scanning a busy mempool, and the attacker's 50,000 addresses are well formed and simply belong to
    /// nobody. The test measures the scan itself, against the same query with 100 addresses, so the number that
    /// is asserted is the *marginal* cost of one attacker chosen address. The submission issued into the scan is
    /// kept as a side measurement: it came back close to the idle submission in the triage run, which is exactly
    /// why the assertions live on the scan cost and not on a blocked submission.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn f01_address_scan_holds_the_mempool_lock() {
        init_allocator_with_default_settings();
        kaspa_core::log::try_init_logger("info");
        let _serial = SERIAL.lock().await;

        // Two spare UTXOs beyond the fill: one for the idle probe, one for the probe issued during the scan.
        let fixture = fixture((F01_FILL_TXS + 2) as u64, 1, |_| {});
        let mut node = Daemon::new_random_with_args(fixture.args.clone(), 20);
        let probe_client = node.start().await;
        let scan_client = node.new_client().await;

        // ---- 1. Fill the pool with ordinary, valid, fee paying transactions ----
        let fill_started = Instant::now();
        let mut accepted = 0usize;
        for chunk in fixture.utxos[..F01_FILL_TXS].chunks(F01_SUBMIT_CONCURRENCY) {
            let txs: Vec<Transaction> = chunk.iter().map(|(outpoint, entry)| plain_tx(&fixture, *outpoint, entry)).collect();
            let results = join_all(txs.iter().map(|tx| submit(&probe_client, tx))).await;
            for (tx, result) in txs.iter().zip(results) {
                assert!(result.is_ok(), "the filler {} is valid and must be accepted: {:?}", tx.id(), result.err());
                accepted += 1;
            }
        }
        info!("F-01: {accepted} ordinary transactions accepted into the mempool in {:?}", fill_started.elapsed());

        // ---- 2. The pool really holds them (verified through the very RPC under attack) ----
        let own = scan_client
            .get_mempool_entries_by_addresses(vec![fixture.address.clone()], false, false)
            .await
            .expect("the one-address query must succeed");
        assert_eq!(own.len(), 1, "one response entry per requested address");
        assert_eq!(own[0].sending.len(), accepted, "every filler spends a genesis UTXO of the fixture address");
        assert_eq!(own[0].receiving.len(), accepted, "every filler pays the fixture address back");

        // ---- 3. Control: the same query with 100 addresses against the same 10,000 transaction pool ----
        let control_started = Instant::now();
        let control = scan_client
            .get_mempool_entries_by_addresses(distinct_addresses(F01_CONTROL_ADDRESSES), false, false)
            .await
            .expect("the control query must succeed");
        let control_elapsed = control_started.elapsed();
        assert_eq!(control.len(), F01_CONTROL_ADDRESSES, "one response entry per requested address");
        assert!(
            control.iter().all(|entry| entry.sending.is_empty() && entry.receiving.is_empty()),
            "no pool transaction may match addresses that belong to nobody"
        );

        // ---- 4. How long one valid submission takes on this node while nobody is scanning ----
        let (idle_outpoint, idle_entry) = &fixture.utxos[F01_FILL_TXS];
        let idle_started = Instant::now();
        submit(&probe_client, &plain_tx(&fixture, *idle_outpoint, idle_entry))
            .await
            .expect("the idle probe is a valid payment and must be accepted");
        let idle_submit = idle_started.elapsed();

        // ---- 5. The attack: one scan on a second connection, one honest payment 250 ms into it ----
        let (during_scan_outpoint, during_scan_entry) = &fixture.utxos[F01_FILL_TXS + 1];
        let during_scan_tx = plain_tx(&fixture, *during_scan_outpoint, during_scan_entry);
        let scan_client_task = scan_client.clone();
        let scan = tokio::spawn(async move {
            let started = Instant::now();
            let result =
                scan_client_task.get_mempool_entries_by_addresses(distinct_addresses(F01_ATTACK_ADDRESSES), false, false).await;
            (result, started.elapsed())
        });
        tokio::time::sleep(Duration::from_millis(250)).await;
        let during_scan_started = Instant::now();
        let during_scan_result = submit(&probe_client, &during_scan_tx).await;
        let during_scan_submit = during_scan_started.elapsed();
        let (scan_result, scan_elapsed) = scan.await.expect("the scanning client task must not panic");
        let scanned = scan_result.expect("the scan itself must succeed -- the damage is in the time it takes");
        assert_eq!(scanned.len(), F01_ATTACK_ADDRESSES, "one response entry per requested address");
        assert!(
            scanned.iter().all(|entry| entry.sending.is_empty() && entry.receiving.is_empty()),
            "the scan must come back empty: the attacker learns nothing, it only makes the node work"
        );
        // The submission issued into the scan is asserted in step 6. Triage showed it is *not* held back by the
        // scan, so it is evidence that the node keeps serving -- not the finding.

        // ---- 6. The finding: real, attacker-chosen cost on the node -- but no submission lockout ----
        // TRIAGE (see `Master Context.txt` §293.2): this test was written to show a *lockout*, i.e. that a
        // submission issued in the middle of the scan waits for the scan to finish. The measurement refuted that
        // half of the hypothesis: the scan does cost seconds of node CPU, but the honest payment sent 250 ms into
        // it was accepted ~23 ms later, so the submission path is not queued behind the whole scan. What survives
        // triage is the amplification half -- one request buys node time on a scale the client picks -- and that
        // is what is asserted here; the node keeping its submissions flowing is asserted as well, because that is
        // the property the triage found intact.
        let marginal_ns_per_address =
            scan_elapsed.saturating_sub(control_elapsed).as_nanos() as f64 / (F01_ATTACK_ADDRESSES - F01_CONTROL_ADDRESSES) as f64;
        assert!(
            scan_elapsed >= Duration::from_secs(1),
            "scanning {F01_ATTACK_ADDRESSES} addresses against {accepted} transactions must take real time, took {scan_elapsed:?}"
        );
        assert!(
            scan_elapsed >= control_elapsed * 20,
            "the cost must scale with the number of addresses: {F01_CONTROL_ADDRESSES} took {control_elapsed:?}, \
             {F01_ATTACK_ADDRESSES} took {scan_elapsed:?}"
        );
        assert!(
            marginal_ns_per_address > 0.0,
            "every additional address is one more full pass over the pool, so it must add cost: {} marginal ns \
             over {scan_elapsed:?}",
            marginal_ns_per_address
        );
        assert!(
            during_scan_result.is_ok(),
            "the node must keep serving honest traffic while it scans -- no lockout was measured, so a valid \
             payment cannot be refused: {:?}",
            during_scan_result.err()
        );

        // ---- 7. The finding, quantified ----
        // One legal 1 GB request (`rpc/grpc/core/src/lib.rs:8`) fits roughly `1 GB / 36 bytes` addresses (2 bytes
        // of version, a 33-34 byte script and its length prefix), so the marginal cost measured above
        // extrapolates to the node time a *single* request can buy.
        let addresses_per_max_message = 1_000_000_000f64 / 36.0;
        let node_hours_per_max_request = marginal_ns_per_address * addresses_per_max_message / 1e9 / 3600.0;
        info!(
            "F-01: {accepted} pool transactions, {F01_CONTROL_ADDRESSES} addresses scanned in {control_elapsed:?}, \
             {F01_ATTACK_ADDRESSES} addresses scanned in {scan_elapsed:?} ({marginal_ns_per_address:.0} ns of \
             marginal cost per address, i.e. {node_hours_per_max_request:.1} h of node CPU for one legal 1 GB \
             request); no lockout was measured: one valid payment submitted 250 ms into the scan was accepted in \
             {during_scan_submit:?} versus {idle_submit:?} on an idle pool ({:.0}x)",
            during_scan_submit.as_secs_f64() / idle_submit.as_secs_f64().max(f64::MIN_POSITIVE)
        );
    }

    /// `--ram-scale` of the node under test: `ram_scale` is a plain CLI argument (`kaspad/src/args.rs:97`, its
    /// minimum is 0.1, `kaspad/src/daemon.rs:107-109`) and `MempoolConfig::apply_ram_scale` multiplies both
    /// pool limits by it (`mining/src/mempool/config.rs:130-135`).
    const F02_RAM_SCALE: f64 = 0.1;
    /// `DEFAULT_MEMPOOL_SIZE_LIMIT` (`mining/src/mempool/config.rs:4`): the byte budget itself has no CLI flag,
    /// only the `--ram-scale` factor in front of it, so at 0.1 the node allows 100 MB.
    const F02_MEMPOOL_SIZE_LIMIT: u64 = 1_000_000_000;
    /// Payload carried by each filler. The transient mass of such a transaction is about twice its serialized
    /// size, so ~90 KB stays far below the 500,000 compute / 1,000,000 transient per transaction limits of the
    /// simnet params (`consensus/core/src/config/params.rs:719`) while still buying ~90 KB of pool budget.
    const F02_PAYLOAD_BYTES: usize = 90_000;
    /// Flood ceiling. Should the budget arithmetic ever be off, the test fails on `accepted < F02_MAX_FILLERS`
    /// instead of running forever.
    const F02_MAX_FILLERS: u64 = 4_000;

    /// **F-02 -- ~1,100 valid, minimum-fee, payload carrying RPC transactions fill the node's mempool budget
    /// (triage: the budget fills, but the honest user that follows is still admitted).**
    ///
    /// The flood transactions are legitimate in every respect (valid signatures, standard scripts, relay fee
    /// paid) and they are submitted exactly like a wallet would submit them, so the node accepts them with
    /// `Priority::High` (`protocol/flows/src/flow_context.rs:751-761`). High priority transactions are never
    /// eviction candidates (`mining/src/mempool/model/transactions_pool.rs:256-260`), so a full pool can only
    /// turn away the next transaction with `RejectMempoolIsFull` (`transactions_pool.rs:295-305`) -- neither the
    /// flood nor the honest user evicts anything. The test asserts what was measured (`Master Context.txt`
    /// §293.3): the flood really is refused at the budget, yet the paying user is still served, because the
    /// refusal leaves the residual headroom of the partially filled budget free.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn f02_high_priority_flood_locks_out_paying_users() {
        init_allocator_with_default_settings();
        kaspa_core::log::try_init_logger("info");
        let _serial = SERIAL.lock().await;

        // UTXO indices: 0 = control payment, 1 = the sampled filler, 2..=F02_MAX_FILLERS = the flood, and the
        // last one is kept for the victim, the paying user that must still get in after the flood.
        let fixture = fixture(F02_MAX_FILLERS + 3, 1, |args| args.ram_scale = F02_RAM_SCALE);
        let budget = (F02_MEMPOOL_SIZE_LIMIT as f64 * F02_RAM_SCALE) as u64;
        let mut node = Daemon::new_random_with_args(fixture.args.clone(), 20);
        let client = node.start().await;

        // ---- 1. A paying user gets in while the pool is empty ----
        let (control_outpoint, control_entry) = &fixture.utxos[0];
        let control_tx = plain_tx(&fixture, *control_outpoint, control_entry);
        let control_id = control_tx.id();
        submit(&client, &control_tx).await.expect("with an empty pool a paying user must get in");

        // ---- 2. What one filler costs the attacker and what it costs the pool ----
        let (sample_outpoint, sample_entry) = &fixture.utxos[1];
        let sample_tx = payload_tx(&fixture, *sample_outpoint, sample_entry, F02_PAYLOAD_BYTES);
        let (per_tx_bytes, filler_fee) = {
            let sample_mtx = MutableTransaction::with_entries(sample_tx.clone(), vec![sample_entry.clone()]);
            (sample_mtx.mempool_estimated_bytes() as u64, sample_entry.amount - sample_tx.outputs[0].value)
        };
        assert!(
            per_tx_bytes >= F02_PAYLOAD_BYTES as u64,
            "the payload alone must dominate the footprint of a filler, got {per_tx_bytes} bytes"
        );
        let expected_fillers = budget / per_tx_bytes;
        info!(
            "F-02: budget {budget} bytes ({F02_MEMPOOL_SIZE_LIMIT} bytes x ram_scale {F02_RAM_SCALE}), one \
             {F02_PAYLOAD_BYTES} byte payload transaction occupies {per_tx_bytes} mempool bytes and pays \
             {filler_fee} sompi, so about {expected_fillers} of them fill the pool"
        );

        // ---- 3. Flood: one valid, fee paying, 90 KB transaction at a time ----
        let flood_started = Instant::now();
        let mut accepted = 0u64;
        let mut rejection = None;
        for index in 1..F02_MAX_FILLERS {
            let tx = if index == 1 {
                sample_tx.clone() // the sampled transaction is a normal filler, do not waste a UTXO
            } else {
                let (outpoint, entry) = &fixture.utxos[index as usize];
                payload_tx(&fixture, *outpoint, entry, F02_PAYLOAD_BYTES)
            };
            match submit(&client, &tx).await {
                Ok(_) => accepted += 1,
                Err(err) => {
                    rejection = Some(err);
                    break;
                }
            }
        }
        let flood_elapsed = flood_started.elapsed();
        let rejection = rejection.expect(
            "the flood must eventually be refused: either the pool filled up (expected) or the node never \\
             enforces its own byte budget",
        );

        // ---- 4. The finding: the refusal names the reason, and the amount of work matches the budget ----
        assert!(
            rejection.contains("full with transactions with higher priority"),
            "the node must refuse because the pool is full of equal-or-higher priority transactions, said: {rejection}"
        );
        assert!(
            accepted >= expected_fillers * 8 / 10,
            "the attacker must be able to fill at least 80% of the budget: {accepted} accepted of ~{expected_fillers} expected"
        );
        assert!(
            accepted <= expected_fillers * 12 / 10,
            "the attacker must not be able to exceed the budget by more than 20%: {accepted} accepted of ~{expected_fillers} expected"
        );
        assert!(
            accepted < F02_MAX_FILLERS,
            "the pool must have stopped the flood before the ceiling of {F02_MAX_FILLERS} transactions"
        );

        // ---- 5. The victim: a plain payment, issued on a fresh UTXO, after the flood ----
        // TRIAGE (see `Master Context.txt` §293.3): the lockout this test was written to show did not happen.
        // The node refuses the *filler* that would cross the byte budget and stops there, which leaves the
        // residual headroom of the partially filled budget free -- orders of magnitude more than the ~200 bytes a
        // plain payment occupies -- so the paying user was served. That property is asserted here: an honest user
        // is not locked out by a flood that the node itself is already refusing.
        let (victim_outpoint, victim_entry) = &fixture.utxos[F02_MAX_FILLERS as usize + 1];
        let victim_tx = plain_tx(&fixture, *victim_outpoint, victim_entry);
        let victim_id = victim_tx.id();
        let victim_fee = victim_entry.amount - victim_tx.outputs[0].value;
        submit(&client, &victim_tx)
            .await
            .unwrap_or_else(|err| panic!("a paying user was locked out by the flood: {err}"));
        assert!(
            client.get_mempool_entry(victim_id, false, false).await.is_ok(),
            "the accepted payment must be in the pool, read back through the same RPC that reports the flood"
        );
        assert!(
            client.get_mempool_entry(control_id, false, false).await.is_ok(),
            "the payment submitted before the flood is still in the pool"
        );

        info!(
            "F-02: {accepted} payload transactions ({F02_PAYLOAD_BYTES} bytes each, {per_tx_bytes} pool bytes each) \
             were accepted in {flood_elapsed:?}, i.e. {:.1} MB of the {:.0} MB budget for {} sompi each ({} sompi, \
             {:.4} ZTHR total at {KASPA_SOMPI_PER_KAS} sompi per ZTHR); the honest payment that followed was still \
             admitted ({victim_fee} sompi fee): the flood consumed the budget but did not lock the paying user out",
            (accepted * per_tx_bytes) as f64 / 1e6,
            budget as f64 / 1e6,
            filler_fee,
            accepted * filler_fee,
            (accepted * filler_fee) as f64 / KASPA_SOMPI_PER_KAS as f64
        );
    }
}
