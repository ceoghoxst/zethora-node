//! End-to-end proof that the Zethora stack works together in one process.
//!
//! The four legs of the stack are driven in order, each on the output of the
//! previous one:
//!
//! 1. **L1** — a real [`TestConsensus`] devnet is started and ten blocks are
//!    mined; the chain must advance by exactly ten blue scores.
//! 2. **Bridge** — one L1 lock event is simulated with the federation's
//!    [`FederationSigner`], a secp256k1 [`MintProof`] is produced for it, and
//!    the mint is executed against the real [`zethora_evm::EvmExecutor`]; the
//!    depositor's wZTHR balance must rise by exactly the mintable amount.
//! 3. **EVM** — the DEX AMM contract is deployed into the executor and its
//!    constructor state (the two token addresses) is read back out of EVM
//!    storage.
//! 4. **DEX** — a swap is executed against the deployed pair and the trader's
//!    token balances and the pool reserves must move by exactly the amounts the
//!    constant-product invariant (with its 0.3% fee) dictates.
//!
//! No node, bridge or DEX code is stubbed, re-implemented or patched: this file
//! only calls the public APIs, so a green run means the *stack* works, not
//! merely that the pieces exist.

#![allow(clippy::arithmetic_side_effects)]

use alloy_primitives::{Address, U256};
use kaspa_alloc::init_allocator_with_default_settings;
use kaspa_consensus::config::ConfigBuilder;
use kaspa_consensus::consensus::test_consensus::TestConsensus;
use kaspa_consensus::model::stores::headers::HeaderStoreReader;
use kaspa_consensus::params::DEVNET_PARAMS;
use kaspa_consensus_core::blockstatus::BlockStatus;
use kaspa_consensus_core::Hash;
use zethora_bridge::{FederationSigner, LockEvent, LockStatus, MintProof, mint, wzthr_balance};
use zethora_dex::token::{balance_of, mint_to};
use zethora_dex::{add_liquidity, deploy, reserves, swap, tokens};
use zethora_evm::EvmExecutor;

/// How many L1 blocks to mine in step 1.
const BLOCKS_TO_MINE: u64 = 10;

#[tokio::test]
async fn zethora_stack_works_end_to_end() {
    init_allocator_with_default_settings();

    // -----------------------------------------------------------------------
    // Step 1 (L1): start a TestConsensus devnet and mine 10 blocks.
    // -----------------------------------------------------------------------
    let config = ConfigBuilder::new(DEVNET_PARAMS).skip_proof_of_work().build();
    let consensus = TestConsensus::new(&config);
    let consensus_handles = consensus.init();

    let genesis = consensus.params().genesis.hash;
    let genesis_score = consensus.headers_store().get_blue_score(genesis).expect("the genesis header exists");

    let mut tip = genesis;
    for height in 1..=BLOCKS_TO_MINE {
        let hash = Hash::from_u64_word(height);
        let status = consensus
            .add_empty_utxo_valid_block_with_parents(hash, vec![tip])
            .await
            .unwrap_or_else(|err| panic!("L1 block {height} must be accepted, got: {err:?}"));
        assert_eq!(status, BlockStatus::StatusUTXOValid, "L1 block {height} must reach the UTXO-valid status");
        tip = hash;
    }

    let tip_score = consensus.headers_store().get_blue_score(tip).expect("the tip header exists");
    assert_eq!(
        tip_score,
        genesis_score + BLOCKS_TO_MINE,
        "the L1 chain must advance by exactly {BLOCKS_TO_MINE} blue scores"
    );

    // The remaining steps exercise the L2 stack and no longer touch consensus,
    // so the node can be torn down here; `tip_score` is kept as the L1 height
    // the simulated deposit was confirmed at.
    consensus.shutdown(consensus_handles);

    // -----------------------------------------------------------------------
    // Step 2 (Bridge): simulate one L1 lock, prove it, and mint wZTHR on L2.
    // -----------------------------------------------------------------------
    // The 2-of-3 federation that custodies the deposit side of the bridge.
    let federation =
        FederationSigner::new(vec![[0x11; 32], [0x22; 32], [0x33; 32]], 2).expect("a 2-of-3 federation is valid");

    let mut executor = EvmExecutor::new();
    let wzthr_contract = Address::repeat_byte(0xc0);
    let depositor = Address::repeat_byte(0x11);

    // One L1 lock: 1,000,000 base units confirmed at the current L1 tip, held
    // under the federation's script, crediting `depositor` after a 1,000 fee.
    let lock = LockEvent {
        block_height: tip_score,
        block_hash: [0x42; 32],
        txid: [0xab; 32],
        outpoint: (0, 0),
        amount: U256::from(1_000_000u64),
        recipient: depositor,
        fee: U256::from(1_000u64),
        status: LockStatus::Live,
    };

    // The secp256k1 mint proof: the federation signs the deposit statement for
    // this exact recipient, amount and chain.
    let proof = MintProof::new(&lock, executor.chain_id(), depositor, &federation);

    assert!(wzthr_balance(&mut executor, wzthr_contract, depositor).is_zero(), "the depositor starts with no wZTHR");

    mint(&mut executor, federation.lock(), wzthr_contract, depositor, proof.amount, &proof.encode())
        .expect("a federation-authorised mint must be accepted by the L2 contract");

    assert_eq!(
        wzthr_balance(&mut executor, wzthr_contract, depositor),
        proof.amount,
        "the mint credits exactly the amount the proof commits to"
    );
    assert_eq!(proof.amount, U256::from(999_000u64), "1,000,000 locked less the 1,000 bridge fee");

    // -----------------------------------------------------------------------
    // Step 3 (EVM): deploy the DEX AMM contract and read its state back.
    // -----------------------------------------------------------------------
    let zthr = Address::repeat_byte(0x21);
    let wzthr = Address::repeat_byte(0x22);
    let trader = Address::repeat_byte(0xa1);

    let pair = deploy(&mut executor, zthr, wzthr).expect("the DEX pair must deploy");

    assert_eq!(pair.token0, zthr, "token0 is the lower address");
    assert_eq!(pair.token1, wzthr, "token1 is the higher address");
    assert_eq!(
        tokens(&mut executor, pair.pair),
        (zthr, wzthr),
        "the pair's constructor wrote its two token addresses into EVM storage"
    );
    assert_eq!(
        reserves(&mut executor, pair.pair),
        (U256::ZERO, U256::ZERO),
        "a freshly deployed pair holds no reserves"
    );

    // -----------------------------------------------------------------------
    // Step 4 (DEX): swap tokens through the L2 EVM and assert balances move.
    // -----------------------------------------------------------------------
    mint_to(&mut executor, pair.token0, trader, U256::from(10_000_000u64)).expect("seed token0 for the trader");
    mint_to(&mut executor, pair.token1, trader, U256::from(10_000_000u64)).expect("seed token1 for the trader");

    let liquidity = add_liquidity(
        &mut executor,
        pair.pair,
        trader,
        pair.token0,
        U256::from(1_000_000u64),
        pair.token1,
        U256::from(2_000_000u64),
    )
    .expect("the trader must be able to add liquidity");

    let reserves_before = reserves(&mut executor, pair.pair);
    let trader0_before = balance_of(&mut executor, pair.token0, trader);
    let trader1_before = balance_of(&mut executor, pair.token1, trader);

    let amount_in = U256::from(10_000u64);
    let amount_out = swap(&mut executor, pair.pair, trader, pair.token0, amount_in, U256::ZERO, U256::MAX)
        .expect("the swap must execute");

    let trader0_after = balance_of(&mut executor, pair.token0, trader);
    let trader1_after = balance_of(&mut executor, pair.token1, trader);
    let reserves_after = reserves(&mut executor, pair.pair);

    assert!(amount_out > U256::ZERO, "the swap must pay out");
    assert_eq!(trader0_after, trader0_before - amount_in, "the trader paid exactly the input token amount");
    assert_eq!(trader1_after, trader1_before + amount_out, "the trader received exactly the quoted output token amount");
    assert_eq!(reserves_after.0, reserves_before.0 + amount_in, "the pool gained the input token");
    assert_eq!(reserves_after.1, reserves_before.1 - amount_out, "the pool paid out the output token");

    // Pin the constant-product arithmetic (with its 0.3% fee) to the values the
    // DEX crate documents, so a drift in the invariant cannot pass silently.
    assert_eq!(liquidity, U256::from(1_413_213u64));
    assert_eq!(amount_out, U256::from(19_743u64));
    assert_eq!(reserves_after, (U256::from(1_010_000u64), U256::from(1_980_257u64)));
}

