//! Zethora GHOSTDAG integration test (attack phase): a block which declares two valid, known direct parents but
//! declares them with the wrong first parent — `direct_parents()[0]` swapped with another parent — must be refused by
//! the real production pipeline with `BlockStatus::StatusDisqualifiedFromChain`.
//!
//! This is deliberately *not* a replica test. There is no GHOSTDAG logic here, no expected blue set, no expected
//! state and no expected hash. Every block is built, mined and processed by `TestConsensus`, the DAG is resolved by
//! the production code, and the only thing asserted is the `BlockStatus` the production pipeline itself returns.

use crate::{config::ConfigBuilder, consensus::test_consensus::TestConsensus};
use kaspa_consensus_core::coinbase::MinerData;
use kaspa_consensus_core::tx::ScriptPublicKey;
use kaspa_consensus_core::{api::ConsensusApi, blockstatus::BlockStatus, config::params::DEVNET_PARAMS};

#[tokio::test]
async fn swapped_first_direct_parent_is_disqualified_from_chain() {
    let config = ConfigBuilder::new(DEVNET_PARAMS).skip_proof_of_work().build();
    let tc = TestConsensus::new(&config);
    let handles = tc.init();
    let genesis = config.genesis.hash;

    // A valid block sequence, processed through the real pipeline: genesis -> a -> a2 (the deeper branch)
    let a = tc.build_utxo_valid_block_with_parents(
        1.into(),
        vec![genesis],
        MinerData::new(ScriptPublicKey::from_vec(0, vec![]), vec![]),
        vec![],
    );
    let a_hash = a.header.hash;
    let status = tc
        .validate_and_insert_block(a.to_immutable())
        .virtual_state_task
        .await
        .expect("a is a valid block on genesis");
    assert_eq!(status, BlockStatus::StatusUTXOValid, "the sequence's first block must be accepted, got {status:?}");

    let a2 = tc.build_utxo_valid_block_with_parents(
        2.into(),
        vec![a_hash],
        MinerData::new(ScriptPublicKey::from_vec(0, vec![]), vec![]),
        vec![],
    );
    let a2_hash = a2.header.hash;
    let status = tc
        .validate_and_insert_block(a2.to_immutable())
        .virtual_state_task
        .await
        .expect("a2 is a valid block on a");
    assert_eq!(status, BlockStatus::StatusUTXOValid, "the sequence's second block must be accepted, got {status:?}");

    // A second, shorter branch: genesis -> b. Both branches are known and non-related, so {a2, b} is a legal parent set
    let b = tc.build_utxo_valid_block_with_parents(
        3.into(),
        vec![genesis],
        MinerData::new(ScriptPublicKey::from_vec(0, vec![]), vec![]),
        vec![],
    );
    let b_hash = b.header.hash;
    let status = tc
        .validate_and_insert_block(b.to_immutable())
        .virtual_state_task
        .await
        .expect("b is a valid block on genesis");
    assert_eq!(status, BlockStatus::StatusUTXOValid, "the sibling branch's block must be accepted, got {status:?}");

    // Positive control: the very same parent set, declared with the production-preferred first parent, is accepted.
    // This proves the two parents are individually fine and that nothing but the declared order differs below.
    let control = tc.build_utxo_valid_block_with_parents(
        4.into(),
        vec![a2_hash, b_hash],
        MinerData::new(ScriptPublicKey::from_vec(0, vec![]), vec![]),
        vec![],
    );
    let status = tc
        .validate_and_insert_block(control.to_immutable())
        .virtual_state_task
        .await
        .expect("the parent set {a2, b} is legal");
    assert_eq!(
        status,
        BlockStatus::StatusUTXOValid,
        "the correctly ordered block on parents {{a2, b}} must be accepted, got {status:?}"
    );

    // The attack: the identical parent set with `direct_parents()[0]` swapped, so the block declares `b` first.
    // The production pipeline must resolve this itself and disqualify the block from the chain.
    let swapped = tc.build_utxo_valid_block_with_parents(
        5.into(),
        vec![b_hash, a2_hash],
        MinerData::new(ScriptPublicKey::from_vec(0, vec![]), vec![]),
        vec![],
    );
    let swapped_hash = swapped.header.hash;
    let result = tc.validate_and_insert_block(swapped.to_immutable()).virtual_state_task.await;

    let status = match result {
        Ok(status) => status,
        Err(err) => panic!(
            "the pipeline returned an error for block {swapped_hash} whose direct_parents()[0] was swapped \
             (parents [{b_hash}, {a2_hash}]) instead of a block status: {err:?}"
        ),
    };

    // The only assertion of this test: the status the production pipeline actually computed for the swapped block.
    assert_eq!(
        status,
        BlockStatus::StatusDisqualifiedFromChain,
        "production returned {status:?} for block {swapped_hash} whose direct_parents()[0] was swapped with another \
         parent (declared [{b_hash}, {a2_hash}]), expected StatusDisqualifiedFromChain"
    );

    tc.shutdown(handles);
}
