//! Zethora: serves the private state at the pruning point to a node joining from it (ZTH-SPEC-006 §6.4).
//!
//! Sends the private coin list, then every spent private coin tag, then every coin list snapshot (with the blue score of
//! the block that produced it), in chunks. The joining node checks all of it against the fingerprint sealed in the
//! pruning point's coinbase, so a wrong answer from this node only costs it the peer, never the joiner's safety.

use crate::flowcontext::zethora_state_cache::RequestLimiter;
use crate::{
    flow_context::FlowContext,
    flow_trait::Flow,
    ibd::{ZETHORA_PRIVATE_STATE_CHUNK_SIZE, ZETHORA_PRIVATE_STATE_FLOW_CONTROL_WINDOW},
};
use kaspa_consensus_core::errors::consensus::ConsensusError;
use kaspa_core::info;
use kaspa_hashes::Hash;
use kaspa_p2p_lib::{
    IncomingRoute, Router,
    common::ProtocolError,
    dequeue, make_message,
    pb::{UnexpectedPruningPointMessage, ZethoraPrivateStateChunkMessage, ZethoraPrivateStateHeaderMessage, kaspad_message::Payload},
};
use std::sync::Arc;

pub struct RequestZethoraPrivateStateFlow {
    ctx: FlowContext,
    router: Arc<Router>,
    incoming_route: IncomingRoute,
    /// Seam review P3-1: how often this connection asked for each pruning point's state
    requests: RequestLimiter<Hash>,
}

/// Seam review P3-1: an honest joiner asks once per sync attempt; a few retries on one connection are fine.
const MAX_REQUESTS_PER_PRUNING_POINT: usize = 3;

#[async_trait::async_trait]
impl Flow for RequestZethoraPrivateStateFlow {
    fn router(&self) -> Option<Arc<Router>> {
        Some(self.router.clone())
    }

    async fn start(&mut self) -> Result<(), ProtocolError> {
        self.start_impl().await
    }
}

impl RequestZethoraPrivateStateFlow {
    pub fn new(ctx: FlowContext, router: Arc<Router>, incoming_route: IncomingRoute) -> Self {
        Self { ctx, router, incoming_route, requests: RequestLimiter::new(MAX_REQUESTS_PER_PRUNING_POINT) }
    }

    async fn start_impl(&mut self) -> Result<(), ProtocolError> {
        loop {
            let expected_pp = dequeue!(self.incoming_route, Payload::RequestZethoraPrivateState)?.try_into()?;
            self.handle_request(expected_pp).await?
        }
    }

    async fn handle_request(&mut self, expected_pp: Hash) -> Result<(), ProtocolError> {
        if !self.requests.allow(expected_pp) {
            return Err(ProtocolError::OtherOwned(format!(
                "asked for the private state of pruning point {expected_pp} more than {MAX_REQUESTS_PER_PRUNING_POINT} times"
            )));
        }
        // Seam review P3-1: built once per pruning point (under one consensus session, so pruning cannot rewrite the
        // records meanwhile) and kept; every later request is answered from the kept copy without a session. The
        // pruning point is checked on every request, so a moved pruning point is answered as before.
        let session = self.ctx.consensus().unguarded_session();
        if session.async_pruning_point().await != expected_pp {
            self.router.enqueue(make_message!(Payload::UnexpectedPruningPoint, UnexpectedPruningPointMessage {})).await?;
            return Ok(());
        }
        let ctx = self.ctx.clone();
        let built = self
            .ctx
            .zethora_private_state_cache
            .get_or_build(expected_pp, || async move {
                let session = ctx.consensus().session().await;
                session.async_get_zethora_private_state(expected_pp).await
            })
            .await;
        let state = match built {
            Err(ConsensusError::UnexpectedPruningPoint) => {
                self.router.enqueue(make_message!(Payload::UnexpectedPruningPoint, UnexpectedPruningPointMessage {})).await?;
                return Ok(());
            }
            res => res,
        }?;

        self.router
            .enqueue(make_message!(
                Payload::ZethoraPrivateStateHeader,
                ZethoraPrivateStateHeaderMessage {
                    note_tree: state.note_tree.clone(),
                    spent_count: state.spent.len() as u64,
                    anchor_count: state.anchors.len() as u64,
                }
            ))
            .await?;

        #[allow(clippy::arithmetic_side_effects, reason = "ARITH-SAFETY(LENGTH)")]
        let total = state.spent.len() + state.anchors.len();
        let mut items_sent = 0usize;
        let mut chunks_sent = 0usize;
        let spent_chunks = state
            .spent
            .chunks(ZETHORA_PRIVATE_STATE_CHUNK_SIZE)
            .map(|chunk| ZethoraPrivateStateChunkMessage { spent: chunk.iter().flatten().copied().collect(), anchors: Vec::new() });
        let anchor_chunks = state.anchors.chunks(ZETHORA_PRIVATE_STATE_CHUNK_SIZE).map(|chunk| ZethoraPrivateStateChunkMessage {
            spent: Vec::new(),
            anchors: chunk.iter().flat_map(|(root, blue_score)| root.iter().copied().chain(blue_score.to_le_bytes())).collect(),
        });
        for message in spent_chunks.chain(anchor_chunks) {
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "ARITH-SAFETY(LENGTH): byte lengths divided by the nonzero item sizes 32 and 40."
            )]
            let items = message.spent.len() / 32 + message.anchors.len() / 40;
            self.router.enqueue(make_message!(Payload::ZethoraPrivateStateChunk, message)).await?;
            #[allow(clippy::arithmetic_side_effects, reason = "ARITH-SAFETY(COUNTER)")]
            {
                items_sent += items;
                chunks_sent += 1;
            }
            // Flow control: wait for the joiner to ask for more after every window, except after the last chunk
            if items_sent < total && chunks_sent.is_multiple_of(ZETHORA_PRIVATE_STATE_FLOW_CONTROL_WINDOW) {
                dequeue!(self.incoming_route, Payload::RequestNextZethoraPrivateStateChunk)?;
            }
        }

        info!(
            "Zethora: sent the private state of pruning point {}: {} spent private coin tags, {} coin list snapshots in {} chunks",
            expected_pp,
            state.spent.len(),
            state.anchors.len(),
            chunks_sent
        );
        Ok(())
    }
}
