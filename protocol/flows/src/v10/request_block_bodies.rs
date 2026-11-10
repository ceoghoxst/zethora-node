use crate::{
    flow_context::FlowContext,
    flow_trait::Flow,
    v10::MAX_BLOCK_HASHES_PER_REQUEST,
};
use kaspa_core::debug;
use kaspa_p2p_lib::{
    IncomingRoute, Router, common::ProtocolError, dequeue_with_request_id, make_response, pb::kaspad_message::Payload,
};
use std::sync::Arc;

pub struct HandleBlockBodyRequests {
    ctx: FlowContext,
    router: Arc<Router>,
    incoming_route: IncomingRoute,
}

#[async_trait::async_trait]
impl Flow for HandleBlockBodyRequests {
    fn router(&self) -> Option<Arc<Router>> {
        Some(self.router.clone())
    }

    async fn start(&mut self) -> Result<(), ProtocolError> {
        self.start_impl().await
    }
}

impl HandleBlockBodyRequests {
    pub fn new(ctx: FlowContext, router: Arc<Router>, incoming_route: IncomingRoute) -> Self {
        Self { ctx, router, incoming_route }
    }

    async fn start_impl(&mut self) -> Result<(), ProtocolError> {
        loop {
            let (msg, request_id) = dequeue_with_request_id!(self.incoming_route, Payload::RequestBlockBodies)?;
            // Zethora (OBS-4): same cap as `RequestRelayBlocks`. IBD itself asks for at most `IBD_BATCH_SIZE` (99)
            // bodies per message, so refusing more than this never affects an honest sync while it stops one request
            // from being turned into an unbounded stream of block bodies.
            if msg.hashes.len() > MAX_BLOCK_HASHES_PER_REQUEST {
                return Err(ProtocolError::OtherOwned(format!(
                    "requested {} block bodies in one message, over the limit of {MAX_BLOCK_HASHES_PER_REQUEST}",
                    msg.hashes.len()
                )));
            }
            let hashes: Vec<_> = msg.try_into()?;
            debug!("got request for {} blocks bodies", hashes.len());
            let session = self.ctx.consensus().unguarded_session();

            for hash in hashes {
                let body = session.async_get_block_body(hash).await?;
                self.router.enqueue(make_response!(Payload::BlockBody, body.as_ref().into(), request_id)).await?;
            }
        }
    }
}
