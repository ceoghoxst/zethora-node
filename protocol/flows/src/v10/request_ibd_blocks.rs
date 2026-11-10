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

pub struct HandleIbdBlockRequests {
    ctx: FlowContext,
    router: Arc<Router>,
    incoming_route: IncomingRoute,
}

#[async_trait::async_trait]
impl Flow for HandleIbdBlockRequests {
    fn router(&self) -> Option<Arc<Router>> {
        Some(self.router.clone())
    }

    async fn start(&mut self) -> Result<(), ProtocolError> {
        self.start_impl().await
    }
}

impl HandleIbdBlockRequests {
    pub fn new(ctx: FlowContext, router: Arc<Router>, incoming_route: IncomingRoute) -> Self {
        Self { ctx, router, incoming_route }
    }

    async fn start_impl(&mut self) -> Result<(), ProtocolError> {
        loop {
            let (msg, request_id) = dequeue_with_request_id!(self.incoming_route, Payload::RequestIbdBlocks)?;
            // Zethora (OBS-4): same cap as `RequestRelayBlocks` -- one message may not name an unbounded number of
            // blocks, so a peer that tries is dropped instead of being served.
            if msg.hashes.len() > MAX_BLOCK_HASHES_PER_REQUEST {
                return Err(ProtocolError::OtherOwned(format!(
                    "requested {} IBD blocks in one message, over the limit of {MAX_BLOCK_HASHES_PER_REQUEST}",
                    msg.hashes.len()
                )));
            }
            let hashes: Vec<_> = msg.try_into()?;

            debug!("got request for {} IBD blocks", hashes.len());
            let session = self.ctx.consensus().unguarded_session();

            for hash in hashes {
                let block = session.async_get_block(hash).await?;
                self.router.enqueue(make_response!(Payload::IbdBlock, (&block).into(), request_id)).await?;
            }
        }
    }
}
