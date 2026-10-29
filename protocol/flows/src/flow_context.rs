use crate::flowcontext::{
    orphans::{OrphanBlocksPool, OrphanOutput, OrphanSenders},
    process_queue::ProcessQueue,
    transactions::TransactionsSpread,
};
use crate::user_agent_rule::{UserAgentRuleRejectReason, UserAgentRuleSet};
use crate::{v10, v11};
use async_trait::async_trait;
use futures::future::join_all;
use kaspa_addressmanager::AddressManager;
use kaspa_connectionmanager::ConnectionManager;
use kaspa_consensus_core::api::{BlockValidationFuture, BlockValidationFutures};
use kaspa_consensus_core::block::Block;
use kaspa_consensus_core::config::Config;
use kaspa_consensus_core::errors::block::RuleError;
use kaspa_consensus_core::tx::{Transaction, TransactionId};
use kaspa_consensus_notify::{
    notification::{Notification, PruningPointUtxoSetOverrideNotification},
    root::ConsensusNotificationRoot,
};
use kaspa_consensusmanager::{BlockProcessingBatch, ConsensusInstance, ConsensusManager, ConsensusProxy, ConsensusSessionOwned};
use kaspa_core::{
    debug, info,
    kaspad_env::{name, version},
    task::tick::TickService,
};
use kaspa_core::{time::unix_now, warn};
use kaspa_hashes::Hash;
use kaspa_mining::mempool::tx::{Orphan, Priority};
use kaspa_mining::{manager::MiningManagerProxy, mempool::tx::RbfPolicy};
use kaspa_notify::notifier::Notify;
use kaspa_p2p_lib::{
    ConnectionInitializer, Hub, KaspadHandshake, PeerKey, PeerProperties, Router,
    common::ProtocolError,
    convert::model::version::Version,
    make_message,
    pb::{InvRelayBlockMessage, kaspad_message::Payload},
};
use kaspa_p2p_mining::rule_engine::MiningRuleEngine;
use kaspa_utils::iter::IterExtensions;
use kaspa_utils::networking::PeerId;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;
use std::{collections::hash_map::Entry, fmt::Display};
use std::{
    iter::once,
    ops::Deref,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::{
    RwLock as AsyncRwLock,
    mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
};
use tokio_stream::{StreamExt, wrappers::UnboundedReceiverStream};
use uuid::Uuid;

/// The P2P protocol version.
const PROTOCOL_VERSION: u32 = 11;

/// See `check_orphan_resolution_range`
const BASELINE_ORPHAN_RESOLUTION_RANGE: u32 = 5;

/// Orphans are kept as full blocks so we cannot hold too much of them in memory
const MAX_ORPHANS_UPPER_BOUND: usize = 1024;

/// The min time to wait before allowing another parallel request
const REQUEST_SCOPE_WAIT_TIME: Duration = Duration::from_secs(1);

/// Represents a block event to be logged
#[derive(Debug, PartialEq)]
pub enum BlockLogEvent {
    /// Accepted block via *relay*
    Relay(Hash),
    /// Accepted block via *submit block*
    Submit(Hash),
    /// Orphaned block with x missing roots
    Orphaned(Hash, usize),
    /// Unorphaned x blocks with hash being a representative
    Unorphaned(Hash, usize),
}

pub struct BlockEventLogger {
    bps: usize,
    sender: UnboundedSender<BlockLogEvent>,
    receiver: Mutex<Option<UnboundedReceiver<BlockLogEvent>>>,
}

impl BlockEventLogger {
    fn new(bps: usize) -> Self {
        let (sender, receiver) = unbounded_channel();
        Self { bps, sender, receiver: Mutex::new(Some(receiver)) }
    }

    pub fn log(&self, event: BlockLogEvent) {
        self.sender.send(event).unwrap();
    }

    /// Start the logger listener. Must be called from an async tokio context
    fn start(&self) {
        #[allow(clippy::arithmetic_side_effects, reason = "bps << usize::MAX")]
        let chunk_limit = self.bps * 10; // We prefer that the 1 sec timeout forces the log, but nonetheless still want a reasonable bound on each chunk
        let receiver = self.receiver.lock().take().expect("expected to be called once");
        tokio::spawn(async move {
            let chunk_stream = UnboundedReceiverStream::new(receiver).chunks_timeout(chunk_limit, Duration::from_secs(1));
            tokio::pin!(chunk_stream);
            while let Some(chunk) = chunk_stream.next().await {
                #[derive(Default)]
                struct LogSummary {
                    // Representatives
                    relay_rep: Option<Hash>,
                    submit_rep: Option<Hash>,
                    orphan_rep: Option<Hash>,
                    unorphan_rep: Option<Hash>,
                    // Counts
                    relay_count: usize,
                    submit_count: usize,
                    orphan_count: usize,
                    unorphan_count: usize,
                    orphan_roots_count: usize,
                }

                struct LogHash {
                    op: Option<Hash>,
                }

                impl From<Option<Hash>> for LogHash {
                    fn from(op: Option<Hash>) -> Self {
                        Self { op }
                    }
                }

                impl Display for LogHash {
                    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        if let Some(hash) = self.op { hash.fmt(f) } else { Ok(()) }
                    }
                }

                impl LogSummary {
                    fn relay(&self) -> LogHash {
                        self.relay_rep.into()
                    }

                    fn submit(&self) -> LogHash {
                        self.submit_rep.into()
                    }

                    fn orphan(&self) -> LogHash {
                        self.orphan_rep.into()
                    }

                    fn unorphan(&self) -> LogHash {
                        self.unorphan_rep.into()
                    }
                }

                let summary = chunk.into_iter().fold(LogSummary::default(), |mut summary, ev| {
                    match ev {
                        BlockLogEvent::Relay(hash) => {
                            #[allow(clippy::arithmetic_side_effects, reason = "ARITH-SAFETY(COUNTER)")]
                            {
                                summary.relay_count += 1;
                            }
                            summary.relay_rep = Some(hash);
                        }
                        BlockLogEvent::Submit(hash) => {
                            #[allow(clippy::arithmetic_side_effects, reason = "ARITH-SAFETY(COUNTER)")]
                            {
                                summary.submit_count += 1;
                            }
                            summary.submit_rep = Some(hash);
                        }
                        BlockLogEvent::Orphaned(hash, roots_count) => {
                            #[allow(clippy::arithmetic_side_effects, reason = "ARITH-SAFETY(COUNTER)")]
                            {
                                summary.orphan_roots_count += roots_count;
                            }
                            #[allow(clippy::arithmetic_side_effects, reason = "ARITH-SAFETY(COUNTER)")]
                            {
                                summary.orphan_count += 1;
                            }
                            summary.orphan_rep = Some(hash)
                        }
                        BlockLogEvent::Unorphaned(hash, count) => {
                            #[allow(clippy::arithmetic_side_effects, reason = "ARITH-SAFETY(COUNTER)")]
                            {
                                summary.unorphan_count += count;
                            }
                            summary.unorphan_rep = Some(hash)
                        }
                    }
                    summary
                });

                match (summary.submit_count, summary.relay_count) {
                    (0, 0) => {}
                    (1, 0) => {
                        info!("Accepted block {} via submit block", summary.submit());
                    }
                    (n, 0) => {
                        info!("Accepted {} blocks ...{} via submit block", n, summary.submit());
                    }
                    (0, 1) => {
                        info!("Accepted block {} via relay", summary.relay());
                    }
                    (0, m) => {
                        info!("Accepted {} blocks ...{} via relay", m, summary.relay());
                    }
                    (n, m) => {
                        #[allow(clippy::arithmetic_side_effects, reason = "ARITH-SAFETY(COUNTER)")]
                        {
                            {
                                info!("Accepted {} blocks ...{}, {} via relay and {} via submit block", n + m, summary.submit(), m, n);
                            }
                        }
                    }
                }

                match (summary.orphan_count, summary.orphan_roots_count) {
                    (0, 0) => {}
                    (n, m) => {
                        info!("Orphaned {} block(s) ...{} and queued {} missing roots", n, summary.orphan(), m);
                    }
                }

                match summary.unorphan_count {
                    0 => {}
                    1 => {
                        info!("Unorphaned block {}", summary.unorphan());
                    }
                    n => {
                        info!("Unorphaned {} block(s) ...{}", n, summary.unorphan());
                    }
                }
            }
        });
    }
}

pub struct FlowContextInner {
    pub node_id: PeerId,
    pub consensus_manager: Arc<ConsensusManager>,
    pub config: Arc<Config>,
    hub: Hub,
    orphans_pool: AsyncRwLock<OrphanBlocksPool>,
    shared_block_requests: Arc<Mutex<HashMap<Hash, RequestScopeMetadata>>>,
    transactions_spread: AsyncRwLock<TransactionsSpread>,
    shared_transaction_requests: Arc<Mutex<HashMap<TransactionId, RequestScopeMetadata>>>,
    is_ibd_running: Arc<AtomicBool>,
    ibd_metadata: Arc<RwLock<Option<IbdMetadata>>>,
    pub address_manager: Arc<Mutex<AddressManager>>,
    connection_manager: RwLock<Option<Arc<ConnectionManager>>>,
    /// ZTH-IMPL-020 D4 / seam review P4-1, P3-4, pack 1 #9: per-IP strike timestamps (`ProtocolError::is_strike`), used
    /// to apply the 3-in-10-minutes ban threshold. Entries older than the window are pruned and the map is capped.
    strikes: Arc<Mutex<HashMap<IpAddr, Vec<Instant>>>>,
    /// Seam review P4-1: per-IP times of relayed blocks that turned out to be orphans. An orphan can't be checked
    /// against its real difficulty (its parents are unknown), so each one costs a RandomZ check that may never lead to
    /// a strike; past `orphan_budget()` in `ORPHAN_BUDGET_WINDOW_SECS` the peer is disconnected (not banned).
    /// Per IP: (start of the current window, orphans counted in it).
    relayed_orphans: Arc<Mutex<HashMap<IpAddr, (Instant, usize)>>>,
    /// Seam review P3-1: the private state served to joining peers, built once per pruning point.
    pub(crate) zethora_private_state_cache:
        Arc<crate::flowcontext::zethora_state_cache::SingleEntryCache<Hash, kaspa_consensus_core::api::ZethoraPrivateState>>,
    mining_manager: MiningManagerProxy,
    pub(crate) tick_service: Arc<TickService>,
    notification_root: Arc<ConsensusNotificationRoot>,
    user_agent_rules: UserAgentRuleSet,

    // Special sampling logger used only for high-bps networks where logs must be throttled
    block_event_logger: Option<BlockEventLogger>,

    bps: usize,

    // Orphan parameters
    orphan_resolution_range: u32,
    max_orphans: usize,

    // Mining rule engine
    mining_rule_engine: Arc<MiningRuleEngine>,
}

#[derive(Clone)]
pub struct FlowContext {
    inner: Arc<FlowContextInner>,
}

pub struct IbdRunningGuard {
    indicator: Arc<AtomicBool>,
}

impl Drop for IbdRunningGuard {
    fn drop(&mut self) {
        let result = self.indicator.compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst);
        assert!(result.is_ok())
    }
}

#[derive(Debug, Clone, Copy)]
struct IbdMetadata {
    /// The peer from which current IBD is syncing from
    peer: PeerKey,
    /// The DAA score of the relay block which triggered the current IBD
    daa_score: u64,
}

pub struct RequestScopeMetadata {
    pub timestamp: Instant,
    pub obtained: bool,
}

pub struct RequestScope<T: PartialEq + Eq + std::hash::Hash> {
    set: Arc<Mutex<HashMap<T, RequestScopeMetadata>>>,
    pub req: T,
}

impl<T: PartialEq + Eq + std::hash::Hash> RequestScope<T> {
    pub fn new(set: Arc<Mutex<HashMap<T, RequestScopeMetadata>>>, req: T) -> Self {
        Self { set, req }
    }

    /// Scope holders should use this function to report that the request has
    /// successfully been obtained from the peer and is now being processed
    pub fn report_obtained(&self) {
        if let Some(e) = self.set.lock().get_mut(&self.req) {
            e.obtained = true;
        }
    }
}

impl<T: PartialEq + Eq + std::hash::Hash> Drop for RequestScope<T> {
    fn drop(&mut self) {
        self.set.lock().remove(&self.req);
    }
}

impl Deref for FlowContext {
    type Target = FlowContextInner;

    fn deref(&self) -> &Self::Target {
        self.inner.as_ref()
    }
}

impl FlowContext {
    pub fn new(
        consensus_manager: Arc<ConsensusManager>,
        address_manager: Arc<Mutex<AddressManager>>,
        config: Arc<Config>,
        mining_manager: MiningManagerProxy,
        tick_service: Arc<TickService>,
        notification_root: Arc<ConsensusNotificationRoot>,
        hub: Hub,
        mining_rule_engine: Arc<MiningRuleEngine>,
    ) -> Self {
        let bps = config.bps() as usize;
        let orphan_resolution_range = BASELINE_ORPHAN_RESOLUTION_RANGE.saturating_add((bps as f64).log2().ceil() as u32);
        let user_agent_rules = UserAgentRuleSet::parse_lossy(&config.user_agent_rules);

        // The maximum amount of orphans allowed in the orphans pool. This number is an approximation
        // of how many orphans there can possibly be on average bounded by an upper bound.
        let max_orphans =
            (2u64.pow(orphan_resolution_range) as usize).saturating_mul(config.ghostdag_k() as usize).min(MAX_ORPHANS_UPPER_BOUND);
        Self {
            inner: Arc::new(FlowContextInner {
                node_id: Uuid::new_v4().into(),
                consensus_manager,
                orphans_pool: AsyncRwLock::new(OrphanBlocksPool::new(max_orphans)),
                shared_block_requests: Arc::new(Mutex::new(HashMap::new())),
                transactions_spread: AsyncRwLock::new(TransactionsSpread::new(hub.clone())),
                shared_transaction_requests: Arc::new(Mutex::new(HashMap::new())),
                is_ibd_running: Default::default(),
                ibd_metadata: Default::default(),
                hub,
                address_manager,
                connection_manager: Default::default(),
                strikes: Arc::new(Mutex::new(HashMap::new())),
                relayed_orphans: Arc::new(Mutex::new(HashMap::new())),
                zethora_private_state_cache: Default::default(),
                mining_manager,
                tick_service,
                notification_root,
                user_agent_rules,
                block_event_logger: Some(BlockEventLogger::new(bps)),
                bps,
                orphan_resolution_range,
                max_orphans,
                config,
                mining_rule_engine,
            }),
        }
    }

    #[allow(clippy::arithmetic_side_effects, reason = "bps, channel size << usize::MAX")]
    pub fn block_invs_channel_size(&self) -> usize {
        self.bps * Router::incoming_flow_baseline_channel_size()
    }

    pub fn orphan_resolution_range(&self) -> u32 {
        self.orphan_resolution_range
    }

    pub fn max_orphans(&self) -> usize {
        self.max_orphans
    }

    pub fn start_async_services(&self) {
        if let Some(logger) = self.block_event_logger.as_ref() {
            logger.start();
        }
    }

    pub fn set_connection_manager(&self, connection_manager: Arc<ConnectionManager>) {
        self.connection_manager.write().replace(connection_manager);
    }

    pub fn drop_connection_manager(&self) {
        self.connection_manager.write().take();
    }

    pub fn connection_manager(&self) -> Option<Arc<ConnectionManager>> {
        self.connection_manager.read().clone()
    }

    /// Zethora: everything a peer's error can cost it (`ProtocolError::is_strike`): a forged private payment (ZTH-SPEC-006
    /// §8.3, pack 1 #9), unearned proof of work (seam review P4-1, ZTH-IMPL-020) or a private state that does not match
    /// its pruning point (P3-4) is a strike, and 3 strikes in 10 minutes (ZTH-IMPL-020 D4) ban its IP; escalation is
    /// handled by the connection manager (ZTH-IMPL-020 D2). Peers added with --connect / --addpeer are never banned.
    /// Call this exactly once per error.
    pub async fn penalize_if_misbehaving(&self, router: &Router, err: &ProtocolError) {
        self.penalize_ip_if_misbehaving(router.net_address().ip(), err).await
    }

    /// Same as `penalize_if_misbehaving`, by IP (for orphan blocks, validated after their sender's message).
    pub async fn penalize_ip_if_misbehaving(&self, ip: IpAddr, err: &ProtocolError) {
        if !err.is_strike() {
            return;
        }
        const WINDOW_SECS: u64 = 10 * 60;
        const THRESHOLD: usize = 3;

        let count = record_implausible_proof_attempt(&mut self.strikes.lock(), ip, Instant::now(), WINDOW_SECS, THRESHOLD);
        if count < THRESHOLD {
            warn!("Peer IP {} misbehaved (strike {}/{}): {}", ip, count, THRESHOLD, err);
            return;
        }

        warn!("Banning peer IP {} for {} strikes in {}s: {}", ip, count, WINDOW_SECS, err);
        self.strikes.lock().remove(&ip);
        if let Some(connection_manager) = self.connection_manager() {
            connection_manager.ban(ip).await;
        }
    }

    /// Seam review P4-1: how many relayed orphan blocks one IP may send per `ORPHAN_BUDGET_WINDOW_SECS`: twice what
    /// an honest peer could relay at the network's block rate (every block it relays an orphan), and at least 100.
    pub fn orphan_budget(&self) -> usize {
        orphan_budget_for(self.bps)
    }

    /// Seam review P4-1: counts a relayed block from `ip` that turned out to be an orphan. Returns an error (the flow
    /// disconnects the peer, no ban) once the IP has sent more than `orphan_budget()` orphans in the current window.
    /// An honest peer relays at most one block per network block, so it stays under the budget.
    pub fn note_relayed_orphan(&self, ip: IpAddr) -> Result<(), ProtocolError> {
        let budget = self.orphan_budget();
        let count = count_in_window(&mut self.relayed_orphans.lock(), ip, Instant::now(), ORPHAN_BUDGET_WINDOW_SECS);
        if count > budget {
            return Err(ProtocolError::OtherOwned(format!(
                "sent more than {budget} orphan blocks in {ORPHAN_BUDGET_WINDOW_SECS}s (each one costs a RandomZ check)"
            )));
        }
        Ok(())
    }

    pub fn consensus(&self) -> ConsensusInstance {
        self.consensus_manager.consensus()
    }

    pub fn hub(&self) -> &Hub {
        &self.hub
    }

    pub fn mining_manager(&self) -> &MiningManagerProxy {
        &self.mining_manager
    }

    pub fn try_set_ibd_running(&self, peer: PeerKey, relay_daa_score: u64) -> Option<IbdRunningGuard> {
        if self.is_ibd_running.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
            self.ibd_metadata.write().replace(IbdMetadata { peer, daa_score: relay_daa_score });
            Some(IbdRunningGuard { indicator: self.is_ibd_running.clone() })
        } else {
            None
        }
    }

    pub fn is_ibd_running(&self) -> bool {
        self.is_ibd_running.load(Ordering::SeqCst)
    }

    /// If IBD is running, returns the IBD peer we are syncing from
    pub fn ibd_peer_key(&self) -> Option<PeerKey> {
        if self.is_ibd_running() { self.ibd_metadata.read().map(|md| md.peer) } else { None }
    }

    /// If IBD is running, returns the DAA score of the relay block which triggered it
    pub fn ibd_relay_daa_score(&self) -> Option<u64> {
        if self.is_ibd_running() { self.ibd_metadata.read().map(|md| md.daa_score) } else { None }
    }

    fn try_adding_request_impl(req: Hash, map: &Arc<Mutex<HashMap<Hash, RequestScopeMetadata>>>) -> Option<RequestScope<Hash>> {
        match map.lock().entry(req) {
            Entry::Occupied(mut e) => {
                if e.get().obtained {
                    None
                } else {
                    let now = Instant::now();

                    #[allow(
                        clippy::arithmetic_side_effects,
                        reason = "ARITH-SAFETY(TIMESTAMP): `REQUEST_SCOPE_WAIT_TIME` is small enough."
                    )]
                    if now > e.get().timestamp + REQUEST_SCOPE_WAIT_TIME {
                        e.get_mut().timestamp = now;
                        Some(RequestScope::new(map.clone(), req))
                    } else {
                        None
                    }
                }
            }
            Entry::Vacant(e) => {
                e.insert(RequestScopeMetadata { timestamp: Instant::now(), obtained: false });
                Some(RequestScope::new(map.clone(), req))
            }
        }
    }

    pub fn try_adding_block_request(&self, req: Hash) -> Option<RequestScope<Hash>> {
        Self::try_adding_request_impl(req, &self.shared_block_requests)
    }

    pub fn try_adding_transaction_request(&self, req: TransactionId) -> Option<RequestScope<TransactionId>> {
        Self::try_adding_request_impl(req, &self.shared_transaction_requests)
    }

    /// `sender` is the IP of the peer that sent the orphan (Zethora: banned later if the block carries a forged
    /// private payment)
    pub async fn add_orphan(&self, consensus: &ConsensusProxy, orphan_block: Block, sender: Option<IpAddr>) -> Option<OrphanOutput> {
        self.orphans_pool.write().await.add_orphan(consensus, orphan_block, sender).await
    }

    pub async fn is_known_orphan(&self, hash: Hash) -> bool {
        self.orphans_pool.read().await.is_known_orphan(hash)
    }

    pub async fn get_orphan_roots_if_known(&self, consensus: &ConsensusProxy, orphan: Hash) -> OrphanOutput {
        self.orphans_pool.read().await.get_orphan_roots_if_known(consensus, orphan).await
    }

    pub async fn unorphan_blocks(&self, consensus: &ConsensusProxy, root: Hash) -> Vec<(Block, BlockValidationFuture)> {
        let (blocks, block_tasks, virtual_state_tasks, senders) =
            self.orphans_pool.write().await.unorphan_blocks(consensus, root).await;
        let mut unorphaned_blocks = Vec::with_capacity(blocks.len());
        let results = join_all(block_tasks).await;
        for (((block, result), virtual_state_task), sender) in blocks.into_iter().zip(results).zip(virtual_state_tasks).zip(senders) {
            match result {
                Ok(_) => {
                    unorphaned_blocks.push((block, virtual_state_task));
                }
                Err(e) => {
                    warn!("Validation failed for orphan block {}: {}", block.hash(), e);
                    // Zethora: the peer that sent this orphan is banned if it carried a forged private payment, and gets a
                    // strike if its proof of work was unearned (e.g. it claimed an easy target: seam review P4-1)
                    if let Some(ip) = sender {
                        self.penalize_ip_if_misbehaving(ip, &ProtocolError::RuleError(e)).await;
                    }
                }
            }
        }

        // Log or send to event logger
        if !unorphaned_blocks.is_empty() {
            if let Some(logger) = self.block_event_logger.as_ref() {
                logger.log(BlockLogEvent::Unorphaned(unorphaned_blocks[0].0.hash(), unorphaned_blocks.len()));
            } else {
                match unorphaned_blocks.len() {
                    1 => {
                        info!("Unorphaned block {}", unorphaned_blocks[0].0.hash());
                    }
                    n => {
                        info!("Unorphaned {} blocks: {}", n, unorphaned_blocks.iter().map(|b| b.0.hash()).reusable_format(", "));
                    }
                }
            }
        }
        unorphaned_blocks
    }

    pub async fn revalidate_orphans(&self, consensus: &ConsensusProxy) -> (Vec<Hash>, Vec<BlockValidationFuture>, OrphanSenders) {
        self.orphans_pool.write().await.revalidate_orphans(consensus).await
    }

    /// Adds the rpc-submitted block to the DAG and propagates it to peers.
    pub async fn submit_rpc_block(&self, consensus: &ConsensusProxy, block: Block) -> Result<(), ProtocolError> {
        if block.transactions.is_empty() {
            return Err(RuleError::NoTransactions)?;
        }
        let hash = block.hash();
        let BlockValidationFutures { block_task, virtual_state_task } = consensus.validate_and_insert_block(block.clone());
        if let Err(err) = block_task.await {
            warn!("Validation failed for block {}: {}", hash, err);
            return Err(err)?;
        }
        // Broadcast as soon as the block has been validated and inserted into the DAG
        self.hub.broadcast(make_message!(Payload::InvRelayBlock, InvRelayBlockMessage { hash: Some(hash.into()) }), None).await;

        self.on_new_block(consensus, Default::default(), block, virtual_state_task).await;
        self.log_block_event(BlockLogEvent::Submit(hash));

        Ok(())
    }

    pub fn log_block_event(&self, event: BlockLogEvent) {
        if let Some(logger) = self.block_event_logger.as_ref() {
            logger.log(event)
        } else {
            match event {
                BlockLogEvent::Relay(hash) => {
                    info!("Accepted block {} via relay", hash);
                }
                BlockLogEvent::Submit(hash) => {
                    info!("Accepted block {} via submit block", hash);
                }
                BlockLogEvent::Orphaned(orphan, roots_count) => {
                    info!("Received a block with {} missing ancestors, adding to orphan pool: {}", roots_count, orphan);
                }
                _ => {}
            }
        }
    }

    /// Updates the mempool after a new block arrival, relays newly unorphaned transactions
    /// and possibly rebroadcast manually added transactions when not in IBD.
    ///
    /// _GO-KASPAD: OnNewBlock + broadcastTransactionsAfterBlockAdded_
    pub async fn on_new_block(
        &self,
        consensus: &ConsensusProxy,
        ancestor_batch: BlockProcessingBatch,
        block: Block,
        virtual_state_task: BlockValidationFuture,
    ) {
        let hash = block.hash();
        let mut blocks = self.unorphan_blocks(consensus, hash).await;

        // Broadcast unorphaned blocks
        let msgs = blocks
            .iter()
            .map(|(b, _)| make_message!(Payload::InvRelayBlock, InvRelayBlockMessage { hash: Some(b.hash().into()) }))
            .collect();
        self.hub.broadcast_many(msgs, None).await;

        // Process blocks in topological order
        blocks.sort_by(|a, b| a.0.header.blue_work.partial_cmp(&b.0.header.blue_work).unwrap());
        // Use a ProcessQueue so we get rid of duplicates
        let mut transactions_to_broadcast = ProcessQueue::new();
        for (block, virtual_state_task) in ancestor_batch.zip().chain(once((block, virtual_state_task))).chain(blocks) {
            // We only care about waiting for virtual to process the block at this point, before proceeding with post-processing
            // actions such as updating the mempool. We know this will not err since `block_task` already completed w/o error
            let _ = virtual_state_task.await;
            if let Ok(txs) = self
                .mining_manager()
                .clone()
                .handle_new_block_transactions(consensus, block.header.daa_score, block.transactions.clone())
                .await
            {
                transactions_to_broadcast.enqueue_chunk(txs.into_iter().map(|x| x.id()));
            }
        }

        // Transaction relay is disabled if the node is out of sync
        if !self.is_nearly_synced(consensus).await {
            return;
        }

        // TODO: Throttle these transactions as well if needed
        self.broadcast_transactions(transactions_to_broadcast, false).await;

        if self.should_run_mempool_scanning_task().await {
            // Spawn a task executing the removal of expired low priority transactions and, if time has come too,
            // the revalidation of high priority transactions.
            //
            // The TransactionSpread member ensures at most one instance of this task is running at any
            // given time.
            let mining_manager = self.mining_manager().clone();
            let consensus_clone = consensus.clone();
            let context = self.clone();
            debug!("<> Starting mempool scanning task #{}...", self.mempool_scanning_job_count().await);
            tokio::spawn(async move {
                mining_manager.clone().expire_low_priority_transactions(&consensus_clone).await;
                if context.should_rebroadcast().await {
                    let (tx, mut rx) = unbounded_channel();
                    tokio::spawn(async move {
                        mining_manager.revalidate_high_priority_transactions(&consensus_clone, tx).await;
                    });
                    while let Some(transactions) = rx.recv().await {
                        let _ = context
                            .broadcast_transactions(
                                transactions,
                                true, // We throttle high priority even when the network is not flooded since they will be rebroadcast if not accepted within reasonable time.
                            )
                            .await;
                    }
                }
                context.mempool_scanning_is_done().await;
                debug!("<> Mempool scanning task is done");
            });
        }
    }

    pub async fn is_nearly_synced(&self, session: &ConsensusSessionOwned) -> bool {
        let sink_daa_score_and_timestamp = session.async_get_sink_daa_score_timestamp().await;
        self.mining_rule_engine.is_nearly_synced(sink_daa_score_and_timestamp)
    }

    pub async fn should_mine(&self, session: &ConsensusSessionOwned) -> bool {
        let sink_daa_score_and_timestamp = session.async_get_sink_daa_score_timestamp().await;
        self.mining_rule_engine.should_mine(sink_daa_score_and_timestamp)
    }

    /// Notifies that the UTXO set was reset due to pruning point change via IBD.
    pub fn on_pruning_point_utxoset_override(&self) {
        // Notifications from the flow context might be ignored if the inner channel is already closing
        // due to global shutdown, hence we ignore the possible error
        let _ = self.notification_root.notify(Notification::PruningPointUtxoSetOverride(PruningPointUtxoSetOverrideNotification {}));
    }

    /// Notifies that a transaction has been added to the mempool.
    pub async fn on_transaction_added_to_mempool(&self) {
        // TODO: call a handler function or a predefined registered service
    }

    /// Adds the rpc-submitted transaction to the mempool and propagates it to peers.
    ///
    /// Transactions submitted through rpc are considered high priority. This definition does not affect the tx selection algorithm
    /// but only changes how we manage the lifetime of the tx. A high-priority tx does not expire and is repeatedly rebroadcasted to
    /// peers
    pub async fn submit_rpc_transaction(
        &self,
        consensus: &ConsensusProxy,
        transaction: Transaction,
        orphan: Orphan,
    ) -> Result<(), ProtocolError> {
        let transaction_insertion = self
            .mining_manager()
            .clone()
            .validate_and_insert_transaction(consensus, transaction, Priority::High, orphan, RbfPolicy::Forbidden)
            .await?;
        self.broadcast_transactions(
            transaction_insertion.accepted.iter().map(|x| x.id()),
            false, // RPC transactions are considered high priority, so we don't want to throttle them
        )
        .await;
        Ok(())
    }

    /// Replaces the rpc-submitted transaction into the mempool and propagates it to peers.
    ///
    /// Returns the removed mempool transaction on successful replace by fee.
    ///
    /// Transactions submitted through rpc are considered high priority. This definition does not affect the tx selection algorithm
    /// but only changes how we manage the lifetime of the tx. A high-priority tx does not expire and is repeatedly rebroadcasted to
    /// peers
    pub async fn submit_rpc_transaction_replacement(
        &self,
        consensus: &ConsensusProxy,
        transaction: Transaction,
    ) -> Result<Arc<Transaction>, ProtocolError> {
        let transaction_insertion = self
            .mining_manager()
            .clone()
            .validate_and_insert_transaction(consensus, transaction, Priority::High, Orphan::Forbidden, RbfPolicy::Mandatory)
            .await?;
        self.broadcast_transactions(
            transaction_insertion.accepted.iter().map(|x| x.id()),
            false, // RPC transactions are considered high priority, so we don't want to throttle them
        )
        .await;
        // The combination of args above of Orphan::Forbidden and RbfPolicy::Mandatory should always result
        // in a removed transaction returned, however we prefer failing gracefully in case of future internal mempool changes
        transaction_insertion.removed.ok_or(ProtocolError::Other(
            "Replacement transaction was actually accepted but the *replaced* transaction was not returned from the mempool",
        ))
    }

    /// Returns true if the time has come for running the task cleaning mempool transactions.
    async fn should_run_mempool_scanning_task(&self) -> bool {
        self.transactions_spread.write().await.should_run_mempool_scanning_task()
    }

    /// Returns true if the time has come for a rebroadcast of the mempool high priority transactions.
    async fn should_rebroadcast(&self) -> bool {
        self.transactions_spread.read().await.should_rebroadcast()
    }

    async fn mempool_scanning_job_count(&self) -> u64 {
        self.transactions_spread.read().await.mempool_scanning_job_count()
    }

    async fn mempool_scanning_is_done(&self) {
        self.transactions_spread.write().await.mempool_scanning_is_done()
    }

    /// Add the given transactions IDs to a set of IDs to broadcast. The IDs will be broadcasted to all peers
    /// within transaction Inv messages.
    ///
    /// The broadcast itself may happen only during a subsequent call to this function since it is done at most
    /// after a predefined interval or when the queue length is larger than the Inv message capacity.
    pub async fn broadcast_transactions<I: IntoIterator<Item = TransactionId>>(&self, transaction_ids: I, should_throttle: bool) {
        self.transactions_spread.write().await.broadcast_transactions(transaction_ids, should_throttle).await
    }
}

#[async_trait]
impl ConnectionInitializer for FlowContext {
    async fn initialize_connection(&self, router: Arc<Router>) -> Result<(), ProtocolError> {
        // We only ban inbound connections here, since if we got to this stage with a banned outbound peer, it means
        // the user has explicitly allowed it.
        if !router.is_outbound() && self.address_manager.lock().is_banned(router.net_address().ip().into()) {
            return Err(ProtocolError::Other("peer is banned"));
        }

        // Build the handshake object and subscribe to handshake messages
        let mut handshake = KaspadHandshake::new(&router);

        // We start the router receive loop only after we registered to handshake routes
        router.start();

        let network_name = self.config.network_name();

        let local_address = self.address_manager.lock().best_local_address();

        // Build the local version message
        // Subnets are not currently supported
        let mut self_version_message = Version::new(local_address, self.node_id, network_name.clone(), None, PROTOCOL_VERSION);
        self_version_message.add_user_agent(name(), version(), &self.config.user_agent_comments);
        // TODO: disable_relay_tx from config/cmd

        // Perform the handshake
        let peer_version_message = handshake.handshake(self_version_message.into()).await?;
        // Get time_offset as accurate as possible by computing right after the handshake
        let time_offset = (unix_now() as i64).saturating_sub(peer_version_message.timestamp);

        let peer_version: Version = peer_version_message.try_into()?;
        router.set_identity(peer_version.id);
        // Avoid duplicate connections
        if self.hub.has_peer(router.key()) {
            return Err(ProtocolError::PeerAlreadyExists(router.key()));
        }
        // And loopback connections...
        if self.node_id == router.identity() {
            return Err(ProtocolError::LoopbackConnection(router.key()));
        }

        if peer_version.network != network_name {
            return Err(ProtocolError::WrongNetwork(network_name, peer_version.network));
        }

        if let Some(reason) = self.user_agent_rules.reject_reason(&peer_version.user_agent) {
            match reason {
                UserAgentRuleRejectReason::AllowanceExcluded => {
                    info!(
                        "Rejecting peer {} because user agent is outside configured allowance rules: {}",
                        router, peer_version.user_agent
                    );
                }
                UserAgentRuleRejectReason::Rejection(rule) => {
                    info!(
                        "Rejecting peer {} because user agent matched rejection rule `{}`: {}",
                        router,
                        rule.source(),
                        peer_version.user_agent
                    );
                }
            }
            return Err(ProtocolError::OtherOwned(format!("peer user agent rejected: {}", peer_version.user_agent)));
        }

        debug!("protocol versions - self: {}, peer: {}", PROTOCOL_VERSION, peer_version.protocol_version);

        let peer_protocol_version = peer_version.protocol_version;

        // Peers must advertise at least the current protocol version. Register all flows according to version.
        let (flows, applied_protocol_version) = match peer_protocol_version {
            v if v >= PROTOCOL_VERSION => (v11::register(self.clone(), router.clone()), PROTOCOL_VERSION),
            10 => (v10::register(self.clone(), router.clone()), 10),
            v => return Err(ProtocolError::VersionMismatch(PROTOCOL_VERSION, v)),
        };

        // Build and register the peer properties
        let peer_properties = Arc::new(PeerProperties {
            user_agent: peer_version.user_agent,
            advertised_protocol_version: peer_version.protocol_version,
            protocol_version: applied_protocol_version,
            disable_relay_tx: peer_version.disable_relay_tx,
            subnetwork_id: peer_version.subnetwork_id,
            time_offset,
        });
        router.set_properties(peer_properties);

        // Send and receive the ready signal
        handshake.exchange_ready_messages().await?;

        info!("Registering p2p flows for peer {} for protocol version {}", router, applied_protocol_version);

        // Launch all flows. Note we launch only after the ready signal was exchanged
        for flow in flows {
            flow.launch();
        }

        if router.is_outbound() || peer_version.address.is_some() {
            let mut address_manager = self.address_manager.lock();

            if router.is_outbound() {
                address_manager.add_address(router.net_address().into());
            }

            if let Some(peer_ip_address) = peer_version.address {
                address_manager.add_address(peer_ip_address);
            }
        }

        // Note: we deliberately do not hold the handshake in memory so at this point receivers for handshake subscriptions
        // are dropped, hence effectively unsubscribing from these messages. This means that if the peer re-sends them
        // it is considered a protocol error and the connection will disconnect

        Ok(())
    }
}

/// Zethora (ZTH-IMPL-020 D4, seam review pack 1, #16): records one implausible-proof attempt by `ip` at `now` and
/// returns how many attempts by `ip` fall inside the last `window_secs` (at most `threshold`). The map never holds more
/// than `MAX_TRACKED_IPS` + 1 addresses: past the cap, expired entries are dropped first, then the least recently seen
/// addresses, down to half the cap.
/// Seam review P4-1: the window of the per-IP orphan budget.
pub(crate) const ORPHAN_BUDGET_WINDOW_SECS: u64 = 10 * 60;

/// Seam review P4-1: twice the blocks the network makes in one window, at least 100.
pub(crate) fn orphan_budget_for(bps: usize) -> usize {
    (bps.saturating_mul(ORPHAN_BUDGET_WINDOW_SECS as usize).saturating_mul(2)).max(100)
}

/// Seam review P4-1: adds one event for `ip` in fixed windows of `window_secs` and returns the count in the current
/// window. One (window start, count) pair per IP; the map is capped like the strike map (old windows dropped first).
pub(crate) fn count_in_window(counts: &mut HashMap<IpAddr, (Instant, usize)>, ip: IpAddr, now: Instant, window_secs: u64) -> usize {
    const MAX_TRACKED_IPS: usize = 10_000;
    if counts.len() > MAX_TRACKED_IPS {
        counts.retain(|_, (start, _)| now.duration_since(*start).as_secs() < window_secs);
        if counts.len() > MAX_TRACKED_IPS {
            let mut by_start: Vec<_> = counts.iter().map(|(ip, (start, _))| (*start, *ip)).collect();
            by_start.sort_unstable();
            let excess = counts.len().saturating_sub(MAX_TRACKED_IPS / 2);
            for (_, old_ip) in by_start.into_iter().take(excess) {
                counts.remove(&old_ip);
            }
        }
    }
    let entry = counts.entry(ip).or_insert((now, 0));
    if now.duration_since(entry.0).as_secs() >= window_secs {
        *entry = (now, 0);
    }
    entry.1 = entry.1.saturating_add(1);
    entry.1
}

pub(crate) fn record_implausible_proof_attempt(
    attempts: &mut HashMap<IpAddr, Vec<Instant>>,
    ip: IpAddr,
    now: Instant,
    window_secs: u64,
    threshold: usize,
) -> usize {
    const MAX_TRACKED_IPS: usize = 10_000;
    if attempts.len() > MAX_TRACKED_IPS {
        attempts.retain(|_, v| {
            v.retain(|t| now.duration_since(*t).as_secs() < window_secs);
            !v.is_empty()
        });
        if attempts.len() > MAX_TRACKED_IPS {
            let mut by_last_seen: Vec<_> = attempts.iter().map(|(ip, v)| (*v.last().unwrap(), *ip)).collect();
            by_last_seen.sort_unstable();
            let excess = attempts.len().saturating_sub(MAX_TRACKED_IPS / 2);
            for (_, old_ip) in by_last_seen.into_iter().take(excess) {
                attempts.remove(&old_ip);
            }
        }
    }
    let entry = attempts.entry(ip).or_default();
    // Only attempts inside the window count (before, old attempts were dropped only when the map passed the cap, so
    // attempts spread over days could still ban)
    entry.retain(|t| now.duration_since(*t).as_secs() < window_secs);
    entry.push(now);
    if entry.len() > threshold {
        entry.drain(..entry.len().saturating_sub(threshold));
    }
    entry.len()
}

#[cfg(test)]
mod zethora_attempt_tests {
    use super::{ORPHAN_BUDGET_WINDOW_SECS, count_in_window, orphan_budget_for, record_implausible_proof_attempt};
    use std::{
        collections::HashMap,
        net::{IpAddr, Ipv4Addr},
        time::{Duration, Instant},
    };

    fn ip(n: u32) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(n))
    }

    #[test]
    fn attempts_count_only_inside_the_window() {
        let mut map = HashMap::new();
        let t0 = Instant::now();
        // Positive control: 3 attempts within 10 minutes reach the threshold
        assert_eq!(record_implausible_proof_attempt(&mut map, ip(1), t0, 600, 3), 1);
        assert_eq!(record_implausible_proof_attempt(&mut map, ip(1), t0 + Duration::from_secs(60), 600, 3), 2);
        assert_eq!(record_implausible_proof_attempt(&mut map, ip(1), t0 + Duration::from_secs(120), 600, 3), 3);
        // Spread over hours, the count never reaches 3 (before the fix it did)
        let t1 = t0 + Duration::from_secs(10_000);
        assert_eq!(record_implausible_proof_attempt(&mut map, ip(2), t1, 600, 3), 1);
        assert_eq!(record_implausible_proof_attempt(&mut map, ip(2), t1 + Duration::from_secs(700), 600, 3), 1);
        assert_eq!(record_implausible_proof_attempt(&mut map, ip(2), t1 + Duration::from_secs(1_400), 600, 3), 1);
        // At most `threshold` timestamps are kept per address
        for i in 0..10 {
            record_implausible_proof_attempt(&mut map, ip(3), t0 + Duration::from_secs(i), 600, 3);
        }
        assert_eq!(map[&ip(3)].len(), 3);
    }

    #[test]
    fn the_map_never_grows_without_bound() {
        let mut map = HashMap::new();
        let t0 = Instant::now();
        // 25,000 distinct addresses, all inside the window (nothing expires): the map stays bounded
        for n in 0..25_000u32 {
            record_implausible_proof_attempt(&mut map, ip(n), t0 + Duration::from_millis(n as u64), 600, 3);
            assert!(map.len() <= 10_001, "map grew to {}", map.len());
        }
        // The most recently seen address is still tracked; the oldest ones were dropped
        assert!(map.contains_key(&ip(24_999)));
        assert!(!map.contains_key(&ip(0)));
    }

    /// Seam review P4-1: the orphan budget is twice the blocks the network makes in one window (at least 100).
    #[test]
    fn orphan_budget_scales_with_the_block_rate() {
        assert_eq!(ORPHAN_BUDGET_WINDOW_SECS, 600);
        assert_eq!(orphan_budget_for(1), 1_200);
        assert_eq!(orphan_budget_for(10), 12_000);
        assert_eq!(orphan_budget_for(0), 100);
    }

    /// Seam review P4-1: orphans are counted per IP in fixed windows; a new window starts from zero.
    #[test]
    fn orphan_counts_are_per_ip_and_per_window() {
        let mut map = HashMap::new();
        let t0 = Instant::now();
        let budget = orphan_budget_for(1);
        // An honest peer at 1 block per second, every relayed block an orphan, for a whole window: under budget
        for i in 0..600u64 {
            assert!(count_in_window(&mut map, ip(1), t0 + Duration::from_secs(i), 600) <= budget);
        }
        assert_eq!(count_in_window(&mut map, ip(1), t0 + Duration::from_secs(599), 600), 601);
        // Another IP has its own count
        assert_eq!(count_in_window(&mut map, ip(2), t0, 600), 1);
        // The next window starts over
        assert_eq!(count_in_window(&mut map, ip(1), t0 + Duration::from_secs(600), 600), 1);
        // A flood goes over the budget exactly at budget + 1
        let t1 = t0 + Duration::from_secs(5_000);
        for n in 1..=budget {
            assert_eq!(count_in_window(&mut map, ip(3), t1, 600), n);
        }
        assert_eq!(count_in_window(&mut map, ip(3), t1, 600), budget + 1);
        // Bounded memory
        for n in 0..25_000u32 {
            count_in_window(&mut map, ip(100 + n), t1 + Duration::from_millis(n as u64), 600);
            assert!(map.len() <= 10_001, "map grew to {}", map.len());
        }
    }
}
