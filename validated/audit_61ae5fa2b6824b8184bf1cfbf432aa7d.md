# Audit Report

## Title
Stale Timeout Tasks Fire After Epoch Transition Due to Missing AbortHandle Cleanup in RoundState

## Summary
The `RoundState` struct stores an `AbortHandle` for scheduled timeout tasks but lacks a `Drop` implementation to abort pending tasks when the struct is destroyed. During epoch transitions, the old `RoundState` is dropped without aborting scheduled timeouts, while the `timeout_sender` channel is shared across epochs. This allows stale timeout tasks from a previous epoch to fire in the new epoch when round numbers coincidentally match, causing premature round timeouts.

## Finding Description

The vulnerability exists in the consensus layer's round timeout management. The `RoundState` struct stores an `abort_handle: Option<AbortHandle>` field to manage scheduled timeout tasks [1](#0-0) . When a new timeout is scheduled, the previous handle is properly aborted during normal round transitions [2](#0-1) .

However, `RoundState` lacks a `Drop` implementation to abort the handle when the struct itself is destroyed. The `timeout_sender` channel is created as a field of `EpochManager` [3](#0-2)  and shared across all epochs by passing it to `create_round_state()` [4](#0-3) .

During epoch transitions, `shutdown_current_processor()` is called [5](#0-4) , which sends a shutdown signal to the `RoundManager`. The `RoundManager::start()` method breaks out of its event loop [6](#0-5) , causing the `RoundManager` and its `RoundState` to be dropped. Since there's no `Drop` implementation, the `abort_handle` is simply dropped without calling `abort()`, leaving the scheduled timeout task running.

The timeout task only sends a round number (not an epoch identifier) [7](#0-6)  to the shared `timeout_sender` channel. When the timeout fires, it's received by `EpochManager::process_local_timeout()` [8](#0-7)  and forwarded to the new epoch's `RoundManager`.

The `RoundState::process_local_timeout()` method only validates that the round number matches the current round [9](#0-8) . There is no epoch validation. If a stale timeout from epoch N fires when epoch N+1 happens to be at the same round number, the check passes and the timeout is processed.

New epochs start with a genesis block at round 0 [10](#0-9) , and the `RoundManager` initializes from sync_info [11](#0-10) . When processed, the stale timeout causes the `RoundManager` to broadcast timeout votes prematurely [12](#0-11) .

## Impact Explanation

**Severity: MEDIUM**

This vulnerability causes temporary liveness issues that align with the MEDIUM severity category in the Aptos bug bounty program:

1. **Temporary Consensus Disruption**: Premature round timeouts cause validators to broadcast timeout messages before the actual timeout duration has elapsed, disrupting normal consensus flow.

2. **State Inconsistency Risk**: Different validators experiencing this at different times during epoch transitions could lead to temporary inconsistent timeout behavior across the network.

3. **Epoch Transition Brittleness**: Every epoch transition creates a race condition window where stale timeouts can interfere with the new epoch's operation.

This does NOT cause:
- Fund loss or theft
- Permanent network halt
- Consensus safety violations (double-spending)
- Chain splits

The impact is limited to temporary operational disruption during epoch transitions, which qualifies as MEDIUM severity rather than CRITICAL.

## Likelihood Explanation

**Likelihood: MEDIUM to LOW**

The vulnerability triggers automatically during epoch transitions but requires specific conditions:

1. **Automatic Trigger**: Occurs naturally during epoch transitions without attacker action
2. **Timing Dependency**: Requires the new epoch to reach the same round number as a stale timeout before it fires
3. **Probabilistic Matching**: Round number collisions depend on:
   - Timeout duration (longer with exponential backoff)
   - Round progression speed in the new epoch
   - Round number when epoch transition occurs

**Realistic Scenario**: If epoch N at round 50 schedules a 30-second timeout due to exponential backoff, and an epoch transition occurs after 5 seconds, the stale timeout fires 25 seconds into epoch N+1. For the vulnerability to trigger, epoch N+1 must reach round 50 within 25 seconds, which at typical 2-3 second round durations would only reach round 8-12.

The probability increases with:
- Higher round numbers in the old epoch
- Longer timeout durations
- Faster round progression in the new epoch

## Recommendation

Implement a `Drop` trait for `RoundState` to abort pending timeout tasks:

```rust
impl Drop for RoundState {
    fn drop(&mut self) {
        if let Some(handle) = self.abort_handle.take() {
            handle.abort();
        }
    }
}
```

Additionally, consider adding epoch validation to timeout processing or encoding epoch information in timeout messages to prevent cross-epoch timeout processing.

## Proof of Concept

The vulnerability can be demonstrated through code inspection:

1. Verify `RoundState` lacks `Drop` implementation (grep search returns no matches)
2. Confirm `abort_handle` is not aborted when `RoundState` is dropped during epoch transitions
3. Trace that `timeout_sender` is shared across epochs via `EpochManager`
4. Verify `process_local_timeout()` only checks round numbers, not epochs
5. Observe that timeout tasks only send round numbers without epoch identifiers

A full integration test would require:
- Simulating an epoch transition while a timeout is pending
- Verifying the timeout task continues running after `RoundState` is dropped
- Confirming the timeout fires and is processed in the new epoch when round numbers match

The code paths and logic defects are clearly present in the cited source locations.

### Citations

**File:** consensus/src/liveness/round_state.rs (L165-165)
```rust
    abort_handle: Option<AbortHandle>,
```

**File:** consensus/src/liveness/round_state.rs (L233-241)
```rust
    pub fn process_local_timeout(&mut self, round: Round) -> bool {
        if round != self.current_round {
            return false;
        }
        warn!(round = round, "Local timeout");
        counters::TIMEOUT_COUNT.inc();
        self.setup_timeout(1);
        true
    }
```

**File:** consensus/src/liveness/round_state.rs (L347-352)
```rust
        let abort_handle = self
            .time_service
            .run_after(timeout, SendTask::make(timeout_sender, self.current_round));
        if let Some(handle) = self.abort_handle.replace(abort_handle) {
            handle.abort();
        }
```

**File:** consensus/src/epoch_manager.rs (L140-140)
```rust
    timeout_sender: aptos_channels::Sender<Round>,
```

**File:** consensus/src/epoch_manager.rs (L273-283)
```rust
    fn create_round_state(
        &self,
        time_service: Arc<dyn TimeService>,
        timeout_sender: aptos_channels::Sender<Round>,
    ) -> RoundState {
        let time_interval = Box::new(ExponentialTimeInterval::new(
            Duration::from_millis(self.config.round_initial_timeout_ms),
            self.config.round_timeout_backoff_exponent_base,
            self.config.round_timeout_backoff_max_exponent,
        ));
        RoundState::new(time_interval, time_service, timeout_sender)
```

**File:** consensus/src/epoch_manager.rs (L637-683)
```rust
    async fn shutdown_current_processor(&mut self) {
        if let Some(close_tx) = self.round_manager_close_tx.take() {
            // Release the previous RoundManager, especially the SafetyRule client
            let (ack_tx, ack_rx) = oneshot::channel();
            close_tx
                .send(ack_tx)
                .expect("[EpochManager] Fail to drop round manager");
            ack_rx
                .await
                .expect("[EpochManager] Fail to drop round manager");
        }
        self.round_manager_tx = None;

        if let Some(close_tx) = self.dag_shutdown_tx.take() {
            // Release the previous RoundManager, especially the SafetyRule client
            let (ack_tx, ack_rx) = oneshot::channel();
            close_tx
                .send(ack_tx)
                .expect("[EpochManager] Fail to drop DAG bootstrapper");
            ack_rx
                .await
                .expect("[EpochManager] Fail to drop DAG bootstrapper");
        }
        self.dag_shutdown_tx = None;

        // Shutdown the previous rand manager
        self.rand_manager_msg_tx = None;

        // Shutdown the previous secret share manager
        self.secret_share_manager_tx = None;

        // Shutdown the previous buffer manager, to release the SafetyRule client
        self.execution_client.end_epoch().await;

        // Shutdown the block retrieval task by dropping the sender
        self.block_retrieval_tx = None;
        self.batch_retrieval_tx = None;

        if let Some(mut quorum_store_coordinator_tx) = self.quorum_store_coordinator_tx.take() {
            let (ack_tx, ack_rx) = oneshot::channel();
            quorum_store_coordinator_tx
                .send(CoordinatorCommand::Shutdown(ack_tx))
                .await
                .expect("Could not send shutdown indicator to QuorumStore");
            ack_rx.await.expect("Failed to stop QuorumStore");
        }
    }
```

**File:** consensus/src/epoch_manager.rs (L1896-1910)
```rust
    fn process_local_timeout(&mut self, round: u64) {
        let Some(sender) = self.round_manager_tx.as_mut() else {
            warn!(
                "Received local timeout for round {} without Round Manager",
                round
            );
            return;
        };

        let peer_id = self.author;
        let event = VerifiedEvent::LocalTimeout(round);
        if let Err(e) = sender.push((peer_id, discriminant(&event)), (peer_id, event)) {
            error!("Failed to send event to round manager {:?}", e);
        }
    }
```

**File:** consensus/src/round_manager.rs (L993-1043)
```rust
    pub async fn process_local_timeout(&mut self, round: Round) -> anyhow::Result<()> {
        if !self.round_state.process_local_timeout(round) {
            return Ok(());
        }

        if self.sync_only() {
            self.network
                .broadcast_sync_info(self.block_store.sync_info())
                .await;
            bail!("[RoundManager] sync_only flag is set, broadcasting SyncInfo");
        }

        if self.local_config.enable_round_timeout_msg {
            let timeout = if let Some(timeout) = self.round_state.timeout_sent() {
                timeout
            } else {
                let timeout = TwoChainTimeout::new(
                    self.epoch_state.epoch,
                    round,
                    self.block_store.highest_quorum_cert().as_ref().clone(),
                );
                let signature = self
                    .safety_rules
                    .lock()
                    .sign_timeout_with_qc(
                        &timeout,
                        self.block_store.highest_2chain_timeout_cert().as_deref(),
                    )
                    .context("[RoundManager] SafetyRules signs 2-chain timeout")?;

                let timeout_reason = self.compute_timeout_reason(round);

                RoundTimeout::new(
                    timeout,
                    self.proposal_generator.author(),
                    timeout_reason,
                    signature,
                )
            };

            self.round_state.record_round_timeout(timeout.clone());
            let round_timeout_msg = RoundTimeoutMsg::new(timeout, self.block_store.sync_info());
            self.network
                .broadcast_round_timeout(round_timeout_msg)
                .await;
            warn!(
                round = round,
                remote_peer = self.proposer_election.get_valid_proposer(round),
                event = LogEvent::Timeout,
            );
            bail!("Round {} timeout, broadcast to all peers", round);
```

**File:** consensus/src/round_manager.rs (L2018-2030)
```rust
    pub async fn init(&mut self, last_vote_sent: Option<Vote>) {
        let epoch_state = self.epoch_state.clone();
        let new_round_event = self
            .round_state
            .process_certificates(self.block_store.sync_info(), &epoch_state.verifier)
            .expect("Can not jump start a round_state from existing certificates.");
        if let Some(vote) = last_vote_sent {
            self.round_state.record_vote(vote);
        }
        if let Err(e) = self.process_new_round_event(new_round_event).await {
            warn!(error = ?e, "[RoundManager] Error during start");
        }
    }
```

**File:** consensus/src/round_manager.rs (L2076-2080)
```rust
                close_req = close_rx.select_next_some() => {
                    if let Ok(ack_sender) = close_req {
                        ack_sender.send(()).expect("[RoundManager] Fail to ack shutdown");
                    }
                    break;
```

**File:** consensus/src/util/time_service.rs (L56-96)
```rust
pub struct SendTask<T>
where
    T: Send + 'static,
{
    sender: Option<aptos_channels::Sender<T>>,
    message: Option<T>,
}

impl<T> SendTask<T>
where
    T: Send + 'static,
{
    /// Makes new SendTask for given sender and message and wraps it to Box
    pub fn make(sender: aptos_channels::Sender<T>, message: T) -> Box<dyn ScheduledTask> {
        Box::new(SendTask {
            sender: Some(sender),
            message: Some(message),
        })
    }
}

impl<T> ScheduledTask for SendTask<T>
where
    T: Send + 'static,
{
    fn run(&mut self) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let mut sender = self
            .sender
            .take()
            .expect("Expect to be able to take sender");
        let message = self
            .message
            .take()
            .expect("Expect to be able to take message");
        let r = async move {
            if let Err(e) = sender.send(message).await {
                error!("Error on send: {:?}", e);
            };
        };
        r.boxed()
    }
```

**File:** consensus/consensus-types/src/block_data.rs (L292-300)
```rust
    pub fn new_genesis(timestamp_usecs: u64, quorum_cert: QuorumCert) -> Self {
        assume!(quorum_cert.certified_block().epoch() < u64::MAX); // unlikely to be false in this universe
        Self {
            epoch: quorum_cert.certified_block().epoch() + 1,
            round: 0,
            timestamp_usecs,
            quorum_cert,
            block_type: BlockType::Genesis,
        }
```
