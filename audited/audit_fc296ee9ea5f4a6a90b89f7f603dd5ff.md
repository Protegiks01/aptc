# Audit Report

## Title
Commit Vote Loss During Epoch Transition Due to Unprotected Channel Transition Window

## Summary
During epoch transitions, there exists a critical time window where `handle.commit_tx` is `None` after the old buffer manager is shut down but before the new buffer manager is initialized. Commit votes arriving during this window are silently dropped, causing potential consensus liveness issues and block commitment delays.

## Finding Description

The vulnerability stems from the non-atomic nature of epoch transitions in the consensus pipeline. When a new epoch begins, the following sequence occurs: [1](#0-0) 

The `shutdown_current_processor()` call at line 554 triggers the buffer manager shutdown, which ultimately calls: [2](#0-1) 

This shutdown sequence calls `handle.write().reset()` at line 718, which sets `self.commit_tx = None`: [3](#0-2) 

After `shutdown_current_processor()` completes, there is a significant delay before the new buffer manager is initialized, including:
1. State sync operation (`sync_to_target().await`)
2. Waiting for reconfiguration notification (`await_reconfig_notification().await`)
3. Starting the new epoch with multiple async operations

During this entire window, when network commit messages arrive and are processed by `send_commit_msg()`, they encounter `commit_tx = None`: [4](#0-3) 

The message is silently dropped with only a warning log and a counter increment. The commit vote is permanently lost.

**Attack Scenario:**
1. Validator A completes block execution and sends commit votes to all validators
2. Validator B receives epoch change proof and begins epoch transition
3. Validator B's buffer manager is shut down, setting `handle.commit_tx = None`
4. Validator A's commit vote arrives at Validator B during the transition window
5. `send_commit_msg()` finds `commit_tx = None` and drops the message
6. Commit vote is lost and never reaches the new epoch's buffer manager
7. Block may fail to reach quorum if enough votes are lost across validators during transition

This breaks the **Consensus Safety** invariant as commit votes are critical for achieving quorum and ensuring all validators agree on committed blocks.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty criteria:

- **Significant Protocol Violations**: Lost commit votes directly violate consensus protocol assumptions that all valid votes will be processed
- **Consensus Liveness Impact**: If multiple validators are transitioning epochs simultaneously, enough votes could be lost to prevent blocks from reaching quorum, stalling consensus progress
- **No Fork/Safety Violation**: While serious, this doesn't cause chain splits or double-spending (doesn't reach Critical severity)

The impact is bounded by:
- Duration of the transition window (typically seconds)
- Number of concurrent epoch transitions
- Vote redundancy in the system

However, in worst-case scenarios with synchronized epoch changes across the network, this could temporarily halt consensus progress until validators retransmit votes or the next round begins.

## Likelihood Explanation

**Likelihood: Medium to High**

- **Epoch transitions are routine**: Occur regularly based on on-chain governance
- **No attacker action required**: This is a race condition in normal operations
- **Network latency makes it probable**: Commit votes transmitted during epoch boundaries will naturally fall into this window
- **Affects all validators**: Any validator transitioning epochs is vulnerable

The race window is substantial due to:
1. Async state sync operations
2. Reconfiguration notification delays  
3. New epoch initialization overhead

## Recommendation

**Solution: Buffer commit messages during epoch transitions**

Modify the epoch transition logic to queue incoming commit messages when `commit_tx` is `None` and replay them once the new buffer manager is ready. Alternatively, extend the old buffer manager's lifetime to overlap with the new epoch initialization.

**Code Fix Approach:**

1. Add a pending message queue to `BufferManagerHandle`:
```rust
struct BufferManagerHandle {
    pub commit_tx: Option<...>,
    pub pending_commits: Arc<Mutex<Vec<(AccountAddress, IncomingCommitRequest)>>>,
    // ... other fields
}
```

2. Modify `send_commit_msg` to queue messages when channel is unavailable:
```rust
fn send_commit_msg(&self, peer_id: AccountAddress, commit_msg: IncomingCommitRequest) -> Result<()> {
    if let Some(tx) = &self.handle.read().commit_tx {
        tx.push(peer_id, (peer_id, commit_msg))
    } else {
        // Queue message for delivery when new epoch starts
        self.handle.write().pending_commits.lock().push((peer_id, commit_msg));
        Ok(())
    }
}
```

3. When initializing new epoch, drain and process pending messages:
```rust
pub fn init(&mut self, ...) {
    self.commit_tx = Some(commit_tx);
    // Process queued messages
    for (peer_id, msg) in self.pending_commits.lock().drain(..) {
        let _ = commit_tx.push(peer_id, (peer_id, msg));
    }
}
```

**Alternative: Epoch validation in BufferManager**

Add epoch checking to the BufferManager's verification logic to reject messages from wrong epochs: [5](#0-4) 

The verification should check `commit_msg.req.epoch()` matches `epoch_state.epoch` before processing.

## Proof of Concept

**Rust Test Scenario:**

```rust
#[tokio::test]
async fn test_commit_vote_loss_during_epoch_transition() {
    // Setup: Create validator with epoch N
    let (execution_client, mut network_rx) = setup_test_execution_client(epoch_n);
    
    // Step 1: Initiate epoch transition to N+1
    let epoch_change_handle = tokio::spawn(async move {
        execution_client.initiate_new_epoch(epoch_n_plus_1_proof).await;
    });
    
    // Step 2: Wait for old buffer manager to shut down
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Step 3: Send commit vote during transition window
    let commit_vote = create_test_commit_vote(epoch_n, round_100);
    let result = execution_client.send_commit_msg(peer_id, commit_vote).await;
    
    // Step 4: Verify vote was dropped
    assert!(result.is_ok()); // Returns Ok but message is lost
    
    // Step 5: Wait for epoch transition to complete
    epoch_change_handle.await.unwrap();
    
    // Step 6: Verify commit vote was never processed
    // Check that buffer manager never received the vote
    assert_eq!(get_received_votes_count(), 0);
    
    // Verify counter was incremented
    assert_eq!(
        counters::EPOCH_MANAGER_ISSUES_DETAILS
            .with_label_values(&["buffer_manager_not_started"])
            .get(),
        1
    );
}
```

**Reproduction Steps:**

1. Setup network with multiple validators
2. Execute blocks to trigger epoch transition
3. Monitor commit vote message delivery during epoch boundary
4. Observe votes arriving during shutdown→initialization window
5. Confirm these votes are logged as "Buffer manager not started" and never processed
6. Measure impact on block commitment latency

The vulnerability can be confirmed by inspecting the metric: `EPOCH_MANAGER_ISSUES_DETAILS{label="buffer_manager_not_started"}` during epoch transitions.

## Notes

This vulnerability affects all validators during routine epoch transitions. While individual instances may have limited impact, the cumulative effect across the network during synchronized epoch changes could significantly impact consensus performance. The fix should ensure zero message loss while maintaining clean epoch boundaries.

### Citations

**File:** consensus/src/epoch_manager.rs (L544-569)
```rust
    async fn initiate_new_epoch(&mut self, proof: EpochChangeProof) -> anyhow::Result<()> {
        let ledger_info = proof
            .verify(self.epoch_state())
            .context("[EpochManager] Invalid EpochChangeProof")?;
        info!(
            LogSchema::new(LogEvent::NewEpoch).epoch(ledger_info.ledger_info().next_block_epoch()),
            "Received verified epoch change",
        );

        // shutdown existing processor first to avoid race condition with state sync.
        self.shutdown_current_processor().await;
        *self.pending_blocks.lock() = PendingBlocks::new();
        // make sure storage is on this ledger_info too, it should be no-op if it's already committed
        // panic if this doesn't succeed since the current processors are already shutdown.
        self.execution_client
            .sync_to_target(ledger_info.clone())
            .await
            .context(format!(
                "[EpochManager] State sync to new epoch {}",
                ledger_info
            ))
            .expect("Failed to sync to new epoch");

        monitor!("reconfig", self.await_reconfig_notification().await);
        Ok(())
    }
```

**File:** consensus/src/pipeline/execution_client.rs (L159-176)
```rust
    pub fn reset(
        &mut self,
    ) -> (
        Option<UnboundedSender<ResetRequest>>,
        Option<UnboundedSender<ResetRequest>>,
        Option<UnboundedSender<ResetRequest>>,
    ) {
        let reset_tx_to_rand_manager = self.reset_tx_to_rand_manager.take();
        let reset_tx_to_buffer_manager = self.reset_tx_to_buffer_manager.take();
        let reset_tx_to_secret_share_manager = self.reset_tx_to_secret_share_manager.take();
        self.execute_tx = None;
        self.commit_tx = None;
        (
            reset_tx_to_rand_manager,
            reset_tx_to_buffer_manager,
            reset_tx_to_secret_share_manager,
        )
    }
```

**File:** consensus/src/pipeline/execution_client.rs (L626-640)
```rust
    fn send_commit_msg(
        &self,
        peer_id: AccountAddress,
        commit_msg: IncomingCommitRequest,
    ) -> Result<()> {
        if let Some(tx) = &self.handle.read().commit_tx {
            tx.push(peer_id, (peer_id, commit_msg))
        } else {
            counters::EPOCH_MANAGER_ISSUES_DETAILS
                .with_label_values(&["buffer_manager_not_started"])
                .inc();
            warn!("Buffer manager not started");
            Ok(())
        }
    }
```

**File:** consensus/src/pipeline/execution_client.rs (L711-759)
```rust
    async fn end_epoch(&self) {
        let (
            reset_tx_to_rand_manager,
            reset_tx_to_buffer_manager,
            reset_tx_to_secret_share_manager,
        ) = {
            let mut handle = self.handle.write();
            handle.reset()
        };

        if let Some(mut tx) = reset_tx_to_rand_manager {
            let (ack_tx, ack_rx) = oneshot::channel();
            tx.send(ResetRequest {
                tx: ack_tx,
                signal: ResetSignal::Stop,
            })
            .await
            .expect("[EpochManager] Fail to drop rand manager");
            ack_rx
                .await
                .expect("[EpochManager] Fail to drop rand manager");
        }

        if let Some(mut tx) = reset_tx_to_secret_share_manager {
            let (ack_tx, ack_rx) = oneshot::channel();
            tx.send(ResetRequest {
                tx: ack_tx,
                signal: ResetSignal::Stop,
            })
            .await
            .expect("[EpochManager] Fail to drop secret share manager");
            ack_rx
                .await
                .expect("[EpochManager] Fail to drop secret share manager");
        }

        if let Some(mut tx) = reset_tx_to_buffer_manager {
            let (ack_tx, ack_rx) = oneshot::channel();
            tx.send(ResetRequest {
                tx: ack_tx,
                signal: ResetSignal::Stop,
            })
            .await
            .expect("[EpochManager] Fail to drop buffer manager");
            ack_rx
                .await
                .expect("[EpochManager] Fail to drop buffer manager");
        }
        self.execution_proxy.end_epoch();
```

**File:** consensus/src/pipeline/buffer_manager.rs (L912-934)
```rust
    pub async fn start(mut self) {
        info!("Buffer manager starts.");
        let (verified_commit_msg_tx, mut verified_commit_msg_rx) = create_channel();
        let mut interval = tokio::time::interval(Duration::from_millis(LOOP_INTERVAL_MS));
        let mut commit_msg_rx = self.commit_msg_rx.take().expect("commit msg rx must exist");
        let epoch_state = self.epoch_state.clone();
        let bounded_executor = self.bounded_executor.clone();
        spawn_named!("buffer manager verification", async move {
            while let Some((sender, commit_msg)) = commit_msg_rx.next().await {
                let tx = verified_commit_msg_tx.clone();
                let epoch_state_clone = epoch_state.clone();
                bounded_executor
                    .spawn(async move {
                        match commit_msg.req.verify(sender, &epoch_state_clone.verifier) {
                            Ok(_) => {
                                let _ = tx.unbounded_send(commit_msg);
                            },
                            Err(e) => warn!("Invalid commit message: {}", e),
                        }
                    })
                    .await;
            }
        });
```
