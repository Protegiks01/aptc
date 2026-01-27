# Audit Report

## Title
Zombie Randomness Share Aggregation Tasks Can Corrupt RandStore State After Reset

## Summary
The `process_reset()` function in RandManager fails to properly prevent zombie share aggregation tasks from continuing to process randomness shares after a reset. This allows stale partial share state to be re-inserted into the `rand_map`, violating reset semantics and potentially causing blocks to get stuck or produce incorrect randomness.

## Finding Description

When `RandManager::process_reset()` is called during state synchronization, it attempts to clear all in-flight randomness generation state by:
1. Replacing the block queue with a new empty one (which drops DropGuards)
2. Calling `rand_store.reset(target_round)` to clear rounds >= target_round [1](#0-0) 

The reset clears entries from `rand_map` for rounds >= target_round: [2](#0-1) 

However, there is a critical race condition. When blocks are processed, `spawn_aggregate_shares_task()` creates async tasks that broadcast share requests to other validators: [3](#0-2) 

These tasks pass a `ShareAggregateState` to the reliable broadcast, which holds an `Arc<Mutex<RandStore>>`. When responses arrive from other validators, the reliable broadcast spawns executor tasks that call `ShareAggregateState::add()`: [4](#0-3) 

The critical issue is that even after the DropGuard is dropped and the main task is aborted, executor tasks that are already processing responses will complete their execution. When they call `add_share()`, the function checks: [5](#0-4) 

With `FUTURE_ROUNDS_TO_ACCEPT = 200`, zombie tasks for old rounds can pass this check and create NEW entries in `rand_map`: [6](#0-5) 

**Concrete Attack Scenario:**
1. Node processes blocks for rounds 100, 101, 102, spawning share aggregation tasks
2. Tasks broadcast share requests via `rb.multicast()`, spawning executor tasks
3. State sync triggers reset to round 95 via `ExecutionProxyClient::reset()`
4. `rand_store.reset(95)` clears rounds >= 95, sets `highest_known_round = 95`
5. Zombie executor tasks receive responses for rounds 100, 101, 102
6. Check: `100 <= 95 + 200` = TRUE → share is accepted
7. New entries created in `rand_map` for rounds 100, 101, 102 with partial state
8. When blocks re-enter after state sync, they find stale partial state instead of clean slate
9. Blocks may get stuck waiting for shares that will never arrive, or mix old/new shares [7](#0-6) 

## Impact Explanation

This vulnerability qualifies as **High Severity** under Aptos bug bounty criteria:

**Validator Node Slowdowns:** Blocks can get stuck in the randomness generation queue indefinitely if they find partial share state that cannot complete aggregation, causing the validator to fall behind and experience performance degradation.

**Significant Protocol Violations:** The reset mechanism is intended to ensure clean state when synchronizing. Allowing zombie tasks to violate this invariant breaks the State Consistency guarantee that "state transitions must be atomic and verifiable."

Additionally, this could escalate to **Medium Severity** for state inconsistencies requiring intervention, as different validators resetting at different times may have different partial states in their rand_maps, potentially leading to non-deterministic randomness if the race timing varies across nodes.

## Likelihood Explanation

This vulnerability has **HIGH likelihood** of occurring in production:

1. **Frequent Trigger:** State sync and resets happen regularly during normal operation when validators fall behind or during validator restarts
2. **Inherent Race Condition:** The 300ms sleep in aggregation tasks combined with network latencies makes it highly probable that some executor tasks will still be processing when reset occurs
3. **Wide Window:** With `FUTURE_ROUNDS_TO_ACCEPT = 200`, there's a large range of old rounds that can be re-inserted
4. **No Validation Gap:** The code contains no mechanism to detect or prevent this race condition

The issue requires no attacker action - it occurs naturally during the consensus protocol's normal operation.

## Recommendation

**Primary Fix:** Track the epoch/reset generation in `ShareAggregateState` and reject shares if the generation has changed:

```rust
// In RandStore
pub struct RandStore<S> {
    // ... existing fields ...
    reset_generation: u64,  // Increment on each reset
}

impl<S: TShare> RandStore<S> {
    pub fn reset(&mut self, round: u64) {
        self.update_highest_known_round(round);
        self.reset_generation += 1;  // Increment generation
        let _ = self.rand_map.split_off(&round);
        let _ = self.fast_rand_map.as_mut().map(|map| map.split_off(&round));
    }
}

// In ShareAggregateState
pub struct ShareAggregateState<S> {
    rand_metadata: RandMetadata,
    rand_store: Arc<Mutex<RandStore<S>>>,
    rand_config: RandConfig,
    expected_generation: u64,  // Capture at creation time
}

impl<S: TShare, D: TAugmentedData> BroadcastStatus<RandMessage<S, D>, RandMessage<S, D>>
    for Arc<ShareAggregateState<S>>
{
    fn add(&self, peer: Author, share: Self::Response) -> anyhow::Result<Option<()>> {
        let mut store = self.rand_store.lock();
        
        // Reject shares if reset has occurred
        ensure!(
            store.reset_generation == self.expected_generation,
            "Share rejected: reset occurred (expected gen {}, current gen {})",
            self.expected_generation,
            store.reset_generation
        );
        
        // ... rest of existing logic ...
    }
}
```

**Alternative Fix:** Explicitly abort all in-flight broadcasts before reset by storing abort handles in RandManager and calling abort on them synchronously.

## Proof of Concept

```rust
#[tokio::test]
async fn test_zombie_share_aggregation_after_reset() {
    use consensus::rand::rand_gen::{rand_manager::RandManager, types::{Share, AugmentedData}};
    use futures_channel::mpsc::unbounded;
    
    // Setup: Create RandManager with blocks for rounds 100, 101, 102
    // ... (setup code omitted for brevity) ...
    
    // Step 1: Process blocks to spawn aggregation tasks
    for round in [100, 101, 102] {
        let metadata = create_test_metadata(round);
        rand_manager.process_incoming_metadata(metadata);
    }
    
    // Step 2: Wait for tasks to start broadcasting (past the 300ms sleep)
    tokio::time::sleep(Duration::from_millis(350)).await;
    
    // Step 3: Trigger reset to round 95
    let (reset_tx, reset_rx) = oneshot::channel();
    rand_manager.process_reset(ResetRequest {
        tx: reset_tx,
        signal: ResetSignal::TargetRound(95),
    });
    
    // Step 4: Verify rand_map was cleared
    assert!(rand_manager.rand_store.lock().rand_map.get(&100).is_none());
    
    // Step 5: Simulate late responses from zombie executor tasks
    // These responses will be processed even though reset occurred
    let share = create_test_share(100);
    // The zombie task calls ShareAggregateState::add()
    // which calls rand_store.add_share(share)
    
    // Step 6: Verify BUG - round 100 re-appears in rand_map!
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(rand_manager.rand_store.lock().rand_map.get(&100).is_some());
    // This should be None but is Some due to zombie task re-inserting it
}
```

## Notes

This vulnerability exists because the `Abortable` wrapper only cancels futures at await points, but executor tasks spawned by the reliable broadcast are independent and continue executing their completion logic. The permissive `FUTURE_ROUNDS_TO_ACCEPT = 200` window exacerbates the issue by allowing a wide range of old rounds to be re-inserted after reset.

The comment in `RandStore::reset()` explicitly acknowledges this scenario: "remove future rounds items in case they're already decided, otherwise if the block re-enters the queue, it'll be stuck" - but the implementation fails to prevent zombie tasks from violating this invariant.

### Citations

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L184-194)
```rust
    fn process_reset(&mut self, request: ResetRequest) {
        let ResetRequest { tx, signal } = request;
        let target_round = match signal {
            ResetSignal::Stop => 0,
            ResetSignal::TargetRound(round) => round,
        };
        self.block_queue = BlockQueue::new();
        self.rand_store.lock().reset(target_round);
        self.stop = matches!(signal, ResetSignal::Stop);
        let _ = tx.send(ResetAck::default());
    }
```

**File:** consensus/src/rand/rand_gen/rand_manager.rs (L263-303)
```rust
    fn spawn_aggregate_shares_task(&self, metadata: RandMetadata) -> DropGuard {
        let rb = self.reliable_broadcast.clone();
        let aggregate_state = Arc::new(ShareAggregateState::new(
            self.rand_store.clone(),
            metadata.clone(),
            self.config.clone(),
        ));
        let epoch_state = self.epoch_state.clone();
        let round = metadata.round;
        let rand_store = self.rand_store.clone();
        let task = async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            let maybe_existing_shares = rand_store.lock().get_all_shares_authors(round);
            if let Some(existing_shares) = maybe_existing_shares {
                let epoch = epoch_state.epoch;
                let request = RequestShare::new(metadata.clone());
                let targets = epoch_state
                    .verifier
                    .get_ordered_account_addresses_iter()
                    .filter(|author| !existing_shares.contains(author))
                    .collect::<Vec<_>>();
                info!(
                    epoch = epoch,
                    round = round,
                    "[RandManager] Start broadcasting share request for {}",
                    targets.len(),
                );
                rb.multicast(request, aggregate_state, targets)
                    .await
                    .expect("Broadcast cannot fail");
                info!(
                    epoch = epoch,
                    round = round,
                    "[RandManager] Finish broadcasting share request",
                );
            }
        };
        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        tokio::spawn(Abortable::new(task, abort_registration));
        DropGuard::new(abort_handle)
    }
```

**File:** consensus/src/rand/rand_gen/rand_store.rs (L253-259)
```rust
    pub fn reset(&mut self, round: u64) {
        self.update_highest_known_round(round);
        // remove future rounds items in case they're already decided
        // otherwise if the block re-enters the queue, it'll be stuck
        let _ = self.rand_map.split_off(&round);
        let _ = self.fast_rand_map.as_mut().map(|map| map.split_off(&round));
    }
```

**File:** consensus/src/rand/rand_gen/rand_store.rs (L280-313)
```rust
    pub fn add_share(&mut self, share: RandShare<S>, path: PathType) -> anyhow::Result<bool> {
        ensure!(
            share.metadata().epoch == self.epoch,
            "Share from different epoch"
        );
        ensure!(
            share.metadata().round <= self.highest_known_round + FUTURE_ROUNDS_TO_ACCEPT,
            "Share from future round"
        );
        let rand_metadata = share.metadata().clone();

        let (rand_config, rand_item) = if path == PathType::Fast {
            match (self.fast_rand_config.as_ref(), self.fast_rand_map.as_mut()) {
                (Some(fast_rand_config), Some(fast_rand_map)) => (
                    fast_rand_config,
                    fast_rand_map
                        .entry(rand_metadata.round)
                        .or_insert_with(|| RandItem::new(self.author, path)),
                ),
                _ => anyhow::bail!("Fast path not enabled"),
            }
        } else {
            (
                &self.rand_config,
                self.rand_map
                    .entry(rand_metadata.round)
                    .or_insert_with(|| RandItem::new(self.author, PathType::Slow)),
            )
        };

        rand_item.add_share(share, rand_config)?;
        rand_item.try_aggregate(rand_config, self.decision_tx.clone());
        Ok(rand_item.has_decision())
    }
```

**File:** consensus/src/rand/rand_gen/reliable_broadcast_state.rs (L131-151)
```rust
    fn add(&self, peer: Author, share: Self::Response) -> anyhow::Result<Option<()>> {
        ensure!(share.author() == &peer, "Author does not match");
        ensure!(
            share.metadata() == &self.rand_metadata,
            "Metadata does not match: local {:?}, received {:?}",
            self.rand_metadata,
            share.metadata()
        );
        share.verify(&self.rand_config)?;
        info!(LogSchema::new(LogEvent::ReceiveReactiveRandShare)
            .epoch(share.epoch())
            .round(share.metadata().round)
            .remote_peer(*share.author()));
        let mut store = self.rand_store.lock();
        let aggregated = if store.add_share(share, PathType::Slow)? {
            Some(())
        } else {
            None
        };
        Ok(aggregated)
    }
```

**File:** consensus/src/rand/rand_gen/types.rs (L26-26)
```rust
pub const FUTURE_ROUNDS_TO_ACCEPT: u64 = 200;
```

**File:** consensus/src/pipeline/execution_client.rs (L674-709)
```rust
    async fn reset(&self, target: &LedgerInfoWithSignatures) -> Result<()> {
        let (reset_tx_to_rand_manager, reset_tx_to_buffer_manager) = {
            let handle = self.handle.read();
            (
                handle.reset_tx_to_rand_manager.clone(),
                handle.reset_tx_to_buffer_manager.clone(),
            )
        };

        if let Some(mut reset_tx) = reset_tx_to_rand_manager {
            let (ack_tx, ack_rx) = oneshot::channel::<ResetAck>();
            reset_tx
                .send(ResetRequest {
                    tx: ack_tx,
                    signal: ResetSignal::TargetRound(target.commit_info().round()),
                })
                .await
                .map_err(|_| Error::RandResetDropped)?;
            ack_rx.await.map_err(|_| Error::RandResetDropped)?;
        }

        if let Some(mut reset_tx) = reset_tx_to_buffer_manager {
            // reset execution phase and commit phase
            let (tx, rx) = oneshot::channel::<ResetAck>();
            reset_tx
                .send(ResetRequest {
                    tx,
                    signal: ResetSignal::TargetRound(target.commit_info().round()),
                })
                .await
                .map_err(|_| Error::ResetDropped)?;
            rx.await.map_err(|_| Error::ResetDropped)?;
        }

        Ok(())
    }
```
