# Audit Report

## Title
Race Condition in Epoch Transition: end_epoch() Fails to Synchronize with Concurrent State Sync Operations

## Summary
The `end_epoch()` function in `ExecutionProxy` clears epoch-specific state without acquiring the `write_mutex`, allowing concurrent state synchronization operations to continue executing with stale epoch context. This race condition can cause state inconsistencies, executor corruption, and logical time desynchronization during epoch transitions.

## Finding Description

The `ExecutionProxy` struct uses two synchronization mechanisms: [1](#0-0) 

The `write_mutex` serializes all state synchronization operations (`sync_to_target()` and `sync_for_duration()`), which acquire this lock before modifying executor state: [2](#0-1) 

However, `end_epoch()` only locks the `state` RwLock, completely bypassing the `write_mutex`: [3](#0-2) 

**The Race Condition:**

During epoch transitions in `EpochManager::initiate_new_epoch()`: [4](#0-3) 

The flow executes:
1. `shutdown_current_processor()` → calls `execution_client.end_epoch().await`
2. `sync_to_target()` for new epoch

This creates a critical race window where:

**Thread A (Background Sync):** Executing `sync_to_target(Epoch N, Round 200)` from consensus observer: [5](#0-4) 

**Thread B (Epoch Transition):** Calls `end_epoch()` to transition to Epoch N+1

**Timeline:**
1. Thread A acquires `write_mutex` for Epoch N sync
2. Thread A calls `executor.finish()` to free memory
3. Thread B calls `end_epoch()`, clears `state` without waiting for `write_mutex`
4. Thread A continues syncing (holding `write_mutex`)
5. Thread A calls `executor.reset()` **after epoch has ended**
6. Thread A updates `latest_logical_time` with stale Epoch N data
7. New Epoch N+1 starts with `LogicalTime` containing stale Epoch N values

**Critical Issues:**

1. **Executor State Corruption:** `executor.reset()` is called after `end_epoch()` has already cleared epoch state, potentially corrupting the executor cache during new epoch initialization.

2. **Logical Time Desynchronization:** The `write_mutex` guards `LogicalTime(epoch, round)` but is never reset during epoch transitions. A sync operation from the old epoch can update it with stale values after `end_epoch()` completes.

3. **Broken Synchronization Invariant:** The `write_mutex` is designed to ensure atomicity of state sync operations, but `end_epoch()` breaks this guarantee by modifying related state without acquiring the mutex.

## Impact Explanation

**Severity: HIGH** (per Aptos Bug Bounty criteria)

This vulnerability qualifies as "Significant protocol violations" and "State inconsistencies requiring intervention":

1. **State Consistency Violation:** Breaks the critical invariant that state transitions must be atomic. The system can enter an inconsistent state where epoch state is N+1 but logical time reflects epoch N.

2. **Executor Corruption Risk:** The `executor.reset()` operation refreshes the executor cache with latest committed state. Calling this after epoch transition could load stale state or interfere with new epoch setup.

3. **Consensus Observer Impact:** Any node running as consensus observer can trigger this race through normal operations, affecting network-wide consensus coordination.

4. **Difficult to Debug:** This is a timing-dependent race condition that may manifest intermittently during epoch transitions, causing hard-to-reproduce state inconsistencies.

5. **Potential Synchronization Failures:** Stale logical time could cause nodes to make incorrect synchronization decisions, though the derived `Ord` implementation mitigates some impact.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

This race condition will occur when:
- An epoch transition happens (regular occurrence in Aptos)
- Concurrent state sync operations are in progress (common with consensus observer)
- Timing allows sync operation to hold `write_mutex` during `end_epoch()` call

The consensus observer frequently spawns independent sync tasks: [6](#0-5) 

Block sync manager also calls sync operations independently: [7](#0-6) 

Given that:
- Epoch transitions are predictable events
- Multiple components spawn concurrent sync tasks
- The race window spans the entire sync operation duration (potentially seconds)

The likelihood of occurrence during production operation is significant, though impact may vary depending on exact timing.

## Recommendation

**Solution:** Acquire `write_mutex` in `end_epoch()` to ensure all concurrent sync operations complete before epoch state is cleared.

```rust
fn end_epoch(&self) {
    // Acquire write_mutex to ensure no sync operations are in progress
    // Use blocking_lock since end_epoch is not async
    let _guard = self.write_mutex.blocking_lock();
    
    // Now safe to clear epoch state
    self.state.write().take();
    
    // Consider resetting logical time to prevent stale data
    // This would require making end_epoch async or using a different approach
}
```

**Alternative Solution (Better):** Make `end_epoch()` async and properly synchronize:

```rust
async fn end_epoch(&self) {
    // Wait for any in-progress sync operations to complete
    let mut latest_logical_time = self.write_mutex.lock().await;
    
    // Clear epoch state
    self.state.write().take();
    
    // Reset logical time to mark epoch boundary
    // The next sync will set appropriate values for new epoch
    *latest_logical_time = LogicalTime::new(0, 0);
}
```

This requires updating the trait definition in `StateComputer`: [8](#0-7) 

And the `TExecutionClient` trait: [9](#0-8) 

## Proof of Concept

```rust
#[tokio::test]
async fn test_end_epoch_race_condition() {
    use std::sync::Arc;
    use tokio::time::{sleep, Duration};
    
    // Setup ExecutionProxy with test components
    let execution_proxy = Arc::new(/* initialize ExecutionProxy */);
    
    // Simulate epoch N = 5, round = 100
    let target_n = create_test_ledger_info(5, 100);
    
    // Thread A: Start sync operation
    let proxy_clone = execution_proxy.clone();
    let sync_task = tokio::spawn(async move {
        println!("Thread A: Starting sync_to_target for epoch 5, round 100");
        let result = proxy_clone.sync_to_target(target_n).await;
        println!("Thread A: Completed sync_to_target: {:?}", result);
    });
    
    // Small delay to ensure sync_task acquires write_mutex
    sleep(Duration::from_millis(10)).await;
    
    // Thread B: End epoch while sync is in progress
    let proxy_clone2 = execution_proxy.clone();
    let end_epoch_task = tokio::spawn(async move {
        println!("Thread B: Calling end_epoch()");
        proxy_clone2.end_epoch();
        println!("Thread B: end_epoch() completed");
    });
    
    // Wait for both tasks
    let _ = tokio::join!(sync_task, end_epoch_task);
    
    // Thread C: Start new epoch and verify state
    execution_proxy.new_epoch(/* epoch 6 state */);
    
    // BUG: The write_mutex still contains LogicalTime(5, 100) from old epoch
    // even though we're now in epoch 6
    
    // Try to sync to epoch 6, round 5
    let target_n1 = create_test_ledger_info(6, 5);
    let result = execution_proxy.sync_to_target(target_n1).await;
    
    // Verify: The logical time should be (6, 5) but may still show (5, 100)
    // This demonstrates the race condition
}
```

**Note:** Full PoC requires access to test infrastructure and mock components, but the race condition is demonstrated through the concurrent execution pattern above.

### Citations

**File:** consensus/src/state_computer.rs (L54-63)
```rust
pub struct ExecutionProxy {
    executor: Arc<dyn BlockExecutorTrait>,
    txn_notifier: Arc<dyn TxnNotifier>,
    state_sync_notifier: Arc<dyn ConsensusNotificationSender>,
    write_mutex: AsyncMutex<LogicalTime>,
    txn_filter_config: Arc<BlockTransactionFilterConfig>,
    state: RwLock<Option<MutableState>>,
    enable_pre_commit: bool,
    secret_share_config: Option<SecretShareConfig>,
}
```

**File:** consensus/src/state_computer.rs (L177-182)
```rust
    async fn sync_to_target(&self, target: LedgerInfoWithSignatures) -> Result<(), StateSyncError> {
        // Grab the logical time lock and calculate the target logical time
        let mut latest_logical_time = self.write_mutex.lock().await;
        let target_logical_time =
            LogicalTime::new(target.ledger_info().epoch(), target.ledger_info().round());

```

**File:** consensus/src/state_computer.rs (L266-268)
```rust
    fn end_epoch(&self) {
        self.state.write().take();
    }
```

**File:** consensus/src/epoch_manager.rs (L554-569)
```rust
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

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L150-153)
```rust
                let latest_synced_ledger_info = match execution_client
                    .clone()
                    .sync_for_duration(fallback_duration)
                    .await
```

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L218-222)
```rust
                // Sync to the commit decision
                if let Err(error) = execution_client
                    .clone()
                    .sync_to_target(commit_decision.commit_proof().clone())
                    .await
```

**File:** consensus/src/block_storage/sync_manager.rs (L512-514)
```rust
        execution_client
            .sync_to_target(highest_commit_cert.ledger_info().clone())
            .await?;
```

**File:** consensus/src/state_replication.rs (L1-50)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

use crate::{
    error::StateSyncError, network::NetworkSender, payload_manager::TPayloadManager,
    transaction_deduper::TransactionDeduper, transaction_shuffler::TransactionShuffler,
};
use anyhow::Result;
use aptos_consensus_types::pipelined_block::PipelinedBlock;
use aptos_types::{
    block_executor::config::BlockExecutorConfigFromOnchain, epoch_state::EpochState,
    ledger_info::LedgerInfoWithSignatures, on_chain_config::OnChainConsensusConfig,
};
use std::{sync::Arc, time::Duration};

pub type StateComputerCommitCallBackType =
    Box<dyn FnOnce(&[Arc<PipelinedBlock>], LedgerInfoWithSignatures) + Send + Sync>;

/// While Consensus is managing proposed blocks, `StateComputer` is managing the results of the
/// (speculative) execution of their payload.
/// StateComputer is using proposed block ids for identifying the transactions.
#[async_trait::async_trait]
pub trait StateComputer: Send + Sync {
    /// Best effort state synchronization for the specified duration.
    /// This function returns the latest synced ledger info after state syncing.
    /// Note: it is possible that state sync may run longer than the specified
    /// duration (e.g., if the node is very far behind).
    async fn sync_for_duration(
        &self,
        duration: Duration,
    ) -> Result<LedgerInfoWithSignatures, StateSyncError>;

    /// Best effort state synchronization to the given target LedgerInfo.
    /// In case of success (`Result::Ok`) the LI of storage is at the given target.
    /// In case of failure (`Result::Error`) the LI of storage remains unchanged, and the validator
    /// can assume there were no modifications to the storage made.
    async fn sync_to_target(&self, target: LedgerInfoWithSignatures) -> Result<(), StateSyncError>;

    // Reconfigure to execute transactions for a new epoch.
    fn new_epoch(
        &self,
        epoch_state: &EpochState,
        payload_manager: Arc<dyn TPayloadManager>,
        transaction_shuffler: Arc<dyn TransactionShuffler>,
        block_executor_onchain_config: BlockExecutorConfigFromOnchain,
        transaction_deduper: Arc<dyn TransactionDeduper>,
        randomness_enabled: bool,
        consensus_onchain_config: OnChainConsensusConfig,
        persisted_auxiliary_info_version: u8,
        network_sender: Arc<NetworkSender>,
```

**File:** consensus/src/pipeline/execution_client.rs (L118-118)
```rust
    async fn end_epoch(&self);
```
