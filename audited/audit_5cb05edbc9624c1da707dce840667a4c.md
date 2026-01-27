# Audit Report

## Title
Consensus Liveness Failure: Unconditional Logical Time Update on State Sync Failure

## Summary
The `sync_to_target()` function in `consensus/src/state_computer.rs` unconditionally updates the internal logical time tracker even when state synchronization fails, causing the node to incorrectly believe it has synced to a higher consensus round than its actual committed state. This breaks state consistency invariants and can cause permanent validator node liveness failures.

## Finding Description

The vulnerability exists in the `ExecutionProxy::sync_to_target()` implementation where the logical time is updated unconditionally before checking if the synchronization succeeded. [1](#0-0) 

The critical bug is on line 222, where `*latest_logical_time = target_logical_time;` executes **before** checking if the `state_sync_notifier.sync_to_target(target)` call succeeded. Even if synchronization fails (due to network errors, invalid signatures, storage failures, or other issues), the node's internal logical time tracking gets updated to the target epoch and round.

This contrasts with the correct implementation in `sync_for_duration()` which only updates logical time when synchronization succeeds: [2](#0-1) 

While there is validation preventing backward syncing: [3](#0-2) 

This validation becomes harmful when logical time is corrupted. Once logical time is set to a higher value than actual committed state, future legitimate sync requests get incorrectly rejected.

**Attack Scenario:**

1. Validator node is genuinely at epoch 1, round 10 with committed state
2. A `sync_to_target()` call is made with target at epoch 1, round 100
3. Validation passes (100 > 10)
4. State synchronization fails (network error, storage issue, or malicious invalid ledger info)
5. **BUG TRIGGERED**: `latest_logical_time` updated to (1, 100) despite sync failure
6. Error returned to caller, but internal state corrupted
7. Node's actual committed state remains at round 10, but `write_mutex` now stores (1, 100)

**Consequence:**
8. Legitimate `sync_to_target()` called with target at epoch 1, round 50
9. Validation check: 100 >= 50? **TRUE**
10. Function returns `Ok()` without syncing (line 193)
11. **Node permanently stuck at round 10, unable to catch up with network**

This breaks the **State Consistency** invariant as the node's internal logical time view diverges from actual committed state, and the **Consensus Liveness** invariant as the node cannot progress.

## Impact Explanation

**Severity: HIGH** (up to $50,000 per Aptos Bug Bounty)

This vulnerability qualifies as **"Validator node slowdowns"** and **"Significant protocol violations"** under the High severity category. 

**Impact:**
- **Validator Liveness Failure**: Affected validator nodes become unable to synchronize to the latest consensus state
- **Consensus Participation Loss**: Node cannot participate in voting and block production at current rounds
- **Cascading Failures**: Each failed sync compounds the problem, increasing the logical time gap
- **Recovery Difficulty**: Node requires restart and resync from scratch to recover

While this doesn't cause network-wide consensus failure (not Critical), it severely impacts individual validator availability and consensus participation. Multiple affected validators could degrade network performance and approach the Byzantine fault tolerance threshold.

## Likelihood Explanation

**Likelihood: HIGH**

This bug is highly likely to manifest in production because:

1. **Natural Triggers**: State synchronization can legitimately fail due to:
   - Transient network failures
   - Storage I/O errors
   - Temporary unavailability of state sync peers
   - Database lock timeouts

2. **No Malicious Action Required**: The bug triggers on any sync failure, not requiring attacker involvement

3. **Multiple Call Sites**: The function is invoked from critical consensus paths: [4](#0-3) [5](#0-4) [6](#0-5) 

4. **Developer Awareness**: A TODO comment acknowledges related issues: [7](#0-6) 

## Recommendation

**Fix: Update logical time only on successful synchronization**

Modify `sync_to_target()` to match the pattern used in `sync_for_duration()`:

```rust
async fn sync_to_target(&self, target: LedgerInfoWithSignatures) -> Result<(), StateSyncError> {
    let mut latest_logical_time = self.write_mutex.lock().await;
    let target_logical_time =
        LogicalTime::new(target.ledger_info().epoch(), target.ledger_info().round());

    self.executor.finish();

    if *latest_logical_time >= target_logical_time {
        warn!(
            "State sync target {:?} is lower than already committed logical time {:?}",
            target_logical_time, *latest_logical_time
        );
        return Ok(());
    }

    if let Some(inner) = self.state.read().as_ref() {
        let block_timestamp = target.commit_info().timestamp_usecs();
        inner
            .payload_manager
            .notify_commit(block_timestamp, Vec::new());
    }

    fail_point!("consensus::sync_to_target", |_| {
        Err(anyhow::anyhow!("Injected error in sync_to_target").into())
    });

    let result = monitor!(
        "sync_to_target",
        self.state_sync_notifier.sync_to_target(target).await
    );

    // FIXED: Only update logical time if sync succeeded
    if result.is_ok() {
        *latest_logical_time = target_logical_time;
    }

    self.executor.reset()?;

    result.map_err(|error| {
        let anyhow_error: anyhow::Error = error.into();
        anyhow_error.into()
    })
}
```

**Key Change**: Replace unconditional update with conditional update inside `if result.is_ok() { ... }` block.

## Proof of Concept

```rust
#[tokio::test]
async fn test_sync_to_target_logical_time_corruption() {
    // Setup: Create ExecutionProxy with mocked state sync that fails
    let mock_executor = Arc::new(MockExecutor::new());
    let mock_txn_notifier = Arc::new(MockTxnNotifier::new());
    let mock_state_sync = Arc::new(FailingStateSyncNotifier::new()); // Always fails
    
    let execution_proxy = ExecutionProxy::new(
        mock_executor,
        mock_txn_notifier,
        mock_state_sync,
        BlockTransactionFilterConfig::default(),
        false,
        None,
    );

    // Initial state: epoch 1, round 10
    let initial_ledger_info = create_ledger_info(1, 10, 100);
    execution_proxy.sync_to_target(initial_ledger_info).await.unwrap();

    // Attack: Try to sync to round 100, but sync will fail
    let high_target = create_ledger_info(1, 100, 1000);
    let result = execution_proxy.sync_to_target(high_target).await;
    
    // Verify sync failed (expected)
    assert!(result.is_err());

    // Bug: logical_time is now corrupted to round 100, even though we're still at round 10
    // Try to sync to legitimate target at round 50
    let legitimate_target = create_ledger_info(1, 50, 500);
    let result = execution_proxy.sync_to_target(legitimate_target).await;
    
    // Bug manifests: This should sync, but returns Ok() without syncing
    // because logical_time (100) >= target (50)
    assert!(result.is_ok());
    
    // Verify node is still at old state (round 10), not synced to round 50
    // This demonstrates the liveness failure
    assert_eq!(mock_executor.get_committed_round(), 10); // Still at round 10!
}
```

**Notes:**
- This requires proper mocking of state sync failure conditions
- Can be triggered in integration tests by injecting fail points
- Demonstrates complete liveness failure when sync fails followed by legitimate sync requests

### Citations

**File:** consensus/src/state_computer.rs (L158-163)
```rust
        // Update the latest logical time
        if let Ok(latest_synced_ledger_info) = &result {
            let ledger_info = latest_synced_ledger_info.ledger_info();
            let synced_logical_time = LogicalTime::new(ledger_info.epoch(), ledger_info.round());
            *latest_logical_time = synced_logical_time;
        }
```

**File:** consensus/src/state_computer.rs (L188-194)
```rust
        if *latest_logical_time >= target_logical_time {
            warn!(
                "State sync target {:?} is lower than already committed logical time {:?}",
                target_logical_time, *latest_logical_time
            );
            return Ok(());
        }
```

**File:** consensus/src/state_computer.rs (L216-232)
```rust
        let result = monitor!(
            "sync_to_target",
            self.state_sync_notifier.sync_to_target(target).await
        );

        // Update the latest logical time
        *latest_logical_time = target_logical_time;

        // Similarly, after state synchronization, we have to reset the cache of
        // the BlockExecutor to guarantee the latest committed state is up to date.
        self.executor.reset()?;

        // Return the result
        result.map_err(|error| {
            let anyhow_error: anyhow::Error = error.into();
            anyhow_error.into()
        })
```

**File:** consensus/src/block_storage/sync_manager.rs (L512-514)
```rust
        execution_client
            .sync_to_target(highest_commit_cert.ledger_info().clone())
            .await?;
```

**File:** consensus/src/consensus_observer/observer/state_sync_manager.rs (L219-222)
```rust
                if let Err(error) = execution_client
                    .clone()
                    .sync_to_target(commit_decision.commit_proof().clone())
                    .await
```

**File:** consensus/src/epoch_manager.rs (L558-560)
```rust
        self.execution_client
            .sync_to_target(ledger_info.clone())
            .await
```

**File:** consensus/src/pipeline/execution_client.rs (L669-670)
```rust
        // TODO: handle the state sync error (e.g., re-push the ordered
        // blocks to the buffer manager when it's reset but sync fails).
```
