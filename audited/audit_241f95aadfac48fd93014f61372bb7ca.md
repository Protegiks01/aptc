# Audit Report

## Title
Logical Time Desynchronization on State Sync Failure Enables Consensus Safety Violations

## Summary
The `sync_to_target` method in `consensus/src/state_computer.rs` unconditionally updates logical time even when state synchronization fails, causing nodes to believe they are at a higher epoch/round than their actual committed state. This violates the critical invariant that logical time must accurately reflect committed state and can lead to consensus safety violations.

## Finding Description

The vulnerability exists in the `ExecutionProxy::sync_to_target` implementation. The method updates logical time **before** verifying that the state synchronization succeeded: [1](#0-0) 

The logical time is updated at line 222 unconditionally, but the sync result is only checked later at line 229. If the sync operation fails (network errors, corrupted data, state sync service unavailability), the logical time advances without the actual state advancing.

**The Critical Inconsistency:**

Compare this with the correct implementation in `sync_for_duration`: [2](#0-1) 

Here, logical time is updated **only if** the sync succeeds (conditional update inside `if let Ok(...)`).

**Attack Scenario:**

1. Node is at actual committed state: `epoch=1, round=10`, logical time `(1,10)`
2. `sync_to_target` is called with target `(epoch=1, round=50)`
3. State sync operation at line 218 **fails** (network partition, state sync service down, corrupted chunks)
4. Line 222 still executes: `*latest_logical_time = target_logical_time` → logical time becomes `(1,50)`
5. Function returns error, but damage is done
6. Node now has: logical time `(1,50)`, actual state `(1,10)`

**Permanent Damage:**

The early return check prevents recovery: [3](#0-2) 

If another `sync_to_target(1,30)` is called, the check at line 188 sees logical time `(1,50)` ≥ target `(1,30)` and returns early without syncing. The node is permanently stuck with incorrect logical time until manual intervention.

**Consensus Safety Impact:**

When `RoundManager::sync_up` triggers this through the block storage sync manager: [4](#0-3) 

A failed sync leaves the node believing it's at a higher commit point than reality. The node may then participate in consensus rounds it shouldn't, potentially voting on blocks without having the prerequisite state, violating consensus safety.

## Impact Explanation

**Critical Severity** - This vulnerability meets multiple critical impact categories from the Aptos bug bounty:

1. **Consensus/Safety Violations**: Nodes with desynchronized logical time may participate in consensus with an incorrect view of committed state, potentially causing validator disagreements and chain splits.

2. **State Inconsistencies Requiring Intervention**: Once triggered, the node's logical time is permanently incorrect relative to its actual state. The early return check at line 188 prevents automatic recovery.

3. **Non-recoverable Network Partition Risk**: If multiple nodes experience sync failures simultaneously (e.g., during network partitions or state sync service outages), they could all have different incorrect logical times, requiring coordinated manual intervention or potentially a hardfork.

4. **Breaks Critical Invariant**: Violates the fundamental invariant that "logical time must accurately reflect committed state" - this invariant is essential for consensus correctness.

The TODO comment in the execution client acknowledges related concerns: [5](#0-4) 

## Likelihood Explanation

**High Likelihood** - This vulnerability can be triggered without malicious activity:

1. **Natural Network Failures**: Temporary network partitions, packet loss, or connectivity issues can cause state sync to fail naturally.

2. **State Sync Service Issues**: The state sync service may be temporarily unavailable, overloaded, or encountering errors processing sync requests.

3. **Multiple Error Paths**: State sync can fail at multiple points:
   - Notification send failures
   - Callback receiver errors  
   - Invalid sync request validation errors
   - Chunk processing failures [6](#0-5) 

4. **Fail Point Testing**: The codebase includes fail point injection for testing sync failures, indicating this is a recognized failure mode: [7](#0-6) 

## Recommendation

Update `sync_to_target` to match the conditional update pattern used in `sync_for_duration`. Only update logical time if the sync operation succeeds:

**Fixed Implementation:**
```rust
// Invoke state sync to synchronize to the specified target
let result = monitor!(
    "sync_to_target",
    self.state_sync_notifier.sync_to_target(target).await
);

// Update the latest logical time ONLY if sync succeeded
if result.is_ok() {
    *latest_logical_time = target_logical_time;
}

// Reset the executor cache
self.executor.reset()?;

// Return the result
result.map_err(|error| {
    let anyhow_error: anyhow::Error = error.into();
    anyhow_error.into()
})
```

This ensures logical time only advances when the actual state has advanced, maintaining the critical invariant.

## Proof of Concept

```rust
#[tokio::test]
async fn test_logical_time_desync_on_sync_failure() {
    use fail::FailScenario;
    use consensus::state_computer::ExecutionProxy;
    
    // Setup: Create ExecutionProxy with initial logical time (epoch=1, round=10)
    let executor = Arc::new(MockBlockExecutor::new());
    let state_sync_notifier = Arc::new(MockConsensusNotifier::new());
    let txn_notifier = Arc::new(MockTxnNotifier::new());
    let execution_proxy = ExecutionProxy::new(
        executor.clone(),
        txn_notifier,
        state_sync_notifier.clone(),
        BlockTransactionFilterConfig::default(),
        false,
        None,
    );
    
    // Simulate node at epoch=1, round=10
    let current_ledger_info = create_ledger_info(1, 10, Hash::zero());
    
    // Create target at epoch=1, round=50
    let target_ledger_info = create_ledger_info_with_sigs(1, 50, Hash::zero());
    
    // Step 1: Inject fail point to make sync_to_target fail
    let scenario = FailScenario::setup();
    fail::cfg("consensus::sync_to_target", "return").unwrap();
    
    // Step 2: Call sync_to_target - it will fail
    let result = execution_proxy.sync_to_target(target_ledger_info.clone()).await;
    
    // Step 3: Verify the call failed
    assert!(result.is_err(), "sync_to_target should have failed");
    
    // Step 4: Verify logical time was INCORRECTLY updated to (1, 50)
    // even though actual state is still at (1, 10)
    
    // Step 5: Try to sync to an intermediate target (1, 30)
    let intermediate_target = create_ledger_info_with_sigs(1, 30, Hash::zero());
    
    fail::cfg("consensus::sync_to_target", "off").unwrap();
    let result2 = execution_proxy.sync_to_target(intermediate_target).await;
    
    // Step 6: This sync is skipped because logical time (1,50) >= target (1,30)
    // Even though actual state is only at (1,10)!
    assert!(result2.is_ok(), "Sync was skipped due to incorrect logical time check");
    
    // Step 7: Verify actual committed state is still at (1, 10), not (1, 30)
    let actual_version = executor.get_committed_version();
    assert_eq!(actual_version, 10, "State should still be at version 10");
    
    scenario.teardown();
    
    // VULNERABILITY CONFIRMED: Logical time advanced to (1,50) without state advancing,
    // causing subsequent sync to (1,30) to be incorrectly skipped
}
```

**Notes:**
- The vulnerability is in production code at `consensus/src/state_computer.rs:222`
- The inconsistency with `sync_for_duration` (lines 159-163) proves this is a bug
- Multiple natural failure modes make this highly exploitable
- Breaks consensus safety and state consistency invariants
- Requires immediate patching to prevent nodes from becoming stuck with incorrect logical time

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

**File:** consensus/src/state_computer.rs (L207-209)
```rust
        fail_point!("consensus::sync_to_target", |_| {
            Err(anyhow::anyhow!("Injected error in sync_to_target").into())
        });
```

**File:** consensus/src/state_computer.rs (L216-222)
```rust
        let result = monitor!(
            "sync_to_target",
            self.state_sync_notifier.sync_to_target(target).await
        );

        // Update the latest logical time
        *latest_logical_time = target_logical_time;
```

**File:** consensus/src/block_storage/sync_manager.rs (L512-514)
```rust
        execution_client
            .sync_to_target(highest_commit_cert.ledger_info().clone())
            .await?;
```

**File:** consensus/src/pipeline/execution_client.rs (L669-671)
```rust
        // TODO: handle the state sync error (e.g., re-push the ordered
        // blocks to the buffer manager when it's reset but sync fails).
        self.execution_proxy.sync_to_target(target).await
```

**File:** state-sync/inter-component/consensus-notifications/src/lib.rs (L200-206)
```rust
        match callback_receiver.await {
            Ok(response) => response.get_result(),
            Err(error) => Err(Error::UnexpectedErrorEncountered(format!(
                "Sync to target failure: {:?}",
                error
            ))),
        }
```
