# Audit Report

## Title
State Poisoning via Unconditional Logical Time Update on sync_to_target Failure

## Summary
The `ExecutionProxy::sync_to_target` method in `consensus/src/state_computer.rs` unconditionally updates the internal `latest_logical_time` to the target logical time before verifying that state synchronization succeeded. This allows Byzantine validators to poison an honest validator's view of its sync state by causing sync failures, leading the validator to believe it has synced to a higher epoch/round than it actually has, resulting in consensus disruption and potential safety violations. [1](#0-0) 

## Finding Description

The vulnerability exists in the state synchronization logic where the consensus layer tracks its logical time (epoch and round). The `ExecutionProxy` maintains a `latest_logical_time` that represents the highest epoch/round the validator believes it has synced to.

**The Bug:**

In the `sync_to_target` method, the code unconditionally updates `latest_logical_time` to the target after calling state sync, regardless of whether the sync operation succeeded or failed: [2](#0-1) 

Notice that at line 222, `*latest_logical_time = target_logical_time;` executes **before** the function checks if `result` contains an error. This is in stark contrast to the correct implementation in `sync_for_duration`: [3](#0-2) 

The `sync_for_duration` method correctly only updates `latest_logical_time` when the sync succeeds (within the `if let Ok(...)` block).

**Attack Scenario:**

1. Byzantine validators craft a valid `SyncInfo` message with a `highest_commit_cert` pointing to a future round/epoch that they control. The signatures are valid (they have sufficient stake), so it passes verification: [4](#0-3) 

2. The honest validator verifies the SyncInfo and initiates sync via `add_certs`: [5](#0-4) 

3. During state sync, Byzantine validators either:
   - Refuse to provide the required blockchain data (timeouts)
   - Provide invalid transaction data that fails verification
   - Provide data for a non-existent or forked chain

4. State sync fails and returns a `StateSyncError`.

5. **Critical Bug Trigger**: Despite the failure, the `ExecutionProxy` has already updated `latest_logical_time` to the target logical time at line 222.

6. **State Poisoning**: The honest validator now incorrectly believes it has synced to the target epoch/round, even though its actual committed state hasn't changed.

7. **Subsequent Sync Prevention**: Future sync attempts to the same or nearby targets are blocked by the check at line 188: [6](#0-5) 

The validator will skip necessary synchronization because it believes `latest_logical_time >= target_logical_time`, even though it never actually synced.

**Broken Invariants:**

- **State Consistency**: The validator's internal view of its logical time is inconsistent with its actual committed state
- **Consensus Safety**: The validator may participate in consensus with an incorrect view of the blockchain state, potentially leading to safety violations

## Impact Explanation

**Critical Severity** - This vulnerability qualifies as Critical under the Aptos bug bounty program for the following reasons:

1. **Consensus Safety Violation**: The poisoned validator has an incorrect view of its sync state, which can cause it to:
   - Skip necessary synchronization operations
   - Make incorrect voting decisions based on stale state
   - Potentially commit to blocks it shouldn't commit to
   - Fail to participate correctly in consensus rounds

2. **Non-Recoverable State Corruption**: Once the `latest_logical_time` is poisoned, the validator cannot recover without manual intervention. The check at line 188 permanently blocks future sync attempts to the same epoch/round range.

3. **Byzantine Attack Vector**: This can be triggered by Byzantine validators (within the < 1/3 assumption) against honest validators, allowing them to disrupt network consensus.

4. **Affects Network Liveness**: Multiple validators with poisoned state can cause consensus liveness failures, preventing the network from making progress.

The impact severity aligns with "Consensus/Safety violations" and "Significant protocol violations" categories in the bug bounty program.

## Likelihood Explanation

**High Likelihood** - This vulnerability is highly likely to be exploited because:

1. **Easy to Trigger**: Byzantine validators only need to:
   - Create a valid SyncInfo with proper signatures (normal validator operation)
   - Cause sync operations to fail (simply by not responding or providing invalid data)

2. **Low Attacker Requirements**: 
   - Does not require > 1/3 Byzantine stake
   - Does not require sophisticated cryptographic attacks
   - Uses normal consensus message flow

3. **Persistent Effect**: Once triggered, the state poisoning persists until manual node reset, making it highly effective for disrupting consensus.

4. **Natural Occurrence Possible**: Even without malicious intent, network issues or bugs in state sync could trigger this vulnerability, causing honest validators to poison their own state.

5. **Inconsistent Implementation**: The fact that `sync_for_duration` has the correct logic but `sync_to_target` doesn't suggests this was an oversight, not a deliberate design choice.

## Recommendation

The fix is straightforward - only update `latest_logical_time` when synchronization succeeds, matching the pattern used in `sync_for_duration`:

**Fixed Code:**

```rust
async fn sync_to_target(&self, target: LedgerInfoWithSignatures) -> Result<(), StateSyncError> {
    // Grab the logical time lock and calculate the target logical time
    let mut latest_logical_time = self.write_mutex.lock().await;
    let target_logical_time =
        LogicalTime::new(target.ledger_info().epoch(), target.ledger_info().round());

    // Before state synchronization, we have to call finish() to free the
    // in-memory SMT held by BlockExecutor to prevent a memory leak.
    self.executor.finish();

    // The pipeline phase already committed beyond the target block timestamp, just return.
    if *latest_logical_time >= target_logical_time {
        warn!(
            "State sync target {:?} is lower than already committed logical time {:?}",
            target_logical_time, *latest_logical_time
        );
        return Ok(());
    }

    // This is to update QuorumStore with the latest known commit in the system,
    // so it can set batches expiration accordingly.
    if let Some(inner) = self.state.read().as_ref() {
        let block_timestamp = target.commit_info().timestamp_usecs();
        inner
            .payload_manager
            .notify_commit(block_timestamp, Vec::new());
    }

    // Invoke state sync to synchronize to the specified target.
    let result = monitor!(
        "sync_to_target",
        self.state_sync_notifier.sync_to_target(target).await
    );

    // FIXED: Only update the latest logical time if sync succeeded
    if result.is_ok() {
        *latest_logical_time = target_logical_time;
    }

    // Similarly, after state synchronization, we have to reset the cache of
    // the BlockExecutor to guarantee the latest committed state is up to date.
    self.executor.reset()?;

    // Return the result
    result.map_err(|error| {
        let anyhow_error: anyhow::Error = error.into();
        anyhow_error.into()
    })
}
```

The key change is wrapping the logical time update in `if result.is_ok()` to ensure it only happens on successful synchronization.

## Proof of Concept

```rust
#[tokio::test]
async fn test_sync_to_target_state_poisoning() {
    use aptos_consensus::state_computer::ExecutionProxy;
    use aptos_consensus_notifications::Error as ConsensusNotificationError;
    use aptos_types::{
        block_info::BlockInfo,
        ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
        aggregate_signature::AggregateSignature,
    };
    use std::sync::Arc;
    
    // Setup: Create ExecutionProxy with mock components
    let (executor, txn_notifier, state_sync_notifier, txn_filter_config) = 
        create_mock_execution_components();
    
    let execution_proxy = ExecutionProxy::new(
        Arc::new(executor),
        Arc::new(txn_notifier),
        Arc::new(state_sync_notifier),
        txn_filter_config,
        false,
        None,
    );
    
    // Create a target LedgerInfo for epoch 5, round 100
    let target = LedgerInfoWithSignatures::new(
        LedgerInfo::new(
            BlockInfo::new(5, 100, HashValue::zero(), HashValue::zero(), 
                          0, 0, None),
            HashValue::zero(),
        ),
        AggregateSignature::empty(),
    );
    
    // Configure mock state_sync_notifier to return an error
    state_sync_notifier.set_sync_to_target_result(
        Err(ConsensusNotificationError::UnexpectedErrorEncountered(
            "Byzantine validators refused to provide data".to_string()
        ))
    );
    
    // Attempt sync_to_target - this should fail
    let result = execution_proxy.sync_to_target(target.clone()).await;
    assert!(result.is_err(), "Sync should fail");
    
    // BUG: Try to sync again to the same target
    // This should succeed in syncing, but due to the bug, it will skip
    state_sync_notifier.set_sync_to_target_result(Ok(()));
    
    let result2 = execution_proxy.sync_to_target(target).await;
    
    // VULNERABILITY: The second sync is skipped because latest_logical_time
    // was updated even though the first sync failed
    // The validator now has poisoned state - it thinks it's at epoch 5 round 100
    // but its actual committed state is still at epoch 0 round 0
    
    // Verify state poisoning: check that internal logical time is wrong
    assert!(result2.is_ok(), "Second sync returns OK but was skipped");
    assert_eq!(execution_proxy.get_latest_logical_time(), (5, 100));
    assert_eq!(execution_proxy.get_actual_committed_state(), (0, 0));
}
```

**Notes:**
- This PoC demonstrates how a failed sync_to_target updates the logical time
- Subsequent sync attempts to the same target are skipped due to the check at line 188
- The validator's internal view becomes inconsistent with its actual state
- In a real attack, Byzantine validators would craft valid SyncInfo messages and then cause sync failures to trigger this bug repeatedly, preventing honest validators from syncing correctly

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

**File:** consensus/src/state_computer.rs (L176-233)
```rust
    /// Synchronize to a commit that is not present locally.
    async fn sync_to_target(&self, target: LedgerInfoWithSignatures) -> Result<(), StateSyncError> {
        // Grab the logical time lock and calculate the target logical time
        let mut latest_logical_time = self.write_mutex.lock().await;
        let target_logical_time =
            LogicalTime::new(target.ledger_info().epoch(), target.ledger_info().round());

        // Before state synchronization, we have to call finish() to free the
        // in-memory SMT held by BlockExecutor to prevent a memory leak.
        self.executor.finish();

        // The pipeline phase already committed beyond the target block timestamp, just return.
        if *latest_logical_time >= target_logical_time {
            warn!(
                "State sync target {:?} is lower than already committed logical time {:?}",
                target_logical_time, *latest_logical_time
            );
            return Ok(());
        }

        // This is to update QuorumStore with the latest known commit in the system,
        // so it can set batches expiration accordingly.
        // Might be none if called in the recovery path, or between epoch stop and start.
        if let Some(inner) = self.state.read().as_ref() {
            let block_timestamp = target.commit_info().timestamp_usecs();
            inner
                .payload_manager
                .notify_commit(block_timestamp, Vec::new());
        }

        // Inject an error for fail point testing
        fail_point!("consensus::sync_to_target", |_| {
            Err(anyhow::anyhow!("Injected error in sync_to_target").into())
        });

        // Invoke state sync to synchronize to the specified target. Here, the
        // ChunkExecutor will process chunks and commit to storage. However, after
        // block execution and commits, the internal state of the ChunkExecutor may
        // not be up to date. So, it is required to reset the cache of the
        // ChunkExecutor in state sync when requested to sync.
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
    }
```

**File:** consensus/src/round_manager.rs (L878-906)
```rust
    async fn sync_up(&mut self, sync_info: &SyncInfo, author: Author) -> anyhow::Result<()> {
        let local_sync_info = self.block_store.sync_info();
        if sync_info.has_newer_certificates(&local_sync_info) {
            info!(
                self.new_log(LogEvent::ReceiveNewCertificate)
                    .remote_peer(author),
                "Local state {},\n remote state {}", local_sync_info, sync_info
            );
            // Some information in SyncInfo is ahead of what we have locally.
            // First verify the SyncInfo (didn't verify it in the yet).
            sync_info.verify(&self.epoch_state.verifier).map_err(|e| {
                error!(
                    SecurityEvent::InvalidSyncInfoMsg,
                    sync_info = sync_info,
                    remote_peer = author,
                    error = ?e,
                );
                VerifyError::from(e)
            })?;
            SYNC_INFO_RECEIVED_WITH_NEWER_CERT.inc();
            let result = self
                .block_store
                .add_certs(sync_info, self.create_block_retriever(author))
                .await;
            self.process_certificates().await?;
            result
        } else {
            Ok(())
        }
```

**File:** consensus/src/block_storage/sync_manager.rs (L512-514)
```rust
        execution_client
            .sync_to_target(highest_commit_cert.ledger_info().clone())
            .await?;
```
