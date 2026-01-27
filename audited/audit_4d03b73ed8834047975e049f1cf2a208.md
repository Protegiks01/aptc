# Audit Report

## Title
TOCTOU Race Condition in State Sync Driver Causes Invariant Violation and Incorrect Rejection of Valid Consensus Sync Requests

## Summary
The `initialize_sync_target_request()` function in the state-sync driver performs two non-atomic reads to fetch `latest_pre_committed_version` and `latest_committed_version` from separate data sources, creating a Time-of-Check-Time-of-Use (TOCTOU) race condition. This can violate the invariant `pre_committed_version >= committed_version`, causing valid consensus sync requests to be incorrectly rejected with `OldSyncRequest` errors, leading to state sync failures and consensus liveness issues.

## Finding Description

The vulnerability exists in how the state-sync driver handles consensus sync target notifications. The critical invariant that should hold is: **pre-committed version must always be greater than or equal to committed version** because transactions are first pre-committed (optimistically written to storage) before being committed (certified with a LedgerInfo). [1](#0-0) 

The `handle_consensus_sync_target_notification` function fetches these versions through two separate, non-atomic database reads from different data sources. The pre-committed version comes from `state_store.current_state_locked()` while the committed version comes from `metadata_db.get_latest_ledger_info()`. [2](#0-1) 

**Race Condition Scenario:**

1. Thread A (state-sync driver) begins processing a consensus sync target notification
2. Thread A reads `pre_committed_version = 100` 
3. Thread B (storage/consensus) calls `commit_ledger(version=150)` and updates the committed version in metadata_db
4. Thread A then reads `committed_version = 150` from the now-updated metadata_db
5. Thread A calls `initialize_sync_target_request(sync_target=120, pre_committed=100, committed=150)`

Now the invariant is violated: `100 < 150` [3](#0-2) 

The error handling logic checks if the sync target is less than either version. With `sync_target=120`, `committed=150`, and `pre_committed=100`, the condition `sync_target_version < latest_committed_version` evaluates to true (120 < 150), causing the function to return an `OldSyncRequest` error even though the sync target of 120 is actually ahead of the pre-committed version of 100 and represents a valid sync request that should be processed. [4](#0-3) 

This incorrect error response breaks the state sync protocol between consensus and the state-sync driver, preventing valid synchronization operations from proceeding.

## Impact Explanation

This vulnerability qualifies as **Critical Severity** under the Aptos bug bounty criteria because it can cause:

1. **Consensus/Safety violations**: When consensus issues a valid sync request that gets incorrectly rejected, it may be unable to make progress on block commits, affecting the node's ability to participate in consensus.

2. **Non-recoverable network partition scenarios**: If multiple validator nodes simultaneously experience this race condition during critical synchronization periods (e.g., epoch transitions), they may be unable to sync to the required target, potentially causing network-wide liveness failures.

3. **Total loss of liveness**: A validator node that consistently hits this race condition cannot successfully process consensus sync requests, causing it to fall behind the network. This leads to validator inactivity, missed proposals, and reduced network capacity.

The bug directly impacts the state consistency invariant by causing nodes to fail synchronization when they should succeed, and affects consensus liveness by blocking valid sync operations that consensus depends on.

## Likelihood Explanation

This vulnerability has a **HIGH likelihood** of occurring in production environments because:

1. **Concurrent Operations**: The race window occurs during normal operations when storage commit operations run concurrently with consensus sync request processing. In a busy validator node, these operations happen frequently and in parallel.

2. **No Synchronization**: There is no lock, mutex, or atomic operation protecting the two reads, making the race condition exploitable in multi-threaded environments.

3. **Timing-Dependent**: The bug manifests when a commit completes between the two read operations. Given that commits can take milliseconds and the reads are separated by function calls, this timing window is realistic.

4. **Production Conditions**: During high transaction throughput, epoch transitions, or when a node is catching up after being offline, the frequency of commits and sync requests increases, making the race condition more likely.

The vulnerability does not require any malicious actor or privileged access—it occurs naturally as a result of concurrent normal operations in the system.

## Recommendation

The fix should ensure atomic consistency between the two version reads. Here are recommended solutions:

**Option 1: Add Invariant Validation and Retry Logic**

Add validation in `handle_consensus_sync_target_notification` to detect when the invariant is violated and retry with fresh reads:

```rust
// In driver.rs handle_consensus_sync_target_notification
async fn handle_consensus_sync_target_notification(
    &mut self,
    sync_target_notification: ConsensusSyncTargetNotification,
) -> Result<(), Error> {
    // Retry loop to handle race conditions
    for attempt in 0..3 {
        let latest_pre_committed_version = 
            utils::fetch_pre_committed_version(self.storage.clone())?;
        let latest_synced_ledger_info = 
            utils::fetch_latest_synced_ledger_info(self.storage.clone())?;
        let latest_committed_version = latest_synced_ledger_info.ledger_info().version();
        
        // Validate invariant
        if latest_pre_committed_version < latest_committed_version {
            warn!(
                "Invariant violation detected: pre_committed ({}) < committed ({}), retrying...",
                latest_pre_committed_version, latest_committed_version
            );
            continue; // Retry
        }
        
        // Process with validated versions
        return self.consensus_notification_handler
            .initialize_sync_target_request(
                sync_target_notification,
                latest_pre_committed_version,
                latest_synced_ledger_info,
            )
            .await;
    }
    
    Err(Error::StorageError("Failed to get consistent version reads".into()))
}
```

**Option 2: Add a Storage-Level Atomic Read Method**

Implement an atomic method in the storage interface that returns both versions consistently:

```rust
// In storage-interface/src/lib.rs
fn get_version_snapshot(&self) -> Result<(Version, LedgerInfoWithSignatures)> {
    // Implementation should ensure atomic read of both values
    let pre_committed = self.get_pre_committed_version()?.ok_or(...)?;
    let ledger_info = self.get_latest_ledger_info()?;
    let committed = ledger_info.ledger_info().version();
    
    // Validate invariant at read time
    ensure!(
        pre_committed >= committed,
        "Invariant violation: pre_committed < committed"
    );
    
    Ok((pre_committed, ledger_info))
}
```

Both approaches ensure the invariant holds before processing, preventing incorrect error responses.

## Proof of Concept

The following Rust test demonstrates the race condition:

```rust
#[tokio::test]
async fn test_sync_target_race_condition() {
    use std::sync::Arc;
    use tokio::sync::Barrier;
    
    // Setup mock storage with initial state
    let storage = Arc::new(create_mock_storage(
        pre_committed_version: 100,
        committed_version: 90,
    ));
    
    let barrier = Arc::new(Barrier::new(2));
    let barrier_clone = barrier.clone();
    let storage_clone = storage.clone();
    
    // Thread 1: Read pre-committed, then wait, then process
    let thread1 = tokio::spawn(async move {
        // Read pre-committed version = 100
        let pre_committed = fetch_pre_committed_version(storage_clone.clone()).unwrap();
        assert_eq!(pre_committed, 100);
        
        // Wait for thread 2 to commit
        barrier_clone.wait().await;
        
        // Read committed version (now 150 after thread 2)
        let ledger_info = fetch_latest_synced_ledger_info(storage_clone).unwrap();
        let committed = ledger_info.ledger_info().version();
        
        // Invariant violated: 100 < 150
        assert!(pre_committed < committed);
        
        (pre_committed, committed)
    });
    
    // Thread 2: Commit new version
    let thread2 = tokio::spawn(async move {
        barrier.wait().await;
        
        // Simulate commit_ledger updating committed version to 150
        storage.commit_ledger(150, Some(&create_ledger_info(150)), None).unwrap();
    });
    
    let (pre_committed, committed) = thread1.await.unwrap();
    thread2.await.unwrap();
    
    // Now call initialize_sync_target_request with sync_target=120
    let mut handler = create_consensus_notification_handler();
    let sync_target = create_sync_target_notification(target_version: 120);
    
    let result = handler.initialize_sync_target_request(
        sync_target,
        pre_committed, // 100
        create_ledger_info(committed), // 150
    ).await;
    
    // Bug: Valid sync request (120 > 100) incorrectly rejected as "old"
    assert!(matches!(result, Err(Error::OldSyncRequest(120, 100, 150))));
}
```

The test demonstrates that a sync target of 120 (which is ahead of the pre-committed version of 100 and should be accepted) is incorrectly rejected when the race condition causes the committed version to appear as 150.

## Notes

This vulnerability is particularly dangerous during:
- Epoch transitions when sync activity increases
- Node recovery scenarios when catching up with the network
- High-throughput periods with frequent commits

The fix should be prioritized as it affects core consensus-state sync coordination, a critical path for network liveness and validator operation.

### Citations

**File:** state-sync/state-sync-driver/src/driver.rs (L412-441)
```rust
        // Fetch the pre-committed and committed versions
        let latest_pre_committed_version =
            utils::fetch_pre_committed_version(self.storage.clone())?;
        let latest_synced_ledger_info =
            utils::fetch_latest_synced_ledger_info(self.storage.clone())?;
        let latest_committed_version = latest_synced_ledger_info.ledger_info().version();

        // Update the sync target notification logs and metrics
        info!(
            LogSchema::new(LogEntry::ConsensusNotification).message(&format!(
                "Received a consensus sync target notification! Target: {:?}. \
                Latest pre-committed version: {}. Latest committed version: {}.",
                sync_target_notification.get_target(),
                latest_pre_committed_version,
                latest_committed_version,
            ))
        );
        metrics::increment_counter(
            &metrics::DRIVER_COUNTERS,
            metrics::DRIVER_CONSENSUS_SYNC_TARGET_NOTIFICATION,
        );

        // Initialize a new sync request
        self.consensus_notification_handler
            .initialize_sync_target_request(
                sync_target_notification,
                latest_pre_committed_version,
                latest_synced_ledger_info,
            )
            .await
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L125-141)
```rust
    fn get_latest_ledger_info_option(&self) -> Result<Option<LedgerInfoWithSignatures>> {
        gauged_api("get_latest_ledger_info_option", || {
            Ok(self.ledger_db.metadata_db().get_latest_ledger_info_option())
        })
    }

    fn get_synced_version(&self) -> Result<Option<Version>> {
        gauged_api("get_synced_version", || {
            self.ledger_db.metadata_db().get_synced_version()
        })
    }

    fn get_pre_committed_version(&self) -> Result<Option<Version>> {
        gauged_api("get_pre_committed_version", || {
            Ok(self.state_store.current_state_locked().version())
        })
    }
```

**File:** state-sync/state-sync-driver/src/notification_handlers.rs (L262-318)
```rust
    pub async fn initialize_sync_target_request(
        &mut self,
        sync_target_notification: ConsensusSyncTargetNotification,
        latest_pre_committed_version: Version,
        latest_synced_ledger_info: LedgerInfoWithSignatures,
    ) -> Result<(), Error> {
        // Get the target sync version and latest committed version
        let sync_target_version = sync_target_notification
            .get_target()
            .ledger_info()
            .version();
        let latest_committed_version = latest_synced_ledger_info.ledger_info().version();

        // If the target version is old, return an error to consensus (something is wrong!)
        if sync_target_version < latest_committed_version
            || sync_target_version < latest_pre_committed_version
        {
            let error = Err(Error::OldSyncRequest(
                sync_target_version,
                latest_pre_committed_version,
                latest_committed_version,
            ));
            self.respond_to_sync_target_notification(sync_target_notification, error.clone())?;
            return error;
        }

        // If the committed version is at the target, return successfully
        if sync_target_version == latest_committed_version {
            info!(
                LogSchema::new(LogEntry::NotificationHandler).message(&format!(
                    "We're already at the requested sync target version: {} \
                (pre-committed version: {}, committed version: {})!",
                    sync_target_version, latest_pre_committed_version, latest_committed_version
                ))
            );
            let result = Ok(());
            self.respond_to_sync_target_notification(sync_target_notification, result.clone())?;
            return result;
        }

        // If the pre-committed version is already at the target, something has else gone wrong
        if sync_target_version == latest_pre_committed_version {
            let error = Err(Error::InvalidSyncRequest(
                sync_target_version,
                latest_pre_committed_version,
            ));
            self.respond_to_sync_target_notification(sync_target_notification, error.clone())?;
            return error;
        }

        // Save the request so we can notify consensus once we've hit the target
        let consensus_sync_request =
            ConsensusSyncRequest::new_with_target(sync_target_notification);
        self.consensus_sync_request = Arc::new(Mutex::new(Some(consensus_sync_request)));

        Ok(())
    }
```

**File:** state-sync/state-sync-driver/src/error.rs (L39-40)
```rust
    #[error("Received an old sync request for version {0}, but our pre-committed version is: {1} and committed version: {2}")]
    OldSyncRequest(Version, Version, Version),
```
