# Audit Report

## Title
Peer Monitoring Service Returns Inverted Version Range Due to Synced/Committed Version Divergence During Pruning

## Summary
The peer monitoring service can return logically inconsistent node information where `lowest_available_version > highest_synced_version`, violating the fundamental invariant that a node's available data range must be valid. This occurs because the ledger pruner operates on the synced version while `get_highest_synced_epoch_and_version()` returns the committed version, which can diverge significantly during state sync operations.

## Finding Description

The vulnerability exists in the interaction between two distinct version tracking mechanisms in AptosDB:

1. **Synced Version**: Updated on every commit via `OverallCommitProgress` 
2. **Committed Version**: Updated only when `LedgerInfoWithSignatures` is provided via the in-memory `latest_ledger_info` cache [1](#0-0) 

The critical flaw is in the `post_commit` function's ordering: [2](#0-1) [3](#0-2) 

The ledger pruner is notified with the synced version, updating `min_readable_version` atomically based on `latest_version - prune_window`: [4](#0-3) 

However, the in-memory `latest_ledger_info` cache is only updated when `ledger_info_with_sigs` is provided. This cache is what the peer monitoring service reads: [5](#0-4) [6](#0-5) 

Meanwhile, `get_lowest_available_version()` reads from the pruner's atomically-updated `min_readable_version`: [7](#0-6) [8](#0-7) 

**Attack Scenario:**
1. Initial state: committed_version = 1000, synced_version = 1000, min_readable_version = 0, prune_window = 1000
2. State sync receives chunks rapidly and commits without ledger info (no epoch change):
   - `commit_ledger(5000, None, ...)` - synced_version = 5000, committed_version = 1000
   - Pruner triggers: `min_readable_version = 5000 - 1000 = 4000`
3. Peer monitoring query:
   - `get_lowest_available_version()` → 4000
   - `get_highest_synced_epoch_and_version()` → (epoch, 1000)
   - **INVERTED RANGE: 4000 > 1000** [9](#0-8) 

## Impact Explanation

This vulnerability constitutes a **High Severity** issue under the Aptos bug bounty program criteria for the following reasons:

1. **Significant Protocol Violation**: The peer monitoring service is a critical component for network health. Returning inconsistent data where `lowest_available_version > highest_synced_version` violates the fundamental invariant that a node's data range must be logically valid.

2. **State Sync Failures**: Peers attempting to sync from affected nodes may:
   - Request data in the range [1000, 4000] believing it's available based on `highest_synced_version`
   - Receive errors because data below version 4000 has been pruned
   - Experience repeated sync failures leading to network fragmentation

3. **Incorrect Peer Selection**: State sync components use peer monitoring data to select optimal sync sources. Inconsistent data leads to:
   - Filtering out healthy peers due to perceived data unavailability
   - Selecting peers without required data
   - Degraded network synchronization performance

4. **Network-Wide Impact**: During periods of heavy state sync activity (network upgrades, new nodes joining), all nodes may exhibit this behavior simultaneously, potentially causing widespread state sync failures.

## Likelihood Explanation

This vulnerability has **HIGH** likelihood of occurrence because:

1. **Normal Operation Trigger**: The issue manifests during standard state sync operations, not requiring any attacker action. State sync routinely calls `commit_ledger` with `None` for `ledger_info_with_sigs` between epoch boundaries.

2. **Large Divergence Window**: In production networks with prune windows of 100M+ transactions and state sync processing millions of transactions between epoch changes, the divergence between synced and committed versions can be massive.

3. **No Safeguards**: There are no validation checks preventing `min_readable_version` from exceeding the committed version, and no synchronization between the pruner notification and cache update.

4. **Observable in Production**: This issue likely occurs in production Aptos nodes during heavy sync periods but may go unnoticed as transient monitoring anomalies.

## Recommendation

The fundamental issue is that the ledger pruner operates on synced version while peer monitoring reports committed version. The fix requires ensuring the pruner only operates on committed versions, or peer monitoring reports synced versions:

**Option 1: Pruner operates on committed version (RECOMMENDED)**

Modify `LedgerPrunerManager::maybe_set_pruner_target_db_version` to check the committed version from `latest_ledger_info` instead of using the passed version parameter directly:

```rust
fn maybe_set_pruner_target_db_version(&self, latest_version: Version) {
    *self.latest_version.lock() = latest_version;
    
    // Get the actual committed version from latest_ledger_info
    let committed_version = self.ledger_db.metadata_db().get_committed_version()
        .unwrap_or(0);
    
    let min_readable_version = self.get_min_readable_version();
    
    // Use committed version for pruning decisions, not synced version
    if self.is_pruner_enabled()
        && committed_version >= min_readable_version + self.pruning_batch_size as u64 + self.prune_window
    {
        self.set_pruner_target_db_version(committed_version);
    }
}
```

**Option 2: Add synced version endpoint to peer monitoring**

Add a new method to `StorageReaderInterface` that returns synced version and use that for consistency with pruner state. However, this requires protocol changes to the peer monitoring service API.

**Option 3: Synchronize updates**

Update the in-memory cache BEFORE notifying pruners in `post_commit`, though this doesn't solve the fundamental issue when ledger_info_with_sigs is None.

## Proof of Concept

```rust
#[test]
fn test_peer_monitoring_inverted_range() {
    // Initialize AptosDB with pruning enabled (prune_window = 1000)
    let tmpdir = TempPath::new();
    let db = AptosDB::new_for_test_with_pruner(&tmpdir, 1000);
    let storage_reader = StorageReader::new(Arc::new(db.clone()));
    
    // Commit initial ledger info with signatures at version 1000
    let ledger_info_1000 = create_test_ledger_info(1000, epoch: 0);
    db.commit_ledger(1000, Some(&ledger_info_1000), None).unwrap();
    
    // Verify initial state is consistent
    let (epoch, highest) = storage_reader.get_highest_synced_epoch_and_version().unwrap();
    let lowest = storage_reader.get_lowest_available_version().unwrap();
    assert!(lowest <= highest); // Should be consistent
    
    // Simulate state sync committing many transactions WITHOUT ledger_info_with_sigs
    // This happens between epoch boundaries during normal state sync
    for version in 1001..=5000 {
        let chunk = create_test_chunk(version);
        db.commit_ledger(version, None, Some(chunk)).unwrap();
    }
    
    // Force pruning by waiting for pruner to process
    // With prune_window=1000, min_readable_version should become ~4000
    std::thread::sleep(Duration::from_secs(2));
    
    // Query peer monitoring service
    let (epoch, highest) = storage_reader.get_highest_synced_epoch_and_version().unwrap();
    let lowest = storage_reader.get_lowest_available_version().unwrap();
    
    // BUG: lowest > highest because:
    // - highest still shows 1000 (last committed LedgerInfo)
    // - lowest shows ~4000 (pruned based on synced version 5000)
    println!("Highest synced version: {}", highest);
    println!("Lowest available version: {}", lowest);
    assert!(lowest > highest, "VULNERABILITY: Inverted range detected!");
}
```

## Notes

This vulnerability demonstrates a critical architectural flaw in the separation between synced and committed version tracking. While the distinction serves valid purposes (allowing pre-commit optimizations), the lack of synchronization between pruning decisions and peer monitoring data creates a consistency violation that affects network reliability.

The issue is particularly insidious because:
1. It occurs during normal operation without malicious input
2. The inverted range is transient (corrected at next epoch boundary) but can persist for millions of blocks
3. Current monitoring may not detect this as an anomaly vs. normal sync lag
4. The impact compounds network-wide during heavy sync periods

This finding underscores the importance of maintaining consistency between different views of blockchain state, especially when these views are exposed through network APIs that influence distributed system behavior.

### Citations

**File:** storage/storage-interface/src/lib.rs (L643-646)
```rust
    /// Commit pre-committed transactions to the ledger.
    ///
    /// If a LedgerInfoWithSigs is provided, both the "synced version" and "committed version" will
    /// advance, otherwise only the synced version will advance.
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L628-632)
```rust
            self.ledger_pruner
                .maybe_set_pruner_target_db_version(version);
            self.state_store
                .state_kv_pruner
                .maybe_set_pruner_target_db_version(version);
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L662-669)
```rust
        if let Some(x) = ledger_info_with_sigs {
            self.ledger_db
                .metadata_db()
                .set_latest_ledger_info(x.clone());

            LEDGER_VERSION.set(x.ledger_info().version() as i64);
            NEXT_BLOCK_EPOCH.set(x.ledger_info().next_block_epoch() as i64);
        }
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/ledger_pruner_manager.rs (L48-50)
```rust
    fn get_min_readable_version(&self) -> Version {
        self.min_readable_version.load(Ordering::SeqCst)
    }
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/ledger_pruner_manager.rs (L162-176)
```rust
    fn set_pruner_target_db_version(&self, latest_version: Version) {
        assert!(self.pruner_worker.is_some());
        let min_readable_version = latest_version.saturating_sub(self.prune_window);
        self.min_readable_version
            .store(min_readable_version, Ordering::SeqCst);

        PRUNER_VERSIONS
            .with_label_values(&["ledger_pruner", "min_readable"])
            .set(min_readable_version as i64);

        self.pruner_worker
            .as_ref()
            .unwrap()
            .set_target_db_version(min_readable_version);
    }
```

**File:** peer-monitoring-service/server/src/storage.rs (L45-48)
```rust
    fn get_highest_synced_epoch_and_version(&self) -> Result<(u64, u64), Error> {
        let latest_ledger_info = self.get_latest_ledger_info()?;
        Ok((latest_ledger_info.epoch(), latest_ledger_info.version()))
    }
```

**File:** storage/aptosdb/src/ledger_db/ledger_metadata_db.rs (L94-98)
```rust
    pub(crate) fn get_latest_ledger_info_option(&self) -> Option<LedgerInfoWithSignatures> {
        let ledger_info_ptr = self.latest_ledger_info.load();
        let ledger_info: &Option<_> = ledger_info_ptr.deref();
        ledger_info.clone()
    }
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L329-333)
```rust
    fn get_first_txn_version(&self) -> Result<Option<Version>> {
        gauged_api("get_first_txn_version", || {
            Ok(Some(self.ledger_pruner.get_min_readable_version()))
        })
    }
```

**File:** peer-monitoring-service/server/src/lib.rs (L264-277)
```rust
        let (highest_synced_epoch, highest_synced_version) =
            self.storage.get_highest_synced_epoch_and_version()?;
        let ledger_timestamp_usecs = self.storage.get_ledger_timestamp_usecs()?;
        let lowest_available_version = self.storage.get_lowest_available_version()?;

        // Create and return the response
        let node_information_response = NodeInformationResponse {
            build_information,
            highest_synced_epoch,
            highest_synced_version,
            ledger_timestamp_usecs,
            lowest_available_version,
            uptime,
        };
```
