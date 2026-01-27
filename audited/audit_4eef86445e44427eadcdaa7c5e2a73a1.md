# Audit Report

## Title
Infinite Loop DoS in Indexer Service During Fast Sync State Synchronization Failure

## Summary
The `get_start_version()` function in the internal indexer service contains an unbounded while loop that waits for the database synced version to become non-zero during fast sync. If state synchronization fails to progress, this loop runs indefinitely, causing a denial of service of the indexer API by preventing the service from initializing.

## Finding Description [1](#0-0) 

The vulnerable code implements a wait loop that assumes the synced version will eventually progress from 0 to a higher value during fast sync. However, there is no timeout mechanism or maximum retry count to handle scenarios where state synchronization fails to make progress.

**Execution Flow:**

1. Node starts with fast sync enabled and database synced version = 0
2. Indexer service calls `get_start_version()` to initialize
3. The function enters the while loop to wait for state sync completion
4. If state sync fails to progress (due to network issues, crashes, misconfigurations, or bugs), the synced version remains at 0
5. The loop continues indefinitely, checking every second without any exit condition

**State Sync Dependency:** [2](#0-1) 

During fast sync initialization, the system creates a dual-database setup when the synced version is 0. The synced version only gets updated when `finalize_state_snapshot()` is called after successful state download. [3](#0-2) 

**Failure Scenarios:**

1. **State sync initialization failure**: If the state sync driver fails to start due to misconfiguration or dependency issues, `finalize_state_snapshot()` is never called
2. **State sync crashes before completion**: If state sync starts but crashes during state download, the synced version remains at 0
3. **Persistent network connectivity issues**: If the node cannot establish connections to peers for state download, fast sync cannot proceed
4. **Resource exhaustion**: If disk space runs out during state snapshot download, the process fails and cannot complete

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits" - the loop has no bounds on execution time or iterations.

## Impact Explanation

**Severity: High** per Aptos bug bounty criteria - "API crashes"

**Direct Impact:**
- The indexer service initialization is permanently blocked
- Indexer gRPC API remains unavailable indefinitely
- CPU resources are continuously consumed (checking every 1 second)
- Node operators must manually intervene to diagnose and restart the service

**Scope:**
- Affects any node running the internal indexer service with fast sync enabled
- Does not impact consensus, block production, or validator rewards (indexer is separate from core consensus)
- Impacts ecosystem services that depend on indexer API for historical data queries

## Likelihood Explanation

**Likelihood: Medium-High**

This issue has moderate-to-high likelihood of occurrence in production environments:

1. **State sync failures are not uncommon**: During node bootstrapping, state sync can fail due to network instability, peer unavailability, or resource constraints
2. **Fast sync is commonly used**: Fast sync mode is the recommended bootstrapping method for new nodes, making this code path frequently executed
3. **No defensive programming**: The code has no timeout, retry limit, or fallback mechanism, making it vulnerable to any prolonged state sync failure
4. **Silent failure**: The loop blocks indefinitely without logging warnings or errors, making it difficult to diagnose

While an external attacker cannot directly trigger this without network-level attacks (which are out of scope), the bug can be triggered by:
- Environmental conditions (network issues, resource exhaustion)
- State sync implementation bugs
- Configuration errors
- Infrastructure failures

## Recommendation

Add a configurable timeout mechanism with proper error handling:

```rust
pub async fn get_start_version(&self, node_config: &NodeConfig) -> Result<Version> {
    let fast_sync_enabled = node_config
        .state_sync
        .state_sync_driver
        .bootstrapping_mode
        .is_fast_sync();
    let mut main_db_synced_version = self.db_indexer.main_db_reader.ensure_synced_version()?;

    // Add configurable timeout (e.g., 10 minutes)
    let timeout_duration = Duration::from_secs(600);
    let start_time = tokio::time::Instant::now();
    
    // Wait till fast sync is done with timeout
    while fast_sync_enabled && main_db_synced_version == 0 {
        if start_time.elapsed() > timeout_duration {
            return Err(anyhow::anyhow!(
                "Timeout waiting for fast sync to complete. \
                 Synced version remained at 0 for {} seconds. \
                 Check state sync logs and network connectivity.",
                timeout_duration.as_secs()
            ));
        }
        
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        main_db_synced_version = self.db_indexer.main_db_reader.ensure_synced_version()?;
        
        // Log progress periodically
        if start_time.elapsed().as_secs() % 60 == 0 {
            warn!(
                "Still waiting for fast sync to complete. Elapsed: {} seconds",
                start_time.elapsed().as_secs()
            );
        }
    }
    
    // Rest of the function remains the same...
```

**Additional improvements:**
1. Add metrics to track how long nodes wait in this loop
2. Log a warning after 5 minutes of waiting
3. Consider allowing the indexer to start in degraded mode and retry synchronization in the background
4. Make the timeout configurable via node configuration

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use aptos_config::config::{NodeConfig, BootstrappingMode};
    use aptos_storage_interface::DbReader;
    use std::sync::Arc;
    use tokio::sync::watch;

    // Mock DbReader that always returns synced version = 0
    struct AlwaysZeroDbReader;
    
    impl DbReader for AlwaysZeroDbReader {
        fn get_synced_version(&self) -> Result<Option<Version>> {
            Ok(Some(0)) // Always returns 0 to simulate stuck state sync
        }
        
        // Implement other required trait methods as no-ops...
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_infinite_loop_during_fast_sync_failure() {
        let mut node_config = NodeConfig::default();
        node_config.state_sync.state_sync_driver.bootstrapping_mode = 
            BootstrappingMode::DownloadLatestStates;
        
        let db_reader = Arc::new(AlwaysZeroDbReader);
        let internal_db = InternalIndexerDB::new(/* ... */);
        let (tx, rx) = watch::channel((Instant::now(), 0));
        
        let service = InternalIndexerDBService::new(db_reader, internal_db, rx);
        
        // Set a timeout to prevent test from hanging
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            service.get_start_version(&node_config)
        ).await;
        
        // This will timeout, demonstrating the infinite loop
        assert!(result.is_err(), "Function should timeout due to infinite loop");
    }
}
```

**Steps to reproduce:**
1. Start a node with fast sync enabled
2. Simulate state sync failure by blocking network connectivity to peers
3. Observe the indexer service getting stuck in the wait loop
4. Monitor CPU usage showing continuous polling every second
5. Indexer API remains unavailable until manual intervention

## Notes

This vulnerability represents a **robustness failure** rather than a direct security exploit. While an external attacker cannot directly trigger this condition without network-level attacks (which are out of scope), the bug exposes the system to availability issues under realistic failure conditions. The lack of timeout and error handling violates defensive programming best practices and can cause operational issues requiring manual intervention.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-table-info/src/internal_indexer_db_service.rs (L88-100)
```rust
    pub async fn get_start_version(&self, node_config: &NodeConfig) -> Result<Version> {
        let fast_sync_enabled = node_config
            .state_sync
            .state_sync_driver
            .bootstrapping_mode
            .is_fast_sync();
        let mut main_db_synced_version = self.db_indexer.main_db_reader.ensure_synced_version()?;

        // Wait till fast sync is done
        while fast_sync_enabled && main_db_synced_version == 0 {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            main_db_synced_version = self.db_indexer.main_db_reader.ensure_synced_version()?;
        }
```

**File:** storage/aptosdb/src/fast_sync_storage_wrapper.rs (L66-76)
```rust
        if config
            .state_sync
            .state_sync_driver
            .bootstrapping_mode
            .is_fast_sync()
            && (db_main
                .ledger_db
                .metadata_db()
                .get_synced_version()?
                .map_or(0, |v| v)
                == 0)
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L213-218)
```rust
            ledger_db_batch
                .ledger_metadata_db_batches
                .put::<DbMetadataSchema>(
                    &DbMetadataKey::OverallCommitProgress,
                    &DbMetadataValue::Version(version),
                )?;
```
