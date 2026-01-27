# Audit Report

## Title
Indexer-gRPC Stream Termination on Block Info Retrieval Failure

## Summary
The `convert_to_api_txns()` function in the indexer-grpc fullnode service contains explicit panic calls when `get_block_info_by_version()` fails, causing immediate termination of the gRPC transaction stream and leaving clients with incomplete data and no recovery mechanism.

## Finding Description

The indexer-grpc fullnode service uses panic-based error handling when retrieving block information during transaction streaming. There are two critical panic points:

**Panic Point 1**: In `convert_to_api_txns()`, when fetching block info for the first transaction version: [1](#0-0) 

**Panic Point 2**: In `process_next_batch()`, when fetching block info for the end version: [2](#0-1) 

The `get_block_info_by_version()` function can fail in several scenarios: [3](#0-2) 

Failure conditions include:
1. **Ledger pruning**: When requested versions fall below the minimum readable version [4](#0-3) 

2. **Block info not found**: When the database lookup fails to find the block height mapping [5](#0-4) 

3. **Version exceeds synced version**: When requested version is ahead of what's been synchronized [6](#0-5) 

When the panic occurs during task execution, it propagates upward, causing additional panics in the join handler: [7](#0-6) 

The gRPC stream handler spawns this coordinator as a task, and when the panic occurs, the entire stream terminates: [8](#0-7) 

## Impact Explanation

This issue qualifies as **High Severity** under the Aptos bug bounty program category of "API crashes" (up to $50,000). The indexer-grpc fullnode service is a critical API component that external indexers and data consumers rely upon for transaction streaming.

**Impact includes:**
- **Service Disruption**: Panic crashes the gRPC stream handler task completely
- **Data Loss**: Clients receive partial transaction batches without completion markers
- **No Recovery Path**: No automatic retry mechanism; clients must detect failure and reconnect
- **Silent Failures**: Mid-batch panics leave clients uncertain about data consistency

While this doesn't affect core consensus or validator operations, it represents a significant availability failure for blockchain data consumers.

## Likelihood Explanation

**Likelihood: Medium to High** in production environments with active pruning.

**Triggering scenarios:**
1. **Pruning Race Condition**: Transactions fetched successfully, but block info pruned before retrieval
   - Window between `fetch_transactions_from_storage()` (line 104-105) and `get_block_info_by_version()` (line 119-128)
   - Pruner operates concurrently with indexer

2. **Sync Lag**: Clients request recently committed versions before indexer metadata fully syncs

3. **Database Inconsistencies**: Transaction data present but corresponding block info missing due to partial writes or corruption

The pruning race condition is particularly realistic in production:
- Pruning runs continuously on fullnodes with storage limits
- Indexer streams can request historical data near pruning boundaries
- No atomic protection between transaction fetch and block info retrieval

## Recommendation

Replace panic-based error handling with graceful error propagation and retry logic:

```rust
fn convert_to_api_txns(
    context: Arc<Context>,
    raw_txns: Vec<TransactionOnChainData>,
) -> Result<Vec<(APITransaction, TransactionSizeInfo)>, Status> {
    if raw_txns.is_empty() {
        return Ok(vec![]);
    }
    
    let first_version = raw_txns.first().map(|txn| txn.version).unwrap();
    let state_view = context.latest_state_view()
        .map_err(|e| Status::internal(format!("Failed to get state view: {}", e)))?;
    let converter = state_view.as_converter(context.db.clone(), context.indexer_reader.clone());

    // Replace panic with error return
    let (_, _, block_event) = context
        .db
        .get_block_info_by_version(first_version)
        .map_err(|e| Status::unavailable(format!(
            "Block info unavailable for version {} (possibly pruned): {}", 
            first_version, e
        )))?;
    
    // ... rest of function
}
```

In `process_next_batch()`, propagate errors instead of panicking:

```rust
pub async fn process_next_batch(&mut self) -> Vec<Result<EndVersion, Status>> {
    // ... existing fetch logic ...
    
    let (_, _, block_event) = match self
        .context
        .db
        .get_block_info_by_version(end_version as u64)
    {
        Ok(info) => info,
        Err(e) => {
            error!(
                version = end_version,
                error = format!("{:?}", e),
                "[Indexer Fullnode] Failed to get block info, may be pruned"
            );
            return vec![Err(Status::unavailable(format!(
                "Block info unavailable for version {}: {:?}", 
                end_version, e
            )))];
        }
    };
    
    // ... continue processing ...
}
```

Add retry logic in the stream coordinator to handle transient failures from pruning race conditions.

## Proof of Concept

```rust
// Reproduction test (requires running fullnode with pruning enabled)
#[tokio::test]
async fn test_block_info_panic_on_pruned_version() {
    // Setup: Start fullnode with aggressive pruning (prune_window = 1000)
    // 1. Let blockchain advance beyond prune_window
    // 2. Start indexer-grpc stream from version 0
    // 3. While streaming, trigger pruner to remove early versions
    // 4. Observe panic when get_block_info_by_version(0) fails with pruning error
    
    // Expected: Panic crashes stream with message:
    // "[Indexer Fullnode] Could not get block_info for start version 0"
    
    // Actual behavior: Stream abruptly terminates, client receives incomplete data
}

// Minimal reproduction:
// 1. Deploy fullnode with pruning configuration: prune_window = 10000
// 2. Wait for chain to advance to version > 20000
// 3. Connect indexer-grpc client requesting from version 0
// 4. Panic occurs when early versions are pruned during stream processing
```

**Test steps:**
1. Configure AptosDB with `enable_indexer = true` and `prune_window = 10000`
2. Run fullnode until ledger version exceeds 20,000
3. Start indexer-grpc client with `starting_version = 0`
4. Monitor logs for panic: `"Could not get block_info for start version"`
5. Verify client receives incomplete transaction batches and disconnects

---

## Notes

This vulnerability specifically affects the **indexer-grpc auxiliary service**, not core consensus or validator operations. However, it represents a significant availability issue for blockchain data consumers who rely on this service for reliable transaction streaming. The use of explicit panics for error handling violates Rust best practices and creates unnecessary service disruptions that could be handled gracefully with proper error propagation.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L119-128)
```rust
        let (_, _, block_event) = self
            .context
            .db
            .get_block_info_by_version(end_version as u64)
            .unwrap_or_else(|_| {
                panic!(
                    "[Indexer Fullnode] Could not get block_info for version {}",
                    end_version,
                )
            });
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L202-207)
```rust
        let responses = match futures::future::try_join_all(tasks).await {
            Ok(res) => res.into_iter().flatten().collect::<Vec<_>>(),
            Err(err) => panic!(
                "[Indexer Fullnode] Error processing transaction batches: {:?}",
                err
            ),
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L376-384)
```rust
        let (_, _, block_event) = context
            .db
            .get_block_info_by_version(first_version)
            .unwrap_or_else(|_| {
                panic!(
                    "[Indexer Fullnode] Could not get block_info for start version {}",
                    first_version,
                )
            });
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L779-789)
```rust
    fn get_block_info_by_version(
        &self,
        version: Version,
    ) -> Result<(Version, Version, NewBlockEvent)> {
        gauged_api("get_block_info", || {
            self.error_if_ledger_pruned("NewBlockEvent", version)?;

            let (block_height, block_info) = self.get_raw_block_info_by_version(version)?;
            self.to_api_block_info(block_height, block_info)
        })
    }
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L261-271)
```rust
    pub(super) fn error_if_ledger_pruned(&self, data_type: &str, version: Version) -> Result<()> {
        let min_readable_version = self.ledger_pruner.get_min_readable_version();
        ensure!(
            version >= min_readable_version,
            "{} at version {} is pruned, min available version is {}.",
            data_type,
            version,
            min_readable_version
        );
        Ok(())
    }
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L344-348)
```rust
        let synced_version = self.ensure_synced_version()?;
        ensure!(
            version <= synced_version,
            "Requested version {version} > synced version {synced_version}",
        );
```

**File:** storage/aptosdb/src/ledger_db/ledger_metadata_db.rs (L270-280)
```rust
    pub(crate) fn get_block_height_by_version(&self, version: Version) -> Result<u64> {
        let mut iter = self.db.iter::<BlockByVersionSchema>()?;

        iter.seek_for_prev(&version)?;
        let (_, block_height) = iter
            .next()
            .transpose()?
            .ok_or_else(|| anyhow!("Block is not found at version {version}, maybe pruned?"))?;

        Ok(block_height)
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/fullnode_data_service.rs (L101-138)
```rust
        tokio::spawn(async move {
            // Initialize the coordinator that tracks starting version and processes transactions
            let mut coordinator = IndexerStreamCoordinator::new(
                context,
                starting_version,
                ending_version,
                processor_task_count,
                processor_batch_size,
                output_batch_size,
                tx.clone(),
                // For now the request for this interface doesn't include a txn filter
                // because it is only used for the txn stream filestore worker, which
                // needs every transaction. Later we may add support for txn filtering
                // to this interface too.
                None,
                Some(abort_handle.clone()),
            );
            // Sends init message (one time per request) to the client in the with chain id and starting version. Basically a handshake
            let init_status = get_status(StatusType::Init, starting_version, None, ledger_chain_id);
            match tx.send(Result::<_, Status>::Ok(init_status)).await {
                Ok(_) => {
                    // TODO: Add request details later
                    info!(
                        start_version = starting_version,
                        chain_id = ledger_chain_id,
                        service_type = SERVICE_TYPE,
                        "[Indexer Fullnode] Init connection"
                    );
                },
                Err(_) => {
                    panic!("[Indexer Fullnode] Unable to initialize stream");
                },
            }
            let mut base: u64 = 0;
            while coordinator.current_version < coordinator.end_version {
                let start_time = std::time::Instant::now();
                // Processes and sends batch of transactions to client
                let results = coordinator.process_next_batch().await;
```
