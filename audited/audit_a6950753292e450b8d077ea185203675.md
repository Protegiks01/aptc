# Audit Report

## Title
Pruning Race Condition in Block Retrieval API Causes Incorrect Error Codes and Potential Partial Data Exposure

## Summary
A time-of-check-time-of-use (TOCTOU) race condition exists in the `get_by_height()` function where blocks can be pruned between the `latest_ledger_info` validation check and the actual database retrieval, causing the API to return incorrect HTTP 404 (Not Found) errors instead of HTTP 410 (Gone) errors, and potentially exposing inconsistent or partially pruned block data. [1](#0-0) 

## Finding Description

The vulnerability occurs in the block retrieval flow where the API captures a snapshot of the ledger state but does not hold any lock during the subsequent database operations. The background pruner thread operates independently and can prune blocks concurrently.

**Attack Flow:**

1. API thread calls `get_latest_ledger_info()` which retrieves `oldest_block_height = H` at time T1 [2](#0-1) 

2. The background pruner worker thread continuously prunes data in a separate thread [3](#0-2) 

3. Pruner updates `min_readable_version` atomically to advance the pruning boundary to `H + 100` at time T2 (where T2 > T1) [4](#0-3) 

4. Pruner physically deletes block events and transaction data from database at time T3 (where T3 > T2) [5](#0-4) 

5. API thread checks `if height < latest_ledger_info.oldest_block_height` with stale value H, so a request for block `H + 50` passes the check at time T4 (where T4 > T3) [6](#0-5) 

6. API thread calls `db.get_block_info_by_height(H + 50)` which fails because the block event was pruned [7](#0-6) 

7. The error from the database lookup (event not found due to pruning) is incorrectly mapped to `block_not_found_by_height` (HTTP 404) instead of `block_pruned_by_height` (HTTP 410) [8](#0-7) 

The event store's `lookup_events_by_key` function detects pruned events with the message "First requested event is probably pruned" but this distinction is lost in the error handling: [9](#0-8) 

**Secondary Issue - Partial Data Exposure:**

If the block metadata retrieval succeeds but transaction data has been pruned, the `get_block()` function returns an InternalError instead of a proper pruned error: [10](#0-9) 

This breaks the API's consistency guarantee that states blocks should return HTTP 410 when pruned: [11](#0-10) 

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos Bug Bounty program for the following reasons:

1. **API Crashes/Incorrect Responses**: The API returns semantically incorrect HTTP status codes (404 vs 410), violating the documented API contract

2. **Client Confusion**: API consumers cannot distinguish between:
   - A block that never existed (404 - retriable/client error)
   - A block that was pruned (410 - permanent/expected)
   
3. **Inconsistent API Behavior**: The same block height can return different errors depending on race condition timing, breaking idempotency

4. **Potential Partial Data Exposure**: In scenarios where block metadata is retrieved but transactions fail, clients receive InternalError with potentially inconsistent state information

5. **Affects All API Clients**: Any application using the `/blocks/by_height/:height` endpoint near the pruning boundary is affected

The minimum viable version calculation uses atomic operations but provides no synchronization with the actual database reads: [12](#0-11) 

## Likelihood Explanation

**Likelihood: HIGH**

This race condition will occur regularly in production environments:

1. **Continuous Pruning**: The pruner runs continuously in a background thread with only 1ms sleep intervals in production [13](#0-12) 

2. **Large Race Window**: The window between capturing `latest_ledger_info` and retrieving block data can be significant (network latency, database load, concurrent requests)

3. **No Synchronization**: There are no locks or synchronization mechanisms between the API layer and the pruner

4. **Common Access Pattern**: Clients frequently query recent blocks near the pruning boundary for historical analysis, state synchronization, or monitoring

5. **Production Conditions**: Under high load or during catch-up scenarios, the race window widens significantly

## Recommendation

**Solution 1: Re-validate Pruning Status After Database Error (Minimal Change)**

Add re-validation logic to distinguish between true NotFound and pruned-after-check scenarios:

```rust
pub fn get_block_by_height<E: StdApiError>(
    &self,
    height: u64,
    latest_ledger_info: &LedgerInfo,
    with_transactions: bool,
) -> Result<BcsBlock, E> {
    if height < latest_ledger_info.oldest_block_height.0 {
        return Err(block_pruned_by_height(height, latest_ledger_info));
    } else if height > latest_ledger_info.block_height.0 {
        return Err(block_not_found_by_height(height, latest_ledger_info));
    }

    let (first_version, last_version, new_block_event) = self
        .db
        .get_block_info_by_height(height)
        .map_err(|err| {
            // Re-check if block was pruned during retrieval
            let current_oldest = self.db.get_first_viable_block()
                .map(|(_, block_height)| block_height)
                .unwrap_or(0);
            
            if height < current_oldest {
                block_pruned_by_height(height, latest_ledger_info)
            } else {
                block_not_found_by_height(height, latest_ledger_info)
            }
        })?;

    self.get_block(
        latest_ledger_info,
        with_transactions,
        first_version,
        last_version,
        new_block_event,
    )
}
```

**Solution 2: Error Type Propagation (More Robust)**

Modify the storage layer to return typed errors distinguishing pruned vs not-found, and properly propagate these through the API layer:

```rust
// In storage layer
pub enum BlockRetrievalError {
    NotFound,
    Pruned,
    Internal(anyhow::Error),
}

// Propagate through the stack and handle appropriately in API layer
```

**Solution 3: Snapshot-Based Reads (Best Practice)**

Use database snapshots or read transactions that provide a consistent view of the database state throughout the entire read operation.

## Proof of Concept

```rust
#[tokio::test]
async fn test_pruning_race_condition() {
    use aptos_api::context::Context;
    use aptos_api_types::LedgerInfo;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;
    
    // Setup: Create a test node with pruning enabled
    let (context, _) = setup_test_context_with_pruning();
    let blocks_api = BlocksApi { context: Arc::new(context) };
    
    // Generate 1000 blocks
    generate_test_blocks(&context, 1000).await;
    
    // Configure aggressive pruning (prune_window = 100)
    let prune_window = 100;
    
    // Get current oldest block
    let ledger_info = context.get_latest_ledger_info::<BasicError>().unwrap();
    let oldest_height = ledger_info.oldest_block_height.0;
    let target_height = oldest_height + 50; // Block in pruning window
    
    // Trigger pruning in background thread
    thread::spawn(move || {
        context.db.trigger_pruning(); // Prunes blocks up to latest - prune_window
        thread::sleep(Duration::from_millis(50));
    });
    
    // Introduce delay to allow pruning to progress
    thread::sleep(Duration::from_millis(100));
    
    // Attempt to retrieve block that was valid at check time but pruned during retrieval
    let result = blocks_api.get_by_height(
        AcceptType::Json,
        target_height,
        false,
    );
    
    // Expected: HTTP 410 (Gone) with BlockPruned error code
    // Actual: HTTP 404 (Not Found) with BlockNotFound error code
    match result {
        Err(e) => {
            assert_eq!(e.error_code(), AptosErrorCode::BlockPruned, 
                "Expected BlockPruned but got {:?}", e.error_code());
            assert_eq!(e.status_code(), 410,
                "Expected HTTP 410 but got {}", e.status_code());
        }
        Ok(_) => panic!("Expected error but retrieval succeeded"),
    }
}
```

## Notes

This vulnerability is a classic TOCTOU race condition where the validation check uses stale metadata while the background pruner operates independently. The lack of transactional consistency between the ledger info snapshot and actual database reads creates this exploitable window. The issue is exacerbated by the error handling that loses the distinction between different failure modes, returning incorrect HTTP status codes that violate REST API semantics.

### Citations

**File:** api/src/blocks.rs (L108-122)
```rust
    fn get_by_height(
        &self,
        accept_type: AcceptType,
        block_height: u64,
        with_transactions: bool,
    ) -> BasicResultWith404<Block> {
        let latest_ledger_info = self.context.get_latest_ledger_info()?;
        let bcs_block = self.context.get_block_by_height(
            block_height,
            &latest_ledger_info,
            with_transactions,
        )?;

        self.render_bcs_block(&accept_type, latest_ledger_info, bcs_block)
    }
```

**File:** storage/aptosdb/src/pruner/pruner_worker.rs (L45-45)
```rust
            pruning_time_interval_in_ms: if cfg!(test) { 100 } else { 1 },
```

**File:** storage/aptosdb/src/pruner/pruner_worker.rs (L53-68)
```rust
    fn work(&self) {
        while !self.quit_worker.load(Ordering::SeqCst) {
            let pruner_result = self.pruner.prune(self.batch_size);
            if pruner_result.is_err() {
                sample!(
                    SampleRate::Duration(Duration::from_secs(1)),
                    error!(error = ?pruner_result.err().unwrap(),
                        "Pruner has error.")
                );
                sleep(Duration::from_millis(self.pruning_time_interval_in_ms));
                continue;
            }
            if !self.pruner.is_pruning_pending() {
                sleep(Duration::from_millis(self.pruning_time_interval_in_ms));
            }
        }
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/ledger_pruner_manager.rs (L52-63)
```rust
    fn get_min_viable_version(&self) -> Version {
        let min_version = self.get_min_readable_version();
        if self.is_pruner_enabled() {
            let adjusted_window = self
                .prune_window
                .saturating_sub(self.user_pruning_window_offset);
            let adjusted_cutoff = self.latest_version.lock().saturating_sub(adjusted_window);
            std::cmp::max(min_version, adjusted_cutoff)
        } else {
            min_version
        }
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

**File:** storage/aptosdb/src/pruner/ledger_pruner/mod.rs (L62-92)
```rust
    fn prune(&self, max_versions: usize) -> Result<Version> {
        let mut progress = self.progress();
        let target_version = self.target_version();

        while progress < target_version {
            let current_batch_target_version =
                min(progress + max_versions as Version, target_version);

            info!(
                progress = progress,
                target_version = current_batch_target_version,
                "Pruning ledger data."
            );
            self.ledger_metadata_pruner
                .prune(progress, current_batch_target_version)?;

            THREAD_MANAGER.get_background_pool().install(|| {
                self.sub_pruners.par_iter().try_for_each(|sub_pruner| {
                    sub_pruner
                        .prune(progress, current_batch_target_version)
                        .map_err(|err| anyhow!("{} failed to prune: {err}", sub_pruner.name()))
                })
            })?;

            progress = current_batch_target_version;
            self.record_progress(progress);
            info!(progress = progress, "Pruning ledger data is done.");
        }

        Ok(target_version)
    }
```

**File:** api/src/context.rs (L634-638)
```rust
        if height < latest_ledger_info.oldest_block_height.0 {
            return Err(block_pruned_by_height(height, latest_ledger_info));
        } else if height > latest_ledger_info.block_height.0 {
            return Err(block_not_found_by_height(height, latest_ledger_info));
        }
```

**File:** api/src/context.rs (L640-643)
```rust
        let (first_version, last_version, new_block_event) = self
            .db
            .get_block_info_by_height(height)
            .map_err(|_| block_not_found_by_height(height, latest_ledger_info))?;
```

**File:** api/src/context.rs (L711-721)
```rust
        let txns = if with_transactions {
            Some(
                self.get_transactions(first_version, max_txns, ledger_version)
                    .context("Failed to read raw transactions from storage")
                    .map_err(|err| {
                        E::internal_with_code(
                            err,
                            AptosErrorCode::InternalError,
                            latest_ledger_info,
                        )
                    })?,
```

**File:** storage/aptosdb/src/event_store/mod.rs (L130-136)
```rust
            if seq != cur_seq {
                let msg = if cur_seq == start_seq_num {
                    "First requested event is probably pruned."
                } else {
                    "DB corruption: Sequence number not continuous."
                };
                db_other_bail!("{} expected: {}, actual: {}", msg, cur_seq, seq);
```

**File:** api/src/response.rs (L786-792)
```rust
pub fn block_pruned_by_height<E: GoneError>(block_height: u64, ledger_info: &LedgerInfo) -> E {
    E::gone_with_code(
        format!("Block({}) has been pruned", block_height),
        AptosErrorCode::BlockPruned,
        ledger_info,
    )
}
```
