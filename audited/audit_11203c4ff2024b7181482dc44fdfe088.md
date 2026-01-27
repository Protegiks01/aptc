# Audit Report

## Title
Race Condition Between fetch_add and fetch_max on file_store_version Causes Indexer-GRPC Node Panic

## Summary
The `DataManager::update_file_store_version_in_cache()` function uses `Ordering::SeqCst` for `fetch_max` operations on the `file_store_version` atomic. However, this ordering is **insufficient** to prevent race conditions with concurrent `fetch_add` operations performed by the `FileStoreUploader`. This race condition triggers a panic check, causing the indexer-grpc node to crash and disrupting API availability. [1](#0-0) 

## Finding Description

The vulnerability stems from two conflicting atomic operations on `Cache::file_store_version`:

1. **fetch_add operation**: Used when `FileStoreUploader` reads transactions from cache with `update_file_store_version=true` [2](#0-1) 

2. **fetch_max operation**: Used when `DataManager` updates the cache to match the file store version [3](#0-2) 

**The Race Condition:**

Both operations are called from threads holding **read locks** on the cache RwLock, allowing concurrent execution: [4](#0-3) 

**Critical Race Scenario:**
1. Initial state: `file_store_version = 100`, file store on disk contains versions [0, 100)
2. Thread 1 (FileStoreUploader): Reads 50 transactions [100, 150) from cache, calls `fetch_add(50)` → changes atomic from 100 to 150
3. Thread 2 (DataManager): Reads file store version from disk → gets 100 (stale, upload hasn't completed)
4. Thread 2: Calls `fetch_max(100)` → atomic stays at 150, but returns 150 as the "before" value
5. Thread 2: Panic check evaluates: `!version_can_go_backward && 150 > 100` → **TRUE**
6. **Node panics**: "File store version is going backward, data might be corrupted"

The panic occurs because `fetch_add` optimistically increments the version **before** transactions are persisted to file store, while `fetch_max` reads the actual persisted version. These operations have conflicting semantics:
- `fetch_add`: Assumes monotonic increment based on cache consumption
- `fetch_max`: Assumes synchronization with external file store state

**Why SeqCst is Insufficient:**

`Ordering::SeqCst` provides the strongest memory ordering guarantees - all operations appear in a single total order visible to all threads. However, it **cannot prevent this race** because the issue is logical, not about memory ordering:
- SeqCst ensures each atomic operation is atomic and visible consistently
- But it doesn't prevent the conflicting semantics when `fetch_add` increments beyond the file store version
- No memory ordering can resolve the fundamental design flaw of using two operations with incompatible assumptions

## Impact Explanation

**Severity: Medium** (per Aptos Bug Bounty Program)

This vulnerability causes **indexer-grpc node crashes**, falling under the "API crashes" category (High Severity: up to $50,000) or "State inconsistencies requiring intervention" (Medium Severity: up to $10,000).

**Impact Scope:**
- **Component Affected**: Indexer-GRPC service (not consensus-critical)
- **Availability Impact**: Service crashes and becomes unavailable until restart
- **Data Integrity**: The panic is actually a safety mechanism preventing data loss (without it, transactions could be GC'd before persistence)
- **No Consensus Impact**: Does not affect validators or blockchain consensus
- **User Impact**: API query disruption for applications relying on indexer-grpc

Given this is the indexer-grpc component (not core consensus), **Medium severity** is appropriate, though it approaches High severity due to service crashes.

## Likelihood Explanation

**Likelihood: Medium to High**

This race occurs **naturally during normal operation** without requiring attacker intervention:

1. **FileStoreUploader** continuously consumes transactions from cache in a loop [5](#0-4) 

2. **DataManager** periodically updates file store version in its main loop [6](#0-5) 

**Factors Increasing Likelihood:**
- High transaction throughput increases `fetch_add` frequency
- Network latency in file store reads increases staleness window
- The timing window exists between transaction read and file upload completion

**Attacker Influence:**
- Cannot directly trigger the race condition
- Could increase transaction volume to make timing more likely
- But this is a timing-dependent concurrency bug, not a directly exploitable vulnerability

## Recommendation

**Solution: Use a single atomic operation or proper synchronization**

The fundamental issue is mixing `fetch_add` (increment) with `fetch_max` (set to external value). 

**Option 1: Eliminate fetch_add** (Recommended)
Remove the optimistic version update in `get_transactions`. Only update `file_store_version` after successful file upload:

```rust
// In Cache::get_transactions() - REMOVE fetch_add:
if update_file_store_version {
    if !transactions.is_empty() {
        // Remove these lines:
        // let old_version = self.file_store_version.fetch_add(...);
        // FILE_STORE_VERSION_IN_CACHE.set(new_version as i64);
        
        // Version will be updated by update_file_store_version_in_cache()
        // after successful upload to file store
    }
}
```

Then rely solely on `fetch_max` in `update_file_store_version_in_cache()` to update the version after persistence.

**Option 2: Use proper locking**
Protect version updates with a write lock instead of relying on atomics:

```rust
// Change file_store_version from AtomicU64 to u64
// Acquire write lock before updating version
// But this increases lock contention
```

**Option 3: Remove panic and use compare_exchange**
Replace `fetch_max` with a loop using `compare_exchange` that only updates if the new value is actually greater, without panicking on backward movement.

**Recommended approach**: Option 1, as it eliminates the race entirely by removing the optimistic increment.

## Proof of Concept

The following Rust test demonstrates the race condition:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;
    use std::time::Duration;

    #[test]
    #[should_panic(expected = "File store version is going backward")]
    fn test_fetch_add_fetch_max_race() {
        let file_store_version = Arc::new(AtomicU64::new(100));
        
        let version_clone1 = file_store_version.clone();
        let version_clone2 = file_store_version.clone();
        
        // Thread 1: Simulates FileStoreUploader doing fetch_add
        let thread1 = thread::spawn(move || {
            thread::sleep(Duration::from_millis(10));
            let old = version_clone1.fetch_add(50, Ordering::SeqCst);
            println!("fetch_add: {} -> {}", old, old + 50);
        });
        
        // Thread 2: Simulates DataManager doing fetch_max with stale value
        let thread2 = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            // Simulates reading stale file store version (100)
            let file_store_version_from_disk = 100;
            let before = version_clone2.fetch_max(
                file_store_version_from_disk, 
                Ordering::SeqCst
            );
            println!("fetch_max: before={}, from_disk={}", before, file_store_version_from_disk);
            
            // This is the panic check from the actual code
            let version_can_go_backward = false;
            if !version_can_go_backward && before > file_store_version_from_disk {
                panic!("File store version is going backward, data might be corrupted. {} v.s. {}", 
                       before, file_store_version_from_disk);
            }
        });
        
        thread1.join().unwrap();
        thread2.join().unwrap();
    }
}
```

This test demonstrates that even with `Ordering::SeqCst`, the race between `fetch_add` and `fetch_max` causes the panic condition when the operations interleave with a stale file store read.

## Notes

- The panic at line 415-417 is actually a **safety mechanism** that prevents data loss. Without it, transactions could be garbage collected from cache before being persisted to file store.
- This issue is specific to the indexer-grpc component and does not affect consensus or core blockchain operation.
- The vulnerability exists because of the architectural decision to optimistically update the version during cache read rather than after file persistence.
- `Ordering::SeqCst` is semantically correct for the individual operations but cannot prevent the logical race between conflicting operation types.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/data_manager.rs (L127-135)
```rust
        if update_file_store_version {
            if !transactions.is_empty() {
                let old_version = self
                    .file_store_version
                    .fetch_add(transactions.len() as u64, Ordering::SeqCst);
                let new_version = old_version + transactions.len() as u64;
                FILE_STORE_VERSION_IN_CACHE.set(new_version as i64);
                info!("Updated file_store_version in cache to {new_version}.");
            }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/data_manager.rs (L196-282)
```rust
        'out: loop {
            let _timer = TIMER
                .with_label_values(&["data_manager_main_loop"])
                .start_timer();
            let cache = self.cache.read().await;
            if watch_file_store_version {
                self.update_file_store_version_in_cache(
                    &cache, /*version_can_go_backward=*/ false,
                )
                .await;
            }
            let request = GetTransactionsFromNodeRequest {
                starting_version: Some(cache.start_version + cache.transactions.len() as u64),
                transactions_count: Some(100000),
            };
            drop(cache);

            debug!(
                "Requesting transactions from fullnodes, starting_version: {}.",
                request.starting_version.unwrap()
            );
            let (address, mut fullnode_client) =
                self.metadata_manager.get_fullnode_for_request(&request);
            trace!("Fullnode ({address}) is picked for request.");
            let response = fullnode_client.get_transactions_from_node(request).await;
            if response.is_err() {
                warn!(
                    "Error when getting transactions from fullnode ({address}): {}",
                    response.err().unwrap()
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            } else {
                trace!("Got success response from fullnode.");
            }

            let mut response = response.unwrap().into_inner();
            while let Some(response_item) = response.next().await {
                trace!("Processing 1 response item.");
                loop {
                    trace!("Maybe running GC.");
                    if self.cache.write().await.maybe_gc() {
                        IS_FILE_STORE_LAGGING.set(0);
                        trace!("GC is done, file store is not lagging.");
                        break;
                    }
                    IS_FILE_STORE_LAGGING.set(1);
                    // If file store is lagging, we are not inserting more data.
                    let cache = self.cache.read().await;
                    warn!("Filestore is lagging behind, cache is full [{}, {}), known_latest_version ({}).",
                          cache.start_version,
                          cache.start_version + cache.transactions.len() as u64,
                          self.metadata_manager.get_known_latest_version());
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    if watch_file_store_version {
                        self.update_file_store_version_in_cache(
                            &cache, /*version_can_go_backward=*/ false,
                        )
                        .await;
                    }
                }
                match response_item {
                    Ok(r) => {
                        if let Some(response) = r.response {
                            match response {
                                Response::Data(data) => {
                                    trace!(
                                        "Putting data into cache, {} transaction(s).",
                                        data.transactions.len()
                                    );
                                    self.cache.write().await.put_transactions(data.transactions);
                                },
                                Response::Status(_) => continue,
                            }
                        } else {
                            warn!("Error when getting transactions from fullnode: no data.");
                            continue 'out;
                        }
                    },
                    Err(e) => {
                        warn!("Error when getting transactions from fullnode: {}", e);
                        continue 'out;
                    },
                }
            }
        }
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/data_manager.rs (L374-384)
```rust
    pub(crate) async fn get_transactions_from_cache(
        &self,
        start_version: u64,
        max_size: usize,
        update_file_store_version: bool,
    ) -> Vec<Transaction> {
        self.cache
            .read()
            .await
            .get_transactions(start_version, max_size, update_file_store_version)
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/data_manager.rs (L403-419)
```rust
    async fn update_file_store_version_in_cache(
        &self,
        cache: &RwLockReadGuard<'_, Cache>,
        version_can_go_backward: bool,
    ) {
        let file_store_version = self.file_store_reader.get_latest_version().await;
        if let Some(file_store_version) = file_store_version {
            let file_store_version_before_update = cache
                .file_store_version
                .fetch_max(file_store_version, Ordering::SeqCst);
            FILE_STORE_VERSION_IN_CACHE.set(file_store_version as i64);
            info!("Updated file_store_version in cache to {file_store_version}.");
            if !version_can_go_backward && file_store_version_before_update > file_store_version {
                panic!("File store version is going backward, data might be corrupted. {file_store_version_before_update} v.s. {file_store_version}");
            };
        }
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/file_store_uploader.rs (L147-177)
```rust
            s.spawn(async move {
                loop {
                    let _timer = TIMER
                        .with_label_values(&["file_store_uploader_main_loop"])
                        .start_timer();
                    let next_version = file_store_operator.version();
                    let transactions = {
                        let _timer = TIMER
                            .with_label_values(&["get_transactions_from_cache"])
                            .start_timer();
                        data_manager
                            .get_transactions_from_cache(
                                next_version,
                                MAX_SIZE_PER_FILE,
                                /*update_file_store_version=*/ true,
                            )
                            .await
                    };
                    let len = transactions.len();
                    for transaction in transactions {
                        file_store_operator
                            .buffer_and_maybe_dump_transactions_to_file(transaction, tx.clone())
                            .await
                            .unwrap();
                    }
                    if len == 0 {
                        info!("No transaction was returned from cache, requested version: {next_version}.");
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                }
            });
```
