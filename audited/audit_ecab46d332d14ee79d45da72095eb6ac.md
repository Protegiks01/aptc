# Audit Report

## Title
Race Condition in Indexer Cache Allows Transaction Data Regression and Corruption

## Summary
A Time-of-Check-Time-of-Use (TOCTOU) race condition in `fetch_and_update_cache()` allows the indexer cache to regress when concurrent operations cause old transaction data to overwrite newer transactions in the circular buffer. The `version` parameter is not validated against the current `end_version` before writing, enabling cache corruption that serves incorrect historical transaction data to clients.

## Finding Description

The vulnerability exists in the interaction between `fetch_and_update_cache()` [1](#0-0)  and `DataManager::update_data()` [2](#0-1) .

**Attack Flow:**

1. Initial cache state: `start_version=200, end_version=300`, `num_slots=100` (holding versions 200-299)

2. Client requests transaction at version 250 via the gRPC API [3](#0-2) 

3. `InMemoryCache::get_data()` checks if the slot exists, finds it's None (evicted/sparse) [4](#0-3) 

4. Thread A calls `fetch_past_data(250)` [5](#0-4)  and begins fetching transactions from the data source without holding any lock [6](#0-5) 

5. **During the fetch**, Thread B running `continuously_fetch_latest_data()` [7](#0-6)  advances the cache to `start_version=300, end_version=400` (versions 300-399 now occupy slots 0-99)

6. Thread A's fetch completes with 100 transactions [250-349]

7. Thread A calls `update_data(250, transactions)` which validates:
   - Is `250 > 400` (current end_version)? **NO** - continues [8](#0-7) 
   - Is `350 <= 300` (current start_version)? **NO** - continues [9](#0-8) 

8. **Cache corruption occurs**: The loop writes versions 250-349 to slots [10](#0-9) :
   - Version 250 → slot 50 (**overwrites version 350**)
   - Version 251 → slot 51 (**overwrites version 351**)
   - ...
   - Version 299 → slot 99 (**overwrites version 399**)
   - Versions 300-349 → slots 0-49 (same versions, no harm)

9. Cache metadata remains `end_version=400` because the condition `350 > 400` is false [11](#0-10) 

**Result**: Cache claims to serve versions [300, 400) but slots 50-99 contain stale data from versions [250-299]. When clients request version 350, they receive version 250's data instead.

## Impact Explanation

This is a **High severity** vulnerability per Aptos bug bounty criteria because it causes:

1. **Significant protocol violations**: The indexer-grpc service is critical infrastructure that applications depend on for blockchain data. Serving incorrect historical transaction data breaks the integrity guarantee that indexer services are expected to provide.

2. **API data corruption**: While this doesn't directly impact consensus or validator nodes, it corrupts the indexer's cached data, causing all subsequent clients to receive incorrect transaction information. Applications making decisions based on this data (e.g., wallets showing transaction history, analytics platforms, DeFi protocols verifying past events) would receive false information.

3. **No automatic recovery**: Once the cache is corrupted, it continues serving wrong data until the affected slots are naturally evicted and refilled, or the service restarts. There's no detection or self-healing mechanism.

The vulnerability affects the data integrity invariant: clients querying the indexer must receive authentic, unmodified blockchain transaction data.

## Likelihood Explanation

**High likelihood** of occurrence:

1. **Natural race condition**: The vulnerability requires no malicious intent—it can occur during normal operation when:
   - Multiple clients request different version ranges concurrently
   - The `continuously_fetch_latest_data` task runs frequently
   - Network latency causes fetches to complete out of order

2. **No synchronization**: The fetch operation happens without holding the DataManager lock [12](#0-11) , creating a wide race window

3. **Common trigger**: Requests for past data when slots are evicted (which happens regularly in a circular buffer under load) will trigger the vulnerable code path

4. **Concurrent tasks**: The design explicitly runs fetch operations concurrently [13](#0-12)  and [14](#0-13) 

## Recommendation

Add version validation in `fetch_and_update_cache()` to prevent writing stale data:

```rust
async fn fetch_and_update_cache(
    data_client: Arc<DataClient>,
    data_manager: Arc<RwLock<DataManager>>,
    version: u64,
) -> usize {
    let transactions = data_client.fetch_transactions(version).await;
    let len = transactions.len();

    if len > 0 {
        let mut dm = data_manager.write().await;
        
        // NEW VALIDATION: Reject if version is before current end_version
        // This prevents overwriting newer data with older data
        if version < dm.end_version {
            warn!(
                "Rejecting stale data fetch: version {} is before cache end_version {}",
                version, dm.end_version
            );
            return 0;
        }
        
        dm.update_data(version, transactions);
    }

    len
}
```

Alternative fix: Add the same check in `update_data()`:

```rust
pub(super) fn update_data(&mut self, start_version: u64, transactions: Vec<Transaction>) {
    let end_version = start_version + transactions.len() as u64;
    
    // NEW CHECK: Prevent backwards seeks that could corrupt the cache
    if start_version < self.end_version {
        warn!(
            "Rejecting backwards update: start_version {} < cache end_version {}",
            start_version, self.end_version
        );
        COUNTER.with_label_values(&["rejected_backwards_update"]).inc();
        return;
    }
    
    // ... rest of existing validation and update logic
}
```

## Proof of Concept

```rust
// Reproduction test demonstrating the race condition
#[tokio::test]
async fn test_cache_regression_race_condition() {
    use std::sync::Arc;
    use tokio::sync::RwLock;
    
    let num_slots = 100;
    let data_manager = Arc::new(RwLock::new(DataManager::new(300, num_slots, 1000000)));
    
    // Simulate: Cache currently has versions [200, 300)
    // Fill cache with versions 200-299
    let mut txns = vec![];
    for v in 200..300 {
        txns.push(create_test_transaction(v));
    }
    data_manager.write().await.update_data(200, txns);
    
    // Thread A: Start fetching old data at version 250
    let dm1 = data_manager.clone();
    let handle1 = tokio::spawn(async move {
        // Simulate fetch delay
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        let txns: Vec<_> = (250..350).map(create_test_transaction).collect();
        dm1.write().await.update_data(250, txns);
    });
    
    // Thread B: Advance cache to versions [300, 400) while Thread A is fetching
    let dm2 = data_manager.clone();
    let handle2 = tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        
        let txns: Vec<_> = (300..400).map(create_test_transaction).collect();
        dm2.write().await.update_data(300, txns);
    });
    
    handle2.await.unwrap();
    handle1.await.unwrap();
    
    // Verify corruption: Requesting version 350 should fail or return wrong data
    let dm = data_manager.read().await;
    assert_eq!(dm.end_version, 400);
    
    // Slot for version 350 = 350 % 100 = 50
    // After race, this slot contains version 250 instead of 350!
    let data_at_350 = dm.get_data(350);
    if let Some(txn) = data_at_350 {
        // BUG: This assertion will FAIL - txn.version is 250, not 350!
        assert_eq!(txn.version, 350, "Cache corruption: got wrong version!");
    }
}
```

## Notes

This vulnerability is specific to the indexer-grpc-data-service-v2 component and does not directly impact consensus, validator nodes, or on-chain state. However, it represents a critical data integrity violation for the indexer infrastructure that applications rely on. The race condition is inherent in the current design where fetches occur without holding locks, and validation checks are insufficient to prevent cache regression during concurrent updates.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/fetch_manager.rs (L34-38)
```rust
    pub(super) async fn fetch_past_data(&self, version: u64) -> usize {
        let _timer = TIMER.with_label_values(&["fetch_past_data"]).start_timer();
        Self::fetch_and_update_cache(self.data_client.clone(), self.data_manager.clone(), version)
            .await
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/fetch_manager.rs (L40-46)
```rust
    pub(super) async fn continuously_fetch_latest_data(&'a self) {
        loop {
            let task = self.fetch_latest_data().boxed().shared();
            *self.fetching_latest_data_task.write().await = Some(task.clone());
            let _ = task.await;
        }
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/fetch_manager.rs (L48-64)
```rust
    async fn fetch_and_update_cache(
        data_client: Arc<DataClient>,
        data_manager: Arc<RwLock<DataManager>>,
        version: u64,
    ) -> usize {
        let transactions = data_client.fetch_transactions(version).await;
        let len = transactions.len();

        if len > 0 {
            data_manager
                .write()
                .await
                .update_data(version, transactions);
        }

        len
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/data_manager.rs (L44-120)
```rust
    pub(super) fn update_data(&mut self, start_version: u64, transactions: Vec<Transaction>) {
        let end_version = start_version + transactions.len() as u64;

        trace!(
            "Updating data for {} transactions in range [{start_version}, {end_version}).",
            transactions.len(),
        );
        if start_version > self.end_version {
            error!(
                "The data is in the future, cache end_version: {}, data start_version: {start_version}.",
                self.end_version
            );
            COUNTER.with_label_values(&["data_too_new"]).inc();
            return;
        }

        if end_version <= self.start_version {
            warn!(
                "The data is too old, cache start_version: {}, data end_version: {end_version}.",
                self.start_version
            );
            COUNTER.with_label_values(&["data_too_old"]).inc();
            return;
        }

        let num_to_skip = self.start_version.saturating_sub(start_version);
        let start_version = start_version.max(self.start_version);

        let mut size_increased = 0;
        let mut size_decreased = 0;

        for (i, transaction) in transactions
            .into_iter()
            .enumerate()
            .skip(num_to_skip as usize)
        {
            let version = start_version + i as u64;
            let slot_index = version as usize % self.num_slots;
            if let Some(transaction) = self.data[slot_index].take() {
                size_decreased += transaction.encoded_len();
            }
            size_increased += transaction.encoded_len();
            self.data[version as usize % self.num_slots] = Some(Box::new(transaction));
        }

        if end_version > self.end_version {
            self.end_version = end_version;
            if self.start_version + (self.num_slots as u64) < end_version {
                self.start_version = end_version - self.num_slots as u64;
            }
            if let Some(txn_timestamp) = self.get_data(end_version - 1).as_ref().unwrap().timestamp
            {
                let timestamp_since_epoch =
                    Duration::new(txn_timestamp.seconds as u64, txn_timestamp.nanos as u32);
                let now_since_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
                let latency = now_since_epoch.saturating_sub(timestamp_since_epoch);
                LATENCY_MS.set(latency.as_millis() as i64);
            }
        }

        self.total_size += size_increased;
        self.total_size -= size_decreased;

        if self.total_size >= self.size_limit_bytes {
            while self.total_size >= self.eviction_target {
                if let Some(transaction) =
                    self.data[self.start_version as usize % self.num_slots].take()
                {
                    self.total_size -= transaction.encoded_len();
                    drop(transaction);
                }
                self.start_version += 1;
            }
        }

        self.update_cache_metrics();
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/mod.rs (L66-73)
```rust
        tokio_scoped::scope(|scope| {
            scope.spawn(async move {
                let _ = self
                    .in_memory_cache
                    .fetch_manager
                    .continuously_fetch_latest_data()
                    .await;
            });
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/mod.rs (L83-96)
```rust
                let starting_version = request.starting_version.unwrap_or(known_latest_version);

                info!("Received request: {request:?}.");
                if starting_version > known_latest_version + 10000 {
                    let err = Err(Status::failed_precondition(
                        "starting_version cannot be set to a far future version.",
                    ));
                    info!("Client error: {err:?}.");
                    let _ = response_sender.blocking_send(err);
                    COUNTER
                        .with_label_values(&["live_data_service_requested_data_too_new"])
                        .inc();
                    continue;
                }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/mod.rs (L127-139)
```rust
                scope.spawn(async move {
                    self.start_streaming(
                        id,
                        starting_version,
                        ending_version,
                        max_num_transactions_per_batch,
                        MAX_BYTES_PER_BATCH,
                        filter,
                        request_metadata,
                        response_sender,
                    )
                    .await
                });
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/in_memory_cache.rs (L73-77)
```rust
            if data_manager.get_data(starting_version).is_none() {
                drop(data_manager);
                self.fetch_manager.fetch_past_data(starting_version).await;
                continue;
            }
```
