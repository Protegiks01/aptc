# Audit Report

## Title
Backup Service Runtime Lacks Resource Limits Enabling Validator Performance Degradation

## Summary
The backup service runtime is created without any CPU, memory, or disk I/O resource limits, allowing backup operations to consume excessive resources and potentially degrade validator performance through resource contention.

## Finding Description

The `start_backup_service()` function creates a dedicated tokio runtime for the backup service without configuring any resource limits: [1](#0-0) 

The `spawn_named_runtime` function is called with `None` as the second parameter, which means no worker thread limit is specified. This function defaults to using all available CPU cores: [2](#0-1) 

The only resource limit configured is `max_blocking_threads(64)`, which only restricts the blocking thread pool, not the async worker threads that handle the actual request processing and I/O operations.

The backup service exposes multiple data-intensive endpoints that can trigger heavy database I/O: [3](#0-2) 

These endpoints allow retrieving entire state snapshots and transaction ranges without rate limiting or resource throttling. The backup handler performs direct database reads: [4](#0-3) 

While the backup service listens on localhost by default for validators, backup tools running on the same machine can access it: [5](#0-4) 

**Broken Invariant**: This violates the **Resource Limits** invariant (#9): "All operations must respect gas, storage, and computational limits."

## Impact Explanation

This qualifies as **High Severity** per the Aptos bug bounty criteria for "Validator node slowdowns."

When backup operations run concurrently with validator operations:
- The backup runtime can consume all CPU cores (no worker thread limit)
- Heavy disk I/O from database reads competes with consensus and execution operations
- Memory usage from buffering backup data is unbounded
- No I/O throttling prevents backup from saturating disk bandwidth

This can cause:
- Increased consensus round times and missed block proposals
- Degraded validator performance metrics
- Reduced validator rewards due to missed proposals
- Potential liveness issues if multiple validators are affected simultaneously

## Likelihood Explanation

**Medium-High Likelihood** through operational scenarios:
1. Automated backup tools configured to run periodically on validator nodes
2. Manual backup operations triggered during peak validator activity
3. Multiple concurrent backup requests without coordination
4. No warnings or safeguards in documentation about backup timing

While the backup service is on localhost for validators (not directly externally exploitable), operators regularly run backup tools against their own validators, making this a realistic operational hazard.

## Recommendation

Configure explicit resource limits for the backup runtime to prevent resource contention:

**Option 1: Add worker thread limit configuration**
```rust
// In StorageConfig
pub struct StorageConfig {
    pub backup_service_address: SocketAddr,
    pub backup_service_worker_threads: Option<usize>,  // NEW
    // ... other fields
}

// In start_backup_service
pub fn start_backup_service(address: SocketAddr, db: Arc<AptosDB>, worker_threads: Option<usize>) -> Runtime {
    let backup_handler = db.get_backup_handler();
    let routes = get_routes(backup_handler);
    
    // Limit to 2 worker threads instead of all CPU cores
    let runtime = aptos_runtimes::spawn_named_runtime("backup".into(), worker_threads.or(Some(2)));
    
    let _guard = runtime.enter();
    let server = warp::serve(routes).bind(address);
    runtime.handle().spawn(server);
    info!("Backup service spawned with {:?} worker threads.", worker_threads.or(Some(2)));
    runtime
}
```

**Option 2: Add rate limiting to backup endpoints**
Implement per-endpoint rate limiting using a token bucket or semaphore to restrict concurrent requests.

**Option 3: Process priority configuration**
Use OS-level process priority or cgroups to ensure validator operations have higher priority than backup operations.

**Recommended approach**: Combine all three - limit worker threads to 1-2, add rate limiting, and document best practices for running backups during low-activity periods.

## Proof of Concept

```rust
// Test demonstrating resource contention
// File: storage/backup/backup-service/tests/resource_contention_test.rs

#[tokio::test]
async fn test_backup_service_resource_contention() {
    use aptos_backup_service::start_backup_service;
    use aptos_db::AptosDB;
    use aptos_temppath::TempPath;
    use std::sync::Arc;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Instant;
    
    // Setup database
    let tmpdir = TempPath::new();
    let db = Arc::new(AptosDB::new_for_test(&tmpdir));
    
    // Start backup service (using all CPU cores by default)
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 6186);
    let _backup_runtime = start_backup_service(addr, db.clone());
    
    // Simulate concurrent expensive backup requests
    let mut handles = vec![];
    for i in 0..10 {
        let handle = tokio::spawn(async move {
            let start = Instant::now();
            // Request large state snapshot
            let resp = reqwest::get(format!("http://127.0.0.1:6186/state_snapshot/0")).await;
            println!("Request {} completed in {:?}", i, start.elapsed());
            resp
        });
        handles.push(handle);
    }
    
    // Meanwhile, simulate validator operations that need CPU
    let validator_start = Instant::now();
    let validator_work = tokio::spawn(async {
        let mut sum = 0u64;
        for i in 0..1_000_000 {
            sum = sum.wrapping_add(i);
        }
        sum
    });
    
    // Wait for all to complete
    for handle in handles {
        let _ = handle.await;
    }
    let _ = validator_work.await;
    let validator_elapsed = validator_start.elapsed();
    
    // Validator operations should not be significantly delayed
    // Without resource limits, this assertion may fail
    assert!(validator_elapsed.as_millis() < 1000, 
        "Validator operations delayed by backup service: {:?}", validator_elapsed);
}
```

## Notes

The vulnerability exists in the production code but requires operational context to exploit. While the backup service on validators is localhost-only by default (not directly internet-exposed), the lack of resource limits creates an operational hazard where routine backup operations can inadvertently degrade validator performance. This is particularly concerning for validators running automated backup schedules without awareness of the resource contention risk.

### Citations

**File:** storage/backup/backup-service/src/lib.rs (L16-16)
```rust
    let runtime = aptos_runtimes::spawn_named_runtime("backup".into(), None);
```

**File:** crates/aptos-runtimes/src/lib.rs (L40-54)
```rust
    let mut builder = Builder::new_multi_thread();
    builder
        .thread_name_fn(move || {
            let id = atomic_id.fetch_add(1, Ordering::SeqCst);
            format!("{}-{}", thread_name_clone, id)
        })
        .on_thread_start(on_thread_start)
        .disable_lifo_slot()
        // Limit concurrent blocking tasks from spawn_blocking(), in case, for example, too many
        // Rest API calls overwhelm the node.
        .max_blocking_threads(MAX_BLOCKING_THREADS)
        .enable_all();
    if let Some(num_worker_threads) = num_worker_threads {
        builder.worker_threads(num_worker_threads);
    }
```

**File:** storage/backup/backup-service/src/handlers/mod.rs (L49-56)
```rust
    let state_snapshot = warp::path!(Version)
        .map(move |version| {
            reply_with_bytes_sender(&bh, STATE_SNAPSHOT, move |bh, sender| {
                bh.get_state_item_iter(version, 0, usize::MAX)?
                    .try_for_each(|record_res| sender.send_size_prefixed_bcs_bytes(record_res?))
            })
        })
        .recover(handle_rejection);
```

**File:** storage/aptosdb/src/backup/backup_handler.rs (L145-162)
```rust
    pub fn get_state_item_iter(
        &self,
        version: Version,
        start_idx: usize,
        limit: usize,
    ) -> Result<impl Iterator<Item = Result<(StateKey, StateValue)>> + Send + use<>> {
        let iterator = self
            .state_store
            .get_state_key_and_value_iter(version, start_idx)?
            .take(limit)
            .enumerate()
            .map(move |(idx, res)| {
                BACKUP_STATE_SNAPSHOT_VERSION.set(version as i64);
                BACKUP_STATE_SNAPSHOT_LEAF_IDX.set((start_idx + idx) as i64);
                res
            });
        Ok(Box::new(iterator))
    }
```

**File:** config/src/config/storage_config.rs (L436-436)
```rust
            backup_service_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 6186),
```
