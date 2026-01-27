# Audit Report

## Title
Lock Contention in Consensus Commit Path Causing Potential Validator Performance Degradation

## Summary
The `LedgerPrunerManager` uses a blocking mutex (`Arc<Mutex<Version>>`) for `latest_version` that is accessed both by the critical consensus commit path and by public API endpoints. This design creates a lock contention point where high-frequency API requests can delay consensus commits, potentially degrading validator performance.

## Finding Description

The vulnerability exists in the design of `LedgerPrunerManager` which uses a blocking mutex for tracking the latest database version. This mutex is accessed in two critical paths:

**Write Path (Consensus Commit):**
The consensus commit operation blocks on acquiring this mutex [1](#0-0) 

This is called on every block commit through the following chain:
1. Consensus waits for commit_ledger to complete [2](#0-1) 
2. Which calls the storage layer's commit_ledger [3](#0-2) 
3. Which calls post_commit that invokes the pruner [4](#0-3) 

**Read Path (Public API):**
Public API endpoints access the same mutex through the ledger info retrieval chain:
1. The root API endpoint calls get_latest_ledger_info [5](#0-4) 
2. Which retrieves oldest version information [6](#0-5) 
3. Through get_first_viable_block [7](#0-6) 
4. Which calls get_min_viable_version that locks the mutex [8](#0-7) 

The mutex implementation is a standard blocking mutex [9](#0-8) 

**Attack Scenario:**
An attacker floods public API endpoints (particularly the frequently-polled root `/` endpoint) with requests. Each request briefly acquires the `latest_version` lock. When consensus attempts to commit a block, it must acquire this same lock, potentially blocking until concurrent API requests release it. Under sustained high load, this introduces delays in the consensus commit path.

**Design Flaw:**
The `latest_version` field stores a simple `u64` value that could use atomic operations instead. In contrast, `StateKvPrunerManager` doesn't track latest_version with a mutex at all [10](#0-9) , only using atomics for min_readable_version.

## Impact Explanation

This issue falls under **High Severity** per the Aptos bug bounty program: "Validator node slowdowns."

While the lock is held briefly (single integer operations), the following factors create risk:
- Consensus commits every block (~1-2 seconds in Aptos)
- The root API endpoint is commonly polled by clients, explorers, and wallets
- The consensus commit blocks waiting for this lock acquisition
- Under high API load, lock contention can introduce delays in block commitment
- Sustained delays could cause validators to fall behind or timeout

The impact is amplified because:
1. This affects ALL validators (not just targeted nodes)
2. The API is public and accessible to any attacker
3. No rate limiting is evident in the API layer
4. The commit path explicitly waits for this operation to complete

## Likelihood Explanation

**Likelihood: Medium to High**

The vulnerability is likely to manifest under the following conditions:
- High API traffic (common for popular blockchain nodes)
- Multiple concurrent API clients polling the root endpoint
- Standard blockchain operation (frequent commits)

Factors increasing likelihood:
- The root API endpoint is one of the most frequently accessed endpoints
- No apparent rate limiting on per-IP or global API requests
- Modern applications often poll blockchain state at high frequency
- Block explorers, wallets, and monitoring tools all query this endpoint

The vulnerability doesn't require sophisticated exploitation—simple API flooding is sufficient.

## Recommendation

Replace `Arc<Mutex<Version>>` with `AtomicU64` for the `latest_version` field:

```rust
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) struct LedgerPrunerManager {
    // ... other fields ...
    latest_version: AtomicU64,  // Changed from Arc<Mutex<Version>>
    // ... other fields ...
}
```

Update `maybe_set_pruner_target_db_version()`:
```rust
fn maybe_set_pruner_target_db_version(&self, latest_version: Version) {
    self.latest_version.store(latest_version, Ordering::SeqCst);
    // ... rest of function ...
}
```

Update `get_min_viable_version()`:
```rust
fn get_min_viable_version(&self) -> Version {
    let min_version = self.get_min_readable_version();
    if self.is_pruner_enabled() {
        let adjusted_window = self
            .prune_window
            .saturating_sub(self.user_pruning_window_offset);
        let latest = self.latest_version.load(Ordering::SeqCst);
        let adjusted_cutoff = latest.saturating_sub(adjusted_window);
        std::cmp::max(min_version, adjusted_cutoff)
    } else {
        min_version
    }
}
```

This eliminates lock contention entirely while maintaining thread-safety. `SeqCst` ordering ensures proper synchronization across threads.

## Proof of Concept

```rust
// Stress test demonstrating lock contention
// This would be added to storage/aptosdb/src/pruner/ledger_pruner/ledger_pruner_manager.rs as a test

#[cfg(test)]
mod lock_contention_test {
    use super::*;
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};
    
    #[test]
    fn test_api_contention_delays_commit() {
        // Create a LedgerPrunerManager (setup omitted for brevity)
        let manager = Arc::new(/* ... initialized manager ... */);
        
        // Spawn multiple threads simulating API requests
        let mut api_threads = vec![];
        for _ in 0..100 {
            let mgr = manager.clone();
            api_threads.push(thread::spawn(move || {
                for _ in 0..1000 {
                    // Simulate API call path
                    let _ = mgr.get_min_viable_version();
                }
            }));
        }
        
        // Measure commit path latency under load
        let mgr = manager.clone();
        let commit_thread = thread::spawn(move || {
            let mut max_latency = Duration::from_nanos(0);
            for version in 1..100 {
                let start = Instant::now();
                mgr.maybe_set_pruner_target_db_version(version);
                let latency = start.elapsed();
                max_latency = max_latency.max(latency);
            }
            max_latency
        });
        
        // Wait for completion
        for t in api_threads {
            t.join().unwrap();
        }
        let max_latency = commit_thread.join().unwrap();
        
        // Under mutex contention, max_latency will be significantly higher
        // than the baseline (typically microseconds vs nanoseconds)
        println!("Max commit latency under API load: {:?}", max_latency);
        
        // Assert that contention is observable
        assert!(max_latency > Duration::from_micros(100), 
                "Expected observable lock contention");
    }
}
```

**Notes**

The vulnerability stems from unnecessary use of a blocking mutex in a hot path shared between consensus operations and public API endpoints. While individual lock operations are brief, the combination of high API request frequency and critical consensus timing creates a performance degradation vector. The fix is straightforward—replacing the mutex with atomic operations eliminates contention while maintaining correctness.

### Citations

**File:** storage/aptosdb/src/pruner/ledger_pruner/ledger_pruner_manager.rs (L58-58)
```rust
            let adjusted_cutoff = self.latest_version.lock().saturating_sub(adjusted_window);
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/ledger_pruner_manager.rs (L66-67)
```rust
    fn maybe_set_pruner_target_db_version(&self, latest_version: Version) {
        *self.latest_version.lock() = latest_version;
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L1098-1104)
```rust
        tokio::task::spawn_blocking(move || {
            executor
                .commit_ledger(ledger_info_with_sigs_clone)
                .map_err(anyhow::Error::from)
        })
        .await
        .expect("spawn blocking failed")?;
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L110-110)
```rust
            self.post_commit(old_committed_ver, version, ledger_info_with_sigs, chunk_opt)
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L628-629)
```rust
            self.ledger_pruner
                .maybe_set_pruner_target_db_version(version);
```

**File:** api/src/index.rs (L31-34)
```rust
    async fn get_ledger_info(&self, accept_type: AcceptType) -> BasicResult<IndexResponse> {
        self.context
            .check_api_output_enabled("Get ledger info", &accept_type)?;
        let ledger_info = self.context.get_latest_ledger_info()?;
```

**File:** api/src/context.rs (L238-238)
```rust
            .get_first_viable_block()
```

**File:** api/src/context.rs (L253-253)
```rust
        let (oldest_version, oldest_block_height) = self.get_oldest_version_and_block_height()?;
```

**File:** crates/aptos-infallible/src/mutex.rs (L18-23)
```rust
    /// lock the mutex
    pub fn lock(&self) -> MutexGuard<'_, T> {
        self.0
            .lock()
            .expect("Cannot currently handle a poisoned lock")
    }
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_pruner_manager.rs (L26-27)
```rust
    /// The minimal readable version for the ledger data.
    min_readable_version: AtomicVersion,
```
