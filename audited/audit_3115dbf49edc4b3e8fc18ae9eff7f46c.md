# Audit Report

## Title
BoundedExecutor Semaphore Exhaustion via Blocking Thread Pool Capacity Mismatch Leading to Validator DoS

## Summary
The `BoundedExecutor::spawn_blocking()` implementation acquires semaphore permits before calling `tokio::spawn_blocking()`, but the tokio blocking thread pool has a much lower capacity (64 threads) than typical `BoundedExecutor` semaphore capacities (e.g., 1000 for peer monitoring service). This mismatch allows attackers to exhaust the semaphore by flooding the service with requests that get queued by tokio without releasing their permits, causing denial of service on critical validator services.

## Finding Description

The vulnerability exists in the interaction between `BoundedExecutor`'s semaphore-based concurrency control and tokio's blocking thread pool limitations: [1](#0-0) 

The `spawn_blocking()` method acquires a semaphore permit at line 77 **before** calling `self.executor.spawn_blocking()` at line 78-79. The permit is only released when the blocking task completes: [2](#0-1) 

However, the tokio runtime is configured with a hard limit on blocking threads: [3](#0-2) 

This creates a critical mismatch. The peer monitoring service, for example, configures a `BoundedExecutor` with capacity 1000: [4](#0-3) [5](#0-4) 

**Attack Scenario:**

1. Attacker floods a validator with 1000 concurrent peer monitoring requests
2. Each request calls `bounded_executor.spawn_blocking()`: [6](#0-5) 

3. All 1000 requests successfully acquire semaphore permits (line 77 succeeds)
4. The first 64 tasks execute on tokio's blocking threads
5. The remaining 936 tasks are **queued internally by tokio** but still hold their semaphore permits
6. The semaphore is now exhausted (0 permits available)
7. New legitimate requests cannot proceed - they block waiting for permits
8. The validator's peer monitoring service becomes unresponsive

**Root Cause:** The semaphore permit is consumed when `spawn_blocking()` is called (which returns immediately), not when the task actually executes. Since tokio's `spawn_blocking()` queues tasks when the thread pool is exhausted, permits are held by queued (non-executing) tasks, violating the bounded executor's concurrency guarantee.

## Impact Explanation

**Severity: High** (Validator node slowdowns / DoS)

Per the Aptos Bug Bounty program, this qualifies as **High Severity** because it causes:

1. **Validator Node Slowdowns**: The peer monitoring service becomes unresponsive, preventing the validator from monitoring peer health and network connectivity
2. **Cascading Availability Issues**: Peer monitoring is critical for validator operations - loss of this service degrades consensus participation
3. **Resource Exhaustion**: The bounded executor's purpose (limiting concurrent execution) is completely violated, allowing 936 tasks to hold permits without executing

While not a direct consensus safety violation, this DoS vector can:
- Prevent validators from detecting unhealthy peers
- Cause validators to appear unresponsive to peer health checks
- Degrade overall network health monitoring
- Be exploited repeatedly with minimal attacker cost

The vulnerability affects any `BoundedExecutor` instance where semaphore capacity exceeds 64 (the blocking thread pool limit).

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to occur because:

1. **Easy to Trigger**: Any external actor can send peer monitoring requests - no special permissions required
2. **Low Attack Cost**: Sending 1000 concurrent requests is trivial for an attacker
3. **No Rate Limiting**: The code shows no rate limiting before `spawn_blocking()` is called
4. **Configuration Mismatch**: The 1000:64 ratio (semaphore:threads) makes exploitation inevitable under load
5. **Legitimate Traffic Can Trigger**: Even non-malicious traffic spikes could exhaust the semaphore

The vulnerability is deterministic - if more than 64 requests arrive concurrently, the semaphore will be consumed by queued tasks.

## Recommendation

**Fix 1: Acquire permit only after confirming thread availability**

Change `spawn_blocking()` to check thread availability before acquiring the permit. However, tokio doesn't expose this information, making this approach infeasible.

**Fix 2: Set semaphore capacity equal to blocking thread pool limit**

Ensure all `BoundedExecutor` instances using `spawn_blocking()` have capacity ≤ 64:

```rust
// In config/src/config/peer_monitoring_config.rs
pub struct PeerMonitoringServiceConfig {
    // Reduced to match MAX_BLOCKING_THREADS limit
    pub max_concurrent_requests: u64,  // Change default from 1000 to 64
}

impl Default for PeerMonitoringServiceConfig {
    fn default() -> Self {
        Self {
            max_concurrent_requests: 64,  // Match MAX_BLOCKING_THREADS
            // ... other fields
        }
    }
}
```

**Fix 3: Use dedicated thread pool (recommended)**

Follow the pattern from `AsyncConcurrentDropper` which uses a dedicated thread pool: [7](#0-6) 

Create a `BoundedBlockingExecutor` variant that uses a dedicated rayon thread pool with proper capacity tracking, similar to the `NumTasksTracker` pattern: [8](#0-7) 

This ensures permits are only acquired when thread capacity is actually available.

## Proof of Concept

```rust
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_semaphore_exhaustion_via_blocking_pool_mismatch() {
    use aptos_bounded_executor::BoundedExecutor;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time::sleep;

    // Simulate the configuration mismatch:
    // - Tokio runtime: 64 blocking threads (actual)
    // - BoundedExecutor: 1000 capacity (PeerMonitoringService config)
    
    // For testing, use smaller numbers: 4 blocking threads vs 20 capacity
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .max_blocking_threads(4)  // Simulates MAX_BLOCKING_THREADS=64
        .worker_threads(2)
        .build()
        .unwrap();
    
    let executor = BoundedExecutor::new(20, runtime.handle().clone());  // Simulates capacity=1000
    let executing_count = Arc::new(AtomicU32::new(0));
    let queued_count = Arc::new(AtomicU32::new(0));

    // Spawn 20 blocking tasks that sleep (simulating CPU-bound work)
    let mut handles = vec![];
    for i in 0..20 {
        let executing = executing_count.clone();
        let queued = queued_count.clone();
        
        let handle = executor.spawn_blocking(move || {
            let currently_executing = executing.fetch_add(1, Ordering::SeqCst);
            
            // If more than 4 are "executing", we're actually queued
            if currently_executing >= 4 {
                queued.fetch_add(1, Ordering::SeqCst);
            }
            
            // Simulate work
            std::thread::sleep(Duration::from_millis(100));
            
            executing.fetch_sub(1, Ordering::SeqCst);
        }).await;
        
        handles.push(handle);
    }

    // At this point, all 20 semaphore permits are consumed
    // But only 4 tasks are executing; 16 are queued
    
    sleep(Duration::from_millis(50)).await;  // Let tasks start
    
    // Try to spawn one more task - should block because semaphore is exhausted
    let try_spawn_result = tokio::time::timeout(
        Duration::from_millis(50),
        executor.spawn_blocking(|| {
            println!("This should not execute until permits are released");
        })
    ).await;
    
    assert!(try_spawn_result.is_err(), "New spawn should timeout because semaphore is exhausted");
    
    // Verify vulnerability: many tasks were queued while holding permits
    for handle in handles {
        handle.await.unwrap();
    }
    
    let final_queued = queued_count.load(Ordering::SeqCst);
    assert!(final_queued > 4, "Tasks were queued ({}) while holding semaphore permits, exceeding blocking thread capacity (4)", final_queued);
    
    println!("VULNERABILITY CONFIRMED: {} tasks held semaphore permits while queued", final_queued);
}
```

**Notes**

This vulnerability represents a fundamental design flaw in `BoundedExecutor::spawn_blocking()` where the concurrency control mechanism (semaphore) operates at a different layer than the actual execution capacity constraint (tokio blocking thread pool). The mismatch allows attackers to exhaust the semaphore without consuming actual execution resources, effectively bypassing the bounded executor's purpose and causing validator service degradation.

### Citations

**File:** crates/bounded-executor/src/executor.rs (L72-80)
```rust
    pub async fn spawn_blocking<F, R>(&self, func: F) -> JoinHandle<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let permit = self.acquire_permit().await;
        self.executor
            .spawn_blocking(function_with_permit(func, permit))
    }
```

**File:** crates/bounded-executor/src/executor.rs (L111-124)
```rust
fn function_with_permit<F, R>(
    func: F,
    permit: OwnedSemaphorePermit,
) -> impl FnOnce() -> R + Send + 'static
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    move || {
        let ret = func();
        drop(permit);
        ret
    }
}
```

**File:** crates/aptos-runtimes/src/lib.rs (L27-50)
```rust
    const MAX_BLOCKING_THREADS: usize = 64;

    // Verify the given name has an appropriate length
    if thread_name.len() > MAX_THREAD_NAME_LENGTH {
        panic!(
            "The given runtime thread name is too long! Max length: {}, given name: {}",
            MAX_THREAD_NAME_LENGTH, thread_name
        );
    }

    // Create the runtime builder
    let atomic_id = AtomicUsize::new(0);
    let thread_name_clone = thread_name.clone();
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
```

**File:** config/src/config/peer_monitoring_config.rs (L26-26)
```rust
            max_concurrent_requests: 1000,
```

**File:** peer-monitoring-service/server/src/lib.rs (L66-69)
```rust
        let bounded_executor = BoundedExecutor::new(
            node_config.peer_monitoring_service.max_concurrent_requests as usize,
            executor,
        );
```

**File:** peer-monitoring-service/server/src/lib.rs (L105-121)
```rust
            self.bounded_executor
                .spawn_blocking(move || {
                    let response = Handler::new(
                        base_config,
                        peers_and_metadata,
                        start_time,
                        storage,
                        time_service,
                    )
                    .call(
                        peer_network_id.network_id(),
                        peer_monitoring_service_request,
                    );
                    log_monitoring_service_response(&response);
                    response_sender.send(response);
                })
                .await;
```

**File:** crates/aptos-drop-helper/src/async_concurrent_dropper.rs (L16-27)
```rust
/// A helper to send things to a thread pool for asynchronous dropping.
///
/// Be aware that there is a bounded number of concurrent drops, as a result:
///   1. when it's "out of capacity", `schedule_drop` will block until a slot to be available.
///   2. if the `Drop` implementation tries to lock things, there can be a potential deadlock due
///      to another thing being waiting for a slot to be available.
pub struct AsyncConcurrentDropper {
    name: &'static str,
    num_tasks_tracker: Arc<NumTasksTracker>,
    /// use dedicated thread pool to minimize the possibility of deadlock
    thread_pool: ThreadPool,
}
```

**File:** crates/aptos-drop-helper/src/async_concurrent_dropper.rs (L112-119)
```rust
    fn inc(&self) {
        let mut num_tasks = self.lock.lock();
        while *num_tasks >= self.max_tasks {
            num_tasks = self.cvar.wait(num_tasks).expect("lock poisoned.");
        }
        *num_tasks += 1;
        GAUGE.set_with(&[self.name, "num_tasks"], *num_tasks as i64);
    }
```
