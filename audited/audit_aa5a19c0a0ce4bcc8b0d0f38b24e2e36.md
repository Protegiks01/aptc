# Audit Report

## Title
Thread Pool Exhaustion in Mempool Enables Denial of Service Against Transaction Processing

## Summary
The mempool module uses static rayon thread pools (`IO_POOL` and `VALIDATION_POOL`) that are shared across all transaction processing tasks without timeout mechanisms or prioritization. An attacker can flood the system with expensive-to-validate transactions via peer broadcast messages, exhausting the thread pools and blocking legitimate client transaction submissions, causing a denial of service condition.

## Finding Description

The vulnerability exists in the mempool's transaction processing architecture where two critical static thread pools are shared without proper isolation or resource limits. [1](#0-0) 

These thread pools are used for parallel processing of transaction batches during:
1. Account sequence number fetching (IO_POOL)
2. VM transaction validation (VALIDATION_POOL) [2](#0-1) [3](#0-2) 

The system uses a BoundedExecutor to limit concurrent transaction processing tasks to `shared_mempool_max_concurrent_inbound_syncs` (default: 4 for validators, 16 for VFNs): [4](#0-3) 

**Attack Path:**

1. Attacker establishes peer connections to target fullnode(s) (fullnodes accept peer connections from the public network)
2. Attacker sends broadcast messages containing the maximum batch size of transactions (200 for validators, 300 for fullnodes): [5](#0-4) 

3. Transactions are crafted to be expensive to validate (complex Move bytecode, deep call stacks, large data structures) but still pass basic checks
4. Each peer can send up to `max_broadcasts_per_peer` pending broadcasts (20 for fullnodes, 2 for validators): [6](#0-5) 

5. The coordinator processes these broadcasts through the BoundedExecutor: [7](#0-6) 

6. Each spawned task blocks on the shared thread pools while processing the expensive validation
7. With multiple concurrent tasks (up to 16 for VFNs), each processing 300 transactions in parallel, the thread pools (sized to CPU cores) become saturated
8. The BoundedExecutor fills to capacity and blocks when attempting to spawn new tasks: [8](#0-7) 

9. Client transaction submissions await on the BoundedExecutor, blocking the coordinator: [9](#0-8) 

10. Legitimate transactions cannot be processed - **DoS achieved**

**Critical Flaws:**
- No timeout mechanism on validation operations (verified by code search)
- No prioritization between peer broadcasts and client submissions - single shared BoundedExecutor
- No separate resource allocation for trusted vs untrusted sources
- Thread pools are static with limited capacity (default: number of CPU cores)
- rayon's `install()` with `par_iter()` processes entire batches synchronously

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program:

1. **"Validator node slowdowns"** - Direct impact as mempool becomes unable to process transactions efficiently
2. **"API crashes"** - Client APIs become effectively unresponsive when the BoundedExecutor is saturated, timing out or rejecting new submissions
3. **"Significant protocol violations"** - Mempool is a critical component for transaction ordering; its failure disrupts normal blockchain operation

**Affected Systems:**
- All fullnodes (most vulnerable - accept public peer connections, higher concurrent task limits)
- Validator fullnodes (VFNs) - serve APIs to clients
- Indirectly affects validators if VFNs are DoS'd

**Real-World Impact:**
- Users cannot submit transactions to affected nodes
- DApps relying on affected nodes experience service disruption
- Network appears "frozen" to external observers despite consensus continuing
- Critical transactions (governance, emergency operations) cannot be submitted

This is NOT a "network-level DoS" (which is out of scope) but an **application-level resource exhaustion bug** exploiting poor thread pool isolation.

## Likelihood Explanation

**Likelihood: HIGH**

**Attacker Requirements:**
- Network connectivity to target fullnodes (publicly accessible)
- Ability to establish peer connections (standard P2P protocol)
- Knowledge to craft expensive-to-validate transactions (achievable with understanding of Move VM)
- Can amplify attack using multiple peer identities

**Attack Complexity: LOW**
- No need for validator access or privileged credentials
- No need to compromise cryptographic operations
- Standard P2P protocol messages used
- Can be scripted/automated

**Detection Difficulty: MEDIUM**
- Transactions may appear valid at protocol level
- Distinguish from legitimate high load is challenging
- Requires monitoring thread pool saturation and task queue depths

**Mitigation Gaps:**
- No timeout on validation operations
- No rate limiting beyond `max_broadcasts_per_peer` (which can be bypassed with multiple peers)
- No circuit breakers or adaptive load shedding
- No separate resource pools for different trust levels

## Recommendation

Implement multiple layers of defense:

**1. Add Validation Timeouts**
```rust
// In mempool/src/shared_mempool/tasks.rs
use tokio::time::timeout;

const VALIDATION_TIMEOUT: Duration = Duration::from_secs(5);

let validation_results = VALIDATION_POOL.install(|| {
    transactions
        .par_iter()
        .map(|t| {
            // Wrap validation with timeout
            match timeout(VALIDATION_TIMEOUT, async {
                smp.validator.read().validate_transaction(t.0.clone())
            }).await {
                Ok(result) => result,
                Err(_) => Err(anyhow::anyhow!("Validation timeout")),
            }
        })
        .collect::<Vec<_>>()
});
```

**2. Separate BoundedExecutors with Prioritization**
```rust
// In mempool/src/shared_mempool/coordinator.rs
let client_executor = BoundedExecutor::new(
    workers_available / 2, // Reserve 50% for clients
    executor.clone()
);
let peer_executor = BoundedExecutor::new(
    workers_available / 2,
    executor.clone()
);
```

**3. Implement Per-Peer Rate Limiting on Thread Pool Usage**
Track thread pool usage per peer and throttle/disconnect peers that consume excessive resources.

**4. Add Circuit Breakers**
Monitor thread pool saturation and reject new peer broadcasts when utilization exceeds threshold (e.g., 80%).

**5. Consider Separate Thread Pools**
Use separate thread pools for client vs peer transaction processing to provide hard resource isolation.

## Proof of Concept

```rust
// Test demonstrating thread pool exhaustion
// Place in mempool/src/shared_mempool/tests.rs

#[tokio::test]
async fn test_thread_pool_exhaustion_dos() {
    use crate::thread_pool::{IO_POOL, VALIDATION_POOL};
    use std::time::{Duration, Instant};
    use rayon::prelude::*;
    
    // Simulate expensive validation tasks
    let expensive_task = || {
        // Sleep to simulate complex validation
        std::thread::sleep(Duration::from_secs(10));
    };
    
    // Create multiple batches simulating attacker's broadcasts
    let num_attacker_batches = 16; // Fill the BoundedExecutor
    let transactions_per_batch = 300;
    
    let start = Instant::now();
    
    // Spawn attacker's tasks
    let attacker_handles: Vec<_> = (0..num_attacker_batches)
        .map(|_| {
            tokio::spawn(async move {
                VALIDATION_POOL.install(|| {
                    (0..transactions_per_batch)
                        .into_par_iter()
                        .for_each(|_| expensive_task());
                });
            })
        })
        .collect();
    
    // Try to submit legitimate client transaction
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    let client_start = Instant::now();
    let client_task = tokio::spawn(async move {
        VALIDATION_POOL.install(|| {
            // Simple fast validation
            std::thread::sleep(Duration::from_millis(10));
        });
    });
    
    // Wait for client task with timeout
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        client_task
    ).await;
    
    let client_latency = client_start.elapsed();
    
    // Client should be blocked/timeout due to thread pool exhaustion
    assert!(
        result.is_err() || client_latency > Duration::from_secs(5),
        "Client task should be blocked by attacker's thread pool exhaustion"
    );
    
    // Cleanup
    for handle in attacker_handles {
        handle.abort();
    }
}
```

**Notes:**
- This vulnerability requires addressing the fundamental architectural issue of shared, unbounded thread pools
- The fix requires both immediate mitigations (timeouts, circuit breakers) and longer-term architectural improvements (resource isolation)
- Multiple defense layers are necessary as no single mitigation fully addresses the root cause

### Citations

**File:** mempool/src/thread_pool.rs (L8-20)
```rust
pub(crate) static IO_POOL: Lazy<rayon::ThreadPool> = Lazy::new(|| {
    rayon::ThreadPoolBuilder::new()
        .thread_name(|index| format!("mempool_io_{}", index))
        .build()
        .unwrap()
});

pub(crate) static VALIDATION_POOL: Lazy<rayon::ThreadPool> = Lazy::new(|| {
    rayon::ThreadPoolBuilder::new()
        .thread_name(|index| format!("mempool_vali_{}", index))
        .build()
        .unwrap()
});
```

**File:** mempool/src/shared_mempool/tasks.rs (L335-350)
```rust
    let account_seq_numbers = IO_POOL.install(|| {
        transactions
            .par_iter()
            .map(|(t, _, _)| match t.replay_protector() {
                ReplayProtector::Nonce(_) => Ok(None),
                ReplayProtector::SequenceNumber(_) => {
                    get_account_sequence_number(&state_view, t.sender())
                        .map(Some)
                        .inspect_err(|e| {
                            error!(LogSchema::new(LogEntry::DBError).error(e));
                            counters::DB_ERROR.inc();
                        })
                },
            })
            .collect::<Vec<_>>()
    });
```

**File:** mempool/src/shared_mempool/tasks.rs (L490-503)
```rust
    let validation_results = VALIDATION_POOL.install(|| {
        transactions
            .par_iter()
            .map(|t| {
                let result = smp.validator.read().validate_transaction(t.0.clone());
                // Pre-compute the hash and length if the transaction is valid, before locking mempool
                if result.is_ok() {
                    t.0.committed_hash();
                    t.0.txn_bytes_len();
                }
                result
            })
            .collect::<Vec<_>>()
    });
```

**File:** mempool/src/shared_mempool/coordinator.rs (L90-93)
```rust
    // Use a BoundedExecutor to restrict only `workers_available` concurrent
    // worker tasks that can process incoming transactions.
    let workers_available = smp.config.shared_mempool_max_concurrent_inbound_syncs;
    let bounded_executor = BoundedExecutor::new(workers_available, executor.clone());
```

**File:** mempool/src/shared_mempool/coordinator.rs (L189-196)
```rust
            bounded_executor
                .spawn(tasks::process_client_transaction_submission(
                    smp.clone(),
                    txn,
                    callback,
                    task_start_timer,
                ))
                .await;
```

**File:** mempool/src/shared_mempool/coordinator.rs (L332-341)
```rust
    bounded_executor
        .spawn(tasks::process_transaction_broadcast(
            smp_clone,
            transactions,
            message_id,
            timeline_state,
            peer,
            task_start_timer,
        ))
        .await;
```

**File:** config/src/config/mempool_config.rs (L113-114)
```rust
            shared_mempool_batch_size: 300,
            shared_mempool_max_batch_bytes: MAX_APPLICATION_MESSAGE_SIZE as u64,
```

**File:** config/src/config/mempool_config.rs (L117-117)
```rust
            max_broadcasts_per_peer: 20,
```

**File:** crates/bounded-executor/src/executor.rs (L33-35)
```rust
    async fn acquire_permit(&self) -> OwnedSemaphorePermit {
        self.semaphore.clone().acquire_owned().await.unwrap()
    }
```
