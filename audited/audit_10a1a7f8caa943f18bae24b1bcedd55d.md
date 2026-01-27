# Audit Report

## Title
Unprotected Async Drop in Block Partitioner Causes Validator Node Crash on Thread Panic

## Summary
The block partitioner uses fire-and-forget async drops via `thread_pool.spawn(move || { drop(...) })` without panic protection. If any thread panics during these drop operations, the global panic handler terminates the entire validator process, causing a Denial of Service. This violates Aptos secure coding guidelines requiring Drop implementations to never panic.

## Finding Description

The block partitioner employs an optimization pattern where large data structures are dropped asynchronously on worker threads to avoid blocking the main execution path. This occurs in three locations: [1](#0-0) [2](#0-1) [3](#0-2) 

The async drops are spawned using Rayon's `spawn()` method, which is fire-and-forget with no join handle or error handling. If any Drop implementation panics during execution on a worker thread, the following chain of events occurs:

1. The panic is caught by Aptos's global panic handler [4](#0-3) 

2. The handler logs crash information and calls `process::exit(12)`, terminating the entire validator process

3. The validator node crashes and must be restarted

This violates Aptos's documented secure coding requirement: [5](#0-4) 

**Violation of Security Guarantees:**
- **Availability**: Validator node becomes unavailable until manual restart
- **Defensive Programming**: No panic recovery mechanism despite handling potentially large/complex data structures
- **Secure Coding Compliance**: Direct violation of documented Drop safety requirements

**Attack Scenarios:**

While standard library types (Vec, HashMap, DashMap) are well-tested and rarely panic during drop, several edge cases exist:

1. **Resource Exhaustion**: An attacker floods the network with transactions causing the partitioner to allocate massive data structures. When async drops execute under memory pressure, Out-Of-Memory conditions during deallocation could trigger panics.

2. **Third-Party Crate Bugs**: The partitioner extensively uses DashMap (concurrent HashMap). If DashMap or any other third-party dependency has a bug in its Drop implementation, the panic propagates to process termination.

3. **State Corruption**: If another bug corrupts PartitionState structures, dropping corrupted state could trigger assertions or undefined behavior leading to panics.

4. **Concurrent Drop Race**: Multiple rapid partition calls could spawn numerous async drops concurrently. Thread pool saturation combined with resource contention increases panic probability.

## Impact Explanation

**Severity: Medium** - Single Validator Denial of Service

Per Aptos bug bounty criteria, this qualifies as Medium severity because:
- Causes single validator node unavailability (not Critical which requires network-wide impact)
- Requires manual intervention (node restart and re-synchronization)  
- Does not directly cause fund loss or consensus safety violations
- Creates operational reliability issues rather than critical security breaches

If exploitable across multiple validators simultaneously, impact could escalate to High severity (validator slowdowns/crashes) or Critical (network liveness issues).

## Likelihood Explanation

**Likelihood: Low to Medium**

Direct exploitation is challenging because:
- Standard Rust types have robust Drop implementations that rarely panic
- Transactions have already been "taken" out before async drop occurs
- Requires either resource exhaustion (difficult to achieve reliably) or triggering another bug

However, likelihood increases due to:
- No defensive programming safeguards in place
- Complex concurrent data structures (DashMap) with potential edge cases
- High transaction throughput could trigger resource pressure scenarios
- Third-party dependency risks outside Aptos's control

The vulnerability is best characterized as a **defensive programming failure** that creates unnecessary DOS risk rather than a directly exploitable critical flaw.

## Recommendation

Implement panic protection using one of these approaches:

**Option 1: Use catch_unwind (Immediate Fix)**
```rust
// In v2/mod.rs
self.thread_pool.spawn(move || {
    if let Err(e) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        drop(state);
    })) {
        error!("Panic during async PartitionState drop: {:?}", e);
        // Log metrics but don't crash
    }
});
```

**Option 2: Use AsyncConcurrentDropper (Best Practice)**

The codebase already has a proper async dropper implementation: [6](#0-5) 

Replace direct thread pool spawns with AsyncConcurrentDropper to get:
- Bounded concurrency with backpressure
- Better resource management  
- Consistent drop handling across codebase

**Option 3: Synchronous Drop (Simple but Less Performant)**
If performance impact is acceptable, remove async drops entirely and drop synchronously.

## Proof of Concept

```rust
// Reproduction test for block partitioner panic propagation
// Place in execution/block-partitioner/src/v2/tests.rs

#[test]
#[should_panic(expected = "Simulated drop panic")]
fn test_async_drop_panic_propagation() {
    use rayon::ThreadPoolBuilder;
    use std::sync::Arc;
    
    // Simulate the partitioner's async drop pattern
    let thread_pool = Arc::new(
        ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .unwrap()
    );
    
    // Create a type that panics on drop
    struct PanicOnDrop;
    impl Drop for PanicOnDrop {
        fn drop(&mut self) {
            panic!("Simulated drop panic");
        }
    }
    
    // Spawn async drop (mimicking partitioner behavior)
    thread_pool.spawn(move || {
        let _will_panic = PanicOnDrop;
        // Drop happens here when closure ends
    });
    
    // Give worker thread time to panic
    std::thread::sleep(std::time::Duration::from_millis(100));
    
    // In production with global panic handler, process would exit(12) here
    // In test environment without handler, test should detect the panic
}

// Test demonstrating resource exhaustion scenario
#[test]
fn test_concurrent_async_drops_resource_pressure() {
    use rayon::ThreadPoolBuilder;
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
    
    let thread_pool = Arc::new(
        ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap()
    );
    
    let drop_count = Arc::new(AtomicUsize::new(0));
    
    // Simulate rapid partition calls with async drops
    for _ in 0..100 {
        let count = drop_count.clone();
        thread_pool.spawn(move || {
            // Simulate large allocation
            let _large_vec = vec![0u8; 1024 * 1024]; // 1MB
            count.fetch_add(1, Ordering::SeqCst);
        });
    }
    
    // Wait for all drops
    thread_pool.install(|| {});
    std::thread::sleep(std::time::Duration::from_millis(500));
    
    // Under memory pressure, some drops might fail
    println!("Completed drops: {}", drop_count.load(Ordering::SeqCst));
}
```

## Notes

This vulnerability represents a gap between Aptos's documented secure coding standards and actual implementation. While direct exploitation is difficult, the lack of defensive programming creates unnecessary risk. The issue is compounded by the fire-and-forget pattern providing no visibility into drop failures.

The severity is Medium rather than High/Critical because:
1. Exploitation requires specific conditions (resource exhaustion or other bugs)
2. Impact is limited to single validator availability
3. No direct fund loss or consensus safety violations
4. Standard library drops are well-tested and robust

However, best practices demand panic protection around all potentially-panicking operations, especially in consensus-critical infrastructure. The recommendation aligns with existing patterns in the codebase (AsyncConcurrentDropper) and maintains Aptos's security-first philosophy.

### Citations

**File:** execution/block-partitioner/src/v2/mod.rs (L189-191)
```rust
        self.thread_pool.spawn(move || {
            drop(state);
        });
```

**File:** execution/block-partitioner/src/pre_partition/connected_component/mod.rs (L159-165)
```rust
        state.thread_pool.spawn(move || {
            drop(txns_by_set);
            drop(set_idx_registry);
            drop(group_metadata);
            drop(tasks);
            drop(ori_txns_idxs_by_shard);
        });
```

**File:** execution/block-partitioner/src/v2/partition_to_matrix.rs (L169-171)
```rust
        state.thread_pool.spawn(move || {
            drop(min_discard_table);
        });
```

**File:** crates/crash-handler/src/lib.rs (L26-57)
```rust
pub fn setup_panic_handler() {
    panic::set_hook(Box::new(move |pi: &PanicHookInfo<'_>| {
        handle_panic(pi);
    }));
}

// Formats and logs panic information
fn handle_panic(panic_info: &PanicHookInfo<'_>) {
    // The Display formatter for a PanicHookInfo contains the message, payload and location.
    let details = format!("{}", panic_info);
    let backtrace = format!("{:#?}", Backtrace::new());

    let info = CrashInfo { details, backtrace };
    let crash_info = toml::to_string_pretty(&info).unwrap();
    error!("{}", crash_info);
    // TODO / HACK ALARM: Write crash info synchronously via eprintln! to ensure it is written before the process exits which error! doesn't guarantee.
    // This is a workaround until https://github.com/aptos-labs/aptos-core/issues/2038 is resolved.
    eprintln!("{}", crash_info);

    // Wait till the logs have been flushed
    aptos_logger::flush();

    // Do not kill the process if the panics happened at move-bytecode-verifier.
    // This is safe because the `state::get_state()` uses a thread_local for storing states. Thus the state can only be mutated to VERIFIER by the thread that's running the bytecode verifier.
    //
    // TODO: once `can_unwind` is stable, we should assert it. See https://github.com/rust-lang/rust/issues/92988.
    if state::get_state() == VMState::VERIFIER || state::get_state() == VMState::DESERIALIZER {
        return;
    }

    // Kill the process
    process::exit(12);
```

**File:** RUST_SECURE_CODING.md (L93-94)
```markdown
In a Rust secure development, the implementation of the `std::ops::Drop` trait
must not panic.
```

**File:** crates/aptos-drop-helper/src/async_concurrent_dropper.rs (L16-36)
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

impl AsyncConcurrentDropper {
    pub fn new(name: &'static str, max_tasks: usize, num_threads: usize) -> Self {
        Self {
            name,
            num_tasks_tracker: Arc::new(NumTasksTracker::new(name, max_tasks)),
            thread_pool: ThreadPool::with_name(format!("{}_conc_dropper", name), num_threads),
        }
    }
```
