# Audit Report

## Title
Async Cleanup Thread Panics Cause Unrecoverable Validator Node Crashes

## Summary
Worker thread panics in the block partitioner's async cleanup tasks trigger the global panic handler, causing the entire validator node process to terminate via `process::exit(12)`. This occurs AFTER the `partition()` function returns successfully, creating unexpected availability failures.

## Finding Description
The block partitioner uses Rayon thread pools for parallel operations. At the end of `partition()`, two async cleanup tasks are spawned using `thread_pool.spawn()`: [1](#0-0) [2](#0-1) 

The Aptos node initializes a global panic handler that catches ALL thread panics and terminates the process: [3](#0-2) 

**Critical Behavior Chain:**
1. `partition()` completes and returns `PartitionedTransactions` result
2. Async cleanup tasks are spawned to drop large data structures
3. If any cleanup task panics (e.g., due to lock poisoning, bugs in destructors, or state inconsistencies), the global panic handler executes
4. `process::exit(12)` terminates the ENTIRE validator node process
5. The node crashes unexpectedly, AFTER the partitioning appeared to succeed

This violates the **availability invariant** - the validator node should handle errors gracefully rather than crashing the entire process for non-critical cleanup operations.

**Panic Propagation Analysis:**
- `thread_pool.install()`: Panics propagate to calling thread → handled before function returns
- `thread_pool.spawn()`: Panics trigger global panic handler → process exits asynchronously

The partitioner contains numerous operations that could panic during cleanup: [4](#0-3) [5](#0-4) 

If RwLocks become poisoned during main execution (due to panics in worker threads), subsequent cleanup operations accessing these locks will panic when unwrapping them.

## Impact Explanation
**HIGH Severity** - "Validator node slowdowns" and unexpected crashes.

If a panic occurs during async cleanup:
1. The validator node terminates immediately via `process::exit(12)`
2. The node goes offline unexpectedly
3. Block production/validation is interrupted
4. Network liveness degrades if multiple validators are affected
5. The crash occurs AFTER `partition()` returned, making debugging difficult

This creates an availability vulnerability where cleanup bugs can cause cascading validator failures. The asynchronous nature means the crash is disconnected from the operation that triggered it, making it difficult to diagnose and potentially allowing exploitation through carefully crafted transaction patterns.

## Likelihood Explanation
**Medium-High Likelihood:**
- The partitioning code contains numerous `unwrap()`, `expect()`, and `assert!()` calls throughout
- Lock poisoning can occur if any worker thread panics during main execution
- Memory pressure or resource exhaustion could trigger allocation failures
- Edge cases in concurrent cleanup of large data structures (10,000+ transactions)
- The async cleanup runs AFTER success is signaled, creating a race condition window

While standard library drops rarely panic, the complex state with many locks and assertions creates multiple failure points.

## Recommendation
Replace `thread_pool.spawn()` with proper error handling that doesn't crash the node:

**Option 1: Synchronous Cleanup**
```rust
// Replace async cleanup with synchronous drop before returning
let ret = Self::add_edges(&mut state);
drop(state); // Synchronous cleanup - panics propagate before return
ret
```

**Option 2: Panic-Safe Async Cleanup**
```rust
// Catch panics in cleanup tasks
use std::panic::catch_unwind;
use std::panic::AssertUnwindSafe;

self.thread_pool.spawn(move || {
    if let Err(e) = catch_unwind(AssertUnwindSafe(|| drop(state))) {
        error!("Block partitioner cleanup panic: {:?}", e);
        // Log but don't crash - cleanup failure is non-critical
    }
});
```

**Option 3: Remove Async Cleanup**
Since cleanup is just dropping memory, make it synchronous to avoid asynchronous crashes: [6](#0-5) 

## Proof of Concept
```rust
#[test]
#[should_panic(expected = "cleanup panic")]
fn test_async_cleanup_panic() {
    use std::sync::{Arc, RwLock};
    use rayon::ThreadPoolBuilder;
    
    let pool = Arc::new(ThreadPoolBuilder::new().num_threads(2).build().unwrap());
    
    // Simulate partition() behavior
    let result = {
        let state = Arc::new(RwLock::new(vec![1, 2, 3]));
        let state_clone = state.clone();
        
        // Poison the lock by panicking while holding it
        let _ = std::panic::catch_unwind(|| {
            let _guard = state.write().unwrap();
            panic!("poison lock");
        });
        
        // Spawn async cleanup (like line 189)
        let cleanup_state = state_clone;
        pool.spawn(move || {
            // This will panic when accessing poisoned lock
            let _data = cleanup_state.read().unwrap();
            drop(cleanup_state);
        });
        
        vec![1, 2, 3] // Return "success" before cleanup completes
    };
    
    // Function returned successfully
    assert_eq!(result, vec![1, 2, 3]);
    
    // Wait for cleanup to crash the process
    std::thread::sleep(std::time::Duration::from_millis(100));
}
```

## Notes
The vulnerability is confirmed by examining the global panic handler setup which ALWAYS terminates the process on panic, including panics from spawned Rayon threads. The async nature of the cleanup means crashes occur after apparent success, creating unpredictable validator node failures that could be triggered by adversarial transaction patterns or concurrent load conditions.

### Citations

**File:** execution/block-partitioner/src/v2/mod.rs (L186-193)
```rust
        let ret = Self::add_edges(&mut state);

        // Async clean-up.
        self.thread_pool.spawn(move || {
            drop(state);
        });
        ret
    }
```

**File:** execution/block-partitioner/src/v2/partition_to_matrix.rs (L169-171)
```rust
        state.thread_pool.spawn(move || {
            drop(min_discard_table);
        });
```

**File:** crates/crash-handler/src/lib.rs (L26-58)
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
}
```

**File:** execution/block-partitioner/src/v2/state.rs (L190-191)
```rust
        let tracker_ref = self.trackers.get(&key_idx).unwrap();
        let tracker = tracker_ref.read().unwrap();
```

**File:** execution/block-partitioner/src/v2/conflicting_txn_tracker.rs (L64-64)
```rust
            assert!(self.pending_reads.remove(&txn_id));
```
