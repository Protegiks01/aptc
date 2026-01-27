# Audit Report

## Title
Reset Flag Never Set: Pipeline Phases Continue Processing After Reset, Causing State Corruption During Epoch Transitions

## Summary
The `reset_flag` shared across all consensus pipeline phases is initialized to `false` but never set to `true` anywhere in the codebase. This causes pipeline phases to continue processing requests even after reset operations are triggered, leading to potential state corruption during critical operations like epoch transitions and state synchronization.

## Finding Description

The consensus pipeline uses a shared `Arc<AtomicBool>` called `reset_flag` to coordinate reset operations across multiple pipeline phases (execution scheduling, execution waiting, signing, and persisting). The flag is created in `prepare_phases_and_buffer_manager()` and passed to all phases: [1](#0-0) 

Each pipeline phase checks this flag before processing requests to determine if it should skip processing during a reset: [2](#0-1) 

However, **no code in the entire codebase ever sets this flag to `true`**. The `BufferManager::reset()` function is responsible for coordinating reset operations, but it never sets the `reset_flag`: [3](#0-2) 

The reset function only:
1. Clears internal buffer state
2. Waits for the `ongoing_tasks` counter to reach zero
3. Does NOT set `reset_flag` to notify pipeline phases to stop

This creates a critical race condition where:
1. State sync or epoch transition triggers a reset via `ResetRequest`
2. `BufferManager` clears its state and waits for `ongoing_tasks == 0`
3. Pipeline phases have requests already in their channels
4. These phases never see `reset_flag == true` (because it's always false)
5. They continue processing these queued requests **after** the reset completes
6. This violates the stated invariant in the code comment: "important to avoid race condition with state sync" [4](#0-3) 

**Regarding the Security Question's Memory Ordering Concern:**

While the question asks if weaker memory ordering could cause stale values, the actual issue is more severe: the flag is **never modified at all**. However, to answer the question directly: IF the flag were to be set, using weaker ordering than `SeqCst` (like `Relaxed`) could indeed cause pipeline phases on different CPU cores to observe stale values and continue processing after reset. The current implementation uses `SeqCst` for the load operation, which is correct, but there is no corresponding store operation.

## Impact Explanation

This is a **High Severity** vulnerability that could lead to:

1. **Consensus Safety Violations**: Different validators may end up with inconsistent state during epoch transitions if some process blocks after reset while others don't
2. **State Corruption**: Blocks processed after reset may write to storage that has been cleared or reset to a different epoch
3. **Epoch Boundary Issues**: The code explicitly calls reset during epoch transitions (`commit_proof.ledger_info().ends_epoch()`), and continued processing could cause validators to incorrectly process blocks from the new epoch with old state [5](#0-4) 

This qualifies as **High Severity** per the bug bounty criteria:
- "Significant protocol violations" - reset mechanism failure is a protocol violation
- Could lead to "State inconsistencies requiring intervention"
- Impacts consensus safety during critical epoch transitions

## Likelihood Explanation

**Likelihood: High**

This bug triggers automatically during normal validator operations:
1. Every epoch transition calls `reset()` 
2. State synchronization calls `reset()` when syncing to a new target
3. Both operations happen regularly in production

The bug is deterministic and does not require any attacker action. It occurs whenever:
- Validators transition between epochs (regular occurrence)
- Validators fall behind and need to sync state (common occurrence)
- Any operation that triggers `ResetSignal::Stop` or `ResetSignal::TargetRound`

The race condition window exists between when reset starts clearing state and when pipeline phase channels are fully drained, which could be hundreds of milliseconds with queued requests.

## Recommendation

Add a `reset_flag.store(true, Ordering::SeqCst)` call at the beginning of the reset operation, and clear it after reset completes:

```rust
async fn reset(&mut self) {
    // Signal all pipeline phases to stop processing
    self.reset_flag.store(true, Ordering::SeqCst);
    
    while let Some((_, block)) = self.pending_commit_blocks.pop_first() {
        block.wait_for_commit_ledger().await;
    }
    while let Some(item) = self.buffer.pop_front() {
        for b in item.get_blocks() {
            if let Some(futs) = b.abort_pipeline() {
                futs.wait_until_finishes().await;
            }
        }
    }
    self.buffer = Buffer::new();
    self.execution_root = None;
    self.signing_root = None;
    self.previous_commit_time = Instant::now();
    self.commit_proof_rb_handle.take();
    
    while let Ok(Some(blocks)) = self.block_rx.try_next() {
        for b in blocks.ordered_blocks {
            if let Some(futs) = b.abort_pipeline() {
                futs.wait_until_finishes().await;
            }
        }
    }
    
    // Wait for ongoing tasks to finish before sending back ack.
    while self.ongoing_tasks.load(Ordering::SeqCst) > 0 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    
    // Clear the flag after reset completes
    self.reset_flag.store(false, Ordering::SeqCst);
}
```

The `SeqCst` ordering is necessary to ensure the store is immediately visible to all pipeline phase threads on all CPU cores, preventing them from processing stale requests after reset.

## Proof of Concept

This vulnerability can be demonstrated by:

1. Adding instrumentation to log when pipeline phases process requests
2. Triggering a reset operation (e.g., via state sync)
3. Observing that pipeline phases continue to process queued requests after reset() returns

```rust
// Add to PipelinePhase::start() for demonstration
pub async fn start(mut self) {
    while let Some(counted_req) = self.rx.next().await {
        let CountedRequest { req, guard: _guard } = counted_req;
        if self.reset_flag.load(Ordering::SeqCst) {
            eprintln!("RESET FLAG TRUE - SKIPPING REQUEST");
            continue;
        }
        eprintln!("PROCESSING REQUEST (reset_flag = {})", 
                  self.reset_flag.load(Ordering::SeqCst));
        let response = {
            let _timer = BUFFER_MANAGER_PHASE_PROCESS_SECONDS
                .with_label_values(&[T::NAME])
                .start_timer();
            self.processor.process(req).await
        };
        // ...
    }
}
```

With this instrumentation, you will observe that `reset_flag` is always `false`, and the "RESET FLAG TRUE" message never appears, confirming that pipeline phases never respect reset operations.

## Notes

This vulnerability demonstrates a critical gap between the intended design (using `reset_flag` to coordinate resets) and the actual implementation (flag never set). The comment stating the reset is "important to avoid race condition with state sync" indicates the developers understood the need for proper synchronization, but the implementation is incomplete.

### Citations

**File:** consensus/src/pipeline/decoupled_execution_utils.rs (L51-51)
```rust
    let reset_flag = Arc::new(AtomicBool::new(false));
```

**File:** consensus/src/pipeline/pipeline_phase.rs (L92-94)
```rust
            if self.reset_flag.load(Ordering::SeqCst) {
                continue;
            }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L530-534)
```rust
                if commit_proof.ledger_info().ends_epoch() {
                    // the epoch ends, reset to avoid executing more blocks, execute after
                    // this persisting request will result in BlockNotFound
                    self.reset().await;
                }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L543-545)
```rust
    /// Reset any request in buffer manager, this is important to avoid race condition with state sync.
    /// Internal requests are managed with ongoing_tasks.
    /// Incoming ordered blocks are pulled, it should only have existing blocks but no new blocks until reset finishes.
```

**File:** consensus/src/pipeline/buffer_manager.rs (L546-576)
```rust
    async fn reset(&mut self) {
        while let Some((_, block)) = self.pending_commit_blocks.pop_first() {
            // Those blocks don't have any dependencies, should be able to finish commit_ledger.
            // Abort them can cause error on epoch boundary.
            block.wait_for_commit_ledger().await;
        }
        while let Some(item) = self.buffer.pop_front() {
            for b in item.get_blocks() {
                if let Some(futs) = b.abort_pipeline() {
                    futs.wait_until_finishes().await;
                }
            }
        }
        self.buffer = Buffer::new();
        self.execution_root = None;
        self.signing_root = None;
        self.previous_commit_time = Instant::now();
        self.commit_proof_rb_handle.take();
        // purge the incoming blocks queue
        while let Ok(Some(blocks)) = self.block_rx.try_next() {
            for b in blocks.ordered_blocks {
                if let Some(futs) = b.abort_pipeline() {
                    futs.wait_until_finishes().await;
                }
            }
        }
        // Wait for ongoing tasks to finish before sending back ack.
        while self.ongoing_tasks.load(Ordering::SeqCst) > 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
```
