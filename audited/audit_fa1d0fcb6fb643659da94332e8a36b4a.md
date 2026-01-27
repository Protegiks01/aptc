# Audit Report

## Title
Commit Queue Overflow Causes Executor Panic Instead of Graceful Error Handling

## Summary
The `add_to_commit_queue()` function in SchedulerV1 uses `.expect()` on a bounded queue push operation, which will cause a panic and crash the executor if the function is called more than `num_txns` times due to a bug elsewhere in the system. This lack of defensive error handling makes the block executor fragile to logic errors and race conditions.

## Finding Description

The Scheduler's commit queue is bounded at exactly `num_txns` capacity: [1](#0-0) 

The `add_to_commit_queue()` function assumes push operations will never fail and uses `.expect()`: [2](#0-1) 

However, `ConcurrentQueue::bounded().push()` returns an error when the queue is full. Under normal operation, the `try_commit()` function enforces that at most `num_txns` transactions are committed by checking `commit_idx == self.num_txns`: [3](#0-2) 

But if a bug exists elsewhere (race condition in commit logic, double-commit, off-by-one error), and `add_to_commit_queue()` is called more than `num_txns` times, the bounded queue will be full, `push()` will return an error, and the `.expect()` will panic, crashing the executor thread.

**Contrast with SchedulerV2:** SchedulerV2 properly handles this scenario with defensive error checking: [4](#0-3) 

This demonstrates the correct pattern: check for push errors and return a `PanicError` that can be handled gracefully rather than crashing.

## Impact Explanation

This is a **Medium severity** issue per Aptos bug bounty criteria:
- **State inconsistencies requiring intervention**: If triggered, the executor panics, halting block processing and requiring node restart
- **Availability impact**: Affected validator nodes cannot process blocks until manually restarted
- **No direct fund loss or consensus safety violation**: The panic prevents incorrect state rather than corrupting it
- **Requires bug to trigger**: Not directly exploitable but makes the system fragile to other bugs

The impact aligns with "Validator node slowdowns" and "State inconsistencies requiring intervention" (Medium severity categories).

## Likelihood Explanation

**Moderate likelihood** because:
- The synchronization in `try_commit()` appears correct under current implementation
- However, concurrent systems are prone to subtle race conditions
- The code explicitly acknowledges this concern by having SchedulerV2 implement proper error handling
- Any future refactoring that introduces a bug in commit logic could trigger this
- The lack of defensive programming increases fragility to implementation errors

Factors that could trigger this:
1. Race condition in commit state management
2. Logic error allowing duplicate commits
3. Off-by-one error in transaction counting
4. Block epilogue transaction incorrectly entering commit path

## Recommendation

Replace the `.expect()` with proper error handling matching SchedulerV2's pattern:

```rust
pub fn add_to_commit_queue(&self, txn_idx: u32) -> Result<(), PanicError> {
    if let Err(e) = self.commit_queue.push(txn_idx) {
        return Err(code_invariant_error(format!(
            "Error adding {txn_idx} to commit queue, len {}, error: {:?}",
            self.commit_queue.len(),
            e
        )));
    }
    Ok(())
}
```

Update the caller in `scheduler_wrapper.rs` to propagate the error: [5](#0-4) 

Change line 71 to: `scheduler.add_to_commit_queue(txn_idx)?`

This allows graceful error handling and fallback to sequential execution rather than crashing.

## Proof of Concept

The vulnerability can be demonstrated by simulating a bug that causes extra commits:

```rust
#[test]
#[should_panic(expected = "Pushing to the commit_queue should never fail")]
fn test_commit_queue_overflow() {
    use aptos_move_block_executor::scheduler::Scheduler;
    
    let num_txns = 5;
    let scheduler = Scheduler::new(num_txns);
    
    // Simulate a bug causing num_txns + 1 commits
    for i in 0..=num_txns {
        scheduler.add_to_commit_queue(i);
    }
    // The 6th push to a queue bounded at 5 will panic
}
```

This test demonstrates that calling `add_to_commit_queue()` more than `num_txns` times causes a panic instead of returning an error that could be handled gracefully.

## Notes

This is a defensive programming issue rather than a directly exploitable vulnerability. The proper synchronization in `try_commit()` should prevent this under normal circumstances. However:

1. The existence of SchedulerV2's proper error handling indicates the development team recognizes this pattern is important
2. Consensus-critical code should be maximally defensive against implementation bugs
3. The `.expect()` pattern reduces system robustness and makes debugging harder when bugs occur
4. The Medium severity classification acknowledges this affects availability but not safety

The recommendation improves system robustness by allowing graceful degradation to sequential execution rather than crashing when unexpected conditions occur.

### Citations

**File:** aptos-move/block-executor/src/scheduler.rs (L343-343)
```rust
            commit_queue: ConcurrentQueue::<u32>::bounded(num_txns as usize),
```

**File:** aptos-move/block-executor/src/scheduler.rs (L347-351)
```rust
    pub fn add_to_commit_queue(&self, txn_idx: u32) {
        self.commit_queue
            .push(txn_idx)
            .expect("Pushing to the commit_queue should never fail");
    }
```

**File:** aptos-move/block-executor/src/scheduler.rs (L374-376)
```rust
        if *commit_idx == self.num_txns {
            return None;
        }
```

**File:** aptos-move/block-executor/src/scheduler_v2.rs (L710-716)
```rust
        if let Err(e) = self.post_commit_processing_queue.push(txn_idx) {
            return Err(code_invariant_error(format!(
                "Error adding {txn_idx} to commit queue, len {}, error: {:?}",
                self.post_commit_processing_queue.len(),
                e
            )));
        }
```

**File:** aptos-move/block-executor/src/scheduler_wrapper.rs (L68-76)
```rust
    pub(crate) fn add_to_post_commit(&self, txn_idx: TxnIndex) -> Result<(), PanicError> {
        match self {
            SchedulerWrapper::V1(scheduler, _) => {
                scheduler.add_to_commit_queue(txn_idx);
                Ok(())
            },
            SchedulerWrapper::V2(scheduler, _) => scheduler.end_commit(txn_idx),
        }
    }
```
