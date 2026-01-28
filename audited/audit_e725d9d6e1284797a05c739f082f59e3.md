# Audit Report

## Title
Critical Error Handling Flaw in Consensus Pipeline Allows State Divergence When Database Commit Fails

## Summary
The `notify_state_sync` function in the consensus pipeline contains a critical pattern matching flaw that fails to catch errors from `commit_ledger` when they are wrapped in `TaskError::PropagatedError`. This causes the validator to notify state sync of committed transactions that were never persisted to storage, leading to state divergence between validators.

## Finding Description

The vulnerability exists in the error propagation chain between the `commit_ledger` and `notify_state_sync` functions in the consensus pipeline.

**Error Propagation Chain:**

When `commit_ledger` executes the database write operation, any failure from the executor (disk I/O errors, database corruption, etc.) is converted to `anyhow::Error` and then to `TaskError::InternalError` via the `From` trait implementation: [1](#0-0) 

The `commit_ledger` function calls the executor's commit operation in a blocking task: [2](#0-1) 

However, `commit_ledger` is spawned via `spawn_shared_fut`: [3](#0-2) 

The `spawn_shared_fut` function wraps `InternalError` and `JoinError` into `PropagatedError`: [4](#0-3) 

This means when `commit_ledger` returns `TaskError::InternalError`, it becomes `TaskError::PropagatedError(Box::new(TaskError::InternalError(...)))`.

**The Critical Flaw:**

In `notify_state_sync`, the error check only matches direct `InternalError`, not `PropagatedError`: [5](#0-4) 

The pattern `Err(e @ TaskError::InternalError(_))` at line 1160 only matches direct `InternalError`, not `PropagatedError(InternalError(...))`. When the pattern fails to match, execution continues to line 1164 and proceeds to notify state sync of transactions that were never committed to storage.

**Invariant Violations:**
- **State Consistency**: Validators diverge on committed state - some have the block in storage, others don't
- **Consensus Safety**: Different validators believe different blocks are committed
- **Storage Integrity**: In-memory state diverges from persistent storage state

**Attack Scenario:**
1. Validator V1 successfully executes and pre-commits block B
2. `commit_ledger` attempts to write to database but fails (disk full/I/O error) 
3. Error is converted: `ExecutorError` → `anyhow::Error` → `TaskError::InternalError` → `TaskError::PropagatedError(InternalError(...))`
4. `notify_state_sync` pattern match at line 1160 fails to catch `PropagatedError`
5. Execution continues to line 1164, state sync is notified block B is committed
6. But block B is NOT in V1's storage
7. V1 has divergent state from validators that successfully committed block B

## Impact Explanation

**Critical Severity** - Consensus/Safety Violation

This vulnerability breaks the fundamental consensus safety guarantee that all honest validators maintain consistent committed state. The impact qualifies as **Critical** under the Aptos bug bounty program (up to $1,000,000) because it enables:

**Consensus/Safety Violations:**
- Different validators have different ledger states for the same block height
- The failing validator cannot serve valid Merkle proofs for blocks it claims are committed
- State sync operates on incorrect information, potentially propagating bad state
- Violates the core consensus invariant that all honest validators agree on committed blocks

**State Inconsistencies:**
- In-memory consensus state diverges from persistent storage state
- The validator believes it has committed blocks that don't exist in storage
- Recovery mechanisms may fail due to inconsistent state assumptions

**Potential Network Partition:**
- The affected validator effectively detaches from consensus due to state divergence
- Subsequent block processing may fail when building on non-existent committed state
- Could require manual intervention or hardfork to recover

This falls under the explicit "Consensus/Safety Violations" category in the Aptos bug bounty, which states: "Different validators commit different blocks" and "Chain splits without hardfork requirement."

## Likelihood Explanation

**High Likelihood** - Natural System Failures

This vulnerability can be triggered through common production failure scenarios:

**Natural Triggers:**
- **Disk exhaustion**: Validators processing high transaction volumes can fill disk space
- **I/O errors**: Hardware failures, disk corruption, bad sectors
- **Database write failures**: Lock contention, corruption, filesystem issues
- **Permission errors**: Misconfigured filesystem permissions

**Frequency Assessment:**
- Production blockchain validators are long-running systems that inevitably encounter storage issues
- Disk space management is a common operational challenge in blockchain networks
- Hardware failures occur naturally in distributed validator infrastructure
- The bug is latent in every single block commit operation

**No Attacker Required:**
- This is a robustness bug, not an exploit
- Does not require any malicious actor to trigger
- Occurs naturally under system stress or hardware failure
- Cannot be prevented by validator operators through normal security practices

The likelihood is HIGH because:
1. The trigger condition (storage failure) is common in production
2. The bug affects every block commit operation
3. No special circumstances or timing is required
4. The error path is a normal code execution path when storage fails

## Recommendation

Fix the pattern match in `notify_state_sync` to handle both direct `InternalError` and wrapped `PropagatedError` cases:

```rust
async fn notify_state_sync(
    pre_commit_fut: TaskFuture<PreCommitResult>,
    commit_ledger_fut: TaskFuture<CommitLedgerResult>,
    parent_notify_state_sync_fut: TaskFuture<PostCommitResult>,
    state_sync_notifier: Arc<dyn ConsensusNotificationSender>,
    block: Arc<Block>,
) -> TaskResult<NotifyStateSyncResult> {
    let mut tracker = Tracker::start_waiting("notify_state_sync", &block);
    let compute_result = pre_commit_fut.await?;
    parent_notify_state_sync_fut.await?;
    
    // Check for errors from commit ledger, handling both direct and wrapped errors
    match commit_ledger_fut.await {
        Err(e @ TaskError::InternalError(_)) => {
            return Err(TaskError::PropagatedError(Box::new(e)));
        },
        Err(TaskError::PropagatedError(inner)) => {
            // Unwrap and check if it's an InternalError
            match inner.as_ref() {
                TaskError::InternalError(_) | TaskError::JoinError(_) => {
                    return Err(TaskError::PropagatedError(inner));
                },
                _ => {}, // Continue for other propagated errors
            }
        },
        _ => {}, // Ok or other errors - continue
    }

    tracker.start_working();
    let txns = compute_result.transactions_to_commit().to_vec();
    let subscribable_events = compute_result.subscribable_events().to_vec();
    if let Err(e) = monitor!(
        "notify_state_sync",
        state_sync_notifier
            .notify_new_commit(txns, subscribable_events)
            .await
    ) {
        error!(error = ?e, "Failed to notify state synchronizer");
    }

    Ok(())
}
```

**Alternative Fix:** Modify `spawn_shared_fut` to not wrap `InternalError` when spawning critical operations like `commit_ledger`, or add special handling for errors that should never be ignored.

## Proof of Concept

This vulnerability manifests when database commit operations fail. A test demonstrating this would require:

1. Mock the storage layer to return errors during `commit_ledger`
2. Execute a block through the consensus pipeline
3. Verify that `notify_state_sync` completes successfully despite the storage failure
4. Confirm that state sync was notified even though storage doesn't contain the block

The vulnerability is evident from code inspection - the pattern match at line 1160 demonstrably fails to catch `PropagatedError` wrapped errors, allowing execution to continue to the state sync notification at line 1169.

## Notes

This is a **logic vulnerability** in error handling, not a directly exploitable attack vector. The core issue is that the code pattern does not account for the error wrapping behavior introduced by `spawn_shared_fut`. The comment at lines 1157-1159 indicates the intent was to catch internal errors from commit ledger, but the implementation fails to do so when errors are wrapped.

The severity remains Critical because it violates consensus safety guarantees and can cause state divergence between validators during normal production failures.

### Citations

**File:** consensus/consensus-types/src/pipelined_block.rs (L63-67)
```rust
impl From<Error> for TaskError {
    fn from(value: Error) -> Self {
        Self::InternalError(Arc::new(value))
    }
}
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L155-167)
```rust
    async move {
        match join_handle.await {
            Ok(Ok(res)) => Ok(res),
            Ok(e @ Err(TaskError::PropagatedError(_))) => e,
            Ok(Err(e @ TaskError::InternalError(_) | e @ TaskError::JoinError(_))) => {
                Err(TaskError::PropagatedError(Box::new(e)))
            },
            Err(e) => Err(TaskError::JoinError(Arc::new(e))),
        }
    }
    .boxed()
    .shared()
}
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L547-556)
```rust
        let commit_ledger_fut = spawn_shared_fut(
            Self::commit_ledger(
                pre_commit_fut.clone(),
                commit_proof_fut,
                parent.commit_ledger_fut.clone(),
                self.executor.clone(),
                block.clone(),
            ),
            None,
        );
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L1098-1105)
```rust
        tokio::task::spawn_blocking(move || {
            executor
                .commit_ledger(ledger_info_with_sigs_clone)
                .map_err(anyhow::Error::from)
        })
        .await
        .expect("spawn blocking failed")?;
        Ok(Some(ledger_info_with_sigs))
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L1157-1177)
```rust
        // if commit ledger is aborted, it's typically an abort caused by reset to fall back to state sync
        // we want to finish notifying already pre-committed txns before go into state sync
        // so only return if there's internal error from commit ledger
        if let Err(e @ TaskError::InternalError(_)) = commit_ledger_fut.await {
            return Err(TaskError::PropagatedError(Box::new(e)));
        }

        tracker.start_working();
        let txns = compute_result.transactions_to_commit().to_vec();
        let subscribable_events = compute_result.subscribable_events().to_vec();
        if let Err(e) = monitor!(
            "notify_state_sync",
            state_sync_notifier
                .notify_new_commit(txns, subscribable_events)
                .await
        ) {
            error!(error = ?e, "Failed to notify state synchronizer");
        }

        Ok(())
    }
```
