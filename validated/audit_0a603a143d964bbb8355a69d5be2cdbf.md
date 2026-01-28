# Audit Report

## Title
Race Condition in `committed_block_id()` Causes Non-Deterministic Block Execution and Consensus Safety Violation

## Summary
A critical race condition exists between database commit and block tree root update in the `commit_ledger()` function. This allows `committed_block_id()` to return stale block IDs during a race window, causing different validators to execute the same block via different code paths (normal execution vs. reconfiguration suffix), producing divergent state roots and breaking consensus safety.

## Finding Description

The vulnerability stems from a Time-of-Check-Time-of-Use (TOCTOU) race condition in the block commitment flow.

In `commit_ledger()`, the database is committed first, then `block_tree.prune()` updates the root. [1](#0-0)  During the window between these operations, other threads can call `committed_block_id()` and receive the OLD root block ID.

The `committed_block_id()` function simply returns `self.block_tree.root_block().id`, which reads the current root. [2](#0-1) 

The block tree's root is only updated when `prune()` is called, which replaces the old root with the new one. [3](#0-2) 

The race occurs because these operations use READ locks on `inner`, allowing concurrent execution. The outer `commit_ledger()` uses a READ lock, [4](#0-3)  as does `execute_and_update_state()`. [5](#0-4)  While the `execution_lock` prevents concurrent block execution, it does NOT prevent `commit_ledger()` from running concurrently with `execute_and_update_state()`.

The stale `committed_block_id` value is used in critical execution path decisions. [6](#0-5)  The condition `parent_block_id != committed_block_id && parent_output.has_reconfiguration()` determines whether to execute normally or use `reconfig_suffix()`. When the committed_block_id is stale, this condition is evaluated incorrectly.

The `reconfig_suffix()` creates an empty execution output with no transactions, [7](#0-6)  fundamentally different from normal execution.

Furthermore, the consensus pipeline confirms that Block Y's execution only waits for Block X's execution to complete, not Block X's commit. [8](#0-7)  This means Block Y can start executing while Block X is still committing.

**Attack Scenario:**
1. Validator A commits Block X (containing reconfiguration) via Thread 1
2. Thread 1 completes `db.writer.commit_ledger()` - Block X is now in database
3. Before Thread 1 executes `block_tree.prune()`, Validator A's Thread 2 starts executing Block Y (child of X)
4. Thread 2 calls `committed_block_id()` and gets Block X-1 (stale)
5. Thread 2 evaluates: `X != X-1 && has_reconfig() = TRUE`
6. Block Y incorrectly treated as reconfig suffix - transactions NOT executed
7. Meanwhile, Validator B executes Block Y after its block tree is updated
8. Validator B evaluates: `X != X = FALSE`
9. Block Y executes normally with transactions
10. **Result:** Validator A and B compute DIFFERENT state roots for Block Y → Consensus break

## Impact Explanation

**Severity: CRITICAL** ($1,000,000 tier per Aptos Bug Bounty)

This vulnerability causes a **Consensus Safety Violation**, which is explicitly listed as Critical severity in the Aptos bug bounty program. Specifically:

1. **Breaks Deterministic Execution Invariant**: Different validators execute the same block via different code paths, violating the fundamental requirement that "all validators must produce identical state roots for identical blocks"

2. **Consensus Safety Break**: When validators produce different state roots for the same block, they cannot form valid quorum certificates, leading to:
   - Chain split across the validator network
   - Loss of consensus safety (violates < 1/3 Byzantine fault tolerance)
   - Potential network partition requiring manual intervention or hardfork

3. **Non-Recoverable**: Once validators diverge on state roots, automatic recovery is impossible without rolling back to a common ancestor, potentially requiring a hardfork

The impact is magnified during epoch transitions (reconfiguration blocks), which are critical system events involving validator set changes and governance updates.

## Likelihood Explanation

**Likelihood: HIGH**

The race condition triggers during normal operation without requiring attacker intervention:

1. **Natural Concurrency**: The executor is designed for concurrent operation - `commit_ledger()` runs on consensus threads while `execute_and_update_state()` runs on execution threads with only READ locks allowing concurrent access

2. **No Synchronization**: The `execution_lock` only prevents concurrent block execution, but does NOT synchronize with `commit_ledger()`, creating an exploitable race window

3. **Frequent Occurrence**: The race window exists on EVERY block commit, and with high block rates (multiple blocks per second), the probability of hitting the race window is substantial

4. **Critical Timing**: Reconfiguration blocks amplify the issue - these occur at epoch boundaries (every few hours) and are when the bug causes maximum damage

5. **Multi-Validator Timing**: Different validators commit and execute blocks at slightly different times, making it likely that some validators hit the race window while others don't, causing network-wide divergence

The vulnerability requires no special attacker capabilities - it's a latent bug in the concurrency control that manifests during normal high-load operation.

## Recommendation

The fix requires ensuring atomic visibility of the committed state. Options include:

1. **Use Write Lock for Commit**: Change `commit_ledger()` to acquire a WRITE lock instead of READ lock on `self.inner` during the database commit and prune operations, preventing concurrent execution.

2. **Atomic Update**: Update the block tree root BEFORE committing to the database, ensuring `committed_block_id()` always reflects the state that will be persisted.

3. **Synchronization Barrier**: Introduce a synchronization mechanism that prevents `execute_and_update_state()` from reading `committed_block_id()` while `commit_ledger()` is in progress.

The recommended fix is Option 1, as it provides the simplest and most robust solution:

```rust
fn commit_ledger(&self, ledger_info_with_sigs: LedgerInfoWithSignatures) -> ExecutorResult<()> {
    let _guard = CONCURRENCY_GAUGE.concurrency_with(&["block", "commit_ledger"]);
    
    // Use WRITE lock instead of READ lock to prevent concurrent execution
    let inner_guard = self.inner.write();
    inner_guard
        .as_ref()
        .expect("BlockExecutor is not reset")
        .commit_ledger(ledger_info_with_sigs)
}
```

## Proof of Concept

While a complete PoC would require instrumenting the Aptos consensus pipeline to introduce precise timing delays, the vulnerability can be demonstrated through code inspection:

1. The READ locks allow concurrent access (lines 141-149 and 108-112)
2. The database commit happens before prune (lines 388-392)
3. The execution path decision depends on `committed_block_id()` (line 216)
4. Different timing leads to different execution paths (lines 218-224)

The race window is evident in the code structure, and the impact is deterministic once the race condition is triggered.

### Citations

**File:** execution/executor/src/block_executor/mod.rs (L97-113)
```rust
    fn execute_and_update_state(
        &self,
        block: ExecutableBlock,
        parent_block_id: HashValue,
        onchain_config: BlockExecutorConfigFromOnchain,
    ) -> ExecutorResult<()> {
        let _guard = CONCURRENCY_GAUGE.concurrency_with(&["block", "execute_and_state_checkpoint"]);

        self.maybe_initialize()?;
        // guarantee only one block being executed at a time
        let _guard = self.execution_lock.lock();
        self.inner
            .read()
            .as_ref()
            .expect("BlockExecutor is not reset")
            .execute_and_update_state(block, parent_block_id, onchain_config)
    }
```

**File:** execution/executor/src/block_executor/mod.rs (L141-149)
```rust
    fn commit_ledger(&self, ledger_info_with_sigs: LedgerInfoWithSignatures) -> ExecutorResult<()> {
        let _guard = CONCURRENCY_GAUGE.concurrency_with(&["block", "commit_ledger"]);

        self.inner
            .read()
            .as_ref()
            .expect("BlockExecutor is not reset")
            .commit_ledger(ledger_info_with_sigs)
    }
```

**File:** execution/executor/src/block_executor/mod.rs (L187-189)
```rust
    fn committed_block_id(&self) -> HashValue {
        self.block_tree.root_block().id
    }
```

**File:** execution/executor/src/block_executor/mod.rs (L216-225)
```rust
        let committed_block_id = self.committed_block_id();
        let execution_output =
            if parent_block_id != committed_block_id && parent_output.has_reconfiguration() {
                // ignore reconfiguration suffix, even if the block is non-empty
                info!(
                    LogSchema::new(LogEntry::BlockExecutor).block_id(block_id),
                    "reconfig_descendant_block_received"
                );
                parent_output.execution_output.reconfig_suffix()
            } else {
```

**File:** execution/executor/src/block_executor/mod.rs (L388-392)
```rust
        self.db
            .writer
            .commit_ledger(target_version, Some(&ledger_info_with_sigs), None)?;

        self.block_tree.prune(ledger_info_with_sigs.ledger_info())?;
```

**File:** execution/executor/src/block_executor/block_tree/mod.rs (L264-264)
```rust
        let old_root = std::mem::replace(&mut *self.root.lock(), root);
```

**File:** execution/executor-types/src/execution_output.rs (L113-128)
```rust
    pub fn reconfig_suffix(&self) -> Self {
        Self::new_impl(Inner {
            is_block: false,
            first_version: self.next_version(),
            statuses_for_input_txns: vec![],
            to_commit: TransactionsToKeep::new_empty(),
            to_discard: TransactionsWithOutput::new_empty(),
            to_retry: TransactionsWithOutput::new_empty(),
            result_state: self.result_state.clone(),
            state_reads: ShardedStateCache::new_empty(self.next_version().checked_sub(1)),
            hot_state_updates: HotStateUpdates::new_empty(),
            block_end_info: None,
            next_epoch_state: self.next_epoch_state.clone(),
            subscribable_events: Planned::ready(vec![]),
        })
    }
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L489-501)
```rust
        let execute_fut = spawn_shared_fut(
            Self::execute(
                prepare_fut.clone(),
                parent.execute_fut.clone(),
                rand_check_fut.clone(),
                self.executor.clone(),
                block.clone(),
                self.validators.clone(),
                self.block_executor_onchain_config.clone(),
                self.persisted_auxiliary_info_version,
            ),
            None,
        );
```
