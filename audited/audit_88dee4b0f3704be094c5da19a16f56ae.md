# Audit Report

## Title
False Positive Assertion Failures in Executor Benchmark Tool When Discards Are Allowed

## Summary
The assertions at lines 78 and 80 in `ledger_update_stage.rs` can trigger false positives when the benchmark is configured with `allow_retries = false` and `allow_discards = true`, causing legitimate benchmark runs to crash despite valid configuration.

## Finding Description
The `ledger_update()` function contains assertions that validate the relationship between input transactions and committed transactions: [1](#0-0) 

These assertions assume that the number of transactions to commit equals the number of input transactions (plus one StateCheckpoint transaction when there's no epoch change, or no extra transaction when there is an epoch change). However, this assumption only holds when **no transactions are discarded**.

The issue arises because:
1. The assertions only check `!self.allow_retries` but not `!self.allow_discards`
2. When `allow_discards = true`, transactions can legitimately be discarded during execution
3. Discarded transactions are moved to `to_discard` and not included in `to_commit` [2](#0-1) 

The transaction discard mechanism is legitimate and transactions can be discarded for various reasons like sequence number issues, insufficient balance, or validation failures: [3](#0-2) 

**Exploitation Path:**
1. Run benchmark with flags: `--allow-discards` (without `--allow-retries`)
2. Generate transactions that may be discarded (e.g., with sequence number conflicts)
3. Execution discards some transactions legitimately
4. `check_aborts_discards_retries()` passes because `allow_discards = true`
5. Assertions at lines 78-80 execute because `!allow_retries = true`
6. `num_transactions_to_commit()` is less than expected due to discards
7. Assertion fails and benchmark crashes

## Impact Explanation
This issue does **NOT** meet the Critical, High, or Medium severity criteria per the Aptos bug bounty program. This is a bug in the **executor-benchmark tool**, which is a testing/performance measurement utility, not part of the production blockchain node. 

It does not affect:
- Loss of Funds
- Consensus/Safety violations
- Network availability
- Validator node operations
- Any production blockchain functionality
- Transaction processing or execution
- State management or storage

The impact is limited to preventing certain legitimate benchmark configurations from completing successfully.

## Likelihood Explanation
This would only occur when users intentionally configure the benchmark with incompatible validation flags (`allow_discards = true` while `allow_retries = false`) and run workloads that generate discardable transactions. Given that the benchmark is a development/testing tool, not production infrastructure, the likelihood of this causing any security impact is zero.

## Recommendation
Modify the assertion condition to also check `!self.allow_discards`:

```rust
if !self.allow_retries && !self.allow_discards {
    if output.epoch_state().is_none() {
        assert_eq!(output.num_transactions_to_commit(), num_input_txns + 1);
    } else {
        assert_eq!(output.num_transactions_to_commit(), num_input_txns);
    }
}
```

This ensures the assertions only run when the configuration guarantees that all input transactions will be committed without discards or retries.

## Proof of Concept
```bash
# Run the executor benchmark with allow_discards but not allow_retries
cargo run --release -p aptos-executor-benchmark -- \
  run-executor \
  --block-size 1000 \
  --blocks 10 \
  --allow-discards \
  --data-dir /path/to/data \
  --checkpoint-dir /path/to/checkpoint

# If transactions get discarded during execution, the assertions at lines 78-80 will fail
# Expected: Benchmark completes successfully
# Actual: Panic with "assertion failed: ..." error
```

---

## Notes
**This is NOT a security vulnerability** per the strict criteria defined in the prompt. While technically a valid bug in the benchmark tool's validation logic, it:
- Does not affect blockchain consensus, safety, or liveness
- Does not impact production validator nodes or network operation
- Does not enable any attacks on funds, state, or governance
- Is confined to a testing/benchmarking utility

According to the validation checklist, this fails the critical requirement: "Impact meets Critical, High, or Medium severity criteria per bounty program." The issue is correctly marked as "Low" severity in the original question, but even that overstates its security impact—this is simply a configuration validation bug in a development tool.

### Citations

**File:** execution/executor-benchmark/src/ledger_update_stage.rs (L76-82)
```rust
        if !self.allow_retries {
            if output.epoch_state().is_none() {
                assert_eq!(output.num_transactions_to_commit(), num_input_txns + 1);
            } else {
                assert_eq!(output.num_transactions_to_commit(), num_input_txns);
            }
        }
```

**File:** execution/executor-types/src/execution_output.rs (L150-176)
```rust
pub struct Inner {
    pub is_block: bool,
    pub first_version: Version,
    // Statuses of the input transactions, in the same order as the input transactions.
    // Contains BlockMetadata/Validator transactions,
    // but doesn't contain StateCheckpoint/BlockEpilogue, as those get added during execution
    pub statuses_for_input_txns: Vec<TransactionStatus>,
    // List of all transactions to be committed, including StateCheckpoint/BlockEpilogue if needed.
    pub to_commit: TransactionsToKeep,
    pub to_discard: TransactionsWithOutput,
    pub to_retry: TransactionsWithOutput,

    pub result_state: LedgerState,
    /// State items read during execution, useful for calculating the state storge usage and
    /// indices used by the db pruner.
    pub state_reads: ShardedStateCache,
    /// Updates to hot state, mainly used to compute hot state root hashes.
    pub hot_state_updates: HotStateUpdates,

    /// Optional StateCheckpoint payload
    pub block_end_info: Option<BlockEndInfo>,
    /// Optional EpochState payload.
    /// Only present if the block is the last block of an epoch, and is parsed output of the
    /// state cache.
    pub next_epoch_state: Option<EpochState>,
    pub subscribable_events: Planned<Vec<ContractEvent>>,
}
```

**File:** execution/executor-benchmark/src/main.rs (L163-172)
```rust
    /// Whether transactions are allowed to be discarded.
    /// By default, workload generates transactions that are all expected to succeeded,
    /// so discards are not allowed - to catch any correctness/configuration issues.
    #[clap(long)]
    allow_discards: bool,
    /// Whether transactions are allowed to be retried.
    /// By default, workload generates transactions that are all expected to succeeded,
    /// so retries are not allowed - to catch any correctness/configuration issues.
    #[clap(long)]
    allow_retries: bool,
```
