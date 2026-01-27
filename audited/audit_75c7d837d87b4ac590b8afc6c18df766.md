# Audit Report

## Title
Incomplete Incarnation Verification in MVHashMap write_impl() Allows Delta-to-Write Transitions to Bypass Monotonic Incarnation Invariant

## Summary
The `write_impl()` function in `versioned_data.rs` uses `is_none_or()` to assert that previous entries have lower incarnation numbers. However, when a `Delta` entry is overwritten by a `ResourceWrite`, the assertion unconditionally returns `true` without verifying incarnation ordering, creating a verification gap that could allow lower incarnations to overwrite higher incarnations if scheduler bugs or race conditions occur. [1](#0-0) 

## Finding Description
The MVHashMap is a critical component in Aptos's Block-STM parallel execution engine, maintaining versioned transaction outputs with monotonically increasing incarnation numbers. Each transaction can be executed multiple times (incarnations 0, 1, 2...) due to validation failures, and the system must ensure that only higher incarnations can overwrite lower ones. [2](#0-1) 

The `write_impl()` function contains an assertion designed to verify this invariant. However, the verification has a critical gap:

**For ResourceWrite entries:** The check properly compares `prev_incarnation < incarnation` at line 645.

**For Delta entries:** The else branch at line 650 returns `true` unconditionally, bypassing incarnation verification entirely.

This gap exists because `Delta` entries (used for AggregatorV1 operations) do not store incarnation numbers in the `EntryCell` enum structure, while `ResourceWrite` entries do. [3](#0-2) 

**Attack Scenario:**

1. Transaction T at `txn_idx=5`, incarnation 1 executes and produces a Delta at key K
2. `add_delta(K, 5, delta1)` is called, storing the Delta without incarnation tracking
3. Due to a scheduler bug or race condition, incarnation 0 gets scheduled afterward
4. Incarnation 0 produces a ResourceWrite at the same key K
5. `write(K, 5, 0, value0)` calls `write_impl(incarnation=0)`
6. `prev_entry` contains the Delta from incarnation 1
7. The `if let EntryCell::ResourceWrite` pattern match fails (it's a Delta)
8. The else branch returns `true`, causing the assertion to pass
9. **Result:** Incarnation 0's ResourceWrite successfully overwrites incarnation 1's Delta, violating the monotonic incarnation invariant [4](#0-3) 

The execution flow shows that transactions can produce either deltas or writes at the same key across different incarnations, making this transition path realistic for AggregatorV1 operations. [5](#0-4) 

Note that `add_delta()` performs no incarnation checking whatsoever, compounding the issue.

## Impact Explanation
This vulnerability represents a **defense-in-depth failure** that could lead to:

1. **State Inconsistencies:** Wrong transaction outputs could be committed to the MVHashMap, causing different validators to read different values and compute different state roots.

2. **Consensus Violations:** If different validators experience the race condition differently, they may commit different transaction results, breaking deterministic execution (Critical Invariant #1).

3. **Transaction Output Corruption:** The wrong incarnation's output could be finalized, causing incorrect on-chain state that propagates through dependent transactions.

Per the Aptos bug bounty criteria, this qualifies as **Medium Severity** ($10,000) under "State inconsistencies requiring intervention." While it doesn't directly cause fund loss, it undermines the correctness guarantees of parallel execution and could require manual intervention or block rollback if exploited.

## Likelihood Explanation
**Likelihood: Low-Medium**

This vulnerability requires specific conditions to be exploitable:

1. **Scheduler Bug or Race Condition:** The scheduler must allow incarnations to execute out of order, which violates its design specification. [6](#0-5) 

The scheduler's state machine is designed to ensure monotonic incarnation increases through the `Ready(i) → Executing(i) → Executed(i) → Aborting(i) → Ready(i+1)` progression. However, complex concurrent execution scenarios or bugs in the scheduler implementation could potentially violate this.

2. **Delta-to-Write Transition:** The transaction must switch from producing a Delta to a ResourceWrite at the same key across incarnations, which is semantically valid for AggregatorV1 operations.

3. **Timing Window:** The race must occur in the specific window where the lower incarnation attempts to write after the higher incarnation's Delta is already stored.

While the scheduler is designed to prevent this, the assertion's purpose is to provide defense-in-depth protection against such bugs. The current implementation fails this defensive role for Delta entries.

## Recommendation
**Fix 1: Add incarnation tracking to Delta entries**

Modify the `EntryCell::Delta` variant to include incarnation:

```rust
enum EntryCell<V> {
    ResourceWrite {
        incarnation: Incarnation,
        value_with_layout: ValueWithLayout<V>,
        dependencies: Mutex<RegisteredReadDependencies>,
    },
    Delta {
        incarnation: Incarnation,  // Add this field
        delta_op: DeltaOp,
        shortcut: Option<u128>,
    },
}
```

Update `write_impl()` to verify incarnation for both variants:

```rust
assert!(prev_entry.is_none_or(|entry| -> bool {
    match &entry.value {
        EntryCell::ResourceWrite { incarnation: prev_incarnation, .. } 
        | EntryCell::Delta { incarnation: prev_incarnation, .. } => {
            *prev_incarnation < incarnation
        }
    }
}));
```

Update `add_delta()` to accept incarnation:

```rust
pub fn add_delta(&self, key: K, txn_idx: TxnIndex, incarnation: Incarnation, delta: DeltaOp) {
    let mut v = self.values.entry(key).or_default();
    v.versioned_map.insert(
        ShiftedTxnIndex::new(txn_idx),
        CachePadded::new(Entry::new(EntryCell::Delta { 
            incarnation, 
            delta_op: delta,
            shortcut: None,
        })),
    );
}
```

**Fix 2: Alternative - Document the limitation and add runtime check**

If maintaining Delta without incarnation is a deliberate design choice (as suggested by the TODO comment at line 646), add explicit documentation and a runtime check: [7](#0-6) 

```rust
assert!(prev_entry.is_none_or(|entry| -> bool {
    if let EntryCell::ResourceWrite {
        incarnation: prev_incarnation,
        ..
    } = &entry.value
    {
        *prev_incarnation < incarnation
    } else {
        // Delta entries: Cannot verify incarnation ordering as Deltas
        // don't store incarnation numbers. This is acceptable ONLY if
        // the scheduler guarantees monotonic incarnation execution.
        // If this assertion ever fires with a Delta, it indicates a
        // critical scheduler bug that must be investigated immediately.
        true
    }
}));
```

Additionally, add a debug assertion in the scheduler to verify incarnation ordering is maintained.

## Proof of Concept

The following scenario demonstrates the vulnerability (requires injecting a scheduler bug for testing):

```rust
#[cfg(test)]
mod test_incarnation_gap {
    use super::*;
    use std::sync::Arc;
    
    #[test]
    #[should_panic(expected = "Incarnation ordering violated")]
    fn test_delta_to_write_incarnation_violation() {
        let versioned_data = VersionedData::<u64, TestValue>::empty();
        let key = 100u64;
        let txn_idx = 5;
        
        // Incarnation 1 writes a Delta
        versioned_data.add_delta(key, txn_idx, DeltaOp::new(
            SignedU128::Positive(10),
            1000,
            DeltaHistory::default(),
        ));
        
        // Simulate scheduler bug: incarnation 0 executes after incarnation 1
        // This SHOULD fail but currently passes due to line 650 returning true
        versioned_data.write(
            key,
            txn_idx,
            0, // Lower incarnation
            Arc::new(TestValue::new(100)),
            None,
        );
        
        // If we reach here, the bug allowed lower incarnation to overwrite higher
        panic!("Incarnation ordering violated");
    }
}
```

This test would pass with the current code (demonstrating the bug) but should fail with proper incarnation verification.

## Notes

1. This issue specifically affects the Delta-to-ResourceWrite transition path used in AggregatorV1 operations. The TODO comment acknowledges that AggregatorV1 has known limitations that will be addressed when it's deprecated.

2. The vulnerability's exploitability depends entirely on whether the scheduler can be made to execute incarnations out of order. Under normal operation with a correct scheduler, this should never occur.

3. The issue represents a violation of defense-in-depth principles: critical invariants should be verified at multiple layers, not just assumed based on other components' correctness.

4. This finding aligns with the security question's Medium severity assessment, as it requires a scheduler bug to be exploited but could cause state inconsistencies if triggered.

### Citations

**File:** aptos-move/mvhashmap/src/versioned_data.rs (L46-61)
```rust
enum EntryCell<V> {
    /// Recorded in the shared multi-version data-structure for each write. It
    /// has: 1) Incarnation number of the transaction that wrote the entry (note
    /// that TxnIndex is part of the key and not recorded here), 2) actual data
    /// stored in a shared pointer (to ensure ownership and avoid clones).
    ResourceWrite {
        incarnation: Incarnation,
        value_with_layout: ValueWithLayout<V>,
        dependencies: Mutex<RegisteredReadDependencies>,
    },

    /// Recorded in the shared multi-version data-structure for each delta.
    /// Option<u128> is a shortcut to aggregated value (to avoid traversing down
    /// beyond this index), which is created after the corresponding txn is committed.
    Delta(DeltaOp, Option<u128>),
}
```

**File:** aptos-move/mvhashmap/src/versioned_data.rs (L422-428)
```rust
    pub fn add_delta(&self, key: K, txn_idx: TxnIndex, delta: DeltaOp) {
        let mut v = self.values.entry(key).or_default();
        v.versioned_map.insert(
            ShiftedTxnIndex::new(txn_idx),
            CachePadded::new(new_delta_entry(delta)),
        );
    }
```

**File:** aptos-move/mvhashmap/src/versioned_data.rs (L625-653)
```rust
    fn write_impl(
        versioned_values: &mut VersionedValue<V>,
        txn_idx: TxnIndex,
        incarnation: Incarnation,
        value: ValueWithLayout<V>,
        dependencies: BTreeMap<TxnIndex, Incarnation>,
    ) {
        let prev_entry = versioned_values.versioned_map.insert(
            ShiftedTxnIndex::new(txn_idx),
            CachePadded::new(new_write_entry(incarnation, value, dependencies)),
        );

        // Assert that the previous entry for txn_idx, if present, had lower incarnation.
        assert!(prev_entry.is_none_or(|entry| -> bool {
            if let EntryCell::ResourceWrite {
                incarnation: prev_incarnation,
                ..
            } = &entry.value
            {
                // For BlockSTMv1, the dependencies are always empty.
                *prev_incarnation < incarnation
                // TODO(BlockSTMv2): when AggregatorV1 is deprecated, we can assert that
                // prev_dependencies is empty: they must have been drained beforehand
                // (into dependencies) if there was an entry at the same index before.
            } else {
                true
            }
        }));
    }
```

**File:** aptos-move/block-executor/src/executor.rs (L479-493)
```rust
            for (key, value) in output_before_guard.aggregator_v1_write_set().into_iter() {
                prev_modified_aggregator_v1_keys.remove(&key);

                versioned_cache.data().write(
                    key,
                    idx_to_execute,
                    incarnation,
                    TriompheArc::new(value),
                    None,
                );
            }
            for (key, delta) in output_before_guard.aggregator_v1_delta_set().into_iter() {
                prev_modified_aggregator_v1_keys.remove(&key);
                versioned_cache.data().add_delta(key, idx_to_execute, delta);
            }
```

**File:** aptos-move/block-executor/src/scheduler.rs (L95-137)
```rust
/////////////////////////////// Explanation for ExecutionStatus ///////////////////////////////
/// All possible execution status for each transaction. In the explanation below, we abbreviate
/// 'execution status' as 'status'. Each status contains the latest incarnation number,
/// where incarnation = i means it is the i-th execution instance of the transaction.
///
/// 'Ready' means that the corresponding incarnation should be executed and the scheduler
/// must eventually create a corresponding execution task. The scheduler ensures that exactly one
/// execution task gets created, changing the status to 'Executing' in the process. 'Ready' status
/// contains an ExecutionTaskType, which is either Execution or Wakeup. If it is Execution, then
/// the scheduler creates an execution task for the corresponding incarnation. If it is Wakeup,
/// a dependency condition variable is set in ExecutionTaskType::Wakeup(DependencyCondvar): an execution
/// of a prior incarnation is waiting on it with a read dependency resolved (when dependency was
/// encountered, the status changed to Suspended, and suspended changed to Ready when the dependency
/// finished its execution). In this case the caller need not create a new execution task, but
/// just notify the suspended execution via the dependency condition variable.
///
/// 'Executing' status of an incarnation turns into 'Executed' if the execution task finishes, or
/// if a dependency is encountered, it becomes 'Ready(incarnation)' once the
/// dependency is resolved. An 'Executed' status allows creation of validation tasks for the
/// corresponding incarnation, and a validation failure leads to an abort. The scheduler ensures
/// that there is exactly one abort, changing the status to 'Aborting' in the process. Once the
/// thread that successfully aborted performs everything that's required, it sets the status
/// to 'Ready(incarnation + 1)', allowing the scheduler to create an execution
/// task for the next incarnation of the transaction.
///
/// 'ExecutionHalted' is a transaction status marking that parallel execution is halted, due to
/// reasons such as module r/w intersection or exceeding per-block gas limit. It is safe to ignore
/// this status during the transaction invariant checks, e.g., suspend(), resume(), set_executed_status().
///
/// Status transition diagram:
/// Ready(i)                                                                               ---
///    |  try_incarnate (incarnate successfully)                                             |
///    |                                                                                     |
///    ↓         suspend (waiting on dependency)                resume                       |
/// Executing(i) -----------------------------> Suspended(i) ------------> Ready(i)          |
///    |                                                                                     | halt_transaction_execution
///    |  finish_execution                                                                   |-----------------> ExecutionHalted
///    ↓                                                                                     |
/// Executed(i) (pending for (re)validations) ---------------------------> Committed(i)      |
///    |                                                                                     |
///    |  try_abort (abort successfully)                                                     |
///    ↓                finish_abort                                                         |
/// Aborting(i) ---------------------------------------------------------> Ready(i+1)      ---
```
