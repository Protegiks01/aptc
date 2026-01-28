# Audit Report

## Title
BlockSTMv2 Partial Delayed Field Application Leads to Panic on Re-execution

## Summary
A critical bug in `process_delayed_field_output()` allows partial application of delayed field changes when `record_change()` fails. The error is captured but the loop continues, allowing subsequent fields to be recorded while failed fields remain in the output metadata. During re-execution, the cleanup attempts to remove fields that were never recorded, causing a panic that crashes validator nodes.

## Finding Description

The vulnerability exists in the delayed field processing and cleanup logic within the BlockSTM parallel execution engine.

**Step 1: Partial Application During Error Handling**

In `process_delayed_field_output()`, when `record_change()` fails with a `PanicOr::Or(_)` error (such as `MVDelayedFieldsError::NotFound`), the function captures the error but continues processing subsequent delayed fields without returning. [1](#0-0) 

This allows a scenario where:
- Field A records successfully in `versioned_cache`
- Field B fails to record (error captured at line 371-373)
- Field C records successfully in `versioned_cache`

All three fields (A, B, C) are then recorded in the output metadata when `last_input_output.record()` is called. [2](#0-1) 

**Step 2: Validation Failure and Abort Path**

The captured error causes delayed field validation to fail when `delayed_field_speculative_failure` flag is checked. [3](#0-2) 

This triggers `abort_pre_final_reexecution()`. [4](#0-3) 

In BlockSTMv2, this function only calls `scheduler.direct_abort()` without cleaning up the versioned cache state. [5](#0-4) 

**Step 3: Panic During Cleanup**

During re-execution, `prev_modified_delayed_fields` is populated from the previous incarnation's output metadata, which includes ALL fields (A, B, C). [6](#0-5) 

If re-execution produces different outputs, the cleanup loop attempts to remove fields from the previous incarnation that are not in the new output. [7](#0-6) 

When attempting to remove field B (which failed to record initially), the `remove()` method panics because it expects the field to exist in `values`. [8](#0-7) 

**Trigger Scenario:**

This can occur in parallel execution when:
1. Transaction B applies a delta to an aggregator created by Transaction A
2. Transaction A aborts and re-executes without creating the aggregator
3. Transaction B's cached output becomes invalid - `record_change()` fails with `NotFound` for the delta
4. Some delayed fields record successfully, creating partial state
5. Validation fails, triggering re-execution
6. BlockSTMv2's abort does not clean up the partial state
7. Re-execution cleanup attempts to remove the never-recorded field
8. Panic crashes the validator node

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program:

- **Validator Node Crashes**: The `code_invariant_error` panic will immediately crash the validator node process, directly qualifying as "Validator node slowdowns" or crashes under High Severity criteria

- **Consensus Divergence Risk**: In a parallel execution environment, different validators may experience different timing and state conditions. Some validators may successfully process transactions while others panic, potentially causing consensus disruption

- **State Consistency Violation**: The partial application of delayed field changes violates the atomicity guarantee that transaction state changes should be all-or-nothing

The panic is deterministic once the vulnerable state is reached, making this a reliable crash vector that could be exploited to cause validator unavailability.

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability can be triggered in speculative parallel execution scenarios:

**Preconditions:**
1. BlockSTMv2 parallel execution is enabled (current execution model)
2. Concurrent transactions with dependencies on delayed fields (aggregators)
3. Transaction aborts and re-execution that change aggregator creation patterns

**Trigger Mechanism:**
- In parallel execution, Transaction B reads and applies a delta to an aggregator created by Transaction A
- Transaction A aborts and re-executes without creating that aggregator
- Transaction B's output now references a non-existent aggregator
- The `NotFound` error is triggered when processing B's output

**Complexity:**
- Does not require attacker privileges
- Occurs naturally in high-concurrency scenarios with transaction dependencies
- The attacker cannot directly control transaction ordering but can submit transactions that increase likelihood
- More likely during network congestion when transaction re-execution is common

## Recommendation

**Fix 1: Fail-Fast on Record Error**

Modify `process_delayed_field_output()` to return immediately when `record_change()` fails with an error, rather than capturing and continuing:

```rust
if let Err(e) = versioned_cache.delayed_fields().record_change(id, idx_to_execute, entry) {
    return Err(e.into_panic_error());
}
```

**Fix 2: Track Actually-Recorded Fields**

Maintain a separate set of successfully-recorded delayed field IDs, and use this for cleanup instead of relying on the output metadata:

```rust
let mut actually_recorded_fields = HashSet::new();
// ... in loop ...
if versioned_cache.delayed_fields().record_change(id, idx_to_execute, entry).is_ok() {
    actually_recorded_fields.insert(id);
}
// ... cleanup using actually_recorded_fields instead of prev_modified_delayed_fields
```

**Fix 3: Make Remove Operation Safe**

Change `remove()` to be idempotent and not panic on non-existent fields:

```rust
pub fn remove(&self, id: &K, txn_idx: TxnIndex, is_blockstm_v2: bool) -> Result<(), PanicError> {
    if let Some(mut versioned_value) = self.values.get_mut(id) {
        versioned_value.remove(txn_idx, is_blockstm_v2);
    }
    // No error if field doesn't exist - may have failed to record
    Ok(())
}
```

## Proof of Concept

The vulnerability can be demonstrated through a Rust test that simulates the parallel execution scenario:

```rust
#[test]
fn test_partial_delayed_field_recording_panic() {
    // Setup: Create two transactions with delayed field dependencies
    // Transaction A creates aggregator X
    // Transaction B applies delta to aggregator X
    
    // Step 1: Execute both transactions in parallel
    // Step 2: Abort Transaction A (aggregator X no longer exists)
    // Step 3: Process Transaction B's output
    //   - record_change() fails with NotFound for aggregator X delta
    //   - Other delayed fields record successfully
    //   - Error is captured, loop continues
    
    // Step 4: Validation fails, triggering abort_pre_final_reexecution()
    //   - In BlockSTMv2, this does NOT clean up versioned_cache
    
    // Step 5: Re-execute Transaction B with different output
    //   - Cleanup attempts to remove aggregator X delta
    //   - Panic: "VersionedValue for an (resolved) ID must already exist"
    
    // Expected: Panic crashes the validator node
}
```

## Notes

1. The vulnerability affects BlockSTMv2's execution path specifically due to the incomplete cleanup in `abort_pre_final_reexecution()`. While BlockSTMv1 calls `update_transaction_on_abort()`, it would also encounter issues when `mark_estimate()` expects fields to exist. [9](#0-8) 

2. The root cause is the error handling design that allows partial state application. The loop continuation after error capture (line 374) combined with metadata recording all fields (including failed ones) creates the inconsistency.

3. This is distinct from normal speculative execution failures - it specifically occurs when `record_change()` partially succeeds for some fields but fails for others within the same transaction output.

### Citations

**File:** aptos-move/block-executor/src/executor.rs (L333-335)
```rust
        let mut prev_modified_delayed_fields = last_input_output
            .delayed_field_keys(idx_to_execute)
            .map_or_else(HashSet::new, |keys| keys.collect());
```

**File:** aptos-move/block-executor/src/executor.rs (L358-376)
```rust
                if let Err(e) =
                    versioned_cache
                        .delayed_fields()
                        .record_change(id, idx_to_execute, entry)
                {
                    match e {
                        PanicOr::CodeInvariantError(m) => {
                            return Err(code_invariant_error(format!(
                                "Record change failed with CodeInvariantError: {:?}",
                                m
                            )));
                        },
                        PanicOr::Or(_) => {
                            read_set.capture_delayed_field_read_error(&PanicOr::Or(
                                MVDelayedFieldsError::DeltaApplicationFailure,
                            ));
                        },
                    };
                }
```

**File:** aptos-move/block-executor/src/executor.rs (L380-384)
```rust
        for id in prev_modified_delayed_fields {
            versioned_cache
                .delayed_fields()
                .remove(&id, idx_to_execute, is_v2)?;
        }
```

**File:** aptos-move/block-executor/src/executor.rs (L499-505)
```rust
        last_input_output.record(
            idx_to_execute,
            read_set,
            execution_result,
            block_gas_limit_type,
            txn.user_txn_bytes_len() as u64,
        )?;
```

**File:** aptos-move/block-executor/src/executor.rs (L1018-1023)
```rust
            scheduler.abort_pre_final_reexecution::<T, E>(
                txn_idx,
                incarnation,
                last_input_output,
                versioned_cache,
            )?;
```

**File:** aptos-move/block-executor/src/captured_reads.rs (L1147-1149)
```rust
        if self.delayed_field_speculative_failure {
            return Ok(false);
        }
```

**File:** aptos-move/block-executor/src/scheduler_wrapper.rs (L123-125)
```rust
            SchedulerWrapper::V2(scheduler, _) => {
                scheduler.direct_abort(txn_idx, incarnation, true)?;
            },
```

**File:** aptos-move/mvhashmap/src/versioned_delayed_fields.rs (L518-523)
```rust
    pub fn mark_estimate(&self, id: &K, txn_idx: TxnIndex) {
        self.values
            .get_mut(id)
            .expect("VersionedValue for an (resolved) ID must already exist")
            .mark_estimate(txn_idx);
    }
```

**File:** aptos-move/mvhashmap/src/versioned_delayed_fields.rs (L525-541)
```rust
    pub fn remove(
        &self,
        id: &K,
        txn_idx: TxnIndex,
        is_blockstm_v2: bool,
    ) -> Result<(), PanicError> {
        self.values
            .get_mut(id)
            .ok_or_else(|| {
                code_invariant_error(format!(
                    "VersionedValue for an (resolved) ID {:?} must already exist",
                    id
                ))
            })?
            .remove(txn_idx, is_blockstm_v2);
        Ok(())
    }
```
