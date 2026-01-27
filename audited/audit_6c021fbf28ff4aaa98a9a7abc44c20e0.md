# Audit Report

## Title
Aggregator V1 Delta History Validation Mismatch Causes Validator Node Panic

## Summary
When `read()` returns `Err(Unresolved(accumulator))` in the MVHashMap multi-version data structure, the accumulated `DeltaOp` contains a `DeltaHistory` built during speculative parallel execution. If this history records operation constraints (successful/failed operations) based on speculative values that differ from the actual storage base value, materialization at commit time will fail validation and trigger an `.expect()` panic, crashing the validator node. [1](#0-0) 

## Finding Description

**The Core Issue**: BlockSTM's parallel execution allows transactions to read speculative delta values from earlier transactions. When multiple deltas are accumulated during `read()`, the resulting `DeltaHistory` tracks which operations succeeded or failed during speculative execution. However, at commit time, these deltas are materialized against the **actual storage base value**, not the speculative value used during execution. If these differ significantly, the history validation fails.

**Attack Flow**:

1. Aggregator A exists in storage with value V_storage and max_value M
2. Transaction T1 (lower index) creates a delta D1 based on V_storage
3. Transaction T2 (higher index) executes speculatively and reads A
4. T2's read encounters D1 in the MVHashMap, accumulating it
5. T2 performs aggregator operations based on the speculative value (V_storage + D1)
6. These operations build a `DeltaHistory` with constraints like:
   - `max_achieved_positive_delta`: successful additions
   - `min_overflow_positive_delta`: additions that caused overflow
   - `max_underflow_negative_delta`: subtractions that caused underflow
7. T2 writes the combined delta to MVHashMap
8. At commit time, `materialize_aggregator_v1_delta_writes()` is called for T2 [2](#0-1) 

9. The function fetches the storage value (V_storage, not including T1's delta yet)
10. It calls `op.apply_to(V_storage)` where op contains the history built against (V_storage + D1) [3](#0-2) 

11. The `apply_to()` method calls `validate_against_base_value()` which checks:
    - Successful operations in history would still succeed with V_storage
    - Failed operations (overflow/underflow) in history would still fail with V_storage [4](#0-3) 

12. If V_storage doesn't satisfy the history constraints (because they were built against V_storage + D1), validation fails
13. The `.expect()` at line 1112 triggers a panic, **crashing the validator node**

**Concrete Example**:
- Storage: A = 50, max_value = 100
- T1 writes delta +40
- T2 reads, sees speculative value 90 (50 + 40)
- T2 tries add +15 → 105 > 100, **fails** (overflow)
- T2's history records: `min_overflow_positive_delta = Some(15)`
- T2 successfully adds +5 → 95
- T2's final delta: +45, history includes `min_overflow_positive_delta = Some(15)`
- At materialization: storage = 50
- Validation checks: 50 + 15 = 65 < 100 (should have overflowed but didn't!) ❌
- Panic occurs

This breaks **Invariant #2 (Consensus Safety)** and **Invariant #4 (State Consistency)** by causing validator nodes to crash, potentially leading to network liveness failures.

## Impact Explanation

**Severity: High** ($50,000 per Aptos Bug Bounty)

This vulnerability allows an attacker to crash validator nodes through carefully crafted transaction sequences that create incompatible delta histories. The impact falls under:

1. **Validator node crashes** - Direct impact category in the bug bounty
2. **Significant protocol violations** - Nodes crash during normal block execution
3. **Potential liveness failure** - If enough validators crash simultaneously, block production halts

While this doesn't directly cause loss of funds or consensus safety violations, it threatens network availability. An attacker who can reliably trigger this across multiple validators could halt block production, requiring manual intervention and node restarts.

The attack doesn't require validator privileges - any transaction sender can craft sequences that cause these incompatibilities during parallel execution.

## Likelihood Explanation

**Likelihood: Medium-High**

The vulnerability is exploitable under normal parallel execution conditions:

**Favorable Conditions**:
- BlockSTM routinely executes transactions in parallel with speculative reads
- Aggregator V1 is still in use (though being phased out for DelayedFields)
- No validation checks delta write compatibility before materialization
- The code explicitly uses `.expect()` assuming materialization always succeeds

**Attack Requirements**:
- Craft transactions targeting the same aggregator with specific delta sequences
- Ensure operations succeed/fail differently based on speculative vs. storage values
- Requires understanding of aggregator bounds and delta accumulation behavior
- Some trial and error may be needed to find working combinations

**Mitigating Factors**:
- Aggregator V1 is legacy (being replaced by DelayedFields)
- Transaction ordering affects whether the specific scenario occurs
- Multiple TODO comments indicate developers are aware this code needs improvement [5](#0-4) 

## Recommendation

Replace the `.expect()` with proper error handling that triggers transaction re-execution instead of panicking:

```rust
let committed_delta = versioned_cache
    .data()
    .materialize_delta(&k, txn_idx)
    .unwrap_or_else(|op| {
        let storage_value = base_view
            .get_state_value(&k)
            .expect("Error reading the base value for committed delta in storage");

        let w: T::Value = TransactionWrite::from_state_value(storage_value);
        let value_u128 = w
            .as_u128()
            .expect("Aggregator base value deserialization error")
            .expect("Aggregator base value must exist");

        versioned_cache.data().set_base_value(
            k.clone(),
            ValueWithLayout::RawFromStorage(TriompheArc::new(w)),
        );
        
        // Instead of .expect(), handle the error
        match op.apply_to(value_u128) {
            Ok(value) => value,
            Err(e) => {
                // Delta history incompatible with storage value
                // Trigger re-execution of this transaction
                return Err(PanicError::CodeInvariantError(format!(
                    "Delta materialization failed due to history mismatch at txn {}: {:?}",
                    txn_idx, e
                )));
            }
        }
    });
```

Alternatively, validate delta write compatibility during the commit-time validation phase **before** materialization:

```rust
// In validate_and_commit_delayed_fields, add delta write validation
for k in aggregator_v1_delta_keys {
    if let Some(delta_op) = last_input_output.get_aggregator_delta(txn_idx, &k) {
        let storage_value = base_view.get_state_value(&k)?;
        let value_u128 = extract_u128_from_state_value(storage_value)?;
        
        // Validate delta can be applied to storage value
        if delta_op.apply_to(value_u128).is_err() {
            return Ok(false); // Trigger re-execution
        }
    }
}
```

## Proof of Concept

Due to the complexity of the BlockSTM parallel execution framework and the need to orchestrate specific transaction ordering, a full PoC requires the test infrastructure. However, the vulnerability can be demonstrated through the following conceptual test:

```rust
// Conceptual test - would need adaptation to actual test framework
#[test]
fn test_delta_history_mismatch_panic() {
    let vd: VersionedData<KeyType, TestValue> = VersionedData::empty();
    let key = KeyType(b"aggregator_a".to_vec());
    let max_value = 100u128;
    
    // Setup: Storage has value 50
    vd.set_base_value(
        key.clone(),
        ValueWithLayout::RawFromStorage(Arc::new(TestValue::from_u128(50))),
    );
    
    // T1: Creates delta +40 (speculative result: 90)
    let delta1 = DeltaOp::new(
        SignedU128::Positive(40),
        max_value,
        DeltaHistory {
            max_achieved_positive_delta: 40,
            min_achieved_negative_delta: 0,
            min_overflow_positive_delta: None,
            max_underflow_negative_delta: None,
        }
    );
    vd.add_delta(key.clone(), 5, delta1);
    
    // T2: Reads and encounters T1's delta, performs operations
    // Assuming speculative value 90, tries add +15 which would overflow
    // Records this in history, then successfully adds +5
    let mut delta2_history = DeltaHistory::new();
    delta2_history.record_success(SignedU128::Positive(5));
    delta2_history.record_overflow(15); // This is the key: recorded based on value 90
    
    let delta2 = DeltaOp::new(
        SignedU128::Positive(5),
        max_value,
        delta2_history
    );
    
    // When accumulated with delta1, creates combined delta +45 with history
    // that expects base + 15 to overflow (which is true for base=90, false for base=50)
    
    // Attempt materialization against storage value 50
    // This should panic because validation will fail:
    // - 50 + 5 = 55 ✓ (successful op validation passes)
    // - 50 + 15 = 65 < 100 (overflow expectation fails!) ❌
}
```

The actual triggering of this requires coordination between multiple transactions in the parallel executor, making a standalone unit test insufficient. The vulnerability manifests during block execution when the specific sequence occurs naturally or is intentionally crafted.

## Notes

This vulnerability is specific to Aggregator V1, which is marked as legacy in the codebase. The presence of multiple `TODO[agg_v1](cleanup)` comments indicates that this code path is scheduled for removal. However, until Aggregator V1 is fully deprecated and removed, this vulnerability remains exploitable and poses a risk to network liveness.

The validation logic in `validate_and_commit_delayed_fields` validates transaction **reads** but not whether delta **writes** can be successfully materialized against storage, creating this gap in the security model.

### Citations

**File:** aptos-move/mvhashmap/src/versioned_data.rs (L368-376)
```rust
        // It can happen that while traversing the block and resolving
        // deltas the actual written value has not been seen yet (i.e.
        // it is not added as an entry to the data-structure).
        match accumulator {
            Some(Ok(accumulator)) => Err(Unresolved(accumulator)),
            Some(Err(_)) => Err(DeltaApplicationFailure),
            None => Err(Uninitialized),
        }
    }
```

**File:** aptos-move/block-executor/src/executor.rs (L1069-1123)
```rust
    fn materialize_aggregator_v1_delta_writes(
        txn_idx: TxnIndex,
        last_input_output: &TxnLastInputOutput<T, E::Output>,
        versioned_cache: &MVHashMap<T::Key, T::Tag, T::Value, DelayedFieldID>,
        base_view: &S,
    ) -> Vec<(T::Key, WriteOp)> {
        // Materialize all the aggregator v1 deltas.
        let mut aggregator_v1_delta_writes = Vec::with_capacity(4);
        if let Some(aggregator_v1_delta_keys_iter) =
            last_input_output.aggregator_v1_delta_keys(txn_idx)
        {
            for k in aggregator_v1_delta_keys_iter {
                // Note that delta materialization happens concurrently, but under concurrent
                // commit_hooks (which may be dispatched by the coordinator), threads may end up
                // contending on delta materialization of the same aggregator. However, the
                // materialization is based on previously materialized values and should not
                // introduce long critical sections. Moreover, with more aggregators, and given
                // that the commit_hook will be performed at dispersed times based on the
                // completion of the respective previous tasks of threads, this should not be
                // an immediate bottleneck - confirmed by an experiment with 32 core and a
                // single materialized aggregator. If needed, the contention may be further
                // mitigated by batching consecutive commit_hooks.
                let committed_delta = versioned_cache
                    .data()
                    .materialize_delta(&k, txn_idx)
                    .unwrap_or_else(|op| {
                        // TODO[agg_v1](cleanup): this logic should improve with the new AGGR data structure
                        // TODO[agg_v1](cleanup): and the ugly base_view parameter will also disappear.
                        let storage_value = base_view
                            .get_state_value(&k)
                            .expect("Error reading the base value for committed delta in storage");

                        let w: T::Value = TransactionWrite::from_state_value(storage_value);
                        let value_u128 = w
                            .as_u128()
                            .expect("Aggregator base value deserialization error")
                            .expect("Aggregator base value must exist");

                        versioned_cache.data().set_base_value(
                            k.clone(),
                            ValueWithLayout::RawFromStorage(TriompheArc::new(w)),
                        );
                        op.apply_to(value_u128)
                            .expect("Materializing delta w. base value set must succeed")
                    });

                // Must contain committed value as we set the base value above.
                aggregator_v1_delta_writes.push((
                    k,
                    WriteOp::legacy_modification(serialize(&committed_delta).into()),
                ));
            }
        }
        aggregator_v1_delta_writes
    }
```

**File:** aptos-move/aptos-aggregator/src/delta_math.rs (L148-197)
```rust
    pub fn validate_against_base_value(
        &self,
        base_value: u128,
        max_value: u128,
    ) -> Result<(), DelayedFieldsSpeculativeError> {
        let math = BoundedMath::new(max_value);
        // We need to make sure the following 4 conditions are satisified.
        //     base_value + max_achieved_positive_delta <= self.max_value
        //     base_value >= min_achieved_negative_delta
        //     base_value + min_overflow_positive_delta > self.max_value
        //     base_value < max_underflow_negative_delta
        math.unsigned_add(base_value, self.max_achieved_positive_delta)
            .map_err(|_e| DelayedFieldsSpeculativeError::DeltaApplication {
                base_value,
                max_value,
                delta: SignedU128::Positive(self.max_achieved_positive_delta),
                reason: DeltaApplicationFailureReason::Overflow,
            })?;
        math.unsigned_subtract(base_value, self.min_achieved_negative_delta)
            .map_err(|_e| DelayedFieldsSpeculativeError::DeltaApplication {
                base_value,
                max_value,
                delta: SignedU128::Negative(self.min_achieved_negative_delta),
                reason: DeltaApplicationFailureReason::Underflow,
            })?;

        if let Some(min_overflow_positive_delta) = self.min_overflow_positive_delta {
            if base_value <= max_value - min_overflow_positive_delta {
                return Err(DelayedFieldsSpeculativeError::DeltaApplication {
                    base_value,
                    max_value,
                    delta: SignedU128::Positive(min_overflow_positive_delta),
                    reason: DeltaApplicationFailureReason::ExpectedOverflow,
                });
            }
        }

        if let Some(max_underflow_negative_delta) = self.max_underflow_negative_delta {
            if base_value >= max_underflow_negative_delta {
                return Err(DelayedFieldsSpeculativeError::DeltaApplication {
                    base_value,
                    max_value,
                    delta: SignedU128::Negative(max_underflow_negative_delta),
                    reason: DeltaApplicationFailureReason::ExpectedUnderflow,
                });
            }
        }

        Ok(())
    }
```
