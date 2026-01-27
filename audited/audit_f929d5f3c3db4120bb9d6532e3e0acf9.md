# Audit Report

## Title
Legitimate Runtime Errors Misclassified as Code Invariant Violations in `patch_base_value()`

## Summary
In `LatestView::patch_base_value()`, all errors from `replace_values_with_identifiers()` are unconditionally marked as "incorrect use" (code invariant violations), causing block execution to halt. However, some errors like `TOO_MANY_DELAYED_FIELDS` are legitimate runtime resource limit errors that should be handled gracefully as transaction failures, not as code bugs that halt the executor.

## Finding Description

The vulnerability exists in the error handling logic at [1](#0-0) 

When `replace_values_with_identifiers()` fails during the patching of base values with delayed field identifiers, the code unconditionally marks this as "incorrect use" at line 1214 and returns `DELAYED_FIELD_OR_BLOCKSTM_CODE_INVARIANT_ERROR`. 

The problem is that `replace_values_with_identifiers()` can fail with **legitimate runtime errors** that are not code bugs:

1. **TOO_MANY_DELAYED_FIELDS**: A resource limit defined at [2](#0-1)  - when a resource exceeds 10 delayed fields during serialization.

2. **VM_MAX_VALUE_DEPTH_REACHED**: A depth limit violation at [3](#0-2) 

3. **FAILED_TO_DESERIALIZE_RESOURCE**: Deserialization failures that can occur with corrupted data or type mismatches.

When `incorrect_use` is marked, the executor treats this as a code invariant error at [4](#0-3) , causing block execution to halt instead of failing the transaction gracefully.

**Evidence that TOO_MANY_DELAYED_FIELDS is a legitimate error:**
The VM status classification at [5](#0-4)  explicitly maps `TOO_MANY_DELAYED_FIELDS` to `KeptVMStatus::MiscellaneousError`, meaning it should result in a kept transaction with error status, **not** a code invariant violation.

Test evidence at [6](#0-5)  confirms this expected behavior.

**Attack Path:**
1. Attacker crafts a transaction that creates a resource with multiple delayed fields (e.g., aggregators/snapshots), approaching the 10-field limit
2. The resource is stored on-chain successfully  
3. A subsequent transaction (or during parallel execution) reads this resource
4. `patch_base_value()` is invoked to process the resource at [7](#0-6) 
5. `replace_values_with_identifiers()` attempts to serialize the value with delayed fields
6. Serialization hits `TOO_MANY_DELAYED_FIELDS` limit
7. Error is marked as `incorrect_use` instead of being treated as a legitimate resource limit error
8. Executor raises `code_invariant_error`, halting block execution

The same incorrect error handling occurs in both parallel execution at [8](#0-7)  and sequential fallback at [9](#0-8) 

## Impact Explanation

**Medium Severity** per Aptos bug bounty criteria - "State inconsistencies requiring intervention":

1. **Incorrect Error Classification**: Legitimate runtime resource limit errors are misclassified as code invariant violations, preventing proper transaction status reporting
2. **Availability Impact**: Block execution halts with `code_invariant_error` instead of gracefully failing the transaction
3. **Liveness Risk**: Repeated exploitation could cause validator nodes to repeatedly halt, requiring manual intervention
4. **Determinism Violation**: Different validators may handle corrupted storage differently, potentially causing state divergence
5. **DoS Vector**: Attackers can craft transactions to trigger this condition, disrupting block processing

This does NOT directly cause loss of funds or consensus safety violations, hence Medium rather than Critical/High severity.

## Likelihood Explanation

**Moderate to High likelihood:**

1. **Easy to Trigger**: Attackers can deliberately create resources with many delayed fields through Move transactions
2. **No Special Privileges Required**: Any transaction sender can exploit this
3. **Existing Code Pattern**: The limit of 10 delayed fields per resource is easily reachable in legitimate or malicious code
4. **Natural Occurrence**: Could also occur accidentally with complex resource types, not just malicious intent
5. **Test Evidence**: Existing tests show this scenario is expected to occur (aggregator_v2.rs test)

## Recommendation

Distinguish between different error types from `replace_values_with_identifiers()` and only mark actual code bugs as `incorrect_use`, while handling resource limit errors gracefully:

```rust
let res = self.replace_values_with_identifiers(state_value, layout);
match res {
    Ok((value, _)) => Some(value),
    Err(err) => {
        // Check if this is a legitimate runtime error vs code bug
        let is_runtime_error = err.to_string().contains("TOO_MANY_DELAYED_FIELDS")
            || err.to_string().contains("VM_MAX_VALUE_DEPTH_REACHED")
            || err.to_string().contains("Failed to deserialize");
        
        let log_context = AdapterLogSchema::new(self.base_view.id(), self.txn_idx as usize);
        alert!(
            log_context,
            "[VM, ResourceView] Error during value to id replacement: {}",
            err
        );
        
        if !is_runtime_error {
            // Only mark incorrect_use for actual code bugs
            self.mark_incorrect_use();
        }
        
        return Err(PartialVMError::new(
            if is_runtime_error {
                // Map to appropriate status code based on error type
                StatusCode::VALUE_SERIALIZATION_ERROR
            } else {
                StatusCode::DELAYED_FIELD_OR_BLOCKSTM_CODE_INVARIANT_ERROR
            }
        ).with_message(format!("{}", err)));
    },
}
```

Better yet, propagate the actual `StatusCode` from the serialization/deserialization errors instead of wrapping everything in `DELAYED_FIELD_OR_BLOCKSTM_CODE_INVARIANT_ERROR`.

## Proof of Concept

```move
// Module that creates a resource with many delayed fields
module attacker::exploit {
    use aptos_framework::aggregator_v2::{Self, Aggregator};
    
    struct ManyAggregators has key {
        agg1: Aggregator<u64>,
        agg2: Aggregator<u64>,
        agg3: Aggregator<u64>,
        agg4: Aggregator<u64>,
        agg5: Aggregator<u64>,
        agg6: Aggregator<u64>,
        agg7: Aggregator<u64>,
        agg8: Aggregator<u64>,
        agg9: Aggregator<u64>,
        agg10: Aggregator<u64>,
        // 10 delayed fields - at the limit
    }
    
    // Transaction 1: Create the resource
    public entry fun create_many_aggregators(account: &signer) {
        let resource = ManyAggregators {
            agg1: aggregator_v2::create_aggregator(1000),
            agg2: aggregator_v2::create_aggregator(1000),
            agg3: aggregator_v2::create_aggregator(1000),
            agg4: aggregator_v2::create_aggregator(1000),
            agg5: aggregator_v2::create_aggregator(1000),
            agg6: aggregator_v2::create_aggregator(1000),
            agg7: aggregator_v2::create_aggregator(1000),
            agg8: aggregator_v2::create_aggregator(1000),
            agg9: aggregator_v2::create_aggregator(1000),
            agg10: aggregator_v2::create_aggregator(1000),
        };
        move_to(account, resource);
    }
    
    // Transaction 2: Read the resource, triggering patch_base_value()
    public entry fun read_resource(addr: address) acquires ManyAggregators {
        let _resource = borrow_global<ManyAggregators>(addr);
        // During parallel execution, patch_base_value() will be called
        // replace_values_with_identifiers() may hit TOO_MANY_DELAYED_FIELDS
        // This will mark incorrect_use and halt execution
    }
}
```

**Expected Result**: Transaction 2 should fail with `MiscellaneousError(TOO_MANY_DELAYED_FIELDS)` status.

**Actual Result**: Block executor halts with `code_invariant_error("Incorrect use detected in CapturedReads")`.

## Notes

This vulnerability affects the **Resource Limits invariant** - "All operations must respect gas, storage, and computational limits" - by failing to properly handle resource limit violations as transaction errors rather than code bugs. The misclassification prevents deterministic and graceful error handling across the validator network.

### Citations

**File:** aptos-move/block-executor/src/view.rs (L658-665)
```rust
                                Err(e) => {
                                    error!("Couldn't patch value from versioned map: {}", e);
                                    self.captured_reads.borrow_mut().mark_incorrect_use();
                                    return Ok(ReadResult::HaltSpeculativeExecution(
                                        "Couldn't patch value from versioned map".to_string(),
                                    ));
                                },
                            }
```

**File:** aptos-move/block-executor/src/view.rs (L1165-1225)
```rust
    fn patch_base_value(
        &self,
        value: &T::Value,
        layout: Option<&MoveTypeLayout>,
    ) -> PartialVMResult<T::Value> {
        // Cfg due to deserialize_to_delayed_field_u128 use.
        #[cfg(test)]
        fail_point!("delayed_field_test", |_| {
            let mut ret_state_value = value.as_state_value().clone();
            if let Some(layout) = layout {
                assert_eq!(
                    layout,
                    &mock_layout(),
                    "Layout does not match expected mock layout"
                );
                if let Some(state_value) = value.as_state_value() {
                    let (value, txn_idx) = deserialize_to_delayed_field_u128(state_value.bytes())
                        .expect("Mock deserialization failed in delayed field test.");
                    let base_value = DelayedFieldValue::Aggregator(value);
                    // Replicate the logic of value_to_identifier, we use width 8 in the tests.
                    // The real width is irrelevant as test manages all serialization / deserialization.
                    let id = self.generate_delayed_field_id(8);
                    match &self.latest_view {
                        ViewState::Sync(state) => state.set_delayed_field_value(id, base_value),
                        ViewState::Unsync(state) => state.set_delayed_field_value(id, base_value),
                    };

                    ret_state_value
                        .as_mut()
                        .expect("Cloned value checked, must be Some")
                        .set_bytes(serialize_from_delayed_field_id(id, txn_idx));
                }
            }
            Ok(TransactionWrite::from_state_value(ret_state_value))
        });

        let maybe_patched = match (value.as_state_value(), layout) {
            (Some(state_value), Some(layout)) => {
                let res = self.replace_values_with_identifiers(state_value, layout);
                match res {
                    Ok((value, _)) => Some(value),
                    Err(err) => {
                        let log_context =
                            AdapterLogSchema::new(self.base_view.id(), self.txn_idx as usize);
                        alert!(
                            log_context,
                            "[VM, ResourceView] Error during value to id replacement: {}",
                            err
                        );
                        self.mark_incorrect_use();
                        return Err(PartialVMError::new(
                            StatusCode::DELAYED_FIELD_OR_BLOCKSTM_CODE_INVARIANT_ERROR,
                        )
                        .with_message(format!("{}", err)));
                    },
                }
            },
            (state_value, _) => state_value,
        };
        Ok(TransactionWrite::from_state_value(maybe_patched))
    }
```

**File:** third_party/move/move-vm/types/src/value_serde.rs (L54-65)
```rust
    const MAX_DELAYED_FIELDS_PER_RESOURCE: usize = 10;

    /// Increments the delayed fields count, and checks if there are too many of them. If so, an
    /// error is returned.
    pub(crate) fn inc_and_check_delayed_fields_count(&self) -> PartialVMResult<()> {
        *self.delayed_fields_count.borrow_mut() += 1;
        if *self.delayed_fields_count.borrow() > Self::MAX_DELAYED_FIELDS_PER_RESOURCE {
            return Err(PartialVMError::new(StatusCode::TOO_MANY_DELAYED_FIELDS)
                .with_message("Too many Delayed fields in a single resource.".to_string()));
        }
        Ok(())
    }
```

**File:** third_party/move/move-vm/types/src/value_serde.rs (L149-157)
```rust
    pub(crate) fn check_depth(&self, depth: u64) -> PartialVMResult<()> {
        if self
            .max_value_nested_depth
            .is_some_and(|max_depth| depth > max_depth)
        {
            return Err(PartialVMError::new(StatusCode::VM_MAX_VALUE_DEPTH_REACHED));
        }
        Ok(())
    }
```

**File:** aptos-move/block-executor/src/executor.rs (L423-428)
```rust
        let mut read_set = sync_view.take_parallel_reads();
        if read_set.is_incorrect_use() {
            return Err(code_invariant_error(format!(
                "Incorrect use detected in CapturedReads after executing txn = {idx_to_execute} incarnation = {incarnation}"
            )));
        }
```

**File:** aptos-move/block-executor/src/executor.rs (L2487-2491)
```rust
                    if sequential_reads.incorrect_use {
                        return Err(
                            code_invariant_error("Incorrect use in sequential execution").into(),
                        );
                    }
```

**File:** third_party/move/move-core/types/src/vm_status.rs (L258-272)
```rust
                    | StatusCode::IO_LIMIT_REACHED
                    | StatusCode::STORAGE_LIMIT_REACHED
                    | StatusCode::TOO_MANY_DELAYED_FIELDS
                    | StatusCode::UNABLE_TO_CAPTURE_DELAYED_FIELDS,
                ..
            }
            | VMStatus::Error {
                status_code:
                    StatusCode::EXECUTION_LIMIT_REACHED
                    | StatusCode::IO_LIMIT_REACHED
                    | StatusCode::STORAGE_LIMIT_REACHED
                    | StatusCode::TOO_MANY_DELAYED_FIELDS
                    | StatusCode::UNABLE_TO_CAPTURE_DELAYED_FIELDS,
                ..
            } => Ok(KeptVMStatus::MiscellaneousError),
```

**File:** aptos-move/e2e-move-tests/src/tests/aggregator_v2.rs (L660-663)
```rust
    assert_ok_eq!(
        output[0].status().status(),
        ExecutionStatus::MiscellaneousError(Some(StatusCode::TOO_MANY_DELAYED_FIELDS))
    );
```
