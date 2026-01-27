# Audit Report

## Title
Probabilistic Layout Validation Creates Non-Deterministic Consensus Failure in WriteWithDelayedFields Squashing

## Summary
The `squash_additional_resource_writes()` function uses a probabilistic layout check (`randomly_check_layout_matches()`) that only validates type layout equality 1% of the time. This creates a non-deterministic failure detection mechanism that could lead to consensus divergence if layout mismatches occur, violating the deterministic execution invariant.

## Finding Description
When squashing two `WriteWithDelayedFields` operations for the same resource, the system performs a layout compatibility check. However, this check is probabilistic rather than deterministic. [1](#0-0) 

The `randomly_check_layout_matches()` function only performs the actual layout equality check when `random_number == 1` (1 in 100 chance). This means mismatched layouts pass through unchecked 99% of the time.

When squashing `WriteWithDelayedFields` operations: [2](#0-1) 

If layouts mismatch but pass the random check, the materialized_size is updated but the wrong layout is retained. Later, during delayed field materialization, this causes deserialization failures: [3](#0-2) 

The deserialization uses the stored layout, and if it doesn't match the actual byte structure, it fails with "Failed to deserialize resource during id replacement".

**Critical Issue**: Different validator nodes generate different random numbers, meaning they will catch layout mismatches at different rates. This creates **non-deterministic consensus behavior** - some validators fail while others succeed, breaking the fundamental deterministic execution invariant.

## Impact Explanation
This meets **High Severity** criteria under "Significant protocol violations" for the following reasons:

1. **Consensus Non-Determinism**: Validators executing the same block with mismatched layouts will have different outcomes based on random chance (1% detection rate), causing state root divergence.

2. **Unpredictable Failures**: When the random check fails to catch a mismatch (99% probability), delayed field materialization fails later in the pipeline, potentially causing validator crashes or transaction execution failures.

3. **Failure Amplification**: Any bug in the system that causes layout mismatches becomes 99x harder to detect, as most validators will process it incorrectly and only 1% will catch the error.

While I cannot demonstrate a concrete attack path to trigger layout mismatches (as layouts should be deterministic for a given type), the **probabilistic validation itself violates consensus safety requirements** by introducing random behavior into a system that must be deterministic.

## Likelihood Explanation
**Likelihood: Low to Medium**

The vulnerability requires:
1. A pre-existing condition that causes layout mismatches (e.g., bugs in parallel execution, type system edge cases, or module upgrade timing issues)
2. Multiple writes to the same resource with different layouts reaching the squashing logic

The developers' comment indicates they believe layouts "should" always match, suggesting this is defensive code. However, the probabilistic check means if layouts ever DO mismatch due to bugs elsewhere:
- 99% of validators miss the error and proceed with wrong layouts
- 1% of validators detect it and reject the transaction
- This creates consensus divergence

## Recommendation
Replace the probabilistic check with a deterministic one. Either:

**Option 1 (Strict)**: Always check layout equality
```rust
pub fn randomly_check_layout_matches(
    layout_1: Option<&MoveTypeLayout>,
    layout_2: Option<&MoveTypeLayout>,
) -> Result<(), PanicError> {
    if layout_1 != layout_2 {
        return Err(code_invariant_error(format!(
            "Layouts don't match when they are expected to: {:?} and {:?}",
            layout_1, layout_2
        )));
    }
    Ok(())
}
```

**Option 2 (Performance-Aware)**: Add a feature flag for deterministic vs optimized mode, using full checks in production and random checks only in testing.

## Proof of Concept
Due to the nature of this vulnerability (requiring pre-existing layout mismatch bugs), a full PoC cannot be provided without first demonstrating how to cause layouts to mismatch. However, the non-determinism can be demonstrated:

```rust
#[test]
fn test_random_check_non_determinism() {
    use move_core_types::value::MoveTypeLayout;
    
    let layout1 = MoveTypeLayout::U64;
    let layout2 = MoveTypeLayout::U128;
    
    let mut success_count = 0;
    let mut failure_count = 0;
    
    // Run check 1000 times - should see ~10 failures, ~990 successes
    for _ in 0..1000 {
        match randomly_check_layout_matches(Some(&layout1), Some(&layout2)) {
            Ok(_) => success_count += 1,
            Err(_) => failure_count += 1,
        }
    }
    
    // Demonstrates non-deterministic behavior
    assert!(success_count > 900, "Check passed {} times when layouts actually differ", success_count);
    assert!(failure_count > 0, "Check failed {} times", failure_count);
    
    // In consensus: different validators would get different results
    println!("Non-deterministic: {} successes, {} failures for mismatched layouts", 
             success_count, failure_count);
}
```

This demonstrates that identical inputs produce different validation outcomes across executions, which is fundamentally incompatible with deterministic consensus requirements.

**Notes:**
- The vulnerability is in the validation mechanism itself (probabilistic checking in a deterministic system), not necessarily in the ability to trigger layout mismatches
- Even if layout mismatches "should never happen" in correct execution, consensus systems must fail deterministically, not probabilistically
- The 1% check rate creates a 99% silent failure rate, making debugging extremely difficult if layout mismatches do occur

### Citations

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L48-74)
```rust
/// Sporadically checks if the given two input type layouts match.
pub fn randomly_check_layout_matches(
    layout_1: Option<&MoveTypeLayout>,
    layout_2: Option<&MoveTypeLayout>,
) -> Result<(), PanicError> {
    if layout_1.is_some() != layout_2.is_some() {
        return Err(code_invariant_error(format!(
            "Layouts don't match when they are expected to: {:?} and {:?}",
            layout_1, layout_2
        )));
    }
    if layout_1.is_some() {
        // Checking if 2 layouts are equal is a recursive operation and is expensive.
        // We generally call this `randomly_check_layout_matches` function when we know
        // that the layouts are supposed to match. As an optimization, we only randomly
        // check if the layouts are matching.
        let mut rng = rand::thread_rng();
        let random_number: u32 = rng.gen_range(0, 100);
        if random_number == 1 && layout_1 != layout_2 {
            return Err(code_invariant_error(format!(
                "Layouts don't match when they are expected to: {:?} and {:?}",
                layout_1, layout_2
            )));
        }
    }
    Ok(())
}
```

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L576-598)
```rust
                        (
                            WriteWithDelayedFields(WriteWithDelayedFieldsOp {
                                write_op,
                                layout,
                                materialized_size,
                            }),
                            WriteWithDelayedFields(WriteWithDelayedFieldsOp {
                                write_op: additional_write_op,
                                layout: additional_layout,
                                materialized_size: additional_materialized_size,
                            }),
                        ) => {
                            randomly_check_layout_matches(Some(layout), Some(additional_layout))?;
                            let to_delete = !WriteOp::squash(write_op, additional_write_op.clone())
                                .map_err(|e| {
                                    code_invariant_error(format!(
                                        "Error while squashing two write ops: {}.",
                                        e
                                    ))
                                })?;
                            *materialized_size = *additional_materialized_size;
                            (to_delete, false)
                        },
```

**File:** aptos-move/block-executor/src/view.rs (L1269-1325)
```rust
    pub(crate) fn replace_identifiers_with_values(
        &self,
        bytes: &Bytes,
        layout: &MoveTypeLayout,
    ) -> anyhow::Result<(Bytes, HashSet<DelayedFieldID>)> {
        // Cfg due to deserialize_to_delayed_field_id use.
        #[cfg(test)]
        fail_point!("delayed_field_test", |_| {
            assert_eq!(
                layout,
                &mock_layout(),
                "Layout does not match expected mock layout"
            );

            // Replicate the logic of identifier_to_value.
            let (delayed_field_id, txn_idx) = deserialize_to_delayed_field_id(bytes)
                .expect("Mock deserialization failed in delayed field test.");
            let delayed_field = match &self.latest_view {
                ViewState::Sync(state) => state
                    .versioned_map
                    .delayed_fields()
                    .read_latest_predicted_value(
                        &delayed_field_id,
                        self.txn_idx,
                        ReadPosition::AfterCurrentTxn,
                    )
                    .expect("Committed value for ID must always exist"),
                ViewState::Unsync(state) => state
                    .read_delayed_field(delayed_field_id)
                    .expect("Delayed field value for ID must always exist in sequential execution"),
            };

            // Note: Test correctness relies on the fact that current proptests use the
            // same layout for all values ever stored at any key, given that some value
            // at the key contains a delayed field.
            Ok((
                serialize_from_delayed_field_u128(
                    delayed_field.into_aggregator_value().unwrap(),
                    txn_idx,
                ),
                HashSet::from([delayed_field_id]),
            ))
        });

        // This call will replace all occurrences of aggregator / snapshot
        // identifiers with values with the same type layout.
        let function_value_extension = self.as_function_value_extension();
        let value = ValueSerDeContext::new(function_value_extension.max_value_nest_depth())
            .with_func_args_deserialization(&function_value_extension)
            .with_delayed_fields_serde()
            .deserialize(bytes, layout)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Failed to deserialize resource during id replacement: {:?}",
                    bytes
                )
            })?;
```
