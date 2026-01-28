# Audit Report

## Title
Non-Deterministic Random Number Generation in Consensus-Critical Change Set Squashing

## Summary
The `randomly_check_layout_matches` function uses `rand::thread_rng()`, a non-deterministic random number generator, during consensus-critical transaction execution. This violates the fundamental blockchain requirement of deterministic execution and could cause validators to produce different outcomes for identical transactions, leading to consensus failure.

## Finding Description

The vulnerability exists in the `randomly_check_layout_matches` function which is called during change set squashing operations that occur in consensus-critical transaction execution paths. [1](#0-0) 

The function uses `rand::thread_rng()` at line 64, which generates non-deterministic random numbers based on OS entropy. Each validator will independently generate different random numbers. When `random_number == 1` (1% probability), the function checks if two type layouts match, and returns an error if they don't match.

This function is called during abort hook processing when transactions fail. The execution path is:

1. Transaction aborts → `make_failure_vm_output` [2](#0-1) 

2. Abort hook session finishes → `finish_with_squashed_change_set` [3](#0-2) 

3. Change sets are squashed → `squash_additional_resource_writes` [4](#0-3) 

4. For `WriteWithDelayedFields` operations → `randomly_check_layout_matches` is called [5](#0-4) 

**Consensus Divergence Scenario:**
If type layouts ever mismatch (which the error handling code anticipates), different validators will behave differently:
- Validator A (random_number ≠ 1): Skips layout check, transaction succeeds
- Validator B (random_number = 1): Performs check, detects mismatch, transaction fails with error

This violates the blockchain invariant that all validators must execute identical transactions identically and produce the same state root.

## Impact Explanation

This meets **Critical Severity** per Aptos Bug Bounty criteria for **Consensus/Safety Violations**:

- **Deterministic Execution Violation**: Different validators produce different execution results for identical transactions due to different random numbers
- **Potential State Root Divergence**: If the random check triggers different outcomes, validators cannot reach consensus on the state root
- **Network Partition Risk**: Sustained divergence could require manual intervention or hard fork to resolve

Even if layout mismatches are rare or theoretical, the use of non-deterministic randomness in consensus code is a fundamental design flaw that violates blockchain safety guarantees.

## Likelihood Explanation

**Logic Vulnerability**: This is primarily a logic error rather than an immediately exploitable bug. The likelihood of actual consensus divergence depends on whether type layout mismatches can occur in practice.

The code comment indicates layouts are "supposed to match", suggesting mismatches shouldn't occur in correct operation. However:
- The error handling exists, indicating developers anticipated possible mismatches
- Future code changes could introduce scenarios where layouts don't match
- The non-deterministic random check itself violates consensus determinism requirements

Even if not currently triggered, this represents a critical design flaw in consensus-critical code.

## Recommendation

Remove non-deterministic randomness from consensus-critical code paths. Options include:

1. **Remove the random check entirely** if layouts are guaranteed to always match:
```rust
pub fn check_layout_matches(
    layout_1: Option<&MoveTypeLayout>,
    layout_2: Option<&MoveTypeLayout>,
) -> Result<(), PanicError> {
    if layout_1.is_some() != layout_2.is_some() {
        return Err(code_invariant_error(...));
    }
    // Always check if both present
    if layout_1.is_some() && layout_1 != layout_2 {
        return Err(code_invariant_error(...));
    }
    Ok(())
}
```

2. **Use deterministic sampling** based on transaction hash if probabilistic checking is desired for performance
3. **Always validate layouts** if correctness is critical

## Proof of Concept

The non-deterministic behavior can be demonstrated by observing that different execution runs produce different random numbers:

```rust
// This code demonstrates the non-determinism
use rand::Rng;

fn demonstrate_non_determinism() {
    // Run 1
    let mut rng1 = rand::thread_rng();
    let random1: u32 = rng1.gen_range(0, 100);
    
    // Run 2  
    let mut rng2 = rand::thread_rng();
    let random2: u32 = rng2.gen_range(0, 100);
    
    // These will be different with high probability
    assert_ne!(random1, random2);
}
```

The actual consensus divergence would require triggering a scenario with layout mismatches during abort hook execution with `WriteWithDelayedFields` operations, which the codebase currently may not exhibit but the error handling anticipates.

## Notes

This vulnerability represents a **logic flaw** in the codebase design rather than a currently exploitable attack. The use of `rand::thread_rng()` in consensus-critical code violates fundamental blockchain principles of deterministic execution. While the practical exploitability depends on whether layout mismatches can occur, the presence of non-deterministic randomness in this code path is itself a critical design error that should be addressed.

### Citations

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L49-74)
```rust
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

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L554-737)
```rust
    pub(crate) fn squash_additional_resource_writes(
        write_set: &mut BTreeMap<StateKey, AbstractResourceWriteOp>,
        additional_write_set: BTreeMap<StateKey, AbstractResourceWriteOp>,
    ) -> Result<(), PanicError> {
        use AbstractResourceWriteOp::*;
        for (key, additional_entry) in additional_write_set.into_iter() {
            match write_set.entry(key.clone()) {
                Vacant(entry) => {
                    entry.insert(additional_entry);
                },
                Occupied(mut entry) => {
                    let (to_delete, to_overwrite) = match (entry.get_mut(), &additional_entry) {
                        (Write(write_op), Write(additional_write_op)) => {
                            let to_delete = !WriteOp::squash(write_op, additional_write_op.clone())
                                .map_err(|e| {
                                    code_invariant_error(format!(
                                        "Error while squashing two write ops: {}.",
                                        e
                                    ))
                                })?;
                            (to_delete, false)
                        },
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
                        (
                            WriteResourceGroup(group),
                            WriteResourceGroup(GroupWrite {
                                metadata_op: additional_metadata_op,
                                inner_ops: additional_inner_ops,
                                maybe_group_op_size: additional_maybe_group_op_size,
                                prev_group_size: _, // n.b. group.prev_group_size deliberately kept as is
                            }),
                        ) => {
                            // Squashing creation and deletion is a no-op. In that case, we have to
                            // remove the old GroupWrite from the group write set.
                            let to_delete = !WriteOp::squash(
                                &mut group.metadata_op,
                                additional_metadata_op.clone(),
                            )
                            .map_err(|e| {
                                code_invariant_error(format!(
                                    "Error while squashing two group write metadata ops: {}.",
                                    e
                                ))
                            })?;
                            if to_delete {
                                (true, false)
                            } else {
                                Self::squash_additional_resource_write_ops(
                                    &mut group.inner_ops,
                                    additional_inner_ops.clone(),
                                )?;

                                group.maybe_group_op_size = *additional_maybe_group_op_size;

                                //
                                // n.b. group.prev_group_size deliberately kept as is
                                //

                                (false, false)
                            }
                        },
                        (
                            WriteWithDelayedFields(WriteWithDelayedFieldsOp {
                                materialized_size,
                                ..
                            }),
                            InPlaceDelayedFieldChange(InPlaceDelayedFieldChangeOp {
                                materialized_size: additional_materialized_size,
                                ..
                            }),
                        ) => {
                            // Read cannot change the size (i.e. delayed fields don't modify size)
                            if materialized_size != &Some(*additional_materialized_size) {
                                return Err(code_invariant_error(format!(
                                    "Trying to squash writes where read has different size: {:?}: {:?}",
                                    materialized_size,
                                    additional_materialized_size
                                )));
                            }
                            // any newer read should've read the original write and contain all info from it
                            (false, false)
                        },
                        (
                            WriteResourceGroup(GroupWrite {
                                maybe_group_op_size: materialized_size,
                                ..
                            }),
                            ResourceGroupInPlaceDelayedFieldChange(
                                ResourceGroupInPlaceDelayedFieldChangeOp {
                                    materialized_size: additional_materialized_size,
                                    ..
                                },
                            ),
                        ) => {
                            // Read cannot change the size (i.e. delayed fields don't modify size)
                            if materialized_size.map(|v| v.get())
                                != Some(*additional_materialized_size)
                            {
                                return Err(code_invariant_error(format!(
                                    "Trying to squash group writes where read has different size: {:?}: {:?}",
                                    materialized_size,
                                    additional_materialized_size
                                )));
                            }
                            // any newer read should've read the original write and contain all info from it
                            (false, false)
                        },
                        // If previous value is a read, newer value overwrites it
                        (
                            InPlaceDelayedFieldChange(_),
                            WriteWithDelayedFields(_) | InPlaceDelayedFieldChange(_),
                        )
                        | (
                            ResourceGroupInPlaceDelayedFieldChange(_),
                            WriteResourceGroup(_) | ResourceGroupInPlaceDelayedFieldChange(_),
                        ) => (false, true),
                        (
                            Write(_),
                            WriteWithDelayedFields(_)
                            | WriteResourceGroup(_)
                            | InPlaceDelayedFieldChange(_)
                            | ResourceGroupInPlaceDelayedFieldChange(_),
                        )
                        | (
                            WriteWithDelayedFields(_),
                            Write(_)
                            | WriteResourceGroup(_)
                            | ResourceGroupInPlaceDelayedFieldChange(_),
                        )
                        | (
                            WriteResourceGroup(_),
                            Write(_) | WriteWithDelayedFields(_) | InPlaceDelayedFieldChange(_),
                        )
                        | (
                            InPlaceDelayedFieldChange(_),
                            Write(_)
                            | WriteResourceGroup(_)
                            | ResourceGroupInPlaceDelayedFieldChange(_),
                        )
                        | (
                            ResourceGroupInPlaceDelayedFieldChange(_),
                            Write(_) | WriteWithDelayedFields(_) | InPlaceDelayedFieldChange(_),
                        ) => {
                            return Err(code_invariant_error(format!(
                                "Trying to squash incompatible writes: {:?}: {:?} into {:?}.",
                                entry.key(),
                                entry.get(),
                                additional_entry
                            )));
                        },
                    };

                    if to_overwrite {
                        entry.insert(additional_entry);
                    } else if to_delete {
                        entry.remove();
                    }
                },
            }
        }
        Ok(())
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L705-742)
```rust
        let should_create_account_resource =
            should_create_account_resource(txn_data, self.features(), resolver, module_storage)?;

        let (previous_session_change_set, fee_statement) = if should_create_account_resource {
            let mut abort_hook_session =
                AbortHookSession::new(self, txn_data, resolver, prologue_session_change_set);

            abort_hook_session.execute(|session| {
                create_account_if_does_not_exist(
                    session,
                    module_storage,
                    gas_meter,
                    txn_data.sender(),
                    traversal_context,
                )
                // If this fails, it is likely due to out of gas, so we try again without metering
                // and then validate below that we charged sufficiently.
                .or_else(|_err| {
                    create_account_if_does_not_exist(
                        session,
                        module_storage,
                        &mut UnmeteredGasMeter,
                        txn_data.sender(),
                        traversal_context,
                    )
                })
                .map_err(expect_no_verification_errors)
                .or_else(|err| {
                    expect_only_successful_execution(
                        err,
                        &format!("{:?}::{}", ACCOUNT_MODULE, CREATE_ACCOUNT_IF_DOES_NOT_EXIST),
                        log_context,
                    )
                })
            })?;

            let mut abort_hook_session_change_set =
                abort_hook_session.finish(change_set_configs, module_storage)?;
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/respawned_session.rs (L72-109)
```rust
    pub fn finish_with_squashed_change_set(
        mut self,
        change_set_configs: &ChangeSetConfigs,
        module_storage: &impl ModuleStorage,
        assert_no_additional_creation: bool,
    ) -> Result<VMChangeSet, VMStatus> {
        let additional_change_set = self.with_session_mut(|session| {
            unwrap_or_invariant_violation(
                session.take(),
                "VM session cannot be finished more than once.",
            )?
            .finish(change_set_configs, module_storage)
            .map_err(|e| e.into_vm_status())
        })?;
        if assert_no_additional_creation && additional_change_set.has_creation() {
            // After respawning in the epilogue, there shouldn't be new slots
            // created, otherwise there's a potential vulnerability like this:
            // 1. slot created by the user
            // 2. another user transaction deletes the slot and claims the refund
            // 3. in the epilogue the same slot gets recreated, and the final write set will have
            //    a ModifyWithMetadata carrying the original metadata
            // 4. user keeps doing the same and repeatedly claim refund out of the slot.
            return Err(VMStatus::error(
                StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR,
                err_msg("Unexpected storage allocation after respawning session."),
            ));
        }
        let mut change_set = self.into_heads().executor_view.change_set;
        change_set
            .squash_additional_change_set(additional_change_set)
            .map_err(|_err| {
                VMStatus::error(
                    StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR,
                    err_msg("Failed to squash VMChangeSet"),
                )
            })?;
        Ok(change_set)
    }
```
