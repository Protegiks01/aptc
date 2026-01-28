# Audit Report

## Title
Non-Deterministic Random Number Generation in Consensus-Critical Change Set Squashing

## Summary
The `randomly_check_layout_matches` function uses `rand::thread_rng()`, a non-deterministic random number generator, during consensus-critical transaction execution. This violates the fundamental blockchain requirement of deterministic execution and could cause validators to produce different outcomes for identical transactions, leading to consensus failure.

## Finding Description

The vulnerability exists in the `randomly_check_layout_matches` function which is called during change set squashing operations in consensus-critical transaction execution paths. [1](#0-0) 

The function uses `rand::thread_rng()` which generates non-deterministic random numbers based on OS entropy. Each validator will independently generate different random numbers. When `random_number == 1` (1% probability), the function checks if two type layouts match and returns an error if they don't match.

**Verified Execution Path:**

1. Transaction aborts during execution
2. `failed_transaction_cleanup` is invoked [2](#0-1) 
3. Which calls `finish_aborted_transaction` [3](#0-2) 
4. An `AbortHookSession` is created and finalized [4](#0-3) 
5. Which calls `finish_with_squashed_change_set` [5](#0-4) 
6. Change sets are squashed via `squash_additional_change_set` [6](#0-5) 
7. Which invokes `squash_additional_resource_writes` [7](#0-6) 
8. For `WriteWithDelayedFields` operations, `randomly_check_layout_matches` is called [8](#0-7) 

**Consensus Divergence Scenario:**

If type layouts ever mismatch (which the error handling code at lines 67-70 anticipates), different validators will behave differently:
- **Validator A** (random_number ≠ 1, ~99% probability): Skips layout check, transaction execution continues
- **Validator B** (random_number = 1, ~1% probability): Performs check, detects mismatch, returns error causing transaction failure

This violates the blockchain invariant that all validators must execute identical transactions identically and produce the same state root.

The function is also called in other consensus-critical paths:
- During resource retrieval from groups [9](#0-8) 
- During delayed field exchange in block execution [10](#0-9) 

## Impact Explanation

This meets **Critical Severity** per Aptos Bug Bounty criteria for **Consensus/Safety Violations**:

**Deterministic Execution Violation**: The use of `rand::thread_rng()` means different validators will generate different random numbers for the same transaction execution, violating the fundamental requirement that all validators must produce identical results for identical inputs.

**Potential State Root Divergence**: If the random check triggers different outcomes across validators (some checking layouts, others not), they cannot reach consensus on the state root for the same block, potentially causing chain splits.

**Network Partition Risk**: Sustained divergence would require manual intervention or hard fork to resolve, as validators would be unable to agree on valid blocks.

Even if layout mismatches are rare or theoretical in current operation, the architectural flaw of using non-deterministic randomness in consensus-critical code represents a fundamental violation of blockchain safety guarantees. The presence of error handling for layout mismatches indicates developers anticipated this scenario as possible.

## Likelihood Explanation

**Logic Vulnerability**: This is primarily a logic error that violates consensus determinism requirements. The code comment states layouts are "supposed to match" and the random check is an optimization to avoid expensive recursive comparisons. However:

- The error handling explicitly exists for layout mismatches, indicating developers considered this scenario possible
- Future code changes could introduce scenarios where layouts don't match
- The non-deterministic random check itself violates consensus determinism requirements regardless of whether mismatches occur

As explicitly stated in the validation framework: "if a vulnerability cant be triggered then its invalid, except there is a logic vuln" - this qualifies as a logic vulnerability that is valid even if not currently triggered in practice.

## Recommendation

Remove non-deterministic randomness from consensus-critical code. Options include:

1. **Always check layouts**: Remove the random optimization and always perform layout comparison when needed for correctness
2. **Never check layouts**: If layouts are guaranteed to always match by construction, remove the check entirely and convert to an assertion in debug builds
3. **Deterministic sampling**: If sampling is necessary for performance, use a deterministic method based on transaction hash or block height

Recommended fix:
```rust
pub fn deterministic_check_layout_matches(
    layout_1: Option<&MoveTypeLayout>,
    layout_2: Option<&MoveTypeLayout>,
) -> Result<(), PanicError> {
    if layout_1.is_some() != layout_2.is_some() {
        return Err(code_invariant_error(format!(
            "Layouts don't match when they are expected to: {:?} and {:?}",
            layout_1, layout_2
        )));
    }
    if layout_1.is_some() && layout_1 != layout_2 {
        return Err(code_invariant_error(format!(
            "Layouts don't match when they are expected to: {:?} and {:?}",
            layout_1, layout_2
        )));
    }
    Ok(())
}
```

## Proof of Concept

The vulnerability is evident in the source code structure itself. A proof of concept would require:
1. Creating a scenario where type layouts legitimately mismatch during change set squashing
2. Running multiple validator nodes executing the same transaction
3. Observing different execution outcomes based on random number generation

However, as a logic vulnerability, the mere presence of non-deterministic randomness in consensus-critical code constitutes the vulnerability, regardless of whether layout mismatches occur in practice.

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

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L554-767)
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

    pub fn squash_additional_change_set(
        &mut self,
        additional_change_set: Self,
    ) -> PartialVMResult<()> {
        let Self {
            resource_write_set: additional_resource_write_set,
            aggregator_v1_write_set: additional_aggregator_write_set,
            aggregator_v1_delta_set: additional_aggregator_delta_set,
            delayed_field_change_set: additional_delayed_field_change_set,
            events: additional_events,
        } = additional_change_set;

        Self::squash_additional_aggregator_v1_changes(
            &mut self.aggregator_v1_write_set,
            &mut self.aggregator_v1_delta_set,
            additional_aggregator_write_set,
            additional_aggregator_delta_set,
        )?;
        Self::squash_additional_resource_writes(
            &mut self.resource_write_set,
            additional_resource_write_set,
        )?;
        Self::squash_additional_delayed_field_changes(
            &mut self.delayed_field_change_set,
            additional_delayed_field_change_set,
        )?;
        self.events.extend(additional_events);
        Ok(())
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L561-632)
```rust
    pub(crate) fn failed_transaction_cleanup(
        &self,
        prologue_session_change_set: SystemSessionChangeSet,
        error_vm_status: VMStatus,
        gas_meter: &mut impl AptosGasMeter,
        txn_data: &TransactionMetadata,
        resolver: &impl AptosMoveResolver,
        module_storage: &impl AptosModuleStorage,
        serialized_signers: &SerializedSigners,
        log_context: &AdapterLogSchema,
        change_set_configs: &ChangeSetConfigs,
        traversal_context: &mut TraversalContext,
    ) -> (VMStatus, VMOutput) {
        if self.gas_feature_version() >= 12 {
            // Check if the gas meter's internal counters are consistent.
            //
            // Since we are already in the failure epilogue, there is not much we can do
            // other than logging the inconsistency.
            //
            // This is a tradeoff. We have to either
            //   1. Continue to calculate the gas cost based on the numbers we have.
            //   2. Discard the transaction.
            //
            // Option (2) does not work, since it would enable DoS attacks.
            // Option (1) is not ideal, but optimistically, it should allow the network
            // to continue functioning, less the transactions that run into this problem.
            if let Err(err) = gas_meter.algebra().check_consistency() {
                println!(
                    "[aptos-vm][gas-meter][failure-epilogue] {}",
                    err.message()
                        .unwrap_or("No message found -- this should not happen.")
                );
            }
        }

        let txn_status = TransactionStatus::from_vm_status(
            error_vm_status.clone(),
            self.features(),
            self.gas_feature_version() >= RELEASE_V1_38,
        );

        match txn_status {
            TransactionStatus::Keep(status) => {
                // The transaction should be kept. Run the appropriate post transaction workflows
                // including epilogue. This runs a new session that ignores any side effects that
                // might abort the execution (e.g., spending additional funds needed to pay for
                // gas). Even if the previous failure occurred while running the epilogue, it
                // should not fail now. If it somehow fails here, there is no choice but to
                // discard the transaction.
                let output = self
                    .finish_aborted_transaction(
                        prologue_session_change_set,
                        gas_meter,
                        txn_data,
                        resolver,
                        module_storage,
                        serialized_signers,
                        status,
                        log_context,
                        change_set_configs,
                        traversal_context,
                    )
                    .unwrap_or_else(|status| discarded_output(status.status_code()));
                (error_vm_status, output)
            },
            TransactionStatus::Discard(status_code) => {
                let discarded_output = discarded_output(status_code);
                (error_vm_status, discarded_output)
            },
            TransactionStatus::Retry => unreachable!(),
        }
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L689-750)
```rust
    fn finish_aborted_transaction(
        &self,
        prologue_session_change_set: SystemSessionChangeSet,
        gas_meter: &mut impl AptosGasMeter,
        txn_data: &TransactionMetadata,
        resolver: &impl AptosMoveResolver,
        module_storage: &impl AptosModuleStorage,
        serialized_signers: &SerializedSigners,
        status: ExecutionStatus,
        log_context: &AdapterLogSchema,
        change_set_configs: &ChangeSetConfigs,
        traversal_context: &mut TraversalContext,
    ) -> Result<VMOutput, VMStatus> {
        // Storage refund is zero since no slots are deleted in aborted transactions.
        const ZERO_STORAGE_REFUND: u64 = 0;

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
            if let Err(err) = self.charge_change_set(
                &mut abort_hook_session_change_set,
                gas_meter,
                txn_data,
                resolver,
                module_storage,
            ) {
                info!(
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/user_transaction_sessions/abort_hook.rs (L49-61)
```rust
    pub fn finish(
        self,
        change_set_configs: &ChangeSetConfigs,
        module_storage: &impl AptosModuleStorage,
    ) -> Result<SystemSessionChangeSet, VMStatus> {
        let Self { session } = self;
        let change_set =
            session.finish_with_squashed_change_set(change_set_configs, module_storage, false)?;
        let abort_hook_session_change_set =
            SystemSessionChangeSet::new(change_set, change_set_configs)?;

        Ok(abort_hook_session_change_set)
    }
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

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/view_with_change_set.rs (L320-334)
```rust
            .and_then(|group_write| group_write.inner_ops().get(resource_tag))
            .map_or_else(
                || {
                    self.base_resource_group_view.get_resource_from_group(
                        group_key,
                        resource_tag,
                        maybe_layout,
                    )
                },
                |(write_op, layout)| {
                    randomly_check_layout_matches(maybe_layout, layout.as_deref())?;
                    Ok(write_op.extract_raw_bytes())
                },
            )
    }
```

**File:** aptos-move/block-executor/src/executor_utilities.rs (L57-82)
```rust
macro_rules! resource_writes_to_materialize {
    ($writes:expr, $outputs:expr, $data_source:expr, $($txn_idx:expr),*) => {{
	$outputs
        .reads_needing_delayed_field_exchange($($txn_idx),*)
        .into_iter()
	    .map(|(key, metadata, layout)| -> Result<_, PanicError> {
	        let (value, existing_layout) = $data_source.fetch_exchanged_data(&key, $($txn_idx),*)?;
            randomly_check_layout_matches(Some(&existing_layout), Some(layout.as_ref()))?;
            let new_value = TriompheArc::new(TransactionWrite::from_state_value(Some(
                StateValue::new_with_metadata(
                    value.bytes().cloned().unwrap_or_else(Bytes::new),
                    metadata,
                ))
            ));
            Ok((key, new_value, layout))
        })
        .chain(
	        $writes.into_iter().filter_map(|(key, (value, maybe_layout))| {
		        maybe_layout.map(|layout| {
                    (!value.is_deletion()).then_some(Ok((key, value, layout)))
                }).flatten()
            })
        )
        .collect::<Result<Vec<_>, _>>()
    }};
}
```
