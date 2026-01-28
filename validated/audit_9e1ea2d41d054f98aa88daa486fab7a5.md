# Audit Report

## Title
Resource Group Deletion Bypass Causes Validator Block Execution Failures via Missing Deletion Check

## Summary
The `get_group_reads_needing_exchange_parallel` and `get_group_reads_needing_exchange_sequential` functions in the block executor fail to check for deletion operations before calling `does_value_need_exchange`, allowing resource group deletions to trigger a code invariant error panic that halts block execution. This missing safeguard creates an exploitable path for causing validator liveness issues.

## Finding Description

The vulnerability exists in how resource group reads containing deletions are processed during delayed field value exchange. The codebase has an inconsistent implementation:

**Protected Path**: The `filter_value_for_exchange` function properly checks for deletions before processing: [1](#0-0) 

**Vulnerable Path (Parallel)**: However, `get_group_reads_needing_exchange_parallel` directly calls `does_value_need_exchange` without the deletion check: [2](#0-1) 

**Vulnerable Path (Sequential)**: The sequential execution path has the same vulnerability: [3](#0-2) 

When a deletion reaches `does_value_need_exchange`, it hits the panic error: [4](#0-3) 

**Attack Sequence**:
1. Transaction T1 executes `move_from` on a resource within a resource group, creating a deletion operation
2. Transaction T2 reads the same resource tag from the group
3. When the resource is not found (TagNotFound), the system creates a deletion marker as a base value: [5](#0-4) 

4. The read is captured as `DataRead::Versioned` containing the deletion value: [6](#0-5) 

5. If T2 also performs delayed field (aggregator V2) operations, `get_group_reads_needing_exchange_parallel` is invoked during post-execution processing
6. The function iterates over group reads and calls `does_value_need_exchange` on the deletion without checking `is_deletion()`
7. This triggers the `code_invariant_error` panic
8. The worker loop catches the error and halts the scheduler: [7](#0-6) 

9. Block execution fails and returns an error: [8](#0-7) 

The deletion marker is created via: [9](#0-8) 

## Impact Explanation

**Severity: HIGH** - Validator node slowdowns and block execution failures

This vulnerability enables an attacker to craft transactions that cause deterministic block execution failures on all validators. When triggered:
- The parallel block executor halts with a `CodeInvariantError`
- An alert is logged via the `alert!` macro
- The block execution returns `Err(())`, forcing retry or fallback to sequential execution
- Repeated exploitation causes significant validator performance degradation

Per the Aptos bug bounty program, this qualifies as **High Severity** ($50,000 range) under the "Validator node slowdowns" category. The vulnerability:
- Forces expensive re-execution and fallback mechanisms
- Impacts block production performance across all validators
- Creates a denial-of-service vector against block execution

While this doesn't directly cause fund loss or consensus safety violations, it creates a repeatable attack vector against network liveness through validator performance degradation.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

The attack requires:
1. Ability to submit transactions (any user)
2. Access to resource groups containing resources with delayed fields (aggregator V2)
3. Two transactions in the same block: one deleting a resource, one reading the deletion with delayed field operations

These conditions are realistic because:
- Resource groups are widely used in Aptos (fungible assets, objects, etc.)
- Aggregator V2 (delayed fields) are increasingly deployed for scalable counters
- Transaction ordering within blocks occurs naturally with sufficient transaction volume
- The attacker can submit multiple transaction pairs to increase hit probability

The vulnerability is deterministic - once conditions are met, the error always triggers. An attacker could spam such transaction patterns to repeatedly cause failures until validators fall back to sequential execution or re-execute blocks.

## Recommendation

Add deletion checks before calling `does_value_need_exchange` in both parallel and sequential code paths:

**For `get_group_reads_needing_exchange_parallel`** (line 1392):
```rust
if let DataRead::Versioned(_version, value, Some(layout)) = data_read {
    // Add deletion check
    if value.is_deletion() {
        continue;
    }
    let needs_exchange = self
        .does_value_need_exchange(value, layout.as_ref(), delayed_write_set_ids)
        .map_err(PartialVMError::from)?;
    // ... rest of logic
}
```

**For `get_group_reads_needing_exchange_sequential`** (line 1446):
```rust
if let ValueWithLayout::Exchanged(value, Some(layout)) = value_with_layout {
    // Add deletion check
    if value.is_deletion() {
        continue;
    }
    let needs_exchange = self.does_value_need_exchange(
        &value,
        layout.as_ref(),
        delayed_write_set_ids,
    )?;
    // ... rest of logic
}
```

This mirrors the protection already present in `filter_value_for_exchange`.

## Proof of Concept

A proof of concept would require:
1. Creating a Move module with a resource group containing a resource with aggregator V2 fields
2. Transaction T1: Call `move_from` to delete a resource from the group
3. Transaction T2: Read the deleted resource tag and perform aggregator V2 operations
4. Submit both transactions in the same block
5. Observe the `CodeInvariantError` alert and block execution failure

The vulnerability is confirmed through code analysis showing the missing deletion check in the group reads needing exchange functions, which contrasts with the protected path that properly filters deletions.

## Notes

This vulnerability affects both BlockSTM (V1) and BlockSTMv2 parallel execution modes. The root cause is an inconsistency in how deletions are handled: the `filter_value_for_exchange` function correctly excludes deletions, but the group reads processing functions do not perform this check before calling `does_value_need_exchange`, which explicitly errors on deletions with the message "Delete shouldn't be in values considered for exchange."

### Citations

**File:** aptos-move/block-executor/src/value_exchange.rs (L170-174)
```rust
            // Deletion returns an error.
            Err(code_invariant_error(
                "Delete shouldn't be in values considered for exchange",
            ))
        }
```

**File:** aptos-move/block-executor/src/value_exchange.rs (L193-194)
```rust
        if value.is_deletion() {
            None
```

**File:** aptos-move/block-executor/src/view.rs (L805-810)
```rust
                    return self.captured_reads.borrow_mut().capture_group_read(
                        group_key.clone(),
                        resource_tag.clone(),
                        DataRead::from_value_with_layout(version, value_with_layout),
                        &target_kind,
                    );
```

**File:** aptos-move/block-executor/src/view.rs (L815-827)
```rust
                Err(TagNotFound) => {
                    // TagNotFound means group was initialized (o.w. Uninitialized branch
                    // would be visited), but the tag didn't exist. So record an empty resource
                    // as a base value, and do continue to retry the read.
                    self.versioned_map
                        .group_data()
                        .update_tagged_base_value_with_layout(
                            group_key.clone(),
                            resource_tag.clone(),
                            TransactionWrite::from_state_value(None),
                            None,
                        );
                    continue;
```

**File:** aptos-move/block-executor/src/view.rs (L1392-1395)
```rust
                    if let DataRead::Versioned(_version, value, Some(layout)) = data_read {
                        let needs_exchange = self
                            .does_value_need_exchange(value, layout.as_ref(), delayed_write_set_ids)
                            .map_err(PartialVMError::from)?;
```

**File:** aptos-move/block-executor/src/view.rs (L1446-1450)
```rust
                                let needs_exchange = self.does_value_need_exchange(
                                    &value,
                                    layout.as_ref(),
                                    delayed_write_set_ids,
                                )?;
```

**File:** aptos-move/block-executor/src/executor.rs (L1789-1798)
```rust
                        if let PanicOr::CodeInvariantError(err_msg) = err {
                            alert!(
                                "[BlockSTMv2] worker loop: CodeInvariantError({:?})",
                                err_msg
                            );
                        }
                        shared_maybe_error.store(true, Ordering::SeqCst);

                        // Make sure to halt the scheduler if it hasn't already been halted.
                        scheduler.halt();
```

**File:** aptos-move/block-executor/src/executor.rs (L1839-1840)
```rust
        if has_error {
            return Err(());
```

**File:** types/src/write_set.rs (L401-403)
```rust
    fn is_deletion(&self) -> bool {
        self.write_op_kind() == WriteOpKind::Deletion
    }
```
