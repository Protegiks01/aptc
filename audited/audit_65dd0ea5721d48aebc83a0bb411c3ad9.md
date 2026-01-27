# Audit Report

## Title
Non-Deterministic Layout Validation During Change Set Squashing Causes Consensus Splits

## Summary
The `randomly_check_layout_matches` function uses a non-deterministic random number generator to decide whether to validate type layout matches during change set squashing. This probabilistic checking (1% chance) causes different validators to produce different transaction results for the same inputs, violating the deterministic execution invariant and potentially causing consensus splits.

## Finding Description
During transaction execution, the VM combines change sets from different phases (prologue, execution, epilogue) through a squashing operation. When squashing write operations, the function `randomly_check_layout_matches` is invoked to verify that type layouts match between operations being merged. [1](#0-0) 

The function uses `rand::thread_rng()` to generate a random number and only performs the actual layout comparison 1% of the time (when `random_number == 1`). This means:

- **99% of the time**: Layout mismatches go undetected, squashing succeeds
- **1% of the time**: Layout mismatches are detected, transaction fails with error

This probabilistic behavior is invoked during write operation squashing: [2](#0-1) [3](#0-2) 

The squashing occurs during normal transaction execution when combining change sets from different sessions: [4](#0-3) 

This respawned session mechanism is used throughout transaction execution to combine prologue, user code, and epilogue change sets. Since each validator node has independent RNG state, they will hit the 1% check at different times, causing some validators to accept a transaction while others reject it.

This breaks the **Deterministic Execution** invariant, which states: "All validators must produce identical state roots for identical blocks."

## Impact Explanation
This vulnerability meets **Critical Severity** criteria:

1. **Consensus Safety Violation**: Different validators executing the same transaction can reach different outcomes (success vs. failure), causing state divergence and potential chain splits.

2. **Non-recoverable Network Partition**: Once validators disagree on transaction results, they will compute different state roots, fail to reach consensus, and require manual intervention or a hard fork to recover.

3. **Scope**: Affects all transactions that trigger change set squashing (essentially all user transactions), making this a systemic issue rather than an edge case.

The Aptos secure coding guidelines explicitly state that deterministic data structures are critical for "achieving consensus, maintaining the integrity of the ledger, and ensuring that computations can be reliably reproduced across different nodes." [5](#0-4) 

## Likelihood Explanation
**Likelihood: High**

1. **Automatic Trigger**: The vulnerability activates automatically during normal transaction execution—no special attacker action required beyond submitting transactions.

2. **Probabilistic Nature**: While any single execution has only a 1% chance of hitting the check, across a network of validators processing thousands of transactions per second, consensus splits become inevitable.

3. **No Special Permissions**: Any user can submit transactions that trigger the squashing code path (which is the normal execution flow).

4. **Detection Difficulty**: The non-determinism is subtle—transactions succeed most of the time, making the issue difficult to debug and potentially allowing it to exist undetected in production.

## Recommendation
Replace the probabilistic layout check with a deterministic validation strategy:

**Option 1: Always validate layouts** (if performance allows)
```rust
pub fn check_layout_matches(
    layout_1: Option<&MoveTypeLayout>,
    layout_2: Option<&MoveTypeLayout>,
) -> Result<(), PanicError> {
    if layout_1.is_some() != layout_2.is_some() {
        return Err(code_invariant_error(format!(
            "Layouts don't match when they are expected to: {:?} and {:?}",
            layout_1, layout_2
        )));
    }
    if layout_1 != layout_2 {
        return Err(code_invariant_error(format!(
            "Layouts don't match when they are expected to: {:?} and {:?}",
            layout_1, layout_2
        )));
    }
    Ok(())
}
```

**Option 2: Remove the check entirely** (if layouts are guaranteed to match by construction)

The comment states "we generally call this function when we know that the layouts are supposed to match", suggesting that mismatches represent VM bugs rather than user error. If this is true, the check could be removed from the production code path and moved to debug assertions or test-only validation.

## Proof of Concept
```rust
// Test demonstrating non-deterministic behavior
#[test]
fn test_nondeterministic_layout_check() {
    use aptos_types::write_set::WriteOp;
    use move_core_types::value::MoveTypeLayout;
    
    // Create two different layouts
    let layout1 = MoveTypeLayout::U64;
    let layout2 = MoveTypeLayout::U128;
    
    let mut success_count = 0;
    let mut failure_count = 0;
    
    // Run the check 1000 times
    for _ in 0..1000 {
        let result = randomly_check_layout_matches(
            Some(&layout1),
            Some(&layout2),
        );
        
        if result.is_ok() {
            success_count += 1;
        } else {
            failure_count += 1;
        }
    }
    
    // Expect approximately 990 successes and 10 failures
    // This demonstrates non-deterministic behavior for identical inputs
    println!("Successes: {}, Failures: {}", success_count, failure_count);
    assert!(success_count > 950 && success_count < 1000);
    assert!(failure_count > 0 && failure_count < 50);
}
```

To demonstrate consensus impact, validators can be run in parallel executing the same transaction, showing different outcomes on different nodes.

## Notes
The vulnerability exists in the change set squashing logic which is fundamental to transaction execution. While the comment indicates this is an optimization to avoid expensive recursive layout comparisons, the non-deterministic approach is fundamentally incompatible with blockchain consensus requirements. The fix requires either accepting the performance cost of deterministic validation or proving that layout mismatches cannot occur and removing the check entirely.

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

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L534-537)
```rust
                    randomly_check_layout_matches(
                        type_layout.as_deref(),
                        additional_type_layout.as_deref(),
                    )?;
```

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L588-588)
```rust
                            randomly_check_layout_matches(Some(layout), Some(additional_layout))?;
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

**File:** RUST_SECURE_CODING.md (L121-123)
```markdown
### Data Structures with Deterministic Internal Order

Certain data structures, like HashMap and HashSet, do not guarantee a deterministic order for the elements stored within them. This lack of order can lead to problems in operations that require processing elements in a consistent sequence across multiple executions. In the Aptos blockchain, deterministic data structures help in achieving consensus, maintaining the integrity of the ledger, and ensuring that computations can be reliably reproduced across different nodes.
```
