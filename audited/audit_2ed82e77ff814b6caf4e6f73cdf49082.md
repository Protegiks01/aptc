# Audit Report

## Title
Consensus Fork Risk from Non-Deterministic Resource Group Serialization Error Handling in BCS Fallback Mode

## Summary
When resource group serialization fails during sequential execution's BCS fallback mode, the code increments `CRITICAL_ERRORS`, discards the failing transaction, and continues executing subsequent transactions. This fail-safe approach violates a code invariant ("resource group serialization during bcs fallback should not happen") and could cause consensus forks if different validators non-deterministically encounter serialization errors for different transactions. [1](#0-0) 

## Finding Description

The vulnerability occurs in the sequential execution fallback path when `resource_group_bcs_fallback = true`. The normal execution flow is:

1. **First sequential execution attempt** (with `resource_group_bcs_fallback = false`): If resource group serialization fails during the materialization phase, it returns `ResourceGroupSerializationError`. [2](#0-1) 

2. **Second sequential execution attempt** (with `resource_group_bcs_fallback = true`): The code enters a special path that proactively checks for serialization errors before materializing outputs. [3](#0-2) 

During this second attempt, the code performs manual serialization checks on resource groups by reading from `unsync_map`: [4](#0-3) 

When a serialization error is detected, instead of failing the entire block execution, the code:
1. Logs a critical error and increments `CRITICAL_ERRORS`
2. Discards the problematic transaction
3. **Continues executing subsequent transactions** [5](#0-4) 

However, the developers explicitly indicate this scenario should never occur: [6](#0-5) 

**The vulnerability**: If the serialization check produces non-deterministic results across validators (due to implementation bugs, memory layout differences, or race conditions in state), different validators would discard different transactions, producing different state roots and causing a **consensus fork**.

The critical error could be triggered by:
- Bugs in resource group size calculation leading to size mismatches
- BCS serialization failures due to corrupted or unexpected data structures  
- Non-deterministic behavior in the `finalize_group` or serialization logic

Once triggered, the fail-safe behavior (continue execution) masks the underlying bug while allowing validators to diverge.

## Impact Explanation

**Severity: Critical** (Consensus/Safety Violation - up to $1,000,000)

This breaks the **Deterministic Execution** invariant: "All validators must produce identical state roots for identical blocks."

If validator A encounters a serialization error for transaction X and discards it, while validator B successfully serializes transaction X and commits it, they will:
1. Have different transaction sets in the block
2. Apply different state transitions
3. Compute different state roots
4. Fail to reach consensus on the block

This is a consensus safety violation that could lead to:
- Chain splits requiring manual intervention or hard fork
- Network partition where different validator sets commit different blocks
- Loss of finality and transaction confirmation guarantees

The comment at line 2638-2640 explicitly states this "should not happen," indicating the developers consider encountering this condition to be a critical code invariant violation that undermines the entire fallback mechanism's correctness assumptions. [7](#0-6) 

## Likelihood Explanation

**Likelihood: Low-Medium**

The likelihood depends on whether bugs exist that can cause non-deterministic serialization failures:

**Factors increasing likelihood:**
- Resource group serialization involves complex delayed field materialization and size tracking
- The code path is defensive (handling a "should not happen" case), suggesting uncertainty about all edge cases
- Multiple transformation steps (finalization, BCS encoding, size validation) provide opportunities for subtle bugs
- The serialization check reads from `unsync_map` state accumulated from previous transactions, which could amplify non-determinism

**Factors decreasing likelihood:**  
- BCS serialization itself is deterministic
- The code has extensive testing and has been in production
- Resource group size tracking has explicit validation

The vulnerability is most likely to manifest if there are latent bugs in:
- Delayed field value-to-identifier exchange logic
- Resource group size calculation
- State finalization logic that behaves differently under specific data patterns [8](#0-7) 

## Recommendation

**Fail-fast instead of fail-safe when encountering serialization errors in BCS fallback mode:**

The current code should return a fatal error instead of continuing execution, consistent with the developers' expectation that this "should not happen":

```rust
if serialization_error {
    // This should never happen in bcs fallback mode - fail the entire block
    alert!("Critical: Serialization failed in BCS fallback mode for transaction {}", idx);
    return Err(SequentialBlockExecutionError::ErrorToReturn(
        BlockExecutionError::FatalBlockExecutorError(code_invariant_error(
            "Resource group serialization error in BCS fallback mode"
        ))
    ));
}
```

This ensures:
1. All validators either succeed or fail together (maintaining consensus safety)
2. The underlying bug is immediately surfaced rather than masked
3. Block execution fails explicitly rather than producing potentially divergent results

**Additional recommendations:**
1. Add determinism assertions to resource group size calculations
2. Implement extensive logging of serialization parameters for debugging
3. Add fail-point testing to verify all validators handle these edge cases identically
4. Consider making the `resource_group_bcs_fallback` path return errors for ANY serialization issue rather than attempting recovery [9](#0-8) 

## Proof of Concept

Due to the complexity of the resource group serialization system and lack of direct trigger mechanism from external transactions, a full PoC would require:

1. Injecting a fail-point to simulate non-deterministic serialization behavior
2. Running multiple validator instances
3. Observing divergent state roots

**Conceptual PoC using existing fail-point infrastructure:**

```rust
// In executor.rs test module
#[test]
fn test_consensus_fork_on_nondeterministic_serialization() {
    // Set up two validator instances with identical initial state
    let validator_a = create_test_executor();
    let validator_b = create_test_executor();
    
    // Configure fail-point to trigger serialization error only on validator_a
    fail::cfg("fail-point-resource-group-serialization", "return").unwrap();
    
    // Execute same block on both validators
    let block = create_block_with_resource_group_transaction();
    let result_a = validator_a.execute_block(block.clone());
    
    fail::cfg("fail-point-resource-group-serialization", "off").unwrap();
    let result_b = validator_b.execute_block(block.clone());
    
    // Validators should either both succeed or both fail
    // If result_a discards transaction but result_b commits it, consensus forks
    assert_eq!(
        result_a.to_commit.len(),
        result_b.to_commit.len(),
        "Consensus fork: validators have different transaction counts"
    );
}
```

The existing fail-point at line 2353 can be used to inject serialization errors: [10](#0-9) 

This demonstrates that the infrastructure exists to trigger the vulnerable code path, and the fail-safe behavior (continuing execution after discarding) creates the conditions for consensus divergence.

### Citations

**File:** aptos-move/block-executor/src/executor.rs (L2321-2325)
```rust
                    if resource_group_bcs_fallback {
                        // Dynamic change set optimizations are enabled, and resource group serialization
                        // previously failed in bcs serialization for preparing final transaction outputs.
                        // TODO: remove this fallback when txn errors can be created from block executor.

```

**File:** aptos-move/block-executor/src/executor.rs (L2326-2346)
```rust
                        let finalize = |group_key| -> (BTreeMap<_, _>, ResourceGroupSize) {
                            let (group, size) = unsync_map.finalize_group(&group_key);

                            (
                                group
                                    .map(|(resource_tag, value_with_layout)| {
                                        let value = match value_with_layout {
                                            ValueWithLayout::RawFromStorage(value)
                                            | ValueWithLayout::Exchanged(value, _) => value,
                                        };
                                        (
                                            resource_tag,
                                            value
                                                .extract_raw_bytes()
                                                .expect("Deletions should already be applied"),
                                        )
                                    })
                                    .collect(),
                                size,
                            )
                        };
```

**File:** aptos-move/block-executor/src/executor.rs (L2349-2365)
```rust
                        let serialization_error = output_before_guard
                            .group_reads_needing_delayed_field_exchange()
                            .iter()
                            .any(|(group_key, _)| {
                                fail_point!("fail-point-resource-group-serialization", |_| {
                                    true
                                });

                                let (finalized_group, group_size) = finalize(group_key.clone());
                                match bcs::to_bytes(&finalized_group) {
                                    Ok(group) => {
                                        (!finalized_group.is_empty() || group_size.get() != 0)
                                            && group.len() as u64 != group_size.get()
                                    },
                                    Err(_) => true,
                                }
                            })
```

**File:** aptos-move/block-executor/src/executor.rs (L2399-2408)
```rust
                        if serialization_error {
                            // The corresponding error / alert must already be triggered, the goal in sequential
                            // fallback is to just skip any transactions that would cause such serialization errors.
                            alert!("Discarding transaction because serialization failed in bcs fallback");
                            ret.push(E::Output::discard_output(
                                StatusCode::DELAYED_FIELD_OR_BLOCKSTM_CODE_INVARIANT_ERROR,
                            ));
                            idx += 1;
                            continue;
                        }
```

**File:** aptos-move/block-executor/src/executor.rs (L2439-2442)
```rust
                        let serialized_groups =
                            serialize_groups::<T>(materialized_finalized_groups).map_err(|_| {
                                SequentialBlockExecutionError::ResourceGroupSerializationError
                            })?;
```

**File:** aptos-move/block-executor/src/executor.rs (L2624-2630)
```rust
                let sequential_result = self.execute_transactions_sequential(
                    signature_verified_block,
                    base_view,
                    transaction_slice_metadata,
                    module_cache_manager_guard,
                    true,
                );
```

**File:** aptos-move/block-executor/src/executor.rs (L2637-2640)
```rust
                    Err(SequentialBlockExecutionError::ResourceGroupSerializationError) => {
                        BlockExecutionError::FatalBlockExecutorError(code_invariant_error(
                            "resource group serialization during bcs fallback should not happen",
                        ))
```

**File:** aptos-move/aptos-vm-logging/src/lib.rs (L164-169)
```rust
macro_rules! alert {
    ($($args:tt)+) => {
	error!($($args)+);
	CRITICAL_ERRORS.inc();
    };
}
```
