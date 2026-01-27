# Audit Report

## Title
Inconsistent Block Epilogue Auxiliary Info Determination Causes Execution-Persistence Mismatch

## Summary
The block executor and output processor use different methods to determine the auxiliary info for block epilogue transactions: the executor samples only the first 3 transactions while the output processor checks all transactions. When input transactions have non-uniform auxiliary info patterns (e.g., first 3 are None, but later ones are V1), this creates a mismatch between the auxiliary info used during execution versus what gets persisted to storage.

## Finding Description
When a block epilogue transaction is generated and executed, there are two separate code paths that independently determine its auxiliary info:

**During Execution** (executor.rs): [1](#0-0) 

The executor samples only the **first 3 transactions** to determine if all auxiliary infos are None, then creates the block epilogue's auxiliary info accordingly.

**During Persistence** (do_get_execution_output.rs): [2](#0-1) 

The output processor checks **ALL transactions** to make the same determination.

**Attack Scenario:**
If a block contains transactions where:
- Transactions 0-2: `PersistedAuxiliaryInfo::None`
- Transactions 3+: `PersistedAuxiliaryInfo::V1 { transaction_index }`

Then:
1. Executor samples txns 0-2, determines all are None, creates block epilogue with `None` auxiliary info for execution
2. Output processor checks all txns, sees some V1 values, creates block epilogue with `V1 { transaction_index: N }` for persistence
3. If block epilogue calls `monotonically_increasing_counter` native function, it uses the None auxiliary info during execution (which aborts with `ETRANSACTION_INDEX_NOT_AVAILABLE`): [3](#0-2) 
4. But the persisted auxiliary info indicates V1, creating an execution-persistence mismatch

This violates the **Deterministic Execution** invariant: what you execute must match what you persist.

## Impact Explanation
This qualifies as **High Severity** per the Aptos bug bounty criteria:

1. **Consensus Safety Risk**: Different validators might have different outcomes if they process blocks with non-uniform auxiliary info patterns, especially during protocol upgrades or version transitions
2. **State Inconsistency**: The transaction's auxiliary info hash computed during persistence won't match what was actually used during execution, causing verification failures in state sync
3. **Protocol Violation**: Breaks the fundamental guarantee that execution state matches persisted state

While this requires non-uniform auxiliary infos as a precondition (which shouldn't occur under normal operations), the inconsistency between sampling and checking-all creates fragility during:
- Protocol version transitions (v0 → v1 auxiliary info upgrade)
- State sync with mixed data from different epochs
- Edge cases in consensus code that might produce non-uniform patterns

## Likelihood Explanation
**Moderate-Low likelihood** under current normal operations because:
- Consensus code creates uniform auxiliary infos per block (all same version)
- Requires either a bug elsewhere, protocol transition, or corrupted state sync data

However, the **impact is high** if triggered, and the inconsistency represents a latent bug that increases fragility during upgrades and edge cases.

## Recommendation
**Fix: Use consistent logic in both places - check ALL transactions, not sample**

In `executor.rs`, replace the sampling logic with checking all transactions:

```rust
// Replace lines 1624-1631 with:
let all_auxiliary_infos_are_none = (0..num_txns)
    .all(|i| signature_verified_block
        .get_auxiliary_info(i as TxnIndex)
        .transaction_index()
        .is_none());
```

This ensures both execution and persistence use identical logic to determine the block epilogue's auxiliary info.

**Additional defensive measure:**
Add validation in `by_transaction_execution_unsharded` to detect and reject blocks with mixed auxiliary info patterns:
```rust
// After line 124 in do_get_execution_output.rs
let has_mixed_aux_info = auxiliary_infos.iter().any(|info| matches!(info.persisted_info(), PersistedAuxiliaryInfo::None))
    && auxiliary_infos.iter().any(|info| matches!(info.persisted_info(), PersistedAuxiliaryInfo::V1 { .. }));
ensure!(!has_mixed_aux_info, "Mixed auxiliary info versions in same block");
```

## Proof of Concept
Due to the requirement for non-uniform auxiliary infos (which requires consensus-level access to create), a full PoC would require consensus integration testing rather than a simple Move test. The vulnerability manifests in the difference between these two code locations:

**Sampling approach (executor.rs):** [4](#0-3) 

**Check-all approach (do_get_execution_output.rs):** [5](#0-4) 

**Test scenario** (requires consensus test framework):
1. Create block with 10 transactions
2. Set auxiliary_infos[0-2] = None
3. Set auxiliary_infos[3-9] = V1{idx: 3..9}
4. Execute block and verify block_epilogue gets different auxiliary_info in executor.rs vs do_get_execution_output.rs
5. Verify hash mismatch during ledger update

The key evidence is the **inconsistency itself** - two different methods in critical execution paths that should produce identical results but don't when given non-uniform inputs.

### Citations

**File:** aptos-move/block-executor/src/executor.rs (L1623-1643)
```rust
                let block_epilogue_aux_info = if num_txns > 0 {
                    // Sample a few transactions to check the auxiliary info pattern
                    let sample_aux_infos: Vec<_> = (0..std::cmp::min(num_txns, 3))
                        .map(|i| signature_verified_block.get_auxiliary_info(i as TxnIndex))
                        .collect();

                    let all_auxiliary_infos_are_none = sample_aux_infos
                        .iter()
                        .all(|info| info.transaction_index().is_none());

                    if all_auxiliary_infos_are_none {
                        // If existing auxiliary infos are None, use None for consistency (version 0 behavior)
                        A::new_empty()
                    } else {
                        // Otherwise, use the standard function (version 1 behavior)
                        A::auxiliary_info_at_txn_index(num_txns as u32)
                    }
                } else {
                    // Fallback if no transactions in block
                    A::new_empty()
                };
```

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L133-146)
```rust
            let all_auxiliary_infos_are_none = auxiliary_infos
                .iter()
                .all(|info| matches!(info.persisted_info(), PersistedAuxiliaryInfo::None));

            let block_epilogue_aux_info = if all_auxiliary_infos_are_none {
                // If all other auxiliary infos are None, use None for consistency (version 0 behavior)
                AuxiliaryInfo::new(PersistedAuxiliaryInfo::None, None)
            } else {
                // Otherwise, use the standard function (version 1 behavior)
                AuxiliaryInfo::auxiliary_info_at_txn_index(transactions.len() as u32 - 1)
            };

            auxiliary_infos.push(block_epilogue_aux_info);
        }
```

**File:** aptos-move/framework/src/natives/transaction_context.rs (L199-203)
```rust
            TransactionIndexKind::NotAvailable => {
                return Err(SafeNativeError::Abort {
                    abort_code: error::invalid_state(abort_codes::ETRANSACTION_INDEX_NOT_AVAILABLE),
                });
            },
```
