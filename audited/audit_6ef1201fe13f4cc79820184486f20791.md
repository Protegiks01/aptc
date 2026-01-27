# Audit Report

## Title
Missing Total Supply Correction in Remote Sharded Execution Breaks Deterministic Execution Invariant

## Summary
The `RemoteExecutorClient` fails to call `aggregate_and_update_total_supply` after receiving execution results from remote shards, while `LocalExecutorClient` does. This causes validators using remote execution to produce different write set hashes than those using local execution, breaking the fundamental deterministic execution invariant and potentially causing consensus forks.

## Finding Description
The sharded block executor uses an aggregator override mechanism for total supply during parallel execution. Transactions execute with a fake base value (`TOTAL_SUPPLY_AGGR_BASE_VAL`), and the actual total supply values must be corrected after execution by calling `aggregate_and_update_total_supply`. [1](#0-0) 

However, the `RemoteExecutorClient` implementation returns shard execution results without performing this critical correction step: [2](#0-1) 

The execution path selection depends on whether remote addresses are configured: [3](#0-2) 

When remote execution is used:
1. Transactions execute with fake total supply base value via the override mechanism
2. Write sets contain incorrect total supply values based on `TOTAL_SUPPLY_AGGR_BASE_VAL`
3. Results are returned without correction (no `aggregate_and_update_total_supply` call)
4. `DoLedgerUpdate::assemble_transaction_infos` computes write set hashes from these INCORRECT values [4](#0-3) 

When local execution is used, the same transactions produce CORRECTED total supply values before hash computation, resulting in DIFFERENT write set hashes for identical blocks.

This violates the **Deterministic Execution** invariant: "All validators must produce identical state roots for identical blocks." Validators using different execution modes will compute different `TransactionInfo` hashes, leading to different ledger info commitments and potential consensus safety violations.

## Impact Explanation
**Critical Severity** - This is a consensus safety violation that can cause chain splits:

1. **Non-deterministic state roots**: Different validators produce different write set hashes for the same block
2. **Verification failures**: Write set verification will fail when comparing between validators using different execution modes [5](#0-4) 

3. **Consensus fork risk**: Validators may fail to reach agreement on block commits due to mismatched transaction info hashes
4. **Network partition**: Could require manual intervention or hard fork to recover if sufficient validators disagree

This directly threatens the integrity of AptosBFT consensus and violates the core safety guarantee that all honest validators must agree on the same ledger state.

## Likelihood Explanation
**High Likelihood** if remote sharded execution is enabled in production:

1. The vulnerability is deterministic - it ALWAYS occurs when remote execution is used
2. No attacker interaction required - happens automatically during normal block execution
3. Remote execution is a documented feature for horizontal scaling, likely to be used in production environments
4. The override mechanism is currently active (not feature-flagged), as indicated by the TODO comment [6](#0-5) 

## Recommendation
Add the missing `aggregate_and_update_total_supply` call in `RemoteExecutorClient::execute_block` to match the local executor implementation:

```rust
// In remote_executor_client.rs, execute_block method:
let mut execution_results = self.get_output_from_shards()?;

// Add missing correction step
sharded_aggregator_service::aggregate_and_update_total_supply(
    &mut execution_results,
    &mut vec![], // global_output (empty for remote executor)
    state_view.as_ref(),
    self.thread_pool.clone(),
);

self.state_view_service.drop_state_view();
Ok(ShardedExecutionOutput::new(execution_results, vec![]))
```

Additionally, the remote executor should support global transactions and include them in the correction process, similar to the local executor.

## Proof of Concept
```rust
// Test demonstrating the inconsistency
#[test]
fn test_remote_local_execution_inconsistency() {
    let state_view = create_test_state_view_with_total_supply(1000);
    let transactions = create_test_transactions_modifying_total_supply();
    
    // Execute with local executor
    let local_outputs = execute_with_local_executor(state_view.clone(), transactions.clone());
    let local_hash = compute_write_set_hash(&local_outputs[0]);
    
    // Execute with remote executor (mock)
    let remote_outputs = execute_with_remote_executor(state_view, transactions);
    let remote_hash = compute_write_set_hash(&remote_outputs[0]);
    
    // Hashes MUST match for deterministic execution
    assert_eq!(local_hash, remote_hash, 
        "Local and remote execution produced different write set hashes!");
    // This assertion will FAIL, demonstrating the vulnerability
}
```

The test would fail because remote execution returns uncorrected total supply values, while local execution returns corrected values, producing different write set hashes for identical input blocks.

## Notes
This vulnerability exists because the total supply correction logic was only implemented in the local executor path. The remote executor appears to be a newer addition that missed this critical post-processing step. The issue is exacerbated by the fact that the override mechanism is documented as temporary (per the TODO comment), but the correction logic must remain consistent across all execution paths until the proper aggregated total supply implementation is deployed.

### Citations

**File:** aptos-move/aptos-vm/src/sharded_block_executor/local_executor_shard.rs (L215-220)
```rust
        sharded_aggregator_service::aggregate_and_update_total_supply(
            &mut sharded_output,
            &mut global_output,
            state_view.as_ref(),
            self.global_executor.get_executor_thread_pool(),
        );
```

**File:** execution/executor-service/src/remote_executor_client.rs (L208-211)
```rust
        let execution_results = self.get_output_from_shards()?;

        self.state_view_service.drop_state_view();
        Ok(ShardedExecutionOutput::new(execution_results, vec![]))
```

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L261-267)
```rust
        if !get_remote_addresses().is_empty() {
            Ok(V::execute_block_sharded(
                &REMOTE_SHARDED_BLOCK_EXECUTOR.lock(),
                partitioned_txns,
                state_view,
                onchain_config,
            )?)
```

**File:** execution/executor/src/workflow/do_ledger_update.rs (L76-79)
```rust
                let write_set_hash = CryptoHash::hash(txn_output.write_set());
                let txn_info = TransactionInfo::new(
                    txn.hash(),
                    write_set_hash,
```

**File:** types/src/transaction/mod.rs (L1898-1908)
```rust
        let write_set_hash = CryptoHash::hash(self.write_set());
        ensure!(
            write_set_hash == txn_info.state_change_hash(),
            "{}: version:{}, write_set_hash:{:?}, expected:{:?}, write_set: {:?}, expected(if known): {:?}",
            ERR_MSG,
            version,
            write_set_hash,
            txn_info.state_change_hash(),
            self.write_set,
            expected_write_set,
        );
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/aggr_overridden_state_view.rs (L43-45)
```rust
            // TODO: Remove this when we have aggregated total supply implementation for remote
            //       sharding. For now we need this because after all the txns are executed, the
            //       proof checker expects the total_supply to read/written to the tree.
```
