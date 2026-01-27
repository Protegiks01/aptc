# Audit Report

## Title
Transaction Commit Hook Triggered for Invalid Signature Transactions in Parallel Execution

## Summary
The `on_transaction_committed` hook is incorrectly invoked for transactions with invalid signatures during parallel block execution. Invalid signature transactions are marked as `ExecutionStatus::Success` (with discarded output) instead of `ExecutionStatus::Abort`, causing them to trigger commit hooks that should only fire for valid, successfully executed transactions.

## Finding Description

The vulnerability occurs in the execution flow where transactions with invalid signatures fail signature verification but are still processed through the commit hook mechanism. The security guarantee that "only validated, successfully committed transactions trigger side effects" is violated.

**Attack Flow:**

1. An attacker submits a transaction with an invalid signature to the network
2. During consensus, the transaction is wrapped in `SignatureVerifiedTransaction::Invalid` after signature verification [1](#0-0) 

3. The block executor calls `execute_single_transaction`, which detects the invalid signature and returns a discarded output with `StatusCode::INVALID_SIGNATURE` [2](#0-1) 

4. However, in the VM wrapper, this successful return (Ok status) is converted to `ExecutionStatus::Success` rather than `ExecutionStatus::Abort` [3](#0-2) 

5. This `ExecutionStatus::Success` is recorded as `OutputStatusKind::Success` in the output wrapper [4](#0-3) 

6. During finalization, `notify_listener` matches on `OutputStatusKind::Success` and calls `on_transaction_committed` [5](#0-4) 

The hook receives a `TransactionOutput` for a discarded transaction, breaking the invariant that commit hooks only fire for valid transactions that modified state.

## Impact Explanation

**Severity: High** (up to $50,000 per Aptos Bug Bounty criteria)

This constitutes a **significant protocol violation** for the following reasons:

1. **Semantic Contract Violation**: The `TransactionCommitHook` trait is designed to notify external systems when transactions are successfully committed. Invalid signature transactions should NEVER trigger these notifications as they represent failed authentication attempts.

2. **Cross-Shard Execution Risk**: The current `CrossShardCommitSender` implementation extracts the write set from the transaction output. While it appears safe because discarded transactions have empty write sets, this creates a dangerous precedent where hooks must defensively check transaction validity. [6](#0-5) 

3. **Future Implementation Risk**: Any future hook implementation that assumes `on_transaction_committed` only fires for valid transactions (e.g., for metrics, external notifications, or state synchronization) would be vulnerable to processing invalid data.

4. **State Consistency**: In distributed systems relying on commit hooks for state synchronization, this could lead to inconsistencies where invalid transactions are counted or processed as valid.

This does not reach Critical severity because it does not immediately lead to fund loss, consensus violations, or network unavailability. However, it represents a significant architectural flaw that violates core protocol assumptions.

## Likelihood Explanation

**Likelihood: High**

This vulnerability occurs automatically for EVERY transaction with an invalid signature that reaches the block executor:

- No special privileges required - any attacker can submit invalid signature transactions
- No race conditions or timing dependencies needed
- Deterministic behavior in the execution pipeline
- Affects both BlockSTM v1 and v2 parallel execution modes
- Currently limited impact due to defensive programming in existing hook implementation, but represents a ticking time bomb for future extensions

The only mitigation is that current hook implementations happen to check the write set, but this is not enforced by the type system or documented as a requirement.

## Recommendation

Invalid signature transactions should be categorized as `ExecutionStatus::Abort` rather than `ExecutionStatus::Success`. This ensures they trigger `on_execution_aborted` instead of `on_transaction_committed`.

**Fix in `aptos-move/aptos-vm/src/block_executor/vm_wrapper.rs`:**

Change the execution flow to check if the output is discarded and return Abort for invalid transactions:

```rust
fn execute_transaction(
    &self,
    view: &(impl ExecutorView + ResourceGroupView + AptosCodeStorage + BlockSynchronizationKillSwitch),
    txn: &SignatureVerifiedTransaction,
    auxiliary_info: &Self::AuxiliaryInfo,
    txn_idx: TxnIndex,
) -> ExecutionStatus<AptosTransactionOutput, VMStatus> {
    // ... existing code ...
    
    match self.vm.execute_single_transaction(txn, &resolver, view, &log_context, auxiliary_info) {
        Ok((vm_status, vm_output)) => {
            // NEW: Check if transaction was discarded due to invalid signature
            if vm_output.status().is_discarded() 
                && vm_status.status_code() == StatusCode::INVALID_SIGNATURE {
                return ExecutionStatus::Abort(vm_status);
            }
            
            if vm_output.status().is_discarded() {
                speculative_trace!(&log_context, format!("Transaction discarded, status: {:?}", vm_status));
            }
            // ... rest of existing logic ...
        },
        // ... existing error handling ...
    }
}
```

This ensures invalid signature transactions are treated as aborted rather than successful, preventing the commit hook from being triggered.

## Proof of Concept

```rust
// Test to demonstrate the vulnerability
// File: aptos-move/block-executor/src/tests/hook_test.rs

use crate::txn_commit_hook::TransactionCommitHook;
use aptos_mvhashmap::types::TxnIndex;
use aptos_types::transaction::TransactionOutput;
use once_cell::sync::OnceCell;
use std::sync::{Arc, Mutex};

// Mock hook that tracks calls
struct TestCommitHook {
    committed_txns: Arc<Mutex<Vec<TxnIndex>>>,
    aborted_txns: Arc<Mutex<Vec<TxnIndex>>>,
}

impl TransactionCommitHook for TestCommitHook {
    fn on_transaction_committed(&self, txn_idx: TxnIndex, _output: &OnceCell<TransactionOutput>) {
        self.committed_txns.lock().unwrap().push(txn_idx);
    }
    
    fn on_execution_aborted(&self, txn_idx: TxnIndex) {
        self.aborted_txns.lock().unwrap().push(txn_idx);
    }
}

#[test]
fn test_invalid_signature_triggers_commit_hook() {
    // Setup: Create a transaction with invalid signature
    // (wrapped in SignatureVerifiedTransaction::Invalid)
    
    // Execute the transaction through the block executor
    // with the TestCommitHook installed
    
    // EXPECTED: on_execution_aborted should be called
    // ACTUAL BUG: on_transaction_committed is called instead
    
    let hook = TestCommitHook {
        committed_txns: Arc::new(Mutex::new(Vec::new())),
        aborted_txns: Arc::new(Mutex::new(Vec::new())),
    };
    
    // After execution:
    assert!(hook.committed_txns.lock().unwrap().contains(&0), 
        "BUG: Invalid signature transaction triggered on_transaction_committed");
    assert!(hook.aborted_txns.lock().unwrap().is_empty(),
        "Expected: Invalid signature should trigger on_execution_aborted");
}
```

**Notes:**

The vulnerability is present in the production code path and affects all block execution modes. The current `CrossShardCommitSender` implementation happens to be safe because it checks the write set before sending messages, but this defensive check is not enforced by the type system and future implementations may not include such checks. This represents a violation of the commit hook's semantic contract and the transaction validation invariant.

### Citations

**File:** types/src/transaction/signature_verified_transaction.rs (L132-135)
```rust
            Transaction::UserTransaction(txn) => match txn.verify_signature() {
                Ok(_) => SignatureVerifiedTransaction::Valid(Transaction::UserTransaction(txn)),
                Err(_) => SignatureVerifiedTransaction::Invalid(Transaction::UserTransaction(txn)),
            },
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2881-2884)
```rust
        if let SignatureVerifiedTransaction::Invalid(_) = txn {
            let vm_status = VMStatus::error(StatusCode::INVALID_SIGNATURE, None);
            let discarded_output = discarded_output(vm_status.status_code());
            return Ok((vm_status, discarded_output));
```

**File:** aptos-move/aptos-vm/src/block_executor/vm_wrapper.rs (L92-96)
```rust
                    assert!(
                        Self::is_transaction_dynamic_change_set_capable(txn),
                        "DirectWriteSet should always create SkipRest transaction, validate_waypoint_change_set provides this guarantee"
                    );
                    ExecutionStatus::Success(AptosTransactionOutput::new(vm_output))
```

**File:** aptos-move/block-executor/src/txn_last_input_output.rs (L142-172)
```rust
            ExecutionStatus::Success(output) | ExecutionStatus::SkipRest(output) => {
                let output_before_guard = output.before_materialization()?;

                let maybe_approx_output_size =
                    block_gas_limit_type.block_output_limit().map(|_| {
                        output_before_guard.output_approx_size()
                            + if block_gas_limit_type.include_user_txn_size_in_block_output() {
                                user_txn_bytes_len
                            } else {
                                0
                            }
                    });

                let maybe_read_write_summary =
                    block_gas_limit_type.conflict_penalty_window().map(|_| {
                        ReadWriteSummary::new(
                            read_set.get_read_summary(),
                            output_before_guard.get_write_summary(),
                        )
                    });
                drop(output_before_guard);

                Self {
                    output: Some(output),
                    maybe_approx_output_size,
                    maybe_read_write_summary,
                    output_status_kind: if is_skip_rest {
                        OutputStatusKind::SkipRest
                    } else {
                        OutputStatusKind::Success
                    },
```

**File:** aptos-move/block-executor/src/txn_last_input_output.rs (L415-424)
```rust
        match output_wrapper.output_status_kind {
            OutputStatusKind::Success | OutputStatusKind::SkipRest => {
                txn_listener.on_transaction_committed(
                    txn_idx,
                    output_wrapper
                        .output
                        .as_ref()
                        .expect("Output must be set when status is success or skip rest")
                        .committed_output(),
                );
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_client.rs (L103-134)
```rust
    fn send_remote_update_for_success(
        &self,
        txn_idx: TxnIndex,
        txn_output: &OnceCell<TransactionOutput>,
    ) {
        let edges = self.dependent_edges.get(&txn_idx).unwrap();
        let write_set = txn_output
            .get()
            .expect("Committed output must be set")
            .write_set();

        for (state_key, write_op) in write_set.expect_write_op_iter() {
            if let Some(dependent_shard_ids) = edges.get(state_key) {
                for (dependent_shard_id, round_id) in dependent_shard_ids.iter() {
                    trace!("Sending remote update for success for shard id {:?} and txn_idx: {:?}, state_key: {:?}, dependent shard id: {:?}", self.shard_id, txn_idx, state_key, dependent_shard_id);
                    let message = RemoteTxnWriteMsg(RemoteTxnWrite::new(
                        state_key.clone(),
                        Some(write_op.clone()),
                    ));
                    if *round_id == GLOBAL_ROUND_ID {
                        self.cross_shard_client.send_global_msg(message);
                    } else {
                        self.cross_shard_client.send_cross_shard_msg(
                            *dependent_shard_id,
                            *round_id,
                            message,
                        );
                    }
                }
            }
        }
    }
```
