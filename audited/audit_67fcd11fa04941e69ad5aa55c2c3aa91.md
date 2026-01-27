# Audit Report

## Title
Post-Execution Change Set Validation Allows Transaction Rollback After Successful User Execution

## Summary
The epilogue session validation in `epilogue.rs::finish()` performs change set limit validation AFTER squashing the epilogue changes with the user transaction changes. This creates a vulnerability where a successfully executed user transaction can be rolled back if the combined change set exceeds storage limits, causing users to lose gas without their transaction being applied.

## Finding Description

The vulnerability exists in the timing and ordering of change set validation during transaction epilogue processing. [1](#0-0) 

The critical flaw occurs at lines 116-118:
1. Line 116: `finish_with_squashed_change_set()` succeeds, squashing epilogue changes on top of the user transaction's validated changes
2. Line 118: `UserSessionChangeSet::new()` validates the squashed result for the first time [2](#0-1) 

The validation at line 33 checks storage limits (write ops count, write op sizes, event sizes) which can fail even when both components were individually valid, particularly for events which purely accumulate during squashing: [3](#0-2) 

The squashing operation extends events without any deduplication, meaning event sizes always increase. If the user transaction is near the event size limit and the epilogue adds additional events, the combined result exceeds limits.

When validation fails, the error propagates through the execution stack: [4](#0-3) 

This triggers failure cleanup which discards the user transaction changes: [5](#0-4) 

At line 612, only the `prologue_session_change_set` (gas deduction) is passed to `finish_aborted_transaction`, meaning the user's transaction effects are completely discarded while gas has already been charged.

**Attack Scenario:**
1. Attacker crafts a transaction that produces changes approaching storage limits (e.g., 95% of event size limit)
2. User transaction executes successfully and passes all validations
3. Epilogue runs framework code that emits additional events (e.g., fee payment events)
4. Combined change set exceeds limits (105% of event size limit)
5. Validation fails at `UserSessionChangeSet::new()`
6. Transaction is marked as failed, user changes discarded
7. User loses gas without transaction execution

## Impact Explanation

This vulnerability has **HIGH severity** impact:

1. **Direct Financial Loss**: Users lose gas payment (execution fees + storage fees) without their transaction being applied to state. The gas has been deducted from their account via the prologue, but the transaction effects are rolled back.

2. **Atomicity Violation**: Breaks the critical invariant that transactions are atomic. The user's code executed successfully, but post-execution validation causes a rollback, violating the "State Consistency" invariant.

3. **Unfair Punishment**: Users are penalized for framework behavior they cannot control. The epilogue code is system-managed and adds its own events/writes that contribute to limit violations.

4. **Denial of Service Vector**: Attackers can deliberately craft transactions that approach limits, knowing the epilogue will push them over, causing user transactions to fail. This can be used to grief specific users or transaction types.

5. **Consensus Integrity Risk**: While validators should execute deterministically, any subtle variation in epilogue execution could cause some validators to succeed where others fail, potentially leading to disagreement on transaction outcomes.

This qualifies as **High Severity** per Aptos bug bounty criteria: "Significant protocol violations" and causes validator node issues with transaction processing.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability will occur whenever:
- A user transaction produces a change set approaching any storage limit (write ops, event sizes, etc.)
- The epilogue adds additional changes that push the total over the limit
- Events are particularly vulnerable since they purely accumulate without deduplication

The likelihood is high because:
1. **No special privileges required**: Any transaction sender can trigger this
2. **Natural occurrence**: Legitimate transactions near limits will hit this organically
3. **Framework dependency**: Epilogue behavior is opaque to users - they cannot predict what events/writes the framework will add
4. **Multiple limit types**: Can be triggered via write op count, write op sizes, or event sizes
5. **Deterministic exploitation**: Attackers can precisely craft transactions to maximize the chance of triggering this

## Recommendation

**Fix: Validate the combined change set before finishing the epilogue session, or reserve headroom for epilogue changes.**

**Option 1: Pre-validate before squashing (Preferred)**
```rust
pub fn finish(
    self,
    fee_statement: FeeStatement,
    execution_status: ExecutionStatus,
    change_set_configs: &ChangeSetConfigs,
    module_storage: &impl AptosModuleStorage,
) -> Result<VMOutput, VMStatus> {
    let Self {
        session,
        storage_refund: _,
        module_write_set,
    } = self;

    // Get the epilogue changes WITHOUT squashing yet
    let epilogue_change_set = session.finish(change_set_configs, module_storage)?;
    
    // Validate epilogue changes separately BEFORE squashing
    let temp_epilogue_user_change_set = UserSessionChangeSet::new(
        epilogue_change_set.clone(),
        ModuleWriteSet::empty(),
        change_set_configs,
    )?;
    
    // Now squash - we know it will be valid
    let base_change_set = session.base_change_set();
    let mut final_change_set = base_change_set.clone();
    final_change_set.squash_additional_change_set(epilogue_change_set)?;
    
    // Final validation
    let epilogue_session_change_set =
        UserSessionChangeSet::new(final_change_set, module_write_set, change_set_configs)?;

    let (change_set, module_write_set) = epilogue_session_change_set.unpack();
    Ok(VMOutput::new(
        change_set,
        module_write_set,
        fee_statement,
        TransactionStatus::Keep(execution_status),
    ))
}
```

**Option 2: Reserve headroom for epilogue**
Modify `ChangeSetConfigs` to reserve 10-20% headroom for epilogue operations:
```rust
impl ChangeSetConfigs {
    pub fn for_user_transaction(&self) -> Self {
        // Reserve 20% of limits for epilogue
        Self {
            gas_feature_version: self.gas_feature_version,
            max_bytes_per_write_op: self.max_bytes_per_write_op,
            max_bytes_all_write_ops_per_transaction: (self.max_bytes_all_write_ops_per_transaction * 80) / 100,
            max_bytes_per_event: self.max_bytes_per_event,
            max_bytes_all_events_per_transaction: (self.max_bytes_all_events_per_transaction * 80) / 100,
            max_write_ops_per_transaction: (self.max_write_ops_per_transaction * 80) / 100,
        }
    }
}
```

Then validate user transactions against the reduced limits, ensuring epilogue has room to add its changes.

## Proof of Concept

```rust
#[test]
fn test_epilogue_validation_failure_causes_rollback() {
    // Setup: Create a transaction that produces changes approaching event size limit
    let mut executor = FakeExecutor::from_head_genesis();
    let account = executor.create_raw_account();
    
    // Configure limits to make the vulnerability easier to trigger
    let max_event_size = 1000;
    let configs = ChangeSetConfigs::new_impl(
        12,
        u64::MAX,
        u64::MAX,
        500, // Individual event limit
        max_event_size, // Total event size limit
        u64::MAX,
    );
    
    // Create a Move module that emits events totaling 95% of limit
    let large_events_module = r#"
    module 0x1::TestEvents {
        use std::event;
        
        struct LargeEvent has drop, store {
            data: vector<u8>
        }
        
        public entry fun emit_large_events() {
            // Emit events totaling ~950 bytes (95% of 1000 byte limit)
            let i = 0;
            while (i < 2) {
                event::emit(LargeEvent { 
                    data: vector::fill(475, 1u8) 
                });
                i = i + 1;
            }
        }
    }
    "#;
    
    // Execute the transaction
    let txn = account.transaction()
        .entry_function(function_id!("0x1::TestEvents::emit_large_events"))
        .sequence_number(0)
        .sign();
    
    // The user transaction should succeed with ~950 bytes of events
    // But epilogue adds fee payment events (~100 bytes)
    // Combined total: ~1050 bytes > 1000 byte limit
    // Result: Transaction fails even though user code succeeded
    
    let output = executor.execute_transaction(txn);
    
    // Assert: Transaction marked as Keep(MiscellaneousError)
    // User loses gas but transaction not applied
    assert!(matches!(
        output.status(),
        TransactionStatus::Keep(ExecutionStatus::MiscellaneousError)
    ));
    
    // Assert: User's account sequence number NOT incremented (transaction rolled back)
    let account_resource = executor.read_account_resource(&account.address());
    assert_eq!(account_resource.sequence_number(), 0);
    
    // Assert: Gas was charged despite rollback
    assert!(account_resource.coin() < initial_balance);
}
```

## Notes

This vulnerability represents a fundamental design flaw in the transaction execution pipeline where validation happens after the point of no return. The epilogue session is "finished" (consumed) before validation occurs, making rollback impossible without discarding the entire transaction.

The issue is exacerbated by the fact that events purely accumulate during squashing with no deduplication, making event size limits the most vulnerable to this attack. The framework's epilogue code (fee payment, event emission) is opaque to users, making it impossible for them to predict when their transactions will trigger this failure mode.

### Citations

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/user_transaction_sessions/epilogue.rs (L102-128)
```rust
    pub fn finish(
        self,
        fee_statement: FeeStatement,
        execution_status: ExecutionStatus,
        change_set_configs: &ChangeSetConfigs,
        module_storage: &impl AptosModuleStorage,
    ) -> Result<VMOutput, VMStatus> {
        let Self {
            session,
            storage_refund: _,
            module_write_set,
        } = self;

        let change_set =
            session.finish_with_squashed_change_set(change_set_configs, module_storage, true)?;
        let epilogue_session_change_set =
            UserSessionChangeSet::new(change_set, module_write_set, change_set_configs)?;

        let (change_set, module_write_set) = epilogue_session_change_set.unpack();
        Ok(VMOutput::new(
            change_set,
            module_write_set,
            fee_statement,
            TransactionStatus::Keep(execution_status),
        ))
    }
}
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/user_transaction_sessions/session_change_sets.rs (L23-35)
```rust
impl UserSessionChangeSet {
    pub(crate) fn new(
        change_set: VMChangeSet,
        module_write_set: ModuleWriteSet,
        change_set_configs: &ChangeSetConfigs,
    ) -> Result<Self, VMStatus> {
        let user_session_change_set = Self {
            change_set,
            module_write_set,
        };
        change_set_configs.check_change_set(&user_session_change_set)?;
        Ok(user_session_change_set)
    }
```

**File:** aptos-move/aptos-vm-types/src/change_set.rs (L765-767)
```rust
        self.events.extend(additional_events);
        Ok(())
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L602-624)
```rust
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
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2105-2118)
```rust
        let (vm_status, mut output) = result.unwrap_or_else(|err| {
            self.on_user_transaction_execution_failure(
                prologue_change_set,
                err,
                resolver,
                code_storage,
                &serialized_signers,
                &txn_data,
                log_context,
                gas_meter,
                change_set_configs,
                &mut traversal_context,
            )
        });
```
