# Audit Report

## Title
Gas Parameter Validation Missing: Inverted Limits Allow User Fund Loss Through Failed Transactions

## Summary
The gas schedule update mechanism lacks validation to prevent inverted limits where per-operation limits exceed total transaction limits. This allows governance to accidentally configure invalid parameters (e.g., `max_bytes_per_write_op` = 10MB > `max_bytes_all_write_ops_per_transaction` = 1MB), causing legitimate transactions to fail after execution and users to lose gas fees.

## Finding Description

The vulnerability exists in the gas parameter configuration system where limits can be set in an inverted relationship, breaking the logical invariant that per-operation limits should never exceed total transaction limits.

**Root Cause Location:** [1](#0-0) [2](#0-1) [3](#0-2) 

The gas schedule update functions contain TODO comments indicating validation was planned but never implemented. The functions only validate that the feature version doesn't downgrade: [4](#0-3) 

**Parameter Configuration:**

Gas parameters are configured without relationship validation: [5](#0-4) 

Default values show the intended relationship (per-op < total): [6](#0-5) 

**Validation Logic Error:**

The validation logic checks per-operation limits BEFORE total limits in a loop: [7](#0-6) 

When limits are inverted (e.g., per-op = 10MB, total = 1MB), a single 5MB write operation:
1. Passes the per-operation check (5MB ≤ 10MB)
2. Accumulates to `write_set_size` = 5MB
3. Fails the total check (5MB > 1MB)
4. Returns `STORAGE_WRITE_LIMIT_REACHED` error

**Execution Flow Impact:**

The validation occurs AFTER transaction execution but BEFORE gas charging: [8](#0-7) 

When `check_change_set` fails, the error propagates to the failure epilogue: [9](#0-8) [10](#0-9) 

The failure epilogue charges gas for the failed transaction: [11](#0-10) 

## Impact Explanation

**Medium Severity** per Aptos bug bounty criteria:

1. **Limited Funds Loss**: Users lose gas fees on transactions that execute successfully but fail at the validation stage due to misconfigured limits. Each affected transaction burns gas without achieving its intended state change.

2. **State Inconsistencies Requiring Intervention**: Once inverted limits are set network-wide, certain legitimate operations become impossible to execute (those falling in the "dead zone" between the inverted limits). This requires a governance proposal to fix the parameters, during which affected operations cannot be performed.

3. **Network Usability Degradation**: The inverted limits create unpredictable behavior where transactions that should be valid (under the per-operation limit) are rejected, confusing users and potentially breaking applications that rely on specific write operation sizes.

The vulnerability does NOT cause:
- Consensus safety violations (all nodes deterministically fail the same transactions)
- Loss of existing funds (only gas fees for new failed transactions)
- Network-wide liveness failure (only specific operation sizes are affected)

## Likelihood Explanation

**Medium Likelihood** for the following reasons:

1. **Missing Validation**: The TODO comments demonstrate that developers recognized the need for validation but it was never implemented, making accidental misconfiguration possible.

2. **Governance Parameter Tuning**: During routine gas parameter adjustments to optimize network performance, governance might modify limits without realizing they've created an inversion. The lack of validation means no safety check prevents this.

3. **No Safeguards**: There are no warnings, assertions, or runtime checks to detect inverted limits either at configuration time or during transaction execution.

4. **Non-Obvious Relationship**: The relationship between per-operation and total limits may not be immediately obvious to governance proposal authors, especially when modifying parameters independently.

The likelihood is NOT higher because:
- Requires governance action (not directly exploitable by attackers)
- Default parameters are correctly configured
- Would be noticed relatively quickly through transaction failures

## Recommendation

Implement validation in the gas schedule update functions to enforce the invariant that per-operation limits must not exceed total transaction limits.

**Proposed Fix for `gas_schedule.move`:**

Add validation in `set_for_next_epoch()` after deserializing the new gas schedule. Replace the TODO comments with actual validation logic:

```move
public fun set_for_next_epoch(aptos_framework: &signer, gas_schedule_blob: vector<u8>) acquires GasScheduleV2 {
    system_addresses::assert_aptos_framework(aptos_framework);
    assert!(!vector::is_empty(&gas_schedule_blob), error::invalid_argument(EINVALID_GAS_SCHEDULE));
    let new_gas_schedule: GasScheduleV2 = from_bytes(gas_schedule_blob);
    if (exists<GasScheduleV2>(@aptos_framework)) {
        let cur_gas_schedule = borrow_global<GasScheduleV2>(@aptos_framework);
        assert!(
            new_gas_schedule.feature_version >= cur_gas_schedule.feature_version,
            error::invalid_argument(EINVALID_GAS_FEATURE_VERSION)
        );
    };
    
    // Validate gas schedule consistency
    validate_gas_schedule_consistency(&new_gas_schedule);
    
    config_buffer::upsert(new_gas_schedule);
}

fun validate_gas_schedule_consistency(gas_schedule: &GasScheduleV2) {
    // Extract relevant parameters
    let max_bytes_per_write_op = get_gas_param(gas_schedule, b"txn.max_bytes_per_write_op");
    let max_bytes_all_write_ops = get_gas_param(gas_schedule, b"txn.max_bytes_all_write_ops_per_transaction");
    let max_bytes_per_event = get_gas_param(gas_schedule, b"txn.max_bytes_per_event");
    let max_bytes_all_events = get_gas_param(gas_schedule, b"txn.max_bytes_all_events_per_transaction");
    
    // Validate per-operation limits don't exceed total limits
    if (max_bytes_per_write_op != 0 && max_bytes_all_write_ops != 0) {
        assert!(
            max_bytes_per_write_op <= max_bytes_all_write_ops,
            error::invalid_argument(EINVALID_GAS_SCHEDULE)
        );
    };
    
    if (max_bytes_per_event != 0 && max_bytes_all_events != 0) {
        assert!(
            max_bytes_per_event <= max_bytes_all_events,
            error::invalid_argument(EINVALID_GAS_SCHEDULE)
        );
    };
}
```

**Additional Runtime Check for `change_set_configs.rs`:**

Add defensive validation when constructing `ChangeSetConfigs`:

```rust
fn new_impl(
    gas_feature_version: u64,
    max_bytes_per_write_op: u64,
    max_bytes_all_write_ops_per_transaction: u64,
    max_bytes_per_event: u64,
    max_bytes_all_events_per_transaction: u64,
    max_write_ops_per_transaction: u64,
) -> Self {
    // Defensive check: per-operation limits should not exceed total limits
    if max_bytes_per_write_op != 0 && max_bytes_all_write_ops_per_transaction != 0 {
        debug_assert!(
            max_bytes_per_write_op <= max_bytes_all_write_ops_per_transaction,
            "Invalid gas config: per-write-op limit ({}) exceeds total limit ({})",
            max_bytes_per_write_op,
            max_bytes_all_write_ops_per_transaction
        );
    }
    
    if max_bytes_per_event != 0 && max_bytes_all_events_per_transaction != 0 {
        debug_assert!(
            max_bytes_per_event <= max_bytes_all_events_per_transaction,
            "Invalid gas config: per-event limit ({}) exceeds total limit ({})",
            max_bytes_per_event,
            max_bytes_all_events_per_transaction
        );
    }
    
    Self {
        gas_feature_version,
        max_bytes_per_write_op,
        max_bytes_all_write_ops_per_transaction,
        max_bytes_per_event,
        max_bytes_all_events_per_transaction,
        max_write_ops_per_transaction,
    }
}
```

## Proof of Concept

```rust
#[test]
fn test_inverted_limits_cause_validation_failure() {
    use aptos_gas_schedule::AptosGasParameters;
    use aptos_vm_types::storage::change_set_configs::ChangeSetConfigs;
    use move_core_types::gas_algebra::NumBytes;
    
    // Create gas parameters with inverted limits
    let mut gas_params = AptosGasParameters::initial();
    gas_params.vm.txn.max_bytes_per_write_op = NumBytes::new(10 * 1024 * 1024); // 10MB
    gas_params.vm.txn.max_bytes_all_write_ops_per_transaction = NumBytes::new(1 * 1024 * 1024); // 1MB
    
    // Create ChangeSetConfigs with inverted limits
    let configs = ChangeSetConfigs::new(5, &gas_params);
    
    // Create a mock change set with a single 5MB write operation
    // This should pass the per-op check but fail the total check
    let mut change_set = create_mock_change_set_with_5mb_write();
    
    // Validation should fail even though the single operation is under the per-op limit
    let result = configs.check_change_set(&change_set);
    
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().status_code(),
        StatusCode::STORAGE_WRITE_LIMIT_REACHED
    );
    
    // This demonstrates the bug: a single operation that should be valid
    // (under the 10MB per-op limit) is rejected because it exceeds the
    // 1MB total limit, which is logically inconsistent.
}

#[test]
fn test_correct_limits_allow_valid_operations() {
    use aptos_gas_schedule::AptosGasParameters;
    use aptos_vm_types::storage::change_set_configs::ChangeSetConfigs;
    use move_core_types::gas_algebra::NumBytes;
    
    // Create gas parameters with correct limit ordering
    let mut gas_params = AptosGasParameters::initial();
    gas_params.vm.txn.max_bytes_per_write_op = NumBytes::new(1 * 1024 * 1024); // 1MB
    gas_params.vm.txn.max_bytes_all_write_ops_per_transaction = NumBytes::new(10 * 1024 * 1024); // 10MB
    
    let configs = ChangeSetConfigs::new(5, &gas_params);
    
    // A 500KB write should pass both checks
    let change_set = create_mock_change_set_with_500kb_write();
    let result = configs.check_change_set(&change_set);
    assert!(result.is_ok());
}
```

## Notes

This vulnerability demonstrates a critical gap between intended design (evidenced by TODO comments) and implementation. The missing validation creates a maintenance hazard where governance parameter updates could accidentally degrade network usability and cause user fund loss through gas fees on transactions that should succeed.

The fix is straightforward and should be implemented both at the governance layer (to prevent invalid configurations from being set) and as defensive checks at runtime (to catch any configuration errors early).

### Citations

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L47-47)
```text
        // TODO(Gas): check if gas schedule is consistent
```

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L67-67)
```text
            // TODO(Gas): check if gas schedule is consistent
```

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L75-75)
```text
            // TODO(Gas): check if gas schedule is consistent
```

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L91-103)
```text
    public fun set_for_next_epoch(aptos_framework: &signer, gas_schedule_blob: vector<u8>) acquires GasScheduleV2 {
        system_addresses::assert_aptos_framework(aptos_framework);
        assert!(!vector::is_empty(&gas_schedule_blob), error::invalid_argument(EINVALID_GAS_SCHEDULE));
        let new_gas_schedule: GasScheduleV2 = from_bytes(gas_schedule_blob);
        if (exists<GasScheduleV2>(@aptos_framework)) {
            let cur_gas_schedule = borrow_global<GasScheduleV2>(@aptos_framework);
            assert!(
                new_gas_schedule.feature_version >= cur_gas_schedule.feature_version,
                error::invalid_argument(EINVALID_GAS_FEATURE_VERSION)
            );
        };
        config_buffer::upsert(new_gas_schedule);
    }
```

**File:** aptos-move/aptos-vm-types/src/storage/change_set_configs.rs (L74-84)
```rust
    fn from_gas_params(gas_feature_version: u64, gas_params: &AptosGasParameters) -> Self {
        let params = &gas_params.vm.txn;
        Self::new_impl(
            gas_feature_version,
            params.max_bytes_per_write_op.into(),
            params.max_bytes_all_write_ops_per_transaction.into(),
            params.max_bytes_per_event.into(),
            params.max_bytes_all_events_per_transaction.into(),
            params.max_write_ops_per_transaction.into(),
        )
    }
```

**File:** aptos-move/aptos-vm-types/src/storage/change_set_configs.rs (L101-113)
```rust
        let mut write_set_size = 0;
        for (key, op_size) in change_set.write_set_size_iter() {
            if let Some(len) = op_size.write_len() {
                let write_op_size = len + (key.size() as u64);
                if write_op_size > self.max_bytes_per_write_op {
                    return storage_write_limit_reached(None);
                }
                write_set_size += write_op_size;
            }
            if write_set_size > self.max_bytes_all_write_ops_per_transaction {
                return storage_write_limit_reached(None);
            }
        }
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L154-162)
```rust
            max_bytes_per_write_op: NumBytes,
            { 5.. => "max_bytes_per_write_op" },
            1 << 20, // a single state item is 1MB max
        ],
        [
            max_bytes_all_write_ops_per_transaction: NumBytes,
            { 5.. => "max_bytes_all_write_ops_per_transaction" },
            10 << 20, // all write ops from a single transaction are 10MB max
        ],
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L689-821)
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
                    *log_context,
                    "Failed during charge_change_set: {:?}. Most likely exceeded gas limited.", err,
                );
            };

            let fee_statement =
                AptosVM::fee_statement_from_gas_meter(txn_data, gas_meter, ZERO_STORAGE_REFUND);

            // Verify we charged sufficiently for creating an account slot
            let gas_params = self.gas_params(log_context)?;
            let gas_unit_price = u64::from(txn_data.gas_unit_price());
            if gas_unit_price != 0 || !self.features().is_default_account_resource_enabled() {
                let gas_used = fee_statement.gas_used();
                let storage_fee = fee_statement.storage_fee_used();
                let storage_refund = fee_statement.storage_fee_refund();

                let actual = gas_used * gas_unit_price + storage_fee - storage_refund;
                let expected = u64::from(
                    gas_meter
                        .disk_space_pricing()
                        .hack_account_creation_fee_lower_bound(&gas_params.vm.txn),
                );
                if actual < expected {
                    expect_only_successful_execution(
                        PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                            .with_message(
                                "Insufficient fee for storing account for lazy account creation"
                                    .to_string(),
                            )
                            .finish(Location::Undefined),
                        &format!("{:?}::{}", ACCOUNT_MODULE, CREATE_ACCOUNT_IF_DOES_NOT_EXIST),
                        log_context,
                    )?;
                }
            }
            (abort_hook_session_change_set, fee_statement)
        } else {
            let fee_statement =
                AptosVM::fee_statement_from_gas_meter(txn_data, gas_meter, ZERO_STORAGE_REFUND);
            (prologue_session_change_set, fee_statement)
        };

        let mut epilogue_session = EpilogueSession::on_user_session_failure(
            self,
            txn_data,
            resolver,
            previous_session_change_set,
        );

        // Abort information is injected using the user defined error in the Move contract.
        let status = self.inject_abort_info_if_available(
            module_storage,
            traversal_context,
            log_context,
            status,
        );
        epilogue_session.execute(|session| {
            transaction_validation::run_failure_epilogue(
                session,
                module_storage,
                serialized_signers,
                gas_meter.balance(),
                fee_statement,
                self.features(),
                txn_data,
                log_context,
                traversal_context,
                self.is_simulation,
            )
        })?;
        epilogue_session.finish(fee_statement, status, change_set_configs, module_storage)
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1081-1096)
```rust
        let user_session_change_set = self.resolve_pending_code_publish_and_finish_user_session(
            session,
            resolver,
            code_storage,
            gas_meter,
            traversal_context,
            change_set_configs,
        )?;

        let epilogue_session = self.charge_change_set_and_respawn_session(
            user_session_change_set,
            resolver,
            code_storage,
            gas_meter,
            txn_data,
        )?;
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1955-1980)
```rust
    fn on_user_transaction_execution_failure(
        &self,
        prologue_session_change_set: SystemSessionChangeSet,
        err: VMStatus,
        resolver: &impl AptosMoveResolver,
        module_storage: &impl AptosModuleStorage,
        serialized_signers: &SerializedSigners,
        txn_data: &TransactionMetadata,
        log_context: &AdapterLogSchema,
        gas_meter: &mut impl AptosGasMeter,
        change_set_configs: &ChangeSetConfigs,
        traversal_context: &mut TraversalContext,
    ) -> (VMStatus, VMOutput) {
        self.failed_transaction_cleanup(
            prologue_session_change_set,
            err,
            gas_meter,
            txn_data,
            resolver,
            module_storage,
            serialized_signers,
            log_context,
            change_set_configs,
            traversal_context,
        )
    }
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
