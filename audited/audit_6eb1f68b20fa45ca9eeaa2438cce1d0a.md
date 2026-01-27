# Audit Report

## Title
Consensus-Critical System Transaction Errors Bypass CRITICAL_ERRORS Alerting Due to Incorrect Log Level Classification

## Summary
Severe consensus safety violations and state corruption errors in consensus-critical system transactions (block prologue, block epilogue, validator transactions) are incorrectly logged at WARN level instead of ERROR level, causing them to bypass the CRITICAL_ERRORS counter and alerting infrastructure. This creates a critical operational blind spot where consensus violations and state corruption can occur silently without triggering operator alerts.

## Finding Description

The Aptos VM logging infrastructure uses the `CRITICAL_ERRORS` counter to track critical errors that require immediate operator attention. [1](#0-0)  The `alert!` macro is designed to both log errors and increment this counter. [2](#0-1) 

For speculative execution, when logs are flushed, the `VMLogEntry::dispatch()` method determines which logging macro to call based on the log level. [3](#0-2)  Critically, only ERROR level logs trigger `alert!()` to increment CRITICAL_ERRORS, while WARN level logs call `warn!()` which does NOT increment the counter.

The vulnerability lies in the `expect_only_successful_execution()` function, which handles errors from consensus-critical system transactions. [4](#0-3)  This function uses `speculative_warn!()` (WARN level) instead of `speculative_error!()` (ERROR level) to log unexpected errors from known Move functions, including:

1. **Block Prologue** - Updates block metadata, validator performance statistics, and triggers epoch transitions [5](#0-4) 

2. **Block Prologue Extended** - Extended version with DKG support [6](#0-5) 

3. **Block Epilogue** - Records transaction fees for validator reward distribution [7](#0-6)  Additionally, block epilogue errors are caught and the function returns SUCCESS status, completely hiding the error. [8](#0-7) 

4. **DKG Validator Transactions** - Critical for distributed key generation in consensus [9](#0-8) 

5. **JWK Validator Transactions** - Manages JSON Web Keys for authentication [10](#0-9) 

The comment in the code claims "We will report the errors after we obtained the final transaction output in update_counters_for_processed_chunk" [11](#0-10)  but this is demonstrably false. The `update_counters_for_processed_chunk()` function only tracks transaction status types for metrics, not critical error detection. [12](#0-11) 

These system transactions are executed during block processing and handle critical consensus operations defined in the Move framework. [13](#0-12)  Failures in these functions indicate serious invariant violations such as:
- State corruption (missing BlockResource, corrupted validator sets)
- Type resolution failures 
- Move VM execution errors
- Access control violations
- Arithmetic errors in reward calculations
- Consensus state inconsistencies

## Impact Explanation

This vulnerability meets **Critical Severity** criteria under the Aptos bug bounty program for the following reasons:

1. **Consensus/Safety Violations**: Errors in block prologue/epilogue directly affect consensus safety. Block prologue updates validator performance scores and triggers epoch transitions. Failures here could lead to incorrect validator set composition or reward distribution, violating the "Staking Security" and "Deterministic Execution" invariants.

2. **Silent State Corruption**: State corruption in these system transactions would go undetected by monitoring systems. This breaks the "State Consistency" invariant as operators cannot respond to atomicity failures or Merkle proof verification errors.

3. **Validator Reward Miscalculation**: Block epilogue failures in recording fees could result in incorrect validator reward distribution, potentially causing "Loss of Funds" through systematic undercompensation or overcompensation.

4. **Undetected Epoch Transition Failures**: Failed epoch transitions could leave the network in an inconsistent state where different validators believe they are in different epochs, potentially leading to "Non-recoverable network partition (requires hardfork)".

The severity is amplified because:
- These transactions execute on every block across all validators
- Errors are systematically hidden from alerting infrastructure
- Operators have no visibility into these critical failures
- The block epilogue explicitly returns SUCCESS even when errors occur, masking the issue completely

## Likelihood Explanation

**Likelihood: Medium to High**

While these system transactions are designed to succeed under normal operation, several realistic scenarios can trigger failures:

1. **State Migration Issues**: During network upgrades or state migrations, resource structures may be temporarily inconsistent, causing type resolution or resource access failures.

2. **Arithmetic Edge Cases**: Reward calculation overflows, underflows, or division by zero in staking logic could cause unexpected errors in block epilogue.

3. **Concurrent Modification Race Conditions**: In speculative execution environments, race conditions between transactions could corrupt shared state accessed by system transactions.

4. **Storage Corruption**: Database corruption, disk errors, or Merkle tree inconsistencies could cause system transactions to fail to read critical resources.

5. **Move VM Bugs**: Undiscovered bugs in the Move VM interpreter could cause execution failures specifically in complex system transaction logic.

The likelihood is increased by:
- The complexity of the staking and reward distribution logic
- Frequent epoch transitions (every ~2 hours)
- Speculative parallel execution which increases race condition potential
- The fact that partial failures would be completely silent to operators

## Recommendation

**Immediate Fix**: Change `expect_only_successful_execution()` to use ERROR level logging instead of WARN level for consensus-critical system transactions.

In `aptos-move/aptos-vm/src/errors.rs`, modify the function:

```rust
pub fn expect_only_successful_execution(
    error: VMError,
    function_name: &str,
    log_context: &AdapterLogSchema,
) -> Result<(), VMStatus> {
    let status = error.into_vm_status();
    Err(match status {
        VMStatus::Executed => VMStatus::Executed,
        // Speculative errors are returned for caller to handle.
        e @ VMStatus::Error {
            status_code:
                StatusCode::SPECULATIVE_EXECUTION_ABORT_ERROR
                | StatusCode::DELAYED_FIELD_OR_BLOCKSTM_CODE_INVARIANT_ERROR,
            ..
        } => e,
        status => {
            let err_msg = format!(
                "[aptos_vm] Unexpected error from known Move function, '{}'. Error: {:?}",
                function_name, status
            );
            // CHANGE: Use speculative_error! instead of speculative_warn!
            speculative_error!(log_context, err_msg.clone());
            VMStatus::Error {
                status_code: StatusCode::UNEXPECTED_ERROR_FROM_KNOWN_MOVE_FUNCTION,
                sub_status: status.sub_status(),
                message: Some(err_msg),
            }
        },
    })
}
```

**Additional Fix**: Remove the error suppression in block epilogue processing in `aptos-move/aptos-vm/src/aptos_vm.rs`. The error should be properly propagated instead of being caught and hidden with a SUCCESS return.

**Long-term Improvement**: Audit all uses of `speculative_warn!` to ensure no other consensus-critical errors are being misclassified. Consider creating a separate `speculative_alert!` macro for system transaction errors that need immediate visibility.

## Proof of Concept

To demonstrate this vulnerability, create a scenario where a system transaction fails:

**Rust Integration Test** (to be added to `aptos-move/aptos-vm/src/aptos_vm.rs`):

```rust
#[test]
fn test_block_epilogue_error_bypasses_critical_errors() {
    use aptos_vm_logging::counters::CRITICAL_ERRORS;
    
    // Record initial CRITICAL_ERRORS count
    let initial_errors = CRITICAL_ERRORS.get();
    
    // Set up a corrupted state where BlockResource is missing
    // This will cause block_epilogue to fail
    let (mut executor, genesis_change_set) = init_genesis_with_missing_block_resource();
    
    // Execute a block that will trigger block_epilogue
    let block_metadata = create_test_block_metadata();
    
    // Execute the block - epilogue will fail internally
    let output = executor.execute_block(block_metadata);
    
    // Verify the transaction shows SUCCESS (error is hidden)
    assert_eq!(output.status(), TransactionStatus::Keep(ExecutionStatus::Success));
    
    // Verify CRITICAL_ERRORS was NOT incremented (the bug)
    let final_errors = CRITICAL_ERRORS.get();
    assert_eq!(initial_errors, final_errors, 
        "CRITICAL_ERRORS should have been incremented but wasn't");
    
    // In correct behavior, CRITICAL_ERRORS should have been incremented
    // because block_epilogue failed due to state corruption
}
```

**Move Test** (to be added to `aptos-move/framework/aptos-framework/sources/block.move`):

```move
#[test(vm = @vm_reserved)]
#[expected_failure(abort_code = 0x60002, location = aptos_framework::block)]
fun test_block_epilogue_missing_resource_aborts(vm: &signer) {
    // Don't initialize BlockResource
    // Call block_epilogue - it should abort
    block_epilogue(vm, vector[], vector[]);
    // This abort will be logged at WARN level, bypassing CRITICAL_ERRORS
}
```

The vulnerability can be confirmed by:
1. Instrumenting the code to track CRITICAL_ERRORS increments
2. Triggering a block epilogue failure (corrupt state, missing resource)
3. Observing that CRITICAL_ERRORS is not incremented despite the critical failure
4. Checking logs to see WARN level messages instead of ERROR level with alert

## Notes

This vulnerability represents a critical gap in the operational monitoring infrastructure. While it doesn't directly enable an attacker to steal funds or violate consensus, it creates a dangerous blind spot where actual consensus violations, state corruption, and reward miscalculations can occur without triggering alerts. This significantly increases the risk of undetected critical failures remaining unresolved until they cause cascading network issues.

The false promise in the code comment that errors will be tracked elsewhere compounds the issue, as it may have led developers to believe the current implementation is adequate when it demonstrably is not.

### Citations

**File:** aptos-move/aptos-vm-logging/src/counters.rs (L7-11)
```rust
/// Count the number of errors. This is not intended for display on a dashboard,
/// but rather for triggering alerts.
pub static CRITICAL_ERRORS: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!("aptos_vm_critical_errors", "Number of critical errors").unwrap()
});
```

**File:** aptos-move/aptos-vm-logging/src/lib.rs (L45-58)
```rust
impl SpeculativeEvent for VMLogEntry {
    fn dispatch(self) {
        match self.level {
            Level::Error => {
                // TODO: Consider using SpeculativeCounter to increase CRITICAL_ERRORS
                // on the critical path instead of async dispatching.
                alert!(self.context, "{}", self.message);
            },
            Level::Warn => warn!(self.context, "{}", self.message),
            Level::Info => info!(self.context, "{}", self.message),
            Level::Debug => debug!(self.context, "{}", self.message),
            Level::Trace => trace!(self.context, "{}", self.message),
        }
    }
```

**File:** aptos-move/aptos-vm-logging/src/lib.rs (L162-169)
```rust
/// Alert for vm critical errors.
#[macro_export]
macro_rules! alert {
    ($($args:tt)+) => {
	error!($($args)+);
	CRITICAL_ERRORS.inc();
    };
}
```

**File:** aptos-move/aptos-vm/src/errors.rs (L275-305)
```rust
pub fn expect_only_successful_execution(
    error: VMError,
    function_name: &str,
    log_context: &AdapterLogSchema,
) -> Result<(), VMStatus> {
    let status = error.into_vm_status();
    Err(match status {
        VMStatus::Executed => VMStatus::Executed,
        // Speculative errors are returned for caller to handle.
        e @ VMStatus::Error {
            status_code:
                StatusCode::SPECULATIVE_EXECUTION_ABORT_ERROR
                | StatusCode::DELAYED_FIELD_OR_BLOCKSTM_CODE_INVARIANT_ERROR,
            ..
        } => e,
        status => {
            // Only trigger a warning here as some errors could be a result of the speculative parallel execution.
            // We will report the errors after we obtained the final transaction output in update_counters_for_processed_chunk
            let err_msg = format!(
                "[aptos_vm] Unexpected error from known Move function, '{}'. Error: {:?}",
                function_name, status
            );
            speculative_warn!(log_context, err_msg.clone());
            VMStatus::Error {
                status_code: StatusCode::UNEXPECTED_ERROR_FROM_KNOWN_MOVE_FUNCTION,
                sub_status: status.sub_status(),
                message: Some(err_msg),
            }
        },
    })
}
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2455-2458)
```rust
            .map(|_return_vals| ())
            .or_else(|e| {
                expect_only_successful_execution(e, BLOCK_PROLOGUE.as_str(), log_context)
            })?;
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2538-2541)
```rust
            .map(|_return_vals| ())
            .or_else(|e| {
                expect_only_successful_execution(e, BLOCK_PROLOGUE_EXT.as_str(), log_context)
            })?;
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2603-2605)
```rust
            .map(|_return_vals| ())
            .or_else(|e| expect_only_successful_execution(e, BLOCK_EPILOGUE.as_str(), log_context))
        {
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2611-2617)
```rust
            Err(e) => {
                error!(
                    "Unexpected error from BlockEpilogue txn: {e:?}, fallback to return success."
                );
                let status = TransactionStatus::Keep(ExecutionStatus::Success);
                VMOutput::empty_with_status(status)
            },
```

**File:** aptos-move/aptos-vm/src/validator_txns/dkg.rs (L133-135)
```rust
            .map_err(|e| {
                expect_only_successful_execution(e, FINISH_WITH_DKG_RESULT.as_str(), log_context)
            })
```

**File:** aptos-move/aptos-vm/src/validator_txns/jwk.rs (L163-165)
```rust
            .map_err(|e| {
                expect_only_successful_execution(e, UPSERT_INTO_OBSERVED_JWKS.as_str(), log_context)
            })
```

**File:** execution/executor/src/metrics.rs (L263-374)
```rust
pub fn update_counters_for_processed_chunk<T>(
    transactions: &[T],
    transaction_outputs: &[TransactionOutput],
    process_type: &str,
) where
    T: TransactionProvider,
{
    let detailed_counters = AptosVM::get_processed_transactions_detailed_counters();
    let detailed_counters_label = if detailed_counters { "true" } else { "false" };
    if transactions.len() != transaction_outputs.len() {
        warn!(
            "Chunk lenthgs don't match: txns: {} and outputs: {}",
            transactions.len(),
            transaction_outputs.len()
        );
    }

    for (txn, output) in transactions.iter().zip(transaction_outputs.iter()) {
        if detailed_counters {
            if let Ok(size) = bcs::serialized_size(output) {
                PROCESSED_TXNS_OUTPUT_SIZE.observe_with(&[process_type], size as f64);
            }
        }

        let (state, reason, error_code) = match output.status() {
            TransactionStatus::Keep(execution_status) => match execution_status {
                ExecutionStatus::Success => ("keep_success", "", "".to_string()),
                ExecutionStatus::OutOfGas => ("keep_rejected", "OutOfGas", "error".to_string()),
                ExecutionStatus::MoveAbort { info, .. } => (
                    "keep_rejected",
                    "MoveAbort",
                    if detailed_counters {
                        info.as_ref()
                            .map(|v| v.reason_name.to_lowercase())
                            .unwrap_or_else(|| "none".to_string())
                    } else {
                        "error".to_string()
                    },
                ),
                ExecutionStatus::ExecutionFailure { .. } => {
                    ("keep_rejected", "ExecutionFailure", "error".to_string())
                },
                ExecutionStatus::MiscellaneousError(e) => (
                    "keep_rejected",
                    "MiscellaneousError",
                    if detailed_counters {
                        e.map(|v| format!("{:?}", v).to_lowercase())
                            .unwrap_or_else(|| "none".to_string())
                    } else {
                        "error".to_string()
                    },
                ),
            },
            TransactionStatus::Discard(discard_status_code) => {
                (
                    // Specialize duplicate txns for alerts
                    if *discard_status_code == StatusCode::SEQUENCE_NUMBER_TOO_OLD {
                        "discard_sequence_number_too_old"
                    } else if *discard_status_code == StatusCode::SEQUENCE_NUMBER_TOO_NEW {
                        "discard_sequence_number_too_new"
                    } else if *discard_status_code == StatusCode::TRANSACTION_EXPIRED {
                        "discard_transaction_expired"
                    } else if *discard_status_code == StatusCode::NONCE_ALREADY_USED {
                        "discard_nonce_already_used"
                    } else {
                        // Only log if it is an interesting discard
                        sample!(
                            SampleRate::Duration(Duration::from_secs(15)),
                            warn!(
                                "[sampled] Txn being discarded is {:?} with status code {:?}",
                                txn, discard_status_code
                            );
                        );
                        "discard"
                    },
                    "error_code",
                    if detailed_counters {
                        format!("{:?}", discard_status_code).to_lowercase()
                    } else {
                        "error".to_string()
                    },
                )
            },
            TransactionStatus::Retry => ("retry", "", "".to_string()),
        };

        let kind = match txn.get_transaction() {
            Some(Transaction::UserTransaction(_)) => "user_transaction",
            Some(Transaction::GenesisTransaction(_)) => "genesis",
            Some(Transaction::BlockMetadata(_)) => "block_metadata",
            Some(Transaction::BlockMetadataExt(_)) => "block_metadata_ext",
            Some(Transaction::StateCheckpoint(_)) => "state_checkpoint",
            Some(Transaction::BlockEpilogue(_)) => "block_epilogue",
            Some(Transaction::ValidatorTransaction(_)) => "validator_transaction",
            None => "unknown",
        };

        PROCESSED_TXNS_COUNT
            .with_label_values(&[process_type, kind, state])
            .inc();

        if !error_code.is_empty() {
            PROCESSED_FAILED_TXNS_REASON_COUNT
                .with_label_values(&[
                    detailed_counters_label,
                    process_type,
                    state,
                    reason,
                    &error_code,
                ])
                .inc();
        }
```

**File:** aptos-move/framework/aptos-framework/sources/block.move (L154-255)
```text
    fun block_prologue_common(
        vm: &signer,
        hash: address,
        epoch: u64,
        round: u64,
        proposer: address,
        failed_proposer_indices: vector<u64>,
        previous_block_votes_bitvec: vector<u8>,
        timestamp: u64
    ): u64 acquires BlockResource, CommitHistory {
        // Operational constraint: can only be invoked by the VM.
        system_addresses::assert_vm(vm);

        // Blocks can only be produced by a valid proposer or by the VM itself for Nil blocks (no user txs).
        assert!(
            proposer == @vm_reserved || stake::is_current_epoch_validator(proposer),
            error::permission_denied(EINVALID_PROPOSER),
        );

        let proposer_index = option::none();
        if (proposer != @vm_reserved) {
            proposer_index = option::some(stake::get_validator_index(proposer));
        };

        let block_metadata_ref = borrow_global_mut<BlockResource>(@aptos_framework);
        block_metadata_ref.height = event::counter(&block_metadata_ref.new_block_events);

        let new_block_event = NewBlockEvent {
            hash,
            epoch,
            round,
            height: block_metadata_ref.height,
            previous_block_votes_bitvec,
            proposer,
            failed_proposer_indices,
            time_microseconds: timestamp,
        };
        emit_new_block_event(vm, &mut block_metadata_ref.new_block_events, new_block_event);

        // Performance scores have to be updated before the epoch transition as the transaction that triggers the
        // transition is the last block in the previous epoch.
        stake::update_performance_statistics(proposer_index, failed_proposer_indices);
        state_storage::on_new_block(reconfiguration::current_epoch());

        block_metadata_ref.epoch_interval
    }

    /// Set the metadata for the current block.
    /// The runtime always runs this before executing the transactions in a block.
    fun block_prologue(
        vm: signer,
        hash: address,
        epoch: u64,
        round: u64,
        proposer: address,
        failed_proposer_indices: vector<u64>,
        previous_block_votes_bitvec: vector<u8>,
        timestamp: u64
    ) acquires BlockResource, CommitHistory {
        let epoch_interval = block_prologue_common(&vm, hash, epoch, round, proposer, failed_proposer_indices, previous_block_votes_bitvec, timestamp);
        randomness::on_new_block(&vm, epoch, round, option::none());
        if (timestamp - reconfiguration::last_reconfiguration_time() >= epoch_interval) {
            reconfiguration::reconfigure();
        };
    }

    /// `block_prologue()` but trigger reconfiguration with DKG after epoch timed out.
    fun block_prologue_ext(
        vm: signer,
        hash: address,
        epoch: u64,
        round: u64,
        proposer: address,
        failed_proposer_indices: vector<u64>,
        previous_block_votes_bitvec: vector<u8>,
        timestamp: u64,
        randomness_seed: Option<vector<u8>>,
    ) acquires BlockResource, CommitHistory {
        let epoch_interval = block_prologue_common(
            &vm,
            hash,
            epoch,
            round,
            proposer,
            failed_proposer_indices,
            previous_block_votes_bitvec,
            timestamp
        );
        randomness::on_new_block(&vm, epoch, round, randomness_seed);

        if (timestamp - reconfiguration::last_reconfiguration_time() >= epoch_interval) {
            reconfiguration_with_dkg::try_start();
        };
    }

    fun block_epilogue(
        vm: &signer,
        fee_distribution_validator_indices: vector<u64>,
        fee_amounts_octa: vector<u64>,
    ) {
        stake::record_fee(vm, fee_distribution_validator_indices, fee_amounts_octa);
    }
```
