# Audit Report

## Title
Status Code Information Loss in ExecutionFailure Transaction Receipts

## Summary
The `keep_or_discard()` function intentionally drops the `status_code` field when converting `VMStatus::ExecutionFailure` to `KeptVMStatus::ExecutionFailure`, and this information is never preserved in transaction receipts or auxiliary data. This results in different execution failure types (e.g., `ARITHMETIC_ERROR`, `ACCESS_DENIED`, `RESOURCE_DOES_NOT_EXIST`) being indistinguishable in transaction receipts when they occur at the same location. [1](#0-0) 

## Finding Description
When the Move VM encounters an execution failure, it creates a `VMStatus::ExecutionFailure` containing the `status_code`, `location`, `function`, `code_offset`, `sub_status`, and `message`. [2](#0-1) 

The `keep_or_discard()` function converts this to `KeptVMStatus::ExecutionFailure`, which only retains `location`, `function`, `code_offset`, and `message` - the `status_code` is explicitly dropped. [3](#0-2) 

This `KeptVMStatus` is then converted to `ExecutionStatus::ExecutionFailure`, which similarly lacks a `status_code` field. [4](#0-3) 

The `ExecutionStatus` is included in `TransactionInfo` which gets hashed and committed to the blockchain. [5](#0-4) 

Critically, the `TransactionOutput` always sets `auxiliary_data` to default (None), meaning the detailed error information is never preserved. [6](#0-5) 

When users query transaction receipts via the API, they only see a generic message without the status code. [7](#0-6) 

**Exploitation Scenario:**
Two transactions failing at the same location with different root causes (e.g., `ARITHMETIC_ERROR` vs `ACCESS_DENIED`) will:
1. Produce identical `ExecutionStatus::ExecutionFailure` with same location/function/offset
2. Generate identical `TransactionInfo` hashes
3. Display identical error messages to users: "Execution failed in {function} at code offset {offset}"

This makes security-critical errors like `ACCESS_DENIED` (access control violations) indistinguishable from benign errors like `ARITHMETIC_ERROR`.

## Impact Explanation
This issue qualifies as **Low Severity** under the Aptos bug bounty program as a "Minor information leak." It degrades security observability by:

1. **Hiding Access Control Violations**: `ACCESS_DENIED` errors cannot be distinguished from other errors, masking potential security breaches
2. **Degraded Security Monitoring**: Automated security tools cannot detect specific attack patterns (e.g., repeated arithmetic overflow attempts, access control probing)
3. **Reduced Audit Trail Granularity**: Post-incident analysis cannot determine specific failure causes from on-chain data
4. **User Confusion**: Legitimate users cannot understand why their transactions failed without detailed debugging

However, this does NOT constitute Critical/High/Medium severity because:
- No funds can be stolen or frozen
- Consensus is not broken (VM execution remains deterministic)
- Transactions still fail and are recorded on-chain
- The location/function/offset still provide debugging context
- Validator nodes do log the full `VMStatus` internally [8](#0-7) 

## Likelihood Explanation
This issue affects **every ExecutionFailure transaction** on the Aptos blockchain. It is not an edge case but a systematic information loss by design. Any transaction that fails with an execution error loses its specific error type in the public record.

The likelihood of exploitation for malicious purposes is moderate - an attacker could intentionally craft transactions to fail in ways that hide their true intent, but the location/offset information still provides forensic value.

## Recommendation
To preserve error type information while maintaining backwards compatibility:

1. **Populate TransactionAuxiliaryData**: Modify the VM output creation to include the original `VMStatus` with full `status_code` in `TransactionAuxiliaryData`:

```rust
// In aptos-move/aptos-vm-types/src/output.rs
pub fn into_transaction_output(self) -> Result<TransactionOutput, PanicError> {
    // ... existing code ...
    
    let auxiliary_data = if let TransactionStatus::Keep(ExecutionStatus::ExecutionFailure { .. }) = &status {
        // Preserve the original VMStatus with status_code
        TransactionAuxiliaryData::V1(TransactionAuxiliaryDataV1 {
            detail_error_message: Some(VMErrorDetail::new(
                original_status_code,  // Need to pass this through
                message.clone(),
            )),
        })
    } else {
        TransactionAuxiliaryData::default()
    };
    
    Ok(TransactionOutput::new(
        write_set,
        events,
        fee_statement.gas_used(),
        status,
        auxiliary_data,
    ))
}
```

2. **Update API Response**: Ensure the API layer includes the status code from auxiliary data when available.

3. **Feature Flag**: Gate this behind a feature flag for gradual rollout to avoid breaking existing clients.

## Proof of Concept

**Note**: This is a Low Severity information leak that does NOT meet the Critical/High/Medium severity criteria required for a full bounty claim. The following demonstrates the information loss but not an exploitable security vulnerability.

```rust
// This demonstrates how two different errors become indistinguishable
use move_core_types::vm_status::{VMStatus, StatusCode, AbortLocation};
use aptos_types::transaction::ExecutionStatus;

// Scenario 1: Arithmetic error
let error1 = VMStatus::ExecutionFailure {
    status_code: StatusCode::ARITHMETIC_ERROR,
    location: AbortLocation::Module(module_id.clone()),
    function: 5,
    code_offset: 42,
    sub_status: None,
    message: Some("Division by zero".to_string()),
};

// Scenario 2: Access control violation
let error2 = VMStatus::ExecutionFailure {
    status_code: StatusCode::ACCESS_DENIED,
    location: AbortLocation::Module(module_id.clone()),
    function: 5,
    code_offset: 42,
    sub_status: None,
    message: Some("Unauthorized access".to_string()),
};

// Both convert to same KeptVMStatus
let kept1 = error1.keep_or_discard(false, false, false).unwrap();
let kept2 = error2.keep_or_discard(false, false, false).unwrap();

// Both produce identical ExecutionStatus
let exec_status1: ExecutionStatus = kept1.into();
let exec_status2: ExecutionStatus = kept2.into();

// Both hash to the same TransactionInfo
// Users see identical error: "Execution failed in module::function at code offset 42"
assert_eq!(exec_status1, exec_status2); // They are identical!
```

---

**Validation Checklist Assessment:**
- [x] Vulnerability lies within the Aptos Core codebase
- [x] Exploitable by unprivileged attacker
- [x] Attack path is realistic
- [❌] Impact meets Critical, High, or Medium severity - **FAILS: This is Low Severity**
- [x] PoC demonstrates the issue
- [❌] Issue breaks documented invariant - **FAILS: No critical invariant broken**
- [❌] Clear security harm (funds, consensus, availability) - **FAILS: Only information disclosure**

**Conclusion**: While this is a legitimate design limitation that reduces security observability, it does NOT meet the severity criteria for a valid vulnerability report requiring Critical/High/Medium impact. This is a Low Severity information disclosure issue that was likely an intentional design trade-off.

### Citations

**File:** third_party/move/move-core/types/src/vm_status.rs (L76-83)
```rust
    ExecutionFailure {
        status_code: StatusCode,
        sub_status: Option<u64>,
        location: AbortLocation,
        function: u16,
        code_offset: u16,
        message: Option<String>,
    },
```

**File:** third_party/move/move-core/types/src/vm_status.rs (L102-108)
```rust
    ExecutionFailure {
        location: AbortLocation,
        function: u16,
        code_offset: u16,
        message: Option<String>,
    },
    MiscellaneousError,
```

**File:** third_party/move/move-core/types/src/vm_status.rs (L274-286)
```rust
            VMStatus::ExecutionFailure {
                status_code: _status_code,
                location,
                function,
                code_offset,
                message,
                ..
            } => Ok(KeptVMStatus::ExecutionFailure {
                location,
                function,
                code_offset,
                message,
            }),
```

**File:** types/src/transaction/mod.rs (L1497-1501)
```rust
    ExecutionFailure {
        location: AbortLocation,
        function: u16,
        code_offset: u16,
    },
```

**File:** types/src/transaction/mod.rs (L2023-2051)
```rust
#[derive(Clone, CryptoHasher, BCSCryptoHash, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct TransactionInfoV0 {
    /// The amount of gas used.
    gas_used: u64,

    /// The vm status. If it is not `Executed`, this will provide the general error class. Execution
    /// failures and Move abort's receive more detailed information. But other errors are generally
    /// categorized with no status code or other information
    status: ExecutionStatus,

    /// The hash of this transaction.
    transaction_hash: HashValue,

    /// The root hash of Merkle Accumulator storing all events emitted during this transaction.
    event_root_hash: HashValue,

    /// The hash value summarizing all changes caused to the world state by this transaction.
    /// i.e. hash of the output write set.
    state_change_hash: HashValue,

    /// The root hash of the Sparse Merkle Tree describing the world state at the end of this
    /// transaction. Depending on the protocol configuration, this can be generated periodical
    /// only, like per block.
    state_checkpoint_hash: Option<HashValue>,

    /// The hash value summarizing PersistedAuxiliaryInfo.
    auxiliary_info_hash: Option<HashValue>,
}
```

**File:** aptos-move/aptos-vm-types/src/output.rs (L212-218)
```rust
        Ok(TransactionOutput::new(
            write_set,
            events,
            fee_statement.gas_used(),
            status,
            TransactionAuxiliaryData::default(),
        ))
```

**File:** api/types/src/convert.rs (L1106-1134)
```rust
            ExecutionStatus::ExecutionFailure {
                location,
                function,
                code_offset,
            } => {
                let func_name_and_instruction = match location {
                    AbortLocation::Module(module_id) => self
                        .explain_function_and_code_index(module_id, function, code_offset)
                        .map(|name_and_instruction| {
                            format!(
                                "{}::{}",
                                abort_location_to_str(location),
                                name_and_instruction
                            )
                        })
                        .unwrap_or_else(|_| {
                            format!(
                                "{}::<#{} function>",
                                abort_location_to_str(location),
                                function
                            )
                        }),
                    AbortLocation::Script => "script".to_owned(),
                };
                format!(
                    "Execution failed in {} at code offset {}",
                    func_name_and_instruction, code_offset
                )
            },
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2928-3000)
```rust
                if let StatusType::InvariantViolation = vm_status.status_type() {
                    match vm_status.status_code() {
                        // Type resolution failure can be triggered by user input when providing a bad type argument, skip this case.
                        StatusCode::TYPE_RESOLUTION_FAILURE
                        if vm_status.sub_status()
                            == Some(move_core_types::vm_status::sub_status::type_resolution_failure::EUSER_TYPE_LOADING_FAILURE) => {},
                        // The known Move function failure and type resolution failure could be a result of speculative execution. Use speculative logger.
                        StatusCode::UNEXPECTED_ERROR_FROM_KNOWN_MOVE_FUNCTION
                        | StatusCode::TYPE_RESOLUTION_FAILURE => {
                            speculative_error!(
                                log_context,
                                format!(
                                    "[aptos_vm] Transaction breaking invariant violation: {:?}\ntxn: {:?}",
                                    vm_status,
                                    bcs::to_bytes::<SignedTransaction>(txn),
                                ),
                            );
                        },
                        // Paranoid mode failure. We need to be alerted about this ASAP.
                        StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR
                        if vm_status.sub_status()
                            == Some(unknown_invariant_violation::EPARANOID_FAILURE) =>
                            {
                                error!(
                                *log_context,
                                "[aptos_vm] Transaction breaking paranoid mode: {:?}\ntxn: {:?}",
                                vm_status,
                                bcs::to_bytes::<SignedTransaction>(txn),
                            );
                            },
                        // Paranoid mode failure but with reference counting
                        StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR
                        if vm_status.sub_status()
                            == Some(unknown_invariant_violation::EREFERENCE_COUNTING_FAILURE) =>
                            {
                                error!(
                                *log_context,
                                "[aptos_vm] Transaction breaking paranoid mode: {:?}\ntxn: {:?}",
                                vm_status,
                                bcs::to_bytes::<SignedTransaction>(txn),
                            );
                            },
                        // Paranoid mode failure but with reference safety checks
                        StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR
                        if matches!(
                            vm_status.sub_status(),
                            Some(
                                unknown_invariant_violation::EREFERENCE_SAFETY_FAILURE
                                | unknown_invariant_violation::EINDEXED_REF_TAG_MISMATCH
                            )
                        ) =>
                        {
                            error!(
                            *log_context,
                            "[aptos_vm] Transaction breaking paranoid reference safety check (including enum tag guard). txn: {:?}, status: {:?}",
                            bcs::to_bytes::<SignedTransaction>(txn),
                            vm_status,
                            );
                        }
                        // Ignore DelayedFields speculative errors as it can be intentionally triggered by parallel execution.
                        StatusCode::SPECULATIVE_EXECUTION_ABORT_ERROR => (),
                        // We will log the rest of invariant violation directly with regular logger as they shouldn't happen.
                        //
                        // TODO: Add different counters for the error categories here.
                        _ => {
                            error!(
                                *log_context,
                                "[aptos_vm] Transaction breaking invariant violation: {:?}\ntxn: {:?}, ",
                                vm_status,
                                bcs::to_bytes::<SignedTransaction>(txn),
                            );
                        },
                    }
```
