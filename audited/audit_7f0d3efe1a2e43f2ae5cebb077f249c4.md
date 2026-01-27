# Audit Report

## Title
BCS Simulation Response Omits Critical VM Error Messages Compared to JSON Response

## Summary
The `simulate()` function in `api/src/transactions.rs` returns different levels of diagnostic information depending on the response format. JSON responses include enriched VM error messages, while BCS responses omit these critical error messages, creating an information asymmetry that misleads BCS clients about simulation failures.

## Finding Description

The vulnerability exists in how simulation results are formatted for different API response types (JSON vs BCS).

When a transaction simulation completes, the VM returns a `VMStatus` containing optional error messages in `VMStatus::Error` and `VMStatus::ExecutionFailure` variants. [1](#0-0) 

The simulation function processes this information differently for JSON vs BCS:

**For JSON responses**, the function explicitly enriches the VM status string with error messages from the original `VMStatus`: [2](#0-1) 

**For BCS responses**, only the raw `TransactionOnChainData` is returned, which contains an `ExecutionStatus` enum that has already lost the error messages: [3](#0-2) 

The information loss occurs during the conversion from `KeptVMStatus` to `ExecutionStatus`, where the `ExecutionFailure` message is explicitly discarded: [4](#0-3) 

This means BCS clients receive only the basic execution status enum without the detailed error messages that explain why the simulation failed, while JSON clients receive fully enriched error descriptions.

## Impact Explanation

This qualifies as **Low Severity** per Aptos bug bounty criteria as a "minor information leak" that creates API inconsistency. While it doesn't directly threaten funds, consensus, or chain security, it creates misleading conditions for BCS API consumers who may:

- Misunderstand the root cause of simulation failures
- Make incorrect decisions about transaction viability based on incomplete diagnostic data
- Experience degraded debugging capabilities compared to JSON clients
- Potentially submit doomed transactions due to insufficient error context

The asymmetry violates the principle of API format neutrality—clients should receive equivalent information regardless of encoding format.

## Likelihood Explanation

This issue affects **100% of BCS simulation requests** where the VM returns error messages in `VMStatus::Error` or `VMStatus::ExecutionFailure`. It's not an edge case but a systematic design flaw in the response formatting logic. Any developer using the BCS API format for simulations will encounter this information loss.

## Recommendation

Store and include the original `VMStatus` information in the BCS response structure. Options include:

1. **Add a new field to `TransactionOnChainData`** to carry the original `VMStatus` alongside the `ExecutionStatus`
2. **Modify `ExecutionStatus::ExecutionFailure`** to include the message field (breaking change to core type)
3. **Return a simulation-specific response type for BCS** that includes both the transaction data and the full VM status with messages

The minimal fix would be to preserve the message during the conversion: [4](#0-3) 

Modify `ExecutionStatus::ExecutionFailure` to include an optional message field and update the conversion to preserve it.

## Proof of Concept

```rust
// Test demonstrating the information asymmetry
#[test]
fn test_bcs_json_simulation_parity() {
    // Setup: Create a transaction that will fail with an ExecutionFailure
    let txn = create_failing_transaction_with_execution_error();
    
    // Simulate with JSON accept type
    let json_response = simulate_transaction(&txn, AcceptType::Json);
    let json_vm_status = extract_vm_status_from_json(json_response);
    
    // Simulate with BCS accept type  
    let bcs_response = simulate_transaction(&txn, AcceptType::Bcs);
    let bcs_execution_status = extract_execution_status_from_bcs(bcs_response);
    
    // JSON contains enriched error message
    assert!(json_vm_status.contains("Execution failed with message:"));
    
    // BCS only contains basic ExecutionFailure enum - message is lost
    assert!(matches!(bcs_execution_status, ExecutionStatus::ExecutionFailure { .. }));
    // No way to extract the detailed error message from BCS response
}
```

The test would show that JSON responses contain error messages appended by the simulation endpoint, while BCS responses contain only the basic enum variant without diagnostic details.

## Notes

While this is a valid finding of API inconsistency, it represents **Low severity** impact as it affects only developer experience and debugging capabilities, not blockchain security, consensus, or fund safety. The issue should be addressed to ensure API format parity, but does not pose an immediate security threat to the Aptos network.

### Citations

**File:** third_party/move/move-core/types/src/vm_status.rs (L54-84)
```rust
pub enum VMStatus {
    /// The VM status corresponding to an EXECUTED status code
    Executed,

    /// Indicates an error from the VM, e.g. OUT_OF_GAS, INVALID_AUTH_KEY, RET_TYPE_MISMATCH_ERROR
    /// etc.
    /// The code will neither EXECUTED nor ABORTED
    Error {
        status_code: StatusCode,
        sub_status: Option<u64>,
        message: Option<String>,
    },

    /// Indicates an `abort` from inside Move code. Contains the location of the abort and the code
    MoveAbort {
        location: AbortLocation,
        code: u64,
        message: Option<String>,
    },

    /// Indicates an failure from inside Move code, where the VM could not continue exection, e.g.
    /// dividing by zero or a missing resource
    ExecutionFailure {
        status_code: StatusCode,
        sub_status: Option<u64>,
        location: AbortLocation,
        function: u16,
        code_offset: u16,
        message: Option<String>,
    },
}
```

**File:** api/src/transactions.rs (L1746-1754)
```rust
                                VMStatus::Error {
                                    message: Some(msg), ..
                                }
                                | VMStatus::ExecutionFailure {
                                    message: Some(msg), ..
                                } => {
                                    user_txn.info.vm_status +=
                                        format!("\nExecution failed with message: {}", msg)
                                            .as_str();
```

**File:** api/src/transactions.rs (L1775-1777)
```rust
            AcceptType::Bcs => {
                BasicResponse::try_from_bcs((simulated_txn, &ledger_info, BasicResponseStatus::Ok))
            },
```

**File:** types/src/transaction/mod.rs (L1530-1539)
```rust
            KeptVMStatus::ExecutionFailure {
                location: loc,
                function: func,
                code_offset: offset,
                message: _,
            } => ExecutionStatus::ExecutionFailure {
                location: loc,
                function: func,
                code_offset: offset,
            },
```
