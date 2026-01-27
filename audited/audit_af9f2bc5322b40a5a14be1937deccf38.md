# Audit Report

## Title
Resource vs Resource Group Error Handling Divergence Enables Inconsistent Transaction Status

## Summary
The Aptos VM handles existence invariant violations differently for normal resources versus resource groups, returning different error codes that result in inconsistent transaction status handling. Normal resources return Execution-type errors (RESOURCE_ALREADY_EXISTS, MISSING_DATA) which are always kept and charge gas, while resource groups return InvariantViolation errors (UNKNOWN_INVARIANT_VIOLATION_ERROR) whose transaction status depends on the CHARGE_INVARIANT_VIOLATION feature flag state.

## Finding Description

The vulnerability stems from asymmetric error code assignment for equivalent invariant violations: [1](#0-0) 

**Normal Resources** use StatusType::Execution errors returned from GlobalValue operations: [2](#0-1) 

These errors (RESOURCE_ALREADY_EXISTS = 4004, MISSING_DATA = 4008) are in the runtime execution range: [3](#0-2) 

**Resource Groups** use StatusType::InvariantViolation errors for the same types of violations: [4](#0-3) [5](#0-4) 

The error code UNKNOWN_INVARIANT_VIOLATION_ERROR (2000) is in the invariant violation range: [6](#0-5) 

**Transaction Status Divergence** occurs in the keep_or_discard logic:

Execution errors are always kept: [7](#0-6) 

InvariantViolation errors are conditionally handled: [8](#0-7) 

When CHARGE_INVARIANT_VIOLATION is disabled, resource group invariant violations are Discarded (no gas charge), while normal resource invariant violations are Kept (gas charged). This violates the Deterministic Execution invariant as identical logical operations (existence constraint violations) produce different transaction outcomes.

## Impact Explanation

**Medium Severity** - State Inconsistencies Requiring Intervention:

1. **Gas Charging Inconsistency**: If CHARGE_INVARIANT_VIOLATION is disabled, attackers can attempt resource group invariant violations without gas cost (Discarded), while normal resource violations always cost gas (Kept).

2. **Potential Consensus Divergence**: During feature flag transitions, if validators process blocks with different flag states due to synchronization delays, they would disagree on transaction status (Keep vs Discard), producing different state roots and violating consensus safety.

3. **Non-Deterministic Behavior**: The same logical operation (creating existing resource, deleting non-existing resource) has different outcomes based on whether it targets a resource group member or normal resource, contingent on a runtime feature flag.

## Likelihood Explanation

**Medium Likelihood**:

- CHARGE_INVARIANT_VIOLATION is currently enabled in production [9](#0-8) 

- Exploitation requires either:
  1. Governance action to disable the flag (low probability but possible)
  2. Synchronization issues during flag state transitions (rare but could occur during upgrades)
  3. Replay scenarios where old blocks are processed with different flag configurations

- The architectural design inherently permits this divergence, making it a persistent risk even if not immediately exploitable.

## Recommendation

**Unify Error Handling**: Resource groups should use the same error codes as normal resources for existence invariant violations. Replace UNKNOWN_INVARIANT_VIOLATION_ERROR with RESOURCE_ALREADY_EXISTS/MISSING_DATA in resource group validation:

```rust
// In split_and_merge_resource_groups, replace:
let common_error = || {
    PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
        .with_message("split_and_merge_resource_groups error".to_string())
};

// With:
let existence_error = |exists: bool| {
    if exists {
        PartialVMError::new(StatusCode::RESOURCE_ALREADY_EXISTS)
    } else {
        PartialVMError::new(StatusCode::MISSING_DATA)
    }
};
```

This ensures both resource types produce Execution-type errors with consistent Keep/Discard behavior independent of feature flags.

## Proof of Concept

```rust
// Rust test demonstrating the divergence
#[test]
fn test_resource_vs_group_error_divergence() {
    // Setup: Create transaction violating existence invariants
    // For normal resource: move_to existing resource
    // For resource group: New operation on existing group member
    
    // Execute with CHARGE_INVARIANT_VIOLATION disabled
    let features = Features::default(); // No CHARGE_INVARIANT_VIOLATION
    
    // Normal resource violation
    let normal_status = execute_with_normal_resource_violation(&features);
    assert!(matches!(normal_status, TransactionStatus::Keep(_)));
    // Gas was charged (Execution error)
    
    // Resource group violation  
    let group_status = execute_with_group_resource_violation(&features);
    assert!(matches!(group_status, TransactionStatus::Discard(_)));
    // No gas charged (InvariantViolation error, flag disabled)
    
    // VULNERABILITY: Same logical error, different outcomes
    assert_ne!(normal_status, group_status);
}
```

## Notes

This divergence is documented in the codebase comment but represents a security-relevant design decision. While CHARGE_INVARIANT_VIOLATION mitigates the issue when enabled, the underlying asymmetry remains a consensus risk during configuration changes or cross-version scenarios. The feature flag should be deprecated in favor of consistent error code assignment.

### Citations

**File:** aptos-move/aptos-vm-types/src/resolver.rs (L121-130)
```rust
    /// Needed for backwards compatibility with the additional safety mechanism for resource
    /// groups, where the violation of the following invariant causes transaction failure:
    /// - if a resource is modified or deleted it must already exist within a group,
    /// and if it is created, it must not previously exist.
    ///
    /// For normal resources, this is asserted, but for resource groups the behavior (that
    /// we maintain) is for the transaction to fail with INVARIANT_VIOLATION_ERROR.
    /// Thus, the state does not change and blockchain does not halt while the underlying
    /// issue is addressed. In order to maintain the behavior we check for resource existence,
    /// which in the context of parallel execution does not cause a full R/W conflict.
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L4289-4301)
```rust
    fn move_to(&mut self, val: Value) -> Result<(), (PartialVMError, Value)> {
        match self {
            Self::Fresh { .. } | Self::Cached { .. } => {
                return Err((
                    PartialVMError::new(StatusCode::RESOURCE_ALREADY_EXISTS),
                    val,
                ))
            },
            Self::None => *self = Self::fresh(val)?,
            Self::Deleted => *self = Self::cached(val, GlobalDataStatus::Dirty)?,
        }
        Ok(())
    }
```

**File:** third_party/move/move-core/types/src/vm_status.rs (L307-314)
```rust
                    // Any error encountered during the execution of the transaction will charge gas.
                    StatusType::Execution => Ok(KeptVMStatus::ExecutionFailure {
                        location: AbortLocation::Script,
                        function: 0,
                        code_offset: 0,
                        message,
                    }),
                }
```

**File:** third_party/move/move-core/types/src/vm_status.rs (L837-837)
```rust
    UNKNOWN_INVARIANT_VIOLATION_ERROR = 2000,
```

**File:** third_party/move/move-core/types/src/vm_status.rs (L922-926)
```rust
    RESOURCE_DOES_NOT_EXIST = 4003,
    // We tried to create a resource under an account where that resource
    // already exists.
    RESOURCE_ALREADY_EXISTS = 4004,
    MISSING_DATA = 4008,
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/mod.rs (L341-344)
```rust
        let common_error = || {
            PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                .with_message("split_and_merge_resource_groups error".to_string())
        };
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/mod.rs (L414-428)
```rust
                    ResourceGroupChangeSet::V1(v1_changes) => {
                        // Maintain the behavior of failing the transaction on resource
                        // group member existence invariants.
                        for (struct_tag, current_op) in resources.iter() {
                            let exists =
                                resolver.resource_exists_in_group(&state_key, struct_tag)?;
                            if matches!(current_op, MoveStorageOp::New(_)) == exists {
                                // Deletion and Modification require resource to exist,
                                // while creation requires the resource to not exist.
                                return Err(common_error());
                            }
                        }
                        v1_changes.insert(state_key, resources);
                    },
                }
```

**File:** types/src/transaction/mod.rs (L1640-1646)
```rust
                if code.status_type() == StatusType::InvariantViolation
                    && features.is_enabled(FeatureFlag::CHARGE_INVARIANT_VIOLATION)
                {
                    Self::Keep(ExecutionStatus::MiscellaneousError(Some(code)))
                } else {
                    Self::Discard(code)
                }
```

**File:** types/src/on_chain_config/aptos_features.rs (L194-194)
```rust
            FeatureFlag::CHARGE_INVARIANT_VIOLATION,
```
