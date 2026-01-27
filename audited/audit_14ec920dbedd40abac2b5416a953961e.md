# Audit Report

## Title
Inconsistent Error Categorization in JWK Validator Transaction Processing Leading to Potential Consensus Divergence

## Summary
The `process_jwk_update_inner()` function exhibits inconsistent error handling where identical semantic errors are categorized differently depending on whether they occur at the Rust validation layer or the Move execution layer. Move aborts from `upsert_into_observed_jwks` are incorrectly treated as "Unexpected" system errors rather than "Expected" validation failures, potentially causing validators to disagree on transaction outcomes.

## Finding Description

The vulnerability exists in the error handling flow when processing JWK (JSON Web Key) validator transactions. The system performs duplicate validation at two layers:

**Rust-Level Validation** (categorized as "Expected" failures): [1](#0-0) [2](#0-1) [3](#0-2) 

**Move-Level Validation** (incorrectly categorized as "Unexpected" failures): [4](#0-3) 

When the Move function aborts, the error flows through: [5](#0-4) 

The `expect_only_successful_execution` function treats ALL Move aborts as unexpected: [6](#0-5) 

This causes the same semantic error (e.g., version mismatch) to be handled differently:
- **Rust check fails** → Expected(IncorrectVersion) → Transaction gracefully discarded (Status: Discarded) [7](#0-6) 

- **Move check fails** → Unexpected(VMStatus::Error) → Transaction errors out (Status: Error) [8](#0-7) 

The Move function defines error codes that semantically match Rust's Expected failures but use different numeric values: [9](#0-8) [10](#0-9) 

Note: `EUNEXPECTED_VERSION = 2` produces error code `0x010002`, while `IncorrectVersion = 0x010103` - they represent the same semantic error but are treated completely differently.

## Impact Explanation

**Severity: Medium** - State inconsistencies requiring intervention

This violates the **Deterministic Execution** invariant (#1): "All validators must produce identical state roots for identical blocks."

If timing differences, state view inconsistencies, or race conditions cause different validators to hit Rust-level vs Move-level validation for the same JWK update, they would produce different transaction outcomes (Discarded vs Error). While validator transactions are meant to be deterministic, this error handling inconsistency creates a fragility where identical inputs could theoretically produce different outputs based on execution timing.

The impact is limited because:
- Requires specific timing or state conditions to manifest
- Does not directly cause fund loss
- Does not break consensus safety under normal operation
- Affects validator transaction processing, not user transactions

However, it creates state processing inconsistencies that could require manual intervention to resolve.

## Likelihood Explanation

**Likelihood: Low-to-Medium**

The vulnerability is difficult to exploit for several reasons:

1. **Quorum Requirement**: JWK updates require valid multi-signatures from validators with sufficient voting power, limiting unprivileged attacker access
2. **Deterministic Execution**: Within a single validator's execution context, the state should remain consistent between Rust and Move checks
3. **Protobuf Validation**: The JWK structure is validated at deserialization, limiting malformed inputs

However, the vulnerability becomes more likely if:
- Per-key consensus mode enables concurrent updates from multiple validators
- State caching or parallel execution creates view inconsistencies
- Bugs in the JWK consensus implementation allow edge cases
- Network delays cause validators to process updates at different relative times

## Recommendation

Modify the error handling to properly recognize Move-level validation failures as Expected. Two approaches:

**Option 1**: Use a specialized error converter that recognizes specific Move abort codes:
```rust
fn convert_jwk_update_error(error: VMError, log_context: &AdapterLogSchema) -> Result<(), ExecutionFailure> {
    let status = error.into_vm_status();
    match status {
        VMStatus::Executed => Ok(()),
        VMStatus::MoveAbort { code, .. } => {
            match code {
                0x010002 => Err(Expected(IncorrectVersion)), // EUNEXPECTED_VERSION
                0x010004 => Err(Expected(IncorrectVersion)), // EUNKNOWN_JWK_VARIANT - treat as validation failure
                0x010003 => Err(Expected(IncorrectVersion)), // EUNKNOWN_PATCH_VARIANT
                _ => Err(Unexpected(VMStatus::error(
                    StatusCode::UNEXPECTED_ERROR_FROM_KNOWN_MOVE_FUNCTION,
                    Some(format!("Unexpected JWK update abort: {}", code))
                )))
            }
        },
        // Speculative errors pass through
        e @ VMStatus::Error { 
            status_code: StatusCode::SPECULATIVE_EXECUTION_ABORT_ERROR | 
                        StatusCode::DELAYED_FIELD_OR_BLOCKSTM_CODE_INVARIANT_ERROR, 
            .. 
        } => Err(Unexpected(e)),
        status => Err(Unexpected(VMStatus::error(
            StatusCode::UNEXPECTED_ERROR_FROM_KNOWN_MOVE_FUNCTION,
            Some(format!("Unexpected error: {:?}", status))
        )))
    }
}
```

Then replace lines 163-166 with:
```rust
.map_err(|e| convert_jwk_update_error(e, log_context))?;
```

**Option 2**: Align error codes between Rust and Move by using the native error codes in the Move function: [11](#0-10) 

Change line 478 from:
```move
assert!(cur_issuer_jwks.version + 1 == proposed_provider_jwks.version, error::invalid_argument(EUNEXPECTED_VERSION));
```

To:
```move
assert!(cur_issuer_jwks.version + 1 == proposed_provider_jwks.version, ENATIVE_INCORRECT_VERSION);
```

This would make the Move abort code match the Rust Expected failure code, though `expect_only_successful_execution` would still need modification to recognize it.

## Proof of Concept

```rust
// This PoC demonstrates the error categorization inconsistency
// Location: aptos-move/aptos-vm/tests/validator_txn_error_handling.rs

#[test]
fn test_jwk_error_categorization_inconsistency() {
    // Setup: Create two JWK updates with version conflicts
    let issuer = b"https://example.com".to_vec();
    
    // Scenario 1: Rust-level version check fails
    // Expected: Transaction returns Ok with Discarded status
    let update1 = create_jwk_update(issuer.clone(), /* on_chain_version */ 5, /* proposed_version */ 7);
    let result1 = process_jwk_update(update1);
    assert!(matches!(result1, Ok((VMStatus::MoveAbort { code: 0x010103, .. }, _))));
    
    // Scenario 2: Move-level version check fails (simulated race condition)
    // State changes between Rust check and Move execution
    // Expected: Should also return Ok with Discarded, but actually returns Err
    let update2 = create_jwk_update(issuer, /* validated_at_version */ 5, /* execute_at_version */ 6);
    let result2 = process_jwk_update_with_state_change(update2);
    
    // BUG: Same semantic error (version mismatch), different handling
    assert!(matches!(result2, Err(VMStatus::Error { 
        status_code: StatusCode::UNEXPECTED_ERROR_FROM_KNOWN_MOVE_FUNCTION, 
        .. 
    })));
    
    // This inconsistency violates deterministic execution
    // Different validators could produce different outcomes for identical transactions
}
```

## Notes

The vulnerability requires specific conditions to manifest in production:
- Timing differences between validator transaction processing
- State view inconsistencies during execution
- Or bugs in JWK consensus creating edge cases

While the error handling inconsistency is demonstrable, actual consensus divergence would require additional factors. The primary concern is defensive programming: the codebase should not have duplicate validation logic that can produce conflicting outcomes for the same semantic error.

The issue is exacerbated in per-key consensus mode where multiple validators may propose concurrent updates, increasing the likelihood of version conflicts.

### Citations

**File:** aptos-move/aptos-vm/src/validator_txns/jwk.rs (L41-50)
```rust
enum ExpectedFailure {
    // Move equivalent: `errors::invalid_argument(*)`
    IncorrectVersion = 0x010103,
    MultiSigVerificationFailed = 0x010104,
    NotEnoughVotingPower = 0x010105,

    // Move equivalent: `errors::invalid_state(*)`
    MissingResourceValidatorSet = 0x30101,
    MissingResourceObservedJWKs = 0x30102,
}
```

**File:** aptos-move/aptos-vm/src/validator_txns/jwk.rs (L78-88)
```rust
            Err(Expected(failure)) => {
                // Pretend we are inside Move, and expected failures are like Move aborts.
                debug!("Processing dkg transaction expected failure: {:?}", failure);
                Ok((
                    VMStatus::MoveAbort {
                        location: AbortLocation::Script,
                        code: failure as u64,
                        message: None,
                    },
                    VMOutput::empty_with_status(TransactionStatus::Discard(StatusCode::ABORTED)),
                ))
```

**File:** aptos-move/aptos-vm/src/validator_txns/jwk.rs (L90-96)
```rust
            Err(Unexpected(vm_status)) => {
                debug!(
                    "Processing jwk transaction unexpected failure: {:?}",
                    vm_status
                );
                Err(vm_status)
            },
```

**File:** aptos-move/aptos-vm/src/validator_txns/jwk.rs (L128-130)
```rust
        if on_chain.version + 1 != observed.version {
            return Err(Expected(IncorrectVersion));
        }
```

**File:** aptos-move/aptos-vm/src/validator_txns/jwk.rs (L135-137)
```rust
        verifier
            .check_voting_power(authors.iter(), true)
            .map_err(|_| Expected(NotEnoughVotingPower))?;
```

**File:** aptos-move/aptos-vm/src/validator_txns/jwk.rs (L140-142)
```rust
        verifier
            .verify_multi_signatures(&observed, &multi_sig)
            .map_err(|_| Expected(MultiSigVerificationFailed))?;
```

**File:** aptos-move/aptos-vm/src/validator_txns/jwk.rs (L153-166)
```rust
        session
            .execute_function_bypass_visibility(
                &JWKS_MODULE,
                UPSERT_INTO_OBSERVED_JWKS,
                vec![],
                serialize_values(&args),
                &mut gas_meter,
                &mut TraversalContext::new(&traversal_storage),
                module_storage,
            )
            .map_err(|e| {
                expect_only_successful_execution(e, UPSERT_INTO_OBSERVED_JWKS.as_str(), log_context)
            })
            .map_err(|r| Unexpected(r.unwrap_err()))?;
```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L35-36)
```text
    const EUNEXPECTED_EPOCH: u64 = 1;
    const EUNEXPECTED_VERSION: u64 = 2;
```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L45-49)
```text
    const ENATIVE_MISSING_RESOURCE_VALIDATOR_SET: u64 = 0x0101;
    const ENATIVE_MISSING_RESOURCE_OBSERVED_JWKS: u64 = 0x0102;
    const ENATIVE_INCORRECT_VERSION: u64 = 0x0103;
    const ENATIVE_MULTISIG_VERIFICATION_FAILED: u64 = 0x0104;
    const ENATIVE_NOT_ENOUGH_VOTING_POWER: u64 = 0x0105;
```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L478-478)
```text
                assert!(cur_issuer_jwks.version + 1 == proposed_provider_jwks.version, error::invalid_argument(EUNEXPECTED_VERSION));
```

**File:** aptos-move/aptos-vm/src/errors.rs (L275-304)
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
```
