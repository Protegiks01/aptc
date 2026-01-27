# Audit Report

## Title
Account Authentication Gas Limit Bypass via Post-Authentication OUT_OF_GAS Timing

## Summary
The `ACCOUNT_AUTHENTICATION_GAS_LIMIT_EXCEEDED` protection can be bypassed by crafting authentication functions that consume almost all of `max_aa_gas` but succeed, causing subsequent prologue execution to trigger `OUT_OF_GAS` instead. This bypasses the intended behavior where authentication gas violations should discard transactions, allowing attackers to force fee payers to be charged for transactions that should have been discarded.

## Finding Description

The account abstraction feature implements a gas limit (`max_aa_gas`) for authentication functions to prevent malicious authentication logic from consuming excessive gas. The protection mechanism converts `OUT_OF_GAS` errors from `dispatchable_authenticate()` to `ACCOUNT_AUTHENTICATION_GAS_LIMIT_EXCEEDED`: [1](#0-0) [2](#0-1) 

However, this conversion only applies to errors occurring **within** the `dispatchable_authenticate()` call. After authentication completes successfully, the validation flow continues with prologue execution: [3](#0-2) 

The prologue execution consumes gas from the same limited gas meter. The critical vulnerability is that the gas meter starts with `max_aa_gas` during validation: [4](#0-3) 

**Attack Scenario:**
1. Attacker creates a transaction with account abstraction and a fee payer
2. The authentication function is crafted to consume `(max_aa_gas - ε)` gas but succeeds
3. Authentication returns successfully (no error conversion happens)
4. Prologue execution attempts to run with remaining `ε` gas
5. Prologue hits `OUT_OF_GAS` during execution
6. This `OUT_OF_GAS` error is NOT converted to `ACCOUNT_AUTHENTICATION_GAS_LIMIT_EXCEEDED`
7. The error propagates as plain `OUT_OF_GAS`

**Critical Difference in Transaction Status:**

The `keep_or_discard()` function treats these errors differently: [5](#0-4) [6](#0-5) 

- `OUT_OF_GAS` → Transaction is **KEPT** (recorded on-chain, account charged)
- `ACCOUNT_AUTHENTICATION_GAS_LIMIT_EXCEEDED` → Transaction is **DISCARDED** (not recorded, account not charged)

This means attackers can bypass the authentication gas limit check by timing the gas exhaustion to occur outside the `dispatchable_authenticate()` error handler, causing transactions that should be discarded to be kept and charged instead.

## Impact Explanation

**Severity: Medium** - Limited funds loss or manipulation

The vulnerability allows attackers to:
1. **Force fee payers to pay for invalid transactions**: Malicious authentication functions that violate gas limits can still result in kept transactions instead of discarded ones
2. **Griefing attack**: Attackers can drain fee payer accounts by repeatedly submitting transactions with gas-intensive authentication that barely succeeds, then fails in prologue
3. **Protocol invariant violation**: Breaks the intended security boundary that authentication gas violations should not charge users

This qualifies as Medium severity per Aptos bug bounty criteria because it enables limited funds loss through griefing and manipulation of transaction status determination.

## Likelihood Explanation

**Likelihood: High**

The attack is highly likely because:
1. **Low complexity**: Attacker only needs to craft an authentication function with controlled gas consumption
2. **No special privileges required**: Any user can deploy custom authentication functions via account abstraction
3. **Deterministic exploitation**: Gas consumption can be precisely controlled through Move bytecode operations
4. **Direct financial incentive**: Attackers can profit by griefing competitors' fee payer services or draining specific accounts

The only requirement is that account abstraction features are enabled, which is the intended production configuration.

## Recommendation

The conversion of `OUT_OF_GAS` to `ACCOUNT_AUTHENTICATION_GAS_LIMIT_EXCEEDED` should be applied to the entire validation phase, not just the `dispatchable_authenticate()` call. 

**Proposed Fix:**

Wrap the entire validation flow (including prologue) in error handling that converts `OUT_OF_GAS` to `ACCOUNT_AUTHENTICATION_GAS_LIMIT_EXCEEDED` when account abstraction is active and gas was limited:

```rust
// In validate_signed_transaction, after authentication and before prologue:
let validation_result = self.run_prologue_with_payload(...);

// If AA is enabled and we had limited gas, convert OUT_OF_GAS
if (self.features().is_account_abstraction_enabled() 
    || self.features().is_derivable_account_abstraction_enabled()) 
    && has_abstract_auth {
    validation_result.map_err(|mut vm_status| {
        if vm_status.status_code() == OUT_OF_GAS {
            vm_status.set_status_code(ACCOUNT_AUTHENTICATION_GAS_LIMIT_EXCEEDED);
        }
        vm_status
    })
} else {
    validation_result
}
```

Alternatively, track whether any abstract authentication was performed and apply the conversion to all `OUT_OF_GAS` errors during the validation phase when such authentication occurred.

## Proof of Concept

**Attack Flow:**

1. Deploy a malicious authentication Move module:
```move
module attacker::malicious_auth {
    use aptos_framework::auth_data::AbstractionAuthData;
    
    // Consumes exactly (max_aa_gas - small_amount) gas
    public fun authenticate(
        account: signer,
        signing_data: AbstractionAuthData,
    ): signer {
        // Perform expensive but controlled operations
        let i = 0;
        while (i < CALCULATED_ITERATIONS) {
            // Gas-consuming operations
            i = i + 1;
        };
        account // Return successfully
    }
}
```

2. Register this authentication function for an account

3. Submit a transaction with:
   - Account abstraction enabled
   - Fee payer specified
   - Authentication function set to `attacker::malicious_auth::authenticate`
   - The function is calibrated to consume `(max_aa_gas - 1000)` gas

4. Expected behavior: Transaction is discarded with `ACCOUNT_AUTHENTICATION_GAS_LIMIT_EXCEEDED`

5. Actual behavior: Transaction is kept with `OUT_OF_GAS`, fee payer is charged

**Validation Steps:**
- Monitor transaction status for transactions with heavy authentication logic
- Compare gas consumption in authentication vs prologue phases
- Verify that `OUT_OF_GAS` from prologue results in Keep status rather than Discard

The vulnerability is exploitable in production and violates the fundamental security invariant that authentication gas limit violations must result in transaction discard to protect fee payers.

## Notes

The root cause is the narrow scope of the `map_err` conversion applied only to `dispatchable_authenticate()` results, while the security requirement extends to the entire validation phase when account abstraction is used. The fix should broaden the conversion scope to include all validation-phase `OUT_OF_GAS` errors when abstract authentication is performed.

### Citations

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1845-1860)
```rust
                        dispatchable_authenticate(
                            session,
                            gas_meter,
                            fee_payer,
                            function_info.clone(),
                            auth_data,
                            traversal_context,
                            module_storage,
                        )
                        .map_err(|mut vm_error| {
                            if vm_error.major_status() == OUT_OF_GAS {
                                vm_error
                                    .set_major_status(ACCOUNT_AUTHENTICATION_GAS_LIMIT_EXCEEDED);
                            }
                            vm_error.into_vm_status()
                        })
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1885-1900)
```rust
                        dispatchable_authenticate(
                            session,
                            gas_meter,
                            sender,
                            function_info.clone(),
                            auth_data,
                            traversal_context,
                            module_storage,
                        )
                        .map_err(|mut vm_error| {
                            if vm_error.major_status() == OUT_OF_GAS {
                                vm_error
                                    .set_major_status(ACCOUNT_AUTHENTICATION_GAS_LIMIT_EXCEEDED);
                            }
                            vm_error.into_vm_status()
                        })
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1939-1950)
```rust
        self.run_prologue_with_payload(
            session,
            module_storage,
            &serialized_signers,
            executable,
            extra_config,
            transaction_data,
            log_context,
            is_approved_gov_script,
            traversal_context,
        )?;
        Ok(serialized_signers)
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2149-2155)
```rust
        let initial_balance = if self.features().is_account_abstraction_enabled()
            || self.features().is_derivable_account_abstraction_enabled()
        {
            vm_params.txn.max_aa_gas.min(txn.max_gas_amount().into())
        } else {
            txn.max_gas_amount().into()
        };
```

**File:** third_party/move/move-core/types/src/vm_status.rs (L224-231)
```rust
            VMStatus::ExecutionFailure {
                status_code: StatusCode::OUT_OF_GAS,
                ..
            }
            | VMStatus::Error {
                status_code: StatusCode::OUT_OF_GAS,
                ..
            } => Ok(KeptVMStatus::OutOfGas),
```

**File:** third_party/move/move-core/types/src/vm_status.rs (L292-297)
```rust
                match code.status_type() {
                    // Any unknown error should be discarded
                    StatusType::Unknown => Err(code),
                    // Any error that is a validation status (i.e. an error arising from the prologue)
                    // causes the transaction to not be included.
                    StatusType::Validation => Err(code),
```
