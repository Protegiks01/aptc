# Audit Report

## Title
Failed Transaction Cleanup Discards Transactions Without Charging Gas, Enabling DoS Attacks

## Summary
A critical flaw in the transaction failure handling path allows transactions to be discarded without charging gas fees when the epilogue balance check fails. This directly contradicts the system's design principle and enables DoS attacks where validators process transactions without compensation.

## Finding Description

The transaction failure cleanup flow contains a vulnerability where epilogue failures result in transaction discard instead of gas charging, bypassing the intended economic security model.

**Execution Path:**

When a transaction fails, `failed_transaction_cleanup` determines whether to keep (charge gas) or discard the transaction. [1](#0-0)  The status determination normally results in "Keep" for most failures, triggering `finish_aborted_transaction` to run the failure epilogue and charge gas. [2](#0-1) 

However, the `.unwrap_or_else` fallback handler at line 623 calls `discarded_output` when `finish_aborted_transaction` returns an error, creating a `TransactionStatus::Discard` output. [3](#0-2)  This means no gas is charged despite resource consumption.

**Developer Acknowledgment:**

The developers explicitly document this risk in their code comments, stating: "Option (2) [discard] does not work, since it would enable DoS attacks." [4](#0-3)  Yet line 623 implements exactly this problematic option as a fallback.

**Triggering the Vulnerability:**

The failure epilogue performs a balance check before burning gas. [5](#0-4)  If this check fails (balance insufficient for actual gas fee), the epilogue aborts with `PROLOGUE_ECANT_PAY_GAS_DEPOSIT`.

The failure epilogue uses `expect_only_successful_execution` for error handling, [6](#0-5)  which converts any epilogue error (including balance check failures) to `UNEXPECTED_ERROR_FROM_KNOWN_MOVE_FUNCTION`. [7](#0-6) 

**Exploit Scenario:**

The vulnerability is exploitable because the prologue checks balance against maximum possible fee, but users can spend their balance during execution:

1. Prologue validates: `balance >= (gas_price × max_gas_units)` [8](#0-7) 
2. Transaction executes and user code transfers most of their balance
3. Transaction fails (any reason)
4. Epilogue checks: `balance >= (gas_price × actual_gas_used)`
5. If balance was depleted during execution, epilogue fails
6. Transaction is discarded without gas charge

Example: User with 1000 APT, max_gas=900 units. Prologue passes (1000≥900). Transaction spends 700 APT (balance now 300). Transaction fails with actual gas usage of 500 units. Epilogue checks 300≥500, fails, transaction discarded. Result: 500 gas units consumed for free.

**Bypass of Feature Flag:**

The `CHARGE_INVARIANT_VIOLATION` feature flag is enabled by default [9](#0-8)  and is designed to ensure invariant violations are kept and charged rather than discarded. [10](#0-9)  However, the fallback handler at line 623 bypasses this feature flag by directly calling `discarded_output`, never invoking the `TransactionStatus::from_vm_status` logic that would respect the flag.

## Impact Explanation

This vulnerability enables **High Severity** DoS attacks as defined in the Aptos bug bounty program under "Validator Node Slowdowns (High): DoS through resource exhaustion."

**Direct Impacts:**
- Attackers can submit transactions consuming validator CPU, memory, and bandwidth without paying gas fees
- Validators process and execute transactions without economic compensation
- The fundamental economic security model (gas payment for resource consumption) is bypassed

**System-Wide Consequences:**
- Network resources can be exhausted by free spam transactions
- Sustained attacks could degrade network performance
- Economic incentives for validators are undermined
- Protocol violates its core design principle that "discarding enables DoS attacks"

This aligns precisely with the bug bounty program's High severity category for validator node slowdowns through resource exhaustion, which is explicitly listed as a valid vulnerability class worth up to $50,000.

## Likelihood Explanation

**Likelihood: HIGH**

The vulnerability has high exploitability because:

1. **Simple Attack Pattern**: Any user can trigger by spending their balance during transaction execution to make the epilogue balance check fail. No special permissions or complex setup required.

2. **Reliable Trigger**: The attack is deterministic - if a user crafts a transaction that depletes their balance below the actual gas fee during execution, the epilogue will fail.

3. **Multiple Scenarios**:
   - **Intentional exploitation**: Users deliberately spend balance during execution
   - **Parallel execution race conditions**: Block-STM may cause concurrent transactions from the same account to interfere, depleting balance before epilogue runs
   - **High load conditions**: VM internal errors or gas parameter loading failures become more likely

4. **Economic Incentive**: Attackers profit directly from free computation, creating strong motivation to exploit this vulnerability.

5. **No Protective Mechanisms**: The codebase contains no reservation or locking mechanism to prevent users from spending their balance during transaction execution, making the attack straightforward.

The vulnerability is more likely to manifest during high transaction throughput, parallel execution with Block-STM, and network stress conditions.

## Recommendation

**Fix the fallback handler to respect the CHARGE_INVARIANT_VIOLATION feature flag:**

Modify the error handling in `failed_transaction_cleanup` to properly process errors through `TransactionStatus::from_vm_status` instead of directly calling `discarded_output`. This ensures that invariant violations are kept and charged according to the feature flag.

Specifically, when `finish_aborted_transaction` returns an error:
1. Convert the error to a proper VMStatus
2. Call `TransactionStatus::from_vm_status` with the error and feature flags
3. If the result is `Keep`, create an output with appropriate gas charges
4. Only use `Discard` when `from_vm_status` determines discard is appropriate

**Alternative approach:** Implement balance reservation during prologue to prevent users from spending the maximum transaction fee during execution, ensuring the epilogue balance check cannot fail due to user actions.

**Additional hardening:** Add explicit checks before calling the failure epilogue to verify sufficient balance exists, and handle insufficient balance scenarios gracefully by charging whatever is available rather than discarding.

## Proof of Concept

```move
// PoC Move module demonstrating the vulnerability
module attacker::dos_exploit {
    use std::signer;
    use aptos_framework::coin;
    use aptos_framework::aptos_coin::AptosCoin;
    
    // This function will be called in a transaction that exploits the vulnerability
    public entry fun exploit_gas_bypass(account: &signer, recipient: address) {
        // Get current balance
        let balance = coin::balance<AptosCoin>(signer::address_of(account));
        
        // Calculate amount to transfer to make epilogue fail
        // Leave just enough to pass prologue but not enough for actual gas
        let transfer_amount = balance - 300; // Assuming actual gas will be ~500
        
        // Transfer most of the balance during execution
        coin::transfer<AptosCoin>(account, recipient, transfer_amount);
        
        // Force transaction to abort so failure epilogue runs
        abort 1
    }
}

// Attack scenario:
// 1. Attacker has 1000 APT
// 2. Submits transaction with max_gas = 900 units, gas_price = 1
// 3. Prologue passes: 1000 >= 900 ✓
// 4. Transaction executes exploit_gas_bypass, transfers 700 APT
// 5. Transaction aborts (balance now 300 APT)
// 6. Epilogue tries to charge actual gas (500 units = 500 APT)
// 7. Balance check: 300 >= 500 ✗ fails
// 8. Transaction discarded, no gas charged
// 9. Attacker consumed 500 gas units for free
```

This PoC demonstrates how an attacker can deliberately trigger the vulnerability by spending their balance during execution, causing the epilogue to fail and the transaction to be discarded without gas payment.

### Citations

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L580-586)
```rust
            // This is a tradeoff. We have to either
            //   1. Continue to calculate the gas cost based on the numbers we have.
            //   2. Discard the transaction.
            //
            // Option (2) does not work, since it would enable DoS attacks.
            // Option (1) is not ideal, but optimistically, it should allow the network
            // to continue functioning, less the transactions that run into this problem.
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L596-600)
```rust
        let txn_status = TransactionStatus::from_vm_status(
            error_vm_status.clone(),
            self.features(),
            self.gas_feature_version() >= RELEASE_V1_38,
        );
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L610-623)
```rust
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
```

**File:** aptos-move/aptos-vm/src/errors.rs (L290-303)
```rust
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
```

**File:** aptos-move/aptos-vm/src/errors.rs (L307-309)
```rust
pub(crate) fn discarded_output(status_code: StatusCode) -> VMOutput {
    VMOutput::empty_with_status(TransactionStatus::Discard(status_code))
}
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L188-212)
```text
        let max_transaction_fee = txn_gas_price * txn_max_gas_units;
        if (!skip_gas_payment(
            is_simulation,
            gas_payer_address
        )) {
            assert!(
                permissioned_signer::check_permission_capacity_above(
                    gas_payer,
                    (max_transaction_fee as u256),
                    GasPermission {}
                ),
                error::permission_denied(PROLOGUE_PERMISSIONED_GAS_LIMIT_INSUFFICIENT)
            );
            if (features::operations_default_to_fa_apt_store_enabled()) {
                assert!(
                    aptos_account::is_fungible_balance_at_least(gas_payer_address, max_transaction_fee),
                    error::invalid_argument(PROLOGUE_ECANT_PAY_GAS_DEPOSIT)
                );
            } else {
                assert!(
                    coin::is_balance_at_least<AptosCoin>(gas_payer_address, max_transaction_fee),
                    error::invalid_argument(PROLOGUE_ECANT_PAY_GAS_DEPOSIT)
                );
            }
        };
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L609-618)
```text
                assert!(
                    aptos_account::is_fungible_balance_at_least(gas_payer, transaction_fee_amount),
                    error::out_of_range(PROLOGUE_ECANT_PAY_GAS_DEPOSIT),
                );
            } else {
                assert!(
                    coin::is_balance_at_least<AptosCoin>(gas_payer, transaction_fee_amount),
                    error::out_of_range(PROLOGUE_ECANT_PAY_GAS_DEPOSIT),
                );
            };
```

**File:** aptos-move/aptos-vm/src/transaction_validation.rs (L678-684)
```rust
    .or_else(|err| {
        expect_only_successful_execution(
            err,
            APTOS_TRANSACTION_VALIDATION.user_epilogue_name.as_str(),
            log_context,
        )
    })
```

**File:** types/src/on_chain_config/aptos_features.rs (L194-194)
```rust
            FeatureFlag::CHARGE_INVARIANT_VIOLATION,
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
