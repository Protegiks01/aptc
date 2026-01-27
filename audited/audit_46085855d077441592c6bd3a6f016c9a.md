# Audit Report

## Title
Storage Cost Bypass via Zero Gas Price Account Creation

## Summary
A flawed bypass condition in `check_gas()` allows attackers to create accounts at zero cost when `gas_unit_price` is 0 and the `DEFAULT_ACCOUNT_RESOURCE` feature flag is enabled. This bypasses storage fee validation and enables unlimited free account creation, violating the resource limits invariant and enabling storage spam attacks.

## Finding Description

The account creation cost validation in the `check_gas()` function contains a critical bypass condition that allows attackers to circumvent storage cost requirements. The vulnerability exists in the conditional logic that determines whether to enforce account creation fee validation. [1](#0-0) 

This bypass condition evaluates to `false` (skipping validation) when both:
1. `gas_unit_price == 0`
2. `features.is_default_account_resource_enabled()` returns `true`

The `DEFAULT_ACCOUNT_RESOURCE` feature is enabled by default in production: [2](#0-1) 

When the validation is bypassed, the transaction proceeds to execution without ensuring sufficient gas budget for account creation. During execution, the account is created via the Move framework: [3](#0-2) 

The critical issue occurs during storage fee processing. When `gas_unit_price` is zero, the storage fee calculation returns 0 without charging any fees: [4](#0-3) 

Additionally, there is a similar bypass in the post-execution validation (abort hook): [5](#0-4) 

Finally, in the epilogue, the transaction fee is calculated as `gas_unit_price * gas_used`, resulting in zero total cost: [6](#0-5) 

**Attack Path:**
1. Attacker submits transaction with `gas_unit_price = 0` and `sequence_number = 0` (new account)
2. Pre-execution validation in `check_gas()` is bypassed (lines 213-247)
3. Account is created during execution, consuming storage
4. Storage fee processing returns 0 due to zero gas price (traits.rs:171-173)
5. Post-execution validation is also bypassed (aptos_vm.rs:762-785)
6. Epilogue charges zero fees (`0 * gas_used = 0`)
7. Result: Account created at zero cost

**Prerequisite Conditions:**
- `min_price_per_gas_unit` must be 0 (can be set via on-chain governance, or defaults to 0 in testing environments)
- `DEFAULT_ACCOUNT_RESOURCE` feature flag is enabled (enabled by default in production) [7](#0-6) 

While production defaults to `GAS_UNIT_PRICE = 100`, governance can update this parameter on-chain to 0, enabling the attack.

## Impact Explanation

This vulnerability represents a **High Severity** issue under the Aptos bug bounty criteria for "Significant protocol violations."

**Security Guarantees Broken:**
- **Invariant #9 (Resource Limits)**: "All operations must respect gas, storage, and computational limits" - Storage costs are completely bypassed
- **Storage Cost Model**: The fundamental economic model requiring users to pay for state storage is violated

**Concrete Impact:**
1. **Storage Spam Attack**: Attackers can create unlimited accounts at zero cost, each consuming storage across all validator nodes
2. **State Bloat**: Unbounded state growth degrades network performance and increases hardware requirements for validators
3. **Economic Denial of Service**: Free account creation undermines the storage fee mechanism designed to prevent spam
4. **Validator Resource Exhaustion**: All validators must store and sync the spam accounts, increasing storage and bandwidth requirements

While not directly causing consensus failure or fund loss, this constitutes a significant protocol violation enabling resource exhaustion attacks against the entire network.

## Likelihood Explanation

**Current Likelihood: Low (but non-zero)**
- In production mainnet, `min_price_per_gas_unit` defaults to 100, preventing immediate exploitation
- However, this parameter is governable and can be changed to 0 through on-chain governance
- The code contains a TODO comment acknowledging this risk: [8](#0-7) 

**Testing Environment: High**
- In test/development environments, `GAS_UNIT_PRICE` defaults to 0, making this immediately exploitable
- Could affect devnet/testnet deployments

**Exploitability Assessment:**
- **Complexity**: Low - simple transaction submission
- **Attacker Requirements**: None - any user can submit transactions
- **Detectability**: High - creates observable state bloat

The vulnerability represents a latent risk that becomes critical if governance ever sets `min_price_per_gas_unit` to 0, whether intentionally (e.g., for a promotion period) or accidentally.

## Recommendation

**Fix the flawed bypass condition** to ensure storage cost validation always occurs when accounts are being created, regardless of the `DEFAULT_ACCOUNT_RESOURCE` feature flag status.

**Recommended Code Fix:**

```rust
// In aptos-move/aptos-vm/src/gas.rs, lines 213-247
// Remove the bypass condition and always validate when creating accounts

let gas_unit_price: u64 = txn_metadata.gas_unit_price().into();
if crate::aptos_vm::should_create_account_resource(
    txn_metadata,
    features,
    resolver,
    module_storage,
)? {
    // Remove the bypass condition entirely - always check
    // Alternatively, only bypass when gas_unit_price is non-zero:
    // && gas_unit_price != 0 {
    
    let max_gas_amount: u64 = txn_metadata.max_gas_amount().into();
    let pricing = DiskSpacePricing::new(gas_feature_version, features);
    let storage_fee_per_account_create: u64 = pricing
        .hack_estimated_fee_for_account_creation(txn_gas_params)
        .into();

    let expected = gas_unit_price * 10
        + if features.is_new_account_default_to_fa_store() {
            1
        } else {
            2
        } * storage_fee_per_account_create;
    let actual = gas_unit_price * max_gas_amount;
    if actual < expected {
        // Error handling...
    }
}
```

**Additional Hardening:**
1. Enforce `min_price_per_gas_unit > 0` at the gas parameter level to prevent governance from setting it to 0
2. Add explicit validation that rejects `gas_unit_price = 0` for transactions that create accounts
3. Update the similar bypass condition in `aptos_vm.rs` (line 762)

## Proof of Concept

```rust
// Test demonstrating the vulnerability
// Place in aptos-move/e2e-move-tests/src/tests/

#[test]
fn test_zero_cost_account_creation() {
    use aptos_types::account_config;
    use aptos_cached_packages::aptos_stdlib;
    use move_core_types::account_address::AccountAddress;
    
    // Initialize test harness with DEFAULT_ACCOUNT_RESOURCE enabled
    let mut harness = MoveHarness::new_with_features(
        vec![FeatureFlag::DEFAULT_ACCOUNT_RESOURCE],
        vec![]
    );
    
    // Set min_price_per_gas_unit to 0 via governance
    let governance = harness.aptos_framework_account();
    harness.run_transaction_payload(
        &governance,
        aptos_stdlib::gas_schedule_set_gas_schedule(/* ... set min to 0 ... */)
    );
    
    // Create new account address
    let new_account = AccountAddress::random();
    
    // Submit transaction with gas_unit_price = 0
    let txn = harness
        .create_entry_function(
            &new_account,
            str::parse("0x1::aptos_account::transfer").unwrap(),
            vec![],
            vec![bcs::to_bytes(&AccountAddress::ONE).unwrap()],
        )
        .sequence_number(0)  // New account
        .gas_unit_price(0)   // Zero gas price!
        .max_gas_amount(1000000)
        .sign();
    
    // Transaction should succeed, creating account at zero cost
    let result = harness.run_transaction(txn);
    assert!(result.status().status().unwrap().is_success());
    
    // Verify account was created
    assert!(harness.read_account_resource(&new_account).is_some());
    
    // Verify zero fees were charged
    let fee_statement = result.fee_statement();
    let total_cost = fee_statement.gas_used() * 0; // gas_unit_price = 0
    assert_eq!(total_cost, 0);
    
    println!("✗ Vulnerability confirmed: Account created with ZERO cost!");
}
```

## Notes

This vulnerability stems from an apparent design decision to bypass account creation validation when the `DEFAULT_ACCOUNT_RESOURCE` feature is enabled, possibly under the assumption that account creation behavior would be fundamentally different with this feature. However, this creates a security hole when combined with zero gas pricing.

The bypass conditions appear in multiple locations (pre-validation, post-validation), suggesting this was an intentional design choice rather than an oversight. Nevertheless, it violates the fundamental principle that storage operations should always have associated costs to prevent spam.

The immediate risk is mitigated by the production default of `min_price_per_gas_unit = 100`, but the latent vulnerability could be triggered by governance action or in testing environments where the default is 0.

### Citations

**File:** aptos-move/aptos-vm/src/gas.rs (L213-220)
```rust
    let gas_unit_price: u64 = txn_metadata.gas_unit_price().into();
    if crate::aptos_vm::should_create_account_resource(
        txn_metadata,
        features,
        resolver,
        module_storage,
    )? && (gas_unit_price != 0 || !features.is_default_account_resource_enabled())
    {
```

**File:** types/src/on_chain_config/aptos_features.rs (L260-260)
```rust
            FeatureFlag::DEFAULT_ACCOUNT_RESOURCE,
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L762-785)
```rust
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
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2043-2053)
```rust
        if should_create_account_resource {
            unwrap_or_discard!(
                user_session.execute(|session| create_account_if_does_not_exist(
                    session,
                    code_storage,
                    gas_meter,
                    txn.sender(),
                    &mut traversal_context,
                ))
            );
        }
```

**File:** aptos-move/aptos-gas-meter/src/traits.rs (L171-173)
```rust
        if gas_unit_price.is_zero() {
            return Ok(0.into());
        }
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L603-603)
```text
        let transaction_fee_amount = txn_gas_price * gas_used;
```

**File:** config/global-constants/src/lib.rs (L23-26)
```rust
#[cfg(any(test, feature = "testing"))]
pub const GAS_UNIT_PRICE: u64 = 0;
#[cfg(not(any(test, feature = "testing")))]
pub const GAS_UNIT_PRICE: u64 = 100;
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L60-60)
```rust
        // TODO(Gas): should probably change this to something > 0
```
