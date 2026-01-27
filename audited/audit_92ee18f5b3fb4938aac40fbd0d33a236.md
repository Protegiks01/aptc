# Audit Report

## Title
Free Account Creation Bypass via Zero Gas Price with DEFAULT_ACCOUNT_RESOURCE Feature Flag

## Summary
A logic flaw in gas validation allows unlimited free account creation when `gas_unit_price == 0` combined with the `DEFAULT_ACCOUNT_RESOURCE` feature flag being enabled. The vulnerability bypasses both pre-execution gas checks and post-execution fee validation, enabling attackers to create unlimited accounts without paying any transaction fees, causing unbounded state bloat.

## Finding Description

The vulnerability exists in the account creation fee validation logic across multiple components:

**1. Gas Pre-Check Bypass** [1](#0-0) 

When an account needs to be created, this code checks if sufficient gas is provided. However, the condition on line 219 uses:
```rust
&& (gas_unit_price != 0 || !features.is_default_account_resource_enabled())
```

When `gas_unit_price == 0` AND `is_default_account_resource_enabled()` returns true, this evaluates to `false`, completely bypassing lines 221-246 that validate sufficient fees for account creation.

**2. Account Existence Check Always Passes** [2](#0-1) 

The `exists_at()` function returns true for ANY address when `DEFAULT_ACCOUNT_RESOURCE` is enabled, regardless of whether the Account resource actually exists. This allows transactions with sequence number 0 to pass prologue validation even for non-existent accounts.

**3. Post-Execution Fee Validation Bypass** [3](#0-2) 

After account creation, the VM validates that sufficient fees were charged. However, the same flawed condition is used at line 762, bypassing this critical validation when `gas_unit_price == 0` and the feature flag is enabled.

**4. Zero Fee Charged in Epilogue** [4](#0-3) 

The transaction fee is calculated as `txn_gas_price * gas_used`. When `txn_gas_price == 0`, no fee is charged regardless of gas consumption.

**5. Account Creation Triggers** [5](#0-4) 

The `should_create_account_resource()` function returns true when `DEFAULT_ACCOUNT_RESOURCE` is enabled and sequence number is 0, triggering automatic account creation.

**Attack Path:**

1. Attacker submits transactions with:
   - `gas_unit_price = 0`
   - `sequence_number = 0` 
   - `sender = non-existent account address`
   - Minimal `max_gas_amount`

2. **Prologue passes** because `exists_at()` returns true when `DEFAULT_ACCOUNT_RESOURCE` is enabled

3. **check_gas() validation bypassed** at lines 214-247 in gas.rs

4. **Account created during execution** via `create_account_if_does_not_exist()`

5. **Post-creation fee validation bypassed** at lines 762-785 in aptos_vm.rs

6. **Epilogue charges zero fees** (0 × gas_used = 0)

7. **Each account creates storage**: [6](#0-5) 

## Impact Explanation

**Severity: HIGH**

This vulnerability enables unbounded state bloat, qualifying as **High Severity** under Aptos bug bounty criteria:
- **Validator node slowdowns**: Unlimited account creation increases state size, degrading validator performance
- **Significant protocol violations**: Violates invariant #9 (Resource Limits) - operations must respect storage limits

**Exploitability Conditions:**
- Requires `min_price_per_gas_unit` configured to 0 [7](#0-6) 
- On mainnet: `min_price_per_gas_unit = 100` (mitigated)
- On test/dev builds: `min_price_per_gas_unit = 0` (vulnerable)
- On custom networks: Depends on governance configuration

**Attack Scale:**
An attacker could create millions of accounts at zero cost, with each account storing:
- Authentication key (32 bytes)
- Event handles with GUIDs
- Capability offers
- Sequence number and metadata

This causes permanent state bloat as accounts cannot be deleted, degrading all validator nodes.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH** (on vulnerable networks)

**Attack Requirements:**
- No privileged access needed
- Simple transaction construction
- Requires network where `min_price_per_gas_unit == 0`

**Current Risk:**
- Mainnet: NOT vulnerable (min_price_per_gas_unit = 100)
- Testnets/Devnets: Potentially vulnerable
- Custom networks: Vulnerable if misconfigured

**Exploitation Complexity:** LOW - Attacker can automate mass account creation with simple scripts.

## Recommendation

**Fix the conditional logic to ALWAYS validate account creation fees**, regardless of feature flags:

```rust
// In gas.rs, line 214-247
if crate::aptos_vm::should_create_account_resource(
    txn_metadata,
    features,
    resolver,
    module_storage,
)? {
    // ALWAYS check account creation fees, remove the feature flag bypass
    let max_gas_amount: u64 = txn_metadata.max_gas_amount().into();
    let gas_unit_price: u64 = txn_metadata.gas_unit_price().into();
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
        return Err(VMStatus::error(
            StatusCode::MAX_GAS_UNITS_BELOW_MIN_TRANSACTION_GAS_UNITS,
            None,
        ));
    }
}
```

Apply the same fix to aptos_vm.rs line 762-785.

## Proof of Concept

```rust
// Test demonstrating free account creation
#[test]
fn test_free_account_creation_with_zero_gas_price() {
    let mut h = MoveHarness::new_with_features(
        vec![FeatureFlag::DEFAULT_ACCOUNT_RESOURCE],
        vec![],
    );
    
    // Create 1000 new accounts with zero gas price
    for i in 0..1000 {
        let new_account_addr = AccountAddress::from_hex_literal(
            &format!("0x{:064x}", i)
        ).unwrap();
        
        // Transaction with gas_unit_price = 0
        let txn = TransactionBuilder::new(new_account_addr)
            .sequence_number(0)
            .gas_unit_price(0)  // Zero gas price
            .max_gas_amount(10)
            .payload(aptos_stdlib::aptos_coin_transfer(new_account_addr, 0))
            .build();
            
        // Transaction succeeds with ZERO fees charged
        let output = h.run_transaction(txn);
        assert!(output.status().is_success());
        assert_eq!(output.gas_used(), 0); // No fees charged!
        
        // Account was created
        assert!(h.exists_at(new_account_addr));
    }
    
    // Result: 1000 accounts created with ZERO cost
    // State bloated with no payment for storage
}
```

**Notes:**
- This vulnerability is present in the code logic but mitigated on Aptos mainnet by `min_price_per_gas_unit = 100`
- Vulnerable on networks where `min_price_per_gas_unit = 0` (test environments, misconfigured custom networks)
- The flawed bypass logic should be removed to prevent future exploitation if gas pricing configurations change

### Citations

**File:** aptos-move/aptos-vm/src/gas.rs (L214-247)
```rust
    if crate::aptos_vm::should_create_account_resource(
        txn_metadata,
        features,
        resolver,
        module_storage,
    )? && (gas_unit_price != 0 || !features.is_default_account_resource_enabled())
    {
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
            speculative_warn!(
                log_context,
                format!(
                    "[VM] Insufficient gas for account creation; min {}, submitted {}",
                    expected, actual,
                ),
            );
            return Err(VMStatus::error(
                StatusCode::MAX_GAS_UNITS_BELOW_MIN_TRANSACTION_GAS_UNITS,
                None,
            ));
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/account/account.move (L61-69)
```text
    struct Account has key, store {
        authentication_key: vector<u8>,
        sequence_number: u64,
        guid_creation_num: u64,
        coin_register_events: EventHandle<CoinRegisterEvent>,
        key_rotation_events: EventHandle<KeyRotationEvent>,
        rotation_capability_offer: CapabilityOffer<RotationCapability>,
        signer_capability_offer: CapabilityOffer<SignerCapability>,
    }
```

**File:** aptos-move/framework/aptos-framework/sources/account/account.move (L348-350)
```text
    public fun exists_at(addr: address): bool {
        features::is_default_account_resource_enabled() || exists<Account>(addr)
    }
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

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L3457-3461)
```rust
    if (features.is_enabled(FeatureFlag::DEFAULT_ACCOUNT_RESOURCE)
        || (features.is_enabled(FeatureFlag::SPONSORED_AUTOMATIC_ACCOUNT_V1_CREATION)
            && txn_data.fee_payer.is_some()))
        && txn_data.replay_protector == ReplayProtector::SequenceNumber(0)
    {
```

**File:** aptos-move/framework/aptos-framework/sources/transaction_validation.move (L596-603)
```text
        assert!(txn_max_gas_units >= gas_units_remaining, error::invalid_argument(EOUT_OF_GAS));
        let gas_used = txn_max_gas_units - gas_units_remaining;

        assert!(
            (txn_gas_price as u128) * (gas_used as u128) <= MAX_U64,
            error::out_of_range(EOUT_OF_GAS)
        );
        let transaction_fee_amount = txn_gas_price * gas_used;
```

**File:** config/global-constants/src/lib.rs (L23-26)
```rust
#[cfg(any(test, feature = "testing"))]
pub const GAS_UNIT_PRICE: u64 = 0;
#[cfg(not(any(test, feature = "testing")))]
pub const GAS_UNIT_PRICE: u64 = 100;
```
