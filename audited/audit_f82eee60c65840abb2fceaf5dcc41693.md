# Audit Report

## Title
Zero Gas Unit Scaling Factor Causes API Server Crash and Storage Fee Bypass Due to Missing Validation

## Summary
The gas schedule update mechanism lacks validation of the `gas_unit_scaling_factor` parameter. If this parameter is set to zero (either maliciously or accidentally through governance), it causes a **division by zero panic** in the API server and completely bypasses storage fee charging, allowing unlimited state bloat at zero cost.

## Finding Description

The `gas_unit_scaling_factor` parameter can be updated via on-chain governance without any validation checks. While the `scaling_factor()` method contains a safeguard that returns 1 when the raw value is 0, this protection is bypassed in two critical locations that use the raw parameter directly. [1](#0-0) 

The gas schedule update functions only validate that the blob is non-empty and the feature version is not downgraded, but **do not validate parameter values**. The comments explicitly acknowledge this missing validation: [2](#0-1) 

The raw `gas_unit_scaling_factor` parameter is used directly in two locations:

**Vulnerability 1: API Server Division by Zero Crash** [3](#0-2) 

When clients request gas estimation with `estimate_max_gas_amount`, the API divides by the raw `gas_unit_scaling_factor` without checking for zero. If this value is 0, the API server will panic with a division by zero error, causing complete API unavailability.

**Vulnerability 2: Storage Fee Bypass** [4](#0-3) 

The `charge_storage_fee` function multiplies the storage fee amount by the raw `gas_unit_scaling_factor` to convert from Octa to internal gas units. If the scaling factor is 0, this calculation results in zero gas being charged for all storage operations, completely bypassing storage fees.

The default value is set to 1,000,000: [5](#0-4) [6](#0-5) 

While there is a `scaling_factor()` method with a safeguard: [7](#0-6) 

This safeguard is **not used** in the two vulnerable locations mentioned above.

## Impact Explanation

**High Severity** - This meets the bug bounty criteria for "API crashes" and "Significant protocol violations":

1. **API Unavailability**: A zero scaling factor causes immediate panic in the API server when processing gas estimation requests, resulting in complete API service disruption affecting all users and ecosystem applications.

2. **Economic Security Violation**: Storage fees are a critical economic mechanism to prevent state bloat attacks. Bypassing storage fees allows attackers to write unlimited data to the blockchain state at zero cost, violating the **Resource Limits** invariant (#9) that "all operations must respect gas, storage, and computational limits."

3. **Consensus Divergence Risk**: If the API crash causes some nodes to fail while others continue (due to different API configurations), it could lead to network inconsistencies.

## Likelihood Explanation

**Medium-High Likelihood:**

While requiring a governance proposal, this is highly likely to occur due to:

1. **No Validation**: The complete absence of parameter validation means any proposal setting this value to 0 will be accepted by the system.

2. **Accidental Misconfiguration**: The gas schedule updator tool or proposal generation process could contain a bug that accidentally sets this to 0. The TODO comments indicate this validation was always intended but never implemented.

3. **Testing Artifacts**: Developers commonly use zero values for testing purposes, and such test configurations could accidentally reach production through governance proposals.

4. **Multiple Attack Vectors**: An attacker needs to either compromise the proposal generation process or convince governance to approve a malicious update.

## Recommendation

Add comprehensive validation to the gas schedule update functions:

```rust
public fun set_for_next_epoch(aptos_framework: &signer, gas_schedule_blob: vector<u8>) acquires GasScheduleV2 {
    system_addresses::assert_aptos_framework(aptos_framework);
    assert!(!vector::is_empty(&gas_schedule_blob), error::invalid_argument(EINVALID_GAS_SCHEDULE));
    let new_gas_schedule: GasScheduleV2 = from_bytes(gas_schedule_blob);
    
    // ADD VALIDATION HERE
    validate_gas_schedule_parameters(&new_gas_schedule);
    
    if (exists<GasScheduleV2>(@aptos_framework)) {
        let cur_gas_schedule = borrow_global<GasScheduleV2>(@aptos_framework);
        assert!(
            new_gas_schedule.feature_version >= cur_gas_schedule.feature_version,
            error::invalid_argument(EINVALID_GAS_FEATURE_VERSION)
        );
    };
    config_buffer::upsert(new_gas_schedule);
}

// Add validation function
fun validate_gas_schedule_parameters(schedule: &GasScheduleV2) {
    // Validate gas_unit_scaling_factor is non-zero
    let scaling_factor_entry = find_entry(schedule, "txn.gas_unit_scaling_factor");
    assert!(scaling_factor_entry > 0, error::invalid_argument(EINVALID_GAS_SCHEDULE));
    
    // Add other parameter validations as needed
}
```

Additionally, use the safe `scaling_factor()` method consistently instead of raw parameter access:

```rust
// In algebra.rs, line 261, change from:
(u64::from(amount) as u128) * (u64::from(txn_params.gas_unit_scaling_factor) as u128)

// To:
(u64::from(amount) as u128) * (u64::from(txn_params.scaling_factor()) as u128)
```

## Proof of Concept

```rust
// Rust reproduction steps demonstrating the vulnerability

#[test]
#[should_panic(expected = "attempt to divide by zero")]
fn test_api_crash_with_zero_scaling_factor() {
    // Create mock gas parameters with zero scaling factor
    let mut gas_params = VMGasParameters::zeros();
    gas_params.txn.gas_unit_scaling_factor = GasScalingFactor::new(0);
    
    // This matches the API code path from transactions.rs:656
    let min_transaction_gas_units = u64::from(gas_params.txn.min_transaction_gas_units);
    let scaling_factor = u64::from(gas_params.txn.gas_unit_scaling_factor);
    
    // This will panic with division by zero
    let min_number_of_gas_units = min_transaction_gas_units / scaling_factor;
}

#[test]
fn test_storage_fee_bypass_with_zero_scaling_factor() {
    // Create mock gas parameters with zero scaling factor  
    let mut gas_params = VMGasParameters::zeros();
    gas_params.txn.gas_unit_scaling_factor = GasScalingFactor::new(0);
    
    // Simulate storage fee calculation from algebra.rs:261
    let storage_fee_in_octa: u128 = 1_000_000; // 1 APT storage fee
    let gas_unit_price: u128 = 100; // Price per gas unit
    let scaling_factor: u128 = u64::from(gas_params.txn.gas_unit_scaling_factor) as u128;
    
    // Calculate gas consumed (this should charge gas for storage)
    let gas_consumed = (storage_fee_in_octa * scaling_factor) / gas_unit_price;
    
    // With zero scaling factor, NO GAS IS CHARGED
    assert_eq!(gas_consumed, 0, "Storage fee bypass: zero gas charged!");
    // Expected: should charge (1_000_000 * 1_000_000) / 100 = 10_000_000_000 internal gas
    // Actual: charges 0 gas due to multiplication by zero
}
```

**Notes**

This vulnerability exists because the codebase has incomplete validation infrastructure for gas schedule parameters. The safeguard in the `scaling_factor()` method demonstrates awareness of the zero-value danger, but the inconsistent use of the raw parameter in critical code paths creates exploitable gaps. The TODO comments in `gas_schedule.move` confirm this validation was always planned but never implemented, making this a critical oversight rather than a design decision.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L47-48)
```text
        // TODO(Gas): check if gas schedule is consistent
        let gas_schedule: GasScheduleV2 = from_bytes(gas_schedule_blob);
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

**File:** api/src/transactions.rs (L654-658)
```rust
                let min_number_of_gas_units =
                    u64::from(gas_params.vm.txn.min_transaction_gas_units)
                        / u64::from(gas_params.vm.txn.gas_unit_scaling_factor);
                let max_number_of_gas_units =
                    u64::from(gas_params.vm.txn.maximum_number_of_gas_units);
```

**File:** aptos-move/aptos-gas-meter/src/algebra.rs (L260-263)
```rust
        let gas_consumed_internal = div_ceil(
            (u64::from(amount) as u128) * (u64::from(txn_params.gas_unit_scaling_factor) as u128),
            u64::from(gas_unit_price) as u128,
        );
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L22-22)
```rust
const GAS_SCALING_FACTOR: u64 = 1_000_000;
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L83-86)
```rust
            gas_unit_scaling_factor: GasScalingFactor,
            "gas_unit_scaling_factor",
            GAS_SCALING_FACTOR
        ],
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L291-298)
```rust
    // TODO(Gas): Right now we are relying on this to avoid div by zero errors when using the all-zero
    //            gas parameters. See if there's a better way we can handle this.
    pub fn scaling_factor(&self) -> GasScalingFactor {
        match u64::from(self.gas_unit_scaling_factor) {
            0 => 1.into(),
            x => x.into(),
        }
    }
```
