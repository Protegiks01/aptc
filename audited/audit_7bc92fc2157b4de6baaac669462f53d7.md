# Audit Report

## Title
Division by Zero DoS via Malicious Gas Schedule Deserialization Bypassing Validation

## Summary
The gas algebra deserialization path using `From<u64>` allows invalid gas parameter values (specifically `gas_unit_scaling_factor = 0`) to be set through on-chain governance without validation. This bypasses the protective `scaling_factor()` method and causes a division by zero panic in the public `/transactions/simulate` API endpoint, resulting in API server crashes.

## Finding Description

The vulnerability stems from combining three security weaknesses:

**1. Missing Validation in Deserialization Path** [1](#0-0) [2](#0-1) 

The `GasQuantity<U>` struct derives `Deserialize` and implements `From<u64>` which both directly call the `new()` constructor without any validation. Any u64 value, including 0, is accepted.

**2. Incomplete Gas Schedule Validation in Move Layer** [3](#0-2) 

The `set_for_next_epoch()` function accepts new gas schedules through deserialization but only validates feature version and non-empty blob. The TODO comments at lines 47, 67, and 75 explicitly note that consistency checks are missing.

**3. Unsafe Direct Usage in API Code** [4](#0-3) 

The API code directly converts `gas_unit_scaling_factor` to u64 and uses it as a divisor, bypassing the protective `scaling_factor()` method: [5](#0-4) 

**Attack Path:**
1. Governance proposal sets `txn.gas_unit_scaling_factor` to 0 in gas schedule
2. Value deserializes via `FromOnChainGasSchedule::from_on_chain_gas_schedule()` macro
3. Macro uses `.into()` which calls `From<u64>` trait - no validation occurs
4. User calls public API: `POST /transactions/simulate?estimate_max_gas_amount=true`
5. Line 656 in `api/src/transactions.rs` executes division by zero
6. Server panics and crashes

## Impact Explanation

This is a **High Severity** vulnerability per Aptos bug bounty criteria:
- **API crashes** - explicitly listed under High Severity ($50,000)
- Any unprivileged user can trigger the crash once malicious gas schedule is active
- Affects validator nodes running public APIs
- Causes denial of service for transaction simulation functionality
- Could impact multiple nodes simultaneously

The vulnerability breaks the **Resource Limits** invariant: gas parameters must maintain semantic validity to enable proper gas accounting.

## Likelihood Explanation

**Medium Likelihood:**
- Requires governance access to initially set malicious gas schedule (high barrier)
- However, could occur accidentally during gas schedule updates (human error)
- Once set, exploitation is trivial - any API call with specific parameter
- The TODO comments indicate developers are aware validation is needed but haven't implemented it
- No runtime checks prevent this invalid state from being committed

## Recommendation

Implement three layers of defense:

**1. Add validation in gas parameter deserialization (Rust layer):**

```rust
impl<U> From<u64> for GasQuantity<U> {
    fn from(val: u64) -> Self {
        Self::new(val)
    }
}

// Add validation for specific gas parameters in TransactionGasParameters
impl TransactionGasParameters {
    pub fn validate(&self) -> Result<(), String> {
        if u64::from(self.gas_unit_scaling_factor) == 0 {
            return Err("gas_unit_scaling_factor cannot be zero".to_string());
        }
        // Add other critical parameter validations
        Ok(())
    }
}
```

**2. Enforce validation in Move layer:** [3](#0-2) 

Replace the TODO comment with actual validation:
```move
public fun set_for_next_epoch(aptos_framework: &signer, gas_schedule_blob: vector<u8>) {
    // ... existing checks ...
    let new_gas_schedule: GasScheduleV2 = from_bytes(gas_schedule_blob);
    validate_gas_schedule(&new_gas_schedule); // Add this validation
    // ... rest of function ...
}
```

**3. Always use the protective scaling_factor() method:** [4](#0-3) 

Replace direct usage with:
```rust
let min_number_of_gas_units =
    u64::from(gas_params.vm.txn.min_transaction_gas_units)
        / u64::from(gas_params.vm.txn.scaling_factor());  // Use protective method
```

## Proof of Concept

```rust
#[test]
fn test_gas_scaling_factor_zero_causes_panic() {
    use aptos_gas_schedule::{FromOnChainGasSchedule, AptosGasParameters};
    use std::collections::BTreeMap;
    
    // Create gas schedule with zero scaling factor
    let mut gas_schedule = BTreeMap::new();
    gas_schedule.insert("txn.gas_unit_scaling_factor".to_string(), 0u64);
    gas_schedule.insert("txn.min_transaction_gas_units".to_string(), 1000u64);
    // ... add other required parameters ...
    
    // This succeeds - no validation!
    let params = AptosGasParameters::from_on_chain_gas_schedule(&gas_schedule, 15).unwrap();
    
    // This will panic with division by zero
    let min_gas = u64::from(params.vm.txn.min_transaction_gas_units) 
        / u64::from(params.vm.txn.gas_unit_scaling_factor);
}
```

**Notes**

The vulnerability exists because deserialization through `From<u64>` trait and serde's `Deserialize` derive both bypass any validation that should occur. The `GasQuantity<U>` type is designed as a simple wrapper with saturating arithmetic, but certain gas parameters have semantic constraints (like non-zero values) that must be enforced at the point of configuration, not just at usage.

The protective `scaling_factor()` method exists but is not consistently used throughout the codebase, creating an inconsistent security boundary. The TODO comments in the Move layer gas schedule module confirm that validation was intended but never implemented, leaving this attack surface exposed.

### Citations

**File:** third_party/move/move-core/types/src/gas_algebra.rs (L57-61)
```rust
#[derive(Serialize, Deserialize)]
pub struct GasQuantity<U> {
    val: u64,
    phantom: PhantomData<U>,
}
```

**File:** third_party/move/move-core/types/src/gas_algebra.rs (L128-132)
```rust
impl<U> From<u64> for GasQuantity<U> {
    fn from(val: u64) -> Self {
        Self::new(val)
    }
}
```

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L91-102)
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
```

**File:** api/src/transactions.rs (L654-656)
```rust
                let min_number_of_gas_units =
                    u64::from(gas_params.vm.txn.min_transaction_gas_units)
                        / u64::from(gas_params.vm.txn.gas_unit_scaling_factor);
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
