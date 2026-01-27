# Audit Report

## Title
Integer Overflow Vulnerability in Gas Calculation for Account Creation Validation

## Summary
The gas validation logic in `aptos-move/aptos-vm/src/gas.rs` performs unchecked multiplication of `gas_unit_price * max_gas_amount` when validating account creation requirements. This lacks overflow protection and could lead to incorrect validation results if gas parameters are misconfigured through on-chain governance, potentially causing consensus divergence or denial of service.

## Finding Description

The `check_gas()` function validates that transactions creating new accounts have sufficient gas to cover account creation costs. At line 233, it performs an unchecked u64 multiplication: [1](#0-0) 

This calculation multiplies two u64 values without overflow checking. In Rust, u64 multiplication wraps on overflow in release builds, which could produce incorrect validation results.

While the code validates that user-provided values don't exceed on-chain parameter bounds: [2](#0-1) [3](#0-2) 

The gas schedule parameters themselves can be updated via on-chain governance WITHOUT validation that their product remains under u64::MAX. The gas schedule update functions contain explicit TODO comments acknowledging this missing validation: [4](#0-3) [5](#0-4) 

The transaction gas parameters file acknowledges this overflow constraint should be maintained: [6](#0-5) 

However, there is no runtime enforcement of this invariant. The same unchecked multiplication also appears in the Rosetta API: [7](#0-6) 

Notably, other parts of the codebase properly use `checked_mul()` for similar gas calculations: [8](#0-7) 

This demonstrates that developers are aware of overflow risks but the critical validation path lacks this protection.

**Attack Scenario:**

1. A governance proposal updates `max_price_per_gas_unit` or `maximum_number_of_gas_units` to values where their product exceeds u64::MAX
2. The update succeeds because `gas_schedule.move` lacks validation (TODO not implemented)
3. Users submit transactions with maximum allowed gas values
4. The multiplication at line 233 overflows and wraps to a small value
5. If wrapped value < expected: valid account creation transactions are rejected (DoS)
6. If wrapped value > expected: insufficient gas is accepted, violating account creation invariants
7. Different nodes may calculate differently during parameter transition, causing consensus divergence

## Impact Explanation

This vulnerability has **HIGH severity** potential because:

1. **Consensus Risk**: If different validator nodes use different gas parameters during a governance update transition, the overflow could cause them to accept/reject different transactions, leading to consensus divergence and potential chain splits.

2. **Account Creation DoS**: Legitimate account creation transactions could be systematically rejected if the overflow produces a value less than the expected minimum, preventing new users from joining the network.

3. **Security Invariant Violation**: The account creation validation exists to ensure sufficient gas for storage fees. Bypassing this through overflow could allow account creation with insufficient funds, violating economic invariants.

4. **Governance Attack Surface**: While governance is trusted, this creates an unvalidated attack surface where mistakes in parameter updates could have severe consequences without any safety checks.

Per Aptos bug bounty criteria, this qualifies as **High Severity** ("Significant protocol violations") with potential to escalate to **Critical** ("Consensus/Safety violations") if exploited during a parameter update.

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability requires:
- A governance proposal to update gas parameters with values causing overflow
- No malicious intent required (accidental misconfiguration sufficient)
- The missing validation (acknowledged by TODO comments) makes this possible

Current parameters are safe:
- `maximum_number_of_gas_units`: 2,000,000
- `max_price_per_gas_unit`: 10,000,000,000  
- Product: 20,000,000,000,000,000 < u64::MAX (18,446,744,073,709,551,615)

However, the lack of validation means a future parameter update could inadvertently trigger this. The explicit TODO comments indicate developers planned to add this validation but haven't implemented it, increasing the risk of accidental misconfiguration.

## Recommendation

Implement defensive overflow checking in all gas calculation paths:

**Fix 1: Add checked arithmetic in gas.rs**

Replace line 233 with:
```rust
let actual = gas_unit_price.checked_mul(max_gas_amount)
    .ok_or_else(|| {
        VMStatus::error(
            StatusCode::ARITHMETIC_ERROR,
            None,
        )
    })?;
```

Similarly, add overflow checking at line 227:
```rust
let base_cost = gas_unit_price.checked_mul(10)
    .ok_or_else(|| {
        VMStatus::error(
            StatusCode::ARITHMETIC_ERROR,
            None,
        )
    })?;
let expected = base_cost.checked_add(
    if features.is_new_account_default_to_fa_store() { 1 } else { 2 }
        .checked_mul(storage_fee_per_account_create)
        .ok_or_else(|| VMStatus::error(StatusCode::ARITHMETIC_ERROR, None))?
    )
    .ok_or_else(|| VMStatus::error(StatusCode::ARITHMETIC_ERROR, None))?;
```

**Fix 2: Add validation in gas_schedule.move**

Replace the TODO comments with actual validation:
```move
public fun set_for_next_epoch(aptos_framework: &signer, gas_schedule_blob: vector<u8>) acquires GasScheduleV2 {
    system_addresses::assert_aptos_framework(aptos_framework);
    assert!(!vector::is_empty(&gas_schedule_blob), error::invalid_argument(EINVALID_GAS_SCHEDULE));
    let new_gas_schedule: GasScheduleV2 = from_bytes(gas_schedule_blob);
    
    // Validate gas schedule consistency
    validate_gas_schedule_consistency(&new_gas_schedule);
    
    // ... rest of function
}

fun validate_gas_schedule_consistency(schedule: &GasScheduleV2) {
    // Extract maximum_number_of_gas_units and max_price_per_gas_unit
    // Verify their product < u64::MAX
    // Abort with EINVALID_GAS_SCHEDULE if validation fails
}
```

**Fix 3: Update objects.rs to use checked_mul** [9](#0-8) 

Replace with:
```rust
pub fn suggested_gas_fee(gas_unit_price: u64, max_gas_amount: u64) -> Amount {
    Amount {
        value: gas_unit_price.checked_mul(max_gas_amount)
            .expect("Gas fee calculation overflow")
            .to_string(),
        currency: native_coin(),
    }
}
```

## Proof of Concept

```rust
// Proof of Concept: Overflow in gas calculation
// This demonstrates the overflow behavior with hypothetical misconfigured parameters

#[test]
fn test_gas_calculation_overflow() {
    // Hypothetical misconfigured governance parameters
    let max_price_per_gas_unit: u64 = u64::MAX / 1000; // 18,446,744,073,709,551
    let maximum_number_of_gas_units: u64 = 2000; 
    
    // User submits transaction with maximum allowed values
    let gas_unit_price: u64 = max_price_per_gas_unit; // Passes validation
    let max_gas_amount: u64 = maximum_number_of_gas_units; // Passes validation
    
    // Unchecked multiplication overflows
    let actual_unchecked = gas_unit_price.wrapping_mul(max_gas_amount);
    let actual_checked = gas_unit_price.checked_mul(max_gas_amount);
    
    println!("gas_unit_price: {}", gas_unit_price);
    println!("max_gas_amount: {}", max_gas_amount);
    println!("Unchecked result (wraps): {}", actual_unchecked);
    println!("Checked result: {:?}", actual_checked);
    
    assert!(actual_checked.is_none(), "Overflow should be detected");
    assert_ne!(actual_unchecked, gas_unit_price * max_gas_amount, 
               "Unchecked multiplication wraps on overflow");
    
    // Demonstrate that expected value could be larger than wrapped actual
    let storage_fee_per_account_create: u64 = 50000;
    let expected = gas_unit_price * 10 + 2 * storage_fee_per_account_create;
    
    // This comparison becomes invalid due to overflow
    if actual_unchecked < expected {
        println!("VULNERABILITY: Valid transaction incorrectly rejected due to overflow");
    }
}

// Recommended fix comparison
#[test] 
fn test_gas_calculation_with_overflow_check() {
    let gas_unit_price: u64 = u64::MAX / 1000;
    let max_gas_amount: u64 = 2000;
    
    // With checked_mul, overflow is detected
    match gas_unit_price.checked_mul(max_gas_amount) {
        Some(actual) => {
            // Normal validation proceeds
            println!("Calculated gas: {}", actual);
        },
        None => {
            // Overflow detected, reject transaction
            println!("PROTECTED: Overflow detected and rejected");
            panic!("Arithmetic overflow in gas calculation");
        }
    }
}
```

## Notes

While current gas parameters prevent exploitation, this represents a critical defensive programming failure in a consensus-critical code path. The explicit TODO comments in the governance update functions demonstrate that developers recognized the need for validation but have not implemented it. This creates a latent vulnerability that could be triggered through governance misconfiguration (accidental or otherwise) with severe consequences for network consensus and availability.

### Citations

**File:** aptos-move/aptos-vm/src/gas.rs (L126-138)
```rust
    if txn_metadata.max_gas_amount() > txn_gas_params.maximum_number_of_gas_units {
        speculative_warn!(
            log_context,
            format!(
                "[VM] Gas unit error; max {}, submitted {}",
                txn_gas_params.maximum_number_of_gas_units,
                txn_metadata.max_gas_amount()
            ),
        );
        return Err(VMStatus::error(
            StatusCode::MAX_GAS_UNITS_EXCEEDS_MAX_GAS_UNITS_BOUND,
            None,
        ));
```

**File:** aptos-move/aptos-vm/src/gas.rs (L195-208)
```rust
    if txn_metadata.gas_unit_price() > txn_gas_params.max_price_per_gas_unit {
        speculative_warn!(
            log_context,
            format!(
                "[VM] Gas unit error; max {}, submitted {}",
                txn_gas_params.max_price_per_gas_unit,
                txn_metadata.gas_unit_price()
            ),
        );
        return Err(VMStatus::error(
            StatusCode::GAS_UNIT_PRICE_ABOVE_MAX_BOUND,
            None,
        ));
    }
```

**File:** aptos-move/aptos-vm/src/gas.rs (L233-233)
```rust
        let actual = gas_unit_price * max_gas_amount;
```

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L47-48)
```text
        // TODO(Gas): check if gas schedule is consistent
        let gas_schedule: GasScheduleV2 = from_bytes(gas_schedule_blob);
```

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L67-68)
```text
            // TODO(Gas): check if gas schedule is consistent
            *gas_schedule = new_gas_schedule;
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L50-53)
```rust
        // ~5 microseconds should equal one unit of computational gas. We bound the maximum
        // computational time of any given transaction at roughly 20 seconds. We want this number and
        // `MAX_PRICE_PER_GAS_UNIT` to always satisfy the inequality that
        // MAXIMUM_NUMBER_OF_GAS_UNITS * MAX_PRICE_PER_GAS_UNIT < min(u64::MAX, GasUnits<GasCarrier>::MAX)
```

**File:** crates/aptos-rosetta/src/types/objects.rs (L120-125)
```rust
    pub fn suggested_gas_fee(gas_unit_price: u64, max_gas_amount: u64) -> Amount {
        Amount {
            value: (gas_unit_price * max_gas_amount).to_string(),
            currency: native_coin(),
        }
    }
```

**File:** crates/aptos-rosetta/src/construction.rs (L343-350)
```rust
            if let Some(multiplied_price) = gas_price.checked_mul(gas_multiplier) {
                gas_price = multiplied_price.saturating_div(100)
            } else {
                return Err(ApiError::InvalidInput(Some(format!(
                    "Gas price multiplier {} causes overflow on the price",
                    gas_multiplier
                ))));
            }
```
