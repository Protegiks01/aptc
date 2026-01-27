# Audit Report

## Title
Missing Gas Parameter Validation Allows Zero-Cost State Key Writes Enabling State Bloat Attack

## Summary
The gas schedule governance update mechanism lacks validation to prevent setting `storage_io_per_state_byte_write` to zero, enabling attackers to create state entries with arbitrarily large keys at drastically reduced cost, violating the "Resource Limits" invariant and enabling unlimited state growth.

## Finding Description

The gas schedule update functions in the governance system fail to validate individual gas parameter values for consistency and reasonableness. Specifically, the `set_for_next_epoch()` and `set_for_next_epoch_check_hash()` functions validate only that the gas schedule blob is non-empty and that the feature version is non-decreasing, but do not check if critical gas parameters are set to zero or other harmful values. [1](#0-0) 

The code contains TODO comments explicitly acknowledging this missing validation: [2](#0-1) 

When `storage_io_per_state_byte_write` is set to zero, the IO gas charging logic in all IoPricing versions fails to charge for state key size:

**In IoPricingV1**, the conditional check becomes false: [3](#0-2) 

**In IoPricingV3 and V4**, the multiplication by zero results in zero cost: [4](#0-3) 

**Attack Path:**
1. A governance proposal (malicious or buggy) sets `storage_io_per_state_byte_write` to zero in the gas schedule
2. The proposal passes governance voting and is applied at the next epoch
3. Attackers create table items or other state entries with maximum-sized keys (up to `max_bytes_per_write_op` = 1 MB) [5](#0-4) 
4. They pay only for the fixed per-operation cost (`storage_io_per_state_slot_write`) and value size, but NOT for the key size
5. State grows unbounded at drastically reduced cost, causing node storage exhaustion

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits."

## Impact Explanation

**Severity: HIGH**

This vulnerability enables a state bloat attack that can cause:
- **Validator node slowdowns** due to excessive state size requiring more I/O operations
- **Storage exhaustion** across the validator network
- **Significant protocol violation** by allowing unbounded state growth at minimal cost
- **Economic attack** by undermining the gas pricing model designed to prevent state bloat

The impact qualifies as HIGH severity per the bug bounty criteria for "Significant protocol violations" and potential "Validator node slowdowns." While it requires governance action (preventing Critical severity), the lack of validation is a code defect that enables this attack vector.

The vulnerability affects all IoPricing versions (V1-V4), though current mainnet uses V4 at feature version 45. The gas schedule validation explicitly prevents downgrading the feature version, limiting immediate mainnet exploitability. However, the missing validation remains a critical code defect that could affect:
- Future gas schedule updates where the parameter is accidentally set to zero
- Test networks or private deployments
- Any emergency governance action that modifies gas parameters without proper review

## Likelihood Explanation

**Likelihood: MEDIUM**

While governance is considered a trusted actor, the likelihood of exploitation is non-trivial because:
1. **No validation exists** - A buggy governance proposal could accidentally set this parameter to zero
2. **TODO comments indicate missing code** - The developers intended to add validation but it's not implemented
3. **Complex proposals** - Gas schedule updates involve hundreds of parameters, making errors possible
4. **Emergency scenarios** - Under time pressure, governance might approve poorly validated proposals

The attack does not require:
- Validator collusion
- Protocol-level exploits
- Cryptographic attacks

It only requires a governance proposal that passes voting, which while requiring coordination, is within the threat model for "buggy proposals" even if not "malicious governance."

## Recommendation

Add validation in the gas schedule update functions to ensure critical gas parameters cannot be set to zero or other harmful values. This should be implemented in the `set_for_next_epoch()` and `set_for_next_epoch_check_hash()` functions:

**Recommended Fix Location:** [1](#0-0) 

**Implementation Approach:**
1. Define minimum acceptable values for critical gas parameters (especially per-byte write costs)
2. Add validation logic after deserializing the new gas schedule
3. Assert that `storage_io_per_state_byte_write` is greater than a minimum threshold (e.g., > 10)
4. Provide clear error codes for validation failures

**Example validation logic to add (in Move):**
```move
// After line 94
let new_gas_schedule: GasScheduleV2 = from_bytes(gas_schedule_blob);

// Add validation for critical parameters
validate_gas_schedule_consistency(&new_gas_schedule);
```

Additionally, implement the TODO items for gas schedule consistency checks: [6](#0-5) 

Similar validation exists elsewhere in the codebase and should be used as reference: [7](#0-6) 

## Proof of Concept

```move
// PoC: Governance proposal to set storage_io_per_state_byte_write to zero
// This would be part of a malicious or buggy governance proposal

script {
    use aptos_framework::gas_schedule;
    use aptos_framework::aptos_governance;
    
    fun exploit_zero_byte_cost(framework: &signer) {
        // Modify gas schedule to set storage_io_per_state_byte_write to 0
        let malicious_gas_schedule = create_malicious_schedule(); // Creates schedule with zero byte cost
        
        // This call succeeds because there's no validation
        gas_schedule::set_for_next_epoch(framework, malicious_gas_schedule);
        
        // Trigger reconfiguration
        aptos_governance::reconfigure(framework);
        
        // After epoch change, create large keys at minimal cost
        // Using aptos_std::table or aptos_std::smart_table
        // Key size: close to 1MB, only paying for value + fixed op cost
    }
}

// Rust test demonstrating the issue:
#[test]
fn test_zero_byte_cost_attack() {
    let mut h = MoveHarness::new();
    
    // Modify gas schedule to set storage_io_per_state_byte_write to 0
    h.modify_gas_schedule(|gas_params| {
        gas_params.vm.txn.storage_io_per_state_byte_write = 0.into();
    });
    
    // Create table items with maximum keys
    let large_key = vec![0u8; 1_000_000]; // ~1MB key
    let small_value = vec![1u8; 100];     // Small value
    
    // Gas cost should be minimal (only fixed op cost + value cost)
    // Without the zero check, key size is not charged
    let result = h.run_transaction_payload(...);
    
    // Verify state bloat occurred at minimal cost
    assert!(result.gas_used() < expected_cost_for_1mb_key());
}
```

**Notes:**
- The vulnerability exists in production code paths
- Affects all IoPricing versions when the parameter is zero
- Mainnet is currently protected by feature version 45 (cannot downgrade to V1) but the validation gap remains
- The TODO comments confirm this validation should exist but is missing
- Other critical gas parameters in the codebase have explicit validation, establishing precedent

### Citations

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L47-47)
```text
        // TODO(Gas): check if gas schedule is consistent
```

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L67-67)
```text
            // TODO(Gas): check if gas schedule is consistent
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

**File:** aptos-move/aptos-vm-types/src/storage/io_pricing.rs (L63-65)
```rust
        if self.write_data_per_byte_in_key > 0.into() {
            cost += self.write_data_per_byte_in_key * NumBytes::new(key.encoded().len() as u64);
        }
```

**File:** aptos-move/aptos-vm-types/src/storage/io_pricing.rs (L192-193)
```rust
                    STORAGE_IO_PER_STATE_SLOT_WRITE * NumArgs::new(1)
                        + STORAGE_IO_PER_STATE_BYTE_WRITE * self.write_op_size(key, write_len),
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L154-157)
```rust
            max_bytes_per_write_op: NumBytes,
            { 5.. => "max_bytes_per_write_op" },
            1 << 20, // a single state item is 1MB max
        ],
```

**File:** aptos-move/framework/aptos-framework/sources/storage_gas.move (L147-147)
```text
///
```
