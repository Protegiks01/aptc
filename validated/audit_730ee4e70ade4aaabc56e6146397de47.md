# Audit Report

## Title
Missing Gas Price Bounds Validation in Governance Updates Allows Total Network Liveness Loss

## Summary
The Aptos Framework's `gas_schedule.move` module lacks critical validation to ensure `min_price_per_gas_unit ≤ max_price_per_gas_unit` when governance updates gas parameters. If an invalid gas schedule is applied where `min_price_per_gas_unit > max_price_per_gas_unit`, all transactions become invalid, causing complete network liveness loss requiring a hard fork to recover.

## Finding Description

The vulnerability exists in the gas schedule update mechanism within the Aptos Framework. The `set_for_next_epoch` and `set_for_next_epoch_check_hash` functions accept governance proposals to update gas parameters but fail to validate the consistency of gas price bounds.

**Missing Validation in Aptos:**

The current implementation only validates that the gas schedule blob is non-empty and that the feature version is monotonically increasing: [1](#0-0) 

Multiple TODO comments throughout the module acknowledge that consistency validation should be implemented but remains unimplemented: [2](#0-1) [3](#0-2) [4](#0-3) 

**Comparison to Diem Framework:**

In contrast, the legacy Diem framework (from which Aptos was derived) explicitly validates this constraint: [5](#0-4) 

**Enforcement Without Exemption:**

Once an invalid gas schedule is applied via `on_new_epoch`, the AptosVM enforces BOTH gas price bounds during transaction validation: [6](#0-5) 

Critically, the `is_approved_gov_script` flag does NOT bypass these gas price checks - it only exempts transaction size and execution limits: [7](#0-6) 

**Exploitation Path:**

1. A governance proposal is created with a `GasScheduleV2` where `min_price_per_gas_unit > max_price_per_gas_unit` (either through accidental misconfiguration or automated tooling bugs)
2. The proposal passes governance voting
3. Upon epoch transition, `on_new_epoch` applies the invalid gas schedule without validation: [8](#0-7) 
4. All subsequent transactions are rejected because no valid gas price exists:
   - If `gas_unit_price ≥ min_price_per_gas_unit`, rejected as `GAS_UNIT_PRICE_ABOVE_MAX_BOUND`
   - If `gas_unit_price ≤ max_price_per_gas_unit`, rejected as `GAS_UNIT_PRICE_BELOW_MIN_BOUND`
5. The network cannot process ANY transactions, including governance recovery transactions
6. The network is permanently halted until a hard fork manually corrects the on-chain gas schedule

This represents a **logic vulnerability** - a missing validation that allows an impossible state to be created in the protocol, even when not triggered by malicious actors.

## Impact Explanation

This vulnerability meets the **Critical Severity** criteria per the Aptos Bug Bounty program:

**Total Loss of Liveness/Network Availability (Critical Severity #4):**
Once the invalid gas schedule is applied, no transactions can be validated or executed. The transaction validation layer in `check_gas` will reject all incoming transactions during the prologue phase, regardless of the gas price submitted.

**Non-recoverable Network Partition (Critical Severity #3):**
Unlike temporary liveness issues that can be resolved through on-chain governance, this issue CANNOT be fixed through normal governance procedures because governance transactions themselves are subject to the same gas price validation and will be rejected. The only recovery mechanism is a coordinated hard fork where validators restart with manually corrected on-chain state.

This breaks the fundamental protocol invariant that the resource limit enforcement mechanism should always allow valid transactions to proceed with proper gas pricing.

## Likelihood Explanation

**Likelihood: Low to Medium**

While the report claims "Medium to High," a more realistic assessment is **Low to Medium** because:

**Factors Increasing Likelihood:**
- Accidental misconfiguration in governance proposals (typo swapping min/max values)
- Bugs in automated gas schedule generation tooling
- No client-side validation in proposal creation tools
- No on-chain validation to prevent submission
- Historical precedent: Diem developers explicitly added this validation, suggesting recognized risk

**Factors Decreasing Likelihood:**
- Governance proposals undergo community review and voting
- Multiple stakeholders would review parameters before voting
- The error would be obvious (min > max) during review
- Proposal generation tools would likely include basic sanity checks
- The parameters have default values that are correctly ordered

**Note on Threat Model:** This vulnerability can be triggered through accidental misconfiguration or tooling bugs, which do not constitute malicious behavior by governance participants. This represents a protocol defect (missing validation) rather than an attack on trusted actors.

## Recommendation

Add explicit validation in the `set_for_next_epoch` and `set_for_next_epoch_check_hash` functions to ensure gas price bounds consistency:

```move
public fun set_for_next_epoch(aptos_framework: &signer, gas_schedule_blob: vector<u8>) acquires GasScheduleV2 {
    system_addresses::assert_aptos_framework(aptos_framework);
    assert!(!vector::is_empty(&gas_schedule_blob), error::invalid_argument(EINVALID_GAS_SCHEDULE));
    let new_gas_schedule: GasScheduleV2 = from_bytes(gas_schedule_blob);
    
    // Add validation for gas price bounds consistency
    let entries = &new_gas_schedule.entries;
    let (min_price, max_price) = extract_gas_price_bounds(entries);
    assert!(
        min_price <= max_price,
        error::invalid_argument(EGAS_CONSTANT_INCONSISTENCY)
    );
    
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

Additionally:
1. Add a new error constant `EGAS_CONSTANT_INCONSISTENCY` to the module
2. Implement helper function to extract and validate gas price bounds from the entries vector
3. Apply the same validation in `set_for_next_epoch_check_hash`
4. Add validation for other gas constant consistency requirements (e.g., `min_transaction_gas_units <= maximum_number_of_gas_units`)

## Proof of Concept

A complete PoC would require:
1. Creating a test governance proposal with invalid gas parameters
2. Simulating the governance voting and approval process
3. Triggering epoch transition via `on_new_epoch`
4. Demonstrating that all subsequent transactions are rejected

Due to the complexity of simulating the full governance process in a test environment, the vulnerability is demonstrated through code analysis showing:
- The missing validation in governance update functions
- The unconditional enforcement of both bounds in transaction validation
- The mathematical impossibility of finding a valid gas price when min > max
- The lack of exemption for governance transactions in gas price checks

**Notes:**

This is a valid logic vulnerability representing a protocol defect (missing validation) that could lead to catastrophic network liveness failure. While the likelihood is lower than initially claimed due to governance review processes, the severity of the impact (requiring a hard fork to recover) and the precedent of Diem explicitly adding this validation justify treating this as a Critical severity finding. The vulnerability can be triggered through accidental misconfiguration or tooling bugs, which do not constitute malicious behavior by governance participants and thus do not violate the threat model's assumption of trusted governance actors.

### Citations

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

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L75-76)
```text
            // TODO(Gas): check if gas schedule is consistent
            move_to<GasScheduleV2>(aptos_framework, new_gas_schedule);
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

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L135-145)
```text
    public(friend) fun on_new_epoch(framework: &signer) acquires GasScheduleV2 {
        system_addresses::assert_aptos_framework(framework);
        if (config_buffer::does_exist<GasScheduleV2>()) {
            let new_gas_schedule = config_buffer::extract_v2<GasScheduleV2>();
            if (exists<GasScheduleV2>(@aptos_framework)) {
                *borrow_global_mut<GasScheduleV2>(@aptos_framework) = new_gas_schedule;
            } else {
                move_to(framework, new_gas_schedule);
            }
        }
    }
```

**File:** third_party/move/move-examples/diem-framework/move-packages/DPN/sources/DiemVMConfig.move (L154-161)
```text
        assert!(
            min_price_per_gas_unit <= max_price_per_gas_unit,
            errors::invalid_argument(EGAS_CONSTANT_INCONSISTENCY)
        );
        assert!(
            min_transaction_gas_units <= maximum_number_of_gas_units,
            errors::invalid_argument(EGAS_CONSTANT_INCONSISTENCY)
        );
```

**File:** aptos-move/aptos-vm/src/gas.rs (L83-108)
```rust
    if is_approved_gov_script {
        let max_txn_size_gov = if gas_feature_version >= RELEASE_V1_13 {
            gas_params.vm.txn.max_transaction_size_in_bytes_gov
        } else {
            MAXIMUM_APPROVED_TRANSACTION_SIZE_LEGACY.into()
        };

        if txn_metadata.transaction_size > max_txn_size_gov
            // Ensure that it is only the approved payload that exceeds the
            // maximum. The (unknown) user input should be restricted to the original
            // maximum transaction size.
            || txn_metadata.transaction_size
                > txn_metadata.script_size + txn_gas_params.max_transaction_size_in_bytes
        {
            speculative_warn!(
                log_context,
                format!(
                    "[VM] Governance transaction size too big {} payload size {}",
                    txn_metadata.transaction_size, txn_metadata.script_size,
                ),
            );
            return Err(VMStatus::error(
                StatusCode::EXCEEDED_MAX_TRANSACTION_SIZE,
                None,
            ));
        }
```

**File:** aptos-move/aptos-vm/src/gas.rs (L178-208)
```rust
    let below_min_bound = txn_metadata.gas_unit_price() < txn_gas_params.min_price_per_gas_unit;
    if below_min_bound {
        speculative_warn!(
            log_context,
            format!(
                "[VM] Gas unit error; min {}, submitted {}",
                txn_gas_params.min_price_per_gas_unit,
                txn_metadata.gas_unit_price()
            ),
        );
        return Err(VMStatus::error(
            StatusCode::GAS_UNIT_PRICE_BELOW_MIN_BOUND,
            None,
        ));
    }

    // The submitted gas price is greater than the maximum gas unit price set by the VM.
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
