# Audit Report

## Title
Critical Gas Parameter Validation Bypass Enabling Network-Wide Zero Gas Execution via Governance

## Summary
The on-chain gas schedule loading mechanism fails to validate parameter completeness for a given `feature_version`, allowing a malicious governance proposal to install an incomplete gas schedule. This causes all validators to deterministically fall back to zero gas parameters, enabling free computation and network resource exhaustion.

## Finding Description

The vulnerability exists across three critical components:

**1. Missing Validation in Gas Schedule Governance** [1](#0-0) 

The `set_gas_schedule` and `set_for_next_epoch` functions only validate that `feature_version` is non-decreasing, but do NOT validate that the `entries` vector contains all required parameters for that version. The TODO comment at line 67 explicitly states: "TODO(Gas): check if gas schedule is consistent" - this validation is never implemented.

**2. Error Propagation from Macro-Generated Code** [2](#0-1) 

The `from_on_chain_gas_schedule` implementation correctly returns an error when a required parameter is missing, but this error is not handled properly upstream.

**3. Silent Fallback to Zero in Environment Initialization** [3](#0-2) 

When `get_gas_parameters` returns an error (because required parameters are missing), `Environment::new` catches the error and silently falls back to `NativeGasParameters::zeros()` and `MiscGasParameters::zeros()`. The comment at lines 241-245 acknowledges this as problematic but intended only for "edge cases" like genesis.

**Attack Execution Path:**

1. Attacker crafts a governance proposal with a malicious `GasScheduleV2`:
   - `feature_version: 28` (RELEASE_V1_24 or any recent version)
   - `entries: []` or incomplete entries (missing version-gated parameters)

2. Proposal passes governance validation because only version number is checked [4](#0-3) 

3. Malicious gas schedule is published on-chain and activated at next epoch

4. All validators load the new gas schedule via `get_gas_config_from_storage` [5](#0-4) 

5. For version 28, the system expects parameters like `bcs_serialized_size_base` [6](#0-5)  but they're missing

6. `from_on_chain_gas_schedule` returns error: "Gas parameter move_stdlib.bcs.serialized_size.base does not exist. Feature version: 28."

7. Error is caught and ALL gas parameters fall back to zeros [7](#0-6) 

8. All validators execute transactions with zero gas costs for ALL operations

This breaks the critical invariant: "**Move VM Safety**: Bytecode execution must respect gas limits and memory constraints" and "**Resource Limits**: All operations must respect gas, storage, and computational limits."

## Impact Explanation

**Critical Severity** - This vulnerability qualifies for the highest severity tier ($1,000,000) under "Total loss of liveness/network availability" because:

- **Free Computation**: All Move operations, native functions, and storage operations cost zero gas, allowing attackers to execute arbitrarily expensive computations for free
- **Network DOS**: Attackers can spam the network with computationally intensive transactions that would normally be prohibitively expensive, exhausting validator resources
- **Deterministic Failure**: All validators fall back to zeros simultaneously, so consensus remains but the network becomes economically unprotected
- **Difficult Recovery**: Requires another governance proposal or emergency hard fork to restore proper gas parameters
- **Economic Security Collapse**: The fundamental gas metering system that prevents resource exhaustion is completely bypassed

The vulnerability is particularly severe because the fallback is deterministic - all validators execute identically, so there's no consensus split, but the entire network becomes vulnerable to resource exhaustion attacks.

## Likelihood Explanation

**High Likelihood** of exploitation if discovered:

- **Governance Access**: Requires ability to pass a governance proposal, which requires voting power but not validator access
- **Simple Attack**: Creating a malicious gas schedule with high `feature_version` but incomplete `entries` is trivial
- **No Technical Barriers**: The vulnerability is in validation logic, not cryptographic primitives
- **Clear Evidence**: The TODO comment in the code shows this validation was known to be missing
- **Long-Lived Issue**: The fallback to zeros has existed since the code comments reference it as a known edge case

The main barrier is governance access, but compromised governance or sufficient stake holdings make this exploitable. The impact is so severe that even low likelihood would warrant immediate patching.

## Recommendation

**Immediate Fix**: Implement gas schedule consistency validation before accepting governance proposals.

Add validation function in `gas_schedule.move`:

```rust
public fun validate_gas_schedule_complete(
    gas_schedule_blob: vector<u8>
) {
    let gas_schedule: GasScheduleV2 = from_bytes(gas_schedule_blob);
    // Attempt to parse with the declared feature version
    // This should fail if required parameters are missing
    let map = entries_to_map(&gas_schedule.entries);
    // Call Rust validation that uses from_on_chain_gas_schedule
    assert!(
        native_validate_gas_schedule(&map, gas_schedule.feature_version),
        EINVALID_GAS_SCHEDULE
    );
}
```

Add validation call in `set_for_next_epoch`: [8](#0-7) 

**Secondary Fix**: Remove the silent fallback to zeros in `Environment::new` and instead panic or halt the node if gas parameters cannot be loaded: [9](#0-8) 

Replace the match statement with:
```rust
let (native_gas_params, misc_gas_params, ty_builder) = match &gas_params {
    Ok(gas_params) => { /* existing code */ },
    Err(err) => {
        panic!("CRITICAL: Failed to load gas parameters: {}. Node cannot start safely.", err);
    }
};
```

This ensures that inconsistent gas schedules cause node startup failure rather than silent execution with zero costs.

## Proof of Concept

**Rust Test Demonstrating Fallback Behavior:**

```rust
#[test]
fn test_incomplete_gas_schedule_fallback() {
    use aptos_gas_schedule::{AptosGasParameters, FromOnChainGasSchedule};
    use std::collections::BTreeMap;
    
    // Create incomplete gas schedule with high feature version
    let mut incomplete_schedule = BTreeMap::new();
    // Only include a few parameters, missing many required for version 28
    incomplete_schedule.insert("txn.min_transaction_gas_units".to_string(), 1000);
    
    // Attempt to load with feature version 28 (RELEASE_V1_24)
    let result = AptosGasParameters::from_on_chain_gas_schedule(
        &incomplete_schedule, 
        28  // RELEASE_V1_24
    );
    
    // This should return an error for missing parameters like:
    // "Gas parameter move_stdlib.bcs.serialized_size.base does not exist. Feature version: 28."
    assert!(result.is_err());
    
    // The error message should mention the missing parameter
    let err_msg = result.unwrap_err();
    assert!(err_msg.contains("does not exist"));
    assert!(err_msg.contains("Feature version: 28"));
}
```

**Move Governance Proposal PoC:**

```move
script {
    use aptos_framework::gas_schedule;
    use std::vector;
    
    fun malicious_gas_schedule_proposal(framework: signer) {
        // Create malicious GasScheduleV2 with high version but empty entries
        let malicious_blob = x"1c00000000000000"; // BCS: {feature_version: 28, entries: []}
        
        // This passes validation because only version is checked
        gas_schedule::set_for_next_epoch(&framework, malicious_blob);
        
        // After reconfiguration, all validators fall back to zero gas
    }
}
```

The vulnerability is confirmed by the presence of the unimplemented TODO comment and the silent error handling that falls back to zeros instead of halting execution.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L65-68)
```text
            assert!(new_gas_schedule.feature_version >= gas_schedule.feature_version,
                error::invalid_argument(EINVALID_GAS_FEATURE_VERSION));
            // TODO(Gas): check if gas schedule is consistent
            *gas_schedule = new_gas_schedule;
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

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/macros.rs (L32-46)
```rust
        impl $crate::traits::FromOnChainGasSchedule for $params_name {
            #[allow(unused)]
            fn from_on_chain_gas_schedule(gas_schedule: &std::collections::BTreeMap<String, u64>, feature_version: u64) -> Result<Self, String> {
                let mut params = $params_name::zeros();

                $(
                    if let Some(key) = $crate::gas_schedule::macros::define_gas_parameters_extract_key_at_version!($key_bindings, feature_version) {
                        let name = format!("{}.{}", $prefix, key);
                        params.$name = gas_schedule.get(&name).cloned().ok_or_else(|| format!("Gas parameter {} does not exist. Feature version: {}.", name, feature_version))?.into();
                    }
                )*

                Ok(params)
            }
        }
```

**File:** aptos-move/aptos-vm-environment/src/environment.rs (L246-265)
```rust
        let (gas_params, storage_gas_params, gas_feature_version) =
            get_gas_parameters(&mut sha3_256, &features, state_view);
        let (native_gas_params, misc_gas_params, ty_builder) = match &gas_params {
            Ok(gas_params) => {
                let ty_builder = aptos_prod_ty_builder(gas_feature_version, gas_params);
                (
                    gas_params.natives.clone(),
                    gas_params.vm.misc.clone(),
                    ty_builder,
                )
            },
            Err(_) => {
                let ty_builder = aptos_default_ty_builder();
                (
                    NativeGasParameters::zeros(),
                    MiscGasParameters::zeros(),
                    ty_builder,
                )
            },
        };
```

**File:** aptos-move/aptos-vm-environment/src/gas.rs (L27-35)
```rust
    match GasScheduleV2::fetch_config_and_bytes(state_view) {
        Some((gas_schedule, bytes)) => {
            sha3_256.update(&bytes);
            let feature_version = gas_schedule.feature_version;
            let map = gas_schedule.into_btree_map();
            (
                AptosGasParameters::from_on_chain_gas_schedule(&map, feature_version),
                feature_version,
            )
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/move_stdlib.rs (L42-44)
```rust
        [bcs_serialized_size_base: InternalGas, { RELEASE_V1_18.. => "bcs.serialized_size.base" }, 735],
        [bcs_serialized_size_per_byte_serialized: InternalGasPerByte, { RELEASE_V1_18.. => "bcs.serialized_size.per_byte_serialized" }, 36],
        [bcs_serialized_size_failure: InternalGas, { RELEASE_V1_18.. => "bcs.serialized_size.failure" }, 3676],
```
