# Audit Report

## Title
Critical Network Halt via Malformed Gas Schedule Update - Missing Parameter Validation Allows Total Liveness Failure

## Summary
The on-chain gas schedule update mechanism lacks validation to ensure all required gas parameters for a given feature version are present. A malformed governance proposal can set a high feature version while omitting required parameters, causing all validators to fail gas parameter initialization with `VM_STARTUP_FAILURE`, resulting in permanent network halt requiring a hard fork.

## Finding Description

The vulnerability exists in the interaction between three components:

1. **Gas Schedule Update Validation** - The Move module `gas_schedule.move` that handles governance-driven gas schedule updates performs minimal validation: [1](#0-0) 

   The code contains TODO comments acknowledging missing validation: [2](#0-1) 

2. **Gas Parameter Loading** - The `from_on_chain_gas_schedule` macro expects all parameters defined for a feature version to exist in the on-chain map: [3](#0-2) 

   When a parameter is expected but missing, it returns an error instead of using a default value.

3. **Environment Initialization** - Every block execution creates a fresh environment from state, loading gas parameters: [4](#0-3) 

**Attack Scenario:**

1. Attacker creates a governance proposal with:
   - `feature_version: 26` (or any version ≥ current)
   - `entries: [...]` with critical parameters MISSING (e.g., "instr.add")

2. The proposal passes Move validation because only version ordering is checked, NOT parameter completeness

3. Proposal executes and stores the malformed schedule on-chain

4. At next block, ALL validators:
   - Create environment from state
   - Call `from_on_chain_gas_schedule()` 
   - Fail with error: "Gas parameter instr.add does not exist. Feature version: 26"
   - Store error in `gas_params: Result<AptosGasParameters, String>`

5. When ANY transaction attempts execution: [5](#0-4) 

   This converts the error to `VM_STARTUP_FAILURE`: [6](#0-5) 

6. ALL transactions get status `TransactionStatus::Discard(VM_STARTUP_FAILURE)`

7. Discarded transactions are excluded from state commitment: [7](#0-6) 

8. The network cannot process ANY transactions - permanent halt

The existing test confirms this behavior: [8](#0-7) 

## Impact Explanation

**Severity: CRITICAL** - This qualifies for maximum severity under multiple Aptos bug bounty categories:

1. **Total loss of liveness/network availability** - The entire network becomes unable to process any user transactions. All validators deterministically fail to initialize gas parameters, causing every transaction to be discarded.

2. **Non-recoverable network partition (requires hardfork)** - Recovery requires either:
   - A hard fork with corrected gas schedule
   - Emergency governance proposal (which cannot execute if transactions are discarded)
   - Manual validator intervention to override on-chain state

3. **Breaks Deterministic Execution Invariant** - While all validators fail identically (deterministic failure), this violates the system's availability guarantees that are implicit in the execution model.

The attack affects **all validators simultaneously** with **zero warning** and **no recovery mechanism** built into the protocol.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

The attack is realistic because:

1. **Simple to execute** - Requires only a governance proposal with malformed data
2. **No special privileges needed** - Any governance participant can propose updates
3. **Passes existing validation** - The Move validation logic explicitly does NOT check parameter completeness (see TODO comments)
4. **Accidental trigger possible** - Poor testing of gas schedule updates could accidentally trigger this
5. **No warning system** - Validators have no pre-deployment validation of gas schedules

The only mitigating factor is that governance proposals undergo community review, but technical validation is absent.

## Recommendation

**Immediate Fix:** Add comprehensive validation to `gas_schedule.move`:

```move
// In gas_schedule.move, replace TODO comments with actual validation:

use aptos_framework::gas_schedule_validation;  // New module

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
    
    // NEW: Validate parameter completeness
    gas_schedule_validation::validate_completeness(
        new_gas_schedule.feature_version,
        &new_gas_schedule.entries
    );
    
    config_buffer::upsert(new_gas_schedule);
}
```

**Rust-side validation:** Create a native function that:
1. Calls `from_on_chain_gas_schedule()` with the proposed schedule
2. Returns validation result before allowing the update
3. Provides clear error messages about missing parameters

**Defensive fallback:** Modify the macro to use default values for missing parameters with logging:

```rust
// In macros.rs:
if let Some(key) = define_gas_parameters_extract_key_at_version!($key_bindings, feature_version) {
    let name = format!("{}.{}", $prefix, key);
    params.$name = match gas_schedule.get(&name).cloned() {
        Some(val) => val.into(),
        None => {
            // Log critical error but don't halt the network
            error!("CRITICAL: Missing gas parameter {} for version {}. Using zero.", name, feature_version);
            0.into()
        }
    };
}
```

## Proof of Concept

The vulnerability is already demonstrated by the existing test: [9](#0-8) 

**To reproduce the network halt scenario:**

1. Create a governance proposal:
```move
// In a Move script/proposal:
let incomplete_schedule = GasScheduleV2 {
    feature_version: 26,  // High version
    entries: vector[
        // Intentionally omit critical parameters like "instr.add"
        GasEntry { key: string::utf8(b"instr.mul"), val: 1000 }
        // Missing many required parameters for version 26
    ]
};
let blob = bcs::to_bytes(&incomplete_schedule);
gas_schedule::set_for_next_epoch(&framework_signer, blob);
aptos_governance::reconfigure(&framework_signer);
```

2. Once applied, attempt ANY transaction:
```rust
// Any transaction will fail with VM_STARTUP_FAILURE
let result = executor.execute_transaction(txn);
assert!(matches!(result.status(), 
    TransactionStatus::Discard(StatusCode::VM_STARTUP_FAILURE)));
```

3. Network cannot process any transactions until hard fork recovery

## Notes

This vulnerability demonstrates a critical gap between the Move-level governance validation and the Rust-level execution requirements. The TODO comments in the code explicitly acknowledge this missing validation has never been implemented. The issue is particularly severe because it affects ALL validators simultaneously with no built-in recovery mechanism, requiring emergency hard fork intervention.

### Citations

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

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/macros.rs (L34-45)
```rust
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
```

**File:** aptos-move/block-executor/src/code_cache_global_manager.rs (L211-213)
```rust
        // Get the current environment from storage.
        let storage_environment =
            AptosEnvironment::new_with_delayed_field_optimization_enabled(&state_view);
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L273-282)
```rust
pub(crate) fn get_or_vm_startup_failure<'a, T>(
    gas_params: &'a Result<T, String>,
    log_context: &AdapterLogSchema,
) -> Result<&'a T, VMStatus> {
    gas_params.as_ref().map_err(|err| {
        let msg = format!("VM Startup Failed. {}", err);
        speculative_error!(log_context, msg.clone());
        VMStatus::error(StatusCode::VM_STARTUP_FAILURE, Some(msg))
    })
}
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L373-378)
```rust
    pub(crate) fn gas_params(
        &self,
        log_context: &AdapterLogSchema,
    ) -> Result<&AptosGasParameters, VMStatus> {
        get_or_vm_startup_failure(self.move_vm.env.gas_params(), log_context)
    }
```

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L487-497)
```rust
                TransactionStatus::Discard(_) => to_discard.push(
                    transactions[idx].clone(),
                    transaction_outputs[idx].clone(),
                    persisted_auxiliary_infos[idx],
                ),
            }
        }

        transactions.truncate(num_keep_txns);
        transaction_outputs.truncate(num_keep_txns);
        persisted_auxiliary_infos.truncate(num_keep_txns);
```

**File:** aptos-move/e2e-move-tests/src/tests/missing_gas_parameter.rs (L1-28)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

use crate::{tests::common, MoveHarness};
use aptos_types::{account_address::AccountAddress, transaction::TransactionStatus};
use move_core_types::vm_status::StatusCode;

#[test]
fn missing_gas_parameter() {
    let mut h = MoveHarness::new();

    h.modify_gas_schedule_raw(|gas_schedule| {
        let idx = gas_schedule
            .entries
            .iter()
            .position(|(key, _val)| key == "instr.add")
            .unwrap();
        gas_schedule.entries.remove(idx);
    });

    // Load the code
    let acc = h.new_account_with_balance_at(AccountAddress::from_hex_literal("0xbeef").unwrap(), 0);
    let txn_status = h.publish_package(&acc, &common::test_dir_path("common.data/do_nothing"));
    assert!(matches!(
        txn_status,
        TransactionStatus::Discard(StatusCode::VM_STARTUP_FAILURE)
    ))
}
```
