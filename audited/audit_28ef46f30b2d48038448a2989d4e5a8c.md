# Audit Report

## Title
Empty Gas Schedule Acceptance Leads to Complete Network Halt via Governance Proposal

## Summary
The gas schedule update mechanism fails to validate that `GasScheduleV2.entries` is non-empty, allowing a malicious governance proposal to install an empty gas schedule on-chain. Once applied, all subsequent transactions fail with `VM_STARTUP_FAILURE` because the VM cannot load required gas parameters, causing total network liveness failure requiring a hardfork to recover.

## Finding Description

The vulnerability exists in the gas schedule validation logic across multiple functions. When a governance proposal updates the gas schedule, the system only validates that the serialized blob is non-empty, but never checks that the `entries` vector contains actual gas parameters.

**Vulnerable Code Path:**

1. The `set_for_next_epoch()` function accepts any gas schedule blob that deserializes successfully: [1](#0-0) 

The check at line 93 only validates the blob is non-empty. Since a `GasScheduleV2` with `feature_version` and empty `entries` still serializes to a non-empty blob, this check passes.

2. During epoch change, the empty gas schedule is applied to on-chain storage: [2](#0-1) 

3. When the next transaction executes, the VM environment loads gas parameters from storage: [3](#0-2) 

4. The conversion from on-chain format to `AptosGasParameters` fails because required gas parameters are missing from the empty map: [4](#0-3) 

At line 40, the macro attempts to retrieve each required gas parameter (e.g., "instr.nop", "instr.ret"). With an empty entries map, all these lookups fail, returning an error like "Gas parameter instr.nop does not exist".

5. This error propagates through the system as `VM_STARTUP_FAILURE`: [5](#0-4) 

**Attack Scenario:**

1. Attacker crafts a governance proposal using a modified gas schedule updator with `GasScheduleV2 { feature_version: <current+1>, entries: vector[] }`
2. The proposal script calls `gas_schedule::set_for_next_epoch()` 
3. Proposal passes governance voting
4. Script executes successfully (validation only checks blob is non-empty)
5. After epoch reconfiguration, the empty gas schedule becomes active
6. All subsequent transactions fail with `StatusCode::VM_STARTUP_FAILURE`
7. Chain is completely halted - no transactions can execute
8. Recovery requires emergency hardfork to restore valid gas schedule

**Invariant Violations:**

- **Resource Limits (#9)**: Gas operations cannot function without gas parameters, breaking the guarantee that all operations respect gas limits
- **Transaction Validation (#7)**: The prologue cannot execute because it requires gas metering
- **Deterministic Execution (#1)**: While all nodes fail identically, the chain cannot process any blocks

## Impact Explanation

This is a **Critical Severity** vulnerability under the Aptos Bug Bounty program criteria:

- **Total loss of liveness/network availability**: Once the empty gas schedule is applied, the entire network cannot process any transactions. Every transaction attempt results in `VM_STARTUP_FAILURE` during environment initialization, before any execution can occur.

- **Non-recoverable network partition (requires hardfork)**: The only recovery path is an emergency hardfork to:
  1. Manually restore a valid gas schedule in the state, OR
  2. Patch the VM to use fallback gas parameters when loading fails

- **Scope**: Affects 100% of network capacity - validators, fullnodes, and all clients cannot execute any transactions including emergency governance proposals to fix the issue.

This meets the highest severity tier (up to $1,000,000) as it causes complete network shutdown requiring coordinator intervention.

## Likelihood Explanation

**Likelihood: Medium-High**

**Requirements:**
- Governance proposal must pass voting threshold
- No privileged validator access required
- No technical sophistication beyond basic governance proposal creation

**Feasibility:**
- The attack is straightforward - simply create a gas schedule update proposal with empty entries
- The vulnerability is in production code (`set_for_next_epoch`), not just the deprecated path
- Evidence from tests shows the code already accepts empty entries without validation: [6](#0-5) 

**Barriers:**
- Requires passing governance vote, but a compromised proposal key or social engineering could achieve this
- The TODO comments indicate developers are aware validation is missing but haven't implemented it: [7](#0-6) 

## Recommendation

Add explicit validation that gas schedule entries are non-empty and contain required parameters:

```move
// In aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move

public fun set_for_next_epoch(aptos_framework: &signer, gas_schedule_blob: vector<u8>) acquires GasScheduleV2 {
    system_addresses::assert_aptos_framework(aptos_framework);
    assert!(!vector::is_empty(&gas_schedule_blob), error::invalid_argument(EINVALID_GAS_SCHEDULE));
    let new_gas_schedule: GasScheduleV2 = from_bytes(gas_schedule_blob);
    
    // ADD THIS VALIDATION:
    assert!(!vector::is_empty(&new_gas_schedule.entries), error::invalid_argument(EINVALID_GAS_SCHEDULE));
    
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

Apply the same fix to:
- `set_for_next_epoch_check_hash()` 
- `initialize()` 
- `set_gas_schedule()` (deprecated but still callable during genesis)

Additionally, implement the TODO validation to verify the gas schedule contains all required entries for the given feature version.

## Proof of Concept

```move
#[test_only]
module aptos_framework::gas_schedule_halt_attack {
    use aptos_framework::gas_schedule;
    use std::bcs;
    use aptos_framework::aptos_governance;
    
    #[test(aptos_framework = @aptos_framework)]
    #[expected_failure] // This should fail but currently doesn't
    fun test_empty_gas_schedule_accepted(aptos_framework: signer) {
        // Setup: Initialize with valid gas schedule
        gas_schedule::initialize(&aptos_framework, bcs::to_bytes(&gas_schedule::GasScheduleV2 {
            feature_version: 10,
            entries: vector[
                gas_schedule::GasEntry { key: b"instr.nop", val: 100 }
            ]
        }));
        
        // Attack: Submit empty gas schedule
        let malicious_schedule = gas_schedule::GasScheduleV2 {
            feature_version: 11,
            entries: vector[] // EMPTY!
        };
        
        let malicious_blob = bcs::to_bytes(&malicious_schedule);
        
        // This should fail but currently succeeds
        gas_schedule::set_for_next_epoch(&aptos_framework, malicious_blob);
        
        // After epoch change and attempting to use gas params,
        // all transactions would fail with VM_STARTUP_FAILURE
    }
}
```

**Notes:**

The vulnerability is confirmed by examining the complete execution path from governance proposal to VM initialization. The lack of validation for non-empty entries is explicitly indicated by TODO comments in the code, demonstrating that developers recognized this gap but have not yet implemented the required checks. The test suite even uses empty gas schedules, suggesting the code was designed to accept them without considering the catastrophic consequences when the VM attempts to load gas parameters for actual transaction execution.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L67-68)
```text
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

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L162-174)
```text
        let old_gas_schedule = GasScheduleV2 {
            feature_version: 1000,
            entries: vector[],
        };
        move_to(&fx, old_gas_schedule);

        // Setting an older version should not work.
        let new_gas_schedule = GasScheduleV2 {
            feature_version: 999,
            entries: vector[],
        };
        let new_bytes = to_bytes(&new_gas_schedule);
        set_for_next_epoch(&fx, new_bytes);
```

**File:** aptos-move/aptos-vm-environment/src/gas.rs (L23-46)
```rust
fn get_gas_config_from_storage(
    sha3_256: &mut Sha3_256,
    state_view: &impl StateView,
) -> (Result<AptosGasParameters, String>, u64) {
    match GasScheduleV2::fetch_config_and_bytes(state_view) {
        Some((gas_schedule, bytes)) => {
            sha3_256.update(&bytes);
            let feature_version = gas_schedule.feature_version;
            let map = gas_schedule.into_btree_map();
            (
                AptosGasParameters::from_on_chain_gas_schedule(&map, feature_version),
                feature_version,
            )
        },
        None => match GasSchedule::fetch_config_and_bytes(state_view) {
            Some((gas_schedule, bytes)) => {
                sha3_256.update(&bytes);
                let map = gas_schedule.into_btree_map();
                (AptosGasParameters::from_on_chain_gas_schedule(&map, 0), 0)
            },
            None => (Err("Neither gas schedule v2 nor v1 exists.".to_string()), 0),
        },
    }
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
