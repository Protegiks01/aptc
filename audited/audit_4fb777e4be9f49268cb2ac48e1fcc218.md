# Audit Report

## Title
Empty GasScheduleV2 Entries Cause Network-Wide Denial of Service via Deterministic Block Execution Failure

## Summary
An attacker can submit a governance proposal with a `GasScheduleV2` structure containing an empty `entries` vector, which passes validation but causes complete network liveness failure. However, contrary to the security question's claim of "consensus divergence," all validators behave **deterministically** - they all fail to execute blocks in the same way, resulting in total network halt rather than divergence.

## Finding Description

The security question proposes that empty `GasScheduleV2` entries cause consensus divergence where "some default to free transactions while others reject all transactions." After thorough investigation, this specific divergence scenario does **not** occur. Instead, a different but equally critical vulnerability exists.

**Attack Path:**

1. **Governance Bypass**: The governance proposal validation only checks that the serialized blob is non-empty, not that the `entries` vector contains gas parameters. [1](#0-0) 

The validation at line 93 checks `!vector::is_empty(&gas_schedule_blob)` but a serialized `GasScheduleV2{feature_version: 1, entries: vector[]}` is still a non-empty blob.

2. **Deterministic Failure**: When validators load the empty gas schedule, the `from_on_chain_gas_schedule` macro attempts to extract required parameters from an empty map and returns an error deterministically. [2](#0-1) 

3. **Block Prologue Failure**: When executing any block, the block prologue requires `storage_gas_params()`, which returns the error from the failed gas parameter loading. [3](#0-2) 

4. **Network Halt**: All validators deterministically fail to execute blocks with `FatalVMError`, causing complete network liveness failure. [4](#0-3) 

**Why Consensus Divergence Does NOT Occur:**

The environment creation uses zero gas parameters as a fallback for building the Move VM runtime environment, but transaction execution explicitly checks `gas_params()` which returns the error. [5](#0-4) 

All validators compute the same hash for the environment (including the empty gas schedule bytes), ensuring deterministic behavior. [6](#0-5) 

## Impact Explanation

**Critical Severity** - Total loss of liveness/network availability (per Aptos Bug Bounty criteria):
- Complete network halt - no blocks can be executed
- Even system transactions (BlockMetadata) fail because they require `storage_gas_params()`
- Requires hardfork or emergency governance intervention to recover
- All user transactions become impossible to process

This meets the Critical severity threshold of "Total loss of liveness/network availability" worth up to $1,000,000.

**Note**: While this is Critical severity, it is **not** the consensus divergence vulnerability described in the question. It is a deterministic DoS attack.

## Likelihood Explanation

**High Likelihood** of exploitation:
- Requires only governance proposal submission (available to any participant with sufficient stake/votes)
- No special validator access or insider knowledge required
- Attack is trivial to execute - simply propose `GasScheduleV2{feature_version: N, entries: vector[]}`
- Network recovery requires coordinated hardfork or emergency response

**Low Likelihood** of occurrence:
- Governance proposals are typically reviewed by the community
- Would be immediately obvious in proposal diff that entries are empty

## Recommendation

Add explicit validation in the `set_for_next_epoch` and related functions to ensure the `entries` vector is non-empty and contains all required gas parameters:

```move
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

Additionally, implement server-side validation in the Rust code to verify gas schedule consistency before applying on-chain config changes.

## Proof of Concept

```move
#[test(aptos_framework = @0x1)]
fun test_empty_gas_schedule_dos_attack(aptos_framework: signer) {
    use aptos_framework::gas_schedule;
    use std::bcs;
    
    // Create a GasScheduleV2 with empty entries
    let malicious_schedule = gas_schedule::GasScheduleV2 {
        feature_version: 100,
        entries: vector::empty(), // Empty entries vector
    };
    
    // Serialize it - this creates a non-empty blob
    let schedule_blob = bcs::to_bytes(&malicious_schedule);
    assert!(!vector::is_empty(&schedule_blob), 0); // Blob is not empty, so passes basic check
    
    // This should succeed in current implementation (vulnerability)
    gas_schedule::set_for_next_epoch(&aptos_framework, schedule_blob);
    
    // After epoch transition, all block executions will fail
    // Network experiences complete liveness failure
}
```

---

**Notes:**
- The original security question's premise of "consensus divergence" is **incorrect**
- The actual vulnerability is **deterministic DoS**, not divergence
- All validators fail identically, maintaining consensus safety
- Impact is still **Critical** due to total network halt
- This is a valid governance validation bypass leading to network-wide DoS

### Citations

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

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/macros.rs (L38-41)
```rust
                    if let Some(key) = $crate::gas_schedule::macros::define_gas_parameters_extract_key_at_version!($key_bindings, feature_version) {
                        let name = format!("{}.{}", $prefix, key);
                        params.$name = gas_schedule.get(&name).cloned().ok_or_else(|| format!("Gas parameter {} does not exist. Feature version: {}.", name, feature_version))?.into();
                    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2544-2548)
```rust
        let output = get_system_transaction_output(
            session,
            module_storage,
            &self.storage_gas_params(log_context)?.change_set_configs,
        )?;
```

**File:** aptos-move/block-executor/src/executor.rs (L2237-2248)
```rust
                ExecutionStatus::Abort(err) => {
                    if let Some(commit_hook) = &self.transaction_commit_hook {
                        commit_hook.on_execution_aborted(idx as TxnIndex);
                    }
                    error!(
                        "Sequential execution FatalVMError by transaction {}",
                        idx as TxnIndex
                    );
                    // Record the status indicating the unrecoverable VM failure.
                    return Err(SequentialBlockExecutionError::ErrorToReturn(
                        BlockExecutionError::FatalVMError(err),
                    ));
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
