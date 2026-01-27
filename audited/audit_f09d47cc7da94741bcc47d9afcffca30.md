# Audit Report

## Title
Missing Gas Schedule Validation Enables Chain Halt via Malformed Governance Proposals

## Summary
The gas schedule deserialization system lacks validation of parameter completeness, allowing malformed gas schedules with missing required parameters to be stored on-chain through governance. When validators attempt to load such schedules, parsing fails and causes VM_STARTUP_FAILURE for all transactions, resulting in permanent chain halt.

## Finding Description

The gas schedule loading pipeline consists of two validation stages:

**Move-side validation** (when storing): [1](#0-0) 

The Move code performs minimal validation - only checking BCS structure validity and version monotonicity, with explicit TODO comments acknowledging missing consistency checks.

**Rust-side validation** (when loading): [2](#0-1) 

The Rust macro-generated code requires ALL gas parameters to exist in the map, returning an error if any are missing. When this error occurs during VM initialization: [3](#0-2) 

And when transactions attempt execution: [4](#0-3) 

The VM returns `VM_STARTUP_FAILURE`, blocking all transaction execution indefinitely.

**Attack Scenario:**
1. Attacker crafts `GasScheduleV2` with incomplete parameter entries (e.g., omitting critical parameters like `misc.abs_val.u64`)
2. Proposal passes governance vote (requires >50% stake approval)
3. Move code accepts the schedule (valid BCS structure)
4. At epoch boundary, validators activate the new schedule
5. Rust deserialization fails when loading: missing parameters trigger error return
6. All transactions fail with `VM_STARTUP_FAILURE`
7. Chain becomes permanently unusable until hard fork

**Additional Issue - Duplicate Keys:** [5](#0-4) 

The TODO comment highlights another validation gap: duplicate keys are silently accepted with last-value-wins semantics, though this doesn't cause chain halt.

## Impact Explanation

This vulnerability enables **Total loss of liveness/network availability** (Critical severity category per bug bounty). Once a malformed gas schedule activates:

- All validators enter VM_STARTUP_FAILURE state simultaneously
- No transactions can execute (including governance fixes)
- Recovery requires hard fork or manual state intervention
- Violates the **Move VM Safety** invariant (bytecode execution must respect gas limits) and **Resource Limits** invariant

The impact is deterministic and affects all network participants equally, constituting a non-recoverable network partition.

## Likelihood Explanation

**Likelihood: Medium-High**

While requiring governance approval (>50% voting power) provides a barrier, this is the *intended* mechanism for gas schedule updates. Likelihood factors:

**Increasing factors:**
- No automated validation in proposal generation tooling: [6](#0-5) 
- Multiple TODO comments indicate known validation gaps
- Governance participants may not manually verify completeness of 100+ gas parameters
- Complex versioning logic makes validation errors more likely

**Mitigating factors:**
- Requires governance approval
- Official tooling generates correct schedules by default: [7](#0-6) 

However, a single mistake in a legitimate upgrade or a compromised proposal could permanently halt the network.

## Recommendation

Implement comprehensive validation at the Move contract level before accepting gas schedules:

```rust
// In gas_schedule.move set_for_next_epoch function:
public fun set_for_next_epoch(aptos_framework: &signer, gas_schedule_blob: vector<u8>) acquires GasScheduleV2 {
    system_addresses::assert_aptos_framework(aptos_framework);
    assert!(!vector::is_empty(&gas_schedule_blob), error::invalid_argument(EINVALID_GAS_SCHEDULE));
    
    let new_gas_schedule: GasScheduleV2 = from_bytes(gas_schedule_blob);
    
    // NEW: Validate completeness and uniqueness
    validate_gas_schedule_completeness(&new_gas_schedule);
    validate_no_duplicate_keys(&new_gas_schedule);
    
    // ... rest of function
}

fun validate_gas_schedule_completeness(schedule: &GasScheduleV2) {
    // Define required parameter prefixes for each version
    let required_params = get_required_params(schedule.feature_version);
    // Check all required params exist
    // Abort with EINVALID_GAS_SCHEDULE if any missing
}

fun validate_no_duplicate_keys(schedule: &GasScheduleV2) {
    // Check for duplicate keys in entries vector
    // Abort with new error code EDUPLICATE_GAS_KEYS if found
}
```

Additionally, add validation to Rust proposal generation: [8](#0-7) 

```rust
// After line 124, add validation:
let gas_schedule_blob = bcs::to_bytes(new_gas_schedule).unwrap();
assert!(gas_schedule_blob.len() < 65536);

// NEW: Validate roundtrip works
let test_map = new_gas_schedule.clone().into_btree_map();
AptosGasParameters::from_on_chain_gas_schedule(&test_map, new_gas_schedule.feature_version)
    .expect("Generated gas schedule must be parseable");
```

## Proof of Concept

```rust
// Rust test demonstrating the vulnerability
#[test]
fn test_incomplete_gas_schedule_causes_vm_failure() {
    use aptos_types::on_chain_config::GasScheduleV2;
    use aptos_gas_schedule::{AptosGasParameters, FromOnChainGasSchedule};
    
    // Create gas schedule with missing required parameter
    let incomplete_schedule = GasScheduleV2 {
        feature_version: 12,
        entries: vec![
            ("misc.abs_val.u8".to_string(), 40),
            // Missing many required parameters like misc.abs_val.u64, etc.
        ],
    };
    
    // Move code would accept this (valid BCS)
    let bytes = bcs::to_bytes(&incomplete_schedule).unwrap();
    let deserialized: GasScheduleV2 = bcs::from_bytes(&bytes).unwrap();
    assert_eq!(deserialized.feature_version, 12);
    
    // But Rust parsing fails
    let map = deserialized.into_btree_map();
    let result = AptosGasParameters::from_on_chain_gas_schedule(&map, 12);
    
    // This returns Err, causing VM_STARTUP_FAILURE for all transactions
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("does not exist"));
}
```

## Notes

The TODO comments at lines 47, 67, and 75 in `gas_schedule.move` explicitly acknowledge this validation gap, indicating developers are aware but have not yet implemented the fix. The vulnerability is exacerbated by the gas schedule's complexity (100+ parameters across multiple versions) making manual validation impractical.

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

**File:** types/src/on_chain_config/gas_schedule.rs (L56-60)
```rust
impl GasScheduleV2 {
    pub fn into_btree_map(self) -> BTreeMap<String, u64> {
        // TODO: what if the gas schedule contains duplicated entries?
        self.entries.into_iter().collect()
    }
```

**File:** aptos-move/aptos-release-builder/src/components/gas.rs (L80-155)
```rust
pub fn generate_gas_upgrade_proposal(
    old_gas_schedule: Option<&GasScheduleV2>,
    new_gas_schedule: &GasScheduleV2,
    is_testnet: bool,
    next_execution_hash: Option<HashValue>,
    is_multi_step: bool,
) -> Result<Vec<(String, String)>> {
    let signer_arg = get_signer_arg(is_testnet, &next_execution_hash);
    let mut result = vec![];

    let writer = CodeWriter::new(Loc::default());

    emitln!(
        writer,
        "// Source commit hash: {}",
        aptos_build_info::get_git_hash()
    );
    emitln!(writer);

    emitln!(writer, "// Gas schedule upgrade proposal");

    let old_hash = match old_gas_schedule {
        Some(old_gas_schedule) => {
            let old_bytes = bcs::to_bytes(old_gas_schedule)?;
            let old_hash = hex::encode(Sha3_512::digest(old_bytes.as_slice()));
            emitln!(writer, "//");
            emitln!(writer, "// Old Gas Schedule Hash (Sha3-512): {}", old_hash);

            emit_gas_schedule_diff(&writer, old_gas_schedule, new_gas_schedule)?;

            Some(old_hash)
        },
        None => None,
    };
    emitln!(writer, "//");
    emit_full_gas_schedule(&writer, new_gas_schedule)?;

    let proposal = generate_governance_proposal(
        &writer,
        is_testnet,
        next_execution_hash,
        is_multi_step,
        &["aptos_framework::gas_schedule"],
        |writer| {
            let gas_schedule_blob = bcs::to_bytes(new_gas_schedule).unwrap();
            assert!(gas_schedule_blob.len() < 65536);

            emit!(writer, "let gas_schedule_blob: vector<u8> = ");
            generate_blob_as_hex_string(writer, &gas_schedule_blob);
            emitln!(writer, ";");
            emitln!(writer);

            match old_hash {
                Some(old_hash) => {
                    emitln!(
                        writer,
                        "gas_schedule::set_for_next_epoch_check_hash({}, x\"{}\", gas_schedule_blob);",
                        signer_arg,
                        old_hash,
                    );
                },
                None => {
                    emitln!(
                        writer,
                        "gas_schedule::set_for_next_epoch({}, gas_schedule_blob);",
                        signer_arg
                    );
                },
            }
            emitln!(writer, "aptos_governance::reconfigure({});", signer_arg);
        },
    );

    result.push(("gas-schedule".to_string(), proposal));
    Ok(result)
}
```

**File:** aptos-move/aptos-gas-schedule-updator/src/lib.rs (L116-121)
```rust
pub fn current_gas_schedule(feature_version: u64) -> GasScheduleV2 {
    GasScheduleV2 {
        feature_version,
        entries: AptosGasParameters::initial().to_on_chain_gas_schedule(feature_version),
    }
}
```
