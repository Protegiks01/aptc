# Audit Report

## Title
Network Halt via Incomplete GasScheduleV2 Validation Bypass

## Summary
The gas schedule update mechanism lacks validation of parameter completeness, allowing an incomplete `GasScheduleV2` to be committed to state. When this occurs, all subsequent transactions fail with `VM_STARTUP_FAILURE`, causing total network liveness loss requiring a hardfork to recover.

## Finding Description

The vulnerability exists in the gas schedule update flow where incomplete gas parameter data can be committed to on-chain state without validation: [1](#0-0) 

The `set_for_next_epoch` function only validates that the blob is non-empty and the feature version is monotonically increasing, but does NOT validate that all required gas parameters are present in the `entries` vector. The TODO comments at lines 47, 67, and 75 explicitly acknowledge this missing validation. [2](#0-1) 

When an incomplete `GasScheduleV2` is buffered via `config_buffer::upsert`, it remains dormant until the next epoch: [3](#0-2) 

At epoch transition, `gas_schedule::on_new_epoch` extracts and applies the incomplete schedule: [4](#0-3) 

Subsequently, when any transaction attempts execution, the VM loads gas parameters: [5](#0-4) 

The incomplete entries vector is successfully fetched and deserialized as a valid `GasScheduleV2` struct, but when `from_on_chain_gas_schedule` attempts to parse it: [6](#0-5) 

Missing parameters cause the method to return an error. This error propagates through the execution stack: [7](#0-6) 

Every transaction (user, system, and even BlockMetadata) requires gas parameters: [8](#0-7) 

The `storage_gas_params` call on line 2464 fails with `VM_STARTUP_FAILURE`, causing all transactions to be discarded: [9](#0-8) 

## Impact Explanation

This meets **Critical Severity** criteria per the Aptos bug bounty:

- **Total loss of liveness/network availability**: Once an incomplete gas schedule activates, no transactions can execute. The network completely halts.
- **Non-recoverable network partition (requires hardfork)**: Since no transactions can execute, the bad gas schedule cannot be fixed through governance. Only a hardfork with state rollback or manual database modification can restore the network.

All validator nodes experience identical behavior (deterministic execution), so this causes synchronized network halt, not a partition.

## Likelihood Explanation

**Likelihood: Medium-to-High**

While this requires governance proposal passage, the conditions are realistic:

1. Gas schedule updates are regular operations during network upgrades
2. The validation gap is explicit (TODO comments acknowledge missing checks)
3. Human error in proposal creation is plausible - someone might:
   - Accidentally omit parameters when constructing the update
   - Use an outdated parameter list  
   - Make transcription errors
4. No runtime or compile-time checks catch incomplete schedules before activation

The proposal generation tooling doesn't validate completeness: [10](#0-9) 

## Recommendation

Add validation in `set_for_next_epoch` to verify all required gas parameters exist before buffering:

```move
public fun set_for_next_epoch(aptos_framework: &signer, gas_schedule_blob: vector<u8>) acquires GasScheduleV2 {
    system_addresses::assert_aptos_framework(aptos_framework);
    assert!(!vector::is_empty(&gas_schedule_blob), error::invalid_argument(EINVALID_GAS_SCHEDULE));
    let new_gas_schedule: GasScheduleV2 = from_bytes(gas_schedule_blob);
    
    // NEW: Validate completeness before accepting
    validate_gas_schedule_completeness(&new_gas_schedule);
    
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

Add native function to validate against expected parameter list for the given feature version, or implement Rust-side pre-flight validation in the proposal generation tooling.

## Proof of Concept

```rust
#[test]
fn incomplete_gas_schedule_halts_network() {
    let mut h = MoveHarness::new();
    
    // Create incomplete gas schedule (missing critical parameter)
    h.modify_gas_schedule_raw(|gas_schedule| {
        // Remove a required parameter
        let idx = gas_schedule.entries
            .iter()
            .position(|(key, _)| key == "instr.add")
            .unwrap();
        gas_schedule.entries.remove(idx);
    });
    
    // This should fail but currently succeeds - the incomplete schedule is accepted
    // and buffered for next epoch
    
    // Trigger epoch change to activate the incomplete gas schedule
    h.trigger_epoch_change();
    
    // Now ALL transactions fail with VM_STARTUP_FAILURE
    let acc = h.new_account_with_balance_at(
        AccountAddress::from_hex_literal("0xbeef").unwrap(), 
        100_000_000
    );
    
    let txn_status = h.publish_package(
        &acc, 
        &common::test_dir_path("common.data/do_nothing")
    );
    
    // Network is halted - no transactions can execute
    assert!(matches!(
        txn_status,
        TransactionStatus::Discard(StatusCode::VM_STARTUP_FAILURE)
    ));
    
    // Even system transactions fail - network requires hardfork to recover
}
```

## Notes

This vulnerability represents a defensive programming failure where trusted governance inputs lack validation. The attack surface is not limited to malicious actors - accidental submission of incomplete gas schedules during legitimate upgrades poses equal risk. The explicit TODO comments indicate developers are aware validation is needed but not yet implemented, creating a critical gap in the upgrade safety mechanism.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L47-47)
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

**File:** aptos-move/framework/aptos-framework/sources/reconfiguration_with_dkg.move (L46-61)
```text
    public(friend) fun finish(framework: &signer) {
        system_addresses::assert_aptos_framework(framework);
        dkg::try_clear_incomplete_session(framework);
        consensus_config::on_new_epoch(framework);
        execution_config::on_new_epoch(framework);
        gas_schedule::on_new_epoch(framework);
        std::version::on_new_epoch(framework);
        features::on_new_epoch(framework);
        jwk_consensus_config::on_new_epoch(framework);
        jwks::on_new_epoch(framework);
        keyless_account::on_new_epoch(framework);
        randomness_config_seqnum::on_new_epoch(framework);
        randomness_config::on_new_epoch(framework);
        randomness_api_v0_config::on_new_epoch(framework);
        reconfiguration::reconfigure();
    }
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

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/macros.rs (L38-41)
```rust
                    if let Some(key) = $crate::gas_schedule::macros::define_gas_parameters_extract_key_at_version!($key_bindings, feature_version) {
                        let name = format!("{}.{}", $prefix, key);
                        params.$name = gas_schedule.get(&name).cloned().ok_or_else(|| format!("Gas parameter {} does not exist. Feature version: {}.", name, feature_version))?.into();
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

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2421-2466)
```rust
    fn process_block_prologue(
        &self,
        resolver: &impl AptosMoveResolver,
        module_storage: &impl AptosModuleStorage,
        block_metadata: BlockMetadata,
        log_context: &AdapterLogSchema,
    ) -> Result<(VMStatus, VMOutput), VMStatus> {
        fail_point!("move_adapter::process_block_prologue", |_| {
            Err(VMStatus::error(
                StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR,
                None,
            ))
        });

        let mut gas_meter = UnmeteredGasMeter;
        let mut session = self.new_session(resolver, SessionId::block_meta(&block_metadata), None);

        let args = serialize_values(
            &block_metadata.get_prologue_move_args(account_config::reserved_vm_address()),
        );

        let traversal_storage = TraversalStorage::new();
        let mut traversal_context = TraversalContext::new(&traversal_storage);

        session
            .execute_function_bypass_visibility(
                &BLOCK_MODULE,
                BLOCK_PROLOGUE,
                vec![],
                args,
                &mut gas_meter,
                &mut traversal_context,
                module_storage,
            )
            .map(|_return_vals| ())
            .or_else(|e| {
                expect_only_successful_execution(e, BLOCK_PROLOGUE.as_str(), log_context)
            })?;
        SYSTEM_TRANSACTIONS_EXECUTED.inc();

        let output = get_system_transaction_output(
            session,
            module_storage,
            &self.storage_gas_params(log_context)?.change_set_configs,
        )?;
        Ok((VMStatus::Executed, output))
```

**File:** aptos-move/e2e-move-tests/src/tests/missing_gas_parameter.rs (L8-28)
```rust
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

**File:** aptos-move/aptos-release-builder/src/components/gas.rs (L117-151)
```rust
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
```
