# Audit Report

## Title
Deprecated Gas Schedule Updator Bypasses DKG Protocol, Causing Randomness Unavailability

## Summary
The `aptos-gas-schedule-updator` tool generates governance scripts that call the deprecated `set_gas_schedule()` function instead of the modern `set_for_next_epoch()` function. This bypasses the DKG (Distributed Key Generation) protocol, causing immediate epoch reconfiguration without randomness generation. When randomness is enabled on-chain, this creates a state inconsistency where the randomness feature is configured as enabled but becomes completely unavailable, causing all randomness-dependent transactions to fail. [1](#0-0) 

## Finding Description

The vulnerability exists in the gas schedule update proposal generation flow:

**The Deprecated Path:**
The `aptos-gas-schedule-updator` generates scripts that call the deprecated `set_gas_schedule()` function, which directly triggers reconfiguration without DKG: [2](#0-1) 

The critical issue is at line 80: this function calls `reconfiguration::reconfigure()` directly, bypassing the governance reconfiguration logic that handles DKG.

**The Correct Path:**
The modern `aptos-release-builder` uses the correct approach: [3](#0-2) 

This properly calls `set_for_next_epoch()` to stage the change in the config buffer, then calls `aptos_governance::reconfigure()` which conditionally starts DKG: [4](#0-3) 

**Attack Scenario:**
1. When randomness is enabled (`randomness_config::enabled()` returns true), governance script execution should trigger DKG via `reconfiguration_with_dkg::try_start()`
2. However, the deprecated `set_gas_schedule()` bypasses this by calling `reconfiguration::reconfigure()` directly
3. The epoch increments immediately without DKG being initiated
4. At the new epoch start, validators attempt to extract randomness configuration via `try_get_rand_config_for_new_epoch()`
5. The DKG completion check fails because no DKG session was run for the new epoch: [5](#0-4) 

6. All validators deterministically get `NoRandomnessReason::CompletedSessionTooOld` error
7. Block prologue sets `PerBlockRandomness.seed = option::none()`
8. Any transaction calling randomness APIs (e.g., `randomness::bytes()`, `randomness::u64_integer()`) will abort when attempting to borrow the missing seed: [6](#0-5) 

## Impact Explanation

This vulnerability causes a **High severity** protocol violation:

- **Randomness Feature Unavailability**: When randomness is configured as enabled on-chain but a gas schedule update uses the deprecated tool, the randomness feature becomes completely unavailable even though it should be operational.

- **State Inconsistency**: The system is in an inconsistent state where `randomness_config::enabled()` returns true, but `PerBlockRandomness.seed` is `None`, violating the protocol's correctness guarantees.

- **Transaction Failures**: All user transactions attempting to use randomness APIs will deterministically abort, breaking applications that depend on secure randomness.

- **Recovery Requires Manual Intervention**: Validators must coordinate to use `randomness_override_seq_num` to temporarily disable randomness, then governance must increment the sequence number to re-enable it properly. [7](#0-6) 

**Note**: This does NOT cause a consensus safety violation (no chain split) as all nodes deterministically see the same on-chain state and fail in the same way. The chain continues producing blocks, so it's not total liveness failure. However, it's a significant protocol violation requiring intervention.

## Likelihood Explanation

**Likelihood: Low-Medium**

- **Tool Still Maintained**: The deprecated updator tool is still maintained and tested, as evidenced by active test coverage: [8](#0-7) 

- **Tool Still Referenced**: The tool is still used for data generation in the release builder: [9](#0-8) 

- **Requires Governance Approval**: Exploitation requires a governance proposal to be approved, but this could happen if someone uses the deprecated tool instead of the modern release builder.

- **Developer Confusion**: The existence of two tools (one deprecated, one modern) with similar purposes creates confusion risk, especially since the deprecated tool is still functional and tested.

## Recommendation

**Immediate Actions:**

1. **Deprecate or Remove the Old Tool**: Either remove `aptos-gas-schedule-updator` entirely or modify it to generate correct scripts using `set_for_next_epoch()` + `aptos_governance::reconfigure()`.

2. **Update the Script Generation**: Modify the `generate_script()` function to use the modern approach:

```move
// Instead of:
gas_schedule::set_gas_schedule(&framework_signer, gas_schedule_blob);

// Use:
gas_schedule::set_for_next_epoch(&framework_signer, gas_schedule_blob);
aptos_governance::reconfigure(&framework_signer);
```

3. **Disable the Deprecated Function**: Complete the TODO in the gas_schedule.move file to disable `set_gas_schedule()` as an entry function, or add runtime checks to prevent its use when randomness is enabled. [10](#0-9) 

## Proof of Concept

```bash
# Step 1: Generate a gas schedule update using the deprecated tool
cargo run -p aptos-gas-schedule-updator -- --output ./vulnerable_proposal

# Step 2: Examine the generated script - it will contain:
# gas_schedule::set_gas_schedule(&framework_signer, gas_schedule_blob);

# Step 3: In a testnet with randomness enabled, submit this proposal

# Step 4: After proposal execution, query on-chain resources:
aptos move view --function-id 0x1::randomness_config::enabled
# Returns: true

aptos move view --function-id 0x1::randomness::PerBlockRandomness
# Returns: { seed: null }  <- Inconsistent state!

# Step 5: Attempt to call any randomness API - it will abort:
# Any transaction calling randomness::bytes() will fail with abort at option::borrow
```

**Expected Behavior**: After a gas schedule update with randomness enabled, randomness should remain available with a properly generated seed from DKG.

**Actual Behavior**: Randomness becomes unavailable (seed is None) even though the feature is configured as enabled.

---

**Notes:**

The deprecated function includes an explicit warning about this exact issue, suggesting prior awareness but incomplete mitigation. The modern `aptos-release-builder` uses the correct approach, but the old tool remains functional and could be used inadvertently or by external parties building governance proposals.

### Citations

**File:** aptos-move/aptos-gas-schedule-updator/src/lib.rs (L84-87)
```rust
    emitln!(
        writer,
        "gas_schedule::set_gas_schedule(&framework_signer, gas_schedule_blob);"
    );
```

**File:** aptos-move/framework/aptos-framework/sources/configs/gas_schedule.move (L52-81)
```text
    /// Deprecated by `set_for_next_epoch()`.
    ///
    /// WARNING: calling this while randomness is enabled will trigger a new epoch without randomness!
    ///
    /// TODO: update all the tests that reference this function, then disable this function.
    public fun set_gas_schedule(aptos_framework: &signer, gas_schedule_blob: vector<u8>) acquires GasSchedule, GasScheduleV2 {
        system_addresses::assert_aptos_framework(aptos_framework);
        assert!(!vector::is_empty(&gas_schedule_blob), error::invalid_argument(EINVALID_GAS_SCHEDULE));
        chain_status::assert_genesis();

        if (exists<GasScheduleV2>(@aptos_framework)) {
            let gas_schedule = borrow_global_mut<GasScheduleV2>(@aptos_framework);
            let new_gas_schedule: GasScheduleV2 = from_bytes(gas_schedule_blob);
            assert!(new_gas_schedule.feature_version >= gas_schedule.feature_version,
                error::invalid_argument(EINVALID_GAS_FEATURE_VERSION));
            // TODO(Gas): check if gas schedule is consistent
            *gas_schedule = new_gas_schedule;
        }
        else {
            if (exists<GasSchedule>(@aptos_framework)) {
                _ = move_from<GasSchedule>(@aptos_framework);
            };
            let new_gas_schedule: GasScheduleV2 = from_bytes(gas_schedule_blob);
            // TODO(Gas): check if gas schedule is consistent
            move_to<GasScheduleV2>(aptos_framework, new_gas_schedule);
        };

        // Need to trigger reconfiguration so validator nodes can sync on the updated gas schedule.
        reconfiguration::reconfigure();
    }
```

**File:** aptos-move/aptos-release-builder/src/components/gas.rs (L132-149)
```rust
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
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L685-692)
```text
    public entry fun reconfigure(aptos_framework: &signer) {
        system_addresses::assert_aptos_framework(aptos_framework);
        if (consensus_config::validator_txn_enabled() && randomness_config::enabled()) {
            reconfiguration_with_dkg::try_start();
        } else {
            reconfiguration_with_dkg::finish(aptos_framework);
        }
    }
```

**File:** consensus/src/epoch_manager.rs (L1039-1045)
```rust
        let dkg_state = maybe_dkg_state.map_err(NoRandomnessReason::DKGStateResourceMissing)?;
        let dkg_session = dkg_state
            .last_completed
            .ok_or_else(|| NoRandomnessReason::DKGCompletedSessionResourceMissing)?;
        if dkg_session.metadata.dealer_epoch + 1 != new_epoch_state.epoch {
            return Err(NoRandomnessReason::CompletedSessionTooOld);
        }
```

**File:** aptos-move/framework/aptos-framework/sources/randomness.move (L76-87)
```text
    fun next_32_bytes(): vector<u8> acquires PerBlockRandomness {
        assert!(is_unbiasable(), E_API_USE_IS_BIASIBLE);

        let input = DST;
        let randomness = borrow_global<PerBlockRandomness>(@aptos_framework);
        let seed = *option::borrow(&randomness.seed);

        vector::append(&mut input, seed);
        vector::append(&mut input, transaction_context::get_transaction_hash());
        vector::append(&mut input, fetch_and_increment_txn_counter());
        hash::sha3_256(input)
    }
```

**File:** testsuite/smoke-test/src/randomness/randomness_stall_recovery.rs (L64-84)
```rust
    info!("Hot-fixing all validators.");
    for (idx, validator) in swarm.validators_mut().enumerate() {
        info!("Stopping validator {}.", idx);
        validator.stop();
        let config_path = validator.config_path();
        let mut validator_override_config =
            OverrideNodeConfig::load_config(config_path.clone()).unwrap();
        validator_override_config
            .override_config_mut()
            .randomness_override_seq_num = 1;
        validator_override_config
            .override_config_mut()
            .consensus
            .sync_only = false;
        info!("Updating validator {} config.", idx);
        validator_override_config.save_config(config_path).unwrap();
        info!("Restarting validator {}.", idx);
        validator.start().unwrap();
        info!("Let validator {} bake for 5 secs.", idx);
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
```

**File:** aptos-move/aptos-gas-schedule-updator/tests/gen_tests.rs (L7-18)
```rust
#[test]
fn can_generate_and_build_update_proposal() {
    let output_dir = tempfile::tempdir().unwrap();

    generate_update_proposal(&GenArgs {
        gas_feature_version: None,
        output: Some(output_dir.path().to_string_lossy().to_string()),
    })
    .unwrap();

    BuiltPackage::build(output_dir.path().to_path_buf(), BuildOptions::default()).unwrap();
}
```

**File:** aptos-move/aptos-release-builder/src/components/mod.rs (L210-212)
```rust
            GasScheduleLocator::Current => Ok(aptos_gas_schedule_updator::current_gas_schedule(
                LATEST_GAS_FEATURE_VERSION,
            )),
```
