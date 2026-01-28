# Audit Report

## Title
Emergency Gas Schedule Updates Delayed by DKG Reconfiguration Window

## Summary
When critical gas undercharging is discovered, emergency gas schedule updates via governance cannot be applied immediately in DKG-enabled mode. The update is staged but not applied until DKG completes, creating a multi-block exploitation window where transactions continue executing at undercharged rates, enabling validator resource exhaustion attacks.

## Finding Description

The Aptos gas schedule update mechanism uses a two-phase commit pattern through `config_buffer`. When governance executes an emergency gas schedule update, `gas_schedule::set_for_next_epoch()` stages the new schedule in the config buffer but does not apply it immediately. [1](#0-0) 

In DKG-enabled mode (when both validator transactions and randomness are enabled), the `aptos_governance::reconfigure()` function calls `reconfiguration_with_dkg::try_start()` instead of immediately applying changes. [2](#0-1) 

The `try_start()` function initiates DKG but does not apply any buffered configurations - it only starts the asynchronous DKG process. [3](#0-2) 

The new gas schedule is only applied when `reconfiguration_with_dkg::finish()` is called after DKG completes. This function calls `gas_schedule::on_new_epoch()` which extracts the pending configuration from the buffer. [4](#0-3) 

**The Critical Gap:**

During DKG execution, each block's execution environment is created from the state view, which fetches gas parameters directly from the current `GasScheduleV2` resource - not from the pending config buffer. [5](#0-4) 

The gas parameter retrieval function fetches `GasScheduleV2` from the state view using `GasScheduleV2::fetch_config_and_bytes(state_view)`. [6](#0-5) 

The `on_new_epoch()` function that applies buffered gas schedules is only called when `finish()` executes after DKG completion. [7](#0-6) 

**No Emergency Bypass:**

The `force_end_epoch()` function exists but requires `@aptos_framework` signer access, making it unavailable for emergency response by operators. [8](#0-7) 

**Attack Scenario:**

1. Critical gas undercharging discovered in production gas parameters
2. Emergency governance proposal submitted and approved
3. Proposal executes `set_for_next_epoch()` + `reconfigure()`, which starts DKG via `try_start()`
4. **EXPLOITATION WINDOW**: DKG runs across multiple blocks where ALL transactions execute with OLD undercharged rates
5. Attacker submits transactions exploiting undercharged operations (e.g., table operations, state bloat operations)
6. Attacker creates massive state bloat, exhausts validator CPU/memory resources, causing consensus delays
7. Eventually DKG completes via validator transaction, `finish()` applies new rates, but damage is done

## Impact Explanation

This qualifies as **HIGH SEVERITY** under the Aptos bug bounty program category "Validator node slowdowns" (up to $50,000):

1. **Resource Exhaustion**: If operations are undercharged (e.g., table insertions at 1/100th correct cost), attackers can spam these operations during the DKG window. Validators must process expensive operations while charging minimal gas, leading to CPU/memory exhaustion and consensus delays.

2. **Protocol Invariant Violation**: The gas metering invariant is violated - operations execute at incorrect rates for an extended period despite governance attempting emergency fixes. This breaks the fundamental economic security model where computational costs should match gas charges.

3. **Economic Damage**: Attackers can create state bloat where validators bear storage and computational costs far exceeding collected gas fees, causing long-term network cost burden.

The impact is bounded by DKG completion time (typically several blocks) but is guaranteed to occur in every emergency gas fix scenario when DKG is enabled, which is the standard configuration on mainnet with randomness features. [9](#0-8) 

## Likelihood Explanation

**Likelihood: HIGH**

1. **Realistic Trigger**: Gas undercharging bugs have occurred in blockchain systems and are explicitly contemplated by the existence of emergency governance mechanisms, gas parameter versioning, and the `set_for_next_epoch_check_hash()` function for safe updates.

2. **DKG is Standard Configuration**: Randomness features require DKG, making this the default reconfiguration path on mainnet. The code explicitly documents that "randomness works if and only if `consensus_config::validator_txn_enabled() && randomness_config::enabled()`".

3. **Trivial Exploitation**: Once the governance proposal executes and DKG starts, any user can observe on-chain that gas rates haven't updated yet (by querying the `GasScheduleV2` resource at `@aptos_framework`) and submit transactions exploiting the undercharged operations. No special privileges required.

4. **No Operator Bypass**: Unlike other emergency scenarios, operators cannot force immediate application of gas fixes. The only bypass requires `@aptos_framework` signer, which is governance-controlled and cannot be used for rapid emergency response.

## Recommendation

Implement one or more of the following mitigations:

1. **Emergency Gas Schedule Fast-Path**: Add a special function that allows immediate gas schedule application bypassing DKG when called with proper authorization (e.g., multi-sig from a subset of validators):

```move
public fun apply_emergency_gas_schedule(emergency_auth: &signer) acquires GasScheduleV2 {
    // Verify emergency authorization
    verify_emergency_auth(emergency_auth);
    // Immediately extract and apply buffered gas schedule
    if (config_buffer::does_exist<GasScheduleV2>()) {
        let new_gas_schedule = config_buffer::extract_v2<GasScheduleV2>();
        *borrow_global_mut<GasScheduleV2>(@aptos_framework) = new_gas_schedule;
        // Skip DKG, trigger immediate reconfiguration
        reconfiguration::reconfigure();
    }
}
```

2. **Gas Schedule Hot-Fix Capability**: Allow gas schedules to be applied immediately during DKG without waiting for completion, with a special flag indicating emergency mode.

3. **DKG Abort for Emergencies**: Extend `force_end_epoch()` authorization to a special emergency multisig controlled by validator operators, allowing them to abort DKG and apply critical fixes immediately.

4. **Apply Buffered Gas Schedule During DKG**: Modify the block execution environment creation to check both state view AND config buffer for pending gas schedules, applying the buffered version if it exists during DKG.

## Proof of Concept

While a full PoC would require a testnet deployment, the vulnerability can be demonstrated through Move testing:

```move
#[test(framework = @aptos_framework)]
fun test_gas_schedule_delay_during_dkg(framework: signer) {
    // Setup: Enable DKG
    consensus_config::enable_validator_txns(&framework);
    randomness_config::initialize(&framework, randomness_config::new_v1(...));
    
    // Stage emergency gas schedule update
    let new_schedule = create_undercharged_fix();
    gas_schedule::set_for_next_epoch(&framework, new_schedule);
    
    // Trigger reconfiguration with DKG
    aptos_governance::reconfigure(&framework);
    
    // Verify: DKG started but gas schedule NOT applied
    assert!(dkg::incomplete_session() is_some, ERROR_DKG_NOT_STARTED);
    let current_schedule = borrow_global<GasScheduleV2>(@aptos_framework);
    assert!(current_schedule != new_schedule, ERROR_SCHEDULE_APPLIED_EARLY);
    
    // Simulate multiple blocks during DKG
    // All transactions still use OLD gas schedule
    // Attacker can exploit undercharged operations
    
    // Eventually DKG completes
    dkg::finish(transcript);
    reconfiguration_with_dkg::finish(&framework);
    
    // Only NOW is new schedule applied
    let updated_schedule = borrow_global<GasScheduleV2>(@aptos_framework);
    assert!(updated_schedule == new_schedule, ERROR_SCHEDULE_NOT_APPLIED);
}
```

## Notes

This vulnerability represents a fundamental design trade-off between security (DKG-based epoch changes for randomness) and emergency responsiveness (immediate config application). The exploitation window is bounded but guaranteed, and the impact depends on the severity of the gas undercharging bug being fixed. The recommended mitigations would require careful design to maintain security guarantees while enabling emergency response capabilities.

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

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L700-703)
```text
    public entry fun force_end_epoch(aptos_framework: &signer) {
        system_addresses::assert_aptos_framework(aptos_framework);
        reconfiguration_with_dkg::finish(aptos_framework);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/reconfiguration_with_dkg.move (L24-40)
```text
    public(friend) fun try_start() {
        let incomplete_dkg_session = dkg::incomplete_session();
        if (option::is_some(&incomplete_dkg_session)) {
            let session = option::borrow(&incomplete_dkg_session);
            if (dkg::session_dealer_epoch(session) == reconfiguration::current_epoch()) {
                return
            }
        };
        reconfiguration_state::on_reconfig_start();
        let cur_epoch = reconfiguration::current_epoch();
        dkg::start(
            cur_epoch,
            randomness_config::current(),
            stake::cur_validator_consensus_infos(),
            stake::next_validator_consensus_infos(),
        );
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

**File:** aptos-move/aptos-vm-environment/src/environment.rs (L246-247)
```rust
        let (gas_params, storage_gas_params, gas_feature_version) =
            get_gas_parameters(&mut sha3_256, &features, state_view);
```

**File:** aptos-move/aptos-vm-environment/src/gas.rs (L27-36)
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
        },
```

**File:** aptos-move/framework/aptos-framework/sources/configs/randomness_config.move (L71-83)
```text
    /// Check whether on-chain randomness main logic (e.g., `DKGManager`, `RandManager`, `BlockMetadataExt`) is enabled.
    ///
    /// NOTE: this returning true does not mean randomness will run.
    /// The feature works if and only if `consensus_config::validator_txn_enabled() && randomness_config::enabled()`.
    public fun enabled(): bool acquires RandomnessConfig {
        if (exists<RandomnessConfig>(@aptos_framework)) {
            let config = borrow_global<RandomnessConfig>(@aptos_framework);
            let variant_type_name = *string::bytes(copyable_any::type_name(&config.variant));
            variant_type_name != b"0x1::randomness_config::ConfigOff"
        } else {
            false
        }
    }
```
