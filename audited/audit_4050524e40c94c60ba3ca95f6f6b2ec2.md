# Audit Report

## Title
Time-of-Check to Time-of-Use (TOCTOU) Vulnerability in Consensus Config Reconfiguration Enables Randomness Feature Without DKG

## Summary
A Time-of-Check to Time-of-Use (TOCTOU) logic vulnerability exists in `aptos_governance::reconfigure()` where the decision to run Distributed Key Generation (DKG) is made based on the current on-chain consensus configuration, but buffered (staged) configurations are applied afterward. This allows enabling validator transactions and randomness features without running the required DKG protocol, creating a protocol violation.

## Finding Description
The vulnerability lies in the config application flow during reconfiguration. The `reconfigure()` function checks whether to start DKG based on the current on-chain state: [1](#0-0) 

These checks read the **current on-chain state** through functions that access on-chain resources: [2](#0-1) [3](#0-2) 

However, when `set_for_next_epoch()` is called prior to reconfiguration, it only **stages** the new config in a buffer without updating the on-chain storage: [4](#0-3) [5](#0-4) 

The actual application of staged configs happens later in `on_new_epoch()` functions: [6](#0-5) [7](#0-6) 

These `on_new_epoch()` functions are called from `reconfiguration_with_dkg::finish()`: [8](#0-7) 

**Attack Path:**
1. Initial state: `validator_txn_enabled = false`, `randomness_enabled = false`
2. Governance proposal stages new configs via `set_for_next_epoch(vtxn=true)` and `set_for_next_epoch(randomness=true)`
3. Governance calls `reconfigure()`
4. Line 687 check reads OLD on-chain values (false & false) → evaluates to false
5. Takes else branch, calls `finish()` directly **without DKG**
6. Inside `finish()`, line 49 applies NEW config with `vtxn=true`
7. Inside `finish()`, line 58 applies NEW config with `randomness=true`
8. New epoch starts with randomness enabled but **no shared secret established via DKG**

When validators attempt to initialize randomness for the new epoch, they fail because no DKG session has been completed: [9](#0-8) 

The system handles this by logging an error and continuing without randomness capabilities: [10](#0-9) 

This violates the protocol specification that explicitly states: [11](#0-10) 

## Impact Explanation
**Medium Severity** - This is a logic vulnerability that breaks protocol invariants:

- **Protocol Violation**: The on-chain configuration indicates randomness is enabled, but validators cannot actually generate randomness because no DKG session established the required shared secrets. This violates the protocol specification.

- **State Inconsistency**: The system enters an inconsistent state where on-chain configs claim features are enabled but validators lack the cryptographic material to use them. This requires manual governance intervention to resolve.

- **No Consensus Divergence**: All validators fail identically when attempting to setup randomness without DKG, so this does not cause consensus splits or safety violations.

This qualifies as **Limited Protocol Violation** under the Medium severity category, as it creates state inconsistencies requiring manual intervention but does not cause fund loss, consensus failure, or network halts.

## Likelihood Explanation
**Medium Likelihood**:
- Can occur accidentally during legitimate governance operations when enabling both validator transactions and randomness in a single proposal
- Requires governance proposal, but this is standard operational procedure
- The TOCTOU window exists whenever staged configs differ from current on-chain configs
- No malicious intent required - this is a logic bug in the reconfiguration flow itself
- Uses the correct APIs (`set_for_next_epoch()` and `reconfigure()`) as intended

## Recommendation
The `reconfigure()` function should check the **staged** configs (if they exist) rather than only the current on-chain state:

```move
public entry fun reconfigure(aptos_framework: &signer) {
    system_addresses::assert_aptos_framework(aptos_framework);
    
    // Check both current AND pending configs
    let will_enable_vtxn = consensus_config::validator_txn_enabled() || 
        config_buffer::does_exist<ConsensusConfig>();
    let will_enable_randomness = randomness_config::enabled() || 
        config_buffer::does_exist<RandomnessConfig>();
    
    if (will_enable_vtxn && will_enable_randomness) {
        reconfiguration_with_dkg::try_start();
    } else {
        reconfiguration_with_dkg::finish(aptos_framework);
    }
}
```

Alternatively, require DKG to complete before allowing randomness config updates, or add validation in `set_for_next_epoch()` to prevent this state transition.

## Proof of Concept
This vulnerability can be demonstrated through a governance proposal that stages both configs before reconfiguration:

```move
// Governance script that triggers the vulnerability
script {
    use aptos_framework::consensus_config;
    use aptos_framework::randomness_config;
    use aptos_framework::aptos_governance;
    use aptos_std::fixed_point64;
    
    fun enable_randomness_without_dkg(framework: &signer) {
        // Stage validator transaction enablement
        let vtxn_enabled_config = /* construct config with vtxn=true */;
        consensus_config::set_for_next_epoch(framework, vtxn_enabled_config);
        
        // Stage randomness enablement
        let randomness_config = randomness_config::new_v1(
            fixed_point64::create_from_rational(1, 3),
            fixed_point64::create_from_rational(2, 3)
        );
        randomness_config::set_for_next_epoch(framework, randomness_config);
        
        // Trigger reconfiguration - will skip DKG but apply both configs
        aptos_governance::reconfigure(framework);
        
        // New epoch now has randomness enabled in config but no DKG session completed
    }
}
```

## Notes
This is a logic vulnerability in the reconfiguration flow, not a malicious exploit. It can occur during legitimate governance operations when enabling features in the recommended way. The severity is Medium rather than High because validators handle the missing DKG gracefully by logging errors and continuing operation, rather than crashing or causing consensus divergence. However, it does create a protocol violation that requires governance intervention to resolve.

### Citations

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

**File:** aptos-move/framework/aptos-framework/sources/configs/consensus_config.move (L52-56)
```text
    public fun set_for_next_epoch(account: &signer, config: vector<u8>) {
        system_addresses::assert_aptos_framework(account);
        assert!(vector::length(&config) > 0, error::invalid_argument(EINVALID_CONFIG));
        std::config_buffer::upsert<ConsensusConfig>(ConsensusConfig {config});
    }
```

**File:** aptos-move/framework/aptos-framework/sources/configs/consensus_config.move (L59-69)
```text
    public(friend) fun on_new_epoch(framework: &signer) acquires ConsensusConfig {
        system_addresses::assert_aptos_framework(framework);
        if (config_buffer::does_exist<ConsensusConfig>()) {
            let new_config = config_buffer::extract_v2<ConsensusConfig>();
            if (exists<ConsensusConfig>(@aptos_framework)) {
                *borrow_global_mut<ConsensusConfig>(@aptos_framework) = new_config;
            } else {
                move_to(framework, new_config);
            };
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/configs/consensus_config.move (L71-74)
```text
    public fun validator_txn_enabled(): bool acquires ConsensusConfig {
        let config_bytes = borrow_global<ConsensusConfig>(@aptos_framework).config;
        validator_txn_enabled_internal(config_bytes)
    }
```

**File:** aptos-move/framework/aptos-framework/sources/configs/randomness_config.move (L53-56)
```text
    public fun set_for_next_epoch(framework: &signer, new_config: RandomnessConfig) {
        system_addresses::assert_aptos_framework(framework);
        config_buffer::upsert(new_config);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/configs/randomness_config.move (L59-69)
```text
    public(friend) fun on_new_epoch(framework: &signer) acquires RandomnessConfig {
        system_addresses::assert_aptos_framework(framework);
        if (config_buffer::does_exist<RandomnessConfig>()) {
            let new_config = config_buffer::extract_v2<RandomnessConfig>();
            if (exists<RandomnessConfig>(@aptos_framework)) {
                *borrow_global_mut<RandomnessConfig>(@aptos_framework) = new_config;
            } else {
                move_to(framework, new_config);
            }
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/configs/randomness_config.move (L71-74)
```text
    /// Check whether on-chain randomness main logic (e.g., `DKGManager`, `RandManager`, `BlockMetadataExt`) is enabled.
    ///
    /// NOTE: this returning true does not mean randomness will run.
    /// The feature works if and only if `consensus_config::validator_txn_enabled() && randomness_config::enabled()`.
```

**File:** aptos-move/framework/aptos-framework/sources/configs/randomness_config.move (L75-83)
```text
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

**File:** consensus/src/epoch_manager.rs (L1243-1260)
```rust
        let (rand_config, fast_rand_config) = match rand_configs {
            Ok((rand_config, fast_rand_config)) => (Some(rand_config), fast_rand_config),
            Err(reason) => {
                if onchain_randomness_config.randomness_enabled() {
                    if epoch_state.epoch > 2 {
                        error!(
                            "Failed to get randomness config for new epoch [{}]: {:?}",
                            epoch_state.epoch, reason
                        );
                    } else {
                        warn!(
                            "Failed to get randomness config for new epoch [{}]: {:?}",
                            epoch_state.epoch, reason
                        );
                    }
                }
                (None, None)
            },
```
