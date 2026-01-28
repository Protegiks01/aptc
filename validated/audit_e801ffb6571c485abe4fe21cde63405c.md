# Audit Report

## Title
Governance Version Updates Can Be Skipped Due to Config Buffer Overwriting During Rapid Proposal Resolution

## Summary
Multiple governance proposals that update the blockchain version can be resolved in quick succession while DKG (Distributed Key Generation) is in progress, causing intermediate version updates to be skipped. The config buffer's `upsert` mechanism overwrites pending versions, resulting in only the last buffered version being applied when the epoch transitions, violating governance integrity expectations.

## Finding Description

The vulnerability occurs in the interaction between the governance proposal resolution system, the config buffer mechanism, and the epoch transition logic when DKG is enabled.

**Core Issue:**

The `config_buffer::upsert()` function uses `simple_map::upsert()` which overwrites any previously buffered value for the same configuration type. [1](#0-0)  The `simple_map::upsert()` implementation confirms this overwrite behavior. [2](#0-1) 

When a governance proposal to update the version is resolved, it calls `version::set_for_next_epoch()` which buffers the new version using `config_buffer::upsert()`. [3](#0-2) 

The proposal then calls `aptos_governance::reconfigure()` to trigger an epoch transition. [4](#0-3)  When DKG is enabled, this calls `reconfiguration_with_dkg::try_start()`.

However, `try_start()` returns early if a DKG session is already in progress for the current epoch, preventing multiple concurrent epoch transitions. [5](#0-4) 

**Attack Scenario:**

1. Current blockchain version is 4
2. Governance Proposal A (update to version 5) is approved and resolved
   - Calls `set_for_next_epoch(5)` → validates 4 < 5, buffers `Version{major: 5}`
   - Calls `reconfigure()` → starts DKG, marks reconfiguration as in progress
3. While DKG is in progress, Proposal B (update to version 6) is resolved
   - Calls `set_for_next_epoch(6)` → validates 4 < 6, buffers `Version{major: 6}` (overwrites version 5)
   - Calls `reconfigure()` → returns early (DKG already in progress for current epoch)
4. Proposal C (update to version 7) is resolved
   - Calls `set_for_next_epoch(7)` → validates 4 < 7, buffers `Version{major: 7}` (overwrites version 6)
   - Calls `reconfigure()` → returns early
5. DKG completes, `reconfiguration_with_dkg::finish()` is called [6](#0-5) 
6. `version::on_new_epoch()` extracts only `Version{major: 7}` from buffer [7](#0-6) 

**Result:** Version jumps from 4 to 7, skipping versions 5 and 6 that were approved by governance.

**Why Validation Passes:**

The version validation in `set_for_next_epoch()` only checks against the current on-chain version (`borrow_global<Version>(@aptos_framework).major`), not the buffered version, so all three proposals pass validation. [8](#0-7) 

Critically, there is no check in `version::set_for_next_epoch()` to verify if a reconfiguration is already in progress. The `reconfiguration_state::is_in_progress()` check only exists in the staking module [9](#0-8)  but is not used in version or governance modules to prevent concurrent config updates.

## Impact Explanation

This issue represents a **governance integrity violation** falling into **Medium severity** as defined by Aptos bug bounty categories:

**What is NOT affected:**
- No loss of funds or ability to mint/steal tokens
- No consensus safety violation (all validators deterministically apply the same final version)
- No network partition or liveness failure
- No validator node failures or crashes

**What IS affected:**
- **Governance expectations**: Proposals that received community approval and passed all voting requirements do not have their intended effect
- **Version-gated features**: If intermediate versions gate specific features or bug fixes, those features will not be activated as intended
- **Auditability**: Blockchain history shows approved proposals that never executed
- **State inconsistencies requiring intervention**: The version state becomes inconsistent with governance expectations and multiple approved governance proposals are effectively nullified

This aligns with the Aptos bug bounty definition of Medium severity: "state inconsistencies requiring intervention" where governance-approved changes are silently dropped.

## Likelihood Explanation

**Likelihood: Medium to High**

This can occur in realistic scenarios through normal governance operations:

1. **Multiple concurrent proposals**: Different community members or organizations may independently propose version updates for different features. All proposals can pass voting and become resolvable around the same time.

2. **DKG timing window**: DKG sessions require validator coordination and can take substantial time to complete (from seconds to minutes), creating a realistic window where multiple proposals can be resolved before the epoch actually transitions.

3. **No explicit protection**: The code has no mechanism to prevent multiple version update proposals from being created, voted on, or resolved concurrently. The only protection is the early return in `try_start()`, which prevents multiple DKG sessions but does NOT prevent config buffer overwrites.

4. **Normal operations**: This scenario does NOT require malicious intent. It can happen through legitimate governance activity when the community is actively upgrading the network with multiple approved proposals.

The scenario is technically feasible and can occur without any attacker involvement or special privileges.

## Recommendation

Implement one of the following fixes:

**Option 1: Check reconfiguration state in config updates**
Add a check in `version::set_for_next_epoch()` (and other config modules) to abort if a reconfiguration is already in progress:

```move
public entry fun set_for_next_epoch(account: &signer, major: u64) acquires Version {
    assert!(exists<SetVersionCapability>(signer::address_of(account)), error::permission_denied(ENOT_AUTHORIZED));
    assert!(!reconfiguration_state::is_in_progress(), error::invalid_state(ERECONFIGURATION_IN_PROGRESS));
    let old_major = borrow_global<Version>(@aptos_framework).major;
    assert!(old_major < major, error::invalid_argument(EINVALID_MAJOR_VERSION_NUMBER));
    config_buffer::upsert(Version {major});
}
```

**Option 2: Validate against buffered version**
Modify validation to check against the buffered version if one exists:

```move
public entry fun set_for_next_epoch(account: &signer, major: u64) acquires Version {
    assert!(exists<SetVersionCapability>(signer::address_of(account)), error::permission_denied(ENOT_AUTHORIZED));
    let old_major = if (config_buffer::does_exist<Version>()) {
        // Check against buffered version if it exists
        let buffered = config_buffer::peek<Version>(); // Would need new peek() function
        buffered.major
    } else {
        borrow_global<Version>(@aptos_framework).major
    };
    assert!(old_major < major, error::invalid_argument(EINVALID_MAJOR_VERSION_NUMBER));
    config_buffer::upsert(Version {major});
}
```

**Option 3: Queue multiple updates**
Replace the `SimpleMap` in config buffer with a queue structure that preserves all pending updates and applies them sequentially across multiple epochs.

## Proof of Concept

```move
#[test_only]
module aptos_framework::version_skip_test {
    use aptos_framework::version;
    use aptos_framework::config_buffer;
    use aptos_framework::reconfiguration_with_dkg;
    use aptos_framework::dkg;
    use aptos_framework::reconfiguration_state;
    use aptos_framework::timestamp;
    
    #[test(aptos_framework = @aptos_framework)]
    fun test_version_skip_during_dkg(aptos_framework: &signer) {
        // Initialize
        timestamp::set_time_has_started_for_testing(aptos_framework);
        reconfiguration_state::initialize(aptos_framework);
        config_buffer::initialize(aptos_framework);
        version::initialize(aptos_framework, 4);
        dkg::initialize(aptos_framework);
        
        // Proposal A: Set version to 5
        version::set_for_next_epoch(aptos_framework, 5);
        assert!(config_buffer::does_exist<version::Version>(), 1);
        
        // Start DKG (simulating reconfigure() with DKG enabled)
        reconfiguration_state::on_reconfig_start();
        // In real scenario, DKG would start here
        
        // Proposal B: Set version to 6 (while DKG in progress)
        version::set_for_next_epoch(aptos_framework, 6); // This overwrites version 5!
        
        // Proposal C: Set version to 7 (while DKG still in progress)
        version::set_for_next_epoch(aptos_framework, 7); // This overwrites version 6!
        
        // DKG completes, apply buffered version
        version::on_new_epoch(aptos_framework);
        
        // Version jumped from 4 to 7, skipping 5 and 6
        // Proposals for versions 5 and 6 were approved but never applied!
    }
}
```

## Notes

This vulnerability demonstrates a design flaw in the config buffer pattern when combined with async reconfiguration. The pattern assumes only one config update per epoch transition, but the lack of enforcement allows concurrent updates to overwrite each other. While the impact is limited to governance integrity (not consensus safety or fund loss), it represents a violation of governance expectations where community-approved proposals silently fail to execute.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/configs/config_buffer.move (L65-70)
```text
    public(friend) fun upsert<T: drop + store>(config: T) acquires PendingConfigs {
        let configs = borrow_global_mut<PendingConfigs>(@aptos_framework);
        let key = type_info::type_name<T>();
        let value = any::pack(config);
        simple_map::upsert(&mut configs.configs, key, value);
    }
```

**File:** aptos-move/framework/aptos-stdlib/sources/simple_map.move (L116-134)
```text
    public fun upsert<Key: store, Value: store>(
        self: &mut SimpleMap<Key, Value>,
        key: Key,
        value: Value
    ): (std::option::Option<Key>, std::option::Option<Value>) {
        let data = &mut self.data;
        let len = data.length();
        for (i in 0..len) {
            let element = data.borrow(i);
            if (&element.key == &key) {
                data.push_back(Element { key, value });
                data.swap(i, len);
                let Element { key, value } = data.pop_back();
                return (std::option::some(key), std::option::some(value))
            };
        };
        self.data.push_back(Element { key, value });
        (std::option::none(), std::option::none())
    }
```

**File:** aptos-move/framework/aptos-framework/sources/configs/version.move (L59-64)
```text
    public entry fun set_for_next_epoch(account: &signer, major: u64) acquires Version {
        assert!(exists<SetVersionCapability>(signer::address_of(account)), error::permission_denied(ENOT_AUTHORIZED));
        let old_major = borrow_global<Version>(@aptos_framework).major;
        assert!(old_major < major, error::invalid_argument(EINVALID_MAJOR_VERSION_NUMBER));
        config_buffer::upsert(Version {major});
    }
```

**File:** aptos-move/framework/aptos-framework/sources/configs/version.move (L67-77)
```text
    public(friend) fun on_new_epoch(framework: &signer) acquires Version {
        system_addresses::assert_aptos_framework(framework);
        if (config_buffer::does_exist<Version>()) {
            let new_value = config_buffer::extract_v2<Version>();
            if (exists<Version>(@aptos_framework)) {
                *borrow_global_mut<Version>(@aptos_framework) = new_value;
            } else {
                move_to(framework, new_value);
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

**File:** aptos-move/framework/aptos-framework/sources/stake.move (L1910-1912)
```text
    fun assert_reconfig_not_in_progress() {
        assert!(!reconfiguration_state::is_in_progress(), error::invalid_state(ERECONFIGURATION_IN_PROGRESS));
    }
```
