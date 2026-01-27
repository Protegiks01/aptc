# Audit Report

## Title
Governance Version Updates Can Be Skipped Due to Config Buffer Overwriting During Rapid Proposal Resolution

## Summary
Multiple governance proposals that update the blockchain version can be resolved in quick succession while DKG (Distributed Key Generation) is in progress, causing intermediate version updates to be skipped. The config buffer's `upsert` mechanism overwrites pending versions, resulting in only the last buffered version being applied when the epoch transitions, violating governance integrity expectations.

## Finding Description

The vulnerability occurs in the interaction between the governance proposal resolution system, the config buffer mechanism, and the epoch transition logic when DKG is enabled.

**Core Issue:**

The `config_buffer::upsert()` function uses `simple_map::upsert()` which overwrites any previously buffered value for the same configuration type. [1](#0-0) 

When a governance proposal to update the version is resolved, it calls `version::set_for_next_epoch()` which buffers the new version. [2](#0-1) 

The proposal then calls `aptos_governance::reconfigure()` to trigger an epoch transition. When DKG is enabled, this calls `reconfiguration_with_dkg::try_start()`. [3](#0-2) 

However, `try_start()` returns early if a DKG session is already in progress for the current epoch, preventing multiple concurrent epoch transitions. [4](#0-3) 

**Attack Scenario:**

1. Current blockchain version is 4
2. Governance Proposal A (update to version 5) is approved and resolved
   - Calls `set_for_next_epoch(5)` → buffers `Version{major: 5}`
   - Calls `reconfigure()` → starts DKG
3. While DKG is in progress, Proposal B (update to version 6) is resolved
   - Calls `set_for_next_epoch(6)` → buffers `Version{major: 6}` (overwrites version 5)
   - Calls `reconfigure()` → returns early (DKG already in progress)
4. Proposal C (update to version 7) is resolved
   - Calls `set_for_next_epoch(7)` → buffers `Version{major: 7}` (overwrites version 6)
   - Calls `reconfigure()` → returns early
5. DKG completes, `reconfiguration_with_dkg::finish()` is called
6. `version::on_new_epoch()` extracts only `Version{major: 7}` from buffer [5](#0-4) 

**Result:** Version jumps from 4 to 7, skipping versions 5 and 6 that were approved by governance.

**Why Validation Passes:**

The version validation only checks against the current on-chain version, not the buffered version, so all three proposals pass validation. [6](#0-5) 

## Impact Explanation

This issue represents a **governance integrity violation** rather than a critical security breach:

**What is NOT affected:**
- No loss of funds or ability to mint/steal tokens
- No consensus safety violation (all validators apply the same final version deterministically)
- No network partition or liveness failure
- No validator node failures or crashes

**What IS affected:**
- **Governance expectations**: Proposals that received community approval and passed all voting requirements do not have their intended effect
- **Version-gated features**: If intermediate versions gate specific features or bug fixes, those features will not be activated as intended
- **Auditability**: Blockchain history shows approved proposals that never executed
- **Potential validator confusion**: If validators have version-specific logic expecting sequential updates (though no such code was found in this analysis)

Based on the Aptos bug bounty severity categories, this falls into **Medium severity** as it creates "state inconsistencies requiring intervention" - the version state becomes inconsistent with governance expectations and multiple approved governance proposals are effectively nullified.

## Likelihood Explanation

**Likelihood: Medium to High**

This can occur in realistic scenarios:

1. **Multiple concurrent proposals**: Different community members or organizations may independently propose version updates for different features, all of which pass voting around the same time
2. **Emergency updates**: An urgent version update proposal may be created while a previous proposal is already in the resolution phase
3. **DKG timing**: DKG sessions can take significant time to complete (requiring validator coordination), creating a window where multiple proposals can be resolved
4. **No explicit protection**: There is no mechanism in the code to prevent multiple version update proposals from being created or resolved concurrently

The scenario does NOT require malicious intent - it can happen through normal governance operations when multiple valid proposals are processed in quick succession.

## Recommendation

**Solution: Prevent Multiple Pending Version Updates**

Add validation in `version::set_for_next_epoch()` to check if a version update is already buffered:

```move
public entry fun set_for_next_epoch(account: &signer, major: u64) acquires Version {
    assert!(exists<SetVersionCapability>(signer::address_of(account)), error::permission_denied(ENOT_AUTHORIZED));
    
    // Check if a version update is already pending
    assert!(
        !config_buffer::does_exist<Version>(),
        error::invalid_state(EVERSION_UPDATE_ALREADY_PENDING)
    );
    
    let old_major = borrow_global<Version>(@aptos_framework).major;
    assert!(old_major < major, error::invalid_argument(EINVALID_MAJOR_VERSION_NUMBER));
    config_buffer::upsert(Version {major});
}
```

This ensures only one version update can be buffered at a time, preventing intermediate versions from being overwritten.

**Alternative solution**: Validate that the new version is greater than any buffered version (not just the current version):

```move
public entry fun set_for_next_epoch(account: &signer, major: u64) acquires Version {
    assert!(exists<SetVersionCapability>(signer::address_of(account)), error::permission_denied(ENOT_AUTHORIZED));
    let old_major = borrow_global<Version>(@aptos_framework).major;
    
    // Check against buffered version if it exists
    let min_required_version = if (config_buffer::does_exist<Version>()) {
        // Extract, check, and re-buffer with validation
        let buffered = config_buffer::extract_v2<Version>();
        assert!(buffered.major < major, error::invalid_argument(EINVALID_MAJOR_VERSION_NUMBER));
        config_buffer::upsert(buffered);
        buffered.major
    } else {
        old_major
    };
    
    assert!(min_required_version < major, error::invalid_argument(EINVALID_MAJOR_VERSION_NUMBER));
    config_buffer::upsert(Version {major});
}
```

## Proof of Concept

The following Move test demonstrates the vulnerability:

```move
#[test(aptos_framework = @aptos_framework)]
public entry fun test_rapid_version_updates_skip_intermediate(aptos_framework: signer) acquires Version {
    // Initialize with version 4
    initialize(&aptos_framework, 4);
    
    // Simulate three governance proposals for versions 5, 6, and 7
    // All are valid because they check against current version (4)
    
    // Proposal 1: Update to version 5
    set_for_next_epoch(&aptos_framework, 5);
    // At this point, Version{5} is buffered
    
    // Proposal 2: Update to version 6 (while DKG in progress)
    // This overwrites Version{5} with Version{6}
    set_for_next_epoch(&aptos_framework, 6);
    
    // Proposal 3: Update to version 7 (while DKG still in progress)
    // This overwrites Version{6} with Version{7}
    set_for_next_epoch(&aptos_framework, 7);
    
    // Simulate epoch transition (DKG completes)
    on_new_epoch(&aptos_framework);
    
    // Version should jump from 4 to 7, skipping 5 and 6
    let current = borrow_global<Version>(@aptos_framework);
    assert!(current.major == 7, 0);
    // Versions 5 and 6 were never applied despite being approved by governance
}
```

This test will fail to compile as-is due to visibility restrictions, but demonstrates the logical flow of the vulnerability. A proper integration test would need to go through the full governance proposal creation, voting, and resolution flow while controlling DKG timing.

## Notes

While this vulnerability does answer the security question about validators missing version updates during rapid successive proposals, the practical security impact is limited to governance integrity rather than critical system security. The issue does not compromise consensus, funds, or network availability. However, it does represent a violation of governance expectations where approved proposals should execute as intended, making it worthy of remediation to maintain trust in the governance process.

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

**File:** aptos-move/framework/aptos-framework/sources/reconfiguration_with_dkg.move (L24-31)
```text
    public(friend) fun try_start() {
        let incomplete_dkg_session = dkg::incomplete_session();
        if (option::is_some(&incomplete_dkg_session)) {
            let session = option::borrow(&incomplete_dkg_session);
            if (dkg::session_dealer_epoch(session) == reconfiguration::current_epoch()) {
                return
            }
        };
```
