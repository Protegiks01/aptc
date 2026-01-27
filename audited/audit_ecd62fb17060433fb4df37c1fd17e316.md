# Audit Report

## Title
Epoch Transition Deadlock and State Inconsistency When DKG Fails During Version Upgrade

## Summary
When DKG (Distributed Key Generation) is enabled, a version upgrade proposal can successfully stage a new version in the config buffer but fail to complete the epoch transition if DKG never completes. This leaves the blockchain in an inconsistent state where governance records indicate the version was upgraded, but the blockchain remains on the old version indefinitely. Multiple subsequent proposals can also execute successfully while accumulating staged configurations that never activate, creating a complete liveness failure of the epoch transition mechanism. [1](#0-0) 

## Finding Description

The version upgrade proposal generates a Move script that executes two operations: [2](#0-1) 

The `set_for_next_epoch` function stages the new version in a config buffer but does not immediately apply it. The version only takes effect when `on_new_epoch` is called during an actual epoch transition. [3](#0-2) 

When DKG is enabled (validator_txn_enabled && randomness_config::enabled), `reconfigure()` calls `try_start()` which initiates an asynchronous DKG process rather than immediately completing the epoch transition. [4](#0-3) 

The critical issue is in the `try_start()` logic: if an incomplete DKG session already exists for the current epoch, the function returns early without starting a new DKG session or completing the epoch transition. This creates a deadlock where:

1. The version upgrade proposal executes successfully, staging version N in the config buffer
2. `reconfigure()` calls `try_start()` which starts DKG for epoch E
3. DKG fails to complete (network issues, validator problems, bugs)
4. The epoch remains at E indefinitely because:
   - `try_start()` checks if incomplete_session.dealer_epoch == current_epoch
   - Since both are E, it returns early
   - No new DKG starts, no epoch transition occurs
5. All subsequent reconfiguration attempts (from new proposals or block prologue) hit the same check and return early
6. The staged version never activates because `on_new_epoch` is never called [5](#0-4) 

Multiple proposals can execute during this deadlock, each staging their own configurations, but none will take effect. The blockchain is completely stuck at epoch E until governance passes a `force_end_epoch()` proposal to manually clear the incomplete DKG session. [6](#0-5) 

This breaks the **State Consistency** invariant (state transitions must be atomic and verifiable) and **Governance Integrity** invariant (governance actions must take effect as expected).

## Impact Explanation

This vulnerability meets **High Severity** criteria per the Aptos bug bounty program:

- **Significant Protocol Violations**: The epoch transition mechanism, a core protocol component, becomes completely deadlocked
- **Validator Node/Network Impacts**: All validator nodes are stuck at the same epoch, unable to progress
- **State Inconsistencies Requiring Intervention**: Governance records indicate successful proposals, but on-chain state doesn't match; recovery requires manual intervention via `force_end_epoch()`

The impact includes:
- **Liveness Failure**: Epoch transitions are blocked indefinitely
- **Governance Ineffectiveness**: Multiple proposals can pass but none take effect, undermining governance legitimacy
- **State Inconsistency**: Divergence between governance records and actual blockchain state
- **Configuration Accumulation**: Multiple staged configs accumulate in the buffer without applying
- **Recovery Complexity**: Requires passing another governance proposal to call `force_end_epoch()`, which itself may take days depending on voting periods

While the async reconfiguration behavior is documented in a WARNING comment, the severity of the failure mode (complete epoch deadlock) elevates this to a reportable vulnerability.

## Likelihood Explanation

The likelihood is **Medium to High** because:

1. **DKG Failure Scenarios** are realistic:
   - Network partitions between validators
   - Validator software bugs in DKG implementation
   - Insufficient validator participation in DKG
   - State synchronization issues between validators
   - Resource exhaustion during DKG computation

2. **No Timeout Mechanism**: There is no automatic timeout or retry logic for failed DKG sessions. The `start_time_us` field in `DKGSessionState` is recorded but never used to detect stale sessions. [7](#0-6) 

3. **Natural Occurrence**: DKG is a complex cryptographic protocol requiring coordination between multiple validators. Failures can occur naturally without malicious activity.

4. **No Monitoring**: If the first DKG failure goes unnoticed, multiple proposals could execute before the issue is detected, compounding the problem.

## Recommendation

Implement a multi-layered fix:

**1. Add DKG Timeout Mechanism**

Modify `try_start()` to check if an incomplete DKG session has exceeded a reasonable timeout (e.g., 10 minutes):

```move
public(friend) fun try_start() {
    let incomplete_dkg_session = dkg::incomplete_session();
    if (option::is_some(&incomplete_dkg_session)) {
        let session = option::borrow(&incomplete_dkg_session);
        if (dkg::session_dealer_epoch(session) == reconfiguration::current_epoch()) {
            // Check if DKG has timed out
            let current_time = timestamp::now_microseconds();
            let start_time = dkg::session_start_time(session);
            let timeout = 600_000_000; // 10 minutes in microseconds
            
            if (current_time - start_time < timeout) {
                return // Still waiting for DKG
            };
            // Timeout exceeded, clear stale session and proceed
            dkg::clear_incomplete_session_internal();
        }
    };
    reconfiguration_state::on_reconfig_start();
    // ... rest of function
}
```

**2. Add Epoch-Staleness Check**

Ensure that if we're somehow in a different epoch than the dealer_epoch (edge case), we clear the stale session:

```move
if (dkg::session_dealer_epoch(session) < reconfiguration::current_epoch()) {
    dkg::clear_incomplete_session_internal();
}
```

**3. Improve Proposal Validation**

Add a check in `aptos_governance::reconfigure()` to warn or prevent proposal execution if a DKG session has been incomplete for too long:

```move
public entry fun reconfigure(aptos_framework: &signer) {
    system_addresses::assert_aptos_framework(aptos_framework);
    
    // Check for stuck DKG
    if (consensus_config::validator_txn_enabled() && randomness_config::enabled()) {
        let incomplete = dkg::incomplete_session();
        if (option::is_some(&incomplete)) {
            let session = option::borrow(&incomplete);
            let age = timestamp::now_microseconds() - dkg::session_start_time(session);
            assert!(age < 600_000_000, error::unavailable(EDKG_STUCK));
        };
        reconfiguration_with_dkg::try_start();
    } else {
        reconfiguration_with_dkg::finish(aptos_framework);
    }
}
```

**4. Add Monitoring and Alerting**

Expose DKG session status via view functions for monitoring:

```move
#[view]
public fun get_incomplete_dkg_age_seconds(): Option<u64> {
    let incomplete = dkg::incomplete_session();
    if (option::is_some(&incomplete)) {
        let session = option::borrow(&incomplete);
        let age_us = timestamp::now_microseconds() - dkg::session_start_time(session);
        option::some(age_us / 1_000_000)
    } else {
        option::none()
    }
}
```

## Proof of Concept

```move
#[test_only]
module aptos_framework::version_upgrade_deadlock_test {
    use aptos_framework::aptos_governance;
    use aptos_framework::version;
    use aptos_framework::reconfiguration_with_dkg;
    use aptos_framework::reconfiguration;
    use aptos_framework::dkg;
    use aptos_framework::timestamp;
    use aptos_framework::consensus_config;
    use aptos_framework::randomness_config;
    use std::features;
    
    #[test(aptos_framework = @aptos_framework)]
    fun test_version_upgrade_deadlock(aptos_framework: &signer) {
        // Initialize framework
        // Enable DKG feature
        features::change_feature_flags(aptos_framework, vector[RECONFIGURE_WITH_DKG], vector[]);
        consensus_config::set_for_next_epoch(aptos_framework, consensus_config_with_validator_txn_enabled());
        randomness_config::set_for_next_epoch(aptos_framework, randomness_config_enabled());
        
        let initial_epoch = reconfiguration::current_epoch();
        let initial_version = version::get_version();
        
        // Proposal 1: Upgrade to version 2
        version::set_for_next_epoch(aptos_framework, 2);
        aptos_governance::reconfigure(aptos_framework);
        
        // DKG starts but doesn't complete
        assert!(option::is_some(&dkg::incomplete_session()), 0);
        
        // Time passes, epoch interval expires
        timestamp::fast_forward_seconds(86400); // 1 day
        
        // Try to start new epoch via block prologue
        reconfiguration_with_dkg::try_start(); // Returns early due to incomplete DKG
        
        // Epoch is still the same
        assert!(reconfiguration::current_epoch() == initial_epoch, 1);
        assert!(version::get_version() == initial_version, 2);
        
        // Proposal 2: Upgrade to version 3
        version::set_for_next_epoch(aptos_framework, 3);
        aptos_governance::reconfigure(aptos_framework); // Also returns early
        
        // Still stuck at old epoch and version
        assert!(reconfiguration::current_epoch() == initial_epoch, 3);
        assert!(version::get_version() == initial_version, 4);
        
        // Both versions 2 and 3 are staged but not applied
        // System is completely deadlocked
        
        // Only recovery: force_end_epoch
        aptos_governance::force_end_epoch(aptos_framework);
        
        // NOW the epoch transitions and version 3 is applied
        // (version 2 was overwritten in the buffer)
        assert!(reconfiguration::current_epoch() == initial_epoch + 1, 5);
        assert!(version::get_version() == 3, 6);
    }
}
```

## Notes

While the asynchronous reconfiguration behavior when DKG is enabled is documented in a WARNING comment, the severity of the failure mode when DKG never completes was likely not fully considered. The issue is that there's no automatic recovery mechanism - the system becomes completely deadlocked and requires manual governance intervention. This violates reasonable expectations that governance proposals will either fully succeed or fully fail, not partially succeed with effects indefinitely deferred.

The vulnerability is particularly concerning because:
1. Multiple proposals can execute during the deadlock period
2. Each stages its configuration in the buffer
3. When recovery finally happens via `force_end_epoch()`, all staged configs are applied at once
4. The intermediate proposals' staged configs may have been overwritten by later proposals
5. Governance participants have no visibility into which configs will actually apply

A robust solution should include automatic timeout handling, better monitoring, and clearer failure modes rather than silent deadlocks.

### Citations

**File:** aptos-move/aptos-release-builder/src/components/version.rs (L28-34)
```rust
            emitln!(
                writer,
                "version::set_for_next_epoch({}, {});",
                signer_arg,
                version.major,
            );
            emitln!(writer, "aptos_governance::reconfigure({});", signer_arg);
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

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L676-692)
```text
    /// Manually reconfigure. Called at the end of a governance txn that alters on-chain configs.
    ///
    /// WARNING: this function always ensures a reconfiguration starts, but when the reconfiguration finishes depends.
    /// - If feature `RECONFIGURE_WITH_DKG` is disabled, it finishes immediately.
    ///   - At the end of the calling transaction, we will be in a new epoch.
    /// - If feature `RECONFIGURE_WITH_DKG` is enabled, it starts DKG, and the new epoch will start in a block prologue after DKG finishes.
    ///
    /// This behavior affects when an update of an on-chain config (e.g. `ConsensusConfig`, `Features`) takes effect,
    /// since such updates are applied whenever we enter an new epoch.
    public entry fun reconfigure(aptos_framework: &signer) {
        system_addresses::assert_aptos_framework(aptos_framework);
        if (consensus_config::validator_txn_enabled() && randomness_config::enabled()) {
            reconfiguration_with_dkg::try_start();
        } else {
            reconfiguration_with_dkg::finish(aptos_framework);
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/aptos_governance.move (L694-703)
```text
    /// Change epoch immediately.
    /// If `RECONFIGURE_WITH_DKG` is enabled and we are in the middle of a DKG,
    /// stop waiting for DKG and enter the new epoch without randomness.
    ///
    /// WARNING: currently only used by tests. In most cases you should use `reconfigure()` instead.
    /// TODO: migrate these tests to be aware of async reconfiguration.
    public entry fun force_end_epoch(aptos_framework: &signer) {
        system_addresses::assert_aptos_framework(aptos_framework);
        reconfiguration_with_dkg::finish(aptos_framework);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/reconfiguration_with_dkg.move (L22-40)
```text
    /// Trigger a reconfiguration with DKG.
    /// Do nothing if one is already in progress.
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

**File:** aptos-move/framework/aptos-framework/sources/dkg.move (L18-37)
```text
    struct DKGSessionMetadata has copy, drop, store {
        dealer_epoch: u64,
        randomness_config: RandomnessConfig,
        dealer_validator_set: vector<ValidatorConsensusInfo>,
        target_validator_set: vector<ValidatorConsensusInfo>,
    }

    #[event]
    struct DKGStartEvent has drop, store {
        session_metadata: DKGSessionMetadata,
        start_time_us: u64,
    }

    /// The input and output of a DKG session.
    /// The validator set of epoch `x` works together for an DKG output for the target validator set of epoch `x+1`.
    struct DKGSessionState has copy, store, drop {
        metadata: DKGSessionMetadata,
        start_time_us: u64,
        transcript: vector<u8>,
    }
```
