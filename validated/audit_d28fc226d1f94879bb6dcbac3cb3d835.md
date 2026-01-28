# Audit Report

## Title
Timed Features TOCTOU Vulnerability: Stale Feature State Due to Mid-Epoch Timestamp Advancement

## Summary
A Time-of-Check-to-Time-of-Use (TOCTOU) vulnerability exists in the timed features system where feature flags are evaluated based on `last_reconfiguration_time` at block start, but remain static even when features should activate mid-epoch based on the advancing block timestamp. This causes transactions to execute with incorrect feature enablement state, leading to gas miscalculation and protocol violations.

## Finding Description

The vulnerability arises from a fundamental mismatch between when timed features are evaluated versus when they should logically activate during block execution.

**Root Cause Analysis:**

When `AptosEnvironment` is created for block execution, it fetches the timestamp from `ConfigurationResource.last_reconfiguration_time_micros()`, which represents the last epoch change time, not the current block time: [1](#0-0) 

This timestamp is used to instantiate `TimedFeaturesBuilder`, which then evaluates each feature flag exactly once: [2](#0-1) 

The evaluation logic compares the provided timestamp against each feature's activation time: [3](#0-2) 

Results are stored as an immutable boolean array in `TimedFeatures`: [4](#0-3) 

**The Critical Gap:**

During block execution, the block prologue updates `CurrentTimeMicroseconds` to the current block time: [5](#0-4) [6](#0-5) 

However, reconfiguration (which updates `last_reconfiguration_time`) only occurs when the epoch interval threshold is met: [7](#0-6) [8](#0-7) 

**Exploitation Scenario:**

Consider a feature scheduled to activate at a specific timestamp that falls between epoch boundaries: [9](#0-8) 

If blocks execute after 17:00 but before the next epoch reconfiguration:
1. Environment is created using `last_reconfiguration_time` (e.g., 16:00)
2. Feature evaluated as DISABLED (16:00 < 17:00)
3. Block prologue updates current time to 17:30
4. Transactions execute with feature DISABLED despite current time being 17:30 > 17:00
5. Window persists until next reconfiguration triggers

The environment is created once per block before the prologue executes: [10](#0-9) 

This timing guarantees the vulnerability manifests for every mid-epoch feature activation.

## Impact Explanation

This vulnerability qualifies as **HIGH SEVERITY** under Aptos bug bounty criteria:

**Gas Miscalculation:** Security-critical features remain inactive when they should be enabled:
- `FixMemoryUsageTracking` - Allows undercharging for memory usage, enabling resource exhaustion attacks
- `ChargeBytesForPrints` - Permits free computation via print statements
- `FixTableNativesMemoryDoubleCounting` - Incorrect memory tracking enables DoS [11](#0-10) [12](#0-11) 

**Protocol Violation:** The blockchain executes with incorrect feature state during the vulnerability window, violating the intended activation schedule. All validators execute identically (maintaining consensus safety), but all execute incorrectly according to protocol specifications.

**Resource Exhaustion:** Attackers can exploit unfixed bugs during the window, submitting transactions that undercharge for resources, potentially degrading validator performance.

**Window Duration:** The vulnerability persists from feature activation time until the next epoch reconfiguration, which can span hours on mainnet where epoch intervals are configurable.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability triggers **deterministically** whenever:
- A timed feature has a scheduled activation time
- Blocks execute after that activation time but before the next epoch reconfiguration
- The feature affects security-critical behavior (gas metering, memory tracking)

**Frequency Factors:**
- Occurs for EVERY timed feature activation with mid-epoch timing
- Multiple features are scheduled with specific activation timestamps in the codebase
- Mainnet epoch intervals can be 2 hours, creating extended vulnerability windows

**Attacker Requirements:**
- No special privileges or validator access required
- Simple passive exploitation by submitting transactions during the window
- Attack can be fully automated by monitoring on-chain feature activation schedules

**Exploitation Complexity: LOW**
- No complex transaction construction required
- Deterministic behavior - attacker can predict exact vulnerability windows
- Zero economic barriers beyond normal transaction fees

## Recommendation

**Immediate Fix:** Re-evaluate timed features using the current block timestamp (`timestamp::now_microseconds()`) rather than `last_reconfiguration_time`.

**Implementation Approach:**

1. Modify `AptosEnvironment::new()` to use `CurrentTimeMicroseconds` from state:
```rust
let timestamp_micros = fetch_config_and_update_hash::<CurrentTimeMicroseconds>(&mut sha3_256, state_view)
    .map(|timer| timer.microseconds())
    .unwrap_or(0);
```

2. Alternatively, re-evaluate features after the block prologue executes and updates the timestamp, though this would require environment recreation mid-block.

**Long-term Solution:** Consider redesigning timed features to check activation times dynamically at usage points rather than pre-computing a static boolean array.

## Proof of Concept

The vulnerability can be demonstrated through code analysis showing the execution flow:

**Step 1:** Environment creation reads stale timestamp:
- `AptosModuleCacheManager::try_lock_inner()` creates environment
- Uses `ConfigurationResource.last_reconfiguration_time_micros()`
- Features evaluated with epoch start time, not current block time

**Step 2:** Block prologue updates timestamp:
- `block::block_prologue` or `block::block_prologue_ext` executes
- `timestamp::update_global_time()` sets `CurrentTimeMicroseconds` to current block time
- Features remain static despite timestamp advancement

**Step 3:** Window exploitation:
- Submit transactions between feature activation time and next epoch reconfiguration
- Transactions execute with old (buggy) behavior
- Example: Undercharge for memory usage by exploiting unactivated `FixMemoryUsageTracking`

The deterministic nature of this vulnerability makes formal verification straightforward - any block executing during the window will exhibit incorrect feature state.

## Notes

This vulnerability represents a logic flaw in the temporal design of feature activation. While it maintains consensus safety (all validators behave identically), it violates protocol correctness by allowing security fixes to remain inactive past their scheduled activation times. The impact is amplified by the fact that affected features specifically address gas metering and resource tracking vulnerabilities, creating a compounding security risk during the vulnerability window.

### Citations

**File:** aptos-move/aptos-vm-environment/src/environment.rs (L225-228)
```rust
        let timestamp_micros =
            fetch_config_and_update_hash::<ConfigurationResource>(&mut sha3_256, state_view)
                .map(|config| config.last_reconfiguration_time_micros())
                .unwrap_or(0);
```

**File:** aptos-move/aptos-vm-environment/src/environment.rs (L230-239)
```rust
        let mut timed_features_builder = TimedFeaturesBuilder::new(chain_id, timestamp_micros);
        if let Some(profile) = get_timed_feature_override() {
            // We need to ensure the override is taken into account for the hash.
            let profile_bytes = bcs::to_bytes(&profile)
                .expect("Timed features override should always be serializable");
            sha3_256.update(&profile_bytes);

            timed_features_builder = timed_features_builder.with_override_profile(profile)
        }
        let timed_features = timed_features_builder.build();
```

**File:** types/src/on_chain_config/timed_features.rs (L18-27)
```rust
    ChargeBytesForPrints,

    // Fixes the bug of table natives not tracking the memory usage of the global values they create.
    FixMemoryUsageTracking,
    // Disable checking for captured option types.
    // Only when this feature is turned on, feature flag ENABLE_CAPTURE_OPTION can control whether the option type can be captured.
    DisabledCaptureOption,

    /// Fixes the bug that table natives double count the memory usage of the global values.
    FixTableNativesMemoryDoubleCounting,
```

**File:** types/src/on_chain_config/timed_features.rs (L106-109)
```rust
            (FixMemoryUsageTracking, MAINNET) => Los_Angeles
                .with_ymd_and_hms(2025, 3, 11, 17, 0, 0)
                .unwrap()
                .with_timezone(&Utc),
```

**File:** types/src/on_chain_config/timed_features.rs (L128-135)
```rust
            (FixTableNativesMemoryDoubleCounting, TESTNET) => Los_Angeles
                .with_ymd_and_hms(2025, 10, 16, 17, 0, 0)
                .unwrap()
                .with_timezone(&Utc),
            (FixTableNativesMemoryDoubleCounting, MAINNET) => Los_Angeles
                .with_ymd_and_hms(2025, 10, 21, 10, 0, 0)
                .unwrap()
                .with_timezone(&Utc),
```

**File:** types/src/on_chain_config/timed_features.rs (L181-199)
```rust
    fn is_enabled(&self, flag: TimedFeatureFlag) -> bool {
        use TimedFeaturesImpl::*;

        if let Some(override_) = &self.override_ {
            if let Some(enabled) = override_.get_override(flag) {
                return enabled;
            }
        }

        match &self.inner {
            OnNamedChain {
                named_chain,
                timestamp_micros,
            } => {
                *timestamp_micros >= flag.activation_time_on(named_chain).timestamp_micros() as u64
            },
            EnableAll => true,
        }
    }
```

**File:** types/src/on_chain_config/timed_features.rs (L201-218)
```rust
    pub fn build(self) -> TimedFeatures {
        let mut enabled = [false; TimedFeatureFlag::COUNT];
        for flag in TimedFeatureFlag::iter() {
            enabled[flag as usize] = self.is_enabled(flag)
        }

        TimedFeatures(enabled)
    }
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct TimedFeatures([bool; TimedFeatureFlag::COUNT]);

impl TimedFeatures {
    pub fn is_enabled(&self, flag: TimedFeatureFlag) -> bool {
        self.0[flag as usize]
    }
}
```

**File:** aptos-move/framework/aptos-framework/sources/block.move (L213-218)
```text
        let epoch_interval = block_prologue_common(&vm, hash, epoch, round, proposer, failed_proposer_indices, previous_block_votes_bitvec, timestamp);
        randomness::on_new_block(&vm, epoch, round, option::none());
        if (timestamp - reconfiguration::last_reconfiguration_time() >= epoch_interval) {
            reconfiguration::reconfigure();
        };
    }
```

**File:** aptos-move/framework/aptos-framework/sources/block.move (L264-287)
```text
    fun emit_new_block_event(
        vm: &signer,
        event_handle: &mut EventHandle<NewBlockEvent>,
        new_block_event: NewBlockEvent,
    ) acquires CommitHistory {
        if (exists<CommitHistory>(@aptos_framework)) {
            let commit_history_ref = borrow_global_mut<CommitHistory>(@aptos_framework);
            let idx = commit_history_ref.next_idx;
            if (table_with_length::contains(&commit_history_ref.table, idx)) {
                table_with_length::remove(&mut commit_history_ref.table, idx);
            };
            table_with_length::add(&mut commit_history_ref.table, idx, copy new_block_event);
            spec {
                assume idx + 1 <= MAX_U32;
            };
            commit_history_ref.next_idx = (idx + 1) % commit_history_ref.max_capacity;
        };
        timestamp::update_global_time(vm, new_block_event.proposer, new_block_event.time_microseconds);
        assert!(
            event::counter(event_handle) == new_block_event.height,
            error::invalid_argument(ENUM_NEW_BLOCK_EVENTS_DOES_NOT_MATCH_BLOCK_HEIGHT),
        );
        event::emit_event<NewBlockEvent>(event_handle, new_block_event);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/timestamp.move (L32-50)
```text
    public fun update_global_time(
        account: &signer,
        proposer: address,
        timestamp: u64
    ) acquires CurrentTimeMicroseconds {
        // Can only be invoked by AptosVM signer.
        system_addresses::assert_vm(account);

        let global_timer = borrow_global_mut<CurrentTimeMicroseconds>(@aptos_framework);
        let now = global_timer.microseconds;
        if (proposer == @vm_reserved) {
            // NIL block with null address as proposer. Timestamp must be equal.
            assert!(now == timestamp, error::invalid_argument(EINVALID_TIMESTAMP));
        } else {
            // Normal block. Time must advance
            assert!(now < timestamp, error::invalid_argument(EINVALID_TIMESTAMP));
            global_timer.microseconds = timestamp;
        };
    }
```

**File:** aptos-move/framework/aptos-framework/sources/reconfiguration.move (L106-159)
```text
    public(friend) fun reconfigure() acquires Configuration {
        // Do not do anything if genesis has not finished.
        if (chain_status::is_genesis() || timestamp::now_microseconds() == 0 || !reconfiguration_enabled()) {
            return
        };

        let config_ref = borrow_global_mut<Configuration>(@aptos_framework);
        let current_time = timestamp::now_microseconds();

        // Do not do anything if a reconfiguration event is already emitted within this transaction.
        //
        // This is OK because:
        // - The time changes in every non-empty block
        // - A block automatically ends after a transaction that emits a reconfiguration event, which is guaranteed by
        //   VM spec that all transactions comming after a reconfiguration transaction will be returned as Retry
        //   status.
        // - Each transaction must emit at most one reconfiguration event
        //
        // Thus, this check ensures that a transaction that does multiple "reconfiguration required" actions emits only
        // one reconfiguration event.
        //
        if (current_time == config_ref.last_reconfiguration_time) {
            return
        };

        reconfiguration_state::on_reconfig_start();

        // Call stake to compute the new validator set and distribute rewards and transaction fees.
        stake::on_new_epoch();
        storage_gas::on_reconfig();

        assert!(current_time > config_ref.last_reconfiguration_time, error::invalid_state(EINVALID_BLOCK_TIME));
        config_ref.last_reconfiguration_time = current_time;
        spec {
            assume config_ref.epoch + 1 <= MAX_U64;
        };
        config_ref.epoch = config_ref.epoch + 1;

        if (std::features::module_event_migration_enabled()) {
            event::emit(
                NewEpoch {
                    epoch: config_ref.epoch,
                },
            );
        };
        event::emit_event<NewEpochEvent>(
            &mut config_ref.events,
            NewEpochEvent {
                epoch: config_ref.epoch,
            },
        );

        reconfiguration_state::on_reconfig_finish();
    }
```

**File:** aptos-move/block-executor/src/code_cache_global_manager.rs (L205-231)
```rust
    fn try_lock_inner(
        &self,
        state_view: &impl StateView,
        config: &BlockExecutorModuleCacheLocalConfig,
        transaction_slice_metadata: TransactionSliceMetadata,
    ) -> Result<AptosModuleCacheManagerGuard<'_>, VMStatus> {
        // Get the current environment from storage.
        let storage_environment =
            AptosEnvironment::new_with_delayed_field_optimization_enabled(&state_view);

        Ok(match self.inner.try_lock() {
            Some(mut guard) => {
                guard.check_ready(storage_environment, config, transaction_slice_metadata)?;
                AptosModuleCacheManagerGuard::Guard { guard }
            },
            None => {
                alert_or_println!("Locking module cache manager failed, fallback to empty caches");

                // If this is true, we failed to acquire a lock, and so default storage environment
                // and empty (thread-local) module caches will be used.
                AptosModuleCacheManagerGuard::None {
                    environment: storage_environment,
                    module_cache: GlobalModuleCache::empty(),
                }
            },
        })
    }
```
