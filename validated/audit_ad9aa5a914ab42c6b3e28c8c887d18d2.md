# Audit Report

## Title
Timed Features TOCTOU Vulnerability: Stale Feature State Due to Mid-Epoch Timestamp Advancement

## Summary
A Time-of-Check-to-Time-of-Use (TOCTOU) vulnerability exists in the timed features system where feature flags are evaluated based on `last_reconfiguration_time` at block start but remain static even when features should activate mid-epoch. This causes transactions to execute with incorrect feature enablement state, leading to gas miscalculation and protocol violations.

## Finding Description

The vulnerability arises from a fundamental timing mismatch in the timed features evaluation flow.

**Root Cause:**

When `AptosEnvironment` is created for block execution, it occurs in the module cache manager's `try_lock_inner` method before any transactions execute, including the block prologue. [1](#0-0) 

The environment creation fetches `last_reconfiguration_time_micros()` from `ConfigurationResource`, which represents the last epoch change time, not the current block time. [2](#0-1) 

This timestamp is used to instantiate `TimedFeaturesBuilder`, which evaluates each feature flag exactly once by comparing the timestamp against each feature's activation time. [3](#0-2) 

The evaluation results are stored as an immutable boolean array in `TimedFeatures` with no mechanism for re-evaluation. [4](#0-3) 

**The Critical Gap:**

After environment creation, the block prologue executes and updates `CurrentTimeMicroseconds` to the current block time via `timestamp::update_global_time()`. [5](#0-4) 

The timestamp update advances the global time. [6](#0-5) 

However, reconfiguration (which updates `last_reconfiguration_time`) only occurs when the epoch interval threshold is met. [7](#0-6) 

The reconfiguration updates `last_reconfiguration_time` to current time. [8](#0-7) 

**Exploitation Scenario:**

Consider `FixMemoryUsageTracking` scheduled to activate on mainnet at March 11, 2025 at 5:00 PM PT. [9](#0-8) 

If the last epoch reconfiguration occurred at 4:00 PM and blocks execute after 5:00 PM but before the next reconfiguration:
1. Environment created using `last_reconfiguration_time` (4:00 PM)
2. Feature evaluated as DISABLED (4:00 PM < 5:00 PM)
3. Block prologue updates current time to 5:30 PM
4. Transactions execute with feature DISABLED despite current time being past activation
5. Window persists until next epoch reconfiguration

The timed feature check reads from the static boolean array with no re-evaluation. [10](#0-9) 

## Impact Explanation

This qualifies as **HIGH SEVERITY** under Aptos bug bounty criteria for "Validator Node Slowdowns" and resource exhaustion attacks.

**Gas Miscalculation:**

When `FixMemoryUsageTracking` remains disabled, the `use_heap_memory` function skips memory tracking entirely, allowing transactions to consume heap memory without proper gas charges. [11](#0-10) 

When `ChargeBytesForPrints` remains disabled, print operations don't charge per-byte costs, enabling free computation. [12](#0-11) 

When `FixTableNativesMemoryDoubleCounting` remains disabled, table operations charge memory incorrectly. [13](#0-12) 

**Resource Exhaustion:**

Attackers can submit transactions exploiting unfixed bugs during the vulnerability window, undercharging for resources and potentially degrading validator performance.

**Protocol Violation:**

The blockchain executes with incorrect feature state according to the intended activation schedule. While all validators execute identically (maintaining consensus safety), the execution violates protocol specifications.

**Window Duration:**

The vulnerability persists from feature activation time until the next epoch reconfiguration, which can span hours on mainnet where epoch intervals are configurable.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability triggers deterministically whenever:
- A timed feature has a scheduled activation time
- Blocks execute after that activation time but before the next epoch reconfiguration
- The feature affects security-critical behavior

**Frequency:**
- Occurs for EVERY timed feature activation with mid-epoch timing
- Multiple features are scheduled with specific timestamps
- Mainnet epoch intervals can be 2 hours, creating extended windows

**Attacker Requirements:**
- No special privileges required
- Any user can submit transactions during the window
- Attack fully automated by monitoring on-chain schedules
- Zero economic barriers beyond normal gas fees

**Exploitation Complexity: LOW**
- No complex transaction construction needed
- Deterministic, predictable behavior
- Attacker can calculate exact vulnerability windows from source code

## Recommendation

Evaluate timed features based on `CurrentTimeMicroseconds` (current block time) instead of `last_reconfiguration_time`. This ensures features activate at their intended timestamps regardless of epoch boundaries.

**Proposed Fix:**

Modify `Environment::new()` in `aptos-move/aptos-vm-environment/src/environment.rs` to fetch current time from `CurrentTimeMicroseconds` resource instead of `ConfigurationResource.last_reconfiguration_time_micros()`.

Alternatively, re-evaluate timed features after the block prologue updates the timestamp, though this would require environment reconstruction mid-block.

## Proof of Concept

The vulnerability can be demonstrated by:
1. Deploying a testnet with a timed feature scheduled to activate at timestamp T
2. Setting epoch interval to ensure T falls mid-epoch
3. Executing blocks after timestamp T but before next reconfiguration
4. Observing that the feature remains disabled despite current time exceeding T
5. Submitting transactions that exploit the disabled feature's unfixed behavior

A complete Move test would require control over block timestamps and epoch intervals, which are typically controlled by consensus in production environments.

### Citations

**File:** aptos-move/block-executor/src/code_cache_global_manager.rs (L205-213)
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
```

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

**File:** types/src/on_chain_config/timed_features.rs (L106-109)
```rust
            (FixMemoryUsageTracking, MAINNET) => Los_Angeles
                .with_ymd_and_hms(2025, 3, 11, 17, 0, 0)
                .unwrap()
                .with_timezone(&Utc),
```

**File:** types/src/on_chain_config/timed_features.rs (L201-217)
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
```

**File:** aptos-move/framework/aptos-framework/sources/block.move (L215-217)
```text
        if (timestamp - reconfiguration::last_reconfiguration_time() >= epoch_interval) {
            reconfiguration::reconfigure();
        };
```

**File:** aptos-move/framework/aptos-framework/sources/block.move (L281-281)
```text
        timestamp::update_global_time(vm, new_block_event.proposer, new_block_event.time_microseconds);
```

**File:** aptos-move/framework/aptos-framework/sources/timestamp.move (L32-49)
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
```

**File:** aptos-move/framework/aptos-framework/sources/reconfiguration.move (L136-138)
```text

        assert!(current_time > config_ref.last_reconfiguration_time, error::invalid_state(EINVALID_BLOCK_TIME));
        config_ref.last_reconfiguration_time = current_time;
```

**File:** aptos-move/aptos-native-interface/src/context.rs (L205-216)
```rust
    pub fn use_heap_memory(&mut self, amount: u64) -> SafeNativeResult<()> {
        if self.timed_feature_enabled(TimedFeatureFlag::FixMemoryUsageTracking) {
            if self.has_direct_gas_meter_access_in_native_context() {
                self.gas_meter()
                    .use_heap_memory_in_native_context(amount)
                    .map_err(LimitExceededError::from_err)?;
            } else {
                self.legacy_heap_memory_usage =
                    self.legacy_heap_memory_usage.saturating_add(amount);
            }
        }
        Ok(())
```

**File:** aptos-move/framework/src/natives/string_utils.rs (L342-348)
```rust
                if context.context.timed_feature_enabled(
                    aptos_types::on_chain_config::TimedFeatureFlag::ChargeBytesForPrints,
                ) {
                    context
                        .context
                        .charge(STRING_UTILS_PER_BYTE * NumBytes::new(bytes.len() as u64))?;
                }
```

**File:** aptos-move/framework/table-natives/src/lib.rs (L395-396)
```rust
    let fix_memory_double_counting =
        context.timed_feature_enabled(TimedFeatureFlag::FixTableNativesMemoryDoubleCounting);
```
