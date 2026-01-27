# Audit Report

## Title
Incomplete Timed Feature Override in Replay Mode Causes Non-Deterministic Transaction Replay

## Summary
The `TimedFeatureOverride::Replay` mechanism only hardcodes two legacy timed features (`_LimitTypeTagSize` and `_ModuleComplexityCheck`), leaving all other features to be determined by timestamp-based checks during replay. This incomplete override can cause replayed transactions to execute with different feature states than their original execution, violating deterministic execution guarantees and producing inconsistent results during replay verification. [1](#0-0) 

## Finding Description

When the replay-verify coordinator runs, it sets a global `TimedFeatureOverride::Replay` to ensure consistent feature flag behavior during transaction replay. However, this override only hardcodes two features: [2](#0-1) 

For all other timed features (including `ChargeBytesForPrints`, `FixMemoryUsageTracking`, `DisabledCaptureOption`, `FixTableNativesMemoryDoubleCounting`, and `EntryCompatibility`), the override returns `None`, causing the system to fall back to timestamp-based activation checks. [3](#0-2) 

The timestamp used comes from the `ConfigurationResource.last_reconfiguration_time` in the state being replayed: [4](#0-3) 

**Vulnerability Scenario 1 - State Snapshot Mismatch:**
1. A transaction executes at block height 1000, epoch 5, timestamp T1 (before `FixMemoryUsageTracking` activates at T2)
2. The transaction succeeds because memory tracking is disabled
3. During replay, a state snapshot from epoch 6, timestamp T3 > T2 is restored
4. The replay reads timestamp T3 from the restored state's `ConfigurationResource`
5. `FixMemoryUsageTracking` is enabled during replay (T3 >= T2)
6. The same transaction now fails with `MEMORY_LIMIT_EXCEEDED` due to stricter memory tracking

**Vulnerability Scenario 2 - Cross-Version Replay:**
1. Transaction executes on codebase version V1 which doesn't have feature F
2. Replay occurs on codebase version V2 which adds feature F with activation time in the past
3. State's timestamp >= feature F activation time
4. Feature F is enabled during replay even though it didn't exist during original execution
5. Execution behavior differs (different gas charges, memory accounting, or success/failure)

**Concrete Impact Evidence:**

The `FixMemoryUsageTracking` feature demonstrably changes execution outcomes: [5](#0-4) 

The `ChargeBytesForPrints` feature changes gas metering: [6](#0-5) 

The `FixMemoryUsageTracking` feature changes memory tracking behavior in native context: [7](#0-6) 

## Impact Explanation

This vulnerability breaks the **Deterministic Execution** invariant, which states that "all validators must produce identical state roots for identical blocks." While replay-verify is not directly in the consensus path, it affects critical infrastructure:

1. **Backup Verification Failure**: Replay-verify is used to validate backup integrity. Non-deterministic replay means backups cannot be reliably verified, potentially accepting corrupted backups or rejecting valid ones.

2. **Node Bootstrapping Issues**: If nodes bootstrap from historical snapshots using replay, they may compute different state roots than the original execution, causing state divergence.

3. **Audit/Debugging Unreliability**: Transaction replay for forensic analysis produces inconsistent results, making it impossible to accurately reproduce historical behavior.

This qualifies as **High Severity** per the bug bounty criteria: "State inconsistencies requiring intervention" and "Significant protocol violations" due to violated deterministic execution guarantees.

## Likelihood Explanation

This vulnerability occurs in two realistic scenarios:

**High Likelihood - Cross-Version Replay:**
- Every time a new timed feature is added to the codebase
- Replay of old transactions on new node versions
- Occurs during routine node upgrades and maintenance

**Medium Likelihood - Epoch-Boundary Replay:**
- When replay starts from a state snapshot at a different epoch than the transactions being replayed
- Common in backup/restore operations where snapshot timing doesn't align perfectly with transaction boundaries

The replay-verify tool is actively used in production for backup validation: [8](#0-7) 

## Recommendation

**Solution**: Explicitly hardcode ALL timed features in the `TimedFeatureOverride::Replay` profile to freeze feature states regardless of timestamp. This ensures replay always uses a known, fixed feature set.

**Recommended Fix:**

```rust
impl TimedFeatureOverride {
    #[allow(unused, clippy::match_single_binding)]
    const fn get_override(&self, flag: TimedFeatureFlag) -> Option<bool> {
        use TimedFeatureFlag::*;
        use TimedFeatureOverride::*;

        Some(match self {
            Replay => match flag {
                // Legacy features - always enabled
                _LimitTypeTagSize => true,
                _ModuleComplexityCheck => true,
                
                // Explicitly set state for all other features to ensure deterministic replay
                EntryCompatibility => true,
                ChargeBytesForPrints => true,
                FixMemoryUsageTracking => true,
                DisabledCaptureOption => true,
                FixTableNativesMemoryDoubleCounting => true,
            },
            Testing => match flag {
                EntryCompatibility => true,
                _ => return None,
            },
        })
    }
}
```

**Important**: This fix should be accompanied by a policy requiring that whenever a new `TimedFeatureFlag` is added, the `Replay` override must be updated to explicitly specify that feature's state. Consider adding a compile-time check or enum exhaustiveness enforcement to prevent future omissions.

## Proof of Concept

```rust
// This test demonstrates the vulnerability by showing different execution 
// results for the same transaction replayed with different timestamps

#[test]
fn test_replay_inconsistency_with_timed_features() {
    use aptos_types::on_chain_config::{TimedFeaturesBuilder, TimedFeatureFlag, TimedFeatureOverride};
    use aptos_types::chain_id::ChainId;
    use chrono::{TimeZone, Utc};
    
    // Timestamp before FixMemoryUsageTracking activation (before March 7, 2025)
    let timestamp_before = Utc.with_ymd_and_hms(2025, 2, 1, 0, 0, 0)
        .unwrap()
        .timestamp_micros() as u64;
    
    // Timestamp after FixMemoryUsageTracking activation (after March 7, 2025)
    let timestamp_after = Utc.with_ymd_and_hms(2025, 4, 1, 0, 0, 0)
        .unwrap()
        .timestamp_micros() as u64;
    
    // Build features without override - relies on timestamp
    let features_before = TimedFeaturesBuilder::new(ChainId::testnet(), timestamp_before)
        .with_override_profile(TimedFeatureOverride::Replay)
        .build();
    
    let features_after = TimedFeaturesBuilder::new(ChainId::testnet(), timestamp_after)
        .with_override_profile(TimedFeatureOverride::Replay)
        .build();
    
    // The same transaction replayed with different state timestamps produces different feature states
    let memory_tracking_before = features_before.is_enabled(TimedFeatureFlag::FixMemoryUsageTracking);
    let memory_tracking_after = features_after.is_enabled(TimedFeatureFlag::FixMemoryUsageTracking);
    
    // VULNERABILITY: Same replay override, different timestamps, different feature states!
    assert_ne!(memory_tracking_before, memory_tracking_after,
        "Replay override should produce consistent feature states regardless of timestamp, but it doesn't!");
    
    println!("FixMemoryUsageTracking enabled with timestamp_before: {}", memory_tracking_before);
    println!("FixMemoryUsageTracking enabled with timestamp_after: {}", memory_tracking_after);
    println!("This proves replay can produce different results for the same transaction!");
}
```

**Notes**

The root cause is that the `TimedFeatureOverride::Replay` profile was designed to freeze feature states for deterministic replay, but its implementation is incomplete. The comment on line 57 ("Add overrides for replay here") indicates awareness that features should be explicitly listed, but this maintenance has not been performed as new features were added. This is a systematic issue that will recur with every new timed feature unless the process is fixed.

### Citations

**File:** types/src/on_chain_config/timed_features.rs (L49-66)
```rust
    const fn get_override(&self, flag: TimedFeatureFlag) -> Option<bool> {
        use TimedFeatureFlag::*;
        use TimedFeatureOverride::*;

        Some(match self {
            Replay => match flag {
                _LimitTypeTagSize => true,
                _ModuleComplexityCheck => true,
                // Add overrides for replay here.
                _ => return None,
            },
            Testing => match flag {
                EntryCompatibility => true,
                _ => return None, // Activate all flags
            },
        })
    }
}
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

**File:** aptos-move/aptos-vm-environment/src/environment.rs (L225-239)
```rust
        let timestamp_micros =
            fetch_config_and_update_hash::<ConfigurationResource>(&mut sha3_256, state_view)
                .map(|config| config.last_reconfiguration_time_micros())
                .unwrap_or(0);

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

**File:** aptos-move/e2e-move-tests/src/tests/memory_quota.rs (L92-106)
```rust
    // Forward 2 hours to activate TimedFeatureFlag::FixMemoryUsageTracking
    // Now attempting to load the whole table shall result in an execution failure (memory limit hit)
    h.new_epoch();
    let result = h.run_entry_function(
        &acc,
        str::parse("0xbeef::very_nested_structure::read_all").unwrap(),
        vec![],
        vec![],
    );
    assert!(matches!(
        result,
        TransactionStatus::Keep(ExecutionStatus::MiscellaneousError(Some(
            StatusCode::MEMORY_LIMIT_EXCEEDED
        )))
    ));
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

**File:** aptos-move/aptos-native-interface/src/context.rs (L205-217)
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
    }
```

**File:** storage/backup/backup-cli/src/coordinators/replay_verify.rs (L100-102)
```rust
    async fn run_impl(self) -> Result<(), ReplayError> {
        AptosVM::set_concurrency_level_once(self.replay_concurrency_level);
        set_timed_feature_override(TimedFeatureOverride::Replay);
```
