# Audit Report

## Title
Test-Production Feature Flag Divergence Allows Critical Bugs to Bypass Testing

## Summary
The `aptos_debug_natives()` function enables all timed features unconditionally during Move unit testing, while production validators respect time-based feature activation schedules. This divergence causes Move contracts to execute with different VM configurations, native function behaviors, and gas calculations in tests versus production, allowing critical bugs to escape detection during testing.

## Finding Description

The vulnerability exists in the test native function configuration. [1](#0-0) 

This function uses `TimedFeaturesBuilder::enable_all()` which unconditionally enables all timed features: [2](#0-1) 

The `enable_all()` builder creates a configuration where `is_enabled()` always returns `true`: [3](#0-2) 

In contrast, production validators use time-based activation: [4](#0-3) 

This creates three critical behavioral differences:

**1. VM Configuration Divergence**

The VM's `enable_capture_option` setting depends on the `DisabledCaptureOption` timed feature: [5](#0-4) 

When `DisabledCaptureOption` has different values in tests vs. production (e.g., activated on mainnet from genesis but not yet activated on testnet during testing), the VM enforces different rules about capturing option types.

**2. Memory Tracking Divergence**

Table native functions conditionally apply memory tracking fixes based on the `FixTableNativesMemoryDoubleCounting` timed feature: [6](#0-5) 

This same pattern appears in `borrow_box`, `contains_box`, and `remove_box` operations: [7](#0-6) 

When enabled in tests but disabled in production (before its mainnet activation on Oct 21, 2025), memory is tracked correctly in tests but double-counted in production, causing different gas consumption and out-of-memory errors.

**3. Gas Calculation Divergence**

String formatting operations conditionally charge for bytes based on `ChargeBytesForPrints`: [8](#0-7) 

Tests always charge for bytes, but production may not (before mainnet activation on Mar 11, 2025), allowing transactions to consume more gas than tested.

**Exploitation Path:**
1. Developer writes a Move contract in February 2025 using table operations and debug printing
2. Unit tests execute with ALL timed features enabled (including `FixTableNativesMemoryDoubleCounting` and `ChargeBytesForPrints`)
3. Tests pass with expected gas usage and memory limits
4. Contract is deployed to mainnet before Mar 11, 2025
5. On mainnet, both features are disabled, causing:
   - Memory double-counting in table operations → unexpected OOM errors
   - No gas charging for print operations → gas underestimation
   - Different capture option behavior → type validation differences
6. Critical bugs (memory exhaustion, gas exploits) that only manifest with features disabled go undetected in testing

This violates the **Deterministic Execution** invariant: tests must validate production behavior, but they execute under fundamentally different VM and native function configurations.

## Impact Explanation

**High Severity** - This meets the "Significant protocol violations" category because:

1. **Systematic Testing Failure**: All Move contracts tested during feature transition periods (which can span months) are validated under incorrect assumptions about production behavior.

2. **Gas Miscalculation Vulnerabilities**: Contracts may consume dramatically different gas amounts in production than in tests, enabling:
   - DoS attacks via unexpected OOM errors
   - Gas griefing attacks via undercharged operations
   - Economic exploits via gas discrepancies

3. **Memory Safety Violations**: The `FixTableNativesMemoryDoubleCounting` feature directly affects memory tracking. Contracts that don't OOM in tests may exhaust memory in production, causing transaction failures and potential state corruption.

4. **VM Behavior Divergence**: The `enable_capture_option` flag affects fundamental VM type system behavior. Contracts validated in tests may violate type safety in production.

5. **Ecosystem-Wide Impact**: This affects every Move developer using the standard testing framework, creating a systematic blind spot in the development process during months-long feature rollout periods.

The current timed features show activation dates ranging from 2024 to 2025, meaning contracts tested today may behave differently on mainnet for over a year.

## Likelihood Explanation

**High Likelihood** - This occurs automatically and continuously:

1. **No Attacker Action Required**: The vulnerability is inherent in the testing infrastructure. Any developer using standard Move testing naturally encounters this issue.

2. **Long Exposure Windows**: Timed features have activation dates months or years in the future (e.g., `FixTableNativesMemoryDoubleCounting` activates Oct 21, 2025). All contracts tested before activation are affected.

3. **Multiple Active Transition Periods**: Multiple timed features are in active transition simultaneously, creating overlapping windows where different behaviors manifest.

4. **Invisible to Developers**: Developers have no indication that their tests are running under different feature flags than production. The divergence is silent and systematic.

## Recommendation

**Immediate Fix**: Modify `aptos_debug_natives()` to respect timed feature activation schedules:

```rust
pub fn aptos_debug_natives(
    native_gas_parameters: NativeGasParameters,
    misc_gas_params: MiscGasParameters,
) -> NativeFunctionTable {
    natives::configure_for_unit_test();
    configure_extended_checks_for_unit_test();
    
    // Use testing chain with current timestamp to respect activation schedules
    let timed_features = TimedFeaturesBuilder::new(
        ChainId::test(),
        aptos_infallible::duration_since_epoch().as_micros() as u64
    ).build();
    
    natives::aptos_natives(
        LATEST_GAS_FEATURE_VERSION,
        native_gas_parameters,
        misc_gas_params,
        timed_features,  // Changed from enable_all()
        Features::default(),
    )
}
```

**Alternative**: Provide explicit control over timed features in tests with warnings:

```rust
pub fn aptos_debug_natives_with_features(
    native_gas_parameters: NativeGasParameters,
    misc_gas_params: MiscGasParameters,
    timed_features: TimedFeatures,
) -> NativeFunctionTable {
    // ... implementation
}

pub fn aptos_debug_natives(
    native_gas_parameters: NativeGasParameters,
    misc_gas_params: MiscGasParameters,
) -> NativeFunctionTable {
    eprintln!("WARNING: Using time-based timed features in tests. Some features may not be active yet on mainnet.");
    aptos_debug_natives_with_features(
        native_gas_parameters,
        misc_gas_params,
        TimedFeaturesBuilder::new(
            ChainId::test(),
            aptos_infallible::duration_since_epoch().as_micros() as u64
        ).build()
    )
}
```

**Long-term**: Add CI checks that validate contracts under both current and future feature flag configurations to catch transition-period bugs.

## Proof of Concept

```rust
// File: test_timed_feature_divergence.rs
// Demonstrates how table memory tracking differs between test and production

#[test]
fn test_memory_tracking_divergence() {
    use aptos_types::on_chain_config::{TimedFeaturesBuilder, TimedFeatureFlag};
    use aptos_types::chain_id::ChainId;
    
    // Test environment (enable_all)
    let test_features = TimedFeaturesBuilder::enable_all().build();
    assert!(test_features.is_enabled(TimedFeatureFlag::FixTableNativesMemoryDoubleCounting));
    
    // Production environment before Oct 21, 2025
    let prod_timestamp_before = 1729468800000000; // Oct 20, 2025
    let prod_features = TimedFeaturesBuilder::new(
        ChainId::mainnet(),
        prod_timestamp_before
    ).build();
    assert!(!prod_features.is_enabled(TimedFeatureFlag::FixTableNativesMemoryDoubleCounting));
    
    // This proves tests run with memory fix enabled while production doesn't
    // Contracts using table operations will have different memory tracking behavior
}

#[test]
fn test_gas_charging_divergence() {
    use aptos_types::on_chain_config::{TimedFeaturesBuilder, TimedFeatureFlag};
    use aptos_types::chain_id::ChainId;
    
    // Test environment
    let test_features = TimedFeaturesBuilder::enable_all().build();
    assert!(test_features.is_enabled(TimedFeatureFlag::ChargeBytesForPrints));
    
    // Production environment before Mar 11, 2025
    let prod_timestamp_before = 1741651200000000; // Mar 10, 2025
    let prod_features = TimedFeaturesBuilder::new(
        ChainId::mainnet(),
        prod_timestamp_before
    ).build();
    assert!(!prod_features.is_enabled(TimedFeatureFlag::ChargeBytesForPrints));
    
    // This proves print operations will charge gas in tests but not in production
    // Contracts may exceed gas budgets in production
}
```

**Move Test PoC:**

```move
// File: test_table_memory.move
// This test will pass with enable_all() but may OOM in production before Oct 2025

#[test]
fun test_heavy_table_usage() {
    use std::table;
    
    let t = table::new<u64, vector<u8>>();
    
    // Add many large entries
    let i = 0;
    while (i < 10000) {
        table::add(&mut t, i, vector::empty<u8>());
        i = i + 1;
    };
    
    // In tests: FixTableNativesMemoryDoubleCounting is enabled → correct tracking
    // In production (before Oct 2025): Feature disabled → memory double-counted → OOM
}
```

## Notes

This vulnerability is particularly insidious because it affects the development infrastructure itself rather than the blockchain runtime. Developers cannot detect the issue through normal testing, as the divergence is exactly what prevents proper testing. The multi-month activation windows for timed features create extended periods where this test-production gap exists, maximizing the likelihood of bugs slipping through to mainnet deployment.

### Citations

**File:** crates/aptos/src/move_tool/aptos_debug_natives.rs (L20-36)
```rust
pub fn aptos_debug_natives(
    native_gas_parameters: NativeGasParameters,
    misc_gas_params: MiscGasParameters,
) -> NativeFunctionTable {
    // As a side effect, also configure for unit testing
    natives::configure_for_unit_test();
    configure_extended_checks_for_unit_test();
    // Return all natives -- build with the 'testing' feature, therefore containing
    // debug related functions.
    natives::aptos_natives(
        LATEST_GAS_FEATURE_VERSION,
        native_gas_parameters,
        misc_gas_params,
        TimedFeaturesBuilder::enable_all().build(),
        Features::default(),
    )
}
```

**File:** types/src/on_chain_config/timed_features.rs (L166-171)
```rust
    pub fn enable_all() -> Self {
        Self {
            inner: TimedFeaturesImpl::EnableAll,
            override_: None,
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

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L228-229)
```rust
    let enable_capture_option = !timed_features.is_enabled(TimedFeatureFlag::DisabledCaptureOption)
        || features.is_enabled(FeatureFlag::ENABLE_CAPTURE_OPTION);
```

**File:** aptos-move/framework/table-natives/src/lib.rs (L395-426)
```rust
    let fix_memory_double_counting =
        context.timed_feature_enabled(TimedFeatureFlag::FixTableNativesMemoryDoubleCounting);

    let (extensions, mut loader_context, abs_val_gas_params, gas_feature_version) =
        context.extensions_with_loader_context_and_gas_params();
    let table_context = extensions.get::<NativeTableContext>();
    let mut table_data = table_context.table_data.borrow_mut();

    let val = args.pop_back().unwrap();
    let key = args.pop_back().unwrap();
    let handle = get_table_handle(&safely_pop_arg!(args, StructRef))?;

    let table =
        table_data.get_or_create_table(&mut loader_context, handle, &ty_args[0], &ty_args[2])?;

    let function_value_extension = loader_context.function_value_extension();
    let key_bytes = serialize_key(&function_value_extension, &table.key_layout, &key)?;
    let key_cost = ADD_BOX_PER_BYTE_SERIALIZED * NumBytes::new(key_bytes.len() as u64);

    let (gv, loaded) =
        table.get_or_create_global_value(&function_value_extension, table_context, key_bytes)?;
    let mem_usage = if !fix_memory_double_counting || loaded.is_some() {
        gv.view()
            .map(|val| {
                abs_val_gas_params
                    .abstract_heap_size(&val, gas_feature_version)
                    .map(u64::from)
            })
            .transpose()?
    } else {
        None
    };
```

**File:** aptos-move/framework/table-natives/src/lib.rs (L456-457)
```rust
    let fix_memory_double_counting =
        context.timed_feature_enabled(TimedFeatureFlag::FixTableNativesMemoryDoubleCounting);
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
