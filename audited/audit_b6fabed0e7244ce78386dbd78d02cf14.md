# Audit Report

## Title
VMConfig Lacks Validation of Safety-Critical Field Dependencies Enabling Potential Stack Overflow

## Summary
The `VMConfig` struct allows unsafe field combinations where `enable_depth_checks` can be disabled while function values remain enabled, potentially bypassing value nesting depth limits and enabling stack overflow attacks on validator nodes.

## Finding Description
The `VMConfig` structure in the Move VM runtime defines multiple interdependent configuration fields that control safety-critical behavior. Specifically, the `enable_depth_checks` and `max_value_nest_depth` fields work together to prevent stack overflow during recursive value operations. [1](#0-0) 

When `enable_depth_checks` is false, the `max_value_nest_depth()` method returns `None`, completely disabling depth limit enforcement: [2](#0-1) 

This bypasses the depth check in recursive operations. The `check_depth` function returns `Ok(())` when `max_depth` is `None`: [3](#0-2) 

With function values enabled, closures can capture other closures recursively. During value copy operations, each level increments the depth counter: [4](#0-3) 

The production configuration correctly ties these flags together: [5](#0-4) 

However, the `VMConfig` struct itself contains no validation to enforce this invariant. The struct can be manually constructed with `enable_depth_checks=false` while the `VerifierConfig` enables function values, creating an unsafe combination.

Testing confirms that 129-level nesting triggers the depth limit error when checks are enabled: [6](#0-5) 

**Critical Gap:** The `VMConfig` comment acknowledges its use for consensus detection but provides no runtime validation: [7](#0-6) 

If validators operate with mismatched configurations (e.g., one with `enable_depth_checks=false` while others have it enabled), they would:
1. Accept different maximum value depths
2. Produce different execution results for the same transaction
3. Generate different state roots
4. Break consensus determinism

## Impact Explanation
**Medium Severity** - This constitutes a state inconsistency vulnerability requiring defensive intervention:

1. **Consensus Divergence Risk**: If validators have mismatched `enable_depth_checks` settings, they will disagree on whether deeply-nested closure transactions are valid, breaking deterministic execution (Invariant #1).

2. **Denial of Service**: A validator with `enable_depth_checks=false` could crash from stack overflow when processing deeply-nested closures, while properly configured validators would reject the transaction.

3. **Configuration Validation Gap**: The lack of invariant enforcement in `VMConfig` means bugs in configuration construction could introduce unsafe combinations undetected.

While production code currently prevents this combination, the absence of defensive validation means future code changes or test environments could inadvertently create this unsafe state.

## Likelihood Explanation
**Low-Medium Likelihood** - Currently mitigated by correct production configuration, but vulnerable to:

1. **Configuration Propagation Bugs**: If the feature flag system has bugs, the invariant could be violated
2. **Manual Config Construction**: Test or benchmark code manually constructing `VMConfig` might create unsafe combinations
3. **Future Changes**: Code refactoring could break the production config's defensive tying of these flags
4. **Genesis/Upgrade Bugs**: Errors during network upgrades or genesis could propagate misconfigured VMConfig

The vulnerability is not directly exploitable by unprivileged attackers but represents a defensive programming gap that could enable future exploits.

## Recommendation
Add validation to `VMConfig` construction to enforce safety invariants:

```rust
impl VMConfig {
    /// Validates that config field combinations are safe
    pub fn validate(&self) -> Result<(), String> {
        // Depth checks must be enabled when function values are enabled
        if self.verifier_config.enable_function_values && !self.enable_depth_checks {
            return Err(
                "enable_depth_checks must be true when function values are enabled"
                    .to_string()
            );
        }
        
        // If depth checks are enabled, max_value_nest_depth must be set
        if self.enable_depth_checks && self.max_value_nest_depth.is_none() {
            return Err(
                "max_value_nest_depth must be set when enable_depth_checks is true"
                    .to_string()
            );
        }
        
        Ok(())
    }
}
```

Call `validate()` after constructing VMConfig in all production code paths, including `aptos_prod_vm_config()`. Consider making `VMConfig` construction go through a builder pattern that enforces these invariants.

## Proof of Concept
```rust
// Demonstrates unsafe config combination (would need to be run in test environment)
use move_vm_runtime::config::VMConfig;
use move_bytecode_verifier::VerifierConfig;

#[test]
fn test_unsafe_vm_config_combination() {
    let mut verifier_config = VerifierConfig::default();
    verifier_config.enable_function_values = true; // Enable closures
    
    let unsafe_config = VMConfig {
        verifier_config,
        enable_depth_checks: false, // Disable depth checks - UNSAFE!
        max_value_nest_depth: Some(128), // This will be ignored
        ..VMConfig::default()
    };
    
    // This config would allow unbounded closure nesting
    // max_value_nest_depth() would return None despite max_value_nest_depth being set
    // because enable_depth_checks=false
    
    // If different validators had different enable_depth_checks settings,
    // they would disagree on validity of deeply-nested closures
}
```

## Notes
While production configuration currently prevents this unsafe combination, the lack of structural validation in `VMConfig` represents a defensive programming gap. The struct should enforce its own safety invariants rather than relying on correct usage by all callers. This is particularly important given the comment indicating VMConfig is used for consensus detection through serialization.

### Citations

**File:** third_party/move/move-vm/runtime/src/config.rs (L11-14)
```rust
/// Dynamic config options for the Move VM. Always add new fields to the end, as we rely on the
/// hash or serialized bytes of config to detect if it has changed (e.g., new feature flag was
/// enabled). Also, do not delete existing fields, or change the type of existing field.
#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
```

**File:** third_party/move/move-vm/runtime/src/config.rs (L15-59)
```rust
pub struct VMConfig {
    pub verifier_config: VerifierConfig,
    pub deserializer_config: DeserializerConfig,
    /// When this flag is set to true, MoveVM will perform type checks at every instruction
    /// execution to ensure that type safety cannot be violated at runtime. Note: these
    /// are more than type checks, for example, stack balancing, visibility, but the name
    /// is kept for historical reasons.
    pub paranoid_type_checks: bool,
    /// Always set to false, no longer used, kept for compatibility.
    pub legacy_check_invariant_in_swap_loc: bool,
    /// Maximum value nest depth for structs.
    pub max_value_nest_depth: Option<u64>,
    /// Maximum allowed number of nodes in a type layout. This includes the types of fields for
    /// struct types.
    pub layout_max_size: u64,
    /// Maximum depth (in number of nodes) of the type layout tree.
    pub layout_max_depth: u64,
    pub type_max_cost: u64,
    pub type_base_cost: u64,
    pub type_byte_cost: u64,
    pub delayed_field_optimization_enabled: bool,
    pub ty_builder: TypeBuilder,
    pub enable_function_caches: bool,
    pub enable_lazy_loading: bool,
    pub enable_depth_checks: bool,
    /// Whether trusted code should be optimized, for example, excluding it from expensive
    /// paranoid checks. Checks may still not be done in place, and instead delayed to later time.
    /// Instead, a trace can be recorded which is sufficient for type checking.
    pub optimize_trusted_code: bool,
    /// When this flag is set to true, Move VM will perform additional checks to ensure that
    /// reference safety is maintained during execution. Note that the checks might be delayed and
    /// instead execution trace can be recorded (so that checks are done based on the trace later).
    pub paranoid_ref_checks: bool,
    pub enable_capture_option: bool,
    pub enable_enum_option: bool,
    /// If true, Move VM will try to fetch layout from remote cache.
    pub enable_layout_caches: bool,
    pub propagate_dependency_limit_error: bool,
    pub enable_framework_for_option: bool,
    /// Same as enable_function_caches, but gates missed gating for native dynamic dispatch.
    pub enable_function_caches_for_native_dynamic_dispatch: bool,
    /// Whether this VM should support debugging. If set, environment variables
    /// `MOVE_VM_TRACE` and `MOVE_VM_STEP` will be recognized.
    pub enable_debugging: bool,
}
```

**File:** aptos-move/aptos-native-interface/src/context.rs (L174-186)
```rust
    pub fn max_value_nest_depth(&self) -> Option<u64> {
        self.module_storage()
            .runtime_environment()
            .vm_config()
            .enable_depth_checks
            .then(|| {
                self.module_storage()
                    .runtime_environment()
                    .vm_config()
                    .max_value_nest_depth
            })
            .flatten()
    }
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L617-624)
```rust
            ClosureValue(Closure(fun, captured)) => {
                let captured = captured
                    .iter()
                    .map(|v| v.copy_value(depth + 1, max_depth))
                    .collect::<PartialVMResult<_>>()?;
                ClosureValue(Closure(fun.clone_dyn()?, Box::new(captured)))
            },
        })
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L6166-6171)
```rust
fn check_depth(depth: u64, max_depth: Option<u64>) -> PartialVMResult<()> {
    if max_depth.is_some_and(|max_depth| depth > max_depth) {
        return Err(PartialVMError::new(StatusCode::VM_MAX_VALUE_DEPTH_REACHED));
    }
    Ok(())
}
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L221-227)
```rust
    // Value runtime depth checks have been introduced together with function values and are only
    // enabled when the function values are enabled. Previously, checks were performed over types
    // to bound the value depth (checking the size of a packed struct type bounds the value), but
    // this no longer applies once function values are enabled. With function values, types can be
    // shallow while the value can be deeply nested, thanks to captured arguments not visible in a
    // type. Hence, depth checks have been adjusted to operate on values.
    let enable_depth_checks = features.is_enabled(FeatureFlag::ENABLE_FUNCTION_VALUES);
```

**File:** aptos-move/e2e-move-tests/src/tests/function_value_depth.rs (L14-50)
```rust
#[test]
fn test_vm_value_too_deep_with_function_values() {
    let mut h = MoveHarness::new();
    let acc = h.new_account_at(AccountAddress::from_hex_literal("0x99").unwrap());

    let status = publish(
        &mut h,
        &acc,
        r#"
        module 0x99::m {
            public fun dummy2(_v: || has drop+copy) {}

            // Creates a very deep value that can be tested for off by 1 around the current maximum
            // depth value.
            public entry fun run2(n: u64) {
                let f: || has copy+drop = || {};
                let i = 0;
                while (i < n) {
                  f = || dummy2(f);
                  i = i + 1;
                };
            }
        }
        "#,
    );
    assert_success!(status);

    let status = h.run_entry_function(&acc, str::parse("0x99::m::run2").unwrap(), vec![], vec![
        bcs::to_bytes(&129_u64).unwrap(),
    ]);
    assert_vm_status!(status, StatusCode::VM_MAX_VALUE_DEPTH_REACHED);

    let status = h.run_entry_function(&acc, str::parse("0x99::m::run2").unwrap(), vec![], vec![
        bcs::to_bytes(&128_u64).unwrap(),
    ]);
    assert_success!(status);
}
```
