# Audit Report

## Title
Inconsistent Flag Dependency in Move Compiler Allows Test Functions in Production Bytecode Without Safety Checks

## Summary
The Move compiler's `keep_testing_functions` flag can be enabled independently of the `test` flag, creating a dangerous inconsistency where test-only functions are retained in bytecode without the "poison" function safety mechanism that prevents deployment on production VMs.

## Finding Description

The vulnerability exists in the flag dependency logic between `keep_testing_functions()` and `is_testing()` methods: [1](#0-0) 

The inconsistency creates a critical gap:

1. **Test Function Filtering** uses `keep_testing_functions()` which returns `self.test || self.keep_testing_functions`: [2](#0-1) 

2. **Poison Function Injection** uses `is_testing()` which only returns `self.test`: [3](#0-2) 

The poison function calls `UnitTest::create_signers_for_testing`, which is specifically excluded from production native functions: [4](#0-3) 

The problematic flag combination is used in `model_compilation()`: [5](#0-4) 

This preset is invoked through the compiler v2 path: [6](#0-5) 

And used in package compilation: [7](#0-6) 

**Breaking Security Invariant:**
When `keep_testing_functions=true` but `test=false`:
- Test functions marked with `#[test_only]` are **NOT** removed from bytecode
- The safety "poison" function is **NOT** added to modules
- Modules can be published without runtime linking failure on production VMs
- This bypasses the intended protection against deploying test code

## Impact Explanation

**Severity: High**

This violates the **Deterministic Execution** and **Move VM Safety** invariants. While module metadata validation occurs during publishing, there is no runtime check for test-only attributes: [8](#0-7) 

The metadata validation only checks specific known attributes (view_function, randomness, resource_group) but does NOT validate test attributes: [9](#0-8) 

**Impact:**
- Test-only code could be deployed on production blockchain
- Test functions often have relaxed security checks or debugging capabilities
- Could lead to validator node behavior differences if test code paths exist
- Potential for consensus divergence if test functions behave non-deterministically

## Likelihood Explanation

**Current Likelihood: Low to Medium**

The standard compilation paths use safe flag combinations: [10](#0-9) 

However, the vulnerability can manifest if:
1. Developer tools incorrectly use `model_compilation()` flags for production builds
2. Custom build scripts call `set_keep_testing_functions(true)` without setting `test=true`
3. Future code changes introduce paths using this flag combination

The public API of `set_keep_testing_functions()` makes this exploitable: [11](#0-10) 

## Recommendation

**Fix the flag dependency to enforce invariant:**

```rust
pub fn set_keep_testing_functions(self, value: bool) -> Self {
    // Enforce that keep_testing_functions requires test mode
    if value && !self.test {
        panic!("keep_testing_functions=true requires test=true for safety");
    }
    Self {
        keep_testing_functions: value,
        ..self
    }
}

// OR make keep_testing_functions() always check test flag:
pub fn keep_testing_functions(&self) -> bool {
    // Always require test mode to keep testing functions
    self.test && (self.test || self.keep_testing_functions)
}
```

**Additional safeguards:**
1. Add runtime validation in `verify_module_metadata_for_module_publishing()` to reject modules with test-only attributes
2. Make `set_keep_testing_functions()` private or add debug assertions
3. Update `model_compilation()` to set `test=true` when `keep_testing_functions=true`

## Proof of Concept

**Rust unit test demonstrating the inconsistency:**

```rust
#[test]
fn test_flag_inconsistency_vulnerability() {
    use move_compiler::shared::Flags;
    
    // Create flags with dangerous combination
    let flags = Flags::empty()
        .set_keep_testing_functions(true);
    
    // This is the bug: keep_testing_functions() returns true
    // but is_testing() returns false
    assert_eq!(flags.keep_testing_functions(), true);
    assert_eq!(flags.is_testing(), false);
    
    // This means:
    // - Test functions will NOT be filtered (keep_testing_functions is true)
    // - Poison function will NOT be added (is_testing is false)
    // Result: Test code in production without safety checks!
}

#[test]
fn test_model_compilation_has_vulnerability() {
    use move_compiler::shared::Flags;
    
    let flags = Flags::model_compilation();
    
    // model_compilation() creates the vulnerable state
    assert_eq!(flags.keep_testing_functions(), true); // test functions kept
    assert_eq!(flags.is_testing(), false); // no poison function
}
```

**Move module compilation test:**

```move
module 0x1::TestModule {
    #[test_only]
    public fun dangerous_test_function(): u64 {
        // This function should NEVER appear in production
        999
    }
    
    public fun production_function(): u64 {
        42
    }
}
```

Compile with `keep_testing_functions=true, test=false`:
- `dangerous_test_function` will be in the bytecode
- No `unit_test_poison` function will be present
- Module can be published on production chain

**Notes:**

This is a **design flaw** in the flag system that creates a dangerous API surface. The inconsistency between `keep_testing_functions()` and `is_testing()` breaks the safety mechanism intended to prevent test code deployment. While current standard compilation paths are safe, the public API allows this vulnerable state, and `model_compilation()` already uses it.

### Citations

**File:** third_party/move/move-compiler-v2/legacy-move-compiler/src/shared/mod.rs (L438-447)
```rust
    pub fn model_compilation() -> Self {
        Self {
            test: false,
            verify: true,
            shadow: true, // allows overlapping between sources and deps
            keep_testing_functions: true,
            lang_v2: true,
            ..Self::empty()
        }
    }
```

**File:** third_party/move/move-compiler-v2/legacy-move-compiler/src/shared/mod.rs (L456-461)
```rust
    pub fn set_keep_testing_functions(self, value: bool) -> Self {
        Self {
            keep_testing_functions: value,
            ..self
        }
    }
```

**File:** third_party/move/move-compiler-v2/legacy-move-compiler/src/shared/mod.rs (L474-480)
```rust
    pub fn is_testing(&self) -> bool {
        self.test
    }

    pub fn keep_testing_functions(&self) -> bool {
        self.test || self.keep_testing_functions
    }
```

**File:** third_party/move/move-compiler-v2/legacy-move-compiler/src/unit_test/filter_test_members.rs (L47-55)
```rust
        // instrument the test poison
        if !self.env.flags().is_testing() {
            return Some(module_def);
        }

        let poison_function = create_test_poison(module_def.loc);
        module_def.members.push(poison_function);
        Some(module_def)
    }
```

**File:** third_party/move/move-compiler-v2/legacy-move-compiler/src/unit_test/filter_test_members.rs (L224-235)
```rust
fn should_remove_node(env: &CompilationEnv, attrs: &[P::Attributes], is_source_def: bool) -> bool {
    use known_attributes::TestingAttribute;
    let flattened_attrs: Vec<_> = attrs.iter().flat_map(test_attributes).collect();
    let is_test_only = flattened_attrs
        .iter()
        .any(|attr| matches!(attr.1, TestingAttribute::Test | TestingAttribute::TestOnly));
    is_test_only && !env.flags().keep_testing_functions()
        || (!is_source_def
            && flattened_attrs
                .iter()
                .any(|attr| attr.1 == TestingAttribute::Test))
}
```

**File:** aptos-move/aptos-vm/src/natives.rs (L161-185)
```rust
pub fn assert_no_test_natives(err_msg: &str) {
    assert!(
        aptos_natives(
            LATEST_GAS_FEATURE_VERSION,
            NativeGasParameters::zeros(),
            MiscGasParameters::zeros(),
            TimedFeaturesBuilder::enable_all().build(),
            Features::default()
        )
        .into_iter()
        .all(|(_, module_name, func_name, _)| {
            !(module_name.as_str() == "unit_test"
                && func_name.as_str() == "create_signers_for_testing"
                || module_name.as_str() == "ed25519"
                    && func_name.as_str() == "generate_keys_internal"
                || module_name.as_str() == "ed25519" && func_name.as_str() == "sign_internal"
                || module_name.as_str() == "multi_ed25519"
                    && func_name.as_str() == "generate_keys_internal"
                || module_name.as_str() == "multi_ed25519" && func_name.as_str() == "sign_internal"
                || module_name.as_str() == "bls12381"
                    && func_name.as_str() == "generate_keys_internal"
                || module_name.as_str() == "bls12381" && func_name.as_str() == "sign_internal"
                || module_name.as_str() == "bls12381"
                    && func_name.as_str() == "generate_proof_of_possession_internal"
                || module_name.as_str() == "event"
```

**File:** third_party/move/move-model/src/lib.rs (L102-108)
```rust
        Flags::model_compilation()
            .set_warn_of_deprecation_use(warn_of_deprecation_use)
            .set_warn_of_deprecation_use_in_aptos_libs(warn_of_deprecation_use_in_aptos_libs)
            .set_skip_attribute_checks(skip_attribute_checks)
            .set_verify(compile_verify_code)
            .set_keep_testing_functions(compile_test_code)
            .set_language_version(language_version.into()),
```

**File:** third_party/move/tools/move-package/src/compilation/compiled_package.rs (L585-589)
```rust
        let mut flags = if resolution_graph.build_options.test_mode {
            Flags::testing()
        } else {
            Flags::empty()
        };
```

**File:** third_party/move/tools/move-package/src/compilation/compiled_package.rs (L664-664)
```rust
                        compile_test_code: flags.keep_testing_functions(),
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1715-1716)
```rust
            verify_module_metadata_for_module_publishing(m, self.features())
                .map_err(|err| Self::metadata_validation_error(&err.to_string()))?;
```

**File:** types/src/vm/module_metadata.rs (L441-518)
```rust
pub fn verify_module_metadata_for_module_publishing(
    module: &CompiledModule,
    features: &Features,
) -> Result<(), MetaDataValidationError> {
    if features.is_enabled(FeatureFlag::SAFER_METADATA) {
        check_module_complexity(module)?;
    }

    if features.are_resource_groups_enabled() {
        check_metadata_format(module)?;
    }
    let metadata = if let Some(metadata) = get_metadata_from_compiled_code(module) {
        metadata
    } else {
        return Ok(());
    };

    let functions = module
        .function_defs
        .iter()
        .map(|func_def| {
            let func_handle = module.function_handle_at(func_def.function);
            let name = module.identifier_at(func_handle.name);
            (name, (func_handle, func_def))
        })
        .collect::<BTreeMap<_, _>>();

    for (fun, attrs) in &metadata.fun_attributes {
        for attr in attrs {
            if attr.is_view_function() {
                is_valid_view_function(module, &functions, fun)?;
            } else if attr.is_randomness() {
                is_valid_unbiasable_function(&functions, fun)?;
            } else {
                return Err(AttributeValidationError {
                    key: fun.clone(),
                    attribute: attr.kind,
                }
                .into());
            }
        }
    }

    let structs = module
        .struct_defs
        .iter()
        .map(|struct_def| {
            let struct_handle = module.struct_handle_at(struct_def.struct_handle);
            let name = module.identifier_at(struct_handle.name);
            (name, (struct_handle, struct_def))
        })
        .collect::<BTreeMap<_, _>>();

    for (struct_, attrs) in &metadata.struct_attributes {
        for attr in attrs {
            if features.are_resource_groups_enabled() {
                if attr.is_resource_group() && attr.get_resource_group().is_some() {
                    is_valid_resource_group(&structs, struct_)?;
                    continue;
                } else if attr.is_resource_group_member()
                    && attr.get_resource_group_member().is_some()
                {
                    is_valid_resource_group_member(&structs, struct_)?;
                    continue;
                }
            }
            if features.is_module_event_enabled() && attr.is_event() {
                continue;
            }
            return Err(AttributeValidationError {
                key: struct_.clone(),
                attribute: attr.kind,
            }
            .into());
        }
    }
    Ok(())
}
```
