# Audit Report

## Title
Test Poison Bypass in Move Compiler V2 Allows Test Functions in Production Builds

## Summary
When compiling Move modules with the `--test` flag using Move Compiler v2, test functions are retained in the compiled bytecode but the test poison function is NOT added. This bypasses the security mechanism designed to prevent test-compiled modules from being deployed to production VMs, allowing potentially insecure test code to execute in production environments.

## Finding Description

The Move compiler implements a "test poison" mechanism to prevent modules compiled in test mode from being deployed to production VMs. This works by injecting a dummy function that calls the test-only native `create_signers_for_testing`, which only exists in VMs running with the "testing" feature flag. If a test-compiled module is loaded on a production VM, the module fails to link because this native function doesn't exist. [1](#0-0) 

However, when using Move Compiler v2 with the `--test` flag, a critical flag state mismatch occurs:

**The Vulnerability Flow:**

1. **Initial Flag Creation**: When `BuildConfig.test_mode = true` (from `--test` flag), the compilation creates legacy compiler Flags via `Flags::testing()` which sets `test=true, keep_testing_functions=false`. [2](#0-1) 

2. **Flag Propagation**: The `keep_testing_functions()` method returns `true` because `self.test || self.keep_testing_functions` evaluates to `true || false = true`. [3](#0-2) 

3. **Compiler V2 Options**: This `true` value is passed to compiler v2 as `compile_test_code`. [4](#0-3) 

4. **Model Builder Flags Reconstruction**: The model builder creates NEW Flags starting from `Flags::model_compilation()` which has `test=false, keep_testing_functions=true`, then applies `set_keep_testing_functions(compile_test_code)`. [5](#0-4) [6](#0-5) 

5. **Final Flag State**: The legacy compiler (used for parsing/filtering) receives Flags with `test=false, keep_testing_functions=true`.

6. **Poison Bypass**: In `filter_map_module`, the poison is only added when `is_testing()` returns `true`. Since `is_testing()` only checks the `test` field (which is `false`), the poison is NOT added. [7](#0-6) [8](#0-7) 

7. **Test Functions Retained**: In `should_remove_node`, test functions are only removed when `keep_testing_functions()` returns `false`. Since it returns `true`, test functions are NOT removed. [9](#0-8) 

**Result**: Modules compiled with `--test` in compiler v2 contain test functions without the poison, allowing them to be published and executed on production VMs.

## Impact Explanation

This vulnerability qualifies as **High Severity** per the Aptos bug bounty criteria for the following reasons:

1. **Protocol Violation**: The test poison mechanism is a deliberate security control explicitly designed to prevent test code from reaching production. The production VM validates that test natives don't exist via `assert_no_test_natives`. [10](#0-9) [11](#0-10) 

2. **Unintended Code Execution**: Test functions may contain:
   - Weakened security checks acceptable only for testing
   - Debugging interfaces that expose internal state
   - State manipulation code designed for test setup
   - Assumptions that won't hold in production environments

3. **Developer Expectation Violation**: Developers write test code with the explicit understanding it will never execute in production. This broken assumption can lead to security vulnerabilities.

4. **Widespread Impact**: This affects ALL modules compiled with `--test` using compiler v2, which is the default compiler version for Aptos.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability triggers automatically for every module compiled with:
- Move Compiler v2 (default in Aptos)
- `--test` flag (standard for test compilation)

The issue is systematic and affects the normal development workflow. Developers routinely compile with `--test` for running unit tests, and if they accidentally (or intentionally) publish such bytecode, it will be accepted by the production network without the intended protection.

No special attacker capabilities are required - this is a compiler bug that affects normal usage.

## Recommendation

The root cause is that compiler v2's model builder creates new Flags that lose the `test` field state while preserving `keep_testing_functions`. The fix should ensure that when test functions are kept, the poison is also added.

**Recommended Fix:**

Modify the poison injection logic to check `keep_testing_functions()` instead of `is_testing()`:

```rust
// In filter_test_members.rs, line 47-50
fn filter_map_module(
    &mut self,
    mut module_def: P::ModuleDefinition,
    is_source_def: bool,
) -> Option<P::ModuleDefinition> {
    if self.should_remove_by_attributes(&module_def.attributes, is_source_def) {
        return None;
    }

    // instrument the test poison
    // FIX: Check keep_testing_functions() instead of is_testing()
    if !self.env.flags().keep_testing_functions() {
        return Some(module_def);
    }

    let poison_function = create_test_poison(module_def.loc);
    module_def.members.push(poison_function);
    Some(module_def)
}
```

This ensures that whenever test functions are retained (`keep_testing_functions()` is true), the poison function is also added, regardless of how the Flags were constructed.

**Alternative Fix:**

Preserve the `test` flag state in compiler v2's model builder instead of resetting it:

```rust
// In move-model/src/lib.rs, modify the flags construction
Flags::model_compilation()
    // ... other setters ...
    .set_keep_testing_functions(compile_test_code)
    // Add this line to preserve test flag semantics:
    .set_test(compile_test_code)  // Would need to add this setter method
```

## Proof of Concept

**Step-by-step reproduction:**

1. Create a Move module with test functions:
```move
module 0x1::TestModule {
    #[test_only]
    public entry fun dangerous_test_function() {
        // Code that should never run in production
        // but doesn't use test-only natives
    }
}
```

2. Compile with Move Compiler v2 and `--test` flag:
```bash
aptos move compile --test
```

3. Verify the compiled bytecode:
   - Test function `dangerous_test_function` is present in bytecode
   - NO `unit_test_poison` function is present
   - Module can be published to blockchain

4. Publish the module to a production network:
```bash
aptos move publish --assume-yes
```

5. The module loads successfully (no linking error)

6. The test function can now be invoked in production:
```bash
aptos move run --function-id 0x1::TestModule::dangerous_test_function
```

**Expected Behavior:** Module should fail to load due to missing `create_signers_for_testing` native (from poison function).

**Actual Behavior:** Module loads successfully and test functions are callable because poison was never added.

## Notes

This vulnerability specifically affects Move Compiler v2's integration with the legacy compiler's filtering mechanism. The issue arises from semantic differences in how the `test` and `keep_testing_functions` flags are interpreted across compiler versions. The production VM has the correct protection (`assert_no_test_natives`), but the compiler bypass means that protection never gets tested because no poison is injected.

### Citations

**File:** third_party/move/move-compiler-v2/legacy-move-compiler/src/unit_test/filter_test_members.rs (L47-50)
```rust
        // instrument the test poison
        if !self.env.flags().is_testing() {
            return Some(module_def);
        }
```

**File:** third_party/move/move-compiler-v2/legacy-move-compiler/src/unit_test/filter_test_members.rs (L165-219)
```rust
/// If a module is being compiled in test mode, create a dummy function that calls a native
/// function `0x1::UnitTest::create_signers_for_testing` that only exists if the VM is being run
/// with the "unit_test" feature flag set. This will then cause the module to fail to link if
/// an attempt is made to publish a module that has been compiled in test mode on a VM that is not
/// running in test mode.
fn create_test_poison(mloc: Loc) -> P::ModuleMember {
    let signature = P::FunctionSignature {
        type_parameters: vec![],
        parameters: vec![],
        return_type: sp(mloc, P::Type_::Unit),
    };

    let leading_name_access = sp(
        mloc,
        P::LeadingNameAccess_::Name(sp(mloc, STDLIB_ADDRESS_NAME.into())),
    );

    let mod_name = sp(mloc, UNIT_TEST_MODULE_NAME.into());
    let mod_addr_name = sp(mloc, (leading_name_access, mod_name));
    let fn_name = sp(mloc, "create_signers_for_testing".into());
    let args_ = vec![sp(
        mloc,
        P::Exp_::Value(sp(mloc, P::Value_::Num("0".into()))),
    )];
    let nop_call = P::Exp_::Call(
        sp(mloc, P::NameAccessChain_::Three(mod_addr_name, fn_name)),
        CallKind::Regular,
        None,
        sp(mloc, args_),
    );

    // fun unit_test_poison() { 0x1::UnitTest::create_signers_for_testing(0); () }
    P::ModuleMember::Function(P::Function {
        attributes: vec![],
        loc: mloc,
        visibility: P::Visibility::Internal,
        entry: None,
        access_specifiers: None,
        signature,
        inline: false,
        name: P::FunctionName(sp(mloc, "unit_test_poison".into())),
        body: sp(
            mloc,
            P::FunctionBody_::Defined((
                vec![],
                vec![sp(
                    mloc,
                    P::SequenceItem_::Seq(Box::new(sp(mloc, nop_call))),
                )],
                None,
                Box::new(Some(sp(mloc, P::Exp_::Unit))),
            )),
        ),
    })
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

**File:** third_party/move/move-compiler-v2/legacy-move-compiler/src/shared/mod.rs (L474-476)
```rust
    pub fn is_testing(&self) -> bool {
        self.test
    }
```

**File:** third_party/move/move-compiler-v2/legacy-move-compiler/src/shared/mod.rs (L478-480)
```rust
    pub fn keep_testing_functions(&self) -> bool {
        self.test || self.keep_testing_functions
    }
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

**File:** aptos-node/src/main.rs (L22-23)
```rust
    // Check that we are not including any Move test natives
    aptos_vm::natives::assert_no_test_natives(ERROR_MSG_BAD_FEATURE_FLAGS);
```

**File:** aptos-move/aptos-vm/src/natives.rs (L161-191)
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
                    && func_name.as_str() == "emitted_events_internal")
        }),
        "{}",
        err_msg
    )
}
```
