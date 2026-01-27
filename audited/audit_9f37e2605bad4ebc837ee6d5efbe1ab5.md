# Audit Report

## Title
Unprotected Panic Path in Script Dependency Verification During Transaction Execution

## Summary
Script dependency verification (`dependencies::verify_script`) lacks panic-catching protection during transaction execution, creating a gap in the panic handling mechanism that could crash validator nodes if a verifier panic occurs, potentially causing network disruption.

## Finding Description

The Move bytecode verifier implements a two-stage verification process for scripts during transaction execution:

**Stage 1 - Local Verification (Protected):** [1](#0-0) 

This stage wraps all local bytecode verification in `std::panic::catch_unwind` and sets `VMState::VERIFIER` before verification.

**Stage 2 - Dependency Verification (Unprotected):** [2](#0-1) 

This stage calls `dependencies::verify_script` directly without `catch_unwind` protection and without setting `VMState::VERIFIER`.

**Transaction Execution Flow:** [3](#0-2) 

During script loading in transaction execution, both stages are called sequentially. After Stage 1 completes, `VMState` is restored to its previous value (typically `OTHER`).

**Crash Handler Behavior:** [4](#0-3) 

The crash handler only prevents process termination when `VMState` is `VERIFIER` or `DESERIALIZER`. If a panic occurs in `dependencies::verify_script`, the crash handler will kill the process.

**Potential Panic Sources:** [5](#0-4) 

The `safe_unwrap!` macro used in dependency verification panics in debug mode but returns errors in release mode. However, other implicit panics (index out of bounds, unwrap failures, arithmetic overflows) could still occur in release builds if bugs exist in the verification logic. [6](#0-5) [7](#0-6) 

## Impact Explanation

**Severity: Critical**

If a panic occurs in `dependencies::verify_script` during transaction execution:
1. The panic will NOT be caught (no `catch_unwind` wrapper)
2. `VMState` will NOT be `VERIFIER` (already restored after Stage 1)
3. The crash handler will kill the validator process
4. Transaction state cannot be properly rolled back (process is dead)
5. All validators processing the same malicious transaction would crash
6. This could cause **network-wide validator failure** and **total loss of liveness**

This meets the **Critical Severity** criteria: "Total loss of liveness/network availability" and "Non-recoverable network partition (requires hardfork)" if the issue persists.

## Likelihood Explanation

**Likelihood: Low to Medium**

The vulnerability requires:
1. A bug in `dependencies::verify_script` that triggers a panic in release mode
2. A malicious script that can trigger this bug
3. The script must pass deserialization and local verification (both protected)

While `safe_unwrap!` only panics in debug mode, other panic sources could exist:
- Index out of bounds errors
- Unwrap failures on unexpected None values
- Arithmetic overflows
- Logic bugs causing unreachable code panics

The architectural flaw is confirmed, but exploitation requires discovering a specific panic-inducing bug in the dependency verification code.

## Recommendation

Wrap `dependencies::verify_script` call in the same panic-catching mechanism used for local verification:

```rust
pub fn build_verified_script(
    &self,
    locally_verified_script: LocallyVerifiedScript,
    immediate_dependencies: &[Arc<Module>],
) -> VMResult<Script> {
    // Set VMState and wrap in catch_unwind for consistency
    let prev_state = move_core_types::state::set_state(VMState::VERIFIER);
    let result = std::panic::catch_unwind(|| {
        dependencies::verify_script(
            &self.vm_config.verifier_config,
            locally_verified_script.0.as_ref(),
            immediate_dependencies
                .iter()
                .map(|module| module.as_ref().as_ref()),
        )
    })
    .unwrap_or_else(|_| {
        Err(
            PartialVMError::new(StatusCode::VERIFIER_INVARIANT_VIOLATION)
                .with_message("[VM] dependency verifier panicked for script".to_string())
                .finish(Location::Script),
        )
    });
    move_core_types::state::set_state(prev_state);
    
    result?;
    
    Script::new(
        locally_verified_script.0,
        self.struct_name_index_map(),
        self.ty_pool(),
        self.module_id_pool(),
    )
    .map_err(|err| err.finish(Location::Script))
}
```

Apply the same fix to `build_verified_module_with_linking_checks` for consistency.

## Proof of Concept

**Note:** A complete PoC requires identifying a specific bug in `dependencies::verify_script` that triggers a panic. The following demonstrates the architectural gap:

```rust
// Test to verify the panic handling gap
#[test]
#[should_panic]
fn test_dependency_verification_panic_unprotected() {
    use fail::FailScenario;
    
    // This test would require injecting a failpoint in dependencies::verify_script
    // similar to the one at verifier.rs:161, but currently no such failpoint exists
    
    // The test in catch_unwind.rs only tests verify_module_with_config:
    // third_party/move/move-bytecode-verifier/bytecode-verifier-tests/src/unit_tests/catch_unwind.rs
    
    // To fully demonstrate this, a failpoint would need to be added to dependencies.rs:
    // fail::fail_point!("dependency-verifier-failpoint-panic");
    
    // Then this test would show that panics in dependency verification are NOT caught
    // and WOULD kill the process (unlike panics in verify_module_with_config)
}
```

The existing test only covers local verification: [8](#0-7) 

## Notes

This is an **architectural vulnerability** where the panic protection mechanism is incomplete. While exploitation requires discovering a specific panic-inducing bug in dependency verification code, the architectural flaw violates the defense-in-depth principle and creates an unprotected attack surface. The same panic-catching pattern should be applied uniformly across all verification stages to maintain system resilience.

### Citations

**File:** third_party/move/move-bytecode-verifier/src/verifier.rs (L189-222)
```rust
pub fn verify_script_with_config(config: &VerifierConfig, script: &CompiledScript) -> VMResult<()> {
    if config.verify_nothing() {
        return Ok(());
    }
    let prev_state = move_core_types::state::set_state(VMState::VERIFIER);
    let result = std::panic::catch_unwind(|| {
        // Always needs to run bound checker first as subsequent passes depend on it
        BoundsChecker::verify_script(script).map_err(|e| {
            // We can't point the error at the script, because if bounds-checking
            // failed, we cannot safely index into script
            e.finish(Location::Undefined)
        })?;
        FeatureVerifier::verify_script(config, script)?;
        LimitsVerifier::verify_script(config, script)?;
        DuplicationChecker::verify_script(script)?;

        signature_v2::verify_script(config, script)?;

        InstructionConsistency::verify_script(script)?;
        constants::verify_script(script)?;
        CodeUnitVerifier::verify_script(config, script)?;
        script_signature::verify_script(script, no_additional_script_signature_checks)
    })
    .unwrap_or_else(|_| {
        Err(
            PartialVMError::new(StatusCode::VERIFIER_INVARIANT_VIOLATION)
                .with_message("[VM] bytecode verifier panicked for script".to_string())
                .finish(Location::Undefined),
        )
    });
    move_core_types::state::set_state(prev_state);

    result
}
```

**File:** third_party/move/move-vm/runtime/src/storage/environment.rs (L154-173)
```rust
    pub fn build_verified_script(
        &self,
        locally_verified_script: LocallyVerifiedScript,
        immediate_dependencies: &[Arc<Module>],
    ) -> VMResult<Script> {
        dependencies::verify_script(
            &self.vm_config.verifier_config,
            locally_verified_script.0.as_ref(),
            immediate_dependencies
                .iter()
                .map(|module| module.as_ref().as_ref()),
        )?;
        Script::new(
            locally_verified_script.0,
            self.struct_name_index_map(),
            self.ty_pool(),
            self.module_id_pool(),
        )
        .map_err(|err| err.finish(Location::Script))
    }
```

**File:** third_party/move/move-vm/runtime/src/storage/loader/lazy.rs (L120-166)
```rust
    fn metered_verify_and_cache_script(
        &self,
        gas_meter: &mut impl DependencyGasMeter,
        traversal_context: &mut TraversalContext,
        serialized_script: &[u8],
    ) -> VMResult<Arc<Script>> {
        use Code::*;

        let hash = sha3_256(serialized_script);
        let deserialized_script = match self.module_storage.get_script(&hash) {
            Some(Verified(script)) => {
                // Before returning early, meter modules because script might have been cached by
                // other thread.
                for (addr, name) in script.immediate_dependencies_iter() {
                    let module_id = ModuleId::new(*addr, name.to_owned());
                    self.charge_module(gas_meter, traversal_context, &module_id)
                        .map_err(|err| err.finish(Location::Undefined))?;
                }
                return Ok(script);
            },
            Some(Deserialized(deserialized_script)) => deserialized_script,
            None => self
                .runtime_environment()
                .deserialize_into_script(serialized_script)
                .map(Arc::new)?,
        };

        let locally_verified_script = self
            .runtime_environment()
            .build_locally_verified_script(deserialized_script)?;

        let immediate_dependencies = locally_verified_script
            .immediate_dependencies_iter()
            .map(|(addr, name)| {
                let module_id = ModuleId::new(*addr, name.to_owned());
                self.metered_load_module(gas_meter, traversal_context, &module_id)
            })
            .collect::<VMResult<Vec<_>>>()?;

        let verified_script = self
            .runtime_environment()
            .build_verified_script(locally_verified_script, &immediate_dependencies)?;

        Ok(self
            .module_storage
            .insert_verified_script(hash, verified_script))
    }
```

**File:** crates/crash-handler/src/lib.rs (L48-57)
```rust
    // Do not kill the process if the panics happened at move-bytecode-verifier.
    // This is safe because the `state::get_state()` uses a thread_local for storing states. Thus the state can only be mutated to VERIFIER by the thread that's running the bytecode verifier.
    //
    // TODO: once `can_unwind` is stable, we should assert it. See https://github.com/rust-lang/rust/issues/92988.
    if state::get_state() == VMState::VERIFIER || state::get_state() == VMState::DESERIALIZER {
        return;
    }

    // Kill the process
    process::exit(12);
```

**File:** third_party/move/move-binary-format/src/lib.rs (L138-152)
```rust
macro_rules! safe_unwrap {
    ($e:expr) => {{
        match $e {
            Some(x) => x,
            None => {
                let err = PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                    .with_message(format!("{}:{} (none)", file!(), line!()));
                if cfg!(debug_assertions) {
                    panic!("{:?}", err);
                } else {
                    return Err(err);
                }
            },
        }
    }};
```

**File:** third_party/move/move-bytecode-verifier/src/dependencies.rs (L247-247)
```rust
        let owner_module = safe_unwrap!(context.dependency_map.get(&owner_module_id));
```

**File:** third_party/move/move-bytecode-verifier/src/dependencies.rs (L291-291)
```rust
        let owner_module = safe_unwrap!(context.dependency_map.get(&owner_module_id));
```

**File:** third_party/move/move-bytecode-verifier/bytecode-verifier-tests/src/unit_tests/catch_unwind.rs (L14-29)
```rust
#[ignore]
#[test]
fn test_unwind() {
    let scenario = FailScenario::setup();
    fail::cfg("verifier-failpoint-panic", "panic").unwrap();

    panic::set_hook(Box::new(move |_: &PanicHookInfo<'_>| {
        assert_eq!(state::get_state(), VMState::VERIFIER);
    }));

    let m = empty_module();
    let res = move_bytecode_verifier::verify_module_with_config(&VerifierConfig::unbounded(), &m)
        .unwrap_err();
    assert_eq!(res.major_status(), StatusCode::VERIFIER_INVARIANT_VIOLATION);
    scenario.teardown();
}
```
