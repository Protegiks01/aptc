# Audit Report

## Title
Information Disclosure via Module Location Leakage in Publishing Error Paths

## Summary
The `create_with_compat_config()` function in the Move VM runtime's module publishing code fails to consistently sanitize error locations to `Location::Undefined`. Multiple error paths preserve `Location::Module(...)` information, leaking module identifiers during publishing failures.

## Finding Description
While most errors in `create_with_compat_config()` are explicitly set to `Location::Undefined` at the designated lines (151, 170, 191, 216, 287), several error propagation paths fail to sanitize location information: [1](#0-0) [2](#0-1) [3](#0-2) 

However, errors propagated from dependent function calls are not sanitized:

**Path 1: Cyclic Dependency Detection (Eager Verification)** [4](#0-3) 

This calls into module storage verification: [5](#0-4) 

The cyclic dependency error macro explicitly sets `Location::Module`: [6](#0-5) 

**Path 2: Module Verification Errors**

Bytecode verifiers set `Location::Module` for errors: [7](#0-6) 

When these errors occur during lazy verification, they pass through `expect_no_verification_errors` which **preserves** the location field: [8](#0-7) [9](#0-8) 

## Impact Explanation
This is a **Low severity** information disclosure issue per Aptos bug bounty criteria. The leaked `Location::Module(ModuleId)` reveals:
- The specific module (address + name) where verification failed
- Internal processing order during module verification

The attacker already knows all modules in their published bundle, so the leaked information provides minimal additional intelligence about implementation details. This does not lead to funds loss, consensus violations, or availability issues.

## Likelihood Explanation
This issue triggers whenever:
1. A user publishes modules with cyclic dependencies (eager verification path)
2. A user publishes modules that fail bytecode verification (both paths)

Likelihood: **High** - Any module publishing failure can trigger the leak.

## Recommendation
Wrap all error propagation points with explicit location sanitization:

```rust
// Line 279 - Eager verification path
staged_module_storage
    .unmetered_get_eagerly_verified_module(addr, name)
    .map_err(|e| e.finish(Location::Undefined))?
    .ok_or_else(|| {
        // existing error handling
    })?;

// Line 267-269 - Lazy verification path  
let dependency = staged_module_storage
    .unmetered_get_existing_lazily_verified_module(
        &ModuleId::new(*dep_addr, dep_name.to_owned()),
    )
    .map_err(|e| e.finish(Location::Undefined))?;
```

Additionally, modify `expect_no_verification_errors` to always use `Location::Undefined`:

```rust
.finish(Location::Undefined) // Instead of .finish(location)
```

## Proof of Concept
```rust
// Create two modules with cyclic dependencies
// Module A depends on B, Module B depends on A

// Module A bytecode (pseudo-code)
module 0xALICE::ModuleA {
    use 0xALICE::ModuleB;
    // ... module code
}

// Module B bytecode (pseudo-code)  
module 0xALICE::ModuleB {
    use 0xALICE::ModuleA;
    // ... module code
}

// Publish bundle containing both modules
// Expected: Error with Location::Undefined
// Actual: Error with Location::Module(0xALICE::ModuleA) or Location::Module(0xALICE::ModuleB)
// revealing which module was being processed when the cycle was detected
```

## Notes
While this vulnerability exists as described, its security impact is minimal. The leaked module identifier information is already known to the attacker (they are publishing these modules), and the additional intelligence about verification order provides limited exploitation value. This represents a defensive programming issue rather than a critical security flaw.

### Citations

**File:** third_party/move/move-vm/runtime/src/storage/publishing.rs (L146-152)
```rust
                    .map_err(|err| {
                        err.append_message_with_separator(
                            '\n',
                            "[VM] module deserialization failed".to_string(),
                        )
                        .finish(Location::Undefined)
                    })?;
```

**File:** third_party/move/move-vm/runtime/src/storage/publishing.rs (L164-171)
```rust
                return Err(verification_error(
                    StatusCode::MODULE_ADDRESS_DOES_NOT_MATCH_SENDER,
                    IndexKind::AddressIdentifier,
                    compiled_module.self_handle_idx().0,
                )
                .with_message(msg)
                .finish(Location::Undefined));
            }
```

**File:** third_party/move/move-vm/runtime/src/storage/publishing.rs (L189-191)
```rust
                        compatibility
                            .check(old_module, &compiled_module)
                            .map_err(|e| e.finish(Location::Undefined))?;
```

**File:** third_party/move/move-vm/runtime/src/storage/publishing.rs (L276-289)
```rust
            } else {
                // Verify the module and its dependencies, and that they do not form a cycle.
                staged_module_storage
                    .unmetered_get_eagerly_verified_module(addr, name)?
                    .ok_or_else(|| {
                        PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                            .with_message(format!(
                                "Staged module {}::{} must always exist",
                                compiled_module.self_addr(),
                                compiled_module.self_name()
                            ))
                            .finish(Location::Undefined)
                    })?;
            }
```

**File:** third_party/move/move-vm/runtime/src/storage/module_storage.rs (L162-169)
```rust
    fn unmetered_get_existing_lazily_verified_module(
        &self,
        module_id: &ModuleId,
    ) -> VMResult<Arc<Module>> {
        self.unmetered_get_lazily_verified_module(module_id)
            .map_err(expect_no_verification_errors)?
            .ok_or_else(|| module_linker_error!(module_id.address(), module_id.name()))
    }
```

**File:** third_party/move/move-vm/runtime/src/storage/module_storage.rs (L345-416)
```rust
fn visit_dependencies_and_verify<T, E, V>(
    module_id: ModuleId,
    module: Arc<ModuleCode<CompiledModule, Module, E>>,
    version: V,
    visited: &mut HashSet<ModuleId>,
    module_cache_with_context: &T,
) -> VMResult<Arc<Module>>
where
    T: WithRuntimeEnvironment
        + ModuleCache<
            Key = ModuleId,
            Deserialized = CompiledModule,
            Verified = Module,
            Extension = E,
            Version = V,
        > + ModuleCodeBuilder<
            Key = ModuleId,
            Deserialized = CompiledModule,
            Verified = Module,
            Extension = E,
        >,
    E: WithBytes + WithSize + WithHash,
    V: Clone + Default + Ord,
{
    let runtime_environment = module_cache_with_context.runtime_environment();

    // Step 1: Local verification.
    runtime_environment.paranoid_check_module_address_and_name(
        module.code().deserialized(),
        module_id.address(),
        module_id.name(),
    )?;
    let locally_verified_code = runtime_environment.build_locally_verified_module(
        module.code().deserialized().clone(),
        module.extension().size_in_bytes(),
        module.extension().hash(),
    )?;

    // Step 2: Traverse and collect all verified immediate dependencies so that we can verify
    // non-local properties of the module.
    let mut verified_dependencies = vec![];
    for (addr, name) in locally_verified_code.immediate_dependencies_iter() {
        let dependency_id = ModuleId::new(*addr, name.to_owned());

        let (dependency, dependency_version) = module_cache_with_context
            .get_module_or_build_with(&dependency_id, module_cache_with_context)?
            .ok_or_else(|| module_linker_error!(addr, name))?;

        // Dependency is already verified!
        if dependency.code().is_verified() {
            verified_dependencies.push(dependency.code().verified().clone());
            continue;
        }

        if visited.insert(dependency_id.clone()) {
            // Dependency is not verified, and we have not visited it yet.
            let verified_dependency = visit_dependencies_and_verify(
                dependency_id.clone(),
                dependency,
                dependency_version,
                visited,
                module_cache_with_context,
            )?;
            verified_dependencies.push(verified_dependency);
        } else {
            // We must have found a cycle otherwise.
            return Err(module_cyclic_dependency_error!(
                dependency_id.address(),
                dependency_id.name()
            ));
        }
    }
```

**File:** third_party/move/move-vm/types/src/code/errors.rs (L37-49)
```rust
macro_rules! module_cyclic_dependency_error {
    ($addr:expr, $name:expr) => {
        move_binary_format::errors::PartialVMError::new(
            move_core_types::vm_status::StatusCode::CYCLIC_MODULE_DEPENDENCY,
        )
        .with_message(format!(
            "Module {}::{} forms a cyclic dependency",
            $addr, $name
        ))
        .finish(move_binary_format::errors::Location::Module(
            move_core_types::language_storage::ModuleId::new(*$addr, $name.to_owned()),
        ))
    };
```

**File:** third_party/move/move-bytecode-verifier/src/check_duplication.rs (L32-34)
```rust
    pub fn verify_module(module: &'a CompiledModule) -> VMResult<()> {
        Self::verify_module_impl(module).map_err(|e| e.finish(Location::Module(module.self_id())))
    }
```

**File:** third_party/move/move-vm/runtime/src/logging.rs (L11-42)
```rust
pub fn expect_no_verification_errors(err: VMError) -> VMError {
    match err.status_type() {
        status_type @ StatusType::Deserialization | status_type @ StatusType::Verification => {
            let message = format!(
                "Unexpected verifier/deserialization error! This likely means there is code \
                stored on chain that is unverifiable!\nError: {:?}",
                &err
            );
            let (
                _old_status,
                _old_sub_status,
                _old_message,
                _stacktrace,
                location,
                indices,
                offsets,
            ) = err.all_data();
            let major_status = match status_type {
                StatusType::Deserialization => StatusCode::UNEXPECTED_DESERIALIZATION_ERROR,
                StatusType::Verification => StatusCode::UNEXPECTED_VERIFIER_ERROR,
                _ => unreachable!(),
            };

            PartialVMError::new(major_status)
                .with_message(message)
                .at_indices(indices)
                .at_code_offsets(offsets)
                .finish(location)
        },
        _ => err,
    }
}
```
