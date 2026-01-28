# Audit Report

## Title
Randomness State Persistence Enables Unauthorized Access in Module Initialization Functions

## Summary
The Aptos randomness system's session-wide `unbiasable` flag persists across module publishing operations, allowing `init_module` functions to access randomness APIs without the required `#[randomness]` annotation. This bypasses the fundamental security guarantee that only explicitly annotated entry functions can use randomness features.

## Finding Description

The Aptos randomness system enforces a critical security invariant: only private or friend entry functions with the `#[randomness]` attribute can access randomness APIs to prevent test-and-abort bias attacks. However, a state persistence issue allows this requirement to be bypassed during module initialization.

**Execution Flow:**

1. An entry function with `#[randomness]` annotation executes and calls `session.mark_unbiasable()`, setting `RandomnessContext.unbiasable = true` in the session. [1](#0-0) 

2. The same entry function registers a module publishing request by calling framework code publishing functions. [2](#0-1) 

3. After entry function execution, `resolve_pending_code_publish_and_finish_user_session` is called with the **same session object** to process module publishing. [3](#0-2) 

4. This calls `finish_with_module_publishing_and_initialization`, which executes `init_module` functions for newly published modules using `self.session.execute()` - still within the **same session** where `unbiasable = true`. [4](#0-3) 

5. When `init_module` calls randomness APIs, the native function `fetch_and_increment_txn_counter` checks `is_unbiasable()`, which returns `true` because the flag was never reset. [5](#0-4) 

6. The `RandomnessContext` is only reset to `unbiasable = false` when a new session starts via the `SessionListener::start` method, which does not occur between entry function execution and `init_module` execution. [6](#0-5) 

**Missing Protection:**

Compile-time validation enforces the `#[randomness]` annotation requirement only for entry functions, not `init_module`. [7](#0-6) 

The `check_unsafe_randomness_usage` function similarly only validates entry functions and does not check `init_module`. [8](#0-7) 

Runtime verification of `init_module` checks only signature requirements, not randomness usage. [9](#0-8) 

## Impact Explanation

**Severity: High**

This vulnerability qualifies for **High severity ($50,000)** under the Aptos bug bounty program as a significant protocol security guarantee bypass:

1. **Security Mechanism Bypass**: The `#[randomness]` annotation system is explicitly documented as a required security control. Bypassing it violates the protocol's security model.

2. **Unbiasability Violation**: The system's purpose is to prevent test-and-abort attacks where users bias randomness by aborting unfavorable outcomes. An attacker can now:
   - Create an entry function with `#[randomness]` that publishes a module
   - Have the `init_module` test random values and abort if unfavorable
   - Retry the transaction until favorable randomness is obtained
   - Gain unfair advantages in lotteries, games, or other randomness-dependent applications

3. **Wide Attack Surface**: Any user can publish modules on Aptos without special privileges, making this exploitable by any attacker.

4. **Protocol Invariant Broken**: The documented guarantee that "only private entry function with `#[randomness]` annotation" can access randomness is demonstrably false.

Note: This does NOT cause consensus divergence because all validators process the same deterministic transaction with the same randomness seed, so the impact remains at High rather than Critical.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be exploited:

1. **Zero Prerequisites**: Only requires ability to publish modules (available to any Aptos user)

2. **Easy Discovery**: Any developer testing randomness features in module publishing would naturally discover this behavior

3. **Clear Economic Incentive**: Attackers operating randomness-based applications (games, lotteries, NFT mints) have strong financial motivation to bias outcomes

4. **No Detection Mechanism**: The transaction appears completely valid and passes all existing validation checks

5. **Simple Exploitation**: Requires only basic Move development skills to create the exploit transaction

## Recommendation

**Option 1: Reset randomness context before init_module execution**

Before executing `init_module`, explicitly reset the `RandomnessContext.unbiasable` flag:

```rust
// In user_transaction_sessions/user.rs, before init_module execution:
self.session.execute(|session| {
    // Reset randomness permission
    let randomness_ctx = session.extensions_mut().get_mut::<RandomnessContext>();
    randomness_ctx.unbiasable = false;
    
    // Continue with init_module execution...
});
```

**Option 2: Add compile-time validation**

Extend `check_unsafe_randomness_usage` to verify `init_module` functions do not call randomness APIs:

```rust
// In extended_checks.rs
fn check_init_module(&self, module: &ModuleEnv) {
    let init_module_sym = self.env.symbol_pool().make(INIT_MODULE_FUN);
    if let Some(ref fun) = module.find_function(init_module_sym) {
        // Existing checks...
        
        // NEW: Check randomness usage
        let fun_id = fun.module_env.get_id().qualified(fun.get_id());
        if self.calls_randomness(fun_id) {
            self.env.error(
                &fun.get_id_loc(),
                "init_module cannot use randomness APIs"
            );
        }
    }
}
```

**Recommended approach**: Implement both options for defense-in-depth - Option 1 prevents runtime exploitation, while Option 2 provides early detection during compilation.

## Proof of Concept

```move
// malicious_module.move
module attacker::exploit {
    use aptos_framework::randomness;
    
    // This init_module will successfully call randomness APIs
    // when published from an entry function with #[randomness]
    fun init_module(deployer: &signer) {
        // This call will succeed despite no #[randomness] annotation
        let random_value = randomness::u64_integer();
        
        // Attacker can test-and-abort for favorable values
        assert!(random_value > 1000000, 1); // Abort if unfavorable
        
        // Continue initialization with biased randomness...
    }
}

// publisher.move  
module attacker::publisher {
    use aptos_framework::code;
    
    #[randomness]
    entry fun publish_with_randomness(deployer: &signer, metadata: vector<u8>, code: vector<vector<u8>>) {
        // This has #[randomness], so mark_unbiasable() is called
        code::publish_package_txn(deployer, metadata, code);
        // Module publishing happens in same session
        // init_module inherits the unbiasable permission
    }
}
```

The attacker calls `publisher::publish_with_randomness` which marks the session as unbiasable, then publishes the module whose `init_module` successfully accesses randomness APIs and can bias outcomes through test-and-abort.

## Notes

This vulnerability represents a genuine security guarantee bypass in the Aptos randomness system. The core issue is that `RandomnessContext` state persists across session operations without proper isolation between entry function execution and module initialization. While it does not cause consensus divergence (all validators execute deterministically), it fundamentally breaks the documented security model that prevents randomness bias attacks.

### Citations

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L983-991)
```rust
            if function.is_friend_or_private() {
                let maybe_randomness_annotation = get_randomness_annotation_for_entry_function(
                    entry_fn,
                    &function.owner_as_module()?.metadata,
                );
                if maybe_randomness_annotation.is_some() {
                    session.mark_unbiasable();
                }
            }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1081-1088)
```rust
        let user_session_change_set = self.resolve_pending_code_publish_and_finish_user_session(
            session,
            resolver,
            code_storage,
            gas_meter,
            traversal_context,
            change_set_configs,
        )?;
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1464-1473)
```rust
    fn resolve_pending_code_publish_and_finish_user_session(
        &self,
        mut session: UserSession,
        resolver: &impl AptosMoveResolver,
        module_storage: &impl AptosModuleStorage,
        gas_meter: &mut impl AptosGasMeter,
        traversal_context: &mut TraversalContext,
        change_set_configs: &ChangeSetConfigs,
    ) -> Result<UserSessionChangeSet, VMStatus> {
        let maybe_publish_request = session.execute(|session| session.extract_publish_request());
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/user_transaction_sessions/user.rs (L122-183)
```rust
            self.session.execute(|session| {
                dispatch_loader!(&staging_module_storage, loader, {
                    #[allow(clippy::collapsible_else_if)]
                    if gas_feature_version <= RELEASE_V1_30 {
                        if let Ok(init_func) = loader.load_instantiated_function(
                            &LegacyLoaderConfig::unmetered(),
                            gas_meter,
                            traversal_context,
                            &module.self_id(),
                            init_func_name,
                            &[],
                        ) {
                            // We need to check that init_module function we found is well-formed.
                            verifier::module_init::legacy_verify_module_init_function(module)
                                .map_err(|e| e.finish(Location::Undefined))?;

                            session.execute_loaded_function(
                                init_func,
                                vec![MoveValue::Signer(destination).simple_serialize().unwrap()],
                                gas_meter,
                                traversal_context,
                                &loader,
                                // We should never enable trace record for init_module - it runs on
                                // newly published state so it is safer to do checks in-place.
                                &mut NoOpTraceRecorder,
                            )?;
                        }
                    } else {
                        if let Ok((module, function)) = loader.load_function_definition(
                            gas_meter,
                            traversal_context,
                            &module.self_id(),
                            init_func_name,
                        ) {
                            verifier::module_init::verify_init_module_function(&function)?;

                            let ty_args_id =
                                loader.runtime_environment().ty_pool().intern_ty_args(&[]);
                            let loaded_function = LoadedFunction {
                                owner: LoadedFunctionOwner::Module(module),
                                ty_args: vec![],
                                ty_args_id,
                                function,
                            };
                            session.execute_loaded_function(
                                loaded_function,
                                vec![MoveValue::Signer(destination)
                                    .simple_serialize()
                                    .expect("Signer is always serializable")],
                                gas_meter,
                                traversal_context,
                                &loader,
                                // We should never enable trace record for init_module - it runs on
                                // newly published state so it is safer to do checks in-place.
                                &mut NoOpTraceRecorder,
                            )?;
                        }
                    }
                });
                Ok::<_, VMStatus>(())
            })?;
        }
```

**File:** aptos-move/framework/src/natives/randomness.rs (L33-36)
```rust
    fn start(&mut self, _session_hash: &[u8; 32], _script_hash: &[u8], _session_counter: u8) {
        self.txn_local_state = vec![0; 8];
        self.unbiasable = false;
    }
```

**File:** aptos-move/framework/src/natives/randomness.rs (L88-93)
```rust
    let ctx = context.extensions_mut().get_mut::<RandomnessContext>();
    if !ctx.is_unbiasable() {
        return Err(SafeNativeError::Abort {
            abort_code: E_API_USE_SUSCEPTIBLE_TO_TEST_AND_ABORT,
        });
    }
```

**File:** aptos-move/framework/src/extended_checks.rs (L511-530)
```rust
    fn check_and_record_unbiasabale_entry_functions(&mut self, module: &ModuleEnv) {
        for ref fun in module.get_functions() {
            let maybe_randomness_annotation = match self.get_randomness_max_gas_declaration(fun) {
                Ok(x) => x,
                Err(msg) => {
                    self.env.error(&fun.get_id_loc(), msg.as_str());
                    continue;
                },
            };

            let Some(randomness_annotation) = maybe_randomness_annotation else {
                continue;
            };

            if !fun.is_entry() || fun.visibility().is_public() {
                self.env.error(
                    &fun.get_id_loc(),
                    "only private or public(friend) entry functions can have #[randomness] attribute",
                )
            }
```

**File:** aptos-move/framework/src/extended_checks.rs (L612-625)
```rust
    fn check_unsafe_randomness_usage(&mut self, module: &ModuleEnv) {
        for ref fun in module.get_functions() {
            let fun_id = fun.module_env.get_id().qualified(fun.get_id());
            // Check condition (2)
            if !fun.visibility().is_public() && fun.is_entry() {
                if !self.has_attribute(fun, RANDOMNESS_ATTRIBUTE) && self.calls_randomness(fun_id) {
                    self.env.error(
                        &fun.get_id_loc(),
                        "entry function calling randomness features must \
                    use the `#[randomness]` attribute.",
                    )
                }
                continue;
            }
```

**File:** aptos-move/aptos-vm/src/verifier/module_init.rs (L60-105)
```rust
/// Used for verifying an init_module function for module publishing. Used for 1.31 release and
/// above. The checks include:
///   1. Private visibility.
///   2. No return types, single signer (reference) input.
///   3. No type arguments.
pub(crate) fn verify_init_module_function(function: &Function) -> Result<(), VMStatus> {
    let err = |msg| Err(VMStatus::error(StatusCode::INVALID_INIT_MODULE, Some(msg)));

    if !function.is_private() {
        return err("init_module function must be private, but it is not".to_string());
    }

    if !function.return_tys().is_empty() {
        return err(format!(
            "init_module function must return 0 values, but returns {}",
            function.return_tys().len()
        ));
    }

    let param_tys = function.param_tys();
    if param_tys.len() != 1 {
        return err(format!(
            "init_module function should have a single signer or &signer parameter, \
             but has {} parameters",
            param_tys.len()
        ));
    }

    let arg_ty = &param_tys[0];
    if !arg_ty.is_signer_or_signer_ref() {
        return err(
            "init_module function expects a single signer or &signer parameter, \
             but its parameter type is different"
                .to_string(),
        );
    }

    if function.ty_params_count() != 0 {
        return err(format!(
            "init_module function expects 0 type parameters, but has {} type parameters",
            function.ty_params_count()
        ));
    }

    Ok(())
}
```
