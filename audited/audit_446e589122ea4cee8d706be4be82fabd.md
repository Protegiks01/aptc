# Audit Report

## Title
Critical: init_module Bypass via Type Parameter Exploitation in Legacy Validation Path

## Summary
The legacy `init_module` validation path (gas_feature_version ≤ 34) fails to verify type parameter constraints, allowing attackers to publish modules with type-parameterized `init_module` functions. When such modules are loaded during publishing, the type argument mismatch causes silent load failures that skip initialization entirely, publishing modules without running critical security setup code.

## Finding Description

The Aptos Move VM has two different validation paths for `init_module` functions based on the `gas_feature_version`: [1](#0-0) 

The legacy validation (used when `gas_feature_version <= RELEASE_V1_30`, which is value 34) checks:
1. Private visibility
2. No return values  
3. All parameters must be signer or &signer types

**Critical flaw**: Legacy validation does NOT check for type parameters. [2](#0-1) 

In contrast, the new validation explicitly rejects type parameters.

During module publishing, the code attempts to load and execute `init_module`: [3](#0-2) 

The vulnerability occurs in the legacy path:
1. `load_instantiated_function` is called with empty type arguments `&[]` (line 132)
2. If `init_module` has type parameters (e.g., `init_module<T>`), loading fails with type argument count mismatch
3. The `if let Ok(init_func)` pattern silently catches the error
4. The entire initialization block is skipped
5. Module publishing continues without running `init_module`

**Attack Path:**
1. Attacker crafts bytecode with `fun init_module<T>(account: &signer)` (bypassing Move compiler checks)
2. Submits module for publication when `gas_feature_version <= 34`
3. Legacy validation passes (no type parameter check)
4. Load fails due to type argument mismatch (expects 1, provided 0)
5. Error is silently caught, init block skipped
6. **Module published WITHOUT initialization**

**Security Impact:**
Many Move modules use `init_module` for critical security operations:
- Creating privileged capability resources (MintRef, BurnRef, TransferRef)
- Establishing access control structures
- Initializing global state required for safe operation
- Registering module metadata [4](#0-3) 

If initialization is skipped, modules lack critical security resources, potentially enabling:
- Unauthorized minting/burning of tokens
- Bypassed access controls
- Uninitialized state vulnerabilities
- Complete module dysfunction

## Impact Explanation

**Critical Severity** - This vulnerability allows bypassing the fundamental security guarantee that `init_module` always executes for newly published modules. This breaks the **Move VM Safety** and **Transaction Validation** invariants.

Per Aptos bug bounty criteria, this qualifies as **Critical Severity** because:
- **Loss of Funds**: Modules without proper initialization may allow unauthorized token minting/burning
- **Significant Protocol Violation**: Violates the core guarantee that initialization code executes atomically with module publishing
- **State Consistency**: Modules can exist in invalid, uninitialized states

The vulnerability affects all modules published under legacy validation rules (gas_feature_version ≤ 34), which includes historical mainnet deployments.

## Likelihood Explanation

**High Likelihood** of exploitation:

**Requirements:**
1. Attacker must craft malformed bytecode (moderate complexity - bypassing Move compiler)
2. Target network must be running gas_feature_version ≤ 34 (currently unlikely on mainnet after upgrade to v1.31+)
3. No validator collusion required

**Complexity:** Medium - requires understanding of Move bytecode structure and ability to manually craft or modify compiled modules, but no advanced cryptographic or consensus knowledge needed.

**Detection:** Low - silently skips initialization without error, making exploitation difficult to detect until module is invoked and fails due to missing resources.

**Historical Risk:** High - all modules published during gas_feature_version ≤ 34 periods are potentially vulnerable if they contained type-parameterized init_module functions.

## Recommendation

**Immediate Fix:** Add type parameter validation to legacy verification:

```rust
pub(crate) fn legacy_verify_module_init_function(module: &CompiledModule) -> PartialVMResult<()> {
    let init_func_name = ident_str!("init_module");
    let fdef_opt = module.function_defs().iter().enumerate().find(|(_, fdef)| {
        module.identifier_at(module.function_handle_at(fdef.function).name) == init_func_name
    });
    if fdef_opt.is_none() {
        return Ok(());
    }
    let (_idx, fdef) = fdef_opt.unwrap();
    
    let fhandle = module.function_handle_at(fdef.function);
    
    // ADD THIS CHECK:
    if !fhandle.type_parameters.is_empty() {
        return Err(PartialVMError::new(StatusCode::VERIFICATION_ERROR)
            .with_message("'init_module' should not have type parameters".to_string()));
    }
    
    // ... rest of validation
}
```

**Alternative Fix:** Change error handling to propagate load failures instead of silently skipping: [5](#0-4) 

Replace `if let Ok(init_func)` with explicit error propagation:
```rust
let init_func = loader.load_instantiated_function(
    &LegacyLoaderConfig::unmetered(),
    gas_meter,
    traversal_context,
    &module.self_id(),
    init_func_name,
    &[],
)?;  // Propagate error instead of silent skip
```

**Long-term:** Deprecate legacy validation path entirely and mandate gas_feature_version > 34 across all networks.

## Proof of Concept

**Bytecode Construction PoC:**

```rust
// Rust code to construct malicious module bytecode
use move_binary_format::file_format::*;
use move_core_types::identifier::Identifier;

fn create_malicious_module() -> CompiledModule {
    let mut module = CompiledModule::default();
    
    // Add init_module function with type parameter
    let init_func_name = Identifier::new("init_module").unwrap();
    
    // Create function signature with 1 type parameter and 1 signer parameter
    let type_params = vec![AbilitySet::EMPTY]; // 1 type parameter
    let params = Signature(vec![SignatureToken::Signer]);
    let return_ = Signature(vec![]);
    
    module.function_handles.push(FunctionHandle {
        module: ModuleHandleIndex(0),
        name: module.identifiers.len() as u16,
        parameters: module.signatures.len() as u16,
        return_: (module.signatures.len() + 1) as u16,
        type_parameters: type_params,
    });
    
    module.identifiers.push(init_func_name);
    module.signatures.push(params);
    module.signatures.push(return_);
    
    module.function_defs.push(FunctionDefinition {
        function: FunctionHandleIndex(module.function_handles.len() as u16 - 1),
        visibility: Visibility::Private,
        acquires_global_resources: vec![],
        code: Some(CodeUnit {
            locals: SignatureIndex(0),
            code: vec![Bytecode::Ret],
        }),
    });
    
    module
}

// Submit this bytecode for publishing when gas_feature_version <= 34
// Expected: Legacy validation passes, loading fails, init_module skipped
// Result: Module published without initialization
```

**Verification Steps:**
1. Deploy Aptos node with `gas_feature_version = 34`
2. Construct module bytecode with type-parameterized init_module
3. Submit module publishing transaction
4. Observe: Transaction succeeds but init_module never executes
5. Attempt to invoke module functions requiring initialized resources
6. Observe: Functions fail due to missing resources that should have been created in init_module

## Notes

This vulnerability represents a **version-dependent validation gap** where different gas feature versions apply different security rules. While current mainnet likely runs gas_feature_version > 34 (mitigating this specific attack), the vulnerability demonstrates a broader systemic issue: runtime-configurable validation rules can introduce subtle security bypasses during transition periods.

The silent error swallowing pattern (`if let Ok(...)`) is particularly dangerous as it masks critical failures. All similar patterns in module publishing should be audited to ensure errors are properly propagated rather than silently ignored.

### Citations

**File:** aptos-move/aptos-vm/src/verifier/module_init.rs (L24-58)
```rust
pub(crate) fn legacy_verify_module_init_function(module: &CompiledModule) -> PartialVMResult<()> {
    let init_func_name = ident_str!("init_module");
    let fdef_opt = module.function_defs().iter().enumerate().find(|(_, fdef)| {
        module.identifier_at(module.function_handle_at(fdef.function).name) == init_func_name
    });
    if fdef_opt.is_none() {
        return Ok(());
    }
    let (_idx, fdef) = fdef_opt.unwrap();

    if fdef.visibility != Visibility::Private {
        return Err(PartialVMError::new(StatusCode::VERIFICATION_ERROR)
            .with_message("'init_module' is not private".to_string()));
    }

    let fhandle = module.function_handle_at(fdef.function);
    let parameters = module.signature_at(fhandle.parameters);

    let return_ = module.signature_at(fhandle.return_);

    if !return_.0.is_empty() {
        return Err(PartialVMError::new(StatusCode::VERIFICATION_ERROR)
            .with_message("'init_module' should not return".to_string()));
    }

    let non_signer_tokens = parameters
        .0
        .iter()
        .any(|e| !is_signer_or_signer_reference(e));
    if non_signer_tokens {
        return Err(PartialVMError::new(StatusCode::VERIFICATION_ERROR)
            .with_message("'init_module' should not have no-signer arguments".to_string()));
    }
    Ok(())
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

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/user_transaction_sessions/user.rs (L125-148)
```rust
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
```

**File:** aptos-move/move-examples/fungible_asset/fa_coin/sources/FACoin.move (L39-87)
```text
    fun init_module(admin: &signer) {
        let constructor_ref = &object::create_named_object(admin, ASSET_SYMBOL);
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            constructor_ref,
            option::none(),
            utf8(b"FA Coin"), /* name */
            utf8(ASSET_SYMBOL), /* symbol */
            8, /* decimals */
            utf8(b"http://example.com/favicon.ico"), /* icon */
            utf8(b"http://example.com"), /* project */
        );

        // Create mint/burn/transfer refs to allow creator to manage the fungible asset.
        let mint_ref = fungible_asset::generate_mint_ref(constructor_ref);
        let burn_ref = fungible_asset::generate_burn_ref(constructor_ref);
        let transfer_ref = fungible_asset::generate_transfer_ref(constructor_ref);
        let metadata_object_signer = object::generate_signer(constructor_ref);
        move_to(
            &metadata_object_signer,
            ManagedFungibleAsset { mint_ref, transfer_ref, burn_ref }
        ); // <:!:initialize

        // Create a global state to pause the FA coin and move to Metadata object.
        move_to(
            &metadata_object_signer,
            State { paused: false, }
        );

        // Override the deposit and withdraw functions which mean overriding transfer.
        // This ensures all transfer will call withdraw and deposit functions in this module
        // and perform the necessary checks.
        // This is OPTIONAL. It is an advanced feature and we don't NEED a global state to pause the FA coin.
        let deposit = function_info::new_function_info(
            admin,
            string::utf8(b"fa_coin"),
            string::utf8(b"deposit"),
        );
        let withdraw = function_info::new_function_info(
            admin,
            string::utf8(b"fa_coin"),
            string::utf8(b"withdraw"),
        );
        dispatchable_fungible_asset::register_dispatch_functions(
            constructor_ref,
            option::some(withdraw),
            option::some(deposit),
            option::none(),
        );
    }
```
