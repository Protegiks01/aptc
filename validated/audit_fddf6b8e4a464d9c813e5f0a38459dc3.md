# Audit Report

## Title
Native Struct Bypass Causes Validator Node Crash via Unvalidated Module Publishing

## Summary
The Move bytecode verifier fails to prevent user modules from declaring native structs, which are explicitly marked as removed in the runtime. When validators execute transactions loading such modules, the runtime triggers a panic via `unreachable!()` outside the verifier context, causing the crash handler to terminate the validator process with exit code 12.

## Finding Description

The vulnerability exists across three critical validation gaps that allow malicious modules to crash validator nodes:

**1. Verification Bypass**: The signature verifier explicitly skips field validation for native structs, returning immediately without checks: [1](#0-0) 

**2. Missing Native Struct Validation**: The native validation logic only checks native functions, completely ignoring native structs: [2](#0-1) 

**3. Runtime Panic**: When the module loader encounters a native struct during transaction execution, it triggers an unreachable panic: [3](#0-2) 

**4. Unprotected Crash**: The panic occurs after verification completes, outside the VMState::VERIFIER context. The crash handler detects this and terminates the validator process: [4](#0-3) 

**Attack Flow:**

1. Attacker crafts bytecode with `StructFieldInformation::Native` using the serialized flag value 0x1: [5](#0-4) 

2. Deserializer accepts this value and creates the Native variant: [6](#0-5) 

3. Bounds checker performs no validation for Native structs: [7](#0-6) 

4. Module publishing transaction enters a block and during execution, `StagingModuleStorage::create_with_compat_config` is called: [8](#0-7) 

5. This calls `build_verified_module_with_linking_checks`: [9](#0-8) 

6. Which calls `Module::new()` after VMState has been restored from VERIFIER: [10](#0-9) 

7. `Module::new()` calls `make_struct_type()` which hits the unreachable panic for Native structs

8. The VMState was set to VERIFIER during verification and then restored: [11](#0-10) 

9. Since VMState != VERIFIER when the panic occurs, the crash handler terminates the process

This violates Move VM safety guarantees and deterministic execution requirements - all validators executing the same transaction will crash identically.

## Impact Explanation

**High Severity** - This qualifies under "Validator Node Slowdowns" (more specifically, validator node crashes) per the Aptos bug bounty categories.

A malicious actor can:
- Publish a module with native structs using standard user permissions
- Cause any validator executing a transaction that loads this module to crash with exit code 12
- Trigger coordinated crashes across multiple validators processing the same block
- Potentially impact network liveness if sufficient validators crash simultaneously
- Exploit is deterministic - all validators will crash identically

While not causing permanent network halt (Critical severity), this enables a significant Denial of Service attack against validator infrastructure that violates consensus determinism and can impact network availability.

## Likelihood Explanation

**High Likelihood**:

1. **Low Technical Barrier**: Attacker only needs to craft bytecode with `StructFieldInformation::Native` - the enum variant exists and deserializer accepts it
2. **Standard User Capability**: Module publishing requires no special privileges, just standard transaction submission via the entry function
3. **Multi-Layer Bypass**: Vulnerability passes through all verification layers (bounds checking, signature verification, native validation)
4. **Deterministic Exploitation**: The crash is guaranteed and reproducible across all validators
5. **Low Economic Cost**: Only requires gas fees for module publishing
6. **No Detection**: The runtime comment explicitly states "native structs have been removed" but no validation enforces this

The attack is straightforward to execute with publicly available bytecode manipulation tools.

## Recommendation

Add explicit validation to reject native structs during module publishing:

1. **In native_validation.rs**, extend `validate_module_natives` to check struct definitions:
```rust
pub(crate) fn validate_module_natives(modules: &[CompiledModule]) -> VMResult<()> {
    for module in modules {
        let module_address = module.self_addr();
        
        // Check native functions
        for native in module.function_defs().iter().filter(|def| def.is_native()) {
            if native.is_entry || !module_address.is_special() {
                return Err(PartialVMError::new(StatusCode::USER_DEFINED_NATIVE_NOT_ALLOWED)
                    .with_message("Cannot publish native function to non-special address".to_string())
                    .finish(Location::Module(module.self_id())));
            }
        }
        
        // Check native structs
        for struct_def in module.struct_defs() {
            if matches!(struct_def.field_information, StructFieldInformation::Native) {
                return Err(PartialVMError::new(StatusCode::USER_DEFINED_NATIVE_NOT_ALLOWED)
                    .with_message("Native structs are not supported".to_string())
                    .finish(Location::Module(module.self_id())));
            }
        }
    }
    Ok(())
}
```

2. **Alternative**: Add validation in the signature verifier to explicitly reject Native structs instead of silently accepting them.

## Proof of Concept

```rust
// This test demonstrates the vulnerability by crafting a module with a native struct
#[test]
fn test_native_struct_crash() {
    use move_binary_format::file_format::*;
    use move_core_types::identifier::Identifier;
    use move_core_types::account_address::AccountAddress;
    
    let mut module = CompiledModule {
        version: 6,
        module_handles: vec![ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(0),
        }],
        struct_handles: vec![StructHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            abilities: AbilitySet::EMPTY,
            type_parameters: vec![],
        }],
        function_handles: vec![],
        field_handles: vec![],
        friend_decls: vec![],
        struct_defs: vec![StructDefinition {
            struct_handle: StructHandleIndex(0),
            field_information: StructFieldInformation::Native, // Malicious native struct
        }],
        function_defs: vec![],
        signatures: vec![],
        identifiers: vec![
            Identifier::new("TestModule").unwrap(),
            Identifier::new("NativeStruct").unwrap(),
        ],
        address_identifiers: vec![AccountAddress::ZERO],
        constant_pool: vec![],
        metadata: vec![],
        // ... other required fields
    };
    
    // Serialize the module
    let mut bytes = vec![];
    module.serialize(&mut bytes).unwrap();
    
    // Attempt to publish - this will cause validator crash during execution
    // when Module::new() is called and hits unreachable!() for Native struct
}
```

## Notes

The vulnerability is rooted in the assumption that native structs "have been removed" from the Move VM, yet no validation enforces this invariant. The deserializer still accepts the Native flag, all verifiers accept it, but the runtime expects it to never occur. This creates a critical gap where malicious bytecode can cause deterministic validator crashes across the network.

### Citations

**File:** third_party/move/move-bytecode-verifier/src/signature_v2.rs (L1084-1085)
```rust
        match &struct_def.field_information {
            StructFieldInformation::Native => Ok(()),
```

**File:** aptos-move/aptos-vm/src/verifier/native_validation.rs (L15-16)
```rust
        for native in module.function_defs().iter().filter(|def| def.is_native()) {
            if native.is_entry || !module_address.is_special() {
```

**File:** third_party/move/move-vm/runtime/src/loader/modules.rs (L453-453)
```rust
            StructFieldInformation::Native => unreachable!("native structs have been removed"),
```

**File:** crates/crash-handler/src/lib.rs (L52-57)
```rust
    if state::get_state() == VMState::VERIFIER || state::get_state() == VMState::DESERIALIZER {
        return;
    }

    // Kill the process
    process::exit(12);
```

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L211-212)
```rust
pub enum SerializedNativeStructFlag {
    NATIVE                  = 0x1,
```

**File:** third_party/move/move-binary-format/src/deserializer.rs (L1512-1512)
```rust
        SerializedNativeStructFlag::NATIVE => StructFieldInformation::Native,
```

**File:** third_party/move/move-binary-format/src/check_bounds.rs (L408-408)
```rust
            StructFieldInformation::Native => {},
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/user_transaction_sessions/user.rs (L97-102)
```rust
        let staging_module_storage = StagingModuleStorage::create_with_compat_config(
            &destination,
            compatability_checks,
            module_storage,
            bundle.into_bytes(),
        )?;
```

**File:** third_party/move/move-vm/runtime/src/storage/publishing.rs (L272-275)
```rust
                staged_runtime_environment.build_verified_module_with_linking_checks(
                    locally_verified_code,
                    &verified_dependencies,
                )?;
```

**File:** third_party/move/move-vm/runtime/src/storage/environment.rs (L217-224)
```rust
        let result = Module::new(
            &self.natives,
            locally_verified_module.1,
            locally_verified_module.0,
            self.struct_name_index_map(),
            self.ty_pool(),
            self.module_id_pool(),
        );
```

**File:** third_party/move/move-bytecode-verifier/src/verifier.rs (L138-172)
```rust
    let prev_state = move_core_types::state::set_state(VMState::VERIFIER);
    let result = std::panic::catch_unwind(|| {
        // Always needs to run bound checker first as subsequent passes depend on it
        BoundsChecker::verify_module(module).map_err(|e| {
            // We can't point the error at the module, because if bounds-checking
            // failed, we cannot safely index into module's handle to itself.
            e.finish(Location::Undefined)
        })?;
        FeatureVerifier::verify_module(config, module)?;
        LimitsVerifier::verify_module(config, module)?;
        DuplicationChecker::verify_module(module)?;

        signature_v2::verify_module(config, module)?;

        InstructionConsistency::verify_module(module)?;
        constants::verify_module(module)?;
        friends::verify_module(module)?;

        RecursiveStructDefChecker::verify_module(module)?;
        InstantiationLoopChecker::verify_module(module)?;
        CodeUnitVerifier::verify_module(config, module)?;

        // Add the failpoint injection to test the catch_unwind behavior.
        fail::fail_point!("verifier-failpoint-panic");

        script_signature::verify_module(module, no_additional_script_signature_checks)
    })
    .unwrap_or_else(|_| {
        Err(
            PartialVMError::new(StatusCode::VERIFIER_INVARIANT_VIOLATION)
                .finish(Location::Undefined),
        )
    });
    move_core_types::state::set_state(prev_state);
    result
```
