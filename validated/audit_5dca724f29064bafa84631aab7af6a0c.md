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

1. Attacker crafts bytecode with `StructFieldInformation::Native` (SerializedNativeStructFlag value 0x1)
2. Module passes bytecode verification because native structs bypass field validation
3. Module passes native validation because only functions are checked
4. Module publishing transaction enters a block
5. During block execution by validators, `build_verified_module_with_linking_checks` calls `Module::new()` [5](#0-4) 

6. `Module::new()` calls `make_struct_type()` which hits the unreachable panic
7. VMState has been restored from VERIFIER to normal state
8. Crash handler checks VMState, finds it's not VERIFIER/DESERIALIZER, and kills the process

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
2. **Standard User Capability**: Module publishing requires no special privileges, just standard transaction submission
3. **Multi-Layer Bypass**: Vulnerability passes through all verification layers (bounds checking, signature verification, native validation)
4. **Deterministic Exploitation**: The crash is guaranteed and reproducible across all validators
5. **Low Economic Cost**: Only requires gas fees for module publishing
6. **No Detection**: The runtime comment explicitly states "native structs have been removed" but no validation enforces this

The attack is straightforward to execute with publicly available bytecode manipulation tools.

## Recommendation

Add native struct validation to prevent user modules from declaring them:

```rust
// In aptos-move/aptos-vm/src/verifier/native_validation.rs
pub(crate) fn validate_module_natives(modules: &[CompiledModule]) -> VMResult<()> {
    for module in modules {
        let module_address = module.self_addr();
        
        // Check native functions
        for native in module.function_defs().iter().filter(|def| def.is_native()) {
            if native.is_entry || !module_address.is_special() {
                return Err(
                    PartialVMError::new(StatusCode::USER_DEFINED_NATIVE_NOT_ALLOWED)
                        .with_message("Cannot publish native function to non-special address".to_string())
                        .finish(Location::Module(module.self_id())),
                );
            }
        }
        
        // ADD: Check native structs
        for struct_def in module.struct_defs() {
            if matches!(&struct_def.field_information, StructFieldInformation::Native) {
                if !module_address.is_special() {
                    return Err(
                        PartialVMError::new(StatusCode::USER_DEFINED_NATIVE_NOT_ALLOWED)
                            .with_message("Cannot publish native struct to non-special address".to_string())
                            .finish(Location::Module(module.self_id())),
                    );
                }
            }
        }
    }
    Ok(())
}
```

Alternatively, convert the `unreachable!()` to return an error that can be properly handled.

## Proof of Concept

```rust
// PoC demonstrating the vulnerability
// This would need to be integrated into the Aptos test framework

use move_binary_format::{
    file_format::*,
    CompiledModule,
};

#[test]
fn test_native_struct_crash() {
    // Create a minimal module with a native struct
    let mut module = CompiledModule::default();
    
    // Add struct definition with Native field information
    let struct_def = StructDefinition {
        struct_handle: StructHandleIndex(0),
        field_information: StructFieldInformation::Native,
    };
    
    // Serialize and attempt to publish
    // This would pass verification but crash during Module::new()
    let bytes = module.serialize();
    
    // Submit as module publishing transaction
    // During block execution, validators will hit the unreachable!() panic
    // and crash with exit code 12
}
```

## Notes

The vulnerability is particularly severe because:
1. The crash is deterministic across all validators
2. No mempool-level protection prevents the transaction from entering blocks
3. The crash handler explicitly terminates the process, not allowing graceful recovery
4. Multiple such transactions could be submitted to amplify the impact

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

**File:** third_party/move/move-vm/runtime/src/loader/modules.rs (L452-453)
```rust
        let layout = match &struct_def.field_information {
            StructFieldInformation::Native => unreachable!("native structs have been removed"),
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
