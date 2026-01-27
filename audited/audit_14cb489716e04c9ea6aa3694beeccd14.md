# Audit Report

## Title
Validator Node Crash via Native Struct Publishing Bypassing Verification

## Summary
The Move bytecode verifier accepts modules containing native structs without validation, but the VM runtime panics when attempting to load such modules. An attacker can craft and publish a module with a native struct, causing all validators processing the transaction to crash with `process::exit(12)`, resulting in total network liveness failure.

## Finding Description

The vulnerability exists in a gap between bytecode verification and runtime module loading:

**Verification Gap**: The bytecode verifier accepts `StructFieldInformation::Native` without any checks: [1](#0-0) 

**Runtime Panic**: When loading modules, the VM treats native structs as removed and uses `unreachable!()`: [2](#0-1) 

**Deserialization Allows Native Structs**: The deserializer creates native structs from bytecode flag `0x1`: [3](#0-2) 

**Attack Flow**:
1. Attacker crafts a module where a struct has the NATIVE flag (0x1) set in bytecode
2. Submits module publishing transaction
3. Module passes deserialization and verification
4. During module loading in `StagingModuleStorage::create_with_compat_config`: [4](#0-3) 
5. `Module::new` is called, which invokes `make_struct_type`: [5](#0-4) 
6. Panic occurs outside of any `catch_unwind` block and with VMState != VERIFIER

**Crash Handler Behavior**: The panic occurs when VMState is not VERIFIER, causing the crash handler to terminate the process: [6](#0-5) 

The default VMState is OTHER, not VERIFIER: [7](#0-6) 

This breaks **Deterministic Execution** and **Move VM Safety** invariants - all validators will deterministically crash when processing this transaction.

## Impact Explanation

**CRITICAL Severity** - Total Loss of Network Liveness:
- Any user can publish a module with a native struct
- All validators processing this transaction will crash with `process::exit(12)`
- Network cannot make progress as validators crash sequentially
- Requires no privileged access or validator collusion
- Meets "Total loss of liveness/network availability" criteria (up to $1,000,000)

## Likelihood Explanation

**Very High Likelihood**:
- Attack is trivial to execute - just craft bytecode with NATIVE flag
- No authentication barriers beyond normal transaction submission
- Deterministic - affects all validators equally
- No mitigations in place - verification doesn't check for native structs
- Proptest generator already demonstrates this is possible: [8](#0-7) 

## Recommendation

Add verification pass to reject native structs in non-system modules:

```rust
// In signature_v2.rs, replace line 1085:
StructFieldInformation::Native => {
    // Native structs are deprecated and should only exist in legacy stdlib
    Err(PartialVMError::new(StatusCode::INVALID_FLAG_BITS)
        .with_message("Native structs are not allowed".to_string()))
}
```

Alternatively, handle gracefully in the loader:
```rust
// In modules.rs, replace line 453:
StructFieldInformation::Native => {
    return Err(PartialVMError::new(StatusCode::LINKER_ERROR)
        .with_message("Native struct definitions are not supported".to_string()));
}
```

The verification approach is preferred as it fails fast and prevents the module from being published at all.

## Proof of Concept

```rust
// PoC: Craft malicious module bytecode with native struct
use move_binary_format::file_format::*;
use move_binary_format::file_format_common::SerializedNativeStructFlag;

fn craft_malicious_module() -> Vec<u8> {
    let mut module = CompiledModule {
        version: move_binary_format::file_format_common::VERSION_MAX,
        // ... populate module handles, identifiers, etc ...
        struct_defs: vec![
            StructDefinition {
                struct_handle: StructHandleIndex(0),
                // Set field_information to Native - this will serialize with flag 0x1
                field_information: StructFieldInformation::Native,
            }
        ],
        // ... rest of module ...
    };
    
    let mut bytes = vec![];
    module.serialize(&mut bytes).unwrap();
    bytes
}

// Submit as module publishing transaction:
// 1. Create transaction with module bytecode from craft_malicious_module()
// 2. Submit to network
// 3. All validators crash when processing the transaction
```

## Notes

The proptest generator inadvertently creates these invalid modules for empty field lists, exposing this verification gap. While native structs have been "removed" from Move (per the comment), the deserializer still supports them and the verifier doesn't reject them, creating a critical attack surface.

### Citations

**File:** third_party/move/move-bytecode-verifier/src/signature_v2.rs (L1084-1086)
```rust
        match &struct_def.field_information {
            StructFieldInformation::Native => Ok(()),
            StructFieldInformation::Declared(fields) => self.verify_fields_of_struct(
```

**File:** third_party/move/move-vm/runtime/src/loader/modules.rs (L217-218)
```rust
            let definition_struct_type =
                Arc::new(Self::make_struct_type(&module, struct_def, &struct_idxs)?);
```

**File:** third_party/move/move-vm/runtime/src/loader/modules.rs (L452-453)
```rust
        let layout = match &struct_def.field_information {
            StructFieldInformation::Native => unreachable!("native structs have been removed"),
```

**File:** third_party/move/move-binary-format/src/deserializer.rs (L1511-1512)
```rust
    let field_information = match field_information_flag {
        SerializedNativeStructFlag::NATIVE => StructFieldInformation::Native,
```

**File:** third_party/move/move-vm/runtime/src/storage/publishing.rs (L272-275)
```rust
                staged_runtime_environment.build_verified_module_with_linking_checks(
                    locally_verified_code,
                    &verified_dependencies,
                )?;
```

**File:** crates/crash-handler/src/lib.rs (L52-57)
```rust
    if state::get_state() == VMState::VERIFIER || state::get_state() == VMState::DESERIALIZER {
        return;
    }

    // Kill the process
    process::exit(12);
```

**File:** third_party/move/move-core/types/src/state.rs (L15-16)
```rust
thread_local! {
    static STATE: RefCell<VMState> = const { RefCell::new(VMState::OTHER) };
```

**File:** third_party/move/move-binary-format/src/proptest_types/types.rs (L223-228)
```rust
                let field_information = if self.variants.is_empty() {
                    if fields.is_empty() {
                        StructFieldInformation::Native
                    } else {
                        StructFieldInformation::Declared(fields)
                    }
```
