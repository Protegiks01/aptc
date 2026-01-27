# Audit Report

## Title
Native Struct Validation Bypass Causes Critical Node Crash and Network-Wide DoS

## Summary
The Move bytecode verifier skips validation of native structs in `verify_struct_defs()`, and the module publishing process does not restrict native struct declarations to special addresses. This allows any user to publish a module containing a native struct, which causes all validator nodes to panic and crash when the module is loaded, resulting in total network liveness failure.

## Finding Description

The vulnerability exists across multiple components in the module verification and loading pipeline:

**1. Verification Bypass in features.rs:**
The `verify_struct_defs()` function explicitly skips native structs without performing any validation or access control checks: [1](#0-0) 

**2. Missing Access Control in native_validation.rs:**
The `validate_module_natives()` function only validates native **functions** and restricts them to special addresses (0x0-0xf), but completely ignores native **structs**: [2](#0-1) 

Special addresses are defined as 0x0 through 0xf: [3](#0-2) 

**3. Compiler Accepts Native Struct Syntax:**
The Move compiler supports parsing native struct declarations with the `native` keyword, allowing users to write modules like:
```move
module 0x<attacker>::Malicious {
    native struct CrashStruct;
}
```

**4. Runtime Panic in modules.rs:**
When a module with a native struct is loaded, the runtime encounters an `unreachable!()` macro that panics the entire node: [4](#0-3) 

**Attack Flow:**

1. Attacker compiles a Move module with a native struct at any non-special address (e.g., their own account address)
2. The bytecode verifier skips validation of the native struct
3. Module publishing validation (`validate_module_natives`) only checks native functions, not native structs
4. Module is accepted and stored in blockchain state
5. During publishing, `StagingModuleStorage::create()` loads the module: [5](#0-4) 

6. This calls `Module::new()` which iterates over struct definitions: [6](#0-5) 

7. The `make_struct_type()` function hits the unreachable case and **panics the node**: [4](#0-3) 

8. All validator nodes processing this transaction crash simultaneously
9. Network achieves total loss of liveness

This breaks the critical invariant: **"Move VM Safety: Bytecode execution must respect gas limits and memory constraints"** and **"Deterministic Execution: All validators must produce identical state roots for identical blocks"** - instead, all validators crash before producing any state root.

## Impact Explanation

This vulnerability qualifies as **Critical Severity** under the Aptos bug bounty program for the following reasons:

1. **Total loss of liveness/network availability**: All validator nodes that process the malicious transaction will panic and crash, bringing down the entire network. This is explicitly listed as a Critical impact.

2. **Non-recoverable without intervention**: The malicious transaction would need to be filtered out or the code would need to be patched via emergency hardfork. Regular consensus cannot proceed with all nodes crashing.

3. **Deterministic Execution Violation**: The vulnerability breaks the fundamental invariant that validators must produce identical results - instead they all produce crashes.

4. **No privilege required**: Any user can exploit this by simply publishing a module to their own address - no validator access, stake, or special permissions needed.

5. **Immediate and guaranteed impact**: The crash occurs deterministically during the publishing transaction itself, not through complex race conditions or timing attacks.

## Likelihood Explanation

**Likelihood: VERY HIGH**

1. **Trivial to execute**: An attacker only needs to:
   - Write a 2-line Move module with `native struct`
   - Compile it using the standard Move compiler
   - Submit a module publishing transaction
   
2. **No special resources required**: No stake, validator access, or coordination needed. Any account with enough gas to publish a module can execute this attack.

3. **Immediate effect**: The crash happens during transaction processing, providing instant feedback to the attacker.

4. **Discoverable**: The vulnerability is visible in public source code, and the `unreachable!()` message explicitly indicates the code path is not meant to be reached.

5. **No mitigating factors**: There are no runtime checks, gas limits, or other safeguards that would prevent this attack.

## Recommendation

Add validation in `validate_module_natives()` to reject native structs from non-special addresses, matching the existing logic for native functions:

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
                        .with_message(
                            "Cannot publish native function to non-special address".to_string(),
                        )
                        .finish(Location::Module(module.self_id())),
                );
            }
        }
        
        // ADD THIS: Check native structs
        for struct_def in module.struct_defs() {
            if matches!(struct_def.field_information, StructFieldInformation::Native) {
                if !module_address.is_special() {
                    return Err(
                        PartialVMError::new(StatusCode::USER_DEFINED_NATIVE_NOT_ALLOWED)
                            .with_message(
                                "Cannot publish native struct to non-special address".to_string(),
                            )
                            .finish(Location::Module(module.self_id())),
                    );
                }
            }
        }
    }
    Ok(())
}
```

Additionally, remove the `unreachable!()` and replace it with a proper error to prevent crashes if native structs somehow slip through:

```rust
// In third_party/move/move-vm/runtime/src/loader/modules.rs
fn make_struct_type(...) -> PartialVMResult<StructType> {
    let layout = match &struct_def.field_information {
        StructFieldInformation::Native => {
            return Err(PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                .with_message("Native structs are not supported".to_string()));
        },
        // ... rest of the match arms
    };
}
```

## Proof of Concept

**Move Module (malicious.move):**
```move
module 0x42::MaliciousModule {
    native struct NodeCrasher;
}
```

**Compilation and Attack Steps:**
```bash
# 1. Compile the malicious module
aptos move compile --package-dir ./malicious --named-addresses MaliciousModule=0x42

# 2. Publish the module (this will crash all validator nodes)
aptos move publish --package-dir ./malicious --named-addresses MaliciousModule=0x42
```

**Expected Result:**
All validator nodes processing this transaction will panic with:
```
thread panicked at 'native structs have been removed', 
third_party/move/move-vm/runtime/src/loader/modules.rs:453:53
```

The network will experience total loss of liveness until the malicious transaction is filtered out or nodes are patched.

**Notes:**
- The vulnerability exists because native structs were deprecated but the bytecode format still supports them
- Verification was added for native functions but not for native structs
- The runtime assumes native structs can never appear, but the verifier allows them through
- This creates a critical security gap exploitable by any unprivileged user to crash the entire network

### Citations

**File:** third_party/move/move-bytecode-verifier/src/features.rs (L91-91)
```rust
                        StructFieldInformation::Native => {},
```

**File:** aptos-move/aptos-vm/src/verifier/native_validation.rs (L12-28)
```rust
pub(crate) fn validate_module_natives(modules: &[CompiledModule]) -> VMResult<()> {
    for module in modules {
        let module_address = module.self_addr();
        for native in module.function_defs().iter().filter(|def| def.is_native()) {
            if native.is_entry || !module_address.is_special() {
                return Err(
                    PartialVMError::new(StatusCode::USER_DEFINED_NATIVE_NOT_ALLOWED)
                        .with_message(
                            "Cannot publish native function to non-special address".to_string(),
                        )
                        .finish(Location::Module(module.self_id())),
                );
            }
        }
    }
    Ok(())
}
```

**File:** third_party/move/move-core/types/src/account_address.rs (L110-122)
```rust
    /// Returns whether the address is a "special" address. Addresses are considered
    /// special if the first 63 characters of the hex string are zero. In other words,
    /// an address is special if the first 31 bytes are zero and the last byte is
    /// smaller than than `0b10000` (16). In other words, special is defined as an address
    /// that matches the following regex: `^0x0{63}[0-9a-f]$`. In short form this means
    /// the addresses in the range from `0x0` to `0xf` (inclusive) are special.
    ///
    /// For more details see the v1 address standard defined as part of AIP-40:
    /// <https://github.com/aptos-foundation/AIPs/blob/main/aips/aip-40.md>
    #[inline(always)]
    pub fn is_special(&self) -> bool {
        self.0[..Self::LENGTH - 1].iter().all(|x| *x == 0) && self.0[Self::LENGTH - 1] < 0b10000
    }
```

**File:** third_party/move/move-vm/runtime/src/loader/modules.rs (L216-218)
```rust
        for (idx, struct_def) in module.struct_defs().iter().enumerate() {
            let definition_struct_type =
                Arc::new(Self::make_struct_type(&module, struct_def, &struct_idxs)?);
```

**File:** third_party/move/move-vm/runtime/src/loader/modules.rs (L452-453)
```rust
        let layout = match &struct_def.field_information {
            StructFieldInformation::Native => unreachable!("native structs have been removed"),
```

**File:** third_party/move/move-vm/runtime/src/storage/publishing.rs (L272-275)
```rust
                staged_runtime_environment.build_verified_module_with_linking_checks(
                    locally_verified_code,
                    &verified_dependencies,
                )?;
```
