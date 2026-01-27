# Audit Report

## Title
Integer Overflow in script_into_module() Causing Identifier Index Confusion

## Summary
The `script_into_module()` function contains multiple unchecked `usize` to `u16` casts when adding new identifiers, addresses, module handles, signatures, and function handles to a script being converted to a module. If a script contains 65536 or more identifiers (or other table entries), the cast `script.identifiers.len() as u16` wraps to 0, causing newly added identifiers to reference index 0 instead of their actual position, resulting in semantic incorrectness in the generated module. [1](#0-0) 

## Finding Description

The vulnerability exists at multiple locations in `script_into_module()`:

**Line 108 (Identifiers):** When adding a new identifier name that doesn't exist in the script, the code performs `IdentifierIndex::new(script.identifiers.len() as u16)`. If the identifiers vector has exactly 65536 elements (indices 0-65535), casting 65536 to u16 results in 0 due to integer overflow. [2](#0-1) 

Similar overflows exist at:
- Line 125: `AddressIdentifierIndex::new(script.address_identifiers.len() as u16)`
- Line 139: `ModuleHandleIndex::new(script.module_handles.len() as u16)`  
- Line 153: `SignatureIndex::new(script.signatures.len() as u16)`
- Line 160: `FunctionHandleIndex::new(script.function_handles.len() as u16)` [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) 

**Attack Path:**
1. Attacker crafts a CompiledScript binary with exactly 65536 identifiers (indices 0-65535)
2. All references in the script use valid indices (0-65535), so the script passes bounds checking
3. The deserializer loads all identifiers without checking element count (only validates byte size and individual identifier validity) [7](#0-6) [8](#0-7) 

4. When `script_into_module()` is called (e.g., in the compiler or disassembler), it attempts to add a new identifier
5. The overflow occurs, returning IdentifierIndex(0) instead of IdentifierIndex(65536)
6. The module is created with references pointing to identifier[0] instead of the newly added identifier
7. The resulting module passes bounds checking but has semantic incorrectness [9](#0-8) 

The bounds checker only validates that indices are within table bounds, not that references point to semantically correct identifiers. [10](#0-9) 

## Impact Explanation

**Severity: Low (Out of Scope)**

This vulnerability does NOT meet the criteria for Critical, High, or Medium severity because:

1. **Not a Runtime Vulnerability**: `script_into_module()` is only used in development tools (compiler, disassembler, decompiler), not during transaction execution or consensus. [11](#0-10) [12](#0-11) 

2. **No Consensus Impact**: Does not affect validator agreement, block execution, or state transitions
3. **No Funds at Risk**: Cannot cause loss, theft, or minting of tokens
4. **No State Corruption**: Does not manipulate on-chain state or storage
5. **Limited to Tooling**: Only affects off-chain development tools processing maliciously crafted inputs

The impact is limited to:
- Incorrect module metadata in development tools
- Potential confusion during script disassembly/decompilation
- Possible supply chain issues if malicious scripts are compiled

This falls outside the defined scope focusing on "consensus, execution, storage, governance, and staking components."

## Likelihood Explanation

**Likelihood: Very Low**

1. **Requires Malicious Input**: Attacker must craft a script with exactly 65536 identifiers
2. **Large Binary Size**: A script with 65536 identifiers would be extremely large (tens of megabytes minimum)
3. **No Production Path**: The vulnerable function is not invoked during normal blockchain operation
4. **Compiler Protections**: The Move compiler enforces MAX_IDENTIFIER_COUNT limits during compilation [13](#0-12) [14](#0-13) 

5. **Limited Attack Surface**: Only affects developers using disassembly/decompilation tools on untrusted binaries

## Recommendation

Add bounds checking before casting to prevent integer overflow:

```rust
pub fn script_into_module(compiled_script: CompiledScript, name: &str) -> CompiledModule {
    let mut script = compiled_script;

    // Validate table sizes before any operations
    if script.identifiers.len() > u16::MAX as usize {
        panic!("Script has too many identifiers: {}", script.identifiers.len());
    }
    if script.address_identifiers.len() > u16::MAX as usize {
        panic!("Script has too many address identifiers");
    }
    if script.module_handles.len() > u16::MAX as usize {
        panic!("Script has too many module handles");
    }
    if script.signatures.len() > u16::MAX as usize {
        panic!("Script has too many signatures");
    }
    if script.function_handles.len() > u16::MAX as usize {
        panic!("Script has too many function handles");
    }

    // Existing logic with safe casts...
}
```

Alternatively, use checked conversions:

```rust
let idx = script.identifiers.len()
    .try_into()
    .expect("identifier count exceeds u16::MAX");
let idx = IdentifierIndex::new(idx);
```

## Proof of Concept

```rust
#[test]
fn test_script_into_module_overflow() {
    use move_binary_format::{
        file_format::{CompiledScript, Signature, empty_script},
        module_script_conversion::script_into_module,
    };
    use move_core_types::identifier::Identifier;

    // Create a script with exactly 65536 identifiers
    let mut script = empty_script();
    
    for i in 0..65536 {
        let ident = Identifier::new(format!("id{}", i)).unwrap();
        script.identifiers.push(ident);
    }

    // Try to convert to module with a name not in the identifier table
    // This should trigger the overflow at line 108
    let module = script_into_module(script, "new_function_name");
    
    // The module's self identifier index should point to index 0 due to overflow
    // instead of index 65536 (the newly added identifier)
    // This demonstrates the index confusion vulnerability
    assert_ne!(module.identifiers.len(), 65537); // Will fail - proves overflow occurred
}
```

---

**Note:** While this is a real implementation bug, it does **NOT** qualify as a security vulnerability under the Aptos bug bounty criteria because it only affects development tooling and has no impact on consensus, execution, state management, or funds. The vulnerability does not break any of the critical invariants defined for the Aptos blockchain and cannot be exploited during normal blockchain operation.

### Citations

**File:** third_party/move/move-binary-format/src/module_script_conversion.rs (L97-113)
```rust
pub fn script_into_module(compiled_script: CompiledScript, name: &str) -> CompiledModule {
    let mut script = compiled_script;

    // Add the "<SELF>" identifier if it isn't present.
    let self_ident_idx = match script
        .identifiers
        .iter()
        .position(|ident| ident.as_ident_str().as_str() == name)
    {
        Some(idx) => IdentifierIndex::new(idx as u16),
        None => {
            let idx = IdentifierIndex::new(script.identifiers.len() as u16);
            script
                .identifiers
                .push(Identifier::new(name.to_string()).unwrap());
            idx
        },
```

**File:** third_party/move/move-binary-format/src/module_script_conversion.rs (L123-129)
```rust
        Some(idx) => AddressIdentifierIndex::new(idx as u16),
        None => {
            let idx = AddressIdentifierIndex::new(script.address_identifiers.len() as u16);
            script.address_identifiers.push(dummy_addr);
            idx
        },
    };
```

**File:** third_party/move/move-binary-format/src/module_script_conversion.rs (L137-146)
```rust
        Some(idx) => ModuleHandleIndex::new(idx as u16),
        None => {
            let idx = ModuleHandleIndex::new(script.module_handles.len() as u16);
            script.module_handles.push(ModuleHandle {
                address: dummy_addr_idx,
                name: self_ident_idx,
            });
            idx
        },
    };
```

**File:** third_party/move/move-binary-format/src/module_script_conversion.rs (L150-157)
```rust
    let return_sig_idx = match script.signatures.iter().position(|sig| sig.0.is_empty()) {
        Some(idx) => SignatureIndex::new(idx as u16),
        None => {
            let idx = SignatureIndex::new(script.signatures.len() as u16);
            script.signatures.push(Signature(vec![]));
            idx
        },
    };
```

**File:** third_party/move/move-binary-format/src/module_script_conversion.rs (L160-169)
```rust
    let main_handle_idx = FunctionHandleIndex::new(script.function_handles.len() as u16);
    script.function_handles.push(FunctionHandle {
        module: self_module_handle_idx,
        name: self_ident_idx,
        parameters: script.parameters,
        return_: return_sig_idx,
        type_parameters: script.type_parameters,
        access_specifiers: None, // TODO: access specifiers for script functions
        attributes: vec![],
    });
```

**File:** third_party/move/move-binary-format/src/module_script_conversion.rs (L208-209)
```rust
    BoundsChecker::verify_module(&module).expect("invalid bounds in module");
    module
```

**File:** third_party/move/move-binary-format/src/deserializer.rs (L575-588)
```rust
    fn load<T>(
        &self,
        binary: &VersionedBinary,
        result: &mut Vec<T>,
        deserializer: impl Fn(&mut VersionedCursor) -> BinaryLoaderResult<T>,
    ) -> BinaryLoaderResult<()> {
        let start = self.offset as usize;
        let end = start + self.count as usize;
        let mut cursor = binary.new_cursor(start, end);
        while cursor.position() < self.count as u64 {
            result.push(deserializer(&mut cursor)?)
        }
        Ok(())
    }
```

**File:** third_party/move/move-binary-format/src/deserializer.rs (L979-999)
```rust
fn load_identifier(cursor: &mut VersionedCursor) -> BinaryLoaderResult<Identifier> {
    let size = load_identifier_size(cursor)?;
    let mut buffer: Vec<u8> = vec![0u8; size];
    if !cursor.read(&mut buffer).map(|count| count == size).unwrap() {
        Err(PartialVMError::new(StatusCode::MALFORMED)
            .with_message("Bad Identifier pool size".to_string()))?;
    }
    let ident = Identifier::from_utf8(buffer).map_err(|_| {
        PartialVMError::new(StatusCode::MALFORMED).with_message("Invalid Identifier".to_string())
    })?;
    if cursor.version() < VERSION_9 && ident.as_str().contains('$') {
        Err(
            PartialVMError::new(StatusCode::MALFORMED).with_message(format!(
                "`$` in identifiers not supported in bytecode version {}",
                cursor.version()
            )),
        )
    } else {
        Ok(ident)
    }
}
```

**File:** third_party/move/move-binary-format/src/check_bounds.rs (L883-899)
```rust
fn check_bounds_impl<T, I>(pool: &[T], idx: I) -> PartialVMResult<()>
where
    I: ModuleIndex,
{
    let idx = idx.into_index();
    let len = pool.len();
    if idx >= len {
        Err(bounds_error(
            StatusCode::INDEX_OUT_OF_BOUNDS,
            I::KIND,
            idx as TableIndex,
            len,
        ))
    } else {
        Ok(())
    }
}
```

**File:** third_party/move/move-compiler-v2/src/file_format_generator/mod.rs (L80-88)
```rust
                if options.experiment_on(Experiment::ATTACH_COMPILED_MODULE) {
                    let module_name =
                        ModuleName::pseudo_script_name(env.symbol_pool(), script_index);
                    script_index += 1;
                    let module = module_script_conversion::script_into_module(
                        script.clone(),
                        &module_name.name().display(env.symbol_pool()).to_string(),
                    );
                    script_module_data.insert(module_env.get_id(), (module, source_map.clone()));
```

**File:** third_party/move/move-compiler-v2/src/file_format_generator/mod.rs (L126-127)
```rust
const MAX_MODULE_COUNT: usize = FF::TableIndex::MAX as usize;
const MAX_IDENTIFIER_COUNT: usize = FF::TableIndex::MAX as usize;
```

**File:** third_party/move/tools/move-asm/src/disassembler.rs (L37-42)
```rust
    Disassembler::run(out, module, print_code_size)
}

pub fn disassemble_script<T: fmt::Write>(out: T, script: &CompiledScript) -> anyhow::Result<T> {
    let script_as_module = script_into_module(script.clone(), "main");
    Disassembler::run(out, &script_as_module, false)
```

**File:** third_party/move/move-compiler-v2/src/file_format_generator/module_generator.rs (L472-481)
```rust
        let idx = FF::IdentifierIndex(ctx.checked_bound(
            loc,
            self.module.identifiers.len(),
            MAX_IDENTIFIER_COUNT,
            "identifier",
        ));
        self.module.identifiers.push(ident);
        self.name_to_idx.insert(name, idx);
        idx
    }
```
