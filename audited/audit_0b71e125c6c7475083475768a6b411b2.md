# Audit Report

## Title
Integer Overflow in script_into_module() Index Creation with Maximum-Size Script Vectors

## Summary
The `script_into_module()` function contains an integer overflow vulnerability when converting scripts with table vectors at or exceeding the u16 maximum size (65536 elements). The function casts vector lengths to u16 without overflow checks, causing incorrect index creation that references wrong elements in the resulting module.

## Finding Description

The `script_into_module()` function in `module_script_conversion.rs` converts a compiled script into a module by adding self-references (identifier, address, module handle, etc.). When creating indices for newly added elements, the function casts the current vector length directly to u16: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

If a script has exactly 65536 elements in any table (identifiers, address_identifiers, module_handles, signatures, or function_handles), the cast `65536 as u16` produces 0 due to integer overflow. This causes the index to reference element 0 instead of the newly added element at position 65536.

**Attack Scenario:**
1. Attacker crafts a script binary with exactly 65536 identifiers where index 0 contains a privileged module name (e.g., "aptos_framework")
2. The script's required identifier for conversion is not in the list
3. When `script_into_module()` executes, `idx = IdentifierIndex::new(65536 as u16)` creates index 0 (overflow)
4. The new identifier is pushed to position 65536, but `self_ident_idx` points to index 0
5. The resulting module has the privileged name from index 0 as its self-identifier

While the compiler enforces `MAX_IDENTIFIER_COUNT = TableIndex::MAX = 65535` [5](#0-4) , the deserializer does not explicitly validate table element counts, only checking that individual indices are valid and table sizes in bytes don't exceed limits [6](#0-5) .

The bounds checker called at line 208 does not validate table sizes: [7](#0-6) 

## Impact Explanation

**Medium Severity** - Limited impact due to restricted usage context:

The vulnerability has constrained practical impact because `script_into_module()` is only invoked in non-critical paths:
1. Disassembler tool for development [8](#0-7) 
2. Compiler when ATTACH_COMPILED_MODULE experiment is enabled [9](#0-8) 

However, the module identity corruption could theoretically:
- Cause module resolution failures
- Create confusion if the wrong identifier matches a system module name
- Violate the deterministic execution invariant if such modules were ever executed

The `.expect()` panic provides no graceful error handling, potentially causing tool crashes.

## Likelihood Explanation

**Low Likelihood** in production:
- Requires crafting a binary with exactly 65536 table elements
- Only affects development tools, not consensus/execution paths
- Resulting invalid modules would likely fail subsequent verification
- Compiler already prevents this during normal compilation

However, the overflow **will** occur if an adversarial binary meets the conditions.

## Recommendation

Add overflow checks before creating indices. Replace unchecked casts with checked operations:

```rust
let idx = script.identifiers.len()
    .try_into()
    .map_err(|_| anyhow::anyhow!("identifier table size exceeds u16::MAX"))?;
let self_ident_idx = IdentifierIndex::new(idx);
script.identifiers.push(Identifier::new(name.to_string())?);
```

Apply similar checks for all table index creations (lines 125, 139, 153, 160). Additionally, validate table sizes don't exceed `TABLE_INDEX_MAX` before conversion.

## Proof of Concept

```rust
#[test]
fn test_script_into_module_overflow() {
    use move_binary_format::file_format::*;
    use move_core_types::identifier::Identifier;
    
    // Create script with 65536 identifiers
    let mut script = CompiledScript::default();
    for i in 0..65536 {
        script.identifiers.push(
            Identifier::new(format!("id_{}", i)).unwrap()
        );
    }
    
    // Convert to module with name not in existing identifiers
    let module = script_into_module(script, "new_module");
    
    // self_ident_idx should be 65536, but due to overflow it's 0
    // This means module.identifiers[0] is used as module name
    // instead of module.identifiers[65536]
    
    // Verify the bug: module name should be "new_module" but 
    // due to overflow it's actually "id_0"
    let self_handle = &module.module_handles[module.self_module_handle_idx.0 as usize];
    let actual_name = &module.identifiers[self_handle.name.0 as usize];
    
    assert_eq!(actual_name.as_str(), "id_0"); // Bug confirmed
    assert_ne!(actual_name.as_str(), "new_module"); // Should be this
}
```

**Note Regarding Question Scope**: The security question specifically asks about **empty** script vectors. Empty vectors are handled correctly - they create valid index 0 and add elements properly. The vulnerability discovered involves **maximum-size** vectors (65536+ elements), which represents a different edge case than what the question targets.

### Citations

**File:** third_party/move/move-binary-format/src/module_script_conversion.rs (L108-108)
```rust
            let idx = IdentifierIndex::new(script.identifiers.len() as u16);
```

**File:** third_party/move/move-binary-format/src/module_script_conversion.rs (L125-125)
```rust
            let idx = AddressIdentifierIndex::new(script.address_identifiers.len() as u16);
```

**File:** third_party/move/move-binary-format/src/module_script_conversion.rs (L139-139)
```rust
            let idx = ModuleHandleIndex::new(script.module_handles.len() as u16);
```

**File:** third_party/move/move-binary-format/src/module_script_conversion.rs (L153-153)
```rust
            let idx = SignatureIndex::new(script.signatures.len() as u16);
```

**File:** third_party/move/move-binary-format/src/module_script_conversion.rs (L208-208)
```rust
    BoundsChecker::verify_module(&module).expect("invalid bounds in module");
```

**File:** third_party/move/move-compiler-v2/src/file_format_generator/mod.rs (L84-86)
```rust
                    let module = module_script_conversion::script_into_module(
                        script.clone(),
                        &module_name.name().display(env.symbol_pool()).to_string(),
```

**File:** third_party/move/move-compiler-v2/src/file_format_generator/mod.rs (L127-127)
```rust
const MAX_IDENTIFIER_COUNT: usize = FF::TableIndex::MAX as usize;
```

**File:** third_party/move/move-binary-format/src/deserializer.rs (L573-588)
```rust
impl Table {
    /// Generic function to deserialize a table into a vector of given type.
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

**File:** third_party/move/tools/move-asm/src/disassembler.rs (L41-41)
```rust
    let script_as_module = script_into_module(script.clone(), "main");
```
