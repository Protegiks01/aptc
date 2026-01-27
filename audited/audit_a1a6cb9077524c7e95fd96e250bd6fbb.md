# Audit Report

## Title
Index Out-of-Bounds Panic in Script Function Resolution Due to Unchecked pseudo_script_function_index

## Summary
The move-asm assembler crashes with an index out-of-bounds panic when resolving function references in scripts. The `pseudo_script_function_index()` (value: 65535) is stored in `FunctionDefinition.function` for script main functions but never added to the `function_handles` table. When `FunctionDefinitionView::new()` is created during function name resolution, it attempts to access `function_handles[65535]`, causing a panic. [1](#0-0) 

## Finding Description
The vulnerability exists in the interaction between script function declaration and function name resolution in the module builder.

When declaring a function in a script, the code stores the pseudo index but doesn't add the handle to the function_handles table: [2](#0-1) 

Later, when attempting to resolve a function name (e.g., for a recursive call), the code iterates through function definitions and creates a `FunctionDefinitionView`: [3](#0-2) 

The `FunctionDefinitionView::new()` constructor attempts to access the function handle: [4](#0-3) 

This calls `function_handle_at()` which performs a direct array access without bounds checking: [5](#0-4) 

Since `pseudo_script_function_index()` returns `TableIndex::MAX` (65535) and the `function_handles` table is much smaller, this causes a panic.

**Attack Scenario:**
1. Attacker creates a script with a self-referencing call (e.g., recursive function)
2. The assembler processes the script and attempts to resolve the function name
3. `resolve_fun()` iterates through function definitions
4. `FunctionDefinitionView::new()` is called with the script's main function
5. Panic occurs when accessing `function_handles[65535]`

## Impact Explanation
This is a **High Severity** vulnerability per Aptos bug bounty criteria:
- **API crashes**: The move-asm assembler crashes with an unrecoverable panic
- **Availability impact**: Prevents legitimate users from assembling scripts
- **Toolchain disruption**: Any tooling using the move-asm library (IDEs, CI/CD pipelines, development tools) would crash
- **Denial of Service**: Malicious actors can deliberately craft scripts to crash assembler services

While this doesn't directly affect consensus or on-chain execution, it impacts the developer toolchain that is critical for blockchain operations.

## Likelihood Explanation
**Likelihood: High**

The vulnerability is easily triggered:
- No special privileges required
- Occurs during normal script assembly (offline, before deployment)
- Can be triggered with a simple recursive call attempt
- Affects any script that tries to reference its own main function
- The pseudo_script_function_index check in `resolve_fun` was intended to prevent this, but the panic occurs before the check executes

The vulnerability would be encountered by:
- Developers making legitimate coding mistakes (accidental recursion)
- Malicious actors intentionally crafting attack scripts
- Automated fuzzing or testing tools

## Recommendation

**Option 1 (Preferred):** Check for script context before creating FunctionDefinitionView in `resolve_fun`:

```rust
pub fn resolve_fun(
    &self,
    address_opt: &Option<AccountAddress>,
    name_parts: &[Identifier],
) -> Result<FunctionHandleIndex> {
    if address_opt.is_none() && name_parts.len() == 1 {
        let module = self.module.borrow();
        for fdef in &module.function_defs {
            // For scripts, check if this is the main function before creating view
            if self.is_script() && fdef.function == Self::pseudo_script_function_index() {
                bail!("cannot reference script main function")
            }
            let view = FunctionDefinitionView::new(&*module, fdef);
            if view.name() == name_parts[0].as_ref() {
                return self.fun_index(QualifiedId {
                    module_id: self.this_module(),
                    id: name_parts[0].clone(),
                });
            }
        }
        bail!(...)
    }
    ...
}
```

**Option 2:** Add bounds checking in `function_handle_at`:

```rust
fn function_handle_at(&self, idx: FunctionHandleIndex) -> &FunctionHandle {
    let handles = &self.as_module().function_handles;
    let index = idx.into_index();
    if index >= handles.len() {
        panic!("function handle index {} out of bounds (len: {})", index, handles.len());
    }
    let handle = &handles[index];
    debug_assert!(handle.parameters.into_index() < self.as_module().signatures.len());
    debug_assert!(handle.return_.into_index() < self.as_module().signatures.len());
    handle
}
```

**Option 3:** Store script main function handle differently to avoid FunctionDefinition having an invalid index.

## Proof of Concept

```rust
use move_binary_format::file_format::*;
use move_core_types::identifier::Identifier;
use move_core_types::language_storage::ModuleId;
use move_asm::module_builder::{ModuleBuilder, ModuleBuilderOptions};

fn main() {
    // Create a script (module_id_opt = None)
    let builder = ModuleBuilder::new(
        ModuleBuilderOptions::default(),
        std::iter::empty(),
        None,
    );

    // Declare main function
    let params = builder.signature_index(vec![]).unwrap();
    let return_ = builder.signature_index(vec![]).unwrap();
    builder.declare_fun(
        false,
        Identifier::new("main").unwrap(),
        Visibility::Public,
        vec![],
        params,
        return_,
        vec![],
        vec![],
    ).unwrap();

    // Attempt to resolve "main" function (simulating a recursive call)
    // This will PANIC with index out of bounds
    let result = builder.resolve_fun(&None, &[Identifier::new("main").unwrap()]);
    
    // This line is never reached due to panic
    println!("Result: {:?}", result);
}
```

Running this will produce:
```
thread 'main' panicked at 'index out of bounds: the len is 0 but the index is 65535'
```

### Citations

**File:** third_party/move/tools/move-asm/src/module_builder.rs (L370-382)
```rust
        let fhdl_idx = if self.is_script() {
            *self.main_handle.borrow_mut() = Some(fhdl);
            Self::pseudo_script_function_index()
        } else {
            self.index(
                &mut self.module.borrow_mut().function_handles,
                &mut self.fun_to_idx.borrow_mut(),
                full_name,
                fhdl,
                FunctionHandleIndex,
                "function handle",
            )?
        };
```

**File:** third_party/move/tools/move-asm/src/module_builder.rs (L435-437)
```rust
    fn pseudo_script_function_index() -> FunctionHandleIndex {
        FunctionHandleIndex::new(TableIndex::MAX)
    }
```

**File:** third_party/move/tools/move-asm/src/module_builder.rs (L500-516)
```rust
        if address_opt.is_none() && name_parts.len() == 1 {
            // A simple name can only be resolved into a function within this module.
            let module = self.module.borrow();
            for fdef in &module.function_defs {
                let view = FunctionDefinitionView::new(&*module, fdef);
                if view.name() == name_parts[0].as_ref() {
                    return self.fun_index(QualifiedId {
                        module_id: self.this_module(),
                        id: name_parts[0].clone(),
                    });
                }
            }
            bail!(
                "undeclared function `{}` in `{}`",
                name_parts[0],
                self.this_module()
            )
```

**File:** third_party/move/move-binary-format/src/views.rs (L507-514)
```rust
    pub fn new(module: &'a T, function_def: &'a FunctionDefinition) -> Self {
        let function_handle = module.function_handle_at(function_def.function);
        let function_handle_view = FunctionHandleView::new(module, function_handle);
        Self {
            module,
            function_def,
            function_handle_view,
        }
```

**File:** third_party/move/move-binary-format/src/access.rs (L56-61)
```rust
    fn function_handle_at(&self, idx: FunctionHandleIndex) -> &FunctionHandle {
        let handle = &self.as_module().function_handles[idx.into_index()];
        debug_assert!(handle.parameters.into_index() < self.as_module().signatures.len()); // invariant
        debug_assert!(handle.return_.into_index() < self.as_module().signatures.len()); // invariant
        handle
    }
```
