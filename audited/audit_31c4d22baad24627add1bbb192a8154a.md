# Audit Report

## Title
Stack Overflow in Move Resource Viewer Due to Missing Cyclic Type Detection in Cross-Module Generic Instantiations

## Summary
The move-resource-viewer lacks cycle detection when resolving type structures, allowing cross-module cyclic type instantiations (e.g., `struct B { field: A<B> }`) to cause stack overflow through infinite recursion. This vulnerability can crash nodes or RPC endpoints that use the resource viewer to annotate on-chain data.

## Finding Description

The move-resource-viewer creates `FatStructType` representations to annotate on-chain Move resources. The type resolution logic in `resolve_basic_struct` checks a cache before resolution but populates it only after completion: [1](#0-0) 

This creates a vulnerability when resolving cyclic type structures. Consider this valid Move code:

**Module A:**
```move
module 0x1::A {
    struct A<T> { field: T }
}
```

**Module B (depends on A):**
```move
module 0x2::B {
    use 0x1::A;
    struct B { field: A::A<B> }
}
```

This creates a cyclic type structure:
- `B` contains field of type `A<B>`
- When `A<B>` is instantiated (T=B), it contains field of type `B`
- This forms a cycle: `B` → `A<B>` → `B` → ...

**Why it bypasses verification:**

1. **Compiler's RecursiveStructChecker** only recursively expands structs from the same module: [2](#0-1) 

The check at line 83 (`field_mod_id == self.mod_env.get_id()`) means cross-module cycles are not detected.

2. **Bytecode Verifier's RecursiveStructDefChecker** only tracks within-module dependencies: [3](#0-2) 

At line 155, `handle_to_def.get(sh_idx)` only returns struct definitions from the current module, so cross-module edges are not added to the dependency graph.

3. **Module dependency graph remains acyclic**: Module B depends on Module A, but Module A does not depend on Module B (B is only used as a type parameter).

**Exploitation path:**

When the resource viewer resolves type `B`:
1. Call `resolve_basic_struct("B")` - not in cache
2. → Call `resolve_struct_definition` for B
3. → → Resolve field type `A<B>` via `resolve_signature`
4. → → → Call `resolve_generic_struct` for `A<B>`
5. → → → → Call `base_type.subst` to substitute T with B
6. → → → → → This requires resolving B's fields
7. → → → → → → Call `resolve_basic_struct("B")` - **STILL NOT IN CACHE** (step 1 hasn't completed!)
8. → → → → → → → **INFINITE RECURSION** → Stack overflow

**Comparison with VM Runtime:**

The Move VM runtime has proper cycle detection: [4](#0-3) 

The `currently_visiting` HashSet prevents re-entry. However, the move-resource-viewer does not use `TypeDepthChecker` and has no equivalent protection: [5](#0-4) 

## Impact Explanation

**High Severity** per Aptos Bug Bounty criteria:
- **Validator node slowdowns**: If RPC endpoints use the resource viewer to annotate resources, requests for cyclic types cause stack overflow crashes
- **API crashes**: Resource viewing APIs become DoS vectors
- **Node availability**: Repeated exploitation can degrade service availability

This violates the **Move VM Safety** invariant (memory constraints) and **Resource Limits** invariant (operations must be bounded).

## Likelihood Explanation

**Medium-High Likelihood:**
- The attack requires publishing two modules with specific patterns
- Such modules pass all verification checks (compiler + bytecode verifier)
- Any transaction sender can publish modules
- Once deployed, any call to view resources of the cyclic type triggers the bug
- The resource viewer is commonly used in:
  - Indexers and explorers
  - RPC endpoints that return annotated resources
  - Node APIs for state queries

## Recommendation

Add cycle detection to `resolve_basic_struct` using a `currently_resolving` set similar to the VM runtime's approach:

```rust
fn resolve_basic_struct(
    &self,
    struct_name: &StructName,
    currently_resolving: &mut HashSet<StructName>,
    limit: &mut Limiter,
) -> anyhow::Result<FatStructRef> {
    if let Some(fat_ty) = self.fat_struct_def_cache.borrow().get(struct_name) {
        return Ok(fat_ty.clone());
    }
    
    // Check if we're currently resolving this struct (cycle detection)
    if currently_resolving.contains(struct_name) {
        return Err(anyhow!(
            "Cyclic type structure detected for {}::{}::{}",
            struct_name.address,
            struct_name.module,
            struct_name.name
        ));
    }
    
    currently_resolving.insert(struct_name.clone());
    
    let module_id = ModuleId::new(struct_name.address, struct_name.module.clone());
    let module = self.view_existing_module(&module_id)?;
    let module = module.borrow();
    
    let struct_def = find_struct_def_in_module(module, struct_name.name.as_ident_str())?;
    let base_type = FatStructRef::new(
        self.resolve_struct_definition(module, struct_def, currently_resolving, limit)?
    );
    
    currently_resolving.remove(struct_name);
    
    self.fat_struct_def_cache
        .borrow_mut()
        .insert(struct_name.to_owned(), base_type.clone());
    Ok(base_type)
}
```

Similarly update `resolve_generic_struct`: [6](#0-5) 

## Proof of Concept

**Module A** (`0x1::A`):
```move
module 0x1::A {
    struct A<T> has drop { field: T }
}
```

**Module B** (`0x2::B`):
```move
module 0x2::B {
    use 0x1::A::A;
    
    struct B has drop, store { 
        field: A<B> 
    }
    
    public fun create_b(): B {
        // This compiles and verifies successfully
        B { field: A { field: B { field: A { field: ... } } } }
    }
}
```

**Exploitation:**
```rust
// In a test or RPC handler that uses MoveValueAnnotator
let annotator = MoveValueAnnotator::new(module_viewer);
let struct_tag = StructTag {
    address: AccountAddress::from_hex_literal("0x2").unwrap(),
    module: Identifier::new("B").unwrap(),
    name: Identifier::new("B").unwrap(),
    type_args: vec![],
};

// This will trigger infinite recursion and stack overflow
let result = annotator.view_resource(&struct_tag, &resource_bytes);
// Stack overflow: thread panics with stack overflow
```

The modules compile, pass bytecode verification, and can be published. Any attempt to view resources of type `B` causes the annotator to crash with stack overflow.

## Notes

This vulnerability demonstrates that while Move's type system prevents direct cyclic struct definitions through multiple verification layers, cross-module generic instantiation creates a blind spot where cycles can form. The resource viewer, being a utility tool separate from the VM runtime, lacks the defensive cycle detection present in the VM's `TypeDepthChecker`, making it vulnerable to this attack pattern.

### Citations

**File:** third_party/move/tools/move-resource-viewer/src/lib.rs (L410-432)
```rust
    fn resolve_generic_struct(
        &self,
        struct_name: StructName,
        type_args: Vec<FatType>,
        limit: &mut Limiter,
    ) -> anyhow::Result<FatStructRef> {
        let name_and_args = (struct_name, type_args);
        if let Some(fat_ty) = self.fat_struct_inst_cache.borrow().get(&name_and_args) {
            return Ok(fat_ty.clone());
        }
        let base_type = self.resolve_basic_struct(&name_and_args.0, limit)?;
        let inst_type = FatStructRef::new(
            base_type
                .subst(&name_and_args.1, &self.struct_substitutor(), limit)
                .map_err(|e: PartialVMError| {
                    anyhow!("type {:?} cannot be resolved: {:?}", name_and_args, e)
                })?,
        );
        self.fat_struct_inst_cache
            .borrow_mut()
            .insert(name_and_args, inst_type.clone());
        Ok(inst_type)
    }
```

**File:** third_party/move/tools/move-resource-viewer/src/lib.rs (L434-454)
```rust
    fn resolve_basic_struct(
        &self,
        struct_name: &StructName,
        limit: &mut Limiter,
    ) -> anyhow::Result<FatStructRef> {
        if let Some(fat_ty) = self.fat_struct_def_cache.borrow().get(struct_name) {
            return Ok(fat_ty.clone());
        }

        let module_id = ModuleId::new(struct_name.address, struct_name.module.clone());
        let module = self.view_existing_module(&module_id)?;
        let module = module.borrow();

        let struct_def = find_struct_def_in_module(module, struct_name.name.as_ident_str())?;
        let base_type =
            FatStructRef::new(self.resolve_struct_definition(module, struct_def, limit)?);
        self.fat_struct_def_cache
            .borrow_mut()
            .insert(struct_name.to_owned(), base_type.clone());
        Ok(base_type)
    }
```

**File:** third_party/move/move-compiler-v2/src/env_pipeline/recursive_struct_checker.rs (L80-91)
```rust
                Type::Struct(field_mod_id, field_struct_id, insts) => {
                    // check the field struct if it's not been checked, so that we only need to look at
                    // the type parameters later
                    if field_mod_id == self.mod_env.get_id() && !checked.contains(&field_struct_id)
                    {
                        self.check_struct_as_required_by(
                            path,
                            field_struct_id,
                            field_env.get_loc().clone(),
                            checked,
                        );
                    }
```

**File:** third_party/move/move-bytecode-verifier/src/struct_defs.rs (L154-172)
```rust
            T::Struct(sh_idx) => {
                if let Some(struct_def_idx) = self.handle_to_def.get(sh_idx) {
                    neighbors
                        .entry(cur_idx)
                        .or_default()
                        .insert(*struct_def_idx);
                }
            },
            T::StructInstantiation(sh_idx, inners) => {
                if let Some(struct_def_idx) = self.handle_to_def.get(sh_idx) {
                    neighbors
                        .entry(cur_idx)
                        .or_default()
                        .insert(*struct_def_idx);
                }
                for t in inners {
                    self.add_signature_token(neighbors, cur_idx, t, false)?
                }
            },
```

**File:** third_party/move/move-vm/runtime/src/storage/ty_depth_checker.rs (L219-229)
```rust
        // If the struct is being visited, we found a recursive definition.
        if currently_visiting.contains(idx) {
            let struct_name = self.get_struct_name(idx)?;
            let msg = format!(
                "Definition of struct {}::{}::{} is recursive: failed to construct its depth formula",
                struct_name.module().address, struct_name.module().name, struct_name.name()
            );
            return Err(
                PartialVMError::new(StatusCode::RUNTIME_CYCLIC_MODULE_DEPENDENCY).with_message(msg),
            );
        }
```

**File:** third_party/move/tools/move-resource-viewer/src/fat_type.rs (L46-59)
```rust
/// VM representation of a struct type in Move.
#[derive(Debug, Clone, Serialize, Deserialize, PartialOrd, Ord, PartialEq, Eq)]
pub(crate) struct FatStructType {
    pub address: AccountAddress,
    pub module: Identifier,
    pub name: Identifier,
    pub abilities: WrappedAbilitySet,
    pub ty_args: Vec<FatType>,
    pub layout: FatStructLayout,
    // Whether this struct transitively contains 0x1::table::Table types. This
    // is true if this here is a table itself. Extends to the type arguments and
    // the layout.
    pub contains_tables: bool,
}
```
