# Audit Report

## Title
Unmetered Type Instantiation Cost in Entry Functions Enables Validator Resource Exhaustion

## Summary
The Move VM's eager loader does not charge gas for the computational cost of converting type arguments from `TypeTag` to `Type` when loading entry functions. Attackers can exploit this by calling entry functions with maximally complex but unused type arguments, forcing validators to perform expensive recursive type processing without proportional gas payment.

## Finding Description

When an entry function is invoked with generic type arguments, the execution flow through the Move VM processes these types in several stages: [1](#0-0) 

The loader's `load_instantiated_function` method is responsible for converting the type arguments from their serialized `TypeTag` format into runtime `Type` representations. In the eager loader implementation, this conversion happens through: [2](#0-1) 

Notice that the `gas_meter` parameter is explicitly unused (underscore prefix), and the method calls `unmetered_load_type`. This function performs recursive type processing: [3](#0-2) 

The `create_ty` method recursively processes nested type structures, performing struct lookups and memory allocations: [4](#0-3) 

While the function enforces hard limits (`max_ty_size=128` nodes, `max_ty_depth=20`), it does **not charge any gas** for this computation. [5](#0-4) 

Gas is only charged in two scenarios:
1. For module dependencies used by type arguments (since gas feature version 27)
2. For local variables that actually use the type parameters during frame creation [6](#0-5) 

**Attack Scenario:**
1. Attacker deploys a module with an entry function accepting many type parameters but not using them:
   ```move
   public entry fun attack<T1, T2, T3, T4, T5>() { }
   ```

2. Attacker submits transactions calling this function with maximally complex type arguments (128 nodes each, depth 20), such as deeply nested vectors or complex struct instantiations

3. For each transaction, validators must:
   - Recursively traverse up to 128 nodes per type argument
   - Perform struct definition lookups
   - Allocate memory for type trees
   - **Without charging any gas for this computation**

4. Since the type parameters aren't used in locals, no gas is charged via `num_nodes_in_subst` either

This violates the critical invariant that "All operations must respect gas, storage, and computational limits."

## Impact Explanation

**Medium Severity** per Aptos bug bounty criteria:
- Enables **validator node slowdowns** through resource exhaustion without proportional cost
- While not causing consensus violations or fund loss, it allows attackers to consume validator CPU resources at minimal cost
- With 5 type parameters of 128 nodes each, an attacker can force validators to process 640 type nodes per transaction with only paying for module dependencies
- Sustained attacks could degrade network performance and validator responsiveness

The impact aligns with the bug bounty's Medium to High severity categories for validator slowdowns and resource exhaustion attacks.

## Likelihood Explanation

**High likelihood** of exploitation:
- Attack requires only the ability to submit transactions (no special privileges)
- Attacker can easily create a module with unused type parameters
- Type complexity limits (128 nodes, depth 20) are well-documented
- Attack can be sustained with multiple transactions
- No special validator access or coordination required
- Cost to attacker is minimal (only pays for module dependencies, not type processing)

## Recommendation

Implement gas metering for type argument loading in the eager loader:

```rust
fn load_ty_arg(
    &self,
    gas_meter: &mut impl DependencyGasMeter,
    traversal_context: &mut TraversalContext,
    ty_arg: &TypeTag,
) -> PartialVMResult<Type> {
    // Charge gas based on type tag complexity
    let type_complexity = estimate_type_tag_complexity(ty_arg);
    gas_meter.charge_ty_arg_load(type_complexity)?;
    
    self.unmetered_load_type(ty_arg)
}

fn estimate_type_tag_complexity(ty_tag: &TypeTag) -> u64 {
    // Count nodes in the type tag tree
    let mut count = 0;
    for _ in ty_tag.preorder_traversal_iter() {
        count += 1;
    }
    count
}
```

Introduce a new gas parameter `ty_arg_load_per_node` in the gas schedule to charge proportionally to type argument complexity. The charge should occur **before** the recursive type processing begins.

## Proof of Concept

```move
module attacker::exploit {
    // Entry function with unused type parameters
    public entry fun resource_exhaustion<
        T1, T2, T3, T4, T5, T6, T7, T8
    >() {
        // Empty - type parameters are not used
    }
}
```

Attack transaction:
```rust
// Call with maximally complex type arguments
let type_args = vec![
    TypeTag::Vector(Box::new(
        TypeTag::Vector(Box::new(
            TypeTag::Vector(Box::new(
                // ... nest up to depth 20, 128 total nodes
                TypeTag::U64
            ))
        ))
    )),
    // Repeat for T2-T8
];

let entry_fn = EntryFunction::new(
    ModuleId::new(attacker_addr, Identifier::new("exploit").unwrap()),
    Identifier::new("resource_exhaustion").unwrap(),
    type_args,  // 8 type args × 128 nodes = 1024 nodes processed
    vec![]      // No arguments
);
```

Each transaction forces validators to process 1024 type nodes without charging gas for this computation, only paying for the entry function execution (which is nearly free since the function body is empty) and potentially module dependency loading.

## Notes

This vulnerability affects the eager loader specifically. The issue stems from the explicit design decision to make type loading "unmetered" as evidenced by the function name and unused gas_meter parameter. While module dependency charging was added in gas feature version 27, the computational cost of type processing itself remains uncharged, creating an exploitable resource exhaustion vector.

### Citations

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L960-967)
```rust
            let function = loader.load_instantiated_function(
                &legacy_loader_config,
                gas_meter,
                traversal_context,
                entry_fn.module(),
                entry_fn.function(),
                entry_fn.ty_args(),
            )?;
```

**File:** third_party/move/move-vm/runtime/src/storage/loader/eager.rs (L57-68)
```rust
    /// Converts a type tag into a runtime type. Can load struct definitions.
    fn unmetered_load_type(&self, tag: &TypeTag) -> PartialVMResult<Type> {
        self.runtime_environment()
            .vm_config()
            .ty_builder
            .create_ty(tag, |st| {
                self.module_storage
                    .unmetered_get_existing_eagerly_verified_module(&st.address, &st.module)
                    .and_then(|module| module.get_struct(&st.name))
                    .map_err(|err| err.to_partial())
            })
    }
```

**File:** third_party/move/move-vm/runtime/src/storage/loader/eager.rs (L258-265)
```rust
    fn load_ty_arg(
        &self,
        _gas_meter: &mut impl DependencyGasMeter,
        _traversal_context: &mut TraversalContext,
        ty_arg: &TypeTag,
    ) -> PartialVMResult<Type> {
        self.unmetered_load_type(ty_arg)
    }
```

**File:** third_party/move/move-vm/types/src/loaded_data/runtime_types.rs (L1195-1202)
```rust
    fn check(&self, count: &mut u64, depth: u64) -> PartialVMResult<()> {
        if *count >= self.max_ty_size {
            return self.too_many_nodes_error();
        }
        if depth > self.max_ty_depth {
            return self.too_large_depth_error();
        }
        Ok(())
```

**File:** third_party/move/move-vm/types/src/loaded_data/runtime_types.rs (L1433-1491)
```rust
    fn create_ty_impl<F>(
        &self,
        ty_tag: &TypeTag,
        resolver: &mut F,
        count: &mut u64,
        depth: u64,
    ) -> PartialVMResult<Type>
    where
        F: FnMut(&StructTag) -> PartialVMResult<Arc<StructType>>,
    {
        use Type::*;
        use TypeTag as T;

        self.check(count, depth)?;
        *count += 1;
        Ok(match ty_tag {
            T::Bool => Bool,
            T::U8 => U8,
            T::U16 => U16,
            T::U32 => U32,
            T::U64 => U64,
            T::U128 => U128,
            T::U256 => U256,
            T::I8 => I8,
            T::I16 => I16,
            T::I32 => I32,
            T::I64 => I64,
            T::I128 => I128,
            T::I256 => I256,
            T::Address => Address,
            T::Signer => Signer,
            T::Vector(elem_ty_tag) => {
                let elem_ty = self.create_ty_impl(elem_ty_tag, resolver, count, depth + 1)?;
                Vector(triomphe::Arc::new(elem_ty))
            },
            T::Struct(struct_tag) => {
                let struct_ty = resolver(struct_tag.as_ref())?;

                if struct_ty.ty_params.is_empty() && struct_tag.type_args.is_empty() {
                    Struct {
                        idx: struct_ty.idx,
                        ability: AbilityInfo::struct_(struct_ty.abilities),
                    }
                } else {
                    let mut ty_args = vec![];
                    for ty_arg in &struct_tag.type_args {
                        let ty_arg = self.create_ty_impl(ty_arg, resolver, count, depth + 1)?;
                        ty_args.push(ty_arg);
                    }
                    Type::verify_ty_arg_abilities(struct_ty.ty_param_constraints(), &ty_args)?;
                    StructInstantiation {
                        idx: struct_ty.idx,
                        ty_args: triomphe::Arc::new(ty_args),
                        ability: AbilityInfo::generic_struct(
                            struct_ty.abilities,
                            struct_ty.phantom_ty_params_mask.clone(),
                        ),
                    }
                }
```

**File:** third_party/move/move-vm/runtime/src/frame.rs (L195-203)
```rust
                let local_tys = function.local_tys();
                let mut local_ty_counts = Vec::with_capacity(local_tys.len());
                for ty in local_tys {
                    let cnt = NumTypeNodes::new(ty.num_nodes_in_subst(ty_args)? as u64);
                    gas_meter.charge_create_ty(cnt)?;
                    local_ty_counts.push(cnt);
                }
                cache_borrow.instantiated_local_ty_counts = Some(Rc::from(local_ty_counts));
            }
```
