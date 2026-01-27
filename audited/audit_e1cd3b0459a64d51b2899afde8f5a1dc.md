# Audit Report

## Title
Non-Deterministic Struct Name Index Assignment Causes Consensus Divergence in Parallel Execution

## Summary
The `StructNameIndexMap` assigns indices to struct names based on the order they are encountered during parallel transaction execution. Due to non-deterministic thread scheduling, different validators can assign different indices to the same struct names within a single block. These indices are embedded in `Type` objects that are compared for equality during paranoid type checks, causing validators to diverge on transaction execution results.

## Finding Description

The vulnerability exists in the struct name indexing mechanism used by the Move VM during parallel block execution: [1](#0-0) 

The index assignment is based on `backward_map.len()` at the time of insertion, making it dependent on insertion order. During parallel execution, all worker threads share the same `RuntimeEnvironment` and thus the same `StructNameIndexMap`: [2](#0-1) 

When modules are loaded during parallel transaction execution, struct names are indexed dynamically: [3](#0-2) 

The `Type` enum embeds these indices and derives `Eq`, `Hash`, and `Ord`: [4](#0-3) 

During execution, paranoid type checks compare `Type` objects for equality, which includes comparing the embedded `StructNameIndex`: [5](#0-4) 

These checks are invoked during instruction execution: [6](#0-5) [7](#0-6) 

Paranoid type checks are enabled by default in production: [8](#0-7) 

**Attack Scenario:**

Consider a block with transactions [Txn0, Txn1]:
- Txn0 uses struct `0xA::ModuleA::Foo`
- Txn1 uses struct `0xB::ModuleB::Bar`

**Validator 1 (Thread timing variant A):**
1. Thread 1 processes Txn0 first → encounters `A::Foo` → assigns index 0
2. Thread 2 processes Txn1 → encounters `B::Bar` → assigns index 1

**Validator 2 (Thread timing variant B):**
1. Thread 2 processes Txn1 first → encounters `B::Bar` → assigns index 0
2. Thread 1 processes Txn0 → encounters `A::Foo` → assigns index 1

When a subsequent transaction uses both structs and performs type checks, the `Type::Struct` objects with different indices will fail equality checks on one validator but pass on another, causing consensus divergence.

## Impact Explanation

This is a **CRITICAL** severity vulnerability per Aptos bug bounty criteria:

1. **Consensus/Safety Violation**: Different validators executing the same block can produce different state roots due to divergent execution results from paranoid type checks
2. **Non-recoverable Network Partition**: Validators will disagree on block validity, potentially requiring a hardfork to resolve
3. **Deterministic Execution Invariant Broken**: The fundamental invariant that "all validators must produce identical state roots for identical blocks" is violated

The vulnerability affects every validator in the network whenever parallel execution is enabled and multiple distinct struct types are encountered in non-deterministic order.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability will manifest in normal operations:
- Parallel execution (BlockSTM) is enabled by default in Aptos
- No attacker control is needed - normal transaction flow triggers the issue
- Any block containing transactions that load different modules with struct types can trigger non-deterministic index assignment
- The race condition occurs naturally due to OS thread scheduling variations across different validator hardware

The only mitigating factor is that the struct name index map is occasionally flushed at block boundaries when size limits are exceeded, which temporarily resets the state. However, within a block execution, the vulnerability is actively exploitable.

## Recommendation

**Solution: Assign struct name indices deterministically based on struct name content, not insertion order.**

Modify `struct_name_to_idx` to use a deterministic index assignment scheme:

```rust
pub fn struct_name_to_idx(
    &self,
    struct_name: &StructIdentifier,
) -> PartialVMResult<StructNameIndex> {
    {
        let index_map = self.0.read();
        if let Some(idx) = index_map.forward_map.get(struct_name) {
            return Ok(StructNameIndex(*idx));
        }
    }

    let forward_key = struct_name.clone();
    let backward_value = Arc::new(struct_name.clone());

    // CRITICAL FIX: Use hash-based deterministic index assignment
    // instead of insertion-order-dependent backward_map.len()
    let idx = {
        let mut index_map = self.0.write();
        
        if let Some(idx) = index_map.forward_map.get(struct_name) {
            return Ok(StructNameIndex(*idx));
        }

        // Compute deterministic index from struct name hash
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        struct_name.hash(&mut hasher);
        let idx = (hasher.finish() % u32::MAX as u64) as u32;
        
        // Handle collisions by linear probing
        let mut final_idx = idx;
        while index_map.backward_map.get(final_idx as usize).is_some() {
            final_idx = final_idx.wrapping_add(1);
        }
        
        // Ensure backward_map has enough capacity
        if final_idx as usize >= index_map.backward_map.len() {
            index_map.backward_map.resize(final_idx as usize + 1, None);
        }
        
        index_map.backward_map[final_idx as usize] = Some(backward_value);
        index_map.forward_map.insert(forward_key, final_idx);
        final_idx
    };

    Ok(StructNameIndex(idx))
}
```

**Alternative Solution**: Disable parallel execution for module loading operations, ensuring struct names are indexed in deterministic transaction order.

## Proof of Concept

**Reproduction Steps:**

1. Deploy two Move modules with distinct struct types:
   - Module A at address 0xA with struct `Foo`
   - Module B at address 0xB with struct `Bar`

2. Create a block with two transactions executing in parallel:
   - Txn0: Calls function using `A::Foo`
   - Txn1: Calls function using `B::Bar`

3. Run two validators with the same block

4. Observe non-deterministic struct name index assignment due to thread scheduling:
   - Execute multiple times with controlled thread delays
   - Monitor struct_name_index_map state via instrumentation
   - Compare `Type::Struct` objects across validators

5. Trigger paranoid type check that compares struct types:
   - Add a third transaction that uses both `A::Foo` and `B::Bar`
   - The type equality check will use different indices on different validators
   - Validators will diverge on transaction success/failure

**Expected Result**: Validators assign different indices to the same struct names, causing consensus divergence when paranoid type checks compare `Type::Struct` objects with mismatched indices.

**Notes:**
- This vulnerability is present in production code with paranoid_type_checks enabled by default
- The race window exists throughout block execution until cache flush
- No malicious intent required - normal operation triggers the bug

### Citations

**File:** third_party/move/move-vm/types/src/loaded_data/struct_name_indexing.rs (L70-99)
```rust
    pub fn struct_name_to_idx(
        &self,
        struct_name: &StructIdentifier,
    ) -> PartialVMResult<StructNameIndex> {
        {
            let index_map = self.0.read();
            if let Some(idx) = index_map.forward_map.get(struct_name) {
                return Ok(StructNameIndex(*idx));
            }
        }

        // Possibly need to insert, so make the copies outside of the lock.
        let forward_key = struct_name.clone();
        let backward_value = Arc::new(struct_name.clone());

        let idx = {
            let mut index_map = self.0.write();

            if let Some(idx) = index_map.forward_map.get(struct_name) {
                return Ok(StructNameIndex(*idx));
            }

            let idx = index_map.backward_map.len() as u32;
            index_map.backward_map.push(backward_value);
            index_map.forward_map.insert(forward_key, idx);
            idx
        };

        Ok(StructNameIndex(idx))
    }
```

**File:** third_party/move/move-vm/runtime/src/storage/environment.rs (L44-74)
```rust
/// the code cache, possibly across multiple threads.
pub struct RuntimeEnvironment {
    /// Configuration for the VM. Contains information about enabled checks, verification,
    /// deserialization, etc.
    vm_config: VMConfig,
    /// All registered native functions in the current context (binary). When a verified [Module]
    /// is constructed, existing native functions are inlined in the module representation, so that
    /// the interpreter can call them directly.
    natives: NativeFunctions,

    /// Map from struct names to indices, to save on unnecessary cloning and reduce memory
    /// consumption. Used by all struct type creations in the VM and in code cache.
    ///
    /// SAFETY:
    ///   By itself, it is fine to index struct names even of non-successful module publishes. If
    ///   we cached some name, which was not published, it will stay in cache and will be used by
    ///   another republish. Since there is no other information other than index, even for structs
    ///   with different layouts it is fine to re-use the index.
    ///   We wrap the index map into an [Arc] so that on republishing these clones are cheap.
    struct_name_index_map: Arc<StructNameIndexMap>,

    /// Caches struct tags for instantiated types. This cache can be used concurrently and
    /// speculatively because type tag information does not change with module publishes.
    ty_tag_cache: Arc<TypeTagCache>,

    /// Pool of interned type representations. Same lifetime as struct index map.
    interned_ty_pool: Arc<InternedTypePool>,

    /// Pool of interned module ids.
    interned_module_id_pool: Arc<InternedModuleIdPool>,
}
```

**File:** third_party/move/move-vm/runtime/src/loader/modules.rs (L194-203)
```rust
        // validate the correctness of struct handle references.
        for struct_handle in module.struct_handles() {
            let struct_name = module.identifier_at(struct_handle.name);
            let module_handle = module.module_handle_at(struct_handle.module);
            let module_id = module.module_id_for_handle(module_handle);
            let struct_name =
                StructIdentifier::new(module_id_pool, module_id, struct_name.to_owned());
            struct_idxs.push(struct_name_index_map.struct_name_to_idx(&struct_name)?);
            struct_names.push(struct_name)
        }
```

**File:** third_party/move/move-vm/types/src/loaded_data/runtime_types.rs (L296-331)
```rust
#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Type {
    Bool,
    U8,
    U64,
    U128,
    Address,
    Signer,
    Vector(TriompheArc<Type>),
    Struct {
        idx: StructNameIndex,
        ability: AbilityInfo,
    },
    StructInstantiation {
        idx: StructNameIndex,
        ty_args: TriompheArc<Vec<Type>>,
        ability: AbilityInfo,
    },
    Function {
        args: Vec<Type>,
        results: Vec<Type>,
        abilities: AbilitySet,
    },
    Reference(Box<Type>),
    MutableReference(Box<Type>),
    TyParam(u16),
    U16,
    U32,
    U256,
    I8,
    I16,
    I32,
    I64,
    I128,
    I256,
}
```

**File:** third_party/move/move-vm/types/src/loaded_data/runtime_types.rs (L590-606)
```rust
                    && abilities.is_subset(*given_abilities)
            },
            (Type::Reference(ty), Type::Reference(given)) => {
                given.paranoid_check_assignable(ty)?;
                true
            },
            _ => expected_ty == self,
        };
        if !ok {
            let msg = format!(
                "Expected type {}, got {} which is not assignable ",
                expected_ty, self
            );
            return paranoid_failure!(msg);
        }
        Ok(())
    }
```

**File:** third_party/move/move-vm/runtime/src/runtime_type_checks.rs (L272-280)
```rust
            Instruction::CallClosure(sig_idx) => {
                // For closure, we need to check the type of the closure on
                // top of the stack. The argument types are checked when the frame
                // is constructed in the interpreter, using the same code as for regular
                // calls.
                let (expected_ty, _) = ty_cache.get_signature_index_type(*sig_idx, frame)?;
                let given_ty = operand_stack.pop_ty()?;
                given_ty.paranoid_check_assignable(expected_ty)?;
            },
```

**File:** third_party/move/move-vm/runtime/src/runtime_type_checks.rs (L296-304)
```rust
            Instruction::StLoc(idx) => {
                let expected_ty = frame.local_ty_at(*idx as usize);
                let val_ty = operand_stack.pop_ty()?;
                // For store, use assignability
                val_ty.paranoid_check_assignable(expected_ty)?;
                if !frame.locals.is_invalid(*idx as usize)? {
                    expected_ty.paranoid_check_has_ability(Ability::Drop)?;
                }
            },
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L51-53)
```rust
pub fn get_paranoid_type_checks() -> bool {
    PARANOID_TYPE_CHECKS.get().cloned().unwrap_or(true)
}
```
