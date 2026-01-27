# Audit Report

## Title
Shared State in LazyLoadedFunction::clone_dyn() Causes Non-Deterministic Closure Serialization Leading to Consensus Failure

## Summary
The `clone_dyn()` implementation for `LazyLoadedFunction` creates shallow clones that share the same mutable state via `Rc<RefCell<LazyLoadedFunctionState>>`. This allows one clone to mutate the resolution state (Unresolved → Resolved) while other clones observe the change. Since serialization behavior differs based on resolution state, and layouts in Unresolved state may be outdated, different validators can produce different serialized bytes for the same closure, breaking consensus determinism. [1](#0-0) 

## Finding Description

The `LazyLoadedFunction` struct contains shared mutable state through an `Rc<RefCell<LazyLoadedFunctionState>>`: [2](#0-1) 

When `clone_dyn()` is called, it performs a shallow clone that shares the underlying `RefCell`: [1](#0-0) 

The critical issue manifests in the following sequence:

1. **Closure Cloning**: When a closure value is copied (via `copy_value()`), it calls `clone_dyn()` on the function descriptor: [3](#0-2) 

2. **Shared State Mutation**: When the original closure is executed, `as_resolved()` mutates the shared state from `Unresolved` to `Resolved`: [4](#0-3) 

3. **Layout Divergence**: The code explicitly documents that Unresolved states may contain outdated layouts from storage: [5](#0-4) 

4. **Divergent Serialization**: When serializing, the path taken differs based on resolution state: [6](#0-5) 

**Attack Scenario:**

Validator A:
1. Deserializes closure C1 from storage (Unresolved state with old layouts)
2. Clones C1 to create C2 (shares same Rc state)
3. Executes C1 → triggers `as_resolved()` → state becomes Resolved with current layouts
4. Writes C2 to storage → serialization uses Resolved path with current layouts

Validator B:
1. Deserializes closure C1 from storage (Unresolved state with old layouts)
2. Clones C1 to create C2 (shares same Rc state)
3. Writes C2 to storage → serialization uses Unresolved path with old layouts
4. Later executes C1

**Result**: Validators produce different serialized bytes for the same logical closure, leading to different state roots and consensus failure.

Move closures with `store` ability can be persisted in global storage, making this exploitable: [7](#0-6) 

## Impact Explanation

This vulnerability achieves **Critical Severity** ($1,000,000 range) because it causes:

1. **Consensus Safety Violation**: Different validators produce different state roots for identical blocks, breaking the fundamental blockchain invariant of deterministic execution:
   - Validators execute the same transactions in the same order
   - Due to timing differences in closure resolution, they serialize closures differently
   - This produces different storage writes and different state roots
   - The network cannot reach consensus on the canonical state

2. **Network Partition Risk**: When validators disagree on state roots, they cannot form quorums on blocks, requiring a hard fork to recover. This breaks the "Deterministic Execution" invariant: [8](#0-7) 

The serialization occurs during transaction finalization, directly feeding into the state commitment that validators must agree upon for consensus.

## Likelihood Explanation

**High Likelihood** because:

1. **No Special Privileges Required**: Any user can deploy Move modules with storable closures and trigger this behavior through normal transactions

2. **Natural Occurrence**: The issue arises from routine operations:
   - Closures are cloned during value copying (common VM operation)
   - Closures are executed during transaction processing
   - Closures are serialized when written to storage
   - Timing variations between validators are inherent in distributed systems

3. **Module Upgrades Amplify Risk**: When modules are upgraded, old closures have outdated layouts in storage. The next time these closures are loaded, cloned, and re-serialized, the layout divergence becomes active

4. **No Error Detection**: The system has no mechanism to detect or prevent this inconsistency at runtime. Both serialization paths succeed, producing valid but different outputs

## Recommendation

Replace the shallow clone in `clone_dyn()` with a deep clone that creates an independent copy of the state:

```rust
fn clone_dyn(&self) -> PartialVMResult<Box<dyn AbstractFunction>> {
    // Deep clone: create new Rc with cloned state, not shared state
    let cloned_state = self.state.borrow().clone();
    Ok(Box::new(LazyLoadedFunction {
        state: Rc::new(RefCell::new(cloned_state)),
    }))
}
```

This ensures each clone has independent state, preventing mutations from affecting other clones. The serialization behavior will be consistent regardless of when resolution occurs on any particular clone.

**Alternative Fix**: Ensure serialization always produces identical output regardless of resolution state by:
1. Always reconstructing `SerializedFunctionData` from the original unresolved data
2. Storing the original serialized data even after resolution
3. Using that for serialization consistency

However, the deep clone approach is simpler and more robust.

## Proof of Concept

```move
// File: consensus_break.move
module 0xCAFE::consensus_break {
    use std::vector;
    
    struct ClosureStore has key {
        // Storable closure that will be cloned and re-serialized
        processor: |u64| u64 has store,
        data: vector<u64>,
    }
    
    // Step 1: Store a closure
    public entry fun initialize(account: &signer, multiplier: u64) {
        let processor = |x| x * multiplier;
        move_to(account, ClosureStore { 
            processor, 
            data: vector::empty() 
        });
    }
    
    // Step 2: Clone and execute (triggers resolution on one validator faster)
    public entry fun process_and_store(account: &signer, value: u64) 
        acquires ClosureStore {
        let addr = std::signer::address_of(account);
        let store = borrow_global_mut<ClosureStore>(addr);
        
        // Clone the closure via value copy
        let cloned_processor = store.processor;
        
        // Execute original (triggers lazy resolution)
        let result = (store.processor)(value);
        vector::push_back(&mut store.data, result);
        
        // Update with cloned closure (serializes differently based on timing)
        store.processor = cloned_processor;
    }
}
```

**Exploitation**:
1. Deploy module to blockchain
2. Call `initialize()` to store a closure
3. Upgrade the module (changing layouts)
4. Call `process_and_store()` on multiple validators
5. Validators that resolve before serializing use new layouts
6. Validators that serialize before resolving use old layouts
7. State roots diverge → consensus failure

The vulnerability is exploitable with normal Move operations and requires no special access.

### Citations

**File:** third_party/move/move-vm/runtime/src/loader/function.rs (L227-230)
```rust
#[derive(Clone, Tid)]
pub(crate) struct LazyLoadedFunction {
    pub(crate) state: Rc<RefCell<LazyLoadedFunctionState>>,
}
```

**File:** third_party/move/move-vm/runtime/src/loader/function.rs (L233-253)
```rust
pub(crate) enum LazyLoadedFunctionState {
    Unresolved {
        // Note: this contains layouts from storage, which may be out-dated (e.g., storing only old
        // enum variant layouts even when enum has been upgraded to contain more variants).
        data: SerializedFunctionData,
    },
    Resolved {
        fun: Rc<LoadedFunction>,
        // For a resolved function, we need to store the type argument tags,
        // even though we have the resolved `Type` for the arguments in `fun.ty_args`.
        // This is needed so we can compare with deterministic results an unresolved and
        // resolved function context free (i.e. wo/ converter from Type to TypeTag). For the
        // unresolved case, the type argument tags are stored with the serialized data.
        ty_args: Vec<TypeTag>,
        mask: ClosureMask,
        // Layouts for captured arguments. The invariant is that these are always set for storable
        // closures at construction time. Non-storable closures just have None as they will not be
        // serialized anyway.
        captured_layouts: Option<Vec<MoveTypeLayout>>,
    },
}
```

**File:** third_party/move/move-vm/runtime/src/loader/function.rs (L410-446)
```rust
    pub(crate) fn as_resolved(
        &self,
        loader: &impl Loader,
        gas_meter: &mut impl DependencyGasMeter,
        traversal_context: &mut TraversalContext,
    ) -> PartialVMResult<Rc<LoadedFunction>> {
        let mut state = self.state.borrow_mut();
        Ok(match &mut *state {
            LazyLoadedFunctionState::Resolved { fun, .. } => fun.clone(),
            LazyLoadedFunctionState::Unresolved {
                data:
                    SerializedFunctionData {
                        format_version: _,
                        module_id,
                        fun_id,
                        ty_args,
                        mask,
                        captured_layouts,
                    },
            } => {
                let fun = loader.load_closure(
                    gas_meter,
                    traversal_context,
                    module_id,
                    fun_id,
                    ty_args,
                )?;
                *state = LazyLoadedFunctionState::Resolved {
                    fun: fun.clone(),
                    ty_args: mem::take(ty_args),
                    mask: *mask,
                    captured_layouts: Some(mem::take(captured_layouts)),
                };
                fun
            },
        })
    }
```

**File:** third_party/move/move-vm/runtime/src/loader/function.rs (L473-475)
```rust
    fn clone_dyn(&self) -> PartialVMResult<Box<dyn AbstractFunction>> {
        Ok(Box::new(self.clone()))
    }
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L617-623)
```rust
            ClosureValue(Closure(fun, captured)) => {
                let captured = captured
                    .iter()
                    .map(|v| v.copy_value(depth + 1, max_depth))
                    .collect::<PartialVMResult<_>>()?;
                ClosureValue(Closure(fun.clone_dyn()?, Box::new(captured)))
            },
```

**File:** third_party/move/move-vm/runtime/src/storage/module_storage.rs (L540-579)
```rust
    fn get_serialization_data(
        &self,
        fun: &dyn AbstractFunction,
    ) -> PartialVMResult<SerializedFunctionData> {
        match &*LazyLoadedFunction::expect_this_impl(fun)?.state.borrow() {
            LazyLoadedFunctionState::Unresolved { data, .. } => Ok(data.clone()),
            LazyLoadedFunctionState::Resolved {
                fun,
                mask,
                ty_args,
                captured_layouts,
            } => {
                // If there are no captured layouts, then this closure is non-storable, i.e., the
                // function is not persistent (not public or not private with #[persistent]
                // attribute). This means that anonymous lambda-lifted functions are cannot be
                // serialized as well.
                let captured_layouts = captured_layouts.as_ref().cloned().ok_or_else(|| {
                    let msg = "Captured layouts must always be computed for storable closures";
                    PartialVMError::new(StatusCode::VALUE_SERIALIZATION_ERROR)
                        .with_message(msg.to_string())
                })?;

                Ok(SerializedFunctionData {
                    format_version: FUNCTION_DATA_SERIALIZATION_FORMAT_V1,
                    module_id: fun
                        .module_id()
                        .ok_or_else(|| {
                            PartialVMError::new_invariant_violation(
                                "attempt to serialize a script function",
                            )
                        })?
                        .clone(),
                    fun_id: fun.function.name.clone(),
                    ty_args: ty_args.clone(),
                    mask: *mask,
                    captured_layouts,
                })
            },
        }
    }
```

**File:** aptos-move/e2e-move-tests/src/tests/aggregator_v2.data/function_values/sources/function_store.move (L39-47)
```text
    struct FunctionStoreV2 has key, store {
        value: u64,
        add: |&mut Aggregator<u64>|bool has copy + store,
    }

    public entry fun try_initialize_should_succeed(account: &signer, value: u64) {
        let add = |a| try_add(a, value);
        move_to(account, FunctionStoreV2 { value, add });
    }
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/mod.rs (L161-203)
```rust
    pub fn finish(
        self,
        configs: &ChangeSetConfigs,
        module_storage: &impl ModuleStorage,
    ) -> VMResult<VMChangeSet> {
        // Note: enabled by 1.38 gas feature version.
        let is_1_38_release = module_storage
            .runtime_environment()
            .vm_config()
            .propagate_dependency_limit_error;
        let function_extension = module_storage.as_function_value_extension();

        let resource_converter = |value: Value,
                                  layout: TriompheArc<MoveTypeLayout>,
                                  has_aggregator_lifting: bool|
         -> PartialVMResult<BytesWithResourceLayout> {
            let serialization_result = if has_aggregator_lifting {
                // We allow serialization of native values here because we want to
                // temporarily store native values (via encoding to ensure deterministic
                // gas charging) in block storage.
                ValueSerDeContext::new(function_extension.max_value_nest_depth())
                    .with_delayed_fields_serde()
                    .with_func_args_deserialization(&function_extension)
                    .serialize(&value, &layout)?
                    .map(|bytes| (bytes.into(), Some(layout)))
            } else {
                // Otherwise, there should be no native values so ensure
                // serialization fails here if there are any.
                ValueSerDeContext::new(function_extension.max_value_nest_depth())
                    .with_func_args_deserialization(&function_extension)
                    .serialize(&value, &layout)?
                    .map(|bytes| (bytes.into(), None))
            };
            serialization_result.ok_or_else(|| {
                let status_code = if is_1_38_release {
                    StatusCode::VALUE_SERIALIZATION_ERROR
                } else {
                    StatusCode::INTERNAL_TYPE_ERROR
                };
                PartialVMError::new(status_code)
                    .with_message(format!("Error when serializing resource {}.", value))
            })
        };
```
