# Audit Report

## Title
Memory Quota Bypass in `bcs::to_bytes` Native Function via Unmetered Deep Copy

## Summary
The `native_to_bytes` function in the BCS module performs a deep copy of referenced values without charging memory quota or gas, allowing attackers to temporarily allocate up to 2x the intended memory limit per transaction, potentially causing validator node slowdowns or out-of-memory conditions through concurrent exploitation. [1](#0-0) 

## Finding Description

The Move VM enforces a memory quota (default 10,000,000 abstract value units) to prevent excessive memory consumption during transaction execution. When values are created or manipulated through normal Move operations like `vector::push_back`, memory usage is tracked via `use_heap_memory` calls in the `MemoryTrackedGasMeterImpl`: [2](#0-1) 

However, the `bcs::to_bytes` native function bypasses this tracking mechanism. At line 93, it directly calls `read_ref()` which performs a deep copy of the entire value structure: [3](#0-2) 

This deep copy operation allocates new memory for the entire value tree through recursive `copy_value` calls: [4](#0-3) 

The `copy_value` implementation only checks nesting depth (limited to 128 levels), but performs NO memory quota validation: [5](#0-4) 

Gas is only charged AFTER both the deep copy and serialization complete, based solely on the serialized output size: [6](#0-5) 

**Attack Scenario:**

1. Attacker creates a large value structure (e.g., `vector<vector<u8>>`) that consumes 6,000,000 abstract memory units through normal operations (properly tracked and within the 10,000,000 unit quota)

2. Attacker calls `bcs::to_bytes(&large_value)` 

3. The deep copy at line 93 allocates another 6,000,000 units WITHOUT calling `use_heap_memory`, bypassing memory quota checks

4. Total memory usage spikes to 12,000,000 units (120% of quota), exceeding the intended limit by 2,000,000 units

5. With multiple concurrent transactions exploiting this, aggregate memory consumption could exceed physical memory limits

The memory quota check would normally enforce limits: [7](#0-6) 

But since `use_heap_memory` is never called during the deep copy, the quota enforcement is completely bypassed.

## Impact Explanation

This vulnerability breaks the **"Move VM Safety: Bytecode execution must respect gas limits and memory constraints"** invariant.

**Severity: HIGH** per Aptos Bug Bounty criteria ("Validator node slowdowns" and "Significant protocol violations")

1. **Memory Quota Bypass**: The fundamental memory protection mechanism is circumvented, allowing temporary allocation of up to 2x the intended memory limit per transaction

2. **Validator Node Resource Exhaustion**: Multiple transactions exploiting this concurrently can cause cumulative memory spikes, leading to:
   - Validator node slowdowns
   - Potential out-of-memory crashes
   - Degraded block processing performance

3. **Amplification Attack**: Attackers pay gas/memory costs for creating a structure of size X, but can allocate 2X memory during `bcs::to_bytes` execution without additional charges

4. **Consensus Impact**: All validators processing the same block will experience identical memory spikes, affecting network-wide stability

The memory quota is explicitly configured to prevent resource exhaustion: [8](#0-7) 

## Likelihood Explanation

**Likelihood: HIGH**

1. **Ease of Exploitation**: Any transaction can call `bcs::to_bytes` on large values; no special permissions required

2. **Deterministic Behavior**: The vulnerability is consistent and reproducible across all validators

3. **Economic Feasibility**: Creating large structures costs gas, but the 2x memory amplification provides asymmetric advantage to attackers

4. **Known Efficiency Issue**: A TODO comment (issue #14175) acknowledges the deep copy inefficiency, though the security implications may not have been fully analyzed: [9](#0-8) 

5. **No Rate Limiting**: Multiple transactions can exploit this simultaneously, compounding the effect

## Recommendation

Add memory quota tracking to the deep copy operation in `native_to_bytes`:

```rust
fn native_to_bytes(
    context: &mut SafeNativeContext,
    ty_args: &[Type],
    mut args: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    // ... existing type layout logic ...
    
    // Calculate the heap size of the value BEFORE deep copy
    let heap_size = context.abs_val_gas_params()
        .abstract_heap_size(&ref_to_val, context.feature_version())?;
    
    // Charge memory quota BEFORE performing deep copy
    context.use_heap_memory(heap_size.into())?;
    
    // Now perform the deep copy
    let val = ref_to_val.read_ref()?;
    
    // ... rest of serialization logic ...
    
    // Release the memory after serialization completes
    // (the serialized bytes are tracked separately)
    context.release_heap_memory(heap_size.into())?;
    
    // ... return serialized value ...
}
```

Alternatively, implement zero-copy serialization to avoid the deep copy entirely, as suggested by issue #14175.

## Proof of Concept

```move
module attacker::memory_exploit {
    use std::bcs;
    use std::vector;

    // Create a large nested vector structure
    fun create_large_value(): vector<vector<u8>> {
        let outer = vector::empty<vector<u8>>();
        let i = 0;
        
        // Create 100 inner vectors
        while (i < 100) {
            let inner = vector::empty<u8>();
            let j = 0;
            
            // Each inner vector has 10,000 elements
            // This will consume significant memory quota during creation
            while (j < 10000) {
                vector::push_back(&mut inner, (j as u8));
                j = j + 1;
            };
            
            vector::push_back(&mut outer, inner);
            i = i + 1;
        };
        
        outer
    }

    public entry fun exploit_memory_bypass() {
        // Step 1: Create large structure (memory tracked, ~500k+ abstract units)
        let large_val = create_large_value();
        
        // Step 2: Call bcs::to_bytes - this performs untracked deep copy
        // doubling memory usage temporarily without quota enforcement
        let _serialized = bcs::to_bytes(&large_val);
        
        // Memory spike occurred here without proper quota tracking
        // Multiple concurrent transactions amplify the effect
    }
}
```

**Expected behavior**: The `bcs::to_bytes` call should track the additional memory allocated during deep copy and enforce the memory quota.

**Actual behavior**: The deep copy allocates memory without calling `use_heap_memory`, bypassing quota enforcement and allowing temporary memory usage to exceed intended limits by up to 2x per transaction.

**Notes**

The vulnerability exists because native functions have a different execution path than regular Move bytecode. When Move bytecode executes `ReadRef` or `CopyLoc` instructions, memory is properly tracked: [10](#0-9) 

But the `Reference::read_ref()` method called by native code uses a hardcoded depth limit without memory tracking: [11](#0-10) 

The depth check only prevents stack overflow, not memory quota violations: [12](#0-11) 

This architectural inconsistency between bytecode operations and native function implementations creates the security vulnerability.

### Citations

**File:** aptos-move/framework/move-stdlib/src/natives/bcs.rs (L56-114)
```rust
fn native_to_bytes(
    context: &mut SafeNativeContext,
    ty_args: &[Type],
    mut args: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    debug_assert!(ty_args.len() == 1);
    debug_assert!(args.len() == 1);

    let ref_to_val = safely_pop_arg!(args, Reference);
    let arg_type = &ty_args[0];

    let layout = if context.get_feature_flags().is_lazy_loading_enabled() {
        // With lazy loading, propagate the error directly. This is because errors here are likely
        // from metering, so we should not remap them in any way. Note that makes it possible to
        // fail on constructing a very deep / large layout and not be charged, but this is already
        // the case for regular execution, so we keep it simple. Also, charging more gas after
        // out-of-gas failure in layout construction does not make any sense.
        //
        // Example:
        //   - Constructing layout runs into dependency limit.
        //   - We cannot do `context.charge(BCS_TO_BYTES_FAILURE)?;` because then we can end up in
        //     the state where out of gas and dependency limit are hit at the same time.
        context.type_to_type_layout(arg_type)?
    } else {
        match context.type_to_type_layout(arg_type) {
            Ok(layout) => layout,
            Err(_) => {
                context.charge(BCS_TO_BYTES_FAILURE)?;
                return Err(SafeNativeError::Abort {
                    abort_code: NFE_BCS_SERIALIZATION_FAILURE,
                });
            },
        }
    };

    // TODO(#14175): Reading the reference performs a deep copy, and we can
    //               implement it in a more efficient way.
    let val = ref_to_val.read_ref()?;

    let function_value_extension = context.function_value_extension();
    let max_value_nest_depth = context.max_value_nest_depth();
    let serialized_value = match ValueSerDeContext::new(max_value_nest_depth)
        .with_legacy_signer()
        .with_func_args_deserialization(&function_value_extension)
        .serialize(&val, &layout)?
    {
        Some(serialized_value) => serialized_value,
        None => {
            context.charge(BCS_TO_BYTES_FAILURE)?;
            return Err(SafeNativeError::Abort {
                abort_code: NFE_BCS_SERIALIZATION_FAILURE,
            });
        },
    };
    context
        .charge(BCS_TO_BYTES_PER_BYTE_SERIALIZED * NumBytes::new(serialized_value.len() as u64))?;

    Ok(smallvec![Value::vector_u8(serialized_value)])
}
```

**File:** aptos-move/aptos-memory-usage-tracker/src/lib.rs (L48-59)
```rust
    fn use_heap_memory(&mut self, amount: AbstractValueSize) -> PartialVMResult<()> {
        if self.feature_version >= 3 {
            match self.remaining_memory_quota.checked_sub(amount) {
                Some(remaining_quota) => {
                    self.remaining_memory_quota = remaining_quota;
                    Ok(())
                },
                None => {
                    self.remaining_memory_quota = 0.into();
                    Err(PartialVMError::new(StatusCode::MEMORY_LIMIT_EXCEEDED))
                },
            }
```

**File:** aptos-move/aptos-memory-usage-tracker/src/lib.rs (L660-668)
```rust
    fn charge_read_ref_cached(
        &mut self,
        stack_size: AbstractValueSize,
        heap_size: AbstractValueSize,
    ) -> PartialVMResult<()> {
        self.use_heap_memory(heap_size)?;

        self.base.charge_read_ref_cached(stack_size, heap_size)
    }
```

**File:** aptos-move/aptos-memory-usage-tracker/src/lib.rs (L671-679)
```rust
    fn charge_copy_loc_cached(
        &mut self,
        stack_size: AbstractValueSize,
        heap_size: AbstractValueSize,
    ) -> PartialVMResult<()> {
        self.use_heap_memory(heap_size)?;

        self.base.charge_copy_loc_cached(stack_size, heap_size)
    }
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L581-625)
```rust
    fn copy_value(&self, depth: u64, max_depth: Option<u64>) -> PartialVMResult<Self> {
        use Value::*;

        check_depth(depth, max_depth)?;
        Ok(match self {
            Invalid => Invalid,

            U8(x) => U8(*x),
            U16(x) => U16(*x),
            U32(x) => U32(*x),
            U64(x) => U64(*x),
            U128(x) => U128(*x),
            U256(x) => U256(x.clone()),
            I8(x) => I8(*x),
            I16(x) => I16(*x),
            I32(x) => I32(*x),
            I64(x) => I64(*x),
            I128(x) => I128(*x),
            I256(x) => I256(x.clone()),
            Bool(x) => Bool(*x),
            Address(x) => Address(x.clone()),

            // Note: refs copy only clones Rc, so no need to increment depth.
            ContainerRef(r) => ContainerRef(r.copy_by_ref()),
            IndexedRef(r) => IndexedRef(r.copy_by_ref()),

            // When cloning a container, we need to make sure we make a deep copy of the data
            // instead of a shallow copy of the Rc. Note that we do not increment the depth here
            // because we have done it when entering this value. Inside the container, depth will
            // be further incremented for nested values.
            Container(c) => Container(c.copy_value(depth, max_depth)?),

            // Native values can be copied because this is how read_ref operates,
            // and copying is an internal API.
            DelayedFieldID { id } => DelayedFieldID { id: *id },

            ClosureValue(Closure(fun, captured)) => {
                let captured = captured
                    .iter()
                    .map(|v| v.copy_value(depth + 1, max_depth))
                    .collect::<PartialVMResult<_>>()?;
                ClosureValue(Closure(fun.clone_dyn()?, Box::new(captured)))
            },
        })
    }
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L629-669)
```rust
    fn copy_value(&self, depth: u64, max_depth: Option<u64>) -> PartialVMResult<Self> {
        fn copy_rc_ref_vec_val(
            r: &Rc<RefCell<Vec<Value>>>,
            depth: u64,
            max_depth: Option<u64>,
        ) -> PartialVMResult<Rc<RefCell<Vec<Value>>>> {
            let vals = r.borrow();
            let mut copied_vals = Vec::with_capacity(vals.len());
            for val in vals.iter() {
                copied_vals.push(val.copy_value(depth + 1, max_depth)?);
            }
            Ok(Rc::new(RefCell::new(copied_vals)))
        }

        Ok(match self {
            Self::Vec(r) => Self::Vec(copy_rc_ref_vec_val(r, depth, max_depth)?),
            Self::Struct(r) => Self::Struct(copy_rc_ref_vec_val(r, depth, max_depth)?),

            Self::VecU8(r) => Self::VecU8(Rc::new(RefCell::new(r.borrow().clone()))),
            Self::VecU16(r) => Self::VecU16(Rc::new(RefCell::new(r.borrow().clone()))),
            Self::VecU32(r) => Self::VecU32(Rc::new(RefCell::new(r.borrow().clone()))),
            Self::VecU64(r) => Self::VecU64(Rc::new(RefCell::new(r.borrow().clone()))),
            Self::VecU128(r) => Self::VecU128(Rc::new(RefCell::new(r.borrow().clone()))),
            Self::VecU256(r) => Self::VecU256(Rc::new(RefCell::new(r.borrow().clone()))),
            Self::VecI8(r) => Self::VecI8(Rc::new(RefCell::new(r.borrow().clone()))),
            Self::VecI16(r) => Self::VecI16(Rc::new(RefCell::new(r.borrow().clone()))),
            Self::VecI32(r) => Self::VecI32(Rc::new(RefCell::new(r.borrow().clone()))),
            Self::VecI64(r) => Self::VecI64(Rc::new(RefCell::new(r.borrow().clone()))),
            Self::VecI128(r) => Self::VecI128(Rc::new(RefCell::new(r.borrow().clone()))),
            Self::VecI256(r) => Self::VecI256(Rc::new(RefCell::new(r.borrow().clone()))),
            Self::VecBool(r) => Self::VecBool(Rc::new(RefCell::new(r.borrow().clone()))),
            Self::VecAddress(r) => Self::VecAddress(Rc::new(RefCell::new(r.borrow().clone()))),

            Self::Locals(_) => {
                return Err(
                    PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                        .with_message("cannot copy a Locals container".to_string()),
                )
            },
        })
    }
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L1614-1616)
```rust
    pub fn read_ref(self) -> PartialVMResult<Value> {
        self.0.read_ref(1, Some(DEFAULT_MAX_VM_VALUE_NESTED_DEPTH))
    }
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L6166-6171)
```rust
fn check_depth(depth: u64, max_depth: Option<u64>) -> PartialVMResult<()> {
    if max_depth.is_some_and(|max_depth| depth > max_depth) {
        return Err(PartialVMError::new(StatusCode::VM_MAX_VALUE_DEPTH_REACHED));
    }
    Ok(())
}
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L142-142)
```rust
        [memory_quota: AbstractValueSize, { 1.. => "memory_quota" }, 10_000_000],
```
