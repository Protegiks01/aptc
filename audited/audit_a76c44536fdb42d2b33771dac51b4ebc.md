# Audit Report

## Title
BCS Serialization Memory Allocation Before Gas/Memory Quota Enforcement Enables Node Memory Exhaustion DoS

## Summary
The `bcs::to_bytes()` native function performs BCS serialization and allocates output buffers BEFORE enforcing gas charges and memory quota limits. Unlike table natives which explicitly call `use_heap_memory()` after serialization operations, the BCS native relies solely on implicit memory tracking during return value processing. This creates an exploitable timing window where concurrent transactions can exhaust validator node memory before quota enforcement occurs.

## Finding Description

The `bcs::to_bytes()` native function in Aptos Move stdlib performs Binary Canonical Serialization (BCS) of Move values. The implementation exhibits a critical ordering issue: [1](#0-0) 

The function serializes the value (allocating a `Vec<u8>`) at lines 97-109, then charges gas at line 111. Critically, the native function never calls `context.use_heap_memory()` to explicitly track the serialized output allocation.

In contrast, table natives correctly track serialization memory: [2](#0-1) 

The memory quota tracking for BCS output only occurs implicitly when the VM calls `charge_native_function` with the return value: [3](#0-2) 

This happens AFTER the native function completes and returns to the interpreter: [4](#0-3) 

**Attack Path:**

1. Attacker creates multiple transactions that each build large Move values (e.g., `vector<u64>` with millions of elements) up to the memory quota limit of 10 million abstract value size units
2. Each transaction calls `bcs::to_bytes()` on these values  
3. During parallel execution in the block executor, all transactions simultaneously:
   - Execute the serialization (line 97-109), allocating large `Vec<u8>` buffers (potentially 10+ MB each)
   - The allocations occur on the shared heap
4. These allocations happen BEFORE:
   - Gas charging completes (line 111)
   - Memory quota tracking via `use_heap_memory()` occurs (in `charge_native_function`)
5. With sufficient concurrent transactions, the accumulated allocations exhaust available node memory
6. This causes validator node OOM conditions, crashes, or severe performance degradation

The gas cost for serialization is extremely low: [5](#0-4) 

At 36 internal gas units per byte, serializing 10MB costs only 360 gas units (out of a 2 million gas limit), making this attack economically viable.

## Impact Explanation

**High Severity** - This vulnerability enables validator node slowdowns and potential crashes through memory exhaustion, meeting the High severity criteria of "Validator node slowdowns" and "API crashes" per the Aptos bug bounty program.

**Specific Impacts:**

1. **Validator Node Availability**: Concurrent exploitation can cause validators to experience OOM conditions, leading to crashes or severe performance degradation
2. **Network Liveness**: If sufficient validators are affected simultaneously, the network could experience consensus delays or temporary loss of liveness
3. **Resource Invariant Violation**: Breaks invariant #9 ("All operations must respect gas, storage, and computational limits") - memory limits are not respected during the serialization window

The attack is amplified by Aptos's parallel block executor which enables true concurrent transaction execution across multiple threads sharing the same heap space.

## Likelihood Explanation

**High Likelihood** - The attack is straightforward to execute:

1. **No Special Privileges Required**: Any transaction sender can submit transactions calling `bcs::to_bytes()`
2. **Low Cost**: At 360 gas units per 10MB serialization, an attacker can spam many such transactions economically
3. **Parallel Execution Amplification**: The block executor's parallel execution design makes concurrent transactions the default case, not an edge case
4. **No Rate Limiting**: There are no specific protections against concurrent BCS serialization operations

The only limiting factor is that validators need adequate transaction throughput to execute many transactions concurrently, which is precisely what Aptos's high-performance design enables.

## Recommendation

Add explicit memory quota tracking before serialization completes, matching the pattern used in table natives:

```rust
fn native_to_bytes(
    context: &mut SafeNativeContext,
    ty_args: &[Type],
    mut args: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    // ... existing code ...
    
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
    
    // Add explicit memory tracking BEFORE gas charging
    context.use_heap_memory(serialized_value.len() as u64)?;
    
    context.charge(BCS_TO_BYTES_PER_BYTE_SERIALIZED * NumBytes::new(serialized_value.len() as u64))?;

    Ok(smallvec![Value::vector_u8(serialized_value)])
}
```

Additionally, consider increasing the `bcs_to_bytes_per_byte_serialized` parameter from 36 to a higher value (e.g., 200+) to make serialization more expensive and provide economic disincentive.

## Proof of Concept

```move
// Place in aptos-move/framework/move-stdlib/tests/
module 0x1::bcs_dos_test {
    use std::bcs;
    use std::vector;

    // Create a large vector and serialize it
    public entry fun exploit_serialization_dos() {
        // Create vector with ~1 million u64 elements
        // Each u64 is 8 bytes abstract size, so ~8M total abstract size (within 10M quota)
        let large_vec = vector::empty<u64>();
        let i = 0;
        while (i < 1000000) {
            vector::push_back(&mut large_vec, i);
            i = i + 1;
        };
        
        // Serialize the vector - allocates ~8MB Vec<u8> BEFORE memory quota check
        // Cost: only ~288 gas units (8,000,000 bytes * 36 / 1,000,000)
        let _serialized = bcs::to_bytes(&large_vec);
        
        // In parallel execution with 100+ concurrent transactions,
        // this causes ~800MB+ of unchecked allocations
    }
}
```

To demonstrate the attack:
1. Deploy this module
2. Submit 100+ concurrent transactions calling `exploit_serialization_dos()`
3. Monitor validator node memory usage - observe spikes before quota enforcement
4. With sufficient concurrency on memory-constrained nodes, observe OOM conditions or performance degradation

**Notes**

The vulnerability stems from an architectural inconsistency between the BCS natives and other natives (like table operations) that perform serialization. The BCS implementation lacks the explicit `use_heap_memory()` call that would enforce memory quota tracking before allocations accumulate. This is exacerbated by the extremely low gas cost (36 per byte) for serialization operations, making the attack economically viable at scale.

### Citations

**File:** aptos-move/framework/move-stdlib/src/natives/bcs.rs (L97-111)
```rust
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
```

**File:** aptos-move/framework/table-natives/src/lib.rs (L437-441)
```rust
    // TODO(Gas): Figure out a way to charge this earlier.
    context.charge(key_cost)?;
    if let Some(amount) = mem_usage {
        context.use_heap_memory(amount)?;
    }
```

**File:** aptos-move/aptos-memory-usage-tracker/src/lib.rs (L358-375)
```rust
    fn charge_native_function(
        &mut self,
        amount: InternalGas,
        ret_vals: Option<impl ExactSizeIterator<Item = impl ValueView> + Clone>,
    ) -> PartialVMResult<()> {
        if let Some(mut ret_vals) = ret_vals.clone() {
            self.use_heap_memory(ret_vals.try_fold(AbstractValueSize::zero(), |acc, val| {
                let heap_size = self
                    .vm_gas_params()
                    .misc
                    .abs_val
                    .abstract_heap_size(val, self.feature_version())?;
                Ok::<_, PartialVMError>(acc + heap_size)
            })?)?;
        }

        self.base.charge_native_function(amount, ret_vals)
    }
```

**File:** third_party/move/move-vm/runtime/src/interpreter.rs (L1106-1115)
```rust
        let result = native_function(&mut native_context, ty_args, args)?;

        // Note(Gas): The order by which gas is charged / error gets returned MUST NOT be modified
        //            here or otherwise it becomes an incompatible change!!!
        match result {
            NativeResult::Success {
                cost,
                ret_vals: return_values,
            } => {
                gas_meter.charge_native_function(cost, Some(return_values.iter()))?;
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/move_stdlib.rs (L20-20)
```rust
        [bcs_to_bytes_per_byte_serialized: InternalGasPerByte, "bcs.to_bytes.per_byte_serialized", 36],
```
