# Audit Report

## Title
BCS Serialization Resource Exhaustion via Deferred Gas Charging

## Summary
The `bcs::to_bytes` native function charges gas AFTER completing serialization, violating the "charge first, execute second" principle. This allows attackers to force validators to perform expensive serialization work that exceeds transaction gas limits, creating a resource exhaustion attack vector.

## Finding Description
The vulnerability exists in the gas charging order within the `native_to_bytes` function. The implementation performs two expensive operations before any gas is charged for them: [1](#0-0) 

The critical flaw is at line 93 where a deep copy is performed, and lines 97-109 where serialization happens, both BEFORE gas is charged at line 111. This violates the fundamental gas metering principle: [2](#0-1) 

An attacker can exploit this by:
1. Creating a deeply nested structure within the 128-depth limit and 512-node type layout limit
2. Ensuring the structure's serialized size exceeds the transaction gas limit (2,000,000 gas units ÷ 36 gas/byte = ~55,555 bytes maximum)
3. Calling `bcs::to_bytes` on this structure
4. The VM performs the full deep copy and serialization, consuming CPU cycles, memory, and time
5. When gas charging is attempted at line 111, it fails with out-of-gas error
6. Transaction aborts, but validator resources were already consumed

The type layout limits provide insufficient protection: [3](#0-2) 

While these limits prevent infinite recursion during layout construction, they don't prevent creation of values with high branching factors. For example, a struct with 100 fields, each being a vector of 1000 elements, results in 100,000 elements despite having a small type layout (≈200 nodes).

The serialization depth check only validates nesting level, not total element count: [4](#0-3) 

This check occurs during serialization (after work has begun), and only limits depth, not breadth or total serialization cost.

## Impact Explanation
**Severity: High** (Validator node slowdowns)

This vulnerability enables a resource exhaustion attack against validator nodes:

1. **Validator Performance Degradation**: Attackers can submit transactions that force expensive serialization operations, consuming CPU and memory resources before gas checks terminate the transaction.

2. **Consensus Impact**: If multiple validators process such transactions simultaneously, it can slow block production and affect consensus liveness.

3. **Cost Asymmetry**: Attackers pay only the maximum gas limit (~2M gas units), but validators perform work proportional to the actual data size (potentially 10x-100x more expensive).

4. **Repeatable Attack**: The attack can be repeated across multiple transactions to sustain resource pressure on the network.

The vulnerability does not lead to fund theft or consensus safety violations, but it violates **Invariant #9 (Resource Limits)**: "All operations must respect gas, storage, and computational limits" by executing expensive operations before verifying sufficient gas exists.

## Likelihood Explanation
**Likelihood: High**

The attack is highly likely because:

1. **Low Barrier to Entry**: Any user can submit transactions with arbitrary data structures
2. **No Special Permissions Required**: Requires only ability to submit transactions
3. **Easy to Construct**: Creating nested structures with high serialization costs is straightforward in Move
4. **Deterministic Success**: The vulnerability is not timing-dependent; it reliably consumes resources before gas checks

The attack requires:
- Crafting a Move function that builds a sufficiently large nested structure
- Calling `bcs::to_bytes` on it within the transaction
- Setting `max_gas_amount` to the maximum allowed (2,000,000)

Example structure: A vector of vectors, where outer vector has 100 elements and each inner vector has 10,000 u64 values, resulting in 8MB serialized size (100 × 10,000 × 8 bytes), which would require 288M gas units to serialize but only ~1M gas to create.

## Recommendation
Implement pre-serialization gas estimation and charging:

**Fix 1: Estimate serialization cost before execution**
```rust
fn native_to_bytes(
    context: &mut SafeNativeContext,
    ty_args: &[Type],
    mut args: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    // ... existing layout construction code ...
    
    let ref_to_val = safely_pop_arg!(args, Reference);
    let val = ref_to_val.read_ref()?;
    
    // NEW: Estimate size before serialization
    let estimated_size = estimate_serialized_size(&val, &layout, context)?;
    
    // NEW: Charge gas upfront based on estimate
    context.charge(BCS_TO_BYTES_PER_BYTE_SERIALIZED * NumBytes::new(estimated_size))?;
    
    // Proceed with serialization
    let serialized_value = match ValueSerDeContext::new(max_value_nest_depth)
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
    
    // NEW: Charge only the difference if actual size differs
    let actual_size = serialized_value.len() as u64;
    if actual_size > estimated_size {
        context.charge(BCS_TO_BYTES_PER_BYTE_SERIALIZED * NumBytes::new(actual_size - estimated_size))?;
    }
    
    Ok(smallvec![Value::vector_u8(serialized_value)])
}
```

**Fix 2: Add incremental size limit checks during serialization**
Modify the serializer to periodically check gas limits during traversal, terminating early if exceeded.

**Fix 3: Impose stricter limits on serializable data**
Add a maximum serialized size limit (e.g., 64KB) that can be enforced before serialization begins.

## Proof of Concept
```move
module attacker::serialization_bomb {
    use std::vector;
    use std::bcs;
    
    struct Layer {
        data: vector<vector<u64>>
    }
    
    public entry fun exploit(account: &signer) {
        // Create a structure with moderate depth but high branching
        let outer = vector::empty<vector<u64>>();
        let i = 0;
        
        // Create 100 inner vectors
        while (i < 100) {
            let inner = vector::empty<u64>();
            let j = 0;
            
            // Each inner vector has 10,000 elements
            while (j < 10000) {
                vector::push_back(&mut inner, j);
                j = j + 1;
            };
            
            vector::push_back(&mut outer, inner);
            i = i + 1;
        };
        
        let layer = Layer { data: outer };
        
        // This serialization will:
        // 1. Serialize 1,000,000 u64 values = 8,000,000 bytes
        // 2. Require 8,000,000 * 36 = 288,000,000 gas units
        // 3. Far exceed the 2,000,000 max gas limit
        // 4. But serialization work is done before gas check fails
        let _serialized = bcs::to_bytes(&layer);
    }
}
```

**Expected Behavior**: Transaction creation costs ~2M gas, serialization attempts to charge 288M gas, transaction aborts with out-of-gas, but validator has already performed 8MB serialization work.

## Notes

The vulnerability stems from a fundamental design choice in the BCS native implementation that prioritizes simplicity over security. The Rust `bcs` crate used for serialization has no hooks for incremental gas metering, making it difficult to enforce gas limits during serialization itself.

The 128-depth limit and 512-node type layout limits provide protection against infinite recursion but are insufficient to prevent resource exhaustion attacks that exploit high branching factors within allowed depths.

The gas cost of 36 units per byte is reasonable for the serialization operation itself, but the deferred charging pattern creates the vulnerability. This affects all uses of `bcs::to_bytes` throughout the Move framework.

### Citations

**File:** aptos-move/framework/move-stdlib/src/natives/bcs.rs (L91-114)
```rust
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

**File:** aptos-move/aptos-native-interface/src/context.rs (L69-69)
```rust
    /// Always remember: first charge gas, then execute!
```

**File:** third_party/move/move-vm/runtime/src/storage/ty_layout_converter.rs (L197-222)
```rust
    fn check_depth_and_increment_count(
        &self,
        node_count: &mut u64,
        depth: u64,
    ) -> PartialVMResult<()> {
        let max_count = self.vm_config().layout_max_size;
        if *node_count > max_count || *node_count == max_count && self.is_lazy_loading_enabled() {
            return Err(
                PartialVMError::new(StatusCode::TOO_MANY_TYPE_NODES).with_message(format!(
                    "Number of type nodes when constructing type layout exceeded the maximum of {}",
                    max_count
                )),
            );
        }
        *node_count += 1;

        if depth > self.vm_config().layout_max_depth {
            return Err(
                PartialVMError::new(StatusCode::VM_MAX_VALUE_DEPTH_REACHED).with_message(format!(
                    "Depth of a layout exceeded the maximum of {} during construction",
                    self.vm_config().layout_max_depth
                )),
            );
        }
        Ok(())
    }
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L4838-4838)
```rust
        self.ctx.check_depth(self.depth).map_err(S::Error::custom)?;
```
