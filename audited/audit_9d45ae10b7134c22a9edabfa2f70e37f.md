# Audit Report

## Title
Memory Quota Bypass via Incomplete Struct Field Accounting in Vector Operations

## Summary
The `abstract_packed_size` function fails to recursively calculate the size of struct fields when structs are packed into vectors, charging only the struct container overhead (40 abstract units) instead of the full size including all nested fields. This allows attackers to bypass memory quota enforcement by up to 51x, enabling resource exhaustion attacks against validator nodes.

## Finding Description

The vulnerability exists in the `abstract_packed_size` function's `visit_struct` implementation, which returns `false`, preventing recursive traversal of struct fields: [1](#0-0) 

In contrast, the `abstract_value_size` function correctly returns `true` to enable recursive field traversal: [2](#0-1) 

The ValueView implementation confirms that returning `false` from `visit_struct` skips traversal of struct fields: [3](#0-2) 

This `abstract_packed_size` function is used by the memory tracker to enforce memory quotas during vector operations: [4](#0-3) 

When the VM executes a `VecPack` instruction, it calls `charge_vec_pack` with the elements being packed: [5](#0-4) 

**Attack Path:**
1. Attacker deploys a Move module with structs containing many fields (up to 255 fields per Move binary format limit)
2. Creates instances of these large structs
3. Packs them into vectors using `vector::push_back` or similar operations
4. Only 40 abstract units charged per struct (container overhead), not the actual packed size of all fields
5. With 255 u64 fields: actual packed size = 255 × 8 = 2,040 units, but only 40 units charged
6. Undercharge ratio: 2,040 / 40 = **51x bypass** of memory quota

The struct container overhead is defined as 40 abstract units: [6](#0-5) 

The production configuration confirms no additional field limits beyond the binary format's 255-field maximum: [7](#0-6) 

The binary format limit for struct fields is 255: [8](#0-7) 

The default memory quota is 10,000,000 abstract units: [9](#0-8) 

This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits."

## Impact Explanation

This qualifies as **High Severity** per Aptos bug bounty criteria:

1. **Validator Node Slowdowns**: Attackers can allocate 51x more memory than charged, causing validators to consume excessive RAM and slow down transaction processing.

2. **Resource Exhaustion**: With default memory quota of 10,000,000 units, attackers can allocate significantly more memory than intended. Each struct with 255 u64 fields consumes 2,040 bytes but is only charged 40 units, allowing ~51x more memory allocation than the quota permits.

3. **DoS Potential**: Multiple concurrent transactions can exhaust validator node memory, potentially causing crashes or severe performance degradation.

4. **Significant Protocol Violation**: The memory quota enforcement mechanism, a critical resource limit protection, is fundamentally bypassed.

This does NOT qualify as Critical because:
- No consensus split (all nodes have the same bug)
- No fund theft or minting capability
- No permanent network damage
- Nodes can recover by restarting

## Likelihood Explanation

**High Likelihood** - This vulnerability is:

1. **Trivial to Exploit**: Any user can deploy a Move module with large structs and call functions that pack them into vectors. No special permissions required.

2. **Difficult to Detect**: The undercharging is silent and deterministic. Validators would only notice via abnormal memory consumption patterns.

3. **Immediately Exploitable**: The vulnerable code is active in production with no mitigating controls.

4. **Economically Incentivized**: Attackers can cause disproportionate resource consumption for minimal gas costs, making DoS attacks economically viable.

## Recommendation

The `abstract_packed_size` function's `visit_struct` implementation should return `true` instead of `false` to enable recursive traversal of struct fields, similar to how `abstract_value_size` works. This would ensure that the packed size calculation accounts for all nested fields.

Alternatively, implement a specialized visitor that recursively sums the packed sizes of all struct fields using the `per_*_packed` gas parameters.

## Proof of Concept

A Move module demonstrating the exploit would:
1. Define a struct with 255 u64 fields
2. Create an instance of this struct
3. Pack it into a vector using `vector::push_back`
4. Observe that only 40 units are charged instead of the expected ~2,040 units

The actual memory consumption on the validator would be 51x higher than what the memory quota system accounts for, enabling resource exhaustion attacks.

## Notes

This vulnerability affects the core Move VM memory tracking system. The `abstract_packed_size` function is consistently used across all vector operations (`charge_vec_pack`, `charge_vec_unpack`, `charge_vec_push_back`, `charge_vec_pop_back`), meaning the undercharging is systematic and affects all vector manipulation of large structs. The fix should ensure that packed size calculations properly account for all nested struct fields to maintain accurate memory quota enforcement.

### Citations

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/misc.rs (L47-47)
```rust
        [struct_: AbstractValueSize, "struct", 40],
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/misc.rs (L314-318)
```rust
    fn visit_struct(&mut self, depth: u64, _len: usize) -> PartialVMResult<bool> {
        self.check_depth(depth)?;
        self.size += self.params.struct_;
        Ok(true)
    }
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/misc.rs (L850-854)
```rust
            fn visit_struct(&mut self, depth: u64, _len: usize) -> PartialVMResult<bool> {
                self.check_depth(depth)?;
                self.res = Some(self.params.struct_);
                Ok(false)
            }
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L5494-5501)
```rust
            Struct(r) => {
                let r = r.borrow();
                if visitor.visit_struct(depth, r.len())? {
                    for val in r.iter() {
                        val.visit_impl(visitor, depth + 1)?;
                    }
                }
                Ok(())
```

**File:** aptos-move/aptos-memory-usage-tracker/src/lib.rs (L569-580)
```rust
        self.use_heap_memory(
            args.clone()
                .try_fold(AbstractValueSize::zero(), |acc, val| {
                    Ok::<_, PartialVMError>(
                        acc + self
                            .vm_gas_params()
                            .misc
                            .abs_val
                            .abstract_packed_size(val)?,
                    )
                })?,
        )?;
```

**File:** third_party/move/move-vm/runtime/src/interpreter.rs (L2960-2961)
```rust
                        gas_meter
                            .charge_vec_pack(interpreter.operand_stack.last_n(*num as usize)?)?;
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L170-170)
```rust
        max_fields_in_struct: None,
```

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L78-78)
```rust
pub const FIELD_COUNT_MAX: u64 = 255;
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L142-142)
```rust
        [memory_quota: AbstractValueSize, { 1.. => "memory_quota" }, 10_000_000],
```
