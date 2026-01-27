# Audit Report

## Title
Memory Accounting Bypass in Aggregator Derived Strings via Vec Capacity Overhead

## Summary
The `get_approximate_memory_size()` function for `DelayedFieldValue::Derived` variants only accounts for the logical length (`v.len()`) of the contained vector, not its allocated capacity. Attackers can exploit Rust's vector growth strategy to create vectors with large capacity but small length, bypassing memory accounting at both the VM and DelayedField levels, potentially causing memory exhaustion on validator nodes.

## Finding Description

The vulnerability exists in the memory accounting mechanism for derived string snapshots in the aggregator_v2 system. The core issue is at: [1](#0-0) 

This function calculates memory size as `sizeof(DelayedFieldValue) + v.len()`, which only accounts for the vector's logical length, not its allocated capacity.

**Attack Path:**

1. **Vector Creation with Excess Capacity**: In Move, when a vector grows through `push_back` operations, Rust's default allocation strategy doubles capacity when full. An attacker creates a `vector<u8>` and pushes elements until reaching a desired capacity (e.g., 513 bytes triggers allocation to ~1024 bytes capacity).

2. **Capacity Retention After Pop**: The attacker then calls `pop_back` repeatedly to reduce the length to a small value (e.g., 1 byte). The vector retains its full capacity (~1024 bytes) while the length becomes 1. [2](#0-1) 

3. **String Creation Without Normalization**: The attacker creates a String from this vector using `string::utf8(bytes)`, which takes ownership without cloning or normalizing capacity: [3](#0-2) 

4. **Native Function Extraction**: When `create_derived_string` is called, the native function extracts the Vec via `string_to_bytes`: [4](#0-3) 

Which calls `value_as::<Vec<u8>>()` → `take_unique_ownership()` that returns the Vec AS-IS with its capacity preserved: [5](#0-4) 

5. **Memory Accounting Bypass**: The Vec is stored in `DelayedFieldValue::Derived(vec)` with only `v.len()` counted:
   - **Accounted**: ~32 bytes (struct) + 1 byte (length) = 33 bytes
   - **Actual Physical Memory**: ~32 bytes + 1024 bytes (capacity) = 1056 bytes
   - **Unaccounted**: ~1023 bytes per derived string

6. **Amplification**: With `MAX_DELAYED_FIELDS_PER_RESOURCE = 10`: [6](#0-5) 

An attacker can create multiple resources per transaction, each with 10 derived strings, accumulating significant unaccounted memory.

**Systemic Issue**: The VM's abstract memory accounting also uses length, not capacity: [7](#0-6) 

This creates a gap between abstract (tracked) and physical (actual) memory at both the VM level and the DelayedField level.

## Impact Explanation

**Severity: High** (up to $50,000 per Aptos Bug Bounty)

This vulnerability enables:

1. **Validator Node Slowdowns**: Unaccounted physical memory consumption can degrade node performance as actual RAM usage exceeds expected limits, causing increased GC pressure and memory paging.

2. **Memory Exhaustion DoS**: Attackers can craft transactions that consume significantly more physical memory than their abstract memory quota allows (memory quota default is 10,000,000 abstract units): [8](#0-7) 

With a 1000:1 capacity-to-length ratio achievable per derived string and 10 derived strings per resource, an attacker could consume MBs of unaccounted physical memory per transaction.

3. **Non-Deterministic Node Behavior**: Nodes with different physical memory constraints may fail at different points, potentially causing inconsistent transaction execution results across the network.

4. **Invariant Violation**: Breaks the **"Resource Limits: All operations must respect gas, storage, and computational limits"** invariant by allowing physical memory consumption to bypass abstract memory accounting.

## Likelihood Explanation

**Likelihood: High**

The attack is highly feasible because:

1. **No Special Privileges Required**: Any user can submit transactions with vector manipulations
2. **Standard Operations**: Uses normal Move stdlib operations (`vector::push_back`, `vector::pop_back`, `string::utf8`, `aggregator_v2::create_derived_string`)
3. **Deterministic Behavior**: Rust's vector allocation strategy is predictable and consistent
4. **No Detection Mechanism**: There are no checks comparing physical capacity to logical length
5. **Economic Viability**: Gas costs are based on abstract memory (length), not physical memory (capacity), making the attack cheap to execute

The TODO comment in the codebase suggests awareness of memory optimization issues but not this specific capacity-based bypass: [9](#0-8) 

## Recommendation

**Immediate Fix**: Modify `get_approximate_memory_size()` to account for vector capacity:

```rust
pub fn get_approximate_memory_size(&self) -> usize {
    std::mem::size_of::<DelayedFieldValue>()
        + match &self {
            DelayedFieldValue::Aggregator(_) | DelayedFieldValue::Snapshot(_) => 0,
            DelayedFieldValue::Derived(v) => v.capacity(), // Use capacity instead of len
        }
}
```

**Additional Mitigations**:

1. **Normalize Vec Capacity**: When extracting vectors from Move values for storage in DelayedFieldValue, call `shrink_to_fit()` to eliminate excess capacity:

```rust
let mut value_bytes = string_to_bytes(safely_pop_arg!(args, Struct))?;
value_bytes.shrink_to_fit(); // Normalize capacity to length
```

2. **VM-Level Capacity Tracking**: Update abstract memory size calculations to include capacity overhead for vectors:

```rust
fn visit_vec_u8(&mut self, depth: u64, vals: &[u8]) -> PartialVMResult<()> {
    self.check_depth(depth)?;
    // Account for both length and potential capacity overhead
    let mut size = self.params.per_u8_packed * NumArgs::new(vals.capacity() as u64);
    if self.feature_version >= 3 {
        size += self.params.vector;
    }
    self.size += size;
    Ok(())
}
```

3. **Add Capacity Limits**: Enforce a maximum capacity-to-length ratio check when creating derived strings to prevent egregious abuse.

## Proof of Concept

```move
module attacker::memory_bypass {
    use std::string;
    use std::vector;
    use aptos_framework::aggregator_v2;

    /// Demonstrates memory accounting bypass via vector capacity overhead
    public entry fun exploit_capacity_bypass() {
        // Step 1: Create vector and grow capacity via push operations
        let vec = vector::empty<u8>();
        
        // Push 513 bytes to trigger allocation to ~1024 capacity
        let i = 0;
        while (i < 513) {
            vector::push_back(&mut vec, 65); // Push 'A'
            i = i + 1;
        };
        // Vector now has capacity ~1024, length 513
        
        // Step 2: Pop most elements to create capacity >> length
        i = 0;
        while (i < 512) {
            vector::pop_back(&mut vec);
            i = i + 1;
        };
        // Vector now has capacity ~1024, length 1
        // Physical memory: ~1024 bytes
        // Accounted memory: ~1 byte
        
        // Step 3: Create string (preserves capacity)
        let malicious_string = string::utf8(vec);
        
        // Step 4: Create derived string (only accounts for length)
        let _derived = aggregator_v2::create_derived_string(malicious_string);
        // Memory accounting records ~33 bytes
        // Actual physical memory: ~1056 bytes
        // Unaccounted: ~1023 bytes
        
        // Step 5: Amplification - repeat for max delayed fields per resource
        // With 10 derived strings: ~10KB unaccounted per resource
        // With multiple resources: accumulate MBs of unaccounted memory
    }
}
```

**Expected Behavior**: The transaction should consume ~10KB of physical memory per resource while only accounting for ~330 bytes in abstract memory, demonstrating the bypass.

**Notes**

This vulnerability represents a fundamental gap between Rust's memory management (capacity-based) and Aptos's abstract memory accounting (length-based). The issue affects both the VM-level memory tracking and the DelayedField-specific memory accounting. While the per-resource limit of 10 delayed fields provides some mitigation, the ability to create multiple resources per transaction and the large capacity-to-length ratio achievable make this a viable attack vector for memory exhaustion. The fix requires accounting for capacity rather than length at all memory tracking points, or normalizing vector capacity when values are stored.

### Citations

**File:** aptos-move/aptos-aggregator/src/types.rs (L97-98)
```rust
    // TODO[agg_v2](optimize) probably change to Derived(Arc<Vec<u8>>) to make copying predictably costly
    Derived(Vec<u8>),
```

**File:** aptos-move/aptos-aggregator/src/types.rs (L176-184)
```rust
    pub fn get_approximate_memory_size(&self) -> usize {
        // 32 + len
        std::mem::size_of::<DelayedFieldValue>()
            + match &self {
                DelayedFieldValue::Aggregator(_) | DelayedFieldValue::Snapshot(_) => 0,
                // additional allocated memory for the data:
                DelayedFieldValue::Derived(v) => v.len(),
            }
    }
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L458-467)
```rust
fn take_unique_ownership<T: Debug>(r: Rc<RefCell<T>>) -> PartialVMResult<T> {
    match Rc::try_unwrap(r) {
        Ok(cell) => Ok(cell.into_inner()),
        Err(r) => Err(
            PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                .with_message(format!("moving value {:?} with dangling references", r))
                .with_sub_status(move_core_types::vm_status::sub_status::unknown_invariant_violation::EREFERENCE_COUNTING_FAILURE),
        ),
    }
}
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L3769-3783)
```rust
    pub fn pop(&self) -> PartialVMResult<Value> {
        let c = self.0.container();

        macro_rules! err_pop_empty_vec {
            () => {
                return Err(PartialVMError::new(StatusCode::VECTOR_OPERATION_ERROR)
                    .with_sub_status(POP_EMPTY_VEC))
            };
        }

        let res = match c {
            Container::VecU8(r) => match r.borrow_mut().pop() {
                Some(x) => Value::u8(x),
                None => err_pop_empty_vec!(),
            },
```

**File:** aptos-move/framework/move-stdlib/sources/string.move (L17-20)
```text
    public fun utf8(bytes: vector<u8>): String {
        assert!(internal_check_utf8(&bytes), EINVALID_UTF8);
        String{bytes}
    }
```

**File:** third_party/move/move-vm/types/src/delayed_values/derived_string_snapshot.rs (L102-110)
```rust
pub fn string_to_bytes(value: Struct) -> PartialVMResult<Vec<u8>> {
    expect_ok(value.unpack())?
        .collect::<Vec<Value>>()
        .pop()
        .map_or_else(
            || Err(code_invariant_error("Unable to extract bytes from String")),
            |v| expect_ok(v.value_as::<Vec<u8>>()),
        )
}
```

**File:** third_party/move/move-vm/types/src/value_serde.rs (L54-54)
```rust
    const MAX_DELAYED_FIELDS_PER_RESOURCE: usize = 10;
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/misc.rs (L335-343)
```rust
    fn visit_vec_u8(&mut self, depth: u64, vals: &[u8]) -> PartialVMResult<()> {
        self.check_depth(depth)?;
        let mut size = self.params.per_u8_packed * NumArgs::new(vals.len() as u64);
        if self.feature_version >= 3 {
            size += self.params.vector;
        }
        self.size += size;
        Ok(())
    }
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L142-142)
```rust
        [memory_quota: AbstractValueSize, { 1.. => "memory_quota" }, 10_000_000],
```
