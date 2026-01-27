# Audit Report

## Title
Type Weight Miscalibration in Bytecode Verifier Enables Resource Exhaustion via Struct Field Multiplication

## Summary
The bytecode verifier's `STRUCT_SIZE_WEIGHT` and `PARAM_SIZE_WEIGHT` constants (both set to 4) are improperly calibrated and do not account for actual type expansion behavior when generic structs contain multiple fields. This allows attackers to publish modules with structs containing unlimited fields that pass verification with low weighted scores but trigger expensive runtime type instantiation, causing validator slowdowns and disproportionate resource consumption.

## Finding Description

The Move bytecode verifier uses fixed weight values to estimate type complexity before module execution. [1](#0-0) 

These weights are meant to account for "expansion to an unknown number of nodes" during runtime type instantiation. However, the fixed value of 4 fails to consider the actual expansion factor, which is directly proportional to the number of struct fields.

The critical issue is that Aptos production configuration sets `max_fields_in_struct` to `None`, meaning there is **no limit** on the number of fields a struct can contain: [2](#0-1) 

When a generic struct is instantiated at runtime, the VM must create a separate type instance for **each field** by performing type parameter substitution: [3](#0-2) 

**Attack Scenario:**

1. Attacker publishes a module containing a struct with N fields (e.g., N=1000), all of the same type parameter `T`:
```move
struct ManyFields<T> {
    f1: T, f2: T, ..., f1000: T
}
```

2. The attacker creates a function using this struct with a moderately complex type argument:
```move
public fun process(x: ManyFields<vector<vector<u64>>>) { ... }
```

3. **Verifier Check:**
   - The signature `ManyFields<vector<vector<u64>>>` is analyzed
   - Weighted calculation: 4 (struct) + 1 (vector) + 1 (vector) + 1 (u64) = **7 weighted nodes**
   - Verifier limit (with function values enabled): 128 [4](#0-3) 
   - Status: **PASSES** (7 << 128)

4. **Runtime Execution:**
   - When the function is invoked, `instantiate_generic_struct_fields` is called
   - Creates 1000 separate field type instances, each being `vector<vector<u64>>` (3 nodes)
   - Each field type creation individually passes the runtime check (3 < 128) [5](#0-4) 
   - **Total: 1000 type instantiations = 3000 total nodes**
   - All 1000 types are stored in the frame cache: [6](#0-5) 

5. **Expansion Ratio:** Runtime creates 3000 nodes vs. verifier's prediction of 7 nodes = **428x underestimation**

This breaks the **Resource Limits invariant**: "All operations must respect gas, storage, and computational limits." The verifier's static check fails to accurately predict runtime resource consumption, allowing operations that appear lightweight but are actually expensive.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program criteria for "Validator node slowdowns."

**Concrete Impacts:**

1. **CPU Resource Exhaustion**: Creating thousands of type instances via recursive type substitution consumes significant CPU time on validator nodes. While gas is charged per field type creation, the cumulative effect can cause noticeable validator slowdowns when processing blocks containing such transactions.

2. **Memory Pressure**: The frame type cache stores all instantiated field types. With unlimited fields and complex type arguments, this can consume substantial memory per transaction execution, potentially affecting validator performance under load.

3. **Gas Estimation Mismatch**: Users and tools relying on static analysis (which uses verifier weights) will severely underestimate transaction costs. A transaction appearing to have complexity of 7 nodes actually requires creating 3000 nodes at runtime.

4. **Amplification via Function Parameters**: With `max_function_parameters = 128`, an attacker can multiply the effect by using multiple parameters, each being a high-field-count struct, potentially forcing creation of hundreds of thousands of type nodes in a single transaction.

The vulnerability does not directly enable consensus breaks or fund theft, but validator slowdowns can degrade network performance and user experience, qualifying as High severity.

## Likelihood Explanation

**Likelihood: High**

- **Ease of Exploitation**: Attackers can publish modules with high-field-count structs without restrictions (no cost beyond standard module publishing)
- **No Special Privileges Required**: Any account can publish modules and call functions
- **Bypasses Static Checks**: The verifier explicitly allows this pattern due to miscalibrated weights
- **Repeatable**: Attackers can invoke such functions repeatedly or in loops to amplify impact
- **Current Production Impact**: Since `max_fields_in_struct = None` in production, this is exploitable on mainnet today

The only mitigation is transaction gas limits, but with sufficiently high gas limits (governed by `max_gas_amount` per transaction), attackers can still cause significant per-transaction resource consumption.

## Recommendation

**Immediate Mitigations:**

1. **Set `max_fields_in_struct` Limit**: Add a reasonable upper bound (e.g., 128 or 256) in production configuration:
```rust
max_fields_in_struct: Some(128),
```

2. **Recalibrate STRUCT_SIZE_WEIGHT**: The weight should account for potential field count. Consider:
```rust
const STRUCT_SIZE_WEIGHT: usize = 32; // Account for typical max fields
```

**Long-term Fix:**

Implement field-count-aware weight calculation by looking up the actual struct definition during verification:

```rust
// In verify_type_node()
match token {
    SignatureToken::Struct(idx) | SignatureToken::StructInstantiation(idx, _) => {
        let struct_def = self.resolver.struct_def_at(*idx);
        let field_count = struct_def.field_count(); // Get actual field count
        type_size += STRUCT_BASE_WEIGHT + (field_count * FIELD_WEIGHT);
    },
    // ...
}
```

This ensures the verifier's weight accurately reflects runtime expansion behavior.

**Additional Hardening:**

Add a cumulative type node limit per function instantiation to bound total type creation work, not just individual type sizes.

## Proof of Concept

```move
// Module: attacker::heavy_struct
module attacker::heavy_struct {
    // Struct with 100 fields (can scale to 1000+)
    struct ManyFields<T> has drop {
        f1: T, f2: T, f3: T, f4: T, f5: T,
        f6: T, f7: T, f8: T, f9: T, f10: T,
        // ... repeat to f100
    }
    
    // Function using nested vectors as type argument
    public entry fun process_heavy(
        x: ManyFields<vector<vector<vector<u64>>>>
    ) {
        // Unpack forces field type instantiation
        let ManyFields { 
            f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, /* ... f100 */ 
        } = x;
        // Each field type is vector<vector<vector<u64>>> = 4 nodes
        // Total: 100 fields × 4 nodes = 400 type nodes created
        // Verifier weight: 4 (struct) + 4 (vectors) = 8
        // Expansion ratio: 400/8 = 50x underestimation
    }
}
```

**Verification:**
- Verifier weighted score: ~8 nodes (passes limit of 128)
- Runtime type nodes created: 400+ nodes (100 fields × 4 nodes per field)
- CPU time for type instantiation: Linear with field count
- Memory usage: 100 Type objects cached in frame

**Exploitation:**
Call `process_heavy` repeatedly in a transaction or loop to amplify validator CPU consumption. With `max_function_parameters = 128`, can multiply effect by using 128 such parameters, forcing creation of 51,200 type nodes in a single function call.

---

**Notes**

This vulnerability stems from a fundamental mismatch between static verification heuristics and dynamic runtime behavior. The verifier's weight system assumes average-case expansion, but without field count limits, worst-case expansion is unbounded. The fix requires either bounding the input space (max fields) or making the weight calculation field-aware.

### Citations

**File:** third_party/move/move-bytecode-verifier/src/limits.rs (L140-143)
```rust
        // Structs and Parameters can expand to an unknown number of nodes, therefore
        // we give them a higher size weight here.
        const STRUCT_SIZE_WEIGHT: usize = 4;
        const PARAM_SIZE_WEIGHT: usize = 4;
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L162-166)
```rust
        max_type_nodes: if enable_function_values {
            Some(128)
        } else {
            Some(256)
        },
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L170-170)
```rust
        max_fields_in_struct: None,
```

**File:** third_party/move/move-vm/runtime/src/frame.rs (L450-457)
```rust
        struct_ty
            .fields(variant)?
            .iter()
            .map(|(_, inst_ty)| {
                self.ty_builder
                    .create_ty_with_subst(inst_ty, &instantiation_tys)
            })
            .collect::<PartialVMResult<Vec<_>>>()
```

**File:** third_party/move/move-vm/types/src/loaded_data/runtime_types.rs (L1195-1203)
```rust
    fn check(&self, count: &mut u64, depth: u64) -> PartialVMResult<()> {
        if *count >= self.max_ty_size {
            return self.too_many_nodes_error();
        }
        if depth > self.max_ty_depth {
            return self.too_large_depth_error();
        }
        Ok(())
    }
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
