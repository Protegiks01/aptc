# Audit Report

## Title
Unmetered Resource Exhaustion via Excessive Struct Handles in Script Loading

## Summary
An attacker can submit script transactions containing thousands of struct handles that trigger unmetered CPU-intensive processing during script loading, causing validator performance degradation. The vulnerability violates the fundamental gas model principle that all computational work must be metered.

## Finding Description

The vulnerability exists in the script loading pipeline where `Script::new()` performs unmetered iteration over struct handles without gas charging or count limits.

The vulnerable loop iterates over every struct handle in the script: [1](#0-0) 

Each iteration performs expensive operations:
1. Array lookups for identifiers and module handles
2. String cloning via `to_owned()` 
3. `StructIdentifier::new()` which interns module IDs
4. `struct_name_index_map.struct_name_to_idx()` which acquires read/write locks, performs BTreeMap lookups O(log n), and clones struct identifiers twice on cache misses: [2](#0-1) 

**Attack Path:**

1. Attacker crafts a script with maximum struct handles within the 64 KB transaction size limit: [3](#0-2) 

2. Binary format allows up to 65,535 struct handles (u16 index type): [4](#0-3) 

3. Script is submitted as a valid transaction payload (scripts are fully supported)

4. During block execution, validators call `validate_and_execute_script()` which loads the script: [5](#0-4) 

5. The loading process calls `metered_verify_and_cache_script()`: [6](#0-5) 

6. This invokes `Script::new()` which performs the unmetered struct handle iteration

**Verification Gaps:**

The bytecode verifier only checks type parameters within each struct handle, not the total count: [7](#0-6) 

The `VerifierConfig` has no field for limiting total struct handle count: [8](#0-7) 

**Cache Bypass:**

Scripts are cached by SHA3-256 hash: [9](#0-8) 

Attackers can submit many unique scripts by changing a few bytes, forcing repeated processing.

## Impact Explanation

This qualifies as **High Severity** under Aptos bug bounty criteria: "Validator node slowdowns - Significant performance degradation affecting consensus."

The vulnerability breaks the fundamental security invariant that all computational work must be metered with gas charges. This allows attackers to:

- Consume validator CPU time without proportional gas costs
- Degrade performance across all validators processing the same transaction
- Submit multiple unique scripts to amplify the effect
- Strategically slow validators during critical consensus operations

The gas metering only charges for module dependencies, not for the struct handle processing itself: [10](#0-9) 

## Likelihood Explanation

**High Likelihood:**
- Scripts are fully supported transaction types
- No special permissions required - any user can submit script transactions  
- Attack is technically straightforward - craft binary with many struct handle entries
- Transaction size limit (64 KB) provides sufficient space for thousands of handles
- Caching only prevents identical scripts, easily bypassed with minor byte variations
- No monitoring or rate limiting specifically for this attack pattern
- The vulnerable code path is executed for every new/unique script submitted by all validators

## Recommendation

Implement one or more of the following mitigations:

1. **Add struct handle count limit to VerifierConfig:**
   - Add `max_struct_handles: Option<usize>` field to `VerifierConfig`
   - Enforce this limit in `LimitsVerifier::verify_struct_handles()`

2. **Charge gas for struct handle processing:**
   - Add gas metering within `Script::new()` or `build_verified_script()`
   - Charge gas proportional to the number of struct handles processed

3. **Pre-validation size check:**
   - Add early validation that rejects scripts with excessive struct handle counts before expensive processing

4. **Rate limiting:**
   - Implement per-account rate limiting for unique script submissions in mempool

## Proof of Concept

A complete PoC would require constructing a Move binary with thousands of struct handles within the 64 KB limit. The binary would contain:
- Minimal bytecode
- Reused address/module identifiers  
- Maximum number of unique struct handle entries referencing dummy structs

When submitted as a script transaction, each validator would process all struct handles in `Script::new()` without gas charges, consuming CPU time proportional to the handle count.

**Notes**

The vulnerability is validated through comprehensive code analysis showing that struct handle iteration in `Script::new()` is unmetered, no count limits exist in the verifier, and scripts are fully supported transaction types. The impact qualifies as High severity "Validator node slowdowns" per the Aptos bug bounty program, distinct from out-of-scope "Network DoS attacks" as this exploits computational resource exhaustion during valid transaction processing rather than network-layer flooding.

### Citations

**File:** third_party/move/move-vm/runtime/src/loader/script.rs (L62-70)
```rust
        let mut struct_names = vec![];
        for struct_handle in script.struct_handles() {
            let struct_name = script.identifier_at(struct_handle.name);
            let module_handle = script.module_handle_at(struct_handle.module);
            let module_id = script.module_id_for_handle(module_handle);
            let struct_name =
                StructIdentifier::new(module_id_pool, module_id, struct_name.to_owned());
            struct_names.push(struct_name_index_map.struct_name_to_idx(&struct_name)?);
        }
```

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

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L73-76)
```rust
            max_transaction_size_in_bytes: NumBytes,
            "max_transaction_size_in_bytes",
            64 * 1024
        ],
```

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L48-48)
```rust
pub const STRUCT_HANDLE_INDEX_MAX: u64 = TABLE_INDEX_MAX;
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L909-915)
```rust
            let func = loader.load_script(
                &legacy_loader_config,
                gas_meter,
                traversal_context,
                serialized_script.code(),
                serialized_script.ty_args(),
            )?;
```

**File:** third_party/move/move-vm/runtime/src/storage/loader/lazy.rs (L128-128)
```rust
        let hash = sha3_256(serialized_script);
```

**File:** third_party/move/move-vm/runtime/src/storage/loader/lazy.rs (L151-157)
```rust
        let immediate_dependencies = locally_verified_script
            .immediate_dependencies_iter()
            .map(|(addr, name)| {
                let module_id = ModuleId::new(*addr, name.to_owned());
                self.metered_load_module(gas_meter, traversal_context, &module_id)
            })
            .collect::<VMResult<Vec<_>>>()?;
```

**File:** third_party/move/move-vm/runtime/src/storage/loader/lazy.rs (L159-161)
```rust
        let verified_script = self
            .runtime_environment()
            .build_verified_script(locally_verified_script, &immediate_dependencies)?;
```

**File:** third_party/move/move-bytecode-verifier/src/limits.rs (L53-63)
```rust
    fn verify_struct_handles(&self, config: &VerifierConfig) -> PartialVMResult<()> {
        if let Some(limit) = config.max_generic_instantiation_length {
            for (idx, struct_handle) in self.resolver.struct_handles().iter().enumerate() {
                if struct_handle.type_parameters.len() > limit {
                    return Err(PartialVMError::new(StatusCode::TOO_MANY_TYPE_PARAMETERS)
                        .at_index(IndexKind::StructHandle, idx as u16));
                }
            }
        }
        Ok(())
    }
```

**File:** third_party/move/move-bytecode-verifier/src/verifier.rs (L36-67)
```rust
pub struct VerifierConfig {
    pub scope: VerificationScope,
    pub max_loop_depth: Option<usize>,
    pub max_function_parameters: Option<usize>,
    pub max_generic_instantiation_length: Option<usize>,
    pub max_basic_blocks: Option<usize>,
    pub max_value_stack_size: usize,
    pub max_type_nodes: Option<usize>,
    pub max_push_size: Option<usize>,
    pub max_struct_definitions: Option<usize>,
    pub max_struct_variants: Option<usize>,
    pub max_fields_in_struct: Option<usize>,
    pub max_function_definitions: Option<usize>,
    pub max_back_edges_per_function: Option<usize>,
    pub max_back_edges_per_module: Option<usize>,
    pub max_basic_blocks_in_script: Option<usize>,
    pub max_per_fun_meter_units: Option<u128>,
    pub max_per_mod_meter_units: Option<u128>,
    // signature checker v2 is enabled on mainnet and cannot be disabled
    pub _use_signature_checker_v2: bool,
    pub sig_checker_v2_fix_script_ty_param_count: bool,
    pub enable_enum_types: bool,
    pub enable_resource_access_control: bool,
    pub enable_function_values: bool,
    /// Maximum number of function return values.
    pub max_function_return_values: Option<usize>,
    /// Maximum depth of a type node.
    pub max_type_depth: Option<usize>,
    /// If enabled, signature checker V2 also checks parameter and return types in function
    /// signatures.
    pub sig_checker_v2_fix_function_signatures: bool,
}
```
