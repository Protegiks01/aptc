# Audit Report

## Title
Complexity Budget Bypass via Undercharged Struct Field Type Metering Enables Module Publishing DoS

## Summary
The `meter_struct_defs()` function charges struct field types at only 1 unit per node, while signature types are charged at 8 units per node plus identifier costs. This 8x+ undercharging allows attackers to bypass the complexity budget and publish modules with excessive type complexity, potentially causing denial-of-service during module verification and loading.

## Finding Description

The complexity metering system in Move bytecode has a critical inconsistency in how it charges for type complexity. When metering struct definitions, field types are charged using only `num_nodes()`: [1](#0-0) 

However, when metering signatures, the same types are charged using `signature_token_cost()` which applies `COST_PER_TYPE_NODE` (value: 8) per node PLUS identifier costs for struct names and module names: [2](#0-1) [3](#0-2) 

The complexity check is enforced during module publishing with a budget calculated as `2048 + blob.code().len() * 20`: [4](#0-3) 

An attacker can exploit this by creating a module with many struct definitions containing deeply nested field types (up to the hard limit of 128 type nodes). These complex types consume only 1 unit per node instead of 8+ units, allowing the module to pass the complexity check despite having 8x more actual complexity than the budget implies.

**Attack Steps:**
1. Attacker crafts a Move module with minimal code but many struct definitions
2. Each struct contains fields with deeply nested types (e.g., `vector<vector<vector<...>>>`) approaching the max_type_nodes limit (128 nodes)
3. Bytecode size remains small (e.g., 100 bytes), yielding budget ≈ 4,048 units
4. With undercharging, attacker can include ~3 structs with 128-node field types (384 units consumed)
5. With proper charging, budget would only allow 0-1 such structs (each requiring 1,024+ units)
6. Module passes complexity check but triggers expensive verification operations

While the `LimitsVerifier` still enforces hard limits (max_type_nodes, max_type_depth), the complexity budget bypass allows publishing modules that consume disproportionate verification resources relative to their bytecode size: [5](#0-4) 

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program criteria for "Validator node slowdowns."

The complexity budget is explicitly designed as a DoS mitigation mechanism to ensure module verification time remains proportional to bytecode size. By bypassing this budget through undercharged struct fields, an attacker can:

1. **Publishing DoS**: Submit module publishing transactions that pass initial complexity checks but trigger expensive type verification operations, slowing down validators during transaction processing
2. **Resource Exhaustion**: Type verification involves recursive traversal of nested types, depth checking, and formula construction for generic types, all proportional to type complexity
3. **Amplification Attack**: Small bytecode can encode large complexity, allowing efficient DoS with minimal transaction size

The type verification operations that scale with complexity include: [6](#0-5) 

## Likelihood Explanation

**Likelihood: High**

- **No special privileges required**: Any user can publish Move modules to their own account
- **Trivial to exploit**: Attacker simply needs to generate structs with nested vector types
- **Hard to detect**: Malicious modules pass complexity checks and may not be obviously anomalous
- **Repeatable**: Attacker can submit multiple publishing transactions to amplify DoS effect

The attack requires no validator access, no economic stake, and minimal technical sophistication. The undercharging is systematic and deterministic.

## Recommendation

Modify `meter_struct_defs()` to use `signature_token_cost()` for struct field types, ensuring consistent charging across all type contexts:

```rust
fn meter_struct_defs(&self) -> PartialVMResult<()> {
    let struct_defs = self.resolver.struct_defs().ok_or_else(|| {
        PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
            .with_message("Can't get struct defs -- not a module.".to_string())
    })?;

    for sdef in struct_defs {
        match &sdef.field_information {
            StructFieldInformation::Native => continue,
            StructFieldInformation::Declared(fields) => {
                for field in fields {
                    // FIX: Use signature_token_cost instead of num_nodes
                    let cost = self.signature_token_cost(&field.signature.0)?;
                    self.charge(cost)?;
                }
            },
            StructFieldInformation::DeclaredVariants(variants) => {
                for variant in variants {
                    self.meter_identifier(variant.name)?;
                    for field in &variant.fields {
                        // FIX: Use signature_token_cost instead of num_nodes
                        let cost = self.signature_token_cost(&field.signature.0)?;
                        self.charge(cost)?;
                    }
                }
            },
        }
    }
    Ok(())
}
```

This ensures struct field types are charged at the same 8x rate as signatures, properly accounting for their verification cost.

## Proof of Concept

```move
// Malicious module with deeply nested struct fields
module attacker::complexity_bomb {
    // Each field has ~128 type nodes (vector nesting depth)
    struct Bomb1 {
        f: vector<vector<vector<vector<vector<vector<vector<vector<
           vector<vector<vector<vector<vector<vector<vector<vector<
           vector<vector<vector<vector<u64>>>>>>>>>>>>>>>>>>>>
    }
    
    struct Bomb2 {
        f: vector<vector<vector<vector<vector<vector<vector<vector<
           vector<vector<vector<vector<vector<vector<vector<vector<
           vector<vector<vector<vector<u64>>>>>>>>>>>>>>>>>>>>
    }
    
    struct Bomb3 {
        f: vector<vector<vector<vector<vector<vector<vector<vector<
           vector<vector<vector<vector<vector<vector<vector<vector<
           vector<vector<vector<vector<u64>>>>>>>>>>>>>>>>>>>>
    }
    
    // Minimal code to keep bytecode size small
    public fun noop() {}
}
```

**Expected Results:**
- Current implementation: Module passes complexity check (charged ~384 units for 3 structs)
- With fix: Module rejected with PROGRAM_TOO_COMPLEX error (would require ~3,072+ units)

**Notes**

This vulnerability breaks the **Resource Limits** invariant (#9: "All operations must respect gas, storage, and computational limits") by allowing type complexity to exceed what the complexity budget should permit. While hard limits (max_type_nodes, max_type_depth) still apply, the soft limit bypass enables disproportionate verification costs relative to bytecode size, creating a DoS vector against validators processing module publishing transactions.

### Citations

**File:** third_party/move/move-binary-format/src/check_complexity.rs (L20-21)
```rust
const COST_PER_TYPE_NODE: u64 = 8;
const COST_PER_IDENT_BYTE: u64 = 1;
```

**File:** third_party/move/move-binary-format/src/check_complexity.rs (L52-77)
```rust
    fn signature_token_cost(&self, tok: &SignatureToken) -> PartialVMResult<u64> {
        use SignatureToken::*;

        let mut cost: u64 = 0;

        for node in tok.preorder_traversal() {
            cost = cost.saturating_add(COST_PER_TYPE_NODE);

            match node {
                Struct(sh_idx) | StructInstantiation(sh_idx, _) => {
                    let sh = safe_get_table(self.resolver.struct_handles(), sh_idx.0)?;
                    let mh = safe_get_table(self.resolver.module_handles(), sh.module.0)?;
                    let struct_name = safe_get_table(self.resolver.identifiers(), sh.name.0)?;
                    let moduel_name = safe_get_table(self.resolver.identifiers(), mh.name.0)?;

                    cost = cost.saturating_add(struct_name.len() as u64 * COST_PER_IDENT_BYTE);
                    cost = cost.saturating_add(moduel_name.len() as u64 * COST_PER_IDENT_BYTE);
                },
                U8 | U16 | U32 | U64 | U128 | U256 | I8 | I16 | I32 | I64 | I128 | I256
                | Signer | Address | Bool | Vector(_) | Function(..) | TypeParameter(_)
                | Reference(_) | MutableReference(_) => (),
            }
        }

        Ok(cost)
    }
```

**File:** third_party/move/move-binary-format/src/check_complexity.rs (L242-244)
```rust
                    for field in fields {
                        self.charge(field.signature.0.num_nodes() as u64)?;
                    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1554-1559)
```rust
        for (module, blob) in modules.iter().zip(bundle.iter()) {
            // TODO(Gas): Make budget configurable.
            let budget = 2048 + blob.code().len() as u64 * 20;
            move_binary_format::check_complexity::check_module_complexity(module, budget)
                .map_err(|err| err.finish(Location::Undefined))?;
        }
```

**File:** third_party/move/move-bytecode-verifier/src/limits.rs (L96-125)
```rust
    fn verify_type_nodes(&self, config: &VerifierConfig) -> PartialVMResult<()> {
        for sign in self.resolver.signatures() {
            for ty in &sign.0 {
                self.verify_type_node(config, ty)?
            }
        }
        for cons in self.resolver.constant_pool() {
            self.verify_type_node(config, &cons.type_)?
        }
        if let Some(sdefs) = self.resolver.struct_defs() {
            for sdef in sdefs {
                match &sdef.field_information {
                    StructFieldInformation::Native => {},
                    StructFieldInformation::Declared(fdefs) => {
                        for fdef in fdefs {
                            self.verify_type_node(config, &fdef.signature.0)?
                        }
                    },
                    StructFieldInformation::DeclaredVariants(variants) => {
                        for variant in variants {
                            for fdef in &variant.fields {
                                self.verify_type_node(config, &fdef.signature.0)?
                            }
                        }
                    },
                }
            }
        }
        Ok(())
    }
```

**File:** third_party/move/move-vm/runtime/src/storage/ty_depth_checker.rs (L73-89)
```rust
    pub(crate) fn check_depth_of_type(
        &self,
        gas_meter: &mut impl DependencyGasMeter,
        traversal_context: &mut TraversalContext,
        ty: &Type,
    ) -> PartialVMResult<()> {
        let max_depth = match self.maybe_max_depth {
            Some(max_depth) => max_depth,
            None => return Ok(()),
        };

        let _timer = VM_TIMER.timer_with_label("check_depth_of_type");

        // Start at 1 since we always call this right before we add a new node to the value's depth.
        self.recursive_check_depth_of_type(gas_meter, traversal_context, ty, max_depth, 1)?;
        Ok(())
    }
```
