# Audit Report

## Title
Unbounded Module Verification Cost Enables Validator DoS Through Complex Module Publishing

## Summary
Module bytecode verification during publishing is not bounded by transaction gas limits, only by separate internal verifier meter limits (80 million units per function/module). An attacker can craft modules with maximum complexity within verifier limits to cause synchronous verification delays during block execution, affecting all validators simultaneously and degrading network performance.

## Finding Description

When a user publishes Move modules via the `code::request_publish()` native function, the system charges gas based on module size using `CODE_REQUEST_PUBLISH_PER_BYTE`. [1](#0-0) 

However, the actual bytecode verification that occurs during module publishing is not bounded by the transaction's gas meter. The verification happens in `StagingModuleStorage::create_with_compat_config`, which calls `build_locally_verified_module`. [2](#0-1) 

The bytecode verification itself is performed by `move_bytecode_verifier::verify_module_with_config`, which uses only an internal `BoundMeter` with limits configured in production as 80 million units per function and module. [3](#0-2) [4](#0-3) 

The verification process includes computationally expensive operations such as type safety checking, where each type node costs 30 units and is charged during type inference for every instruction. [5](#0-4) 

The verification is synchronous and occurs during block execution, meaning all validators must perform the same expensive verification when processing a block containing module publications. [6](#0-5) 

**Attack Path:**
1. Attacker crafts modules with maximum complexity within verifier limits: max_type_nodes (128-256), max_basic_blocks (1024), max_push_size (10000), deep type nesting, complex control flow
2. Publishes these modules in transactions, paying only size-based gas
3. During block execution, all validators must verify these modules synchronously
4. Verification takes significant time despite being within verifier limits
5. Multiple such modules in a block compound the effect, causing validator slowdowns

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program criteria: "Validator node slowdowns". 

The impact includes:
- **Validator Performance Degradation**: All validators experience synchronous verification delays during block execution
- **Network Throughput Reduction**: Complex modules slow down block processing, reducing overall network TPS
- **Consensus Impact**: Extended block execution times can affect consensus timing and liveness
- **Economic Cost**: Attackers pay only size-based gas but impose computational cost on all validators

The vulnerability breaks **Invariant #9**: "Resource Limits: All operations must respect gas, storage, and computational limits" - module verification complexity is not properly bounded by gas.

## Likelihood Explanation

**Likelihood: High**

- **Low Barrier to Entry**: Any user can publish modules to their own account
- **Low Cost**: Gas is charged based on module size, not verification complexity
- **Deterministic Impact**: All validators must verify the same modules
- **Compounding Effect**: Multiple complex modules in a block multiply the impact
- **No Rate Limiting**: No specific protection against repeated complex module publishing

## Recommendation

Implement gas charging proportional to actual verification cost:

1. **Pre-compute Verification Cost Estimate**: Before full verification, estimate verification complexity based on module structure (type complexity, control flow depth, instruction count)

2. **Charge Gas for Verification**: Modify the native function to charge gas based on estimated verification cost, not just module size

3. **Tighten Verifier Limits**: Consider reducing `max_per_fun_meter_units` and `max_per_mod_meter_units` from 80 million to lower values based on acceptable verification time budgets

4. **Add Timeout Protection**: Implement verification timeouts at the system level to prevent unbounded execution time

5. **Cache Verification Results More Aggressively**: Expand the verification cache to cover more scenarios

Example fix in `code.rs`:
```rust
// Add verification complexity estimation
let verification_cost = estimate_verification_complexity(&module_code);
context.charge(CODE_VERIFICATION_BASE + 
               CODE_VERIFICATION_PER_COMPLEXITY_UNIT * verification_cost)?;
```

## Proof of Concept

```move
// Complex module designed to maximize verification cost
module attacker::complex_verification {
    use std::vector;
    
    // Deeply nested type structure (maximizes type nodes)
    struct Level0<T> { value: T }
    struct Level1<T> { value: Level0<T> }
    struct Level2<T> { value: Level1<T> }
    // ... continue to maximum depth
    
    // Function with maximum basic blocks and complex control flow
    public fun expensive_verify<T>(
        x: u64, y: u64, z: u64, w: u64
    ): Level2<vector<Level1<T>>> {
        let i = 0;
        // Create maximum basic blocks with complex type operations
        while (i < 1000) {
            if (x > y) {
                if (z > w) {
                    // Complex type instantiations
                    let _v: Level2<vector<Level1<T>>>;
                    // More nested control flow
                } else {
                    let _v: Level1<vector<Level0<T>>>;
                };
            } else {
                // More branches with complex types
            };
            i = i + 1;
        };
        abort 0
    }
}

// Transaction to publish multiple such modules in one block
// Each module stays within verifier limits but takes significant time to verify
// Multiple modules compound the effect on validator performance
```

**Notes:**
- The vulnerability exists because module verification cost is not reflected in transaction gas costs
- The 80 million unit verifier limits are high enough to allow expensive verification within bounds
- The synchronous nature of verification during block execution makes this a network-wide performance issue
- The caching mechanism helps for republished identical modules but not for distinct complex modules

### Citations

**File:** aptos-move/framework/src/natives/code.rs (L292-300)
```rust
    context.charge(CODE_REQUEST_PUBLISH_BASE)?;

    let policy = safely_pop_arg!(args, u8);
    let mut code = vec![];
    for module in safely_pop_arg!(args, Vec<Value>) {
        let module_code = module.value_as::<Vec<u8>>()?;

        context.charge(CODE_REQUEST_PUBLISH_PER_BYTE * NumBytes::new(module_code.len() as u64))?;
        code.push(module_code);
```

**File:** aptos-move/aptos-vm/src/move_vm_ext/session/user_transaction_sessions/user.rs (L97-102)
```rust
        let staging_module_storage = StagingModuleStorage::create_with_compat_config(
            &destination,
            compatability_checks,
            module_storage,
            bundle.into_bytes(),
        )?;
```

**File:** third_party/move/move-vm/runtime/src/storage/environment.rs (L192-195)
```rust
            move_bytecode_verifier::verify_module_with_config(
                &self.vm_config().verifier_config,
                compiled_module.as_ref(),
            )?;
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L175-176)
```rust
        max_per_fun_meter_units: Some(1000 * 80000),
        max_per_mod_meter_units: Some(1000 * 80000),
```

**File:** third_party/move/move-bytecode-verifier/src/type_safety.rs (L87-99)
```rust
    fn push(&mut self, meter: &mut impl Meter, ty: SignatureToken) -> PartialVMResult<()> {
        self.charge_ty(meter, &ty)?;
        self.stack.push(ty);
        Ok(())
    }

    fn charge_ty(&mut self, meter: &mut impl Meter, ty: &SignatureToken) -> PartialVMResult<()> {
        meter.add_items(
            Scope::Function,
            TYPE_NODE_COST,
            ty.preorder_traversal().count(),
        )
    }
```

**File:** third_party/move/move-bytecode-verifier/src/code_unit_verifier.rs (L46-67)
```rust
    fn verify_module_impl(
        verifier_config: &VerifierConfig,
        module: &CompiledModule,
    ) -> PartialVMResult<()> {
        let mut meter = BoundMeter::new(verifier_config);
        let mut name_def_map = HashMap::new();
        for (idx, func_def) in module.function_defs().iter().enumerate() {
            let fh = module.function_handle_at(func_def.function);
            name_def_map.insert(fh.name, FunctionDefinitionIndex(idx as u16));
        }
        let mut total_back_edges = 0;
        for (idx, function_definition) in module.function_defs().iter().enumerate() {
            let index = FunctionDefinitionIndex(idx as TableIndex);
            let num_back_edges = Self::verify_function(
                verifier_config,
                index,
                function_definition,
                module,
                &name_def_map,
                &mut meter,
            )
            .map_err(|err| err.at_index(IndexKind::FunctionDefinition, index.0))?;
```
