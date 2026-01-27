# Audit Report

## Title
Module Verification Cost Not Accounted for in Gas Metering or Complexity Checking

## Summary
The complexity checking system in `check_module_complexity` only accounts for structural complexity (signatures, instantiations, type nodes) but does not account for the actual CPU cost of bytecode verification. Additionally, bytecode verification is performed without charging gas, creating a resource exhaustion vector where attackers can publish modules that pass complexity checks but consume excessive validator CPU time during verification.

## Finding Description

During module publishing, there are three distinct cost accounting mechanisms that operate independently:

1. **Gas Charging** (based on module SIZE): [1](#0-0) 

2. **Complexity Checking** (based on STRUCTURAL complexity): [2](#0-1) 

The complexity budget is calculated as `2048 + blob.code().len() * 20` and meters primarily structural elements: [3](#0-2) 

3. **Bytecode Verification** (based on VERIFICATION complexity): [4](#0-3) 

The verification process calls `verify_module_with_config` which uses a separate `BoundMeter` with fixed limits: [5](#0-4) 

Critically, the bytecode verification process does NOT pass the gas meter and operates with its own independent metering: [6](#0-5) 

The verification process meters expensive operations like reference safety analysis: [7](#0-6) 

For each bytecode instruction during verification, the cost can be:
`STEP_BASE_COST (10) + STEP_PER_LOCAL_COST (20) × locals + STEP_PER_GRAPH_ITEM_COST (50) × graph_size`

An attacker can craft a module with:
- Small size (low gas cost via `DEPENDENCY_PER_BYTE`)
- Simple structural complexity (few signatures/instantiations to pass complexity check)
- But complex verification requirements (many instructions, high local count, complex control flow and reference graphs)

This breaks the **Resource Limits invariant**: "All operations must respect gas, storage, and computational limits."

## Impact Explanation

This is a **Medium Severity** vulnerability per Aptos bug bounty criteria as it enables validator resource exhaustion without proportional gas charging:

1. **Validator Node Slowdowns**: Validators must perform expensive verification during transaction execution. While individual transactions will fail if exceeding 80M verifier units, the CPU time spent attempting verification is not charged via gas.

2. **Network Performance Degradation**: Multiple malicious module publishing transactions in a block could force validators to waste significant CPU cycles on verification without adequate gas compensation, potentially slowing block production.

3. **Economic Attack Vector**: An attacker pays gas based only on module SIZE, not verification cost. A 10KB module might cost minimal gas but could consume near-maximum verification resources (approaching 80M verifier units), creating an asymmetric cost/damage ratio.

The impact is limited to Medium (not High/Critical) because:
- Transactions fail rather than corrupting state
- BoundMeter prevents unbounded resource consumption
- No consensus violations or fund loss occurs
- Network slowdown is temporary, not persistent

## Likelihood Explanation

**High Likelihood** of exploitation:

1. **Easy to Execute**: Any user can publish modules - no special privileges required
2. **No Special Tools Needed**: Standard Move compiler can produce modules with complex verification characteristics
3. **Difficult to Detect**: The attack appears as legitimate module publishing attempts
4. **Economically Viable**: Cost to attacker (transaction gas) is far less than cost to validators (CPU time)

An attacker could repeatedly submit such transactions to maximize impact. The only requirement is having enough funds to pay minimal transaction gas.

## Recommendation

Implement verification cost accounting in the gas metering system:

1. **Short-term Fix**: Add verification cost estimation to the complexity checking budget. The complexity budget should account for projected verification meter units, not just structural complexity:

```rust
// In check_module_complexity, estimate verification cost based on:
// - Total instruction count × average cost per instruction
// - Number of locals across all functions
// - Estimated control flow complexity
let estimated_verification_cost = estimate_verification_units(module);
let adjusted_budget = base_budget + estimated_verification_cost / VERIFICATION_TO_COMPLEXITY_RATIO;
```

2. **Long-term Fix**: Charge gas proportional to actual verification cost. Pass the gas meter to the verification process and charge gas based on verifier meter consumption:

```rust
// In build_locally_verified_module
pub fn build_locally_verified_module(
    &self,
    compiled_module: Arc<CompiledModule>,
    module_size: usize,
    module_hash: &[u8; 32],
    gas_meter: &mut impl GasMeter, // ADD gas meter parameter
) -> VMResult<LocallyVerifiedModule> {
    // ... existing code ...
    
    // Charge gas based on verification cost
    let verification_cost = /* capture from BoundMeter */;
    gas_meter.charge_verification(verification_cost)?;
    
    // ... rest of verification ...
}
```

3. **Alternative Approach**: Adjust `DEPENDENCY_PER_BYTE` cost parameter to more accurately reflect verification cost, or add a `DEPENDENCY_PER_INSTRUCTION` component.

## Proof of Concept

The following Move module demonstrates the attack vector:

```move
module attacker::verification_bomb {
    // Module has small size but high verification cost due to:
    // 1. Many local variables (increases STEP_PER_LOCAL_COST)
    // 2. Complex control flow (increases join operations)
    // 3. Complex reference graph (increases STEP_PER_GRAPH_ITEM_COST)
    
    public fun expensive_verification(
        a1: u64, a2: u64, a3: u64, a4: u64, a5: u64,
        a6: u64, a7: u64, a8: u64, a9: u64, a10: u64,
        // ... repeat for 50+ parameters to maximize locals
    ): u64 {
        let r1 = &a1;
        let r2 = &a2;
        let r3 = &a3;
        // ... create complex reference graph
        
        // Complex control flow with many branches
        if (*r1 > *r2) {
            if (*r2 > *r3) {
                if (*r3 > 0) {
                    // Nested conditions create join points
                    *r1
                } else {
                    *r2
                }
            } else {
                *r3
            }
        } else {
            // Mirror structure to maximize verification work
            if (*r2 > *r3) {
                *r2
            } else {
                *r3
            }
        }
    }
    
    // Repeat pattern across multiple functions to approach 80M verifier unit limit
    // while keeping structural complexity low (few signatures/instantiations)
}
```

To test:
1. Publish this module via transaction
2. Observe that gas charged is minimal (based on small module size)
3. Observe that complexity checking passes (few signatures/instantiations)
4. Observe that verification consumes significant CPU time
5. Transaction may fail with `CONSTRAINT_NOT_SATISFIED` if exceeding 80M units
6. But validator has already spent CPU resources without proportional gas charging

**Notes**

The fundamental issue is the disconnect between three independent metering systems:
- Gas charging (based on SIZE)
- Complexity checking (based on STRUCTURAL elements)
- Verification metering (based on VERIFICATION operations)

None of these systems properly accounts for the actual CPU cost incurred by validators during bytecode verification. The complexity checking system answers the question posed: it does NOT account for actual verification cost, only structural complexity. This creates an exploitable resource exhaustion vector that violates the "Resource Limits" invariant.

### Citations

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1529-1536)
```rust
                gas_meter
                    .charge_dependency(
                        DependencyKind::New,
                        addr,
                        name,
                        NumBytes::new(blob.code().len() as u64),
                    )
                    .map_err(|err| err.finish(Location::Undefined))?;
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

**File:** third_party/move/move-binary-format/src/check_complexity.rs (L20-21)
```rust
const COST_PER_TYPE_NODE: u64 = 8;
const COST_PER_IDENT_BYTE: u64 = 1;
```

**File:** third_party/move/move-vm/runtime/src/storage/publishing.rs (L245-257)
```rust
            if is_lazy_loading_enabled {
                // Local bytecode verification.
                staged_runtime_environment.paranoid_check_module_address_and_name(
                    compiled_module,
                    compiled_module.self_addr(),
                    compiled_module.self_name(),
                )?;
                let locally_verified_code = staged_runtime_environment
                    .build_locally_verified_module(
                        compiled_module.clone(),
                        bytes.len(),
                        &sha3_256(bytes),
                    )?;
```

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L175-176)
```rust
        max_per_fun_meter_units: Some(1000 * 80000),
        max_per_mod_meter_units: Some(1000 * 80000),
```

**File:** third_party/move/move-vm/runtime/src/storage/environment.rs (L192-195)
```rust
            move_bytecode_verifier::verify_module_with_config(
                &self.vm_config().verifier_config,
                compiled_module.as_ref(),
            )?;
```

**File:** third_party/move/move-bytecode-verifier/src/reference_safety/abstract_state.rs (L75-80)
```rust
pub(crate) const STEP_BASE_COST: u128 = 10;
pub(crate) const STEP_PER_LOCAL_COST: u128 = 20;
pub(crate) const STEP_PER_GRAPH_ITEM_COST: u128 = 50;
pub(crate) const JOIN_BASE_COST: u128 = 100;
pub(crate) const JOIN_PER_LOCAL_COST: u128 = 10;
pub(crate) const JOIN_PER_GRAPH_ITEM_COST: u128 = 50;
```
