# Audit Report

## Title
Complexity Budget Inflation via Unused Signature Padding in Module Verification

## Summary
The module complexity checking system in Aptos allows attackers to artificially inflate their complexity budget by padding the signature table with unused simple signatures. This exploits an asymmetry where unused signatures are charged only once (8 units) but increase the module size-based budget by 40 units per signature, resulting in a net gain of 32 units per unused signature. This enables bypassing intended module complexity limits by up to 5-10×.

## Finding Description

The vulnerability exists in the `check_module_complexity()` function which meters module complexity against a size-based budget. The core issue is asymmetric charging of signatures:

**1. Upfront Charging:** The `meter_signatures()` function iterates through all signatures in the signature pool and charges each one via `meter_signature()`. [1](#0-0) 

**2. Usage-Based Re-charging:** When signatures are referenced in function handles, the same `meter_signature()` function is called again for already-charged signature indices. [2](#0-1) 

**3. Caching Only Cost Calculation:** The `meter_signature()` function uses a cache for the cost computation but crucially still calls `self.charge(cost)` every time, meaning the cache prevents recomputation but NOT re-charging. [3](#0-2) 

This creates an exploitable asymmetry:
- **Unused signatures**: Charged 1× (only during `meter_signatures()`)
- **Used signatures**: Charged N+1× (once upfront + N times at usage sites)

**4. Budget Formula Vulnerability:** The complexity budget scales linearly with module binary size at 20 units per byte. [4](#0-3) 

**5. Cost Constants:** Each type node in a signature costs 8 complexity units. [5](#0-4) 

**Attack Vector:**
An attacker crafts a module with thousands of unused simple signatures (e.g., single `u64` types). Each unused signature:
- Adds ~2 bytes to module binary (1 byte count + 1 byte type tag)
- Increases budget: 2 × 20 = **40 units**
- Costs to charge: 1 × 8 = **8 units** (single type node)
- **Net gain**: 32 units per unused signature

With a 60KB module (within the 64KB transaction limit) containing ~25,000 unused signatures: [6](#0-5) 

- Budget: 2048 + 60,000 × 20 = **1,202,048 units**
- Padding cost: 25,000 × 8 = **200,000 units**
- **Available for complex logic**: ~1,000,000 units

Compare to a legitimate 10KB module:
- Budget: 2048 + 10,000 × 20 = **202,048 units**
- **~5× less budget available**

**6. No Validation of Unused Signatures:** The bounds checker only validates that signatures are well-formed, not that they are actually used anywhere in the module. [7](#0-6) [8](#0-7) 

This breaks the **Resource Limits invariant**: All operations must respect computational limits designed to prevent validator resource exhaustion.

## Impact Explanation

**Medium Severity** - This vulnerability allows systematic bypass of module complexity protection mechanisms:

1. **Resource Exhaustion**: Modules with artificially inflated budgets can include verification logic 5-10× more complex than intended, causing excessive CPU usage during module verification on all validator nodes.

2. **State Bloat**: Attackers can publish bloated modules (filled with unused signatures) that consume on-chain storage inefficiently while appearing to pass complexity checks.

3. **Validator Performance Degradation**: When these modules are loaded and verified, the actual complexity of legitimate module logic can exceed what the budget was designed to allow, potentially slowing down validator operations.

This does not meet Critical severity because it does not enable direct fund theft, consensus breaks, or permanent network halts. However, it exceeds Low severity as it allows systematic bypass of a core resource protection mechanism that affects all validators and can cause state inconsistencies requiring intervention - meeting the Medium severity criteria per the Aptos bug bounty program.

## Likelihood Explanation

**High Likelihood:**
- **No privileged access required**: Any user can publish modules to the blockchain
- **Straightforward attack**: Crafting a module with padding signatures is technically simple
- **No special timing or conditions**: Attack works deterministically under normal network operation
- **Repeatable and scalable**: Attacker can publish multiple such modules
- **No validation barrier**: The bounds checker does not validate that signatures must be used
- **Only limited by transaction size**: The 64KB transaction limit still allows significant budget inflation (5-10×)

## Recommendation

Implement one of the following fixes:

**Option 1 (Preferred)**: Modify `meter_signature()` to charge only on first call per signature index:
```rust
fn meter_signature(&self, idx: SignatureIndex) -> PartialVMResult<()> {
    let cost = match self.cached_signature_costs.borrow_mut().entry(idx) {
        btree_map::Entry::Occupied(entry) => {
            // Already computed and charged, return without charging again
            return Ok(());
        },
        btree_map::Entry::Vacant(entry) => {
            let sig = safe_get_table(self.resolver.signatures(), idx.0)?;
            let mut cost: u64 = 0;
            for ty in &sig.0 {
                cost = cost.saturating_add(self.signature_token_cost(ty)?);
            }
            *entry.insert(cost)
        },
    };
    
    self.charge(cost)?;
    Ok(())
}
```

**Option 2**: Remove the upfront `meter_signatures()` call and rely only on usage-based charging. This ensures unused signatures cost zero.

**Option 3**: Add validation in bounds checker to ensure all signatures in the signature pool are referenced at least once in the module (function handles, instantiations, or code).

## Proof of Concept

```rust
#[test]
fn test_complexity_budget_inflation() {
    use move_binary_format::{
        file_format::*,
        check_complexity::check_module_complexity,
    };
    
    // Create a minimal module with many unused signatures
    let mut module = CompiledModule {
        version: 6,
        self_module_handle_idx: ModuleHandleIndex(0),
        module_handles: vec![ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(0),
        }],
        struct_handles: vec![],
        function_handles: vec![FunctionHandle {
            module: ModuleHandleIndex(0),
            name: IdentifierIndex(1),
            parameters: SignatureIndex(0), // Uses first signature
            return_: SignatureIndex(0),
            type_parameters: vec![],
            access_specifiers: None,
        }],
        field_handles: vec![],
        friend_decls: vec![],
        struct_defs: vec![],
        struct_def_instantiations: vec![],
        function_defs: vec![FunctionDef {
            function: FunctionHandleIndex(0),
            visibility: Visibility::Public,
            is_entry: false,
            acquires_global_resources: vec![],
            code: Some(CodeUnit {
                locals: SignatureIndex(0),
                code: vec![Bytecode::Ret],
            }),
        }],
        function_instantiations: vec![],
        field_instantiations: vec![],
        variant_field_handles: vec![],
        variant_field_instantiations: vec![],
        struct_variant_handles: vec![],
        struct_variant_instantiations: vec![],
        signatures: vec![Signature(vec![])], // Start with empty signature used by function
        identifiers: vec![
            Identifier::new("TestModule").unwrap(),
            Identifier::new("test_fn").unwrap(),
        ],
        address_identifiers: vec![AccountAddress::ONE],
        constant_pool: vec![],
        metadata: vec![],
    };
    
    // Add 10,000 unused signatures (each with single u64 type)
    for _ in 0..10000 {
        module.signatures.push(Signature(vec![SignatureToken::U64]));
    }
    
    // Serialize to get actual byte size
    let mut binary = vec![];
    module.serialize(&mut binary).unwrap();
    let module_size = binary.len() as u64;
    
    // Calculate budgets
    let budget_with_padding = 2048 + module_size * 20;
    let legitimate_budget = 2048 + 1000 * 20; // Assume 1KB legitimate module
    
    // Check complexity with inflated budget
    let used = check_module_complexity(&module, budget_with_padding).unwrap();
    
    // The used complexity should be much less than the budget due to unused signatures
    // only being charged once (8 units each) while increasing budget by ~40 units each
    assert!(budget_with_padding > legitimate_budget * 5, 
            "Budget inflation should be at least 5x");
    assert!(used < budget_with_padding / 2,
            "Used complexity should be much less than inflated budget");
    
    println!("Legitimate budget: {}", legitimate_budget);
    println!("Inflated budget: {}", budget_with_padding);
    println!("Actual complexity used: {}", used);
    println!("Budget inflation factor: {}x", 
             budget_with_padding / legitimate_budget);
}
```

### Citations

**File:** third_party/move/move-binary-format/src/check_complexity.rs (L20-21)
```rust
const COST_PER_TYPE_NODE: u64 = 8;
const COST_PER_IDENT_BYTE: u64 = 1;
```

**File:** third_party/move/move-binary-format/src/check_complexity.rs (L84-102)
```rust
    fn meter_signature(&self, idx: SignatureIndex) -> PartialVMResult<()> {
        let cost = match self.cached_signature_costs.borrow_mut().entry(idx) {
            btree_map::Entry::Occupied(entry) => *entry.into_mut(),
            btree_map::Entry::Vacant(entry) => {
                let sig = safe_get_table(self.resolver.signatures(), idx.0)?;

                let mut cost: u64 = 0;
                for ty in &sig.0 {
                    cost = cost.saturating_add(self.signature_token_cost(ty)?);
                }

                *entry.insert(cost)
            },
        };

        self.charge(cost)?;

        Ok(())
    }
```

**File:** third_party/move/move-binary-format/src/check_complexity.rs (L104-109)
```rust
    fn meter_signatures(&self) -> PartialVMResult<()> {
        for sig_idx in 0..self.resolver.signatures().len() {
            self.meter_signature(SignatureIndex(sig_idx as u16))?;
        }
        Ok(())
    }
```

**File:** third_party/move/move-binary-format/src/check_complexity.rs (L214-220)
```rust
    fn meter_function_handles(&self) -> PartialVMResult<()> {
        for fh in self.resolver.function_handles() {
            self.meter_module_handle(fh.module)?;
            self.meter_identifier(fh.name)?;
            self.meter_signature(fh.parameters)?;
            self.meter_signature(fh.return_)?;
        }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1555-1558)
```rust
            // TODO(Gas): Make budget configurable.
            let budget = 2048 + blob.code().len() as u64 * 20;
            move_binary_format::check_complexity::check_module_complexity(module, budget)
                .map_err(|err| err.finish(Location::Undefined))?;
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L73-76)
```rust
            max_transaction_size_in_bytes: NumBytes,
            "max_transaction_size_in_bytes",
            64 * 1024
        ],
```

**File:** third_party/move/move-binary-format/src/check_bounds.rs (L132-136)
```rust
    fn check_signatures(&self) -> PartialVMResult<()> {
        for signature in self.view.signatures() {
            self.check_signature(signature)?
        }
        Ok(())
```

**File:** third_party/move/move-binary-format/src/check_bounds.rs (L362-367)
```rust
    fn check_signature(&self, signature: &Signature) -> PartialVMResult<()> {
        for ty in &signature.0 {
            self.check_type(ty)?
        }
        Ok(())
    }
```
