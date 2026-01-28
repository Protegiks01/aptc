# Audit Report

## Title
Module Verification Cost Not Accounted for in Gas Metering or Complexity Checking

## Summary
The bytecode verification process during module publishing consumes validator CPU time that is not proportionally accounted for in gas charging. While gas is charged based on module size (42 gas units per byte) and structural complexity is checked (budget of 2048 + code_len × 20), the actual CPU cost of bytecode verification can reach 80,000,000 verifier units per function without corresponding gas charges, creating an exploitable resource exhaustion vector.

## Finding Description

During module publishing in Aptos, three distinct cost accounting mechanisms operate independently, creating a critical gap between gas charged and CPU consumed:

**1. Gas Charging Based on Module Size:**
Gas is charged per byte using `DEPENDENCY_PER_BYTE = 42` for module dependencies. [1](#0-0) 

This charging happens in `publish_module_bundle` when processing new modules in the bundle. [2](#0-1) 

**2. Complexity Checking Based on Structural Elements:**
The complexity budget is calculated as `2048 + blob.code().len() * 20` and enforced before verification. [3](#0-2) 

However, the complexity checker only meters structural elements like generic instantiations, function instantiations, and signatures. Regular bytecode instructions (Add, Sub, CopyLoc, MoveLoc, etc.) are explicitly NOT metered. [4](#0-3) 

**3. Bytecode Verification Without Gas Metering:**
After gas charging and complexity checking, module publishing creates `StagingModuleStorage` which performs expensive bytecode verification. [5](#0-4) 

This verification happens through `build_locally_verified_module` which calls `verify_module_with_config` without any gas meter context. [6](#0-5) 

The verification uses `BoundMeter` with production limits of 80,000,000 verifier units per function and module. [7](#0-6) 

**Critical Cost Disparity:**
Reference safety verification charges per instruction: `STEP_BASE_COST (10) + STEP_PER_LOCAL_COST (20) × locals + STEP_PER_GRAPH_ITEM_COST (50) × graph_size`. [8](#0-7) 

The metering happens during bytecode verification. [9](#0-8) 

**Exploitation Vector:**
An attacker can craft modules with:
- Small size (low gas via `DEPENDENCY_PER_BYTE = 42`)
- Few generic instantiations (passes complexity check since regular instructions aren't metered)
- Many regular instructions with high local counts and complex borrow graphs (high verification cost)

When verification fails, gas is still charged as `MiscellaneousError`, but only based on what was already charged (module size). [10](#0-9) 

## Impact Explanation

This vulnerability enables **Validator Node Slowdowns (High Severity per Aptos Bug Bounty)**.

**Economic Asymmetry:**
- A 10KB module pays: 10,000 × 42 = 420,000 gas units
- Same module can consume: 80,000,000 verifier units before failing
- Ratio: ~190x cost multiplier

**Attack Scenario:**
1. Attacker submits transactions attempting to publish small modules with expensive verification requirements
2. Validators must perform full verification during mempool validation AND block execution
3. Each verification attempt consumes up to 80M verifier units of CPU time
4. Attacker only pays gas based on module size (~420,000 units for 10KB)
5. Multiple such transactions per block force validators to waste significant CPU cycles
6. Network throughput degrades as validators spend disproportionate time on verification

**Mitigating Factors:**
- `BoundMeter` caps verification at 80M units (prevents unbounded consumption)
- Module size limits (MAX_MODULE_SIZE = 65,355 bytes) cap attack surface
- Transactions fail properly without state corruption
- No consensus violations or fund loss
- Impact is temporary, not persistent

The combination of high exploitability and validator resource exhaustion, tempered by the mitigating factors, places this at **Medium-to-High Severity**.

## Likelihood Explanation

**High Likelihood** of exploitation:

1. **Easy to Execute**: Any user can publish modules through standard transaction submission without special privileges
2. **Permissionless Operation**: Module publishing is available to all network participants
3. **Difficult to Detect**: Attack appears as legitimate module publishing attempts that fail verification checks
4. **Economically Viable**: The ~190x asymmetry between gas paid and CPU consumed makes this attack cost-effective
5. **Repeatable**: Attacker can submit multiple such transactions per block across many blocks

## Recommendation

Implement verification-aware gas charging by:

1. **Meter verification costs during gas charging phase:**
```rust
// After complexity checking, estimate verification cost
let estimated_verification_units = estimate_verification_cost(module);
gas_meter.charge_verification_cost(estimated_verification_units)?;
```

2. **Alternative: Tighten complexity budget to account for verification:**
```rust
// Adjust complexity budget to be more conservative
let budget = 1024 + blob.code().len() * 10; // Reduced multiplier
// Add instruction-based complexity metering in check_complexity
```

3. **Hybrid approach: Pre-verification sampling:**
```rust
// Perform lightweight verification cost estimation before full verification
// Charge additional gas if estimated cost exceeds threshold
if estimated_verification_cost > VERIFICATION_COST_THRESHOLD {
    gas_meter.charge_additional_verification_cost(...)?;
}
```

4. **Enhanced complexity checking:**
Modify `check_complexity.rs` to meter regular instructions and borrow graph complexity, not just structural elements.

## Proof of Concept

While a full PoC requires crafting specific Move bytecode, the attack vector can be demonstrated conceptually:

```move
// Module with many locals and complex control flow
module publisher::expensive_verify {
    public fun complex_function() {
        let x0: u64; let x1: u64; let x2: u64; /* ... 100+ locals */
        // Many instructions with complex borrow patterns
        let r0 = &x0; let r1 = &x1;
        // Complex control flow creating large borrow graph
        if (*r0 > 0) { /* ... */ };
        // Repeat pattern 1000+ times
    }
}
```

This module would:
- Be small in size (~10KB) → Low gas charge (~420K units)
- Have few generic instantiations → Pass complexity check
- Require expensive verification due to many locals and complex borrow graph → Consume ~80M verifier units

**Notes:**

The vulnerability represents a real gas mis-pricing issue where the cost model (charging based on size) doesn't match the resource consumption model (CPU time based on verification complexity). While various limits prevent unbounded exploitation, the asymmetry remains exploitable for validator resource exhaustion attacks. This is distinct from "Network DoS" (which is out of scope) as it exploits a specific gas accounting gap in the VM layer rather than network-level flooding.

### Citations

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L246-248)
```rust
            dependency_per_byte: InternalGasPerByte,
            { RELEASE_V1_10.. => "dependency_per_byte" },
            42,
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1526-1536)
```rust
            for (module, blob) in modules.iter().zip(bundle.iter()) {
                let addr = module.self_addr();
                let name = module.self_name();
                gas_meter
                    .charge_dependency(
                        DependencyKind::New,
                        addr,
                        name,
                        NumBytes::new(blob.code().len() as u64),
                    )
                    .map_err(|err| err.finish(Location::Undefined))?;
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1556-1558)
```rust
            let budget = 2048 + blob.code().len() as u64 * 20;
            move_binary_format::check_complexity::check_module_complexity(module, budget)
                .map_err(|err| err.finish(Location::Undefined))?;
```

**File:** third_party/move/move-binary-format/src/check_complexity.rs (L302-380)
```rust
                Pop
                | Ret
                | Branch(_)
                | BrTrue(_)
                | BrFalse(_)
                | LdU8(_)
                | LdU16(_)
                | LdU32(_)
                | LdU64(_)
                | LdU128(_)
                | LdU256(_)
                | LdI8(_)
                | LdI16(_)
                | LdI32(_)
                | LdI64(_)
                | LdI128(_)
                | LdI256(_)
                | LdConst(_)
                | CastU8
                | CastU16
                | CastU32
                | CastU64
                | CastU128
                | CastU256
                | CastI8
                | CastI16
                | CastI32
                | CastI64
                | CastI128
                | CastI256
                | LdTrue
                | LdFalse
                | Call(_)
                | Pack(_)
                | Unpack(_)
                | PackVariant(_)
                | UnpackVariant(_)
                | TestVariant(_)
                | PackClosure(..)
                | ReadRef
                | WriteRef
                | FreezeRef
                | Add
                | Sub
                | Mul
                | Mod
                | Div
                | Negate
                | BitOr
                | BitAnd
                | Xor
                | Shl
                | Shr
                | Or
                | And
                | Not
                | Eq
                | Neq
                | Lt
                | Gt
                | Le
                | Ge
                | CopyLoc(_)
                | MoveLoc(_)
                | StLoc(_)
                | MutBorrowLoc(_)
                | ImmBorrowLoc(_)
                | MutBorrowField(_)
                | ImmBorrowField(_)
                | MutBorrowVariantField(_)
                | ImmBorrowVariantField(_)
                | MutBorrowGlobal(_)
                | ImmBorrowGlobal(_)
                | Exists(_)
                | MoveTo(_)
                | MoveFrom(_)
                | Abort
                | AbortMsg
                | Nop => (),
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

**File:** third_party/move/move-vm/runtime/src/storage/publishing.rs (L252-257)
```rust
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

**File:** third_party/move/move-bytecode-verifier/src/reference_safety/abstract_state.rs (L75-77)
```rust
pub(crate) const STEP_BASE_COST: u128 = 10;
pub(crate) const STEP_PER_LOCAL_COST: u128 = 20;
pub(crate) const STEP_PER_GRAPH_ITEM_COST: u128 = 50;
```

**File:** third_party/move/move-bytecode-verifier/src/reference_safety/mod.rs (L246-252)
```rust
    meter.add(Scope::Function, STEP_BASE_COST)?;
    meter.add_items(Scope::Function, STEP_PER_LOCAL_COST, state.local_count())?;
    meter.add_items(
        Scope::Function,
        STEP_PER_GRAPH_ITEM_COST,
        state.graph_size(),
    )?;
```

**File:** third_party/move/move-core/types/src/vm_status.rs (L300-301)
```rust
                    // A transaction that publishes code that cannot be verified will be charged.
                    StatusType::Verification => Ok(KeptVMStatus::MiscellaneousError),
```
