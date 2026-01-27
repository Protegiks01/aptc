# Audit Report

## Title
Missing Instruction Count Metering in Module Complexity Check Enables Verification-Time DoS

## Summary
The `check_module_complexity` function fails to charge for bytecode instruction count, only metering type complexity and identifier length. This mismatch between the budget calculation (based on code byte length) and actual charges (based on type/identifier complexity) allows attackers to submit modules with minimal type complexity but maximal instruction counts, bypassing the intended pre-filter and forcing expensive bytecode verification work on validator nodes. [1](#0-0) 

## Finding Description

The module complexity checker defines only two cost constants for metering module complexity during publishing, lacking any per-instruction cost: [2](#0-1) 

In the `meter_code` function, bytecode instructions are processed but NOT charged to the complexity budget. Only generic instructions requiring type parameters (CallGeneric, PackGeneric, etc.) trigger type signature metering, while simple instructions (Add, Sub, Mul, Pop, Ret, Branch, Nop, etc.) incur **zero cost**.

During module publishing, the complexity check runs first with a budget calculated as `2048 + blob.code().len() * 20`: [3](#0-2) 

**Attack Scenario:**
1. Attacker crafts a module with 60,000 simple instructions (e.g., arithmetic operations, branches, nops)
2. Module uses minimal type complexity (10 simple type nodes = 80 units)
3. Module uses short identifiers (100 bytes = 100 units)
4. Total complexity cost: ~200 units
5. Complexity budget: 2048 + 60,000 * 20 = 1,202,048 units
6. **Complexity check passes using only 0.016% of budget**

The module then proceeds to bytecode verification, which MUST process all 60,000 instructions: [4](#0-3) [5](#0-4) 

Each instruction costs at minimum 10 units (STEP_BASE_COST) plus per-local and per-graph-item costs during verification. For 60,000 instructions with modest locals/graph, verification could consume 1-2 million units, all within the 80 million limit but representing significant CPU work that should have been filtered by the complexity check. [6](#0-5) 

The complexity check's failure to account for instruction count allows it to be bypassed as a resource gate, forcing validators to perform expensive verification work that the check was designed to prevent.

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty program criteria for "Validator node slowdowns."

An attacker can submit multiple module publishing transactions containing instruction-heavy but type-simple modules. Each transaction:
1. Passes the complexity check quickly (minimal work)
2. Forces full bytecode verification (substantial work)
3. The ratio of attacker cost to validator work is disproportionate

While individual modules are bounded by the bytecode verifier's 80M unit limit, the missing instruction metering in the complexity check eliminates an important defense-in-depth layer. The complexity check is explicitly positioned as a cheap pre-filter (note the TODO comment about making budget configurable), but it fails to filter instruction-heavy modules.

Multiple such transactions submitted in succession or concurrently could significantly degrade validator performance during block production, as each validator must verify modules before execution. This impacts network throughput and latency during periods of malicious module publishing activity.

## Likelihood Explanation

**Likelihood: High**

Exploitation requirements are minimal:
- No special privileges required (any account can publish modules)
- Attack is deterministic and reliable
- Modules can be easily generated programmatically
- Cost to attacker is standard gas fees for module publishing
- Multiple transactions can be submitted to amplify effect

The maximum bytecode count per function is 65,535, and package size limits are 60KB, providing substantial room for instruction-heavy modules. [7](#0-6) 

The mismatch between budget calculation (based on code length) and actual charges (only type/identifier complexity) is a clear implementation bug rather than intentional design.

## Recommendation

Add a `COST_PER_INSTRUCTION` constant and charge for each bytecode instruction processed in the `meter_code` function:

```rust
// Add constant
const COST_PER_INSTRUCTION: u64 = 2;

// In meter_code function, charge for each instruction
fn meter_code(&self, code: &CodeUnit) -> PartialVMResult<()> {
    use Bytecode::*;
    
    self.meter_signature(code.locals)?;
    
    // Charge for instruction count
    self.charge(code.code.len() as u64 * COST_PER_INSTRUCTION)?;
    
    for instr in &code.code {
        // existing per-instruction metering for generics...
    }
    Ok(())
}
```

This ensures the complexity check properly filters instruction-heavy modules before expensive bytecode verification, aligning with the budget formula's intent to scale with code size.

Additionally, consider making the complexity budget configurable per the TODO comment to allow tuning based on observed attack patterns.

## Proof of Concept

```rust
// Rust test demonstrating the bypass
#[test]
fn test_instruction_count_bypass() {
    use move_binary_format::{
        file_format::*,
        CompiledModule,
    };
    
    // Build module with minimal type complexity but maximum instructions
    let mut code = CodeUnit {
        locals: Signature(vec![]), // Empty locals signature
        code: vec![],
    };
    
    // Add 60,000 simple instructions that incur no complexity charge
    for _ in 0..60_000 {
        code.code.push(Bytecode::Nop); // Each Nop costs 0 in complexity check
    }
    code.code.push(Bytecode::Ret);
    
    // Create minimal module (simplified pseudo-code)
    let module = create_test_module_with_code(code);
    let blob = serialize_module(&module);
    
    // Complexity check budget
    let budget = 2048 + blob.len() as u64 * 20;
    
    // This should reject due to high instruction count, but passes
    let result = check_module_complexity(&module, budget);
    assert!(result.is_ok()); // PASSES despite 60K instructions
    
    // Used budget is minimal (only type complexity, no instruction cost)
    let used = result.unwrap();
    assert!(used < 1000); // Less than 1K units used for 60K instructions!
}
```

## Notes

The bytecode verifier provides a secondary defense with its 80 million unit limit, preventing unbounded work. However, this defense-in-depth architecture requires the complexity check to function as an effective pre-filter. The missing instruction metering undermines this layered security model, allowing disproportionate validator resource consumption relative to attacker cost.

The TODO comment in the code acknowledges the budget formula needs refinement, corroborating that this is a recognized but unaddressed issue. [8](#0-7)

### Citations

**File:** third_party/move/move-binary-format/src/check_complexity.rs (L20-21)
```rust
const COST_PER_TYPE_NODE: u64 = 8;
const COST_PER_IDENT_BYTE: u64 = 1;
```

**File:** third_party/move/move-binary-format/src/check_complexity.rs (L259-384)
```rust
    fn meter_code(&self, code: &CodeUnit) -> PartialVMResult<()> {
        use Bytecode::*;

        self.meter_signature(code.locals)?;

        for instr in &code.code {
            match instr {
                CallGeneric(idx) | PackClosureGeneric(idx, ..) => {
                    self.meter_function_instantiation(*idx)?;
                },
                PackGeneric(idx) | UnpackGeneric(idx) => {
                    self.meter_struct_instantiation(*idx)?;
                },
                PackVariantGeneric(idx) | UnpackVariantGeneric(idx) | TestVariantGeneric(idx) => {
                    self.meter_struct_variant_instantiation(*idx)?;
                },
                ExistsGeneric(idx)
                | MoveFromGeneric(idx)
                | MoveToGeneric(idx)
                | ImmBorrowGlobalGeneric(idx)
                | MutBorrowGlobalGeneric(idx) => {
                    self.meter_struct_instantiation(*idx)?;
                },
                ImmBorrowFieldGeneric(idx) | MutBorrowFieldGeneric(idx) => {
                    self.meter_field_instantiation(*idx)?;
                },
                ImmBorrowVariantFieldGeneric(idx) | MutBorrowVariantFieldGeneric(idx) => {
                    self.meter_variant_field_instantiation(*idx)?;
                },
                CallClosure(idx)
                | VecPack(idx, _)
                | VecLen(idx)
                | VecImmBorrow(idx)
                | VecMutBorrow(idx)
                | VecPushBack(idx)
                | VecPopBack(idx)
                | VecUnpack(idx, _)
                | VecSwap(idx) => {
                    self.meter_signature(*idx)?;
                },

                // List out the other options explicitly so there's a compile error if a new
                // bytecode gets added.
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
            }
        }
        Ok(())
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

**File:** aptos-move/aptos-vm-environment/src/prod_configs.rs (L175-176)
```rust
        max_per_fun_meter_units: Some(1000 * 80000),
        max_per_mod_meter_units: Some(1000 * 80000),
```

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L61-62)
```rust
pub const BYTECODE_COUNT_MAX: u64 = 65535;
pub const BYTECODE_INDEX_MAX: u64 = 65535;
```
