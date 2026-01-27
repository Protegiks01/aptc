# Audit Report

## Title
Binary Complexity Check Bypass via Non-Generic Instruction Sequences

## Summary
The `meter_code()` function in `check_complexity.rs` only meters generic bytecode variants for their type instantiations, while non-generic instructions are not charged at all. This allows an attacker to create modules with massive instruction sequences that bypass the binary complexity budget, potentially causing verification resource exhaustion during module publication.

## Finding Description

The binary complexity checking system is designed to prevent resource exhaustion during module verification by limiting the complexity of published modules based on their code size. The budget is calculated as `2048 + blob.code().len() * 20`. [1](#0-0) 

However, in the `meter_code()` function, only generic bytecode instructions (CallGeneric, PackGeneric, etc.) are metered for their instantiations: [2](#0-1) 

Non-generic instructions, which include arithmetic operations, branches, local operations, field accesses, and global operations, perform no metering at all: [3](#0-2) 

An attacker can exploit this by creating a function with up to 65,534 non-generic instructions (the maximum allowed by `BYTECODE_COUNT_MAX`): [4](#0-3) 

These instructions will all fit within a single basic block (bypassing the `max_basic_blocks: 1024` limit in production config): [5](#0-4) 

During verification, all instructions must be processed by multiple verification passes including type safety, stack usage, and reference safety checks: [6](#0-5) 

## Impact Explanation

This vulnerability allows an attacker to bypass the intended resource limits during module publication. While the verifier metering system (`max_per_fun_meter_units`) provides a backup defense: [7](#0-6) 

The binary complexity check becomes ineffective for its stated purpose - preventing resource exhaustion based on code complexity. This represents a **High Severity** issue as it can cause validator node slowdowns during module publication, matching the Aptos bug bounty criteria for significant protocol violations.

All validators must verify published modules, so a malicious module with maximum non-generic instructions would force all nodes to perform expensive verification while consuming minimal complexity budget.

## Likelihood Explanation

This vulnerability is highly likely to be exploitable because:
1. Any user can publish modules to the blockchain
2. Creating a module with maximum non-generic instructions is straightforward
3. The attack requires no special privileges or validator access
4. The binary complexity check is performed on every module publication
5. The verification cost scales linearly with instruction count

## Recommendation

Modify the `meter_code()` function to charge for ALL bytecode instructions, not just generic ones. Each non-generic instruction should consume at least a minimal amount from the complexity budget to ensure the budget accurately reflects verification cost:

```rust
fn meter_code(&self, code: &CodeUnit) -> PartialVMResult<()> {
    use Bytecode::*;
    
    self.meter_signature(code.locals)?;
    
    for instr in &code.code {
        // Charge a base cost for every instruction
        self.charge(COST_PER_INSTRUCTION)?;
        
        match instr {
            // ... existing generic instruction metering ...
            
            // Non-generic instructions should still charge base cost
            Call(_) | Pack(_) | Unpack(_) | ... => {
                // Base cost already charged above
            }
            _ => ()
        }
    }
    Ok(())
}
```

Where `COST_PER_INSTRUCTION` would be a constant (e.g., 1-5 units per instruction) to ensure that instruction count is reflected in the complexity budget.

## Proof of Concept

```move
// malicious_module.move
module 0x1::resource_exhaustion {
    public fun exhaust_verification() {
        let x: u64 = 0;
        // Repeat this block ~16,000 times to reach near-maximum instruction count
        x = x + 1; x = x + 1; x = x + 1; x = x + 1;
        x = x - 1; x = x - 1; x = x - 1; x = x - 1;
        x = x * 2; x = x * 2; x = x * 2; x = x * 2;
        // ... (repeat many times) ...
    }
}
```

This module would:
1. Pass binary complexity check (non-generic instructions consume 0 budget)
2. Contain ~65,000 arithmetic instructions in a single basic block
3. Force all validators to verify all instructions
4. Cause verification slowdown during module publication

**Notes**

The vulnerability exists because the binary complexity checking system has a fundamental design flaw: it bases the budget on code size but fails to charge for most of the code (non-generic instructions). While the verifier metering system provides some protection, it uses completely different limits and was not designed to be the primary defense against code size attacks. The binary complexity check was specifically introduced to prevent this type of resource exhaustion, but it only works for generic instructions.

### Citations

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1556-1558)
```rust
            let budget = 2048 + blob.code().len() as u64 * 20;
            move_binary_format::check_complexity::check_module_complexity(module, budget)
                .map_err(|err| err.finish(Location::Undefined))?;
```

**File:** third_party/move/move-binary-format/src/check_complexity.rs (L266-298)
```rust
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
```

**File:** third_party/move/move-binary-format/src/check_complexity.rs (L300-380)
```rust
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
```

**File:** third_party/move/move-binary-format/src/file_format_common.rs (L61-61)
```rust
pub const BYTECODE_COUNT_MAX: u64 = 65535;
```

**File:** third_party/move/move-bytecode-verifier/src/verifier.rs (L292-292)
```rust
            max_basic_blocks: Some(1024),
```

**File:** third_party/move/move-bytecode-verifier/src/verifier.rs (L307-308)
```rust
            max_per_fun_meter_units: Some(1000 * 8000),
            max_per_mod_meter_units: Some(1000 * 8000),
```

**File:** third_party/move/move-bytecode-verifier/src/code_unit_verifier.rs (L184-192)
```rust
        StackUsageVerifier::verify(verifier_config, &self.resolver, &self.function_view, meter)?;
        type_safety::verify(&self.resolver, &self.function_view, meter)?;
        locals_safety::verify(&self.resolver, &self.function_view, meter)?;
        reference_safety::verify(
            &self.resolver,
            &self.function_view,
            self.name_def_map,
            meter,
        )
```
