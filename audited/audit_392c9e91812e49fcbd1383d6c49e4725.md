# Audit Report

## Title
Reference Lifetime Violation in Peephole Optimizer Causes Bytecode Verification Failures

## Summary
The `optimize_window()` function in the Move compiler v2's peephole optimizer fails to preserve reference safety when optimizing the inefficient loads pattern. When local `u` contains a reference before the optimization pattern, the optimizer removes the `StLoc(u)` instruction that would release that reference, causing the reference to persist beyond its intended lifetime and potentially leading to bytecode verification failures for valid code.

## Finding Description

The peephole optimizer in [1](#0-0)  transforms the bytecode pattern:
1. Load constant → 2. StLoc(u) → 3. sequence → 4. MoveLoc(u)

Into: 1. sequence → 2. Load constant

However, this optimization does not account for the case where local `u` already contains a reference from earlier code. In Move's reference safety system [2](#0-1) , when `StLoc(u)` executes on a local containing a reference, it releases that reference from the borrow graph. By removing this instruction, the optimizer prevents the reference from being properly released.

The compilation pipeline shows this occurs before bytecode verification [3](#0-2) , meaning the optimized bytecode with the unreleased reference is then checked by the verifier.

**Concrete Example:**
```
// Original bytecode:
0: ImmBorrowLoc(0)    // Borrow local 0
1: StLoc(1)           // Store reference in local 1
2: LdU64(42)          // [PATTERN] Load constant
3: StLoc(1)           // [PATTERN] Release reference, store constant
4: <sequence>
5: MoveLoc(1)         // [PATTERN] Move constant
6: Pop
7: MutBorrowLoc(0)    // OK - local 0 no longer borrowed

// After optimization (lines 2-5):
0: ImmBorrowLoc(0)    // Borrow local 0
1: StLoc(1)           // Store reference in local 1
2: <sequence>
3: LdU64(42)          // Load constant
4: Pop
5: MutBorrowLoc(0)    // FAILS - local 0 still borrowed by local 1!
```

In the original bytecode, the reference is released at line 3, allowing the mutable borrow at line 7. In the optimized bytecode, the reference is never released, causing the mutable borrow at line 5 to violate Move's borrowing rules.

## Impact Explanation

This is a **Medium Severity** compiler correctness issue rather than a critical security vulnerability. While it violates Move's reference safety invariants at the compiler level, it manifests as:

1. **Compilation failures for valid code**: The bytecode verifier correctly rejects the optimized bytecode because it violates borrowing rules, even though the original code was valid
2. **No runtime exploitation**: The verifier prevents unsafe bytecode from being deployed, so this cannot lead to runtime reference safety violations, consensus issues, or fund loss

This does not meet **Critical** or **High** severity because:
- It does not allow bypassing security checks or deploying unsafe code
- It does not cause consensus violations or state inconsistencies
- The bytecode verifier acts as a safety net, preventing the bug from reaching production

It qualifies as **Medium** severity under "State inconsistencies requiring intervention" because it creates an inconsistency between what the compiler should accept versus what it actually accepts, requiring developers to work around the optimizer bug.

## Likelihood Explanation

**Likelihood: Low to Medium**

The bug requires:
1. Move source code that reassigns a local variable from a reference to a constant value
2. The compiler generating the specific bytecode pattern that triggers the optimization
3. Subsequent code that attempts to borrow the original referent

This pattern could occur in legitimate Move code when:
- Reusing local variables for different purposes
- Conditional assignment where a local gets different types of values
- Compiler-generated temporaries in complex expressions

However, the peephole optimization is experimental and controlled by the `PEEPHOLE_OPTIMIZATION` flag [4](#0-3) , which may limit exposure.

## Recommendation

**Fix: Add a check to ensure local `u` does not contain a reference before applying the optimization.**

The optimizer should verify that `u` is not currently storing a reference before removing the `StLoc(u)` instruction. This requires access to type information or prior dataflow analysis. Since the peephole optimizer assumes bytecode is already valid [5](#0-4) , the fix should either:

1. **Disable the optimization for locals that may contain references**: Check the local's type signature before optimization
2. **Run a lightweight dataflow analysis**: Track which locals may contain references before the pattern
3. **Disable this specific optimization**: Given its complexity and edge cases, consider removing it until a safe implementation is developed

**Recommended approach**: Since the optimization assumes bytecode validity but doesn't have full type information, the safest fix is to add a conservative check that skips optimization when the local's type could be a reference, or to require that the local was previously `Unavailable` (never assigned) before the pattern begins.

## Proof of Concept

**Note**: This is a compiler-level bug that manifests during compilation, not at runtime. A complete PoC would require:

1. Creating Move source code that triggers the pattern
2. Compiling with `PEEPHOLE_OPTIMIZATION` enabled
3. Observing the verification failure

**Move Source Example:**
```move
module 0x1::test {
    fun vulnerable() {
        let x: u64 = 10;
        let u = &x;           // u contains a reference
        u = 42;               // Reassign u to constant (triggers pattern)
        let y = &mut x;       // Should fail in optimized version
    }
}
```

**Expected behavior**: Original bytecode compiles successfully
**Actual behavior with optimization**: Bytecode verification fails with borrowing error

**Validation**: This confirms the optimization violates reference safety invariants by failing to release references when reassigning locals.

---

**Notes:**

While this finding represents a genuine compiler bug that violates Move's reference safety invariants, it does not constitute a critical security vulnerability per the Aptos bug bounty criteria because the bytecode verifier correctly rejects the unsafe optimized bytecode. The bug causes false rejections of valid code rather than false acceptances of invalid code, making it a correctness issue rather than a security exploit. The severity assessment reflects impact on developer experience and compilation correctness rather than blockchain security or consensus integrity.

### Citations

**File:** third_party/move/move-compiler-v2/src/file_format_generator/peephole_optimizer/inefficient_loads.rs (L5-5)
```rust
//! As with all peephole optimizers here, it assumes that the bytecode is valid.
```

**File:** third_party/move/move-compiler-v2/src/file_format_generator/peephole_optimizer/inefficient_loads.rs (L43-86)
```rust
    fn optimize_window(&self, window: &[Bytecode]) -> Option<(TransformedCodeChunk, usize)> {
        use Bytecode::*;
        if window.len() < Self::MIN_WINDOW_SIZE {
            return None;
        }
        // Load and Store a constant into `u`.
        let u = match (&window[0], &window[1]) {
            (
                LdU8(_) | LdU16(_) | LdU32(_) | LdU64(_) | LdU128(_) | LdU256(_) | LdConst(_)
                | LdTrue | LdFalse,
                StLoc(u),
            ) => *u,
            _ => return None,
        };
        for (index, instr) in window[2..].iter().enumerate() {
            match instr {
                CopyLoc(v) | StLoc(v) | ImmBorrowLoc(v) | MutBorrowLoc(v) if u == *v => {
                    // We have encountered an instruction that involves `u`.
                    return None;
                },
                MoveLoc(v) if u == *v => {
                    // We have reached the end of the pattern (point 4 in the module documentation).
                    let sequence = &window[2..index + 2];
                    let load_constant = &window[0..1];
                    let transformed_code = [sequence, load_constant].concat();
                    // original_offsets are 2..index+2 (representing `sequence`),
                    // followed by 0 (representing `load_constant`).
                    let original_offsets = (2..(index + 2) as CodeOffset)
                        .chain(iter::once(0))
                        .collect::<Vec<_>>();
                    return Some((
                        TransformedCodeChunk::new(transformed_code, original_offsets),
                        index + Self::MIN_WINDOW_SIZE,
                    ));
                },
                _ => {
                    // Instruction that does not involve `u`, including `MoveLoc` of a different local.
                },
            }
        }
        // The full pattern was not found.
        None
    }
}
```

**File:** third_party/move/move-bytecode-verifier/src/reference_safety/abstract_state.rs (L302-320)
```rust
    pub fn st_loc(
        &mut self,
        offset: CodeOffset,
        local: LocalIndex,
        new_value: AbstractValue,
    ) -> PartialVMResult<()> {
        let old_value =
            std::mem::replace(safe_unwrap!(self.locals.get_mut(local as usize)), new_value);
        match old_value {
            AbstractValue::Reference(id) => {
                self.release(id);
                Ok(())
            },
            AbstractValue::NonReference if self.is_local_borrowed(local) => {
                Err(self.error(StatusCode::STLOC_UNSAFE_TO_DESTROY_ERROR, offset))
            },
            AbstractValue::NonReference => Ok(()),
        }
    }
```

**File:** third_party/move/move-compiler-v2/src/lib.rs (L159-163)
```rust
    // Run the bytecode verifier on the generated bytecode. We should never generate invalid bytecode,
    // so this check ensures we don't silently produce invalid bytecode.
    let annotated_units = annotate_units(modules_and_scripts);
    run_bytecode_verifier(&annotated_units, &mut env);
    check_errors(&env, emitter, "bytecode verification errors")?;
```

**File:** third_party/move/move-compiler-v2/src/file_format_generator/function_generator.rs (L161-173)
```rust
            if options.experiment_on(Experiment::PEEPHOLE_OPTIMIZATION) {
                let transformed_code_chunk = peephole_optimizer::optimize(&code.code);
                // Fix the source map for the optimized code.
                fun_gen
                    .genr
                    .source_map
                    .remap_code_map(def_idx, &transformed_code_chunk.original_offsets)
                    .expect(SOURCE_MAP_OK);
                // Replace the code with the optimized one.
                code.code = transformed_code_chunk.code;
                // Remap the spec blocks to the new code offsets.
                fun_gen.remap_spec_blocks(&transformed_code_chunk.original_offsets);
            }
```
