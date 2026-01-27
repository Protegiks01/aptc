# Audit Report

## Title
Copy-Paste Error in Loop Unrolling Branch Label Remapping Causes Incorrect Control Flow in Move Prover

## Summary
The `unroll()` function in the Move Prover's loop analysis contains a copy-paste error at line 433 that incorrectly checks `then_label` instead of `else_label` when remapping branch back-edges during loop unrolling, resulting in incorrect control flow in the unrolled loop representation used for formal verification.

## Finding Description
The Move Prover performs bounded loop verification through loop unrolling, transforming loops into a directed acyclic graph for formal analysis. During the unrolling process, branch instructions with back-edges to the loop header must be remapped so that each iteration's back-edge points to the next iteration. [1](#0-0) 

At line 433, when processing the `else_label` of a branch instruction, the code incorrectly checks `if then_label == loop_header` instead of `if else_label == loop_header`. This is a copy-paste error from the `then_label` processing block above it.

**Trigger Condition:** The bug manifests when a loop contains a `Branch` bytecode instruction where:
- The `else_label` is a back-edge pointing to the loop header
- The `then_label` points elsewhere (not to the loop header)

**Incorrect Behavior:** Due to the wrong condition, when `else_label == loop_header` but `then_label != loop_header`, the `else_label` gets remapped to iteration `i` instead of iteration `i+1`. This creates a self-loop within a single iteration rather than a proper back-edge to the next iteration.

**Comparison with Correct Implementation:** The same logic appears correctly implemented at lines 458-464 for bridging back-edges: [2](#0-1) 

This shows the correct pattern: if-else structure with proper checks for each label.

## Impact Explanation

**Classification: Low Severity (Not Meeting Medium Criteria)**

While this is a genuine implementation bug, it does NOT meet the Aptos Bug Bounty Medium severity criteria for the following reasons:

1. **Off-Chain Tool:** The Move Prover is a formal verification tool that runs off-chain on developer machines, not part of the on-chain execution engine. It does not directly affect consensus, state transitions, or transaction execution.

2. **No Direct Exploit Path:** An attacker cannot directly exploit this bug. It only affects developers who:
   - Use loop unrolling pragmas for verification
   - Have loops with the specific branch pattern described
   - Rely on the prover's verification results

3. **Indirect Impact Only:** Even if the prover produces incorrect verification results, this does not automatically lead to exploitable vulnerabilities on-chain. The deployed bytecode still executes correctly in the Move VM - only the verification is affected.

4. **No Critical Invariant Violation:** This bug does not violate any of the critical blockchain invariants listed (deterministic execution, consensus safety, Move VM safety, etc.). The actual execution environment is unaffected.

According to the Aptos Bug Bounty criteria:
- **Medium Severity** requires: "Limited funds loss or manipulation" or "State inconsistencies requiring intervention"
- This bug causes neither - it only affects off-chain verification quality

## Likelihood Explanation

**Likelihood: Low**

The bug triggers only under specific conditions:
1. Developer must use `pragma unroll` or inline `[unroll = N]` syntax
2. Loop must contain branch instructions with else-branch back-edges
3. Move compiler must generate `Branch(_, non_header_label, loop_header, _)` pattern
4. Developer must rely on prover verification without additional testing

Most Move loops use simpler control flow patterns where both branches are handled consistently. The bug would likely manifest as prover timeouts or obvious verification failures rather than subtle false negatives.

## Recommendation

Fix the copy-paste error by changing the condition at line 433:

**Current (Buggy):**
```rust
if in_loop_labels.contains(else_label) {
    if then_label == loop_header {  // WRONG: should check else_label
        *else_label = *label_remapping.get(&(*else_label, i + 1)).unwrap();
    } else {
        *else_label = *label_remapping.get(&(*else_label, i)).unwrap();
    }
}
```

**Fixed:**
```rust
if in_loop_labels.contains(else_label) {
    if else_label == loop_header {  // CORRECT: check else_label
        *else_label = *label_remapping.get(&(*else_label, i + 1)).unwrap();
    } else {
        *else_label = *label_remapping.get(&(*else_label, i)).unwrap();
    }
}
```

## Proof of Concept

This bug can be demonstrated with a Move module containing a loop where the branch's else-edge is the back-edge:

```move
module 0x42::branch_backedge {
    fun test_loop(n: u64): u64 {
        let i = 0;
        while (i < n) {
            // Complex condition that might generate Branch with else-back-edge
            if (i % 2 == 0) {
                i = i + 1;
                // then-branch: continues to next iteration
            }
            // implicit else falls through to loop condition check
        };
        i
    }
    spec test_loop {
        pragma unroll = 4;
        ensures result == n;
    }
}
```

Running the prover with this code and examining the generated unrolled bytecode would reveal incorrect label remapping for the branch's else-label, causing the unrolled structure to have self-loops instead of proper iteration progression.

---

## Notes

**This is a real bug in the codebase, but it does NOT qualify as a valid security vulnerability** under the strict Aptos Bug Bounty criteria because:

- It affects an **off-chain verification tool**, not the on-chain execution or consensus layers
- It has **no direct exploitation path** for attackers
- It does **not violate any critical blockchain invariants**
- The impact is limited to **verification quality**, not actual execution safety

While this should be fixed to improve the Move Prover's correctness, it does not represent an exploitable security vulnerability in the Aptos blockchain itself.

### Citations

**File:** third_party/move/move-prover/bytecode-pipeline/src/loop_analysis.rs (L424-438)
```rust
                    Bytecode::Branch(_, then_label, else_label, _) => {
                        if in_loop_labels.contains(then_label) {
                            if then_label == loop_header {
                                *then_label = *label_remapping.get(&(*then_label, i + 1)).unwrap();
                            } else {
                                *then_label = *label_remapping.get(&(*then_label, i)).unwrap();
                            }
                        }
                        if in_loop_labels.contains(else_label) {
                            if then_label == loop_header {
                                *else_label = *label_remapping.get(&(*else_label, i + 1)).unwrap();
                            } else {
                                *else_label = *label_remapping.get(&(*else_label, i)).unwrap();
                            }
                        }
```

**File:** third_party/move/move-prover/bytecode-pipeline/src/loop_analysis.rs (L458-464)
```rust
                    Bytecode::Branch(_, then_label, else_label, _) => {
                        if then_label == loop_header {
                            *then_label = *label_remapping.get(&(*then_label, 0)).unwrap();
                        } else {
                            assert_eq!(else_label, loop_header);
                            *else_label = *label_remapping.get(&(*else_label, 0)).unwrap();
                        }
```
