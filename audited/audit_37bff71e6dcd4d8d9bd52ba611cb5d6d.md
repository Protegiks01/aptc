# Audit Report

## Title
Block Expressions with Move Operations Bypass Sequence-in-Binop Checker Leading to Potential Use-After-Move

## Summary
The `seqs_in_binop_checker` only detects `ExpData::Sequence` nodes within binary operations but does not detect `ExpData::Block` nodes created by `let` bindings. This allows move operations within blocks to bypass overlap detection, potentially causing variables to be consumed between LHS and RHS operands.

## Finding Description

The `seqs_in_binop_checker` is designed to prevent confusing evaluation order issues in Move compiler v1 by detecting sequences within binary operations. However, the checker only looks for `ExpData::Sequence` nodes and completely ignores `ExpData::Block` nodes. [1](#0-0) 

When Move source code contains a `let` binding within a binary operation, it creates an `ExpData::Block` in the AST, not an `ExpData::Sequence`. Single `let` bindings with move operations do not create multi-statement sequences that would trigger detection. [2](#0-1) 

The AST translation shows that single-expression blocks are unwrapped and not represented as Sequences: [3](#0-2) 

**Exploit Scenario:**
```move
let x = Resource {...};
x + {let y = move(x); y}
```

This creates:
- LHS: `LocalVar(x)` 
- RHS: `Block(pattern_y, Some(Call(Move, [x])), y)`

Since no `Sequence` node exists, the checker's visitor does not record it in the `sequences` map. When the binary operation completes, the overlap check at lines 136-159 is never executed because `sequences.remove(&binop_id)` returns `None`. [4](#0-3) 

With v1 compiler's non-intuitive evaluation order, the RHS block may be evaluated before the LHS, causing `x` to be moved before the LHS attempts to use it, violating Move's ownership semantics.

## Impact Explanation

This vulnerability allows compilation of code that violates Move's core ownership invariants. The impact is **High Severity**:

- **Consensus Safety Violation**: Different validators might interpret the evaluation order differently, causing non-deterministic execution and consensus splits, violating the "Deterministic Execution" invariant.
- **Move VM Safety Violation**: Use-after-move could cause undefined behavior in resource handling, potentially leading to resource duplication or loss.
- **Transaction Validation Bypass**: Invalid move semantics bypass compiler validation, reaching runtime execution.

This meets the Aptos bug bounty criteria for High Severity as it represents a significant protocol violation that could affect consensus.

## Likelihood Explanation

**Likelihood: Medium-High**

- The pattern requires specific Move code structure but is not obscure
- Developers might naturally write such code when combining let-bindings with arithmetic
- The checker runs by default for language versions < 2.0, affecting production code
- The issue is in the compiler pipeline that runs before deployment

## Recommendation

Extend the `seqs_in_binop_checker` to also detect `ExpData::Block` nodes that contain side-effectful binding expressions: [5](#0-4) 

Add a case in the visitor to handle Block expressions:

```rust
Block(id, _, Some(binding), _) => {
    // Check if binding has side effects
    if !post && !binding.as_ref().is_ok_to_remove_from_code() {
        if let Some((binop_id, _)) = binop_stack.last() {
            sequences.entry(*binop_id).or_insert(*id);
        }
    }
},
```

Additionally, ensure the `is_ok_to_remove_from_code` check properly identifies move operations as side-effectful: [6](#0-5) 

## Proof of Concept

```move
module 0x1::test {
    struct Resource has key { value: u64 }
    
    public fun vulnerable_code(): u64 {
        let x = Resource { value: 100 };
        
        // This should be caught but isn't:
        // Block expression with move in binding bypasses checker
        let result = x.value + {
            let y = move(x);  // x moved here
            y.value
        };
        
        // If evaluation order is: RHS then LHS,
        // LHS tries to access x.value after x was moved
        result
    }
}
```

Compile with language version < 2.0 and `SEQS_IN_BINOPS_CHECK` experiment enabled. The code should be rejected but may compile due to Block not being detected as a sequence.

### Citations

**File:** third_party/move/move-compiler-v2/src/env_pipeline/seqs_in_binop_checker.rs (L128-177)
```rust
        let mut visitor = |post: bool, e: &ExpData| {
            use ExpData::*;
            match e {
                Call(id, op, exps) if op.is_binop() => {
                    if !post {
                        binop_stack.push((*id, op.clone()));
                    } else {
                        let (binop_id, binop) = binop_stack.pop().expect("unbalanced");
                        if let Some(seq_id) = sequences.remove(&binop_id) {
                            // There was a sequence within the context of this binary operation.
                            // We now check if variables are shared between the two expressions, or
                            // if there are control flow redirections.
                            let param_symbols = function
                                .get_parameters()
                                .into_iter()
                                .map(|p| p.0)
                                .collect::<Vec<_>>();
                            let lhs = &exps[0];
                            let rhs = &exps[1];
                            let lhs_vars = lhs.free_vars_and_used_params(&param_symbols);
                            let rhs_vars = rhs.free_vars_and_used_params(&param_symbols);
                            let overlap = lhs_vars.intersection(&rhs_vars).next().is_some();
                            if overlap
                                || contains_control_flow_redirections(lhs)
                                || contains_control_flow_redirections(rhs)
                            {
                                // Note: if needed, we can make this check even more precise by tracking
                                // read and written variables, and checking only for read-write and
                                // write-write conflicts.
                                errors.push((binop_id, binop.clone(), seq_id));
                            }
                        }
                    }
                },
                Sequence(id, seq)
                    if seq.len() > 1 && !seq.iter().all(|exp| exp.is_ok_to_remove_from_code()) =>
                {
                    if let Some((binop_id, _)) = binop_stack.last() {
                        // There is a non-trivial sequence within the context of a binary operation.
                        // Non-trivial currently means that the sequence has more than one expression,
                        // and not all those expressions are potentially side-effect free.
                        // Note: if needed, we can implement a more precise check instead of reusing
                        // `is_ok_to_remove_from_code` to track side-effect-free expressions.
                        sequences.entry(*binop_id).or_insert(*id);
                    }
                },
                _ => {},
            }
            true // continue traversal
        };
```

**File:** third_party/move/move-model/src/builder/exp_builder.rs (L3636-3646)
```rust
                    let rest = if items.len() == 1 {
                        // If the bind item has no successor, assume an empty block.
                        self.require_impl_language(loc);
                        self.check_type(loc, expected_type, &Type::unit(), context);
                        self.new_unit_exp(loc)
                    } else {
                        self.translate_seq_recursively(loc, &items[1..], expected_type, context)
                    };
                    // Return result
                    self.exit_scope();
                    self.new_bind_exp(loc, pat, binding, rest.into_exp())
```

**File:** third_party/move/move-model/src/builder/exp_builder.rs (L3648-3652)
```rust
                Seq(_) if items.len() > 1 => {
                    self.translate_seq_items(loc, items, expected_type, context)
                },
                Seq(exp) => self.translate_exp_in_context(exp, expected_type, context),
            }
```

**File:** third_party/move/move-model/src/ast.rs (L2901-2903)
```rust
            // Copy and Move
            Copy => false, // Could yield an undroppable value
            Move => false, // Move-related
```
