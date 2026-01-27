Let me investigate the AST representation more carefully to understand when Sequences vs Blocks are used:
> Searching codebase... [1](#0-0)

### Citations

**File:** third_party/move/move-compiler-v2/src/env_pipeline/spec_rewriter.rs (L524-553)
```rust
                Sequence(id, exps) => {
                    // Remove aborts, units, and spec blocks
                    let mut reduced_exps = exps
                        .iter()
                        .take(exps.len() - 1)
                        .flat_map(|e| {
                            if matches!(
                                e.as_ref(),
                                SpecBlock(..) | Call(_, Abort(_), _) | Call(_, Tuple, _)
                            ) {
                                None
                            } else {
                                Some(e.clone())
                            }
                        })
                        .collect_vec();
                    reduced_exps.push(exps.last().unwrap().clone());
                    if reduced_exps.len() != exps.len() {
                        if reduced_exps.len() == 1 {
                            reduced_exps.pop().unwrap()
                        } else {
                            self.contains_imperative_expression = true;
                            Sequence(*id, reduced_exps).into_exp()
                        }
                    } else {
                        if reduced_exps.len() != 1 {
                            self.contains_imperative_expression = true;
                        }
                        exp.clone()
                    }
```
