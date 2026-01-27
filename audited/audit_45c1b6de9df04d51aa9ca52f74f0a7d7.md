# Audit Report

## Title
Included Schema Let Bindings Can Silently Override Local Let Bindings in Move Specifications

## Summary
The `def_ana_spec_block()` function in the Move model builder sorts spec block members to process local `let` bindings before schema `include` statements. However, when schemas are included, their `let` bindings are added without checking for name conflicts with local `let` bindings. During specification translation, the later schema `let` silently overwrites the local `let` in the symbol resolution map, causing all references to resolve to the schema's definition instead of the intended local definition.

## Finding Description
The vulnerability exists in how the Move specification language handles `let` bindings when schemas are included into spec blocks. [1](#0-0) 

The code sorts spec block members to process `Let` members before `Include` members, with a comment claiming this is "needed so that lets included from schemas are properly renamed on name clash." However, no such renaming logic exists. [2](#0-1) 

When a local `let` is processed via `def_ana_let()`, it checks for duplicate local `let` bindings and adds the binding to `spec_block_lets`. However, when a schema is included: [3](#0-2) 

The schema's conditions (including `let` bindings) are expanded and added to the spec without checking against `spec_block_lets`: [4](#0-3) 

During specification translation, the `translate_lets()` function processes all `let` conditions and inserts them into the `let_locals` map: [5](#0-4) 

Since `BTreeMap::insert()` overwrites previous values with the same key, an included schema's `let` binding will silently override a local `let` binding with the same name. All subsequent references to that name will resolve to the schema's definition: [6](#0-5) 

**Attack Scenario:**
1. A developer writes a function spec with a local `let` binding defining a critical property
2. The spec includes a schema that also defines a `let` with the same name
3. No error is reported during compilation
4. The schema's `let` silently overrides the local `let`
5. All conditions using that `let` name now reference the schema's definition
6. Formal verification proceeds with incorrect specifications
7. Critical properties may be unverified or incorrectly verified

## Impact Explanation
This is a **Low Severity** issue per the Aptos bug bounty program criteria. While it doesn't directly cause runtime vulnerabilities or consensus issues, it affects the correctness of formal verification:

- **Specification Correctness**: Developers' intended specifications are silently altered, leading to incorrect formal verification results
- **Verification Reliability**: The Move Prover may produce false positives (failing verification that should pass) or false negatives (passing verification that should fail)
- **Security Assurance**: Critical security properties defined in local `let` bindings may be replaced by weaker or incorrect properties from included schemas
- **No Runtime Impact**: Since specifications are not executed by the Move VM, this does not affect blockchain consensus or transaction execution

This falls under "Non-critical implementation bugs" in the Low Severity category, as it affects development tooling and verification correctness rather than runtime security.

## Likelihood Explanation
The likelihood is **MEDIUM** given:

- **Common Pattern**: Using both local `let` bindings and schema includes is a standard practice in Move specifications
- **No Warning**: The compiler provides no warning when name conflicts occur
- **Deceptive Comment**: The code comment suggests renaming happens, which may mislead developers into thinking this is safe
- **Easy to Trigger**: Any spec with a local `let` and schema include using the same name will trigger this issue
- **Hard to Detect**: The bug is silent and verification may still complete without obvious errors

## Recommendation
Add validation to detect and report name conflicts between local `let` bindings and included schema `let` bindings:

```rust
// In def_ana_schema_exp_leaf, after line 3138, before adding conditions:
match kind {
    ConditionKind::LetPost(name, let_loc) | ConditionKind::LetPre(name, let_loc) => {
        // Check if this let conflicts with a local let already in the spec block
        if let Some((_, local_node_id)) = self.spec_block_lets.get(name) {
            let local_loc = self.parent.env.get_node_loc(*local_node_id);
            self.parent.env.error_with_labels(
                let_loc,
                &format!(
                    "let binding `{}` from included schema conflicts with local let",
                    name.display(self.symbol_pool())
                ),
                vec![(local_loc, "local let defined here".to_string())],
            );
            continue; // Skip adding this conflicting let
        }
    },
    _ => {},
}
```

Alternatively, implement the renaming logic suggested by the comment at line 1513, automatically renaming conflicting schema `let` bindings to unique names.

## Proof of Concept
Create a Move module with specifications demonstrating the issue:

```move
spec schema TestSchema {
    let x = 100;  // Schema defines let x
    ensures result == x;
}

spec fun test(): u64 {
    let x = 42;  // Local let x should take precedence
    include TestSchema;
    ensures result == x;  // Expected: 42, Actual: 100 (schema's x)
}
```

The spec will compile without error, but `x` in the final `ensures` clause will resolve to the schema's definition (100) instead of the local definition (42), causing incorrect verification behavior.

To verify the bug exists, examine the generated verification conditions - they will show that `result == 100` is being checked instead of `result == 42`, proving the local `let` was silently overridden.

### Citations

**File:** third_party/move/move-model/src/builder/module_builder.rs (L1506-1530)
```rust
    fn def_ana_spec_block(&mut self, context: &SpecBlockContext, block: &EA::SpecBlock) {
        let block_loc = self.parent.env.to_loc(&block.loc);
        self.update_spec(context, move |spec| spec.loc = Some(block_loc));

        assert!(self.spec_block_lets.is_empty());

        // Sort members so that lets are processed first. This is needed so that lets included
        // from schemas are properly renamed on name clash.
        let let_sorted_members = block.value.members.iter().sorted_by(|m1, m2| {
            let m1_is_let = matches!(m1.value, EA::SpecBlockMember_::Let { .. });
            let m2_is_let = matches!(m2.value, EA::SpecBlockMember_::Let { .. });
            match (m1_is_let, m2_is_let) {
                (true, true) | (false, false) => std::cmp::Ordering::Equal,
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
            }
        });

        for member in let_sorted_members {
            self.def_ana_spec_block_member(context, member)
        }

        // clear the let bindings stored in the build.
        self.spec_block_lets.clear();
    }
```

**File:** third_party/move/move-model/src/builder/module_builder.rs (L1568-1571)
```rust
            Include { properties, exp } => {
                let properties = self.translate_properties(properties, &|_, _, _| None);
                self.def_ana_schema_inclusion_outside_schema(loc, context, None, properties, exp)
            },
```

**File:** third_party/move/move-model/src/builder/module_builder.rs (L1595-1642)
```rust
    fn def_ana_let(
        &mut self,
        context: &SpecBlockContext,
        loc: &Loc,
        post_state: bool,
        name: &Name,
        def: &EA::Exp,
    ) {
        // Check the expression and extract results.
        let sym = self.symbol_pool().make(&name.value);
        let kind = if post_state {
            ConditionKind::LetPost(sym, loc.clone())
        } else {
            ConditionKind::LetPre(sym, loc.clone())
        };
        let mut et = self.exp_translator_for_context(loc, context, &kind);
        let (_, def) = et.translate_exp_free(def);
        // Need to acquire type information to be able to resolve receiver-style functions.
        et.finalize_types(false);
        // Post-process to resolve placeholders including receiver-style function calls.
        let desugared_exp = et.post_process_body(def.into_exp());
        // Run type inference again with proper error reporting.
        et.finalize_types(true);

        // Check whether a let of this name is already defined, and add it to the
        // map which tracks lets in this block.
        if self
            .spec_block_lets
            .insert(sym, (post_state, desugared_exp.node_id()))
            .is_some()
        {
            self.parent.error(
                &self.parent.to_loc(&name.loc),
                &format!("duplicate declaration of `{}`", name.value),
            );
        }

        // Add the let to the context spec.
        self.update_spec(context, |spec| {
            spec.conditions.push(Condition {
                loc: loc.clone(),
                kind,
                properties: Default::default(),
                exp: desugared_exp,
                additional_exps: vec![],
            })
        })
    }
```

**File:** third_party/move/move-model/src/builder/module_builder.rs (L3075-3138)
```rust
        // Go over all conditions in the schema, rewrite them, and add to the inclusion conditions.
        for Condition {
            loc,
            kind,
            properties,
            exp,
            additional_exps,
        } in schema_entry
            .spec
            .conditions
            .iter()
            .chain(schema_entry.included_spec.conditions.iter())
        {
            let mut replacer = |_, target: RewriteTarget| {
                if let RewriteTarget::LocalVar(sym) = target {
                    argument_map.get(&sym).cloned()
                } else {
                    None
                }
            };
            let mut rewriter =
                ExpRewriter::new(self.parent.env, &mut replacer).set_type_args(type_arguments);
            let mut exp = rewriter.rewrite_exp(exp.to_owned());
            let mut additional_exps = rewriter.rewrite_vec(additional_exps);
            if let Some(cond) = &path_cond {
                // There is a path condition to be added.
                if kind == &ConditionKind::Emits {
                    let cond_exp = if additional_exps.len() < 2 {
                        cond.clone()
                    } else {
                        self.make_path_expr(
                            Operation::And,
                            cond.node_id(),
                            cond.clone(),
                            additional_exps.pop().unwrap(),
                        )
                    };
                    additional_exps.push(cond_exp);
                } else if matches!(kind, ConditionKind::LetPre(..) | ConditionKind::LetPost(..)) {
                    // Ignore path condition for lets.
                } else {
                    // In case of AbortsIf, the path condition is combined with the predicate using
                    // &&, otherwise ==>.
                    exp = self.make_path_expr(
                        if kind == &ConditionKind::AbortsIf {
                            Operation::And
                        } else {
                            Operation::Implies
                        },
                        cond.node_id(),
                        cond.clone(),
                        exp,
                    );
                }
            }
            let mut effective_properties = schema_properties.clone();
            effective_properties.extend(properties.clone());
            spec.conditions.push(Condition {
                loc: loc.clone(),
                kind: kind.clone(),
                properties: effective_properties,
                exp,
                additional_exps,
            });
```

**File:** third_party/move/move-model/src/spec_translator.rs (L467-482)
```rust
    fn translate_lets(&mut self, post_state: bool, spec: &Spec) {
        for cond in &spec.conditions {
            let sym = match &cond.kind {
                ConditionKind::LetPost(sym, _) if post_state => sym,
                ConditionKind::LetPre(sym, _) if !post_state => sym,
                _ => continue,
            };
            let exp = self.translate_exp(&self.auto_trace(&cond.loc, &cond.exp), false);
            let ty = self.builder.global_env().get_node_type(exp.node_id());
            let temp = self.builder.add_local(ty.skip_reference().clone());
            self.let_locals.insert(*sym, temp);
            self.result
                .lets
                .push((cond.loc.clone(), post_state, temp, exp));
        }
    }
```

**File:** third_party/move/move-model/src/spec_translator.rs (L657-669)
```rust
    fn rewrite_local_var(&mut self, id: NodeId, sym: Symbol) -> Option<Exp> {
        if !self.is_shadowed(sym) {
            if let Some(temp) = self.let_locals.get(&sym) {
                // Need to create new node id since the replacement `temp` may
                // differ w.r.t. references.
                let env = self.builder.global_env();
                let new_node_id =
                    env.new_node(env.get_node_loc(id), self.builder.get_local_type(*temp));
                return Some(ExpData::Temporary(new_node_id, *temp).into_exp());
            }
        }
        None
    }
```
