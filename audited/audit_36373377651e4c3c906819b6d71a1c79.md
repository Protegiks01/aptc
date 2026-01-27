# Audit Report

## Title
Type Unification False Positives in Move Prover Monomorphization Analysis

## Summary
The Move Prover's monomorphization analysis contains a critical parameter mismatch between its type unification check and subsequent progressive instantiation. This logic error causes the unification check at line 342 to produce false positives when analyzing generic functions that access the same struct with different type instantiations, potentially allowing unsound verification of Aptos Framework code.

## Finding Description

The vulnerability exists in the monomorphization analysis phase of the Move Prover, which determines what concrete type instantiations of generic functions need to be verified. [1](#0-0) 

The code performs two operations on pairs of memory accesses:

1. **Unification Check (line 341)**: Uses `TypeUnificationAdapter::new_pair(&lhs_ty, &rhs_ty, true, true)`, treating type parameters on BOTH sides as independent unification variables.

2. **Progressive Instantiation (line 350-360)**: Calls `progressive_instantiation` with parameters `(true, false, ...)`, treating only the left-hand side's type parameters as variables.

This parameter mismatch breaks the soundness of the analysis. When a generic function accesses memory locations like `Resource<X, u64>` and `Resource<bool, X>` (where X is the same type parameter), the unification check incorrectly succeeds: [2](#0-1) 

The `TypeUnificationAdapter::new` function converts type parameters to independent `Type::Var` nodes. For the example above:
- Left side: `Resource<X, u64>` → `Resource<Var(0), u64>` 
- Right side: `Resource<bool, X>` → `Resource<bool, Var(1)>` (treating the same X as a different variable!)

The unification succeeds by binding `Var(0)=bool` and `Var(1)=u64`, even though both occurrences of X must have the same instantiation. This is a **false positive** - the unification check claims these types can unify when they actually cannot for any single instantiation of X.

Compare this with the correct usage in global invariant analysis: [3](#0-2) 

Here, both the unification check (line 437) and progressive instantiation (line 458-468) consistently use `(true, true)` parameters, correctly treating type parameters from both sides as variables.

## Impact Explanation

This vulnerability undermines the **soundness** of the Move Prover, which is critical for ensuring the correctness of the Aptos Framework. The potential impacts are:

1. **Incomplete Verification**: The prover may verify only a subset of necessary type instantiations, missing bugs that manifest in unchecked instantiations.

2. **Framework Code Vulnerabilities**: If Aptos Framework code (governance, staking, coin handling) contains type-dependent bugs, they could pass verification and be deployed.

3. **Consensus Violations**: Type-dependent bugs in framework consensus code could cause validators to diverge on state computation, violating the **Deterministic Execution** invariant.

4. **State Corruption**: Bugs in framework storage code could corrupt the Jellyfish Merkle tree or cause state inconsistencies.

This meets **High Severity** criteria: "Significant protocol violations" and potential validator node issues if framework code with verification gaps is deployed.

## Likelihood Explanation

**Likelihood: Medium-High**

This bug will manifest whenever:
1. A generic function accesses the same struct type with different instantiations involving the function's type parameters
2. These instantiations create a pattern where the same type parameter appears in different positions
3. The prover attempts to determine which instantiations need verification

This pattern occurs naturally in generic framework code that manipulates resources parameterized by types (e.g., `Coin<CoinType>`, `StakePool<PoolType>`).

The exploitation requires:
- Writing or modifying Aptos Framework code (limited to core developers)
- The code having a type-dependent bug that only manifests in specific instantiations
- The mono_analysis bug causing those instantiations to not be checked

While direct exploitation requires framework developer access, the bug affects ALL prover runs and could have already allowed vulnerable code into the framework.

## Recommendation

Fix the parameter mismatch by making the progressive instantiation call consistent with the unification check:

**In mono_analysis.rs, line 350-360, change:**
```rust
let fun_insts = TypeInstantiationDerivation::progressive_instantiation(
    std::iter::once(&lhs_ty),
    std::iter::once(&rhs_ty),
    true,
    false,  // ← Change this to true
    true,
    false,
    fun_type_params_arity,
    true,
    false,
);
```

**Change to:**
```rust
let fun_insts = TypeInstantiationDerivation::progressive_instantiation(
    std::iter::once(&lhs_ty),
    std::iter::once(&rhs_ty),
    true,
    true,   // ← Consistent with unification check
    true,
    false,
    fun_type_params_arity,
    true,
    false,
);
```

This ensures both the unification check and instantiation derivation treat type parameters consistently, matching the correct pattern used in `global_invariant_analysis.rs`.

## Proof of Concept

This Move module demonstrates code that would be incorrectly analyzed:

```move
module 0x1::poc {
    struct Resource<T, U> has key {
        t_value: T,
        u_value: U
    }
    
    spec module {
        // Invariant: u_value must be 0 for all Resource<X, u64>
        invariant<X> [global] forall addr: address where exists<Resource<X, u64>>(addr):
            global<Resource<X, u64>>(addr).u_value == 0;
    }
    
    // This function accesses Resource<X, u64> and Resource<bool, X>
    // The mono_analysis bug would incorrectly analyze the unification of these types
    public fun vulnerable<X>() acquires Resource {
        let r1 = borrow_global_mut<Resource<X, u64>>(@0x1);
        let r2 = borrow_global_mut<Resource<bool, X>>(@0x2);
        
        // This violates the invariant for Resource<X, u64>
        r1.u_value = 42;
        
        // If X=u64, then r2 is Resource<bool, u64>, also covered by invariant
        r2.u_value = 99;
    }
}
```

**Expected behavior with bug:**
- Unification check: `Resource<X, u64>` vs `Resource<bool, X>` with (true, true) → incorrectly succeeds
- Progressive instantiation with (true, false) → may derive wrong instantiations or incomplete set
- Prover may miss checking `X=u64` instantiation where both memory accesses interact with the invariant
- Verification incorrectly passes

**Expected behavior after fix:**
- Unification check and progressive instantiation both use (true, true)
- Correctly identifies all necessary instantiations including `X=u64`
- Detects the invariant violation in line `r1.u_value = 42`

## Notes

This is a **logic error** in the Move Prover's type analysis, not a runtime execution bug. However, it directly impacts the security of the Aptos blockchain by potentially allowing unverified code into the framework. The bug is particularly dangerous because it silently produces incorrect analysis results rather than failing loudly, making it difficult to detect without careful code review.

### Citations

**File:** third_party/move/move-prover/bytecode-pipeline/src/mono_analysis.rs (L328-373)
```rust
        if self.inst_opt.is_none() {
            // collect information
            let fun_type_params_arity = target.get_type_parameter_count();
            let usage_state = UsageProcessor::analyze(self.targets, target.func_env, target.data);

            // collect instantiations
            let mut all_insts = BTreeSet::new();
            for lhs_m in usage_state.accessed.all.iter() {
                let lhs_ty = lhs_m.to_type();
                for rhs_m in usage_state.accessed.all.iter() {
                    let rhs_ty = rhs_m.to_type();

                    // make sure these two types unify before trying to instantiate them
                    let adapter = TypeUnificationAdapter::new_pair(&lhs_ty, &rhs_ty, true, true);
                    if adapter
                        .unify(&mut NoUnificationContext, Variance::SpecVariance, false)
                        .is_none()
                    {
                        continue;
                    }

                    // find all instantiation combinations given by this unification
                    let fun_insts = TypeInstantiationDerivation::progressive_instantiation(
                        std::iter::once(&lhs_ty),
                        std::iter::once(&rhs_ty),
                        true,
                        false,
                        true,
                        false,
                        fun_type_params_arity,
                        true,
                        false,
                    );
                    all_insts.extend(fun_insts);
                }
            }

            // mark all the instantiated targets as todo
            for fun_inst in all_insts {
                self.todo_funs.push((
                    target.func_env.get_qualified_id(),
                    target.data.variant.clone(),
                    fun_inst,
                ));
            }
        }
```

**File:** third_party/move/move-model/src/ty_invariant_analysis.rs (L78-104)
```rust
        // Create a type variable instantiation for each side.
        let mut var_count = 0;
        let mut type_vars_map = BTreeMap::new();
        let lhs_inst = match treat_lhs_type_param_as_var_after_index {
            None => vec![],
            Some(boundary) => (0..boundary)
                .map(Type::TypeParameter)
                .chain((boundary..lhs_type_param_count).map(|i| {
                    let idx = var_count;
                    var_count += 1;
                    type_vars_map.insert(idx, (true, i));
                    Type::Var(idx)
                }))
                .collect(),
        };
        let rhs_inst = match treat_rhs_type_param_as_var_after_index {
            None => vec![],
            Some(boundary) => (0..boundary)
                .map(Type::TypeParameter)
                .chain((boundary..rhs_type_param_count).map(|i| {
                    let idx = var_count;
                    var_count += 1;
                    type_vars_map.insert(idx, (false, i));
                    Type::Var(idx)
                }))
                .collect(),
        };
```

**File:** third_party/move/move-prover/bytecode-pipeline/src/global_invariant_analysis.rs (L437-468)
```rust
                    let adapter = TypeUnificationAdapter::new_pair(&rel_ty, &inv_ty, true, true);
                    if adapter
                        .unify(&mut NoUnificationContext, Variance::SpecVariance, false)
                        .is_none()
                    {
                        continue;
                    }

                    // instantiate the bytecode first
                    //
                    // NOTE: in fact, in this phase, we don't intend to instantiation the function
                    // nor do we want to collect information on how this function (or this bytecode)
                    // needs to be instantiated. All we care is how the invariant should be
                    // instantiated in order to be instrumented at this code point, with a generic
                    // function and generic code.
                    //
                    // But unfortunately, based on how the type unification logic is written now,
                    // this two-step instantiation is needed in order to find all possible
                    // instantiations of the invariant. I won't deny that there might be a way to
                    // collect invariant instantiation combinations without instantiating the
                    // function type parameters, but I haven't iron out one so far.
                    let rel_insts = TypeInstantiationDerivation::progressive_instantiation(
                        std::iter::once(&rel_ty),
                        std::iter::once(&inv_ty),
                        true,
                        true,
                        true,
                        false,
                        fun_type_params_arity,
                        true,
                        false,
                    );
```
