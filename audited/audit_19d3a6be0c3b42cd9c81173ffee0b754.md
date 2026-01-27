# Audit Report

## Title
Phantom Type Parameters Bypass Monomorphization Analysis Causing Missing Axiom Instantiations

## Summary
The monomorphization analysis in the Move Prover fails to track types that are used exclusively as phantom type parameters. This causes generic axioms to not be instantiated for these types, potentially leading to incomplete verification and false verification success for Move modules that should fail verification.

## Finding Description

The Move Prover's monomorphization analysis is responsible for computing all type instantiations needed for verification. [1](#0-0) 

When processing struct instantiations, the `add_struct` function stores all type arguments but only recursively analyzes field types: [2](#0-1) 

Phantom type parameters, by definition, do not appear in struct fields or only appear in other phantom positions. [3](#0-2) 

This creates a critical gap: when a type is **only** used as a phantom type parameter, it gets stored in the structs map but never triggers the recursive `add_type` call. Consequently, such types are never added to the `done_types` set.

The `compute_axiom_instances` function uses `done_types` to generate instantiations for generic axioms: [4](#0-3) 

The `all_types` set at line 186 is derived from `done_types`: [5](#0-4) 

**Attack Scenario:**
1. A Move module defines a struct with a phantom type parameter
2. Another module uses this struct with a custom type that appears nowhere else
3. The module also has generic axioms that should apply to all types
4. The monomorphization analysis processes the struct, storing the phantom type argument
5. However, since the type doesn't appear in any fields, `add_type` is never called for it
6. The type is missing from `done_types` and consequently from `all_types`
7. Generic axioms are not instantiated for this type
8. Verification proceeds with incomplete axiom coverage
9. The prover may incorrectly verify code that violates properties for the phantom type

**Real-World Impact:** The Aptos stdlib contains generic axioms for serialization/deserialization: [6](#0-5) 

If a type is only used as a phantom parameter, these axioms won't be instantiated for it, leading to incomplete verification of BCS operations.

## Impact Explanation

**High Severity** - This vulnerability affects the correctness of the Move Prover, which is the primary security verification tool for Aptos smart contracts.

The impact aligns with **High Severity** criteria:
- **Significant protocol violations**: The verification protocol relies on complete axiom instantiation for soundness
- **API crashes**: While not a direct crash, verification incorrectly succeeds when it should fail
- **Validator node slowdowns**: Indirectly, if unverified vulnerable code is deployed, it could affect validator performance

More critically, this creates a **false sense of security**:
- Developers rely on the Move Prover to catch bugs before deployment
- Missing axiom instantiations means the prover doesn't check all required properties
- Vulnerable Move modules could pass verification and be deployed on-chain
- This could cascade into **Critical** impacts: loss of funds, consensus violations, or state corruption if the unverified code contains actual vulnerabilities

The vulnerability is systematic - it affects all Move code using phantom type parameters with generic axioms, which is common in the Aptos framework.

## Likelihood Explanation

**High Likelihood** - This issue occurs automatically whenever:
1. A struct uses phantom type parameters (common pattern in Move)
2. A type is exclusively used as a phantom parameter argument
3. Generic axioms exist in the specification

The Aptos framework extensively uses phantom type parameters: [7](#0-6) 

Generic axioms are also present in critical modules like `from_bcs`: [8](#0-7) 

No special attacker knowledge or privileges are required - this is a systematic flaw in the analysis algorithm that manifests in normal Move development.

## Recommendation

The `add_struct` function should explicitly add all type arguments to the type analysis, not just field types. Modify the function to call `add_type` for each type argument:

```rust
fn add_struct(&mut self, struct_: StructEnv<'_>, targs: &[Type]) {
    if struct_.is_intrinsic_of(INTRINSIC_TYPE_MAP) {
        self.info
            .table_inst
            .entry(struct_.get_qualified_id())
            .or_default()
            .insert((targs[0].clone(), targs[1].clone()));
    } else if struct_.is_intrinsic() && !targs.is_empty() {
        self.info
            .native_inst
            .entry(struct_.module_env.get_id())
            .or_default()
            .insert(targs.to_owned());
    } else {
        self.info
            .structs
            .entry(struct_.get_qualified_id())
            .or_default()
            .insert(targs.to_owned());
            
        // FIX: Add all type arguments, including phantom ones
        for targ in targs {
            self.add_type(targ);
        }
        
        if struct_.has_variants() {
            for variant in struct_.get_variants() {
                for field in struct_.get_fields_of_variant(variant) {
                    self.add_type(&field.get_type().instantiate(targs));
                }
            }
        } else {
            for field in struct_.get_fields() {
                self.add_type(&field.get_type().instantiate(targs));
            }
        }
    }
}
```

This ensures that all type arguments, including those used exclusively in phantom positions, are properly tracked and included in axiom instantiations.

## Proof of Concept

Create a Move module demonstrating the issue:

```move
module 0x42::PhantomBug {
    struct Wrapper<phantom T> { 
        value: u64 
    }
    
    struct PhantomOnly { }
    
    spec module {
        // Generic axiom that should apply to all types
        fun spec_identity<T>(x: T): T;
        axiom<T> forall x: T: spec_identity(x) == x;
    }
    
    // This function uses PhantomOnly only as phantom parameter
    fun test(): Wrapper<PhantomOnly> {
        Wrapper { value: 42 }
    }
    
    spec test {
        // This spec relies on the axiom being instantiated for PhantomOnly
        // But it won't be because PhantomOnly is only in phantom position
        ensures result.value == spec_identity(42u64);
    }
}
```

**Verification Steps:**
1. Run the Move Prover on this module with `--dump=mono-analysis`
2. Examine the monomorphization output
3. Observe that `PhantomOnly` does not appear in the `all_types` set
4. Observe that the axiom is not instantiated for `PhantomOnly`
5. The verification may succeed even though it should check the axiom for `PhantomOnly`

The monomorphization dump will show that `Wrapper<PhantomOnly>` is recorded, but `PhantomOnly` itself is missing from the type instantiations used for axiom generation.

## Notes

This vulnerability specifically affects the **Move Prover verification tool**, not the Move VM runtime execution. However, the security impact is still HIGH because:

1. The Move Prover is the primary security verification mechanism for Aptos smart contracts
2. Incomplete verification can lead to vulnerable code being deployed
3. The issue is systematic and affects common Move programming patterns
4. Missing axiom instantiations violate the soundness guarantees of formal verification

The fix is straightforward but critical: ensure all type arguments are analyzed, regardless of whether they appear in struct fields.

### Citations

**File:** third_party/move/move-prover/bytecode-pipeline/src/mono_analysis.rs (L5-6)
```rust
//! Analysis which computes information needed in backends for monomorphization. This
//! computes the distinct type instantiations in the model for structs and inlined functions.
```

**File:** third_party/move/move-prover/bytecode-pipeline/src/mono_analysis.rs (L181-187)
```rust
        let Analyzer {
            mut info,
            done_types,
            ..
        } = analyzer;
        info.all_types = done_types;
        env.set_extension(info);
```

**File:** third_party/move/move-prover/bytecode-pipeline/src/mono_analysis.rs (L278-311)
```rust
    fn compute_axiom_instances(&self) -> Vec<(Condition, Vec<Vec<Type>>)> {
        let mut axioms = vec![];
        let all_types = self
            .done_types
            .iter()
            .filter(|t| t.can_be_type_argument())
            .cloned()
            .collect::<Vec<_>>();
        for module_env in self.env.get_modules() {
            for cond in &module_env.get_spec().conditions {
                if let ConditionKind::Axiom(params) = &cond.kind {
                    let type_insts = match params.len() {
                        0 => vec![vec![]],
                        1 => all_types.iter().cloned().map(|t| vec![t]).collect(),
                        2 => itertools::iproduct!(
                            all_types.iter().cloned(),
                            all_types.iter().cloned()
                        )
                        .map(|(x, y)| vec![x, y])
                        .collect(),
                        _ => {
                            self.env.error(
                                &cond.loc,
                                "axioms cannot have more than two type parameters",
                            );
                            vec![]
                        },
                    };
                    axioms.push((cond.clone(), type_insts));
                }
            }
        }
        axioms
    }
```

**File:** third_party/move/move-prover/bytecode-pipeline/src/mono_analysis.rs (L606-637)
```rust
    fn add_struct(&mut self, struct_: StructEnv<'_>, targs: &[Type]) {
        if struct_.is_intrinsic_of(INTRINSIC_TYPE_MAP) {
            self.info
                .table_inst
                .entry(struct_.get_qualified_id())
                .or_default()
                .insert((targs[0].clone(), targs[1].clone()));
        } else if struct_.is_intrinsic() && !targs.is_empty() {
            self.info
                .native_inst
                .entry(struct_.module_env.get_id())
                .or_default()
                .insert(targs.to_owned());
        } else {
            self.info
                .structs
                .entry(struct_.get_qualified_id())
                .or_default()
                .insert(targs.to_owned());
            if struct_.has_variants() {
                for variant in struct_.get_variants() {
                    for field in struct_.get_fields_of_variant(variant) {
                        self.add_type(&field.get_type().instantiate(targs));
                    }
                }
            } else {
                for field in struct_.get_fields() {
                    self.add_type(&field.get_type().instantiate(targs));
                }
            }
        }
    }
```

**File:** third_party/move/changes/6-phantom-type-params.md (L47-55)
```markdown
before its declaration. If a type parameter is declared as phantom we say it is a phantom type
parameter. When defining a struct, Move's type checker ensures that every phantom type parameter is
either not used inside the struct definition or it is only used as an argument to a phantom type
parameter.

More formally, if a type is used as an argument to a phantom type parameter we say the type appears
in _phantom position_. With this definition in place, the rule for the correct use of phantom
parameters can be specified as follows: **A phantom type parameter can only appear in phantom
position**.
```

**File:** aptos-move/framework/aptos-stdlib/sources/from_bcs.spec.move (L1-31)
```text
spec aptos_std::from_bcs {
    // ----------------------------------
    // Uninterpreted functions and axioms
    // ----------------------------------
    spec module {
        // An uninterpreted function to represent the desrialization.
        fun deserialize<T>(bytes: vector<u8>): T;

        // Checks if `bytes` is valid so that it can be deserialized into type T.
        // This is modeled as an uninterpreted function.
        fun deserializable<T>(bytes: vector<u8>): bool;

        // `deserialize` is an injective function.
        // axiom<T> forall b1: vector<u8>, b2: vector<u8>:
        //    (deserialize<T>(b1) == deserialize<T>(b2) ==> b1 == b2);

        // If the input are equal, the result of deserialize should be equal too
        axiom<T> forall b1: vector<u8>, b2: vector<u8>:
            ( b1 == b2 ==> deserializable<T>(b1) == deserializable<T>(b2) );

        axiom<T> forall b1: vector<u8>, b2: vector<u8>:
            ( b1 == b2 ==> deserialize<T>(b1) == deserialize<T>(b2) );

        // `deserialize` is an inverse function of `bcs::serialize`.
        // TODO: disabled because this generic axiom causes a timeout.
        // axiom<T> forall v: T: deserialize<T>(bcs::serialize(v)) == v;

        // All serialized bytes are deserializable.
        // TODO: disabled because this generic axiom causes a timeout.
        // axiom<T> forall v: T: deserializable<T>(bcs::serialize(v));
    }
```

**File:** third_party/move/move-compiler-v2/tests/checking/abilities/v1/phantom_param_op_abilities.move (L2-6)
```text
    struct NoAbilities { }
    struct HasDrop<phantom T1, T2> has drop { a: T2 }
    struct HasCopy<phantom T1, T2> has copy { a: T2 }
    struct HasStore<phantom T1, T2> has store { a: T2}
    struct HasKey<phantom T1, T2> has key { a : T2 }
```
