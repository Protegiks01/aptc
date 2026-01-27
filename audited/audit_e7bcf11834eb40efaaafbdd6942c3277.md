# Audit Report

## Title
Move Prover Strict Abort Specification Bypass via Partial Specifications

## Summary
The Move specification translator contains a logic flaw that allows developers to bypass the `aborts_if_is_strict` pragma by providing minimal or vacuous abort specifications. This undermines the verification guarantees intended by the strict checking mechanism, potentially allowing incomplete or incorrect abort specifications to pass verification.

## Finding Description

The `aborts_if_is_strict` pragma is designed to enforce complete abort specifications for Move functions. When enabled, functions without explicit `aborts_if` clauses should implicitly receive `aborts_if false`, meaning they must not abort. [1](#0-0) 

However, the implementation in `translate_spec()` only adds the implicit `aborts_if false` when BOTH the `aborts` and `aborts_with` lists are empty: [2](#0-1) 

This creates two bypass vectors:

**Bypass 1: Using `aborts_with` alone**
A developer can specify only `aborts_with ERROR_CODE` without any `aborts_if` conditions. This makes `self.result.aborts_with` non-empty, preventing the implicit `aborts_if false` from being added. The prover then only verifies that IF the function aborts, it uses the specified error codes - but NOT when it aborts.

**Bypass 2: Vacuous `aborts_if` with `aborts_if_is_partial`**
A developer can specify `aborts_if false` combined with `pragma aborts_if_is_partial = true`. This makes `self.result.aborts` non-empty, bypassing the strict check. With the partial pragma, the prover only verifies the implication `false ==> function_aborts`, which is vacuously true. [3](#0-2) 

The verification logic only emits assertions for abort conditions when `aborts_if_is_partial` is false AND there are abort conditions to check. With the bypasses above, no completeness check is performed.

Multiple Aptos Framework modules rely on `aborts_if_is_strict` for verification: [4](#0-3) [5](#0-4) 

## Impact Explanation

This is a **verification tool vulnerability** that undermines the security guarantees of the Move Prover. While it doesn't directly cause runtime exploits, it allows incomplete specifications to pass verification, which could mask actual bugs in critical Aptos Framework code.

The impact is classified as **Medium severity** because:
- It defeats a key security mechanism (strict abort checking) in the verification tool
- It could allow buggy code in governance, staking, or transaction validation to pass verification
- Undetected abort conditions could lead to unexpected transaction failures, state inconsistencies, or DOS vectors
- It affects the correctness guarantees that Aptos relies on for security-critical framework code

## Likelihood Explanation

The likelihood is **Medium to High** because:
- The bypass pattern is simple and could occur accidentally or intentionally
- Many framework modules use `aborts_if_is_strict`, making them potential targets
- Developers may not understand the subtle interaction between strict pragmas and partial specifications
- The Move Prover documentation warns about risks of `aborts_if_is_partial` but doesn't mention this bypass [6](#0-5) 

## Recommendation

Fix the logic in `translate_spec()` to check only the `aborts` list when deciding whether to add the implicit `aborts_if false`:

```rust
// If there are no aborts_if conditions, and the pragma `aborts_if_is_strict` is set,
// add an implicit aborts_if false.
if self.result.aborts.is_empty()  // Only check aborts, not aborts_with
    && self
        .fun_env
        .is_pragma_true(ABORTS_IF_IS_STRICT_PRAGMA, || false)
{
    self.result.aborts.push((
        self.fun_env.get_loc().at_end(),
        self.builder.mk_bool_const(false),
        None,
    ));
}
```

The presence of `aborts_with` alone should NOT bypass strict checking - developers must still specify `aborts_if` conditions to describe WHEN the function aborts.

Additionally, emit a warning when `aborts_if false` is combined with `aborts_if_is_partial = true`, as this pattern is vacuous and likely indicates a specification error.

## Proof of Concept

```move
module 0x1::StrictBypassDemo {
    
    const ERROR_INVALID: u64 = 1;
    
    spec module {
        pragma verify = true;
        pragma aborts_if_is_strict = true;
    }
    
    /// BYPASS 1: Using aborts_with bypasses strict check
    /// This function CAN abort when x == 0, but verification passes
    public fun bypass_with_aborts_with(x: u64): u64 {
        assert!(x > 0, ERROR_INVALID);  // Aborts when x == 0!
        x
    }
    
    spec bypass_with_aborts_with {
        aborts_with ERROR_INVALID;  // Only codes specified, no conditions
        // Expected: Should fail verification (missing aborts_if)
        // Actual: Passes verification (bypass via aborts_with)
    }
    
    /// BYPASS 2: Vacuous aborts_if with partial pragma
    public fun bypass_with_vacuous_condition(x: u64): u64 {
        assert!(x > 0, ERROR_INVALID);
        x
    }
    
    spec bypass_with_vacuous_condition {
        pragma aborts_if_is_partial = true;
        aborts_if false;  // Vacuously true
        // Expected: Should fail verification
        // Actual: Passes verification (vacuous condition with partial)
    }
    
    /// CORRECT: Properly specified function
    public fun correctly_specified(x: u64): u64 {
        assert!(x > 0, ERROR_INVALID);
        x
    }
    
    spec correctly_specified {
        aborts_if x == 0 with ERROR_INVALID;
    }
}
```

Run with: `move prove StrictBypassDemo.move`

The first two functions should fail verification under strict checking but will pass due to the bypass, demonstrating the vulnerability.

## Notes

This vulnerability exists specifically in the Move Prover's specification translation layer, not in the Move VM runtime. While it doesn't constitute a direct runtime exploit, it represents a significant weakness in Aptos's formal verification infrastructure. The Move Prover is a critical security tool used to verify the correctness of the Aptos Framework, and bypasses in its checking mechanisms could allow buggy or malicious code to be deployed to production with false confidence in its correctness.

### Citations

**File:** third_party/move/move-prover/doc/user/spec-lang.md (L631-632)
```markdown
<a name="risk-aborts-if-is-partial"></a>
> Note that there is a certain risk in setting `aborts_if_is_partial` to true, and best practice is to avoid it in specifications of public functions and transaction scripts once those are considered finalized. This is because changing the code after finalization of the spec can add new (non-trivial, undesired) abort situations which the original specification did not anticipate, but which will nevertheless silently pass verification.
```

**File:** third_party/move/move-prover/doc/user/spec-lang.md (L634-639)
```markdown
If no aborts condition is specified for a function, abort behavior is unspecified. The function may
or may not abort, and verification will not raise any errors, whether `aborts_if_is_partial` is set
or not. In order to state that a function never aborts, use `aborts_if false`. One can use the
pragma `aborts_if_is_strict`
to change this behavior; this is equivalent to as if an `aborts_if false` has been added to each
function which does not have an explicit `aborts_if` clause.
```

**File:** third_party/move/move-model/src/spec_translator.rs (L400-413)
```rust
        // If there are no aborts_if and aborts_with, and the pragma `aborts_if_is_strict` is set,
        // add an implicit aborts_if false.
        if self.result.aborts.is_empty()
            && self.result.aborts_with.is_empty()
            && self
                .fun_env
                .is_pragma_true(ABORTS_IF_IS_STRICT_PRAGMA, || false)
        {
            self.result.aborts.push((
                self.fun_env.get_loc().at_end(),
                self.builder.mk_bool_const(false),
                None,
            ));
        }
```

**File:** third_party/move/move-prover/bytecode-pipeline/src/spec_instrumentation.rs (L893-906)
```rust
        let is_partial = self
            .builder
            .fun_env
            .is_pragma_true(ABORTS_IF_IS_PARTIAL_PRAGMA, || false);

        if !is_partial {
            // If not partial, emit an assertion for the overall aborts condition.
            if let Some(cond) = spec.aborts_condition(&self.builder) {
                let loc = self.builder.fun_env.get_spec_loc();
                self.emit_traces(spec, &cond);
                self.builder.set_loc_and_vc_info(loc, ABORT_NOT_COVERED);
                self.builder.emit_with(move |id| Prop(id, Assert, cond));
            }
        }
```

**File:** aptos-move/framework/aptos-framework/sources/chain_status.spec.move (L23-28)
```text
    spec module {
        pragma verify = true;
        pragma aborts_if_is_strict;
        /// [high-level-req-2]
        invariant is_genesis() == !is_operating();
    }
```

**File:** aptos-move/framework/aptos-framework/sources/storage_gas.spec.move (L64-71)
```text
    spec module {
        use aptos_framework::chain_status;
        pragma verify = true;
        pragma aborts_if_is_strict;
        // After genesis, `StateStorageUsage` and `GasParameter` exist.
        invariant [suspendable] chain_status::is_operating() ==> exists<StorageGasConfig>(@aptos_framework);
        invariant [suspendable] chain_status::is_operating() ==> exists<StorageGas>(@aptos_framework);
    }
```
