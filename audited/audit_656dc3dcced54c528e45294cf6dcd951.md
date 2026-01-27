# Audit Report

## Title
Incomplete Dependency Tracking for Native Spec Functions in Move Compiler

## Summary
The `spec_block_member()` function in the Move compiler's dependency ordering phase fails to process function signatures for native spec functions, potentially hiding module dependencies that should be tracked for correct compilation ordering.

## Finding Description

In the Move compiler's expansion phase, the `dependency_ordering::spec_block_member()` function processes spec block members to track inter-module dependencies. However, when handling spec functions, the implementation only processes the function body when it's `Defined`, completely ignoring the function signature: [1](#0-0) 

The pattern `M::Function { body, .. }` uses `..` to ignore other fields, including the `signature` field which contains type parameters, parameter types, and return types that may reference other modules.

In contrast, regular (non-spec) functions properly track signature dependencies: [2](#0-1) 

The `FunctionBody_` enum has two variants - `Defined(Sequence)` containing actual code, and `Native` for native functions: [3](#0-2) 

## Impact Explanation

**Assessment: This does NOT meet security vulnerability criteria.**

After thorough analysis, this issue is classified as a **compiler correctness bug** rather than a security vulnerability because:

1. **No Runtime Impact**: Spec functions are verification-only constructs used by the Move Prover. They do not execute at runtime and are not included in compiled bytecode.

2. **No Consensus Impact**: The dependency ordering affects compilation order, not execution semantics. Validators execute identical bytecode regardless of compilation order.

3. **No Fund Security Impact**: This cannot lead to loss, theft, or minting of funds.

4. **Limited to Compilation Phase**: The worst-case scenario is compilation errors or incorrect prover verification, which would prevent module deployment rather than allowing vulnerable code.

5. **Outside Bug Bounty Scope**: Per the Aptos bug bounty rules, this falls under "non-critical implementation bugs" without security impact. The bounty focuses on consensus violations, fund security, and network availability - none of which are affected.

The `dependency_order` field is used by the Move Prover's ModelBuilder: [4](#0-3) 

However, incorrect ordering during verification does not compromise blockchain security since verification is a pre-deployment check, not a runtime consensus mechanism.

## Likelihood Explanation

While the bug exists in the codebase, actual exploitation for security impact is not feasible because:

- Native spec functions with external type references are rare in practice
- The impact is limited to compilation/verification correctness
- No pathway exists from this bug to consensus, execution, or fund security issues

## Recommendation

Despite not being a security vulnerability, this is a correctness bug that should be fixed for compiler consistency. The fix should mirror the regular function handling:

```rust
M::Function { signature, body, .. } => {
    function_signature(context, signature);
    if let E::FunctionBody_::Defined(seq) = &body.value {
        sequence(context, seq)
    }
},
```

## Proof of Concept

**Not applicable** - This is a compiler implementation detail that does not constitute an exploitable security vulnerability according to the Aptos bug bounty criteria.

---

## Notes

While this is a legitimate compiler bug affecting dependency tracking consistency, it does not meet the threshold for a security vulnerability per the audit requirements:

- ❌ No consensus or safety violations
- ❌ No runtime execution impact  
- ❌ No fund security implications
- ❌ No state integrity issues
- ❌ Outside bug bounty impact categories

**This should be reported as a compiler correctness issue to the Move language team, not as a blockchain security vulnerability.**

### Citations

**File:** third_party/move/move-compiler-v2/legacy-move-compiler/src/expansion/dependency_ordering.rs (L363-377)
```rust
fn function(context: &mut Context, fdef: &E::Function) {
    function_signature(context, &fdef.signature);
    function_acquires(context, &fdef.acquires);
    if let E::FunctionBody_::Defined(seq) = &fdef.body.value {
        sequence(context, seq)
    }
    fdef.specs
        .values()
        .for_each(|sblock| spec_block(context, sblock));
}

fn function_signature(context: &mut Context, sig: &E::FunctionSignature) {
    types(context, sig.parameters.iter().map(|(_, st)| st));
    type_(context, &sig.return_type)
}
```

**File:** third_party/move/move-compiler-v2/legacy-move-compiler/src/expansion/dependency_ordering.rs (L631-635)
```rust
        M::Function { body, .. } => {
            if let E::FunctionBody_::Defined(seq) = &body.value {
                sequence(context, seq)
            }
        },
```

**File:** third_party/move/move-compiler-v2/legacy-move-compiler/src/expansion/ast.rs (L209-212)
```rust
pub enum FunctionBody_ {
    Defined(Sequence),
    Native,
}
```

**File:** third_party/move/move-model/src/lib.rs (L345-349)
```rust
    for (module_count, (module_id, module_def)) in program
        .modules
        .into_iter()
        .sorted_by_key(|(_, def)| def.dependency_order)
        .enumerate()
```
