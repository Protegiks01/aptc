# Audit Report

## Title
Move Assembler Allows Function Types with Prohibited `key` Ability, Bypassing Bytecode Verification

## Summary
The Move assembler's syntax parser accepts function types with the `key` ability (e.g., `|u64| u64 has key`), which violates Move's type system constraints. The assembler blindly passes these invalid abilities through to bytecode without validation, and critically, the bytecode verifier fails to detect this violation during module publishing. This allows modules with invalid type signatures to be deployed on-chain.

## Finding Description

Move's type system explicitly prohibits function types from having the `key` ability. This constraint is enforced in the Move compiler, but the assembler parser and bytecode verifier have a gap in validation.

**Vulnerability Chain:**

1. **Parser accepts invalid abilities**: The assembler parser in `syntax.rs` parses function type abilities without any validation that `key` is prohibited. [1](#0-0) 

2. **Assembler passes through invalid abilities**: The assembler directly converts parsed function types to bytecode, blindly copying the abilities without validation. [2](#0-1) 

3. **Bytecode verifier fails to catch the violation**: The signature verifier only checks that function types have the *minimum* required abilities, but does NOT validate they don't have *prohibited* abilities like `key`. [3](#0-2) 

The `assert_abilities(*abilities, required_abilities)` check only verifies that `required_abilities ⊆ *abilities`, but doesn't enforce that `*abilities ⊆ MAXIMUM_ALLOWED_ABILITIES`.

**Contrast with Move Compiler**: The Move compiler explicitly rejects this at compile time. [4](#0-3) 

**Valid Ability Constants**: Move defines the maximum allowed abilities for functions, which never include `key`. [5](#0-4) 

**Attack Path:**
1. Attacker creates a `.masm` file with: `fun test(f: |u64| u64 has key): u64`
2. Assembler successfully parses and generates bytecode
3. Module passes bytecode verification (no error)
4. Module is published on-chain with invalid type signature
5. System now contains types that violate Move's documented invariants

## Impact Explanation

**Severity: Medium**

This vulnerability allows publishing modules with type system violations, which constitutes a **state inconsistency requiring intervention** per the Aptos bug bounty program.

**Specific Impacts:**
- **Type System Integrity Violation**: Modules exist on-chain with function types that have prohibited abilities, breaking Move's documented type constraints
- **Deterministic Execution at Risk**: Different implementations of the Move VM might handle invalid types differently, potentially causing consensus issues
- **State Inconsistency**: The blockchain contains modules that violate the language specification
- **Potential for Exploitation Chaining**: While runtime checks prevent direct use in `move_to` operations, the invalid types in the type system could potentially be combined with other bugs (e.g., type confusion, ability checking bypasses) for more serious attacks

While the runtime has paranoid checks that prevent using function types with `key` in global storage operations: [6](#0-5) 

The core issue is that **invalid bytecode passes verification and gets published**, which is a protocol-level violation regardless of runtime mitigations.

## Likelihood Explanation

**Likelihood: Medium**

- **Ease of Exploitation**: Trivial - requires only writing a `.masm` file with invalid function type abilities
- **Attack Complexity**: Low - no special permissions or complex setup required
- **Discoverability**: Medium - requires knowledge of assembler syntax and Move's type system constraints
- **Current Exploitation**: Unknown, but the assembler is a standard development tool in the Move ecosystem

The assembler is used for:
- Low-level testing of Move VM features
- Writing code that the high-level compiler doesn't support
- Creating specialized bytecode for advanced use cases

Any developer using the assembler could inadvertently or maliciously create modules with invalid function types.

## Recommendation

**Fix 1: Add validation in the assembler**

Add a check in `assembler.rs` when building function types to reject prohibited abilities:

```rust
Type::Func(args, result, abilities) => {
    // Validate function type abilities
    if abilities.has_key() {
        self.error(loc, "function types cannot have `key` ability");
        return SignatureToken::Bool; // error fallback
    }
    SignatureToken::Function(
        args.iter().map(|ty| self.build_type(loc, ty)).collect(),
        result.iter().map(|ty| self.build_type(loc, ty)).collect(),
        *abilities,
    )
}
```

**Fix 2: Add validation in the bytecode verifier (defense in depth)**

Add validation in `signature_v2.rs` to enforce maximum allowed abilities for function types:

```rust
Function(params, results, abilities) => {
    // Validate function types cannot have key ability
    if abilities.has_key() {
        return Err(PartialVMError::new(StatusCode::CONSTRAINT_NOT_SATISFIED)
            .with_message("function types cannot have `key` ability".to_string()));
    }
    
    assert_abilities(*abilities, required_abilities)?;
    if self.sig_checker_v2_fix_function_signatures {
        for ty in params.iter().chain(results) {
            self.check_ty(ty, true, AbilitySet::EMPTY, param_constraints)?
        }
    }
}
```

## Proof of Concept

Create a file `invalid_function_type.masm`:

```masm
//# publish
module 0x42::test

// This should be rejected but currently passes verification
fun invalid_fn_type(f: |u64| u64 has key): u64
    ld_u64 42
    ret

fun create_invalid(): |u64| u64 has key
    // This would fail at runtime if actually executed
    // but the module can still be published
    abort 1
```

**Expected Behavior**: Module publishing should fail with error "function types cannot have `key` ability"

**Actual Behavior**: Module passes bytecode verification and is published on-chain with invalid type signature

**Test Steps**:
1. Save the above code to `invalid_function_type.masm`
2. Run through Move assembler/transactional-test framework
3. Observe that module is accepted despite having function type with prohibited `key` ability
4. Compare with equivalent Move source code which correctly rejects this at compile time

**Notes**

This vulnerability represents a gap between the high-level Move compiler's type checking and the low-level bytecode verification. While the Move compiler correctly enforces type system constraints, the bytecode verifier assumes all bytecode follows these rules without actually validating them. This creates a verification bypass when using the assembler or any other tool that generates bytecode directly.

The runtime's paranoid checks provide partial mitigation by preventing actual use of the invalid types in operations like `move_to`, but the fundamental issue remains: the blockchain accepts and stores modules that violate the language specification. This could lead to unexpected behavior, implementation divergence between different Move VM implementations, or provide building blocks for more sophisticated attacks when combined with other vulnerabilities.

### Citations

**File:** third_party/move/tools/move-asm/src/syntax.rs (L447-466)
```rust
        } else if self.is_special("|") {
            self.advance()?;
            let arg_tys = if self.is_type() {
                self.type_list()?
            } else {
                vec![]
            };
            self.expect_special("|")?;
            let res_tys = if self.is_type_tuple() {
                self.result_type_tuple()?
            } else {
                vec![]
            };
            let abs = if self.is_soft_kw("has") {
                self.advance()?;
                self.abilities()?
            } else {
                AbilitySet::EMPTY
            };
            Ok(Type::Func(arg_tys, res_tys, abs))
```

**File:** third_party/move/tools/move-asm/src/assembler.rs (L553-557)
```rust
            Type::Func(args, result, abilities) => SignatureToken::Function(
                args.iter().map(|ty| self.build_type(loc, ty)).collect(),
                result.iter().map(|ty| self.build_type(loc, ty)).collect(),
                *abilities,
            ),
```

**File:** third_party/move/move-bytecode-verifier/src/signature_v2.rs (L172-187)
```rust
            Function(params, results, abilities) => {
                assert_abilities(*abilities, required_abilities)?;
                if self.sig_checker_v2_fix_function_signatures {
                    for ty in params.iter().chain(results) {
                        self.check_ty(
                            ty,
                            // Immediate params and returns can be references.
                            true,
                            // Note we do not need to check abilities of argument or result types,
                            // they do not matter for the `required_abilities`.
                            AbilitySet::EMPTY,
                            param_constraints,
                        )?
                    }
                }
            },
```

**File:** third_party/move/move-model/src/builder/exp_builder.rs (L1128-1131)
```rust
                let ability_set = self.parent.translate_abilities(abilities);
                if ability_set.has_key() {
                    self.error(loc, "function types cannot have `key` ability");
                }
```

**File:** third_party/move/move-core/types/src/ability.rs (L103-113)
```rust
    /// Minimal abilities for all `Functions`
    pub const FUNCTIONS: AbilitySet = Self(Ability::Drop as u8);
    /// Abilities for `Bool`, `U8`, `U64`, `U128`, and `Address`
    pub const PRIMITIVES: AbilitySet =
        Self((Ability::Copy as u8) | (Ability::Drop as u8) | (Ability::Store as u8));
    /// Abilities for `private` user-defined/"primitive" functions (not closures).
    /// These can be be changed in module upgrades, so should not be stored
    pub const PRIVATE_FUNCTIONS: AbilitySet = Self((Ability::Copy as u8) | (Ability::Drop as u8));
    /// Abilities for `public` user-defined/"primitive" functions (not closures)
    pub const PUBLIC_FUNCTIONS: AbilitySet =
        Self((Ability::Copy as u8) | (Ability::Drop as u8) | (Ability::Store as u8));
```

**File:** third_party/move/move-vm/runtime/src/runtime_type_checks.rs (L831-841)
```rust
            Instruction::MoveTo(idx) => {
                let ty = operand_stack.pop_ty()?;
                operand_stack.pop_ty()?.paranoid_check_is_signer_ref_ty()?;
                ty.paranoid_check_eq(&frame.get_struct_ty(*idx))?;
                ty.paranoid_check_has_ability(Ability::Key)?;
            },
            Instruction::MoveToGeneric(idx) => {
                let ty = operand_stack.pop_ty()?;
                operand_stack.pop_ty()?.paranoid_check_is_signer_ref_ty()?;
                ty.paranoid_check_eq(ty_cache.get_struct_type(*idx, frame)?.0)?;
                ty.paranoid_check_has_ability(Ability::Key)?;
```
