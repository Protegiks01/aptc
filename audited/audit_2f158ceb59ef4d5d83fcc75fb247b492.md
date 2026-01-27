# Audit Report

## Title
Move Assembler Allows Creation of Function Types with Invalid `key` Ability, Bypassing Type System Soundness Checks

## Summary
The Move assembler (`move-asm`) allows creation of function types (`SignatureToken::Function`) with the `key` ability, which violates Move's fundamental type system invariant that function types cannot have `key` ability. This bypasses restrictions properly enforced by the Move compiler v2 and could enable type confusion attacks or future exploitation chains.

## Finding Description

Move's type system has a fundamental invariant: function types cannot have the `key` ability. This is explicitly enforced by the Move compiler v2, which produces the error "function types cannot have `key` ability" when such types are declared. [1](#0-0) 

However, the Move assembler tool (`move-asm`) bypasses this check through three vulnerabilities:

**1. Parser accepts arbitrary abilities**: The `type_()` function in the assembler's parser accepts function types with any combination of abilities without validation: [2](#0-1) 

**2. Assembler directly copies abilities**: The assembler's `build_type()` function directly copies abilities from the AST to bytecode without validation: [3](#0-2) 

**3. Bytecode verifier doesn't validate function type abilities**: The signature verifier only checks that function type abilities satisfy required constraints, but never validates that function types shouldn't have `key`: [4](#0-3) 

According to Move's ability system, function types should only have:
- `FUNCTIONS` (minimal): drop only
- `PRIVATE_FUNCTIONS`: copy + drop  
- `PUBLIC_FUNCTIONS`: copy + drop + store [5](#0-4) 

The `key` ability is specifically for types that can serve as top-level resources in global storage, which is fundamentally incompatible with function types.

## Impact Explanation

This vulnerability violates Move's type system soundness, which is a **Medium severity** issue. While I cannot demonstrate an immediate critical exploit path, type system violations can:

1. **Enable future exploitation chains**: Type confusion between compile-time signatures and runtime values could be leveraged with other bugs
2. **Break tooling assumptions**: Static analyzers, IDEs, and other tools that rely on type system invariants may behave incorrectly
3. **Create attack surface**: Invalid type signatures in deployed modules could interact unexpectedly with future VM features
4. **Bypass safety guarantees**: Modules with invalid function types could pass verification while violating Move's safety properties

The assembler is a lower-level tool that bypasses normal compiler checks, making it a vector for sophisticated attacks by adversaries who understand the bytecode format.

## Likelihood Explanation

**Likelihood: Medium**
- Requires attacker to use the assembler tool directly (not typical user path)
- Requires understanding of Move's bytecode format and type system
- The bug is deterministic and reproducible
- No special privileges required beyond ability to publish modules

## Recommendation

Add validation in multiple defense layers:

**1. Signature Verifier Enhancement**: In `signature_v2.rs`, add explicit validation that function types cannot have `key` ability:

```rust
Function(params, results, abilities) => {
    // NEW: Validate function type abilities
    if abilities.has_key() {
        return Err(PartialVMError::new(StatusCode::INVALID_SIGNATURE_TOKEN)
            .with_message("function types cannot have key ability".to_string()));
    }
    
    assert_abilities(*abilities, required_abilities)?;
    // ... rest of existing code
}
```

**2. Assembler Validation**: In `assembler.rs`, add validation when building function types:

```rust
Type::Func(args, result, abilities) => {
    if abilities.has_key() {
        self.error(loc, "function types cannot have key ability");
    }
    SignatureToken::Function(
        args.iter().map(|ty| self.build_type(loc, ty)).collect(),
        result.iter().map(|ty| self.build_type(loc, ty)).collect(),
        *abilities,
    )
}
```

**3. Deserializer Validation**: In `deserializer.rs`, validate abilities when loading function types:

```rust
S::FUNCTION => {
    let abilities = load_ability_set(cursor, AbilitySetPosition::StructTypeParameters)?;
    // NEW: Validate function abilities
    if abilities.has_key() {
        return Err(PartialVMError::new(StatusCode::INVALID_SIGNATURE_TOKEN)
            .with_message("function types cannot have key ability".to_string()));
    }
    // ... rest of existing code
}
```

## Proof of Concept

Create a `.masm` file with an invalid function type:

```
module 0x1::test

public fun invalid_fn_type(f: |u64| has key + store): u64
    ret
```

Compile with `move-asm`:
```bash
move-asm test.masm
```

The assembler will successfully compile this module with an invalid function type signature, bypassing the restriction that the Move compiler v2 properly enforces. The resulting bytecode contains a `SignatureToken::Function` with `key + store` abilities, violating Move's type system invariants.

## Notes

This vulnerability exists specifically in the assembler toolchain and would not occur through normal Move source compilation. However, the assembler is part of the official Aptos distribution and could be used by sophisticated attackers to craft malicious modules. The bytecode verifier, which is the final defense before module deployment, fails to catch this invariant violation.

### Citations

**File:** third_party/move/move-model/src/builder/exp_builder.rs (L1128-1131)
```rust
                let ability_set = self.parent.translate_abilities(abilities);
                if ability_set.has_key() {
                    self.error(loc, "function types cannot have `key` ability");
                }
```

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
