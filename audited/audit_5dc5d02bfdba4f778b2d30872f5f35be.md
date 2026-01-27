# Audit Report

## Title
Move 2.0 Enum Variants with `#[verify_only]` Attribute Bypass Verification Filtering

## Summary
The verification filter in the Move compiler fails to check attributes on individual enum variants (a Move 2.0 feature), allowing variants marked with `#[verify_only]` to bypass removal when verification mode is disabled. This breaks the intended isolation boundary between verification-only code and production code.

## Finding Description

The verification filtering system is designed to remove AST elements annotated with `#[verify_only]` from production compilations while keeping them for formal verification runs. However, this filtering logic has a critical gap when handling Move 2.0 enum types.

**The vulnerability path:**

1. **Enum variants can have attributes**: The parser's `parse_struct_variant` function parses attributes for each enum variant. [1](#0-0) 

2. **Variants are represented in StructDefinition**: Enum variants are stored in `StructLayout::Variants`, where each `StructVariant` has its own `attributes` field. [2](#0-1) 

3. **Variant attributes are processed as struct attributes**: During expansion, variant attributes are flattened using `AttributePosition::Struct`, meaning `#[verify_only]` is accepted on variants. [3](#0-2) 

4. **Verification filter only checks top-level attributes**: The `filter_map_struct` function only examines `struct_def.attributes` and does not recurse into individual variant attributes within the `StructLayout`. [4](#0-3) 

5. **Result**: An enum with a `#[verify_only]` variant will pass through the filter completely intact, including the supposedly verification-only variant.

The `should_remove_node` function only operates on the attributes passed to it and has no recursion logic for nested structures. [5](#0-4) 

## Impact Explanation

This vulnerability qualifies as **HIGH severity** under the Aptos bug bounty criteria for the following reasons:

1. **Verification Guarantee Violation**: The Move Prover makes assumptions about which code exists only in verification mode versus production. When verify-only variants leak into production, the verified properties may not hold, breaking the formal verification guarantees that are critical to Move's security model.

2. **Potential Consensus Divergence**: If different compilation paths or compiler versions handle verification attributes inconsistently, or if future tooling changes this behavior, nodes could end up with different bytecode representations, potentially leading to consensus splits.

3. **Protocol Violation**: The verification filtering is a security boundary designed to separate proof-time code from runtime code. Bypassing this boundary represents a "significant protocol violation" per the bug bounty criteria.

4. **Deterministic Execution Risk**: While all nodes running the same compiler would have consistent behavior, the presence of unintended code paths (verification-only variants) in production violates the principle that production bytecode should only contain intended production logic, creating potential for unexpected state transitions.

## Likelihood Explanation

**Likelihood: MEDIUM**

This issue is moderately likely to occur because:

1. **Increasing Adoption**: Move 2.0 with enums is now the default compilation mode as of Aptos 5.2.0, making this feature widely used.

2. **Natural Use Case**: Developers may reasonably want to add verification-only variants to enums for specification purposes (e.g., ghost states, abstract values for proofs).

3. **Silent Failure**: The compiler accepts the `#[verify_only]` attribute on variants without error, giving developers false confidence that the filtering works correctly.

4. **No Validation**: There are no existing tests or documentation indicating that variant-level `#[verify_only]` is unsupported, making it easy for developers to use incorrectly.

However, exploitation requires:
- A developer to intentionally or accidentally mark enum variants as verify-only
- Production code to potentially interact with these variants
- The verification assumptions to materially differ from production behavior

## Recommendation

**Fix the verification filter to recursively check variant attributes:**

1. Modify `filter_map_struct` in `parser/filter.rs` to inspect and filter `StructLayout::Variants` based on variant attributes:

```rust
fn filter_map_struct(
    &mut self,
    struct_def: P::StructDefinition,
    is_source_def: bool,
    filtered_members: &mut BTreeSet<Symbol>,
) -> Option<P::StructDefinition> {
    if self.should_remove_by_attributes(&struct_def.attributes, is_source_def) {
        filtered_members.insert(struct_def.name.0.value);
        None
    } else {
        // Filter individual variants if this is an enum
        let filtered_layout = match struct_def.layout {
            P::StructLayout::Variants(variants) => {
                let filtered_variants: Vec<_> = variants
                    .into_iter()
                    .filter(|variant| {
                        !self.should_remove_by_attributes(&variant.attributes, is_source_def)
                    })
                    .collect();
                
                // If all variants are filtered, remove the entire enum
                if filtered_variants.is_empty() {
                    filtered_members.insert(struct_def.name.0.value);
                    return None;
                }
                P::StructLayout::Variants(filtered_variants)
            }
            other => other,
        };
        
        Some(P::StructDefinition {
            layout: filtered_layout,
            ..struct_def
        })
    }
}
```

2. Alternatively, add validation to reject `#[verify_only]` on enum variants entirely during the expansion phase, since variant-level filtering is not currently supported.

3. Add test cases covering enum variants with `#[verify_only]` to prevent regression.

## Proof of Concept

Create a Move module demonstrating the bypass:

```move
module 0x1::verify_bypass_test {
    /// This enum should have only one variant in production
    public enum TestEnum {
        ProductionVariant { value: u64 },
        
        #[verify_only]
        VerifyOnlyVariant { proof_value: u64 }
    }
    
    public fun create_production(): TestEnum {
        TestEnum::ProductionVariant { value: 42 }
    }
    
    // This function should not compile in non-verification mode
    // but currently does because VerifyOnlyVariant is not filtered
    public fun create_verify_only(): TestEnum {
        TestEnum::VerifyOnlyVariant { proof_value: 100 }
    }
    
    public fun match_test(e: TestEnum): u64 {
        match (e) {
            TestEnum::ProductionVariant { value } => value,
            // This match arm should not exist in production
            TestEnum::VerifyOnlyVariant { proof_value } => proof_value,
        }
    }
}
```

**Steps to reproduce:**
1. Save the above code in a Move 2.0 project
2. Compile with Move 2.0 enabled but verification mode disabled
3. Observe that the compilation succeeds (it should fail if filtering worked correctly)
4. The `VerifyOnlyVariant` and `create_verify_only` function are present in the compiled output despite the `#[verify_only]` attribute
5. Examine the generated bytecode to confirm the verify-only variant exists

**Expected behavior**: The `VerifyOnlyVariant` should be removed from the AST during the verification filtering pass, causing `create_verify_only` and the second match arm to fail compilation due to referencing a non-existent variant.

**Actual behavior**: The entire enum including `VerifyOnlyVariant` passes through to compilation unchanged.

### Citations

**File:** third_party/move/move-compiler-v2/legacy-move-compiler/src/parser/syntax.rs (L3369-3407)
```rust
fn parse_struct_variant(context: &mut Context) -> Result<(StructVariant, bool), Box<Diagnostic>> {
    let start_loc = context.tokens.start_loc();
    let attributes = parse_attributes(context)?;
    context.tokens.match_doc_comments();
    let name = VariantName(parse_identifier(context)?);
    let (fields, has_block, is_positional) = if context.tokens.peek() == Tok::LBrace {
        (
            parse_comma_list(
                context,
                Tok::LBrace,
                Tok::RBrace,
                parse_field_annot,
                "a field",
            )?,
            true,
            false,
        )
    } else if context.tokens.peek() == Tok::LParen {
        let loc = current_token_loc(context.tokens);
        require_move_2(context, loc, "positional fields");
        (parse_anonymous_fields(context)?, false, true)
    } else {
        (vec![], false, false)
    };
    let loc = make_loc(
        context.tokens.file_hash(),
        start_loc,
        context.tokens.previous_end_loc(),
    );
    Ok((
        StructVariant {
            attributes,
            loc,
            name,
            fields,
            is_positional,
        },
        has_block,
    ))
```

**File:** third_party/move/move-compiler-v2/legacy-move-compiler/src/parser/ast.rs (L224-239)
```rust
#[derive(Debug, PartialEq, Clone)]
pub enum StructLayout {
    // the second field is true iff the struct has positional fields
    Singleton(Vec<(Field, Type)>, bool),
    Variants(Vec<StructVariant>),
    Native(Loc),
}

#[derive(Debug, PartialEq, Clone)]
pub struct StructVariant {
    pub attributes: Vec<Attributes>,
    pub loc: Loc,
    pub name: VariantName,
    pub fields: Vec<(Field, Type)>,
    pub is_positional: bool,
}
```

**File:** third_party/move/move-compiler-v2/legacy-move-compiler/src/expansion/translate.rs (L1495-1505)
```rust
                        E::StructVariant {
                            attributes: flatten_attributes(
                                context,
                                AttributePosition::Struct,
                                v.attributes,
                            ),
                            loc: v.loc,
                            name: v.name,
                            fields: struct_fields(context, v.fields),
                            is_positional: v.is_positional,
                        }
```

**File:** third_party/move/move-compiler-v2/legacy-move-compiler/src/parser/filter.rs (L74-86)
```rust
    fn filter_map_struct(
        &mut self,
        struct_def: P::StructDefinition,
        is_source_def: bool,
        filtered_members: &mut BTreeSet<Symbol>,
    ) -> Option<P::StructDefinition> {
        if self.should_remove_by_attributes(&struct_def.attributes, is_source_def) {
            filtered_members.insert(struct_def.name.0.value);
            None
        } else {
            Some(struct_def)
        }
    }
```

**File:** third_party/move/move-compiler-v2/legacy-move-compiler/src/verification/ast_filter.rs (L48-57)
```rust
// An AST element should be removed if:
// * It is annotated #[verify_only] and verify mode is not set
fn should_remove_node(env: &CompilationEnv, attrs: &[P::Attributes]) -> bool {
    use known_attributes::VerificationAttribute;
    let flattened_attrs: Vec<_> = attrs.iter().flat_map(verification_attributes).collect();
    let is_verify_only = flattened_attrs
        .iter()
        .any(|attr| matches!(attr.1, VerificationAttribute::VerifyOnly));
    is_verify_only && !env.flags().is_verification()
}
```
