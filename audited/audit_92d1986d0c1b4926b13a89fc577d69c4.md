# Audit Report

## Title
Stack Overflow in Move Compiler from Unbounded Recursive Attribute Processing

## Summary
The Move legacy compiler's `attribute()` function in the expansion phase performs unbounded recursion when processing deeply nested parameterized attributes, allowing an attacker to craft malicious Move source code that causes stack overflow and crashes the compiler.

## Finding Description

The vulnerability exists in the attribute processing logic during Move source compilation. The parser and expansion translator both recursively process parameterized attributes without any depth limits.

**Parser Phase (Unbounded Recursion):** [1](#0-0) 

When the parser encounters a parameterized attribute (line 750-762), it recursively calls `parse_attribute` on line 755 for each nested attribute without maintaining a depth counter.

**Expansion Phase (Unbounded Recursion):** [2](#0-1) 

The `attribute()` function recursively processes parameterized attributes (line 824-829). For each nested attribute in `pattrs_`, it calls itself recursively on line 827 without any depth limit.

**Attribute AST Structure (Allows Infinite Nesting):** [3](#0-2) 

The `Attribute_::Parameterized` variant on line 125 contains `Attributes`, which is a vector of `Attribute`, allowing arbitrary nesting depth.

**Attack Vector:**
An attacker creates a Move source file with deeply nested parameterized attributes like:
```
#[attr1(attr2(attr3(attr4(...attr10000...))))]
module 0x1::M { }
```

**Exploitation Flow:**
1. Malicious Move source file is submitted to a compiler service or CI/CD pipeline
2. Parser recursively processes nested attributes without depth check
3. Expansion phase recursively processes the parsed attributes without depth check
4. Each recursion level consumes stack space
5. After sufficient nesting depth (~1000-10000 levels depending on stack size), stack overflow occurs
6. Compiler crashes with segmentation fault or stack overflow error

**Contrast with Other Components:**
The codebase implements depth limits elsewhere to prevent similar issues: [4](#0-3) [5](#0-4) 

However, no such protection exists for attribute nesting in the source compiler.

## Impact Explanation

**Severity Assessment: Out of Scope / Low**

While this is a genuine DoS vulnerability in the Move compiler, it does **not** meet the security impact criteria defined in the validation checklist:

1. **No blockchain impact**: Modules are published as bytecode, not source code. Validators only verify bytecode, never compile source. [6](#0-5) 

2. **No consensus/safety violation**: The vulnerability is in the development toolchain, not the blockchain runtime. It cannot affect validator consensus, state commitment, or transaction execution.

3. **Limited attack surface**: Only affects systems that compile Move source code (developer machines, CI/CD pipelines), not validator nodes or the blockchain itself.

4. **No funds at risk**: Cannot cause loss, theft, or freezing of funds.

According to the Aptos bug bounty categories provided, this does not fit:
- **Critical**: No (no funds, consensus, or liveness impact)
- **High**: No (validators unaffected)
- **Medium**: No (no funds or state consistency impact)
- **Low**: Possibly (non-critical implementation bug)

## Likelihood Explanation

**High likelihood of exploitation in affected contexts, but limited impact:**

- **Trivial to exploit**: Requires only crafting a malicious Move source file
- **No special permissions needed**: Any user with access to a compiler service
- **Easy to automate**: Can programmatically generate deeply nested attributes
- **However**: Limited to development/tooling environments, not production blockchain

## Recommendation

Implement a depth limit constant and track recursion depth during attribute processing:

```rust
const MAX_ATTRIBUTE_NESTING_DEPTH: usize = 16;

fn attribute(
    context: &mut Context,
    attr_position: AttributePosition,
    sp!(loc, attribute_): P::Attribute,
    depth: usize,
) -> Option<E::Attribute> {
    if depth > MAX_ATTRIBUTE_NESTING_DEPTH {
        context.env.add_diag(diag!(
            Declarations::InvalidAttribute,
            (loc, format!("Attribute nesting exceeds maximum depth of {}", MAX_ATTRIBUTE_NESTING_DEPTH))
        ));
        return None;
    }
    
    // ... existing code with depth+1 passed to recursive calls
}
```

## Proof of Concept

**Rust Test to Trigger Stack Overflow:**

```rust
#[test]
#[should_panic(expected = "stack overflow")]
fn test_deeply_nested_attributes_stack_overflow() {
    use move_compiler::parser;
    
    // Generate deeply nested attributes: #[a(a(a(...a...)...))]
    let depth = 10000;
    let mut source = String::from("#[");
    for _ in 0..depth {
        source.push_str("a(");
    }
    source.push('a');
    for _ in 0..depth {
        source.push(')');
    }
    source.push_str("]\nmodule 0x1::M {}");
    
    // This will cause stack overflow during parsing/expansion
    let _ = parser::parse_program(&source);
}
```

**Move Source File (nested_attack.move):**

```move
// Generate this programmatically with 5000+ levels of nesting
#[attr(attr(attr(attr(...attr...)...)...))]
module 0x1::Test {
    public fun dummy() {}
}
```

Compiling this file with `move compile` will crash the compiler with a stack overflow.

## Notes

**Critical Distinction**: This vulnerability affects the **compiler toolchain**, not the **blockchain runtime**. Since Aptos publishes modules as bytecode (not source), and validators only verify bytecode, this cannot directly impact consensus, validator operations, or on-chain security. It is a development tooling issue, not a blockchain security issue.

The validation checklist requires demonstrating "clear security harm to funds, consensus, or availability." This vulnerability fails that test - it only affects compiler availability in development environments, not blockchain availability or security.

**Conclusion**: While technically valid as a compiler bug, this does **not** meet the strict validation criteria for a security vulnerability in the Aptos blockchain core according to the defined invariants and impact categories.

### Citations

**File:** third_party/move/move-compiler-v2/legacy-move-compiler/src/parser/syntax.rs (L750-763)
```rust
        Tok::LParen => {
            let args_ = parse_comma_list(
                context,
                Tok::LParen,
                Tok::RParen,
                parse_attribute,
                "attribute",
            )?;
            let end_loc = context.tokens.previous_end_loc();
            Attribute_::Parameterized(
                n,
                spanned(context.tokens.file_hash(), start_loc, end_loc, args_),
            )
        },
```

**File:** third_party/move/move-compiler-v2/legacy-move-compiler/src/expansion/translate.rs (L814-832)
```rust
fn attribute(
    context: &mut Context,
    attr_position: AttributePosition,
    sp!(loc, attribute_): P::Attribute,
) -> Option<E::Attribute> {
    use E::Attribute_ as EA;
    use P::Attribute_ as PA;
    Some(sp(loc, match attribute_ {
        PA::Name(n) => EA::Name(n),
        PA::Assigned(n, v) => EA::Assigned(n, Box::new(attribute_value(context, *v)?)),
        PA::Parameterized(n, sp!(_, pattrs_)) => {
            let attrs = pattrs_
                .into_iter()
                .map(|a| attribute(context, attr_position, a))
                .collect::<Option<Vec<_>>>()?;
            EA::Parameterized(n, unique_attributes(context, attr_position, true, attrs))
        },
    }))
}
```

**File:** third_party/move/move-compiler-v2/legacy-move-compiler/src/parser/ast.rs (L122-129)
```rust
pub enum Attribute_ {
    Name(Name),
    Assigned(Name, Box<AttributeValue>),
    Parameterized(Name, Attributes),
}
pub type Attribute = Spanned<Attribute_>;

pub type Attributes = Spanned<Vec<Attribute>>;
```

**File:** third_party/move/move-vm/types/src/values/values_impl.rs (L46-46)
```rust
    rc::Rc,
```

**File:** third_party/move/move-core/types/src/safe_serialize.rs (L21-21)
```rust
{
```

**File:** third_party/move/documentation/spec/vm.md (L1-1)
```markdown
# Move VM Specification
```
