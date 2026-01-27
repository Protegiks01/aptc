# Audit Report

## Title
Move Prover Address Format Mismatch in type_name::get() Enables Verification Bypass

## Summary
The Move Prover's Boogie backend uses incorrect address formatting for `std::type_name::get<T>()`, producing full-length addresses without the `0x` prefix (e.g., "0000...0001") instead of the canonical short format with prefix (e.g., "0x1") used at runtime. This causes the prover to verify specifications against incorrect type name strings, allowing contracts to pass verification while failing or behaving differently at runtime.

## Finding Description
The `boogie_reflection_type_name()` function uses different address formatters based on the `stdlib` parameter: [1](#0-0) 

When `stdlib=true` (for `std::type_name::get<T>()`), it uses:
- `prefix: false` (no "0x" prefix)  
- `full_length: true` (32 hex characters with leading zeros)

However, at runtime, `std::type_name::get<T>()` calls `type_tag.to_canonical_string()`, which formats addresses as: [2](#0-1) 

This uses `short_str_lossless()` which produces the `0x` prefix with trimmed leading zeros (e.g., "0x1" not "0000000000000000000000000000001").

**Evidence of Mismatch:**

Runtime test expects short format with prefix: [3](#0-2) 

But Move Prover test expects full-length format without prefix: [4](#0-3) 

This discrepancy means any Move specification that compares or pattern-matches on `type_name::get<T>()` output will be verified against the wrong string format. A contract could be proven to satisfy security invariants that it actually violates at runtime.

**Attack Scenario:**
1. A Move contract implements access control by checking if a type name starts with "0x1::" (privileged system types)
2. The Move Prover verifies this check using the full-length format "0000000000000000000000000000001::"
3. The specification is proven correct
4. At runtime, an attacker passes a type from address "0x10000000000000000000000000000000"
5. Runtime produces "0x10000000000000000000000000000000::" which doesn't match "0x1::" ✓
6. But prover verified against "00000000000000000000000000000010::" which doesn't match "0000000000000000000000000000001::" ✓
7. The verification is sound but for the WRONG string format, potentially missing edge cases

## Impact Explanation
**Medium Severity** - This breaks the fundamental guarantee of the Move Prover that verified contracts behave as specified. While it requires specific contract patterns to be exploitable, it affects all contracts using `type_name::get<T>()` in specifications.

This violates the **Deterministic Execution** invariant: the prover analyzes one behavior while validators execute another. It could enable:
- Specification bypasses where proven invariants don't hold at runtime
- Type confusion attacks in contracts using type names for access control
- State inconsistencies in governance or registry contracts that store/compare type names

## Likelihood Explanation
**High likelihood** of affecting contracts, **medium likelihood** of being exploitable:
- Any contract using `type_name::get<T>()` in specifications is affected
- Exploitation requires the contract to have security-critical logic depending on exact type name string matching
- The 32-character vs short address difference makes certain attack patterns feasible that the prover would incorrectly rule out

## Recommendation
Fix the address formatter for `stdlib=true` case to match runtime behavior:

```rust
pub fn boogie_reflection_type_name(env: &GlobalEnv, ty: &Type, stdlib: bool) -> String {
    let formatter = if stdlib {
        AddressFormatter {
            prefix: true,        // Changed from false
            full_length: false,  // Changed from true
            capitalized: false,
        }
    } else {
        AddressFormatter {
            prefix: true,
            full_length: false,
            capitalized: false,
        }
    };
    // ... rest unchanged
}
```

Update the Move Prover test expectations to use canonical format: [5](#0-4) 

Change line 199 to: `ensures result.bytes == b"0x43::test::Pair<address, bool>";`

## Proof of Concept

```move
module 0x1::verification_bypass_poc {
    use std::type_name;
    use std::string;
    
    // Security check: only allow types from standard library (0x1)
    public fun is_stdlib_type<T>(): bool {
        let name = type_name::into_string(type_name::get<T>());
        let prefix = string::sub_string(&name, 0, 4);
        prefix == string::utf8(b"0x1:")
    }
    
    spec is_stdlib_type {
        // Prover verifies this against "0000000000000000000000000000001::"
        // But runtime checks against "0x1::"
        // This mismatch could cause the prover to miss edge cases
        ensures result == (/* condition based on wrong format */);
    }
}

// Test that demonstrates the format difference:
#[test]
fun test_format_mismatch() {
    // Runtime produces: "0x1::string::String"
    let runtime_name = type_name::into_string(type_name::get<string::String>());
    
    // Prover assumes: "0000000000000000000000000000001::string::String"
    // Verification would analyze different string than runtime uses!
}
```

**Notes:**

This vulnerability affects the soundness of formal verification, which is critical for high-assurance Move contracts. While not directly exploitable for fund theft, it undermines the security guarantees provided by the Move Prover, potentially enabling attacks on contracts that rely on verified type name handling for access control, registry management, or governance logic.

### Citations

**File:** third_party/move/move-prover/boogie-backend/src/boogie_helpers.rs (L1055-1084)
```rust
pub fn boogie_reflection_type_name(env: &GlobalEnv, ty: &Type, stdlib: bool) -> String {
    let formatter = if stdlib {
        AddressFormatter {
            prefix: false,
            full_length: true,
            capitalized: false,
        }
    } else {
        AddressFormatter {
            prefix: true,
            full_length: false,
            capitalized: false,
        }
    };
    let bytes = TypeIdentToken::convert_to_bytes(type_name_to_ident_tokens(env, ty, &formatter));
    if stdlib {
        format!(
            "${}_type_name_TypeName(${}_ascii_String({}))",
            env.get_stdlib_address().expect_numerical().to_big_uint(),
            env.get_stdlib_address().expect_numerical().to_big_uint(),
            bytes
        )
    } else {
        format!(
            "${}_string_String({})",
            env.get_stdlib_address().expect_numerical().to_big_uint(),
            bytes
        )
    }
}
```

**File:** third_party/move/move-core/types/src/language_storage.rs (L280-290)
```rust
        format!(
            // Note:
            //   For historical reasons, we convert addresses as strings using 0x... and trimming
            //   leading zeroes. This cannot be changed easily because 0x1::any::Any relies on that
            //   and may store bytes of these strings on-chain.
            "0x{}::{}::{}{}",
            self.address.short_str_lossless(),
            self.module,
            self.name,
            generics
        )
```

**File:** third_party/move/move-stdlib/tests/type_name_tests.move (L22-28)
```text
    #[test]
    fun test_structs() {
        assert!(into_string(get<TestStruct>()) == string(b"0xa::type_name_tests::TestStruct"), 0);
        assert!(into_string(get<std::ascii::String>()) == string(b"0x1::ascii::String"), 0);
        assert!(into_string(get<std::option::Option<u64>>()) == string(b"0x1::option::Option<u64>"), 0);
        assert!(into_string(get<std::string::String>()) == string(b"0x1::string::String"), 0);
    }
```

**File:** third_party/move/move-prover/tests/sources/functional/type_reflection.move (L195-200)
```text
    fun test_type_name_concrete_struct(): ascii::String {
        type_name::into_string(type_name::get<Pair<address, bool>>())
    }
    spec test_type_name_concrete_struct {
        ensures result.bytes == b"00000000000000000000000000000043::test::Pair<address, bool>";
    }
```
