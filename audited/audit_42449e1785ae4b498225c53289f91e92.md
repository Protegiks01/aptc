# Audit Report

## Title
Arithmetic Overflow in Token Offer Royalty Calculation Causing Transaction Failures for NFT Sales

## Summary
The `settle_payments` function in the marketplace token offer module performs an unsafe multiplication `price * royalty_numerator / royalty_denominator` without overflow protection. When the intermediate multiplication exceeds u64 maximum value (18,446,744,073,709,551,615), Move's checked arithmetic aborts the transaction, causing legitimate NFT sales to fail.

## Finding Description

The vulnerability exists in the royalty calculation performed during NFT sales through the token offer mechanism. [1](#0-0) 

This calculation uses direct u64 multiplication without overflow protection. Move uses checked arithmetic that aborts on overflow rather than wrapping. When `price * royalty_numerator` exceeds 2^64 - 1, the transaction fails with an arithmetic error.

The royalty numerator and denominator are constrained only by the requirement that the royalty cannot exceed 100%: [2](#0-1) 

This allows arbitrarily large numerator/denominator pairs. For example:
- `numerator = 1,000,000,000,000,000,000` (10^18)
- `denominator = 10,000,000,000,000,000,000` (10^19)
- This represents a valid 10% royalty

With such values, even a minimal sale price causes overflow:
- Price: 20 octas (0.0000002 APT)
- Calculation: `20 * 10^18 = 2 * 10^19`
- Result: Exceeds u64 max (1.84 * 10^19) → **Transaction aborts**

In contrast, the same marketplace provides a safe implementation that prevents this issue: [3](#0-2) 

This uses `math64::mul_div` which converts to u128 before multiplication, preventing intermediate overflow: [4](#0-3) 

## Impact Explanation

**High Severity** - This meets the "API crashes" and "Significant protocol violations" criteria for High severity findings (up to $50,000).

The vulnerability causes:
1. **Transaction Failures**: Legitimate NFT sales abort when royalty calculations overflow
2. **Denial of Service**: NFTs with certain royalty configurations become unsellable through the token_offer marketplace
3. **Broken Deterministic Execution**: Valid transactions fail unpredictably based on royalty configuration choices
4. **Liquidity Impact**: NFT holders cannot complete sales, reducing market functionality

While this occurs in marketplace example code rather than core consensus, it represents a significant implementation flaw that affects the usability of NFT trading functionality.

## Likelihood Explanation

**High Likelihood** - This can occur through:
1. **Accidental Configuration**: Developers setting royalty numerator/denominator to large values for precision (e.g., using 10^18 base units like other blockchain systems)
2. **Malicious Configuration**: NFT creators intentionally setting large royalty values to create "unsellable" tokens as a griefing attack
3. **High-Value Sales**: Even with modest royalty denominators, extremely high-value NFT sales could trigger overflow

The attack requires no special privileges - any NFT creator can set royalty parameters during token creation or mutation.

## Recommendation

Replace the unsafe direct multiplication with the existing safe `bounded_percentage` helper function:

**Current vulnerable code:**
```move
let royalty_charge = price * royalty_numerator / royalty_denominator;
```

**Recommended fix:**
```move
let royalty_charge = listing::bounded_percentage(price, royalty_numerator, royalty_denominator);
```

This change:
1. Prevents intermediate overflow by using `math64::mul_div` internally
2. Ensures royalty never exceeds sale price via `min()` capping
3. Handles zero denominator gracefully
4. Maintains consistency with the safer `listing.move` implementation

## Proof of Concept

```move
#[test(creator = @0x123)]
#[expected_failure(abort_code = 0x20001, location = std::arithmetic_error)]
fun test_royalty_overflow() {
    // Create royalty with large but valid values (10% royalty)
    let numerator: u64 = 1000000000000000000;  // 10^18
    let denominator: u64 = 10000000000000000000; // 10^19
    let royalty = royalty::create(numerator, denominator, @0x456);
    
    // Even tiny price causes overflow
    let price: u64 = 20;  // 0.0000002 APT
    
    // This calculation will abort:
    // price * numerator = 20 * 10^18 = 2 * 10^19 > u64_max (1.84 * 10^19)
    let _royalty_charge = price * numerator / denominator;
}
```

**Notes**

1. **Scope Clarification**: While the original security question referenced the Rust event struct `RoyaltyMutate`, that file only stores event data and performs no calculations. The actual vulnerability exists in the Move marketplace code where royalty calculations occur.

2. **Inconsistent Implementation**: The same marketplace codebase contains both vulnerable (token_offer.move) and safe (listing.move) implementations, indicating an oversight rather than a deliberate design choice.

3. **Framework Safety**: The core Aptos token framework itself (royalty.move, token.move) does not perform royalty calculations - it only stores the royalty parameters. The vulnerability only affects marketplace implementations that calculate royalties.

4. **Move Arithmetic Semantics**: Move uses abort-on-overflow rather than wrapping arithmetic, which means this causes transaction failures rather than incorrect (wrapped) royalty amounts.

### Citations

**File:** aptos-move/move-examples/marketplace/sources/token_offer.move (L384-384)
```text
        let royalty_charge = price * royalty_numerator / royalty_denominator;
```

**File:** aptos-move/framework/aptos-token-objects/sources/royalty.move (L54-59)
```text
    public fun create(numerator: u64, denominator: u64, payee_address: address): Royalty {
        assert!(denominator != 0, error::out_of_range(EROYALTY_DENOMINATOR_IS_ZERO));
        assert!(numerator <= denominator, error::out_of_range(EROYALTY_EXCEEDS_MAXIMUM));

        Royalty { numerator, denominator, payee_address }
    }
```

**File:** aptos-move/move-examples/marketplace/sources/listing.move (L292-299)
```text
    /// Calculates a bounded percentage that can't go over 100% and handles 0 denominator as 0
    public inline fun bounded_percentage(amount: u64, numerator: u64, denominator: u64): u64 {
        if (denominator == 0) {
            0
        } else {
            math64::min(amount, math64::mul_div(amount, numerator, denominator))
        }
    }
```

**File:** aptos-move/framework/aptos-stdlib/sources/math64.move (L50-54)
```text
    public inline fun mul_div(a: u64, b: u64, c: u64): u64 {
        // Inline functions cannot take constants, as then every module using it needs the constant
        assert!(c != 0, std::error::invalid_argument(4));
        (((a as u128) * (b as u128) / (c as u128)) as u64)
    }
```
