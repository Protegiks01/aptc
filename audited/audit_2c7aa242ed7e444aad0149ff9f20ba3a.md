# Audit Report

## Title
Token V1 Royalty Division-by-Zero Vulnerability: Missing Denominator Validation Enables Marketplace Transaction Freezing

## Summary
The Aptos Token V1 framework (`token.move`) fails to validate that `royalty_points_denominator` is non-zero when creating royalty configurations, allowing tokens with zero-denominator royalties to be created. When marketplace contracts attempt to calculate royalty amounts using division, these tokens cause arithmetic aborts, freezing all marketplace transactions for the affected tokens.

## Finding Description

The Token V1 framework contains a critical validation gap in its royalty creation logic. The `create_royalty` function only validates that the numerator does not exceed the denominator, but fails to prevent zero-denominator configurations: [1](#0-0) 

The validation `royalty_points_numerator <= royalty_points_denominator` allows both values to be zero (since `0 <= 0` is true). This same insufficient validation exists in the `create_tokendata` function: [2](#0-1) 

In contrast, Token V2 correctly validates against zero denominators with an explicit check: [3](#0-2) 

**Attack Path:**

1. A token creator (maliciously or accidentally) calls `create_token_script` with parameters:
   - `royalty_points_numerator: 0`
   - `royalty_points_denominator: 0`
   - Other valid parameters

2. The validation at line 1267 passes since `0 <= 0` evaluates to true

3. Token is successfully created and stored with invalid royalty configuration

4. When a marketplace attempts to sell/trade this token, it calculates royalties using the pattern demonstrated in the example marketplace: [4](#0-3) 

5. The Move VM encounters division-by-zero (`price * 0 / 0`) and aborts with `ARITHMETIC_ERROR`

6. All marketplace transactions for this token freeze, making the token untradeable

The indexer simply stores these invalid values without performing calculations: [5](#0-4) 

**Invariant Violation:**

This breaks the framework's responsibility to enforce data validity invariants. Token V2's explicit validation proves that zero-denominator royalties are invalid configurations that should be prevented at the framework level, not left to application-layer defensive coding.

## Impact Explanation

**Severity: HIGH** (up to $50,000 per Aptos Bug Bounty criteria)

This vulnerability causes **significant protocol violations** manifesting as:

1. **Marketplace Transaction DoS**: Any token with zero-denominator royalty becomes untradeable on marketplaces using standard royalty calculation patterns, causing transaction aborts

2. **Framework-Level Validation Gap**: The Token V1 framework fails to enforce a critical data validity invariant that Token V2 explicitly validates

3. **Ecosystem-Wide Risk**: While the vulnerable division pattern is in example code, real-world marketplaces may implement similar royalty calculations without defensive checks, assuming framework-validated data

4. **Griefing Vector**: Malicious actors can intentionally create tokens with zero-denominator royalties to DoS marketplace transactions

The impact does not reach CRITICAL severity as there is no funds loss, consensus break, or permanent state corruption. However, it qualifies as HIGH due to protocol violation and significant availability impact on affected tokens.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

**Factors Increasing Likelihood:**
- Token creators may accidentally set both numerator and denominator to zero when intending "no royalty"
- The validation appears correct at first glance (`numerator <= denominator`) but has a blind spot
- Token V2's explicit fix suggests this issue was identified in practice
- Standard marketplace implementations following the example pattern are vulnerable

**Factors Decreasing Likelihood:**
- Requires marketplace contracts to use unsafe division patterns
- Some marketplaces may implement defensive checks (as shown in `collection_offer.move`): [6](#0-5) 

- Token creators may typically use non-zero values for royalties

The vulnerability is easily triggerable and has clear exploitation paths, making occurrence reasonably likely in production environments.

## Recommendation

**Immediate Fix:** Add explicit zero-denominator validation to Token V1's `create_royalty` function, matching Token V2's approach:

```move
public fun create_royalty(royalty_points_numerator: u64, royalty_points_denominator: u64, payee_address: address): Royalty {
    assert!(royalty_points_denominator != 0, error::invalid_argument(EROYALTY_DENOMINATOR_IS_ZERO));
    assert!(royalty_points_numerator <= royalty_points_denominator, error::invalid_argument(EINVALID_ROYALTY_NUMERATOR_DENOMINATOR));
    Royalty {
        royalty_points_numerator,
        royalty_points_denominator,
        payee_address
    }
}
```

Add corresponding validation to `create_tokendata`: [7](#0-6) 

Define the new error constant:
```move
const EROYALTY_DENOMINATOR_IS_ZERO: u64 = 41;
```

**Secondary Recommendation:** Update marketplace documentation to recommend using safe division patterns like `bounded_percentage` for all royalty calculations.

## Proof of Concept

```move
#[test_only]
module test_royalty_division_by_zero {
    use aptos_token::token;
    use std::string;
    use std::signer;
    
    #[test(creator = @0xCAFE)]
    fun test_zero_denominator_creation(creator: &signer) {
        // Initialize collections for the creator
        token::create_collection(
            creator,
            string::utf8(b"Test Collection"),
            string::utf8(b"Test Description"),
            string::utf8(b"https://test.com"),
            0,
            vector[false, false, false]
        );
        
        // Create a token with ZERO denominator royalty
        // This should fail but currently succeeds in Token V1
        let token_data_id = token::create_tokendata(
            creator,
            string::utf8(b"Test Collection"),
            string::utf8(b"Test Token"),
            string::utf8(b"Test Description"),
            1,
            string::utf8(b"https://test.com/token"),
            signer::address_of(creator),
            0, // royalty_points_denominator = 0 (INVALID!)
            0, // royalty_points_numerator = 0
            token::create_token_mutability_config(&vector[false, false, false, false, false]),
            vector[],
            vector[],
            vector[]
        );
        
        // Token created successfully despite invalid royalty
        assert!(token::check_tokendata_exists(
            signer::address_of(creator),
            string::utf8(b"Test Collection"),
            string::utf8(b"Test Token")
        ), 0);
        
        // Now simulate marketplace royalty calculation
        let price = 1000u64;
        let royalty = token::get_royalty(token::create_token_id(token_data_id, 0));
        let numerator = token::get_royalty_numerator(&royalty);
        let denominator = token::get_royalty_denominator(&royalty);
        
        // This division will cause ARITHMETIC_ERROR abort
        // Demonstrating the marketplace DoS vulnerability
        let _royalty_charge = price * numerator / denominator; // ABORTS HERE
    }
}
```

This test demonstrates:
1. Token V1 allows creating tokens with `royalty_points_denominator = 0`
2. Standard marketplace royalty calculation pattern causes transaction abort
3. Tokens become untradeable due to division-by-zero error

### Citations

**File:** aptos-move/framework/aptos-token/sources/token.move (L1001-1010)
```text
    public fun create_royalty(royalty_points_numerator: u64, royalty_points_denominator: u64, payee_address: address): Royalty {
        assert!(royalty_points_numerator <= royalty_points_denominator, error::invalid_argument(EINVALID_ROYALTY_NUMERATOR_DENOMINATOR));
        // Question[Orderless]: Is it okay to remove this check to accommodate stateless accounts?
        // assert!(account::exists_at(payee_address), error::invalid_argument(EROYALTY_PAYEE_ACCOUNT_DOES_NOT_EXIST));
        Royalty {
            royalty_points_numerator,
            royalty_points_denominator,
            payee_address
        }
    }
```

**File:** aptos-move/framework/aptos-token/sources/token.move (L1249-1267)
```text
    public fun create_tokendata(
        account: &signer,
        collection: String,
        name: String,
        description: String,
        maximum: u64,
        uri: String,
        royalty_payee_address: address,
        royalty_points_denominator: u64,
        royalty_points_numerator: u64,
        token_mutate_config: TokenMutabilityConfig,
        property_keys: vector<String>,
        property_values: vector<vector<u8>>,
        property_types: vector<String>
    ): TokenDataId acquires Collections {
        assert!(name.length() <= MAX_NFT_NAME_LENGTH, error::invalid_argument(ENFT_NAME_TOO_LONG));
        assert!(collection.length() <= MAX_COLLECTION_NAME_LENGTH, error::invalid_argument(ECOLLECTION_NAME_TOO_LONG));
        assert!(uri.length() <= MAX_URI_LENGTH, error::invalid_argument(EURI_TOO_LONG));
        assert!(royalty_points_numerator <= royalty_points_denominator, error::invalid_argument(EINVALID_ROYALTY_NUMERATOR_DENOMINATOR));
```

**File:** aptos-move/framework/aptos-token-objects/sources/royalty.move (L54-56)
```text
    public fun create(numerator: u64, denominator: u64, payee_address: address): Royalty {
        assert!(denominator != 0, error::out_of_range(EROYALTY_DENOMINATOR_IS_ZERO));
        assert!(numerator <= denominator, error::out_of_range(EROYALTY_EXCEEDS_MAXIMUM));
```

**File:** aptos-move/move-examples/marketplace/sources/token_offer.move (L384-384)
```text
        let royalty_charge = price * royalty_numerator / royalty_denominator;
```

**File:** crates/indexer/src/models/token_models/token_datas.rs (L122-125)
```rust
                        royalty_points_denominator: token_data
                            .royalty
                            .royalty_points_denominator
                            .clone(),
```

**File:** aptos-move/move-examples/marketplace/sources/listing.move (L293-299)
```text
    public inline fun bounded_percentage(amount: u64, numerator: u64, denominator: u64): u64 {
        if (denominator == 0) {
            0
        } else {
            math64::min(amount, math64::mul_div(amount, numerator, denominator))
        }
    }
```
