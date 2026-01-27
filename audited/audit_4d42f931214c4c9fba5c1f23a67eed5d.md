# Audit Report

## Title
V1 Token Description Field Lacks Length Validation Leading to Indexer Database Storage and Query Performance Issues

## Summary
The Aptos Token V1 standard (0x3::token) does not validate the length of token and collection description fields during creation, allowing descriptions up to the transaction size limit (~64KB). While V2 tokens enforce a 2048-byte limit, the indexer does not truncate descriptions when storing them to the database, potentially causing excessive storage consumption and query performance degradation.

## Finding Description
The vulnerability exists across two layers:

**Layer 1: Missing On-Chain Validation in V1 Token Standard**

The V1 token Move framework validates name and URI lengths but omits description validation: [1](#0-0) 

For token creation, the validation is similarly incomplete: [2](#0-1) 

In contrast, V2 tokens enforce MAX_DESCRIPTION_LENGTH = 2048: [3](#0-2) [4](#0-3) 

**Layer 2: No Truncation in Indexer**

The indexer stores descriptions without validation or truncation. Unlike name and URI fields which use truncation functions: [5](#0-4) 

The description field is directly cloned without truncation: [6](#0-5) 

**Database Schema**

The database uses unbounded TEXT fields: [7](#0-6) 

**Transaction Size Limit**

The maximum transaction size is 64KB: [8](#0-7) 

**Attack Scenario:**
1. Attacker creates V1 tokens/collections with descriptions approaching 60KB each
2. Each description consumes excessive database storage
3. Queries fetching multiple tokens experience performance degradation
4. Mass creation could lead to database bloat and slow indexer performance

## Impact Explanation
This is classified as **Low Severity** per Aptos Bug Bounty criteria because:

1. **No consensus impact**: Does not affect blockchain state, Move VM execution, or validator operations
2. **Off-chain component only**: Affects the indexer database, not the core blockchain
3. **No fund loss**: Cannot lead to theft, minting, or freezing of assets
4. **Limited availability impact**: Only affects indexer query performance, not network liveness
5. **Bounded per-token impact**: Limited to ~60KB per token by transaction size constraints

While this could degrade user experience through slower API responses and increased infrastructure costs, it does not compromise any critical blockchain security invariants.

## Likelihood Explanation
**Likelihood: Medium**

- Gas costs make mass exploitation expensive but not prohibitive
- V1 tokens are still actively used on Aptos mainnet
- Attack requires only standard token creation permissions
- No technical barriers prevent exploitation

However, the limited real-world impact reduces the actual risk.

## Recommendation
Implement consistent description length validation:

1. **Move Framework (V1 tokens)**: Add MAX_DESCRIPTION_LENGTH validation to V1 token creation functions
2. **Indexer Layer**: Apply truncation to description fields as defensive measure

```rust
// In v2_token_datas.rs
const MAX_DESCRIPTION_LENGTH: usize = 2048;

pub fn get_description_trunc(description: &str) -> String {
    truncate_str(description, MAX_DESCRIPTION_LENGTH)
}

// Apply in get_v2_from_write_resource:
description: get_description_trunc(&inner.description),
```

## Proof of Concept
```move
// V1 Token with large description (simplified)
module attacker::large_description_exploit {
    use aptos_token::token;
    use std::string;
    use std::vector;
    
    public entry fun create_bloated_token(creator: &signer) {
        // Create collection
        let name = string::utf8(b"Bloated Collection");
        let large_description = build_large_string(60000); // ~60KB
        let uri = string::utf8(b"https://example.com");
        
        token::create_collection(
            creator,
            name,
            large_description, // No validation - this succeeds
            uri,
            1000000,
            vector[false, false, false]
        );
    }
    
    fun build_large_string(size: u64): string::String {
        let v = vector::empty<u8>();
        let i = 0;
        while (i < size) {
            vector::push_back(&mut v, 65); // 'A'
            i = i + 1;
        };
        string::utf8(v)
    }
}
```

---

**Note**: While this vulnerability is technically valid, it falls below the Medium severity threshold required by the validation checklist. The issue affects only the off-chain indexer component and does not compromise any critical blockchain security invariants (consensus, Move VM safety, state consistency, funds security, or governance integrity). Per the bug bounty program, this qualifies as Low Severity ($1,000 maximum) for "non-critical implementation bugs."

### Citations

**File:** aptos-move/framework/aptos-token/sources/token.move (L1161-1170)
```text
    public fun create_collection(
        creator: &signer,
        name: String,
        description: String,
        uri: String,
        maximum: u64,
        mutate_setting: vector<bool>
    ) acquires Collections {
        assert!(name.length() <= MAX_COLLECTION_NAME_LENGTH, error::invalid_argument(ECOLLECTION_NAME_TOO_LONG));
        assert!(uri.length() <= MAX_URI_LENGTH, error::invalid_argument(EURI_TOO_LONG));
```

**File:** aptos-move/framework/aptos-token/sources/token.move (L1249-1266)
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
```

**File:** aptos-move/framework/aptos-token-objects/sources/token.move (L41-44)
```text
    const MAX_TOKEN_NAME_LENGTH: u64 = 128;
    const MAX_TOKEN_SEED_LENGTH: u64 = 128;
    const MAX_URI_LENGTH: u64 = 512;
    const MAX_DESCRIPTION_LENGTH: u64 = 2048;
```

**File:** aptos-move/framework/aptos-token-objects/sources/token.move (L220-221)
```text
        assert!(description.length() <= MAX_DESCRIPTION_LENGTH, error::out_of_range(EDESCRIPTION_TOO_LONG));
        assert!(uri.length() <= MAX_URI_LENGTH, error::out_of_range(EURI_TOO_LONG));
```

**File:** crates/indexer/src/models/token_models/v2_token_utils.rs (L196-202)
```rust
    pub fn get_uri_trunc(&self) -> String {
        truncate_str(&self.uri, URI_LENGTH)
    }

    pub fn get_name_trunc(&self) -> String {
        truncate_str(&self.name, NAME_LENGTH)
    }
```

**File:** crates/indexer/src/models/token_models/v2_token_datas.rs (L111-127)
```rust
            let collection_id = inner.get_collection_address();
            let token_name = inner.get_name_trunc();
            let token_uri = inner.get_uri_trunc();

            Ok(Some((
                Self {
                    transaction_version: txn_version,
                    write_set_change_index,
                    token_data_id: token_data_id.clone(),
                    collection_id: collection_id.clone(),
                    token_name: token_name.clone(),
                    maximum: maximum.clone(),
                    supply: supply.clone(),
                    largest_property_version_v1: None,
                    token_uri: token_uri.clone(),
                    token_properties: token_properties.clone(),
                    description: inner.description.clone(),
```

**File:** crates/indexer/migrations/2023-04-28-053048_object_token_v2/up.sql (L127-138)
```sql
CREATE TABLE IF NOT EXISTS token_datas_v2 (
  transaction_version BIGINT NOT NULL,
  write_set_change_index BIGINT NOT NULL,
  token_data_id VARCHAR(66) NOT NULL,
  collection_id VARCHAR(66) NOT NULL,
  token_name VARCHAR(128) NOT NULL,
  maximum NUMERIC,
  supply NUMERIC NOT NULL,
  largest_property_version_v1 NUMERIC,
  token_uri VARCHAR(512) NOT NULL,
  token_properties JSONB NOT NULL,
  description TEXT NOT NULL,
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L73-76)
```rust
            max_transaction_size_in_bytes: NumBytes,
            "max_transaction_size_in_bytes",
            64 * 1024
        ],
```
