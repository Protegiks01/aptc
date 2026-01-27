# Audit Report

## Title
Indexer Hash Collision Vulnerability via Delimiter Injection in Token Names

## Summary
The Aptos indexer computes `token_data_id_hash` values by concatenating creator address, collection name, and token name with `::` as a delimiter, then hashing the result. Since the on-chain Move contract does not prohibit `::` characters in collection or token names, attackers can craft tokens that produce identical hashes, causing database constraint violations or data corruption in the indexer.

## Finding Description

The indexer's hash computation is vulnerable to delimiter collision attacks. The vulnerability exists in the `TokenDataIdType::to_hash()` implementation: [1](#0-0) 

This method formats the token identifier using `Display`, which concatenates fields with `::`: [2](#0-1) 

The resulting string is then SHA-256 hashed: [3](#0-2) 

**The Attack Vector:**

An attacker can create two different on-chain tokens that produce identical hashes:
- **Token A**: `creator=0x1`, `collection="my"`, `name="token::evil"` → hash of `"0x0000...001::my::token::evil"`
- **Token B**: `creator=0x1`, `collection="my::token"`, `name="evil"` → hash of `"0x0000...001::my::token::evil"`

Both tokens produce the same string representation and therefore the same hash, despite being completely different tokens on-chain.

**Why This Works:**

The on-chain Move contract only validates string length, not content: [4](#0-3) [5](#0-4) 

Move's `String` type only requires valid UTF-8 encoding, which includes the `:` character. There is no validation preventing `::` in collection or token names.

**Impact on Indexer Tables:**

The `CurrentTokenData` table uses only the hash as primary key: [6](#0-5) 

When two tokens with colliding hashes exist, only one can be stored in `current_token_datas`, causing either:
1. Database constraint violation when inserting the second token
2. Silent data overwriting if using UPSERT logic

Similarly, `CurrentTokenOwnership` uses the hash in its composite primary key: [7](#0-6) 

If the same owner holds both colliding tokens with the same property version, the indexer cannot represent both ownerships correctly.

## Impact Explanation

This vulnerability qualifies as **HIGH severity** per Aptos bug bounty criteria under "API crashes" and "Significant protocol violations":

1. **API Availability**: Indexer failures from constraint violations would cause API endpoints serving token data to fail or return incomplete results, affecting all applications relying on these APIs (wallets, marketplaces, explorers).

2. **Data Integrity**: If the indexer silently overwrites colliding records, applications would display incorrect token ownership and metadata, potentially leading to:
   - Users unable to see tokens they own
   - Wrong token metadata displayed
   - Confusion attacks where Token B appears as Token A

3. **Ecosystem Impact**: Since the indexer is critical infrastructure for querying blockchain state (as on-chain queries are impractical for complex token queries), this affects the entire Aptos NFT ecosystem.

While this does not affect on-chain consensus or fund safety (on-chain state remains correct), it breaks the indexer's fundamental invariant of accurately reflecting on-chain state.

## Likelihood Explanation

**Likelihood: HIGH**

- **Attacker Requirements**: None. Any user can create collections and tokens permissionlessly.
- **Attack Complexity**: Trivial. Simply include `::` in token or collection names when creating tokens.
- **Detection Difficulty**: The attack is subtle—colliding tokens appear valid on-chain but cause indexer failures.
- **Exploitation Cost**: Minimal—just gas fees for token creation transactions.

An attacker could systematically create tokens with colliding hashes to:
1. Cause denial-of-service on the indexer
2. Make legitimate tokens "invisible" by collision
3. Create confusion by making malicious tokens appear as legitimate ones in applications

## Recommendation

**Immediate Fix**: Modify the hash computation to use a collision-resistant delimiter scheme:

```rust
impl fmt::Display for TokenDataIdType {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        // Use length-prefixed encoding to prevent delimiter collisions
        write!(
            f,
            "{}:{}:{}:{}:{}:{}",
            standardize_address(self.creator.as_str()),
            self.creator.len(),
            self.collection,
            self.collection.len(),
            self.name,
            self.name.len()
        )
    }
}
```

Or better, compute the hash over BCS-serialized bytes directly:

```rust
pub fn to_hash(&self) -> String {
    let serialized = bcs::to_bytes(self).expect("BCS serialization failed");
    hash_str(&hex::encode(&serialized))
}
```

**Long-term Fix**: Validate collection and token names on-chain to prohibit the `::` delimiter:

```move
public fun create_tokendata(
    // ... parameters ...
) {
    // Add validation
    assert!(!string::index_of(&name, &string::utf8(b"::")).is_some(), 
            error::invalid_argument(EINVALID_TOKEN_NAME));
    assert!(!string::index_of(&collection, &string::utf8(b"::")).is_some(), 
            error::invalid_argument(EINVALID_COLLECTION_NAME));
    // ... rest of function ...
}
```

## Proof of Concept

**Move Script (execute on Aptos testnet):**

```move
script {
    use aptos_token::token;
    use std::string;
    use std::signer;

    fun create_colliding_tokens(account: &signer) {
        // Create collection with :: in name
        token::create_collection(
            account,
            string::utf8(b"my::token"),
            string::utf8(b"Test collection"),
            string::utf8(b"https://example.com"),
            1000,
            vector[false, false, false]
        );

        // Create token in this collection
        token::create_tokendata(
            account,
            string::utf8(b"my::token"),
            string::utf8(b"evil"),
            string::utf8(b"Token B"),
            100,
            string::utf8(b"https://example.com/b"),
            signer::address_of(account),
            100,
            0,
            token::create_token_mutability_config(&vector[false, false, false, false, false]),
            vector[],
            vector[],
            vector[]
        );

        // Create normal collection
        token::create_collection(
            account,
            string::utf8(b"my"),
            string::utf8(b"Test collection 2"),
            string::utf8(b"https://example.com"),
            1000,
            vector[false, false, false]
        );

        // Create token with :: in name
        token::create_tokendata(
            account,
            string::utf8(b"my"),
            string::utf8(b"token::evil"),
            string::utf8(b"Token A"),
            100,
            string::utf8(b"https://example.com/a"),
            signer::address_of(account),
            100,
            0,
            token::create_token_mutability_config(&vector[false, false, false, false, false]),
            vector[],
            vector[],
            vector[]
        );
    }
}
```

**Expected Result**: Both tokens exist on-chain with different `TokenDataId` structs, but both produce hash of SHA256("0x<creator_address>::my::token::evil"). The indexer will fail to index both tokens correctly, causing database errors or missing token data in API responses.

**Verification**: Query the indexer API for both tokens and observe that only one appears, or check indexer logs for constraint violation errors.

## Notes

This vulnerability is specific to the indexer component and does not affect on-chain consensus, validator operation, or the safety of funds in smart contracts. However, given that the indexer is critical infrastructure for the Aptos ecosystem (powering wallets, explorers, and marketplaces), the practical impact is significant. The issue exemplifies a classic delimiter collision vulnerability where insufficient input validation allows crafted inputs to break assumptions in downstream systems.

### Citations

**File:** crates/indexer/src/models/token_models/token_utils.rs (L46-48)
```rust
    pub fn to_hash(&self) -> String {
        hash_str(&self.to_string())
    }
```

**File:** crates/indexer/src/models/token_models/token_utils.rs (L67-77)
```rust
impl fmt::Display for TokenDataIdType {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}::{}::{}",
            standardize_address(self.creator.as_str()),
            self.collection,
            self.name
        )
    }
}
```

**File:** crates/indexer/src/util.rs (L19-21)
```rust
pub fn hash_str(val: &str) -> String {
    hex::encode(sha2::Sha256::digest(val.as_bytes()))
}
```

**File:** aptos-move/framework/aptos-token/sources/token.move (L1169-1170)
```text
        assert!(name.length() <= MAX_COLLECTION_NAME_LENGTH, error::invalid_argument(ECOLLECTION_NAME_TOO_LONG));
        assert!(uri.length() <= MAX_URI_LENGTH, error::invalid_argument(EURI_TOO_LONG));
```

**File:** aptos-move/framework/aptos-token/sources/token.move (L1264-1266)
```text
        assert!(name.length() <= MAX_NFT_NAME_LENGTH, error::invalid_argument(ENFT_NAME_TOO_LONG));
        assert!(collection.length() <= MAX_COLLECTION_NAME_LENGTH, error::invalid_argument(ECOLLECTION_NAME_TOO_LONG));
        assert!(uri.length() <= MAX_URI_LENGTH, error::invalid_argument(EURI_TOO_LONG));
```

**File:** crates/indexer/src/models/token_models/token_datas.rs (L45-49)
```rust
#[derive(Debug, Deserialize, FieldCount, Identifiable, Insertable, Serialize)]
#[diesel(primary_key(token_data_id_hash))]
#[diesel(table_name = current_token_datas)]
pub struct CurrentTokenData {
    pub token_data_id_hash: String,
```

**File:** crates/indexer/src/models/token_models/token_ownerships.rs (L44-50)
```rust
#[derive(Debug, Deserialize, FieldCount, Identifiable, Insertable, Serialize)]
#[diesel(primary_key(token_data_id_hash, property_version, owner_address))]
#[diesel(table_name = current_token_ownerships)]
pub struct CurrentTokenOwnership {
    pub token_data_id_hash: String,
    pub property_version: BigDecimal,
    pub owner_address: String,
```
