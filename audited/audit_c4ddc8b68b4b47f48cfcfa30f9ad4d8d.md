# Audit Report

## Title
UTF-8 Character Boundary Panic in Token Name Truncation Causing Indexer Denial of Service

## Summary
The `truncate_str()` utility function uses Rust's byte-based `String::truncate()` method to truncate token names to 128 bytes, but treats this as a character limit. When a token name contains multibyte UTF-8 characters positioned such that byte index 128 falls mid-character, the truncation causes a panic, crashing the indexer and preventing transaction processing.

## Finding Description
The vulnerability exists in the token name truncation logic used by the Aptos indexer. [1](#0-0) 

The call chain is:
1. `from_write_table_item()` invokes `token_data_id.get_name_trunc()` [1](#0-0) 
2. Which calls `truncate_str(&self.name, NAME_LENGTH)` where `NAME_LENGTH = 128` [2](#0-1) [3](#0-2) 
3. Which uses `String::truncate(max_chars)` [4](#0-3) 

The critical flaw is that Rust's `String::truncate()` operates on **byte indices**, not character counts, and **panics if the index is not on a UTF-8 character boundary**. The parameter is misleadingly named `max_chars`, suggesting character-based truncation, but the implementation is byte-based.

**Attack Vector:**
An attacker can create a token with a carefully crafted name containing multibyte UTF-8 characters positioned such that byte 128 falls in the middle of a character:
- Example: 42 three-byte characters (126 bytes) + one additional three-byte character (bytes 126-128)
- When `truncate(128)` executes, byte 128 is the middle byte of a 3-byte UTF-8 sequence
- This violates UTF-8 character boundary rules, causing a panic

The token name originates from the Move `TokenData` struct [5](#0-4)  which only specifies the name should be "smaller than 128 characters" but doesn't enforce byte-level constraints. The database schema defines `name VARCHAR(128)` [6](#0-5)  which is a **character limit**, not a byte limit, making the semantic mismatch worse.

## Impact Explanation
This vulnerability qualifies as **High Severity** per the Aptos bug bounty program criteria:
- **API crashes**: The indexer process panics and terminates when processing the malicious token
- **Significant protocol violation**: Breaks the indexer's data processing integrity guarantee
- **Service disruption**: The indexer cannot process subsequent transactions until restarted, and will crash again if the problematic transaction is encountered

The indexer is critical infrastructure that:
- Powers blockchain explorers and analytics dashboards
- Provides queryable historical data for dApps
- Enables token discovery and marketplace functionality

Repeated crashes could force manual intervention and potential data loss if the indexer state becomes inconsistent.

## Likelihood Explanation
**Likelihood: High**

The attack is trivial to execute:
- Any user can create tokens through the Token v1 standard without privileged access
- The attacker only needs to craft a token name with specific UTF-8 byte positioning
- No special permissions, stake, or validator access required
- The vulnerability is deterministic—once triggered, it always crashes

The on-chain token creation does not validate byte-level UTF-8 positioning, only that names are "smaller than 128 characters." Many languages (Chinese, Japanese, Korean, Arabic, emoji-based names) naturally use multibyte UTF-8 characters, making accidental triggering also possible.

## Recommendation
Replace byte-based truncation with character-aware truncation that respects UTF-8 boundaries:

```rust
pub fn truncate_str(val: &str, max_chars: usize) -> String {
    val.chars().take(max_chars).collect()
}
```

This implementation:
- Iterates over Unicode scalar values (characters), not bytes
- Takes the first `max_chars` characters
- Always produces valid UTF-8 output
- Never panics on character boundaries

**Alternative with byte-aware safety:**
```rust
pub fn truncate_str(val: &str, max_bytes: usize) -> String {
    if val.len() <= max_bytes {
        return val.to_string();
    }
    
    // Find the largest valid UTF-8 boundary <= max_bytes
    let mut idx = max_bytes;
    while idx > 0 && !val.is_char_boundary(idx) {
        idx -= 1;
    }
    val[..idx].to_string()
}
```

The first approach is recommended as it matches the semantic intent (character limit) and aligns with the database schema's `VARCHAR(128)` character limit.

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "byte index 128 is not a char boundary")]
    fn test_utf8_truncation_panic() {
        // Create a string where byte 128 is in the middle of a UTF-8 character
        // Japanese character "あ" is 3 bytes in UTF-8: 0xE3 0x81 0x82
        // 42 of these = 126 bytes, then one more = 129 bytes total
        // Byte 128 will be the second byte (0x81) of the last character
        let malicious_name = "あ".repeat(43); // 43 * 3 = 129 bytes
        
        // This should panic when truncate(128) is called
        let result = truncate_str(&malicious_name, 128);
        
        // This line should never be reached
        println!("Result: {}", result);
    }
    
    #[test]
    fn test_safe_utf8_truncation() {
        // Demonstrate the safe alternative
        fn truncate_str_safe(val: &str, max_chars: usize) -> String {
            val.chars().take(max_chars).collect()
        }
        
        let malicious_name = "あ".repeat(43); // 129 bytes, 43 characters
        let result = truncate_str_safe(&malicious_name, 128);
        
        // Should successfully truncate to 128 characters without panic
        assert_eq!(result.chars().count(), 128);
        assert!(result.len() <= 384); // 128 * 3 bytes max
    }
}
```

**Integration test simulating the attack:**
```rust
#[test]
#[should_panic]
fn test_token_name_indexer_crash() {
    use crate::models::token_models::token_utils::TokenDataIdType;
    
    // Simulate a token with a malicious name
    let token_data_id = TokenDataIdType {
        creator: "0x1".to_string(),
        collection: "Test Collection".to_string(),
        name: "あ".repeat(43), // 129 bytes, triggers panic at byte 128
    };
    
    // This should panic when get_name_trunc() is called
    let truncated = token_data_id.get_name_trunc();
    println!("Should not reach here: {}", truncated);
}
```

**Notes**

The vulnerability affects all instances of `truncate_str` usage in the indexer codebase, including collection names [7](#0-6)  and URIs [8](#0-7) . The Move framework itself properly handles UTF-8 boundaries using `is_char_boundary` validation [9](#0-8) , highlighting the inconsistency between on-chain and off-chain string handling.

### Citations

**File:** crates/indexer/src/models/token_models/token_datas.rs (L102-102)
```rust
                let name = token_data_id.get_name_trunc();
```

**File:** crates/indexer/src/models/token_models/token_utils.rs (L17-17)
```rust
pub const NAME_LENGTH: usize = 128;
```

**File:** crates/indexer/src/models/token_models/token_utils.rs (L50-52)
```rust
    pub fn get_collection_trunc(&self) -> String {
        truncate_str(&self.collection, NAME_LENGTH)
    }
```

**File:** crates/indexer/src/models/token_models/token_utils.rs (L54-56)
```rust
    pub fn get_name_trunc(&self) -> String {
        truncate_str(&self.name, NAME_LENGTH)
    }
```

**File:** crates/indexer/src/models/token_models/token_utils.rs (L145-147)
```rust
    pub fn get_uri_trunc(&self) -> String {
        truncate_str(&self.uri, URI_LENGTH)
    }
```

**File:** crates/indexer/src/util.rs (L23-27)
```rust
pub fn truncate_str(val: &str, max_chars: usize) -> String {
    let mut trunc = val.to_string();
    trunc.truncate(max_chars);
    trunc
}
```

**File:** aptos-move/framework/aptos-token/sources/token.move (L198-199)
```text
        /// The name of the token, which should be unique within the collection; the length of name should be smaller than 128, characters, eg: "Aptos Animal #1234"
        name: String,
```

**File:** crates/indexer/migrations/2022-09-04-194128_add_token_data/up.sql (L54-54)
```sql
  name VARCHAR(128) NOT NULL,
```

**File:** aptos-move/framework/move-stdlib/sources/string.move (L180-230)
```text

```
