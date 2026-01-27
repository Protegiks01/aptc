# Audit Report

## Title
Case-Sensitive Address Matching in Indexer Transaction Filter Causes User Transaction Discovery Failures

## Summary
The `standardize_address()` function in the indexer transaction filter preserves the case of hexadecimal characters, while blockchain addresses are always serialized in lowercase. This creates a mismatch when users or explorers query with uppercase addresses, causing legitimate transactions to be filtered out and not displayed.

## Finding Description

The vulnerability exists in the address standardization and matching logic used by the indexer transaction filter system. [1](#0-0) 

The `standardize_address()` function implements AIP-40 display format but **preserves the original case** of the input address. For special addresses (0x0-0xf), it returns "0x" + the last character as-is. For non-special addresses, it pads with zeros but keeps the original hex characters' case.

However, when addresses are serialized from the blockchain's `AccountAddress` type, they are **always lowercase**: [2](#0-1) 

The `AccountAddress::serialize()` method calls `self.to_hex()` which uses the `{:x}` formatter, producing lowercase hex output.

When the filter performs matching, it uses direct string comparison after standardization: [3](#0-2) [4](#0-3) 

The `Option<String>::matches()` implementation uses direct equality (`filter == item`), which is case-sensitive in Rust.

**Attack Scenario:**
1. User has address `0xa` (lowercase) on blockchain
2. Explorer allows searching with `0xA` (uppercase)
3. Filter standardizes user query: `standardize_address("0xA")` → `"0xA"`
4. Transaction from blockchain has sender: `"0xa"` (lowercase)
5. Filter standardizes blockchain address: `standardize_address("0xa")` → `"0xa"`
6. Comparison: `"0xA" != "0xa"` → **NO MATCH**
7. User's legitimate transactions are not displayed

## Impact Explanation

This issue falls under **Medium Severity** based on the following:

- **User Experience Damage**: Users searching for their address in uppercase/mixed case will not find their transactions, creating confusion and eroding trust in the explorer
- **Cross-Explorer Inconsistency**: Different explorers may adopt different case conventions, leading to inconsistent user experiences across platforms
- **Non-Obvious Failure**: Users won't receive an error message; their transactions simply won't appear, making debugging difficult
- **Widespread Effect**: Affects all special addresses (0x0-0xf) and any address where users might naturally use uppercase hex digits

While this doesn't cause fund loss or consensus issues, it represents a **state inconsistency** between what exists on-chain and what users can discover through the indexer API, potentially requiring manual intervention to resolve user support issues.

## Likelihood Explanation

**High Likelihood** - This will occur whenever:
- Users copy addresses from sources that use uppercase hex (common in many tools/explorers)
- Explorers implement search without normalizing address case
- Users manually type addresses with uppercase letters (natural for readability)

The issue is **deterministic** and **easily reproducible** without any special conditions or attacker sophistication.

## Recommendation

Normalize all addresses to lowercase before comparison. Modify the `standardize_address()` function to convert the input to lowercase:

```rust
pub fn standardize_address(address: &str) -> String {
    // Remove "0x" prefix if it exists and convert to lowercase
    let trimmed = address
        .strip_prefix("0x")
        .unwrap_or(address)
        .to_lowercase();  // <-- ADD THIS
    
    // Rest of the function remains the same...
}
```

This ensures that regardless of input case, addresses are normalized to the canonical lowercase format used by the blockchain, enabling consistent matching.

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_case_sensitivity_bug() {
        // Demonstrate that uppercase and lowercase produce different results
        let lowercase_addr = "0xa";
        let uppercase_addr = "0xA";
        
        let standardized_lower = standardize_address(lowercase_addr);
        let standardized_upper = standardize_address(uppercase_addr);
        
        // BUG: These should be equal but they're not!
        assert_ne!(standardized_lower, standardized_upper);
        assert_eq!(standardized_lower, "0xa");  // lowercase
        assert_eq!(standardized_upper, "0xA");  // uppercase - causes mismatch!
        
        // In real usage, blockchain will send "0xa" but user might query "0xA"
        // This causes the filter to miss legitimate transactions
        println!("Blockchain address: {}", standardized_lower);
        println!("User query address: {}", standardized_upper);
        println!("Match result: {}", standardized_lower == standardized_upper); // false!
    }
    
    #[test]
    fn test_non_special_address_case_sensitivity() {
        let lowercase = "0xabcdef";
        let uppercase = "0xABCDEF";
        
        let std_lower = standardize_address(lowercase);
        let std_upper = standardize_address(uppercase);
        
        // BUG: Different results for same logical address
        assert_ne!(std_lower, std_upper);
    }
}
```

## Notes

- This issue affects the indexer transaction filter, which is used by explorers and other applications to query blockchain data
- The root cause is that Rust's string equality is case-sensitive, and the standardization function doesn't normalize case
- AIP-40 address format specification should be interpreted as case-insensitive for matching purposes
- The fix is simple: convert to lowercase during standardization to match the blockchain's canonical format
- This is a data consistency issue between the indexer API and the underlying blockchain representation

### Citations

**File:** ecosystem/indexer-grpc/transaction-filter/src/utils.rs (L10-36)
```rust
pub fn standardize_address(address: &str) -> String {
    // Remove "0x" prefix if it exists
    let trimmed = address.strip_prefix("0x").unwrap_or(address);

    // Check if the address is a special address by seeing if the first 31 bytes are zero and the last byte is smaller than 0b10000
    if let Some(last_char) = trimmed.chars().last() {
        if trimmed[..trimmed.len().saturating_sub(1)]
            .chars()
            .all(|c| c == '0')
            && last_char.is_ascii_hexdigit()
            && last_char <= 'f'
        {
            // Return special addresses in short format
            let mut result = String::with_capacity(3);
            result.push_str("0x");
            result.push(last_char);
            return result;
        }
    }

    // Return non-special addresses in long format
    let mut result = String::with_capacity(66);
    result.push_str("0x");
    result.push_str(&ZEROS[..64 - trimmed.len()]);
    result.push_str(trimmed);
    result
}
```

**File:** third_party/move/move-core/types/src/account_address.rs (L428-440)
```rust
impl Serialize for AccountAddress {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            self.to_hex().serialize(serializer)
        } else {
            // See comment in deserialize.
            serializer.serialize_newtype_struct("AccountAddress", &self.0)
        }
    }
}
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/user_transaction.rs (L93-98)
```rust

        if let Some(sender_filter) = self.get_standardized_sender() {
            if &standardize_address(&user_request.sender) != sender_filter {
                return false;
            }
        }
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/traits.rs (L108-121)
```rust
impl Filterable<String> for Option<String> {
    #[inline]
    fn validate_state(&self) -> Result<(), FilterError> {
        Ok(())
    }

    #[inline]
    fn matches(&self, item: &String) -> bool {
        match self {
            Some(filter) => filter == item,
            None => true,
        }
    }
}
```
