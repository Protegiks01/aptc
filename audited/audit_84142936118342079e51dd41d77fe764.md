# Audit Report

## Title
Case-Insensitive Address Comparison Vulnerability in Transaction Filter Causing Filter Bypass

## Summary
The `standardize_address()` function in the indexer-grpc transaction filter preserves the case of uppercase hex characters ('A'-'F') in special addresses, while blockchain addresses are always serialized in lowercase. This creates a comparison mismatch where filters with uppercase special addresses (e.g., "0xF") fail to match transactions with lowercase addresses (e.g., "0xf"), causing indexer inconsistencies and filter bypasses.

## Finding Description
The vulnerability exists in the special address detection logic at line 20 of `standardize_address()`. [1](#0-0) 

The check `last_char <= 'f'` allows uppercase hex characters 'A'-'F' (ASCII 65-70) to pass since they are numerically less than lowercase 'f' (ASCII 102). However, the function then preserves the case of the input character when returning the standardized address. [2](#0-1) 

According to the Aptos core implementation, all addresses from the blockchain are serialized using lowercase hex encoding. [3](#0-2)  The `hex::encode()` function always produces lowercase output, meaning special addresses like 0xa through 0xf will always appear as lowercase from the blockchain.

When transaction filters are applied, the filter address and transaction address are both passed through `standardize_address()` and then compared. [4](#0-3) 

**Attack Scenario:**
1. User creates a filter for sender address "0xF" (uppercase)
2. Filter standardizes to "0xF" (case preserved)
3. Transaction from blockchain has sender "0xf" (lowercase, as per blockchain serialization)
4. Transaction sender standardizes to "0xf"
5. Comparison: "0xF" != "0xf" → Filter fails to match
6. User misses transactions they intended to track

Similarly, module address filters suffer from the same issue. [5](#0-4) 

## Impact Explanation
This is a **Medium severity** issue classified as "State inconsistencies requiring intervention" per the Aptos bug bounty criteria. The vulnerability causes:

1. **Indexer Data Inconsistency**: Filters fail to match legitimate transactions, causing incomplete indexing results
2. **System Monitoring Failures**: Critical monitoring systems relying on transaction filters may miss important transactions (e.g., transfers to/from special addresses like 0x1-0xf, which include core framework addresses)
3. **User Experience Degradation**: Users cannot reliably filter transactions involving special addresses if they use uppercase hex notation

While this doesn't directly affect consensus or on-chain state, it breaks the correctness guarantees of the indexer filtering system, requiring manual intervention to identify missed transactions.

## Likelihood Explanation
**Likelihood: High**

This issue will occur whenever:
- Users specify filters with uppercase hex characters for special addresses (0xA through 0xF)
- Transactions interact with these special addresses (common, as 0x1-0xa are framework addresses)

The vulnerability is easily triggered without any special privileges or complex attack setup. Users naturally may use uppercase hex notation (e.g., "0xA" instead of "0xa"), as both are valid hex representations. The blockchain will always return lowercase, guaranteeing a mismatch.

## Recommendation
Convert hex characters to lowercase before using them in comparisons. Modify the `standardize_address()` function:

```rust
pub fn standardize_address(address: &str) -> String {
    // Remove "0x" prefix if it exists
    let trimmed = address.strip_prefix("0x").unwrap_or(address);

    // Check if the address is a special address
    if let Some(last_char) = trimmed.chars().last() {
        if trimmed[..trimmed.len().saturating_sub(1)]
            .chars()
            .all(|c| c == '0')
            && last_char.is_ascii_hexdigit()
            && last_char.to_ascii_lowercase() <= 'f'  // FIXED: Convert to lowercase for comparison
        {
            // Return special addresses in short format with lowercase hex
            let mut result = String::with_capacity(3);
            result.push_str("0x");
            result.push(last_char.to_ascii_lowercase());  // FIXED: Store lowercase
            return result;
        }
    }

    // Return non-special addresses in long format with lowercase hex
    let mut result = String::with_capacity(66);
    result.push_str("0x");
    result.push_str(&ZEROS[..64 - trimmed.len()]);
    result.push_str(&trimmed.to_lowercase());  // FIXED: Convert to lowercase
    result
}
```

## Proof of Concept

```rust
#[test]
fn test_uppercase_hex_special_address_mismatch() {
    // Addresses that should be equal after standardization
    let uppercase_filter = standardize_address("0xF");
    let lowercase_blockchain = standardize_address("0xf");
    
    // BUG: These should be equal but aren't
    assert_ne!(uppercase_filter, lowercase_blockchain);
    assert_eq!(uppercase_filter, "0xF");  // Preserves uppercase
    assert_eq!(lowercase_blockchain, "0xf");  // Preserves lowercase
    
    // This demonstrates that a filter with "0xF" would fail to match
    // a transaction with sender "0xf" from the blockchain
}

#[test]
fn test_uppercase_hex_range() {
    // All uppercase special addresses A-F are incorrectly preserved
    for ch in 'A'..='F' {
        let addr = format!("0x{}", ch);
        let standardized = standardize_address(&addr);
        // BUG: Should be lowercase but preserves case
        assert_eq!(standardized, addr);
    }
}

#[test]
fn test_mixed_case_long_address() {
    // Even non-special addresses preserve case incorrectly
    let mixed = standardize_address("0xABCD");
    // BUG: Should normalize to lowercase
    assert!(mixed.contains("ABCD"));
}
```

Run with: `cargo test --package aptos-transaction-filter test_uppercase_hex`

## Notes
The vulnerability specifically affects special addresses 0xA through 0xF (and 0xa through 0xf), as these are the only hex digits that have both uppercase and lowercase representations. Addresses 0x0-0x9 are unaffected since digits don't have case variants. The issue extends beyond special addresses to all addresses in the long form that contain 'A'-'F' characters, though the impact is most severe for special addresses due to their use as framework addresses.

### Citations

**File:** ecosystem/indexer-grpc/transaction-filter/src/utils.rs (L20-20)
```rust
            && last_char <= 'f'
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/utils.rs (L22-26)
```rust
            // Return special addresses in short format
            let mut result = String::with_capacity(3);
            result.push_str("0x");
            result.push(last_char);
            return result;
```

**File:** third_party/move/move-core/types/src/account_address.rs (L132-134)
```rust
    pub fn to_canonical_string(&self) -> String {
        hex::encode(self.0)
    }
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/user_transaction.rs (L94-97)
```rust
        if let Some(sender_filter) = self.get_standardized_sender() {
            if &standardize_address(&user_request.sender) != sender_filter {
                return false;
            }
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/user_transaction.rs (L198-201)
```rust
                if !(self
                    .get_standardized_address()
                    .matches(&standardize_address(&module.address))
                    && self.module.matches(&module.name))
```
