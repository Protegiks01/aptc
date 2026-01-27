# Audit Report

## Title
Panic-Induced DoS via Non-ASCII Characters in Transaction Filter Address Standardization

## Summary
The `standardize_address()` function in the indexer-grpc transaction filter crashes when processing addresses containing non-ASCII UTF-8 characters due to byte-based string slicing that violates character boundaries. This allows any gRPC client to crash the indexer service by sending a transaction filter with a malformed address string. [1](#0-0) 

## Finding Description
The vulnerability exists in two places within the `standardize_address()` function:

**Panic Condition 1 - Line 16:** The code performs byte-based string slicing without validating UTF-8 character boundaries. When `trimmed` ends with a multi-byte UTF-8 character (e.g., "abcdé" where 'é' is 2 bytes), the slice operation `trimmed[..trimmed.len().saturating_sub(1)]` attempts to split in the middle of the multi-byte character, causing a panic with "byte index X is not a char boundary". [2](#0-1) 

**Panic Condition 2 - Line 33:** The padding calculation uses `trimmed.len()` which returns byte count, not character count. If `trimmed` contains more than 64 bytes (achievable with ~50 multi-byte characters), the expression `64 - trimmed.len()` underflows or produces a value exceeding the ZEROS constant length (64 characters), causing an index-out-of-bounds panic. [3](#0-2) 

The function is invoked when processing user-provided transaction filters through the gRPC API. Users can specify a `UserTransactionFilter` with a `sender` address field, which accepts arbitrary UTF-8 strings without validation. [4](#0-3) [5](#0-4) 

The protobuf definition allows any UTF-8 string for the sender field with no format constraints: [6](#0-5) 

## Impact Explanation
This vulnerability causes **API crashes**, which is classified as **High Severity** (up to $50,000) in the Aptos bug bounty program. The indexer-grpc service crashes when processing malicious filter requests, causing denial of service for all clients relying on the indexer API for transaction querying and data aggregation. While this does not directly affect blockchain consensus or validator nodes, it disrupts the availability of critical infrastructure services used by dApps, wallets, and analytics platforms.

## Likelihood Explanation
**Likelihood: High**

The attack requires minimal effort:
1. Attacker identifies the public gRPC endpoint for the indexer service
2. Attacker crafts a `GetTransactionsRequest` with a `UserTransactionFilter` containing a sender address like "0xabcdé"
3. Service crashes upon processing the filter

No authentication or special privileges are required. The attack can be automated and repeated. The vulnerability is present in any deployment using the transaction-filter component for gRPC indexer services.

## Recommendation
Implement proper input validation and use character-based operations instead of byte-based slicing:

```rust
pub fn standardize_address(address: &str) -> Result<String, String> {
    // Validate that address contains only ASCII hex characters and optional 0x prefix
    let trimmed = address.strip_prefix("0x").unwrap_or(address);
    
    // Validate all characters are ASCII hex digits
    if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Address must contain only hexadecimal characters".to_string());
    }
    
    // Now safe to use byte operations since all chars are single-byte ASCII
    if let Some(last_char) = trimmed.chars().last() {
        if trimmed.len() > 1 && trimmed[..trimmed.len() - 1].chars().all(|c| c == '0')
            && last_char.is_ascii_hexdigit()
            && last_char <= 'f'
        {
            return Ok(format!("0x{}", last_char));
        }
    }
    
    // Validate length doesn't exceed maximum
    if trimmed.len() > 64 {
        return Err("Address exceeds maximum length".to_string());
    }
    
    Ok(format!("0x{:0>64}", trimmed))
}
```

Additionally, update the validation logic to reject invalid addresses: [7](#0-6) 

## Proof of Concept
```rust
#[cfg(test)]
mod panic_test {
    use super::*;

    #[test]
    #[should_panic(expected = "byte index")]
    fn test_panic_with_multibyte_char_at_end() {
        // UTF-8 character 'é' is 2 bytes (0xC3 0xA9)
        // This will panic when trying to slice at byte boundary
        let malicious_address = "0xabcdé";
        let _ = standardize_address(malicious_address);
    }

    #[test]
    #[should_panic]
    fn test_panic_with_oversized_multibyte_string() {
        // Create a string with many multi-byte characters exceeding 64 bytes
        let malicious_address = format!("0x{}", "é".repeat(50)); // 100 bytes
        let _ = standardize_address(&malicious_address);
    }
}
```

## Notes
This vulnerability is specific to the indexer-grpc transaction filter component and does not affect core blockchain consensus, Move VM execution, or validator operations. However, it represents a significant availability issue for ecosystem infrastructure that relies on indexer services for data access.

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

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/user_transaction.rs (L39-45)
```rust
    fn get_standardized_sender(&self) -> &Option<String> {
        self.standardized_sender.get_or_init(|| {
            self.sender
                .clone()
                .map(|address| standardize_address(&address))
        })
    }
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/user_transaction.rs (L74-80)
```rust
    fn validate_state(&self) -> Result<(), FilterError> {
        if self.sender.is_none() && self.payload.is_none() {
            return Err(Error::msg("At least one of sender or payload must be set").into());
        };
        self.payload.is_valid()?;
        Ok(())
    }
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/user_transaction.rs (L94-97)
```rust
        if let Some(sender_filter) = self.get_standardized_sender() {
            if &standardize_address(&user_request.sender) != sender_filter {
                return false;
            }
```

**File:** protos/proto/aptos/indexer/v1/filter.proto (L33-36)
```text
message UserTransactionFilter {
  optional string sender = 1;
  optional UserTransactionPayloadFilter payload_filter = 2;
}
```
