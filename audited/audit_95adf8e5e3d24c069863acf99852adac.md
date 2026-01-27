# Audit Report

## Title
Integer Underflow in `standardize_address()` Causes Indexer gRPC API Crash via Malformed Filter Address

## Summary
The `standardize_address()` function in the indexer-grpc transaction-filter module lacks input validation on address string lengths. When processing user-provided filter addresses exceeding 64 characters, it attempts to compute `64 - trimmed.len()`, causing an integer underflow that panics and crashes the indexer gRPC service.

## Finding Description

The vulnerability exists in the address standardization logic used by the indexer's transaction filtering system. When users provide transaction filters via the gRPC API, they can specify addresses to filter by (e.g., sender addresses, module addresses, event struct addresses). These addresses are passed to `standardize_address()` without prior length validation. [1](#0-0) 

The function removes the "0x" prefix and checks if the address is a special address (lines 15-28). For non-special addresses, it attempts to pad with zeros at line 33 using the slice operation `&ZEROS[..64 - trimmed.len()]`. If `trimmed.len()` exceeds 64 characters, this subtraction causes integer underflow.

**Attack Path:**

1. Attacker crafts a gRPC `GetTransactionsRequest` with a malicious `BooleanTransactionFilter`
2. The filter contains a `UserTransactionFilter` with `sender` field set to a string of 100+ hex characters (e.g., "0x" + 100 hex digits)
3. During filter deserialization, the `From<protobuf>` trait conversion is invoked [2](#0-1) 

4. At line 55, `standardize_address(address)` is called with the oversized string
5. Similarly, `MoveStructTagFilter` and `EntryFunctionFilter` exhibit the same vulnerability [3](#0-2) 

6. The integer underflow occurs, causing a panic that crashes the indexer service

The filter validation in `BooleanTransactionFilter::new_from_proto()` only checks the total encoded protobuf size, not individual field content: [4](#0-3) 

The `validate_state()` methods only verify that required fields are set, not their content validity: [5](#0-4) 

## Impact Explanation

This vulnerability qualifies as **High Severity** per the Aptos bug bounty criteria because it causes **API crashes**. An unprivileged attacker can repeatedly crash the indexer gRPC service by sending malformed filter requests, causing a Denial of Service. This affects:

- Indexer service availability for all users
- Applications relying on the indexer for transaction data
- Developer tools and block explorers dependent on the indexer API

While this does not affect consensus or validator nodes directly, the indexer is a critical infrastructure component for ecosystem applications.

## Likelihood Explanation

The likelihood of exploitation is **Very High**:

- No authentication or privileged access required
- Trivial to exploit (send single malformed gRPC request)
- No rate limiting prevents repeated attacks
- Attack can be automated
- Protobuf allows arbitrarily long strings by design

The vulnerability will trigger in both debug and release builds, though the exact panic mechanism differs (debug: overflow panic, release: slice bounds panic after integer wrapping).

## Recommendation

Add input validation to `standardize_address()` to reject addresses exceeding the valid length:

```rust
pub fn standardize_address(address: &str) -> Result<String, &'static str> {
    let trimmed = address.strip_prefix("0x").unwrap_or(address);
    
    // Validate address length (max 64 hex characters for 32-byte address)
    if trimmed.len() > 64 {
        return Err("Address exceeds maximum length of 64 hex characters");
    }
    
    // Rest of function remains the same...
}
```

Alternatively, validate at the filter construction level before calling `standardize_address()`:

```rust
impl From<aptos_protos::indexer::v1::UserTransactionFilter> for UserTransactionFilter {
    fn from(proto_filter: aptos_protos::indexer::v1::UserTransactionFilter) -> Self {
        let standardized_sender = proto_filter.sender.as_ref().and_then(|address| {
            // Validate address length before standardization
            let trimmed = address.strip_prefix("0x").unwrap_or(address);
            if trimmed.len() <= 64 {
                Some(standardize_address(address))
            } else {
                None // Or log error and skip standardization
            }
        });
        
        Self {
            standardized_sender: OnceCell::with_value(standardized_sender),
            sender: proto_filter.sender,
            payload: proto_filter.payload_filter.map(|f| f.into()),
        }
    }
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod test_vulnerability {
    use super::*;

    #[test]
    #[should_panic]
    fn test_standardize_address_integer_underflow() {
        // Create an address string longer than 64 characters
        let malicious_address = format!("0x{}", "a".repeat(100));
        
        // This will panic due to integer underflow at line 33
        let _ = standardize_address(&malicious_address);
    }

    #[test]
    #[should_panic]
    fn test_user_transaction_filter_crash() {
        use aptos_protos::indexer::v1::UserTransactionFilter as ProtoFilter;
        
        // Create protobuf filter with oversized address
        let proto_filter = ProtoFilter {
            sender: Some(format!("0x{}", "f".repeat(100))),
            payload_filter: None,
        };
        
        // This will panic when converting from protobuf
        let _filter = UserTransactionFilter::from(proto_filter);
    }
}
```

**Notes:**

This vulnerability only affects the indexer-grpc service, not the core blockchain consensus or validator nodes. However, it represents a significant availability issue for the Aptos ecosystem infrastructure. The fix is straightforward and should be implemented with proper error handling to gracefully reject malformed filters rather than panicking.

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

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/user_transaction.rs (L48-61)
```rust
impl From<aptos_protos::indexer::v1::UserTransactionFilter> for UserTransactionFilter {
    fn from(proto_filter: aptos_protos::indexer::v1::UserTransactionFilter) -> Self {
        Self {
            standardized_sender: OnceCell::with_value(
                proto_filter
                    .sender
                    .as_ref()
                    .map(|address| standardize_address(address)),
            ),
            sender: proto_filter.sender,
            payload: proto_filter.payload_filter.map(|f| f.into()),
        }
    }
}
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/user_transaction.rs (L73-80)
```rust
    #[inline]
    fn validate_state(&self) -> Result<(), FilterError> {
        if self.sender.is_none() && self.payload.is_none() {
            return Err(Error::msg("At least one of sender or payload must be set").into());
        };
        self.payload.is_valid()?;
        Ok(())
    }
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/move_module.rs (L48-61)
```rust
impl From<aptos_protos::indexer::v1::MoveStructTagFilter> for MoveStructTagFilter {
    fn from(proto_filter: aptos_protos::indexer::v1::MoveStructTagFilter) -> Self {
        Self {
            standardized_address: OnceCell::with_value(
                proto_filter
                    .address
                    .as_ref()
                    .map(|address| standardize_address(address)),
            ),
            address: proto_filter.address,
            module: proto_filter.module,
            name: proto_filter.name,
        }
    }
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/boolean_transaction_filter.rs (L94-127)
```rust
    pub fn new_from_proto(
        proto_filter: aptos_protos::indexer::v1::BooleanTransactionFilter,
        max_filter_size: Option<usize>,
    ) -> Result<Self> {
        if let Some(max_filter_size) = max_filter_size {
            ensure!(
                proto_filter.encoded_len() <= max_filter_size,
                format!(
                    "Filter is too complicated. Max size: {} bytes, Actual size: {} bytes",
                    max_filter_size,
                    proto_filter.encoded_len()
                )
            );
        }
        Ok(
            match proto_filter
                .filter
                .ok_or(anyhow!("Oneof is not set in BooleanTransactionFilter."))?
            {
                aptos_protos::indexer::v1::boolean_transaction_filter::Filter::ApiFilter(
                    api_filter,
                ) => TryInto::<APIFilter>::try_into(api_filter)?.into(),
                aptos_protos::indexer::v1::boolean_transaction_filter::Filter::LogicalAnd(
                    logical_and,
                ) => BooleanTransactionFilter::And(logical_and.try_into()?),
                aptos_protos::indexer::v1::boolean_transaction_filter::Filter::LogicalOr(
                    logical_or,
                ) => BooleanTransactionFilter::Or(logical_or.try_into()?),
                aptos_protos::indexer::v1::boolean_transaction_filter::Filter::LogicalNot(
                    logical_not,
                ) => BooleanTransactionFilter::Not(logical_not.try_into()?),
            },
        )
    }
```
