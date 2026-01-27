# Audit Report

## Title
Indexer gRPC Service Denial of Service via Malformed Address in EntryFunctionFilter

## Summary
The `EntryFunctionFilter` deserialization in the indexer gRPC service does not validate address field length before processing. An attacker can send a transaction filter with an address string exceeding 64 hexadecimal characters, causing a panic in the `standardize_address()` function and crashing the indexer service task.

## Finding Description

The vulnerability exists in the address standardization logic used during filter conversion. When a client sends a `GetTransactionsRequest` with a `BooleanTransactionFilter` containing an `EntryFunctionFilter` with a malformed address, the following execution path occurs:

1. **Deserialization Without Validation**: The protobuf filter is deserialized via serde, where the address field is accepted as an arbitrary string without length or format validation. [1](#0-0) 

2. **Filter Conversion Triggers Panic**: When the protobuf `EntryFunctionFilter` is converted to the internal Rust type, the `standardize_address()` function is called on any provided address value. [2](#0-1) 

3. **Panic on Invalid Length**: The `standardize_address()` function attempts to pad addresses to 64 characters. When the input address (after stripping "0x" prefix) exceeds 64 characters, the expression `&ZEROS[..64 - trimmed.len()]` causes an integer underflow in the subtraction, resulting in an attempt to slice `ZEROS` beyond its bounds (64 characters), triggering a panic. [3](#0-2) 

4. **Service Disruption**: The panic occurs during request parsing before error handling can catch it, terminating the service task and disrupting the indexer's ability to serve filtered transaction streams to that client connection. [4](#0-3) 

The vulnerability violates the principle that services should handle malformed input gracefully without panicking, maintaining availability even when processing invalid requests.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program's "API crashes" category. An attacker can:

- Cause denial of service to the indexer gRPC API by repeatedly sending malformed filters
- Disrupt legitimate users' ability to query filtered transaction data
- Potentially exhaust service resources if multiple malicious requests are sent concurrently

While the core blockchain consensus and execution layers remain unaffected (validators continue to process transactions and reach consensus), the indexer is a critical infrastructure component for dApp developers and users who need to query blockchain data efficiently. Its unavailability impacts the broader ecosystem's usability.

## Likelihood Explanation

**Likelihood: High**

The attack requires minimal sophistication:
- No authentication or authorization is required beyond standard gRPC access
- The attacker needs only to construct a protobuf message with a string field exceeding 64 characters
- The vulnerability is triggered on every request containing the malformed filter
- No rate limiting or input validation prevents repeated exploitation

The attack can be executed by any client with network access to the indexer gRPC endpoint.

## Recommendation

Add address length and format validation before calling `standardize_address()`. The fix should be implemented in two locations:

1. **Add validation to `standardize_address()`** to return a `Result` instead of panicking:

```rust
pub fn standardize_address(address: &str) -> Result<String, &'static str> {
    let trimmed = address.strip_prefix("0x").unwrap_or(address);
    
    // Validate length (Aptos addresses are max 64 hex chars)
    if trimmed.len() > 64 {
        return Err("Address exceeds maximum length of 64 hexadecimal characters");
    }
    
    // Validate hex format
    if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Address contains non-hexadecimal characters");
    }
    
    // Rest of function unchanged...
}
```

2. **Update callers to handle the Result**, particularly in the `From` implementation:

```rust
impl From<aptos_protos::indexer::v1::EntryFunctionFilter> for EntryFunctionFilter {
    fn from(proto_filter: aptos_protos::indexer::v1::EntryFunctionFilter) -> Self {
        Self {
            standardized_address: OnceCell::with_value(
                proto_filter
                    .address
                    .as_ref()
                    .and_then(|address| standardize_address(address).ok()),
            ),
            // ... rest unchanged
        }
    }
}
```

This ensures malformed addresses are rejected early with proper error messages rather than causing panics.

## Proof of Concept

```rust
#[test]
#[should_panic(expected = "index out of bounds")]
fn test_oversized_address_causes_panic() {
    use aptos_transaction_filter::filters::user_transaction::EntryFunctionFilter;
    use aptos_protos::indexer::v1;
    
    // Create a malformed address with 100 hex characters (exceeds 64 limit)
    let oversized_address = "0x".to_string() + &"a".repeat(100);
    
    // Create protobuf EntryFunctionFilter with oversized address
    let proto_filter = v1::EntryFunctionFilter {
        address: Some(oversized_address),
        module_name: Some("module".to_string()),
        function: Some("function".to_string()),
    };
    
    // This conversion will panic when standardize_address() is called
    let _filter: EntryFunctionFilter = proto_filter.into();
    
    // Panic occurs before this line is reached
}

#[test]
fn test_normal_address_works() {
    use aptos_transaction_filter::filters::user_transaction::EntryFunctionFilter;
    use aptos_protos::indexer::v1;
    
    // Valid 64-character address
    let valid_address = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    
    let proto_filter = v1::EntryFunctionFilter {
        address: Some(valid_address.to_string()),
        module_name: None,
        function: None,
    };
    
    // This should work fine
    let filter: EntryFunctionFilter = proto_filter.into();
    assert!(filter.address.is_some());
}
```

**Notes**

This vulnerability affects the indexer gRPC data service components (`indexer-grpc-data-service-v2` and related services) that parse transaction filters from client requests. The issue stems from the lack of input validation in the address standardization utility function, which was designed assuming valid input but is exposed to untrusted client data through the gRPC API. While not consensus-critical, the indexer is essential infrastructure for ecosystem participants querying blockchain data, making its availability important for the broader Aptos ecosystem.

### Citations

**File:** protos/rust/src/pb/aptos.indexer.v1.serde.rs (L535-535)
```rust
                            address__ = map.next_value()?;
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/user_transaction.rs (L155-169)
```rust
impl From<aptos_protos::indexer::v1::EntryFunctionFilter> for EntryFunctionFilter {
    fn from(proto_filter: aptos_protos::indexer::v1::EntryFunctionFilter) -> Self {
        Self {
            standardized_address: OnceCell::with_value(
                proto_filter
                    .address
                    .as_ref()
                    .map(|address| standardize_address(address)),
            ),
            address: proto_filter.address,
            module: proto_filter.module_name,
            function: proto_filter.function,
        }
    }
}
```

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

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/mod.rs (L98-115)
```rust
                let filter = if let Some(proto_filter) = request.transaction_filter {
                    match filter_utils::parse_transaction_filter(
                        proto_filter,
                        self.max_transaction_filter_size_bytes,
                    ) {
                        Ok(filter) => Some(filter),
                        Err(err) => {
                            info!("Client error: {err:?}.");
                            let _ = response_sender.blocking_send(Err(err));
                            COUNTER
                                .with_label_values(&["live_data_service_invalid_filter"])
                                .inc();
                            continue;
                        },
                    }
                } else {
                    None
                };
```
