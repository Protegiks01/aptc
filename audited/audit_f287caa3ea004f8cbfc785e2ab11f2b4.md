# Audit Report

## Title
Integer Underflow Panic in `standardize_address` During EventFilter Deserialization Causes Indexer gRPC Service Crash

## Summary
The `From<aptos_protos::indexer::v1::EventFilter>` implementation in the transaction filter crate lacks input validation during protobuf deserialization. When a `MoveStructTagFilter` is converted from protobuf, it eagerly calls `standardize_address()` on the address field, which panics if the address string exceeds 64 hex characters due to integer underflow. This allows any external client to crash the indexer gRPC service by sending a malicious `GetTransactionsRequest` with an oversized address in the transaction filter.

## Finding Description

The vulnerability exists in the protobuf-to-Rust conversion path for event filters used in the Aptos indexer gRPC transaction streaming API.

**Attack Path:**

1. An attacker crafts a gRPC `GetTransactionsRequest` with a `transaction_filter` containing an `EventFilter`
2. The `EventFilter` includes a `struct_type` field (a `MoveStructTagFilter`) with an `address` field containing more than 64 hex characters (e.g., "0x" + 100 hex digits)
3. The service receives the request and calls `filter_utils::parse_transaction_filter()` [1](#0-0) 
4. This invokes `BooleanTransactionFilter::new_from_proto()` [2](#0-1) 
5. Which calls `TryInto::<APIFilter>::try_into(api_filter)?` [3](#0-2) 
6. This triggers `Into::<EventFilter>::into(event_filter)` [4](#0-3) 
7. Which calls the infallible `From` trait implementation that maps the struct_type: [5](#0-4) 
8. This invokes `From<aptos_protos::indexer::v1::MoveStructTagFilter>` which **eagerly** calls `standardize_address()` during construction: [6](#0-5) 
9. Inside `standardize_address()`, when the address length exceeds 64 characters, the expression `64 - trimmed.len()` causes an integer underflow: [7](#0-6) 

**Panic Mechanism:**
- If `trimmed.len() > 64` (e.g., 100), then `64 - 100` underflows
- In debug mode or with overflow checks: immediate panic
- In release mode: wraps to a very large number (e.g., `u64::MAX - 36`)
- The subsequent slice operation `&ZEROS[..very_large_number]` panics because `ZEROS` is only 64 characters long

**Why Error Handling Doesn't Catch It:**
The `map_err` in `parse_transaction_filter()` only catches `Result::Err`, not panics. Since `From` is an infallible trait, it can only panic on error, not return a `Result`. The panic propagates up and crashes the entire gRPC service thread.

## Impact Explanation

**Severity: High** - API crashes that cause denial of service

This vulnerability allows any unauthenticated external client to crash the Aptos indexer gRPC service by sending a single malformed request. The impact includes:

1. **Service Availability Loss**: The indexer gRPC service crashes and stops serving transaction data to clients (wallets, explorers, dApps)
2. **Repeated DoS**: The attack is trivial to repeat - each malicious request causes a crash
3. **No Authentication Required**: Any network client can send gRPC requests to the public indexer endpoint
4. **Critical Infrastructure**: The indexer gRPC service is essential infrastructure for Aptos ecosystem applications

Per the Aptos bug bounty criteria, this qualifies as **High Severity** (up to $50,000) for "API crashes" and "Validator node slowdowns" (if the indexer is co-located with validators).

While this doesn't directly affect consensus or cause loss of funds, it severely impacts the availability of blockchain data services, which are critical for the ecosystem's operation.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be exploited because:

1. **Trivial Exploitation**: The attack requires only crafting a simple gRPC message with an oversized string - no complex cryptography, timing, or state manipulation needed
2. **Public Attack Surface**: The indexer gRPC API is publicly accessible at `grpc.mainnet.aptoslabs.com:443` and similar endpoints
3. **No Authentication**: The `GetTransactions` API requires no authentication or authorization
4. **Immediate Impact**: Each malicious request causes an instant crash - no need for setup or race conditions
5. **Easily Automated**: The attack can be scripted and repeated indefinitely

The only barrier is discovering the vulnerability - once known, exploitation is guaranteed to succeed.

## Recommendation

**Immediate Fix**: Replace the infallible `From` trait with a fallible `TryFrom` trait that validates the address length before calling `standardize_address()`.

**Modified Code for `move_module.rs`:**

```rust
impl TryFrom<aptos_protos::indexer::v1::MoveStructTagFilter> for MoveStructTagFilter {
    type Error = anyhow::Error;

    fn try_from(proto_filter: aptos_protos::indexer::v1::MoveStructTagFilter) -> Result<Self> {
        // Validate address length before standardizing
        if let Some(address) = &proto_filter.address {
            let trimmed = address.strip_prefix("0x").unwrap_or(address);
            if trimmed.len() > 64 {
                return Err(anyhow::anyhow!(
                    "Address hex string too long: {} characters (max 64)", 
                    trimmed.len()
                ));
            }
        }
        
        Ok(Self {
            standardized_address: OnceCell::with_value(
                proto_filter
                    .address
                    .as_ref()
                    .map(|address| standardize_address(address)),
            ),
            address: proto_filter.address,
            module: proto_filter.module,
            name: proto_filter.name,
        })
    }
}
```

**Update `APIFilter::try_from()` in `boolean_transaction_filter.rs`:**

```rust
aptos_protos::indexer::v1::api_filter::Filter::EventFilter(event_filter) => {
    TryInto::<EventFilter>::try_into(event_filter)?.into()
},
```

**Update `EventFilter::from()` in `event.rs`:**

```rust
impl TryFrom<aptos_protos::indexer::v1::EventFilter> for EventFilter {
    type Error = anyhow::Error;

    fn try_from(proto_filter: aptos_protos::indexer::v1::EventFilter) -> Result<Self> {
        Ok(Self {
            data_substring_filter: proto_filter.data_substring_filter,
            struct_type: proto_filter.struct_type
                .map(|f| f.try_into())
                .transpose()?,
            data_substring_finder: OnceCell::new(),
        })
    }
}
```

**Additional Defensive Measure**: Add bounds checking to `standardize_address()` itself to prevent future similar issues.

## Proof of Concept

```rust
#[cfg(test)]
mod test_vulnerability {
    use super::*;
    use aptos_protos::indexer::v1;

    #[test]
    #[should_panic(expected = "attempt to subtract with overflow")]
    fn test_oversized_address_causes_panic() {
        // Create a malicious address with 100 hex characters (exceeds 64 limit)
        let malicious_address = "0x".to_string() + &"a".repeat(100);
        
        // Create a malicious MoveStructTagFilter protobuf
        let proto_filter = v1::MoveStructTagFilter {
            address: Some(malicious_address),
            module: Some("test".to_string()),
            name: Some("test".to_string()),
        };
        
        // This panics during conversion due to integer underflow
        let _filter: MoveStructTagFilter = proto_filter.into();
    }

    #[test]
    #[should_panic]
    fn test_full_attack_path() {
        // Simulate the full gRPC request path
        let malicious_address = "0x".to_string() + &"deadbeef".repeat(20); // 160 hex chars
        
        let event_filter = v1::EventFilter {
            struct_type: Some(v1::MoveStructTagFilter {
                address: Some(malicious_address),
                module: None,
                name: None,
            }),
            data_substring_filter: None,
        };
        
        let api_filter = v1::ApiFilter {
            filter: Some(v1::api_filter::Filter::EventFilter(event_filter)),
        };
        
        let boolean_filter = v1::BooleanTransactionFilter {
            filter: Some(v1::boolean_transaction_filter::Filter::ApiFilter(api_filter)),
        };
        
        // This panics when converting from protobuf
        let _filter = BooleanTransactionFilter::new_from_proto(boolean_filter, Some(10000));
    }
}
```

**Notes**

1. This vulnerability is in the indexer infrastructure, not the core consensus/execution layers, so it doesn't directly affect blockchain safety or transaction execution
2. However, the indexer gRPC service is critical infrastructure used by wallets, explorers, and dApps throughout the Aptos ecosystem
3. The vulnerability demonstrates a broader pattern: using infallible `From` traits for external input deserialization is dangerous - `TryFrom` should be used instead when validation is needed
4. Similar issues may exist in other filter types (`UserTransactionFilter`, `EntryFunctionFilter`) if they have string fields without length validation
5. The protobuf library (prost) guarantees valid UTF-8 for strings, so that specific concern from the security question is not an issue

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/mod.rs (L98-102)
```rust
                let filter = if let Some(proto_filter) = request.transaction_filter {
                    match filter_utils::parse_transaction_filter(
                        proto_filter,
                        self.max_transaction_filter_size_bytes,
                    ) {
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/filter_utils.rs (L13-14)
```rust
    BooleanTransactionFilter::new_from_proto(proto_filter, Some(max_filter_size_bytes))
        .map_err(|e| Status::invalid_argument(format!("Invalid transaction_filter: {e:?}.")))
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/boolean_transaction_filter.rs (L113-115)
```rust
                aptos_protos::indexer::v1::boolean_transaction_filter::Filter::ApiFilter(
                    api_filter,
                ) => TryInto::<APIFilter>::try_into(api_filter)?.into(),
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/boolean_transaction_filter.rs (L395-397)
```rust
                aptos_protos::indexer::v1::api_filter::Filter::EventFilter(event_filter) => {
                    Into::<EventFilter>::into(event_filter).into()
                },
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/event.rs (L44-52)
```rust
impl From<aptos_protos::indexer::v1::EventFilter> for EventFilter {
    fn from(proto_filter: aptos_protos::indexer::v1::EventFilter) -> Self {
        Self {
            data_substring_filter: proto_filter.data_substring_filter,
            struct_type: proto_filter.struct_type.map(|f| f.into()),
            data_substring_finder: OnceCell::new(),
        }
    }
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

**File:** ecosystem/indexer-grpc/transaction-filter/src/utils.rs (L30-35)
```rust
    // Return non-special addresses in long format
    let mut result = String::with_capacity(66);
    result.push_str("0x");
    result.push_str(&ZEROS[..64 - trimmed.len()]);
    result.push_str(trimmed);
    result
```
