# Audit Report

## Title
Indexer gRPC Service Denial of Service via Malformed Address in EventFilter

## Summary
An attacker can crash the Aptos indexer gRPC service by sending a `GetTransactionsRequest` with an `EventFilter` containing a `MoveStructTagFilter` with an address field exceeding 64 hexadecimal characters. This triggers a panic during protobuf-to-Rust conversion, causing a denial-of-service condition for the indexer API.

## Finding Description

The vulnerability exists in the address standardization logic that executes during protobuf message conversion, before any validation occurs.

**Attack Flow:**

1. Attacker crafts a gRPC `GetTransactionsRequest` with a malformed `EventFilter`:
   - The `EventFilter` contains a `MoveStructTagFilter`
   - The `address` field contains more than 64 hex characters (e.g., 100 'a' characters)

2. The indexer service receives the request and calls `parse_transaction_filter()`: [1](#0-0) 

3. This invokes `BooleanTransactionFilter::new_from_proto()` which performs the conversion: [2](#0-1) 

4. During conversion, the `EventFilter` proto is converted to Rust type via `Into::into()`: [3](#0-2) 

5. This triggers conversion of the nested `MoveStructTagFilter`, which calls `standardize_address()` during initialization: [4](#0-3) 

6. The `standardize_address()` function panics when the address exceeds 64 characters: [5](#0-4) 

Specifically, at line 33, when `trimmed.len() > 64`, the subtraction `64 - trimmed.len()` causes:
- **Debug mode**: Panic with "attempt to subtract with overflow"
- **Release mode**: Integer wraparound followed by out-of-bounds panic when indexing `ZEROS`

**Critical Issue:** The panic occurs during protobuf conversion, BEFORE the `validate_state()` method is ever called. No validation prevents this malformed input from reaching the vulnerable code path. [6](#0-5) 

The validation is implemented but never executed because the crash happens earlier in the conversion chain.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program criteria ("API crashes"). 

**Impact:**
- Complete denial-of-service for the indexer gRPC API endpoint
- Single malicious request causes service crash
- Affects all clients attempting to stream transactions from affected indexer
- Service requires restart to recover

**Scope Limitation:**
This vulnerability affects the indexer gRPC service, which is an auxiliary data service running on fullnodes. It does **not** impact:
- Consensus operations
- Validator operations
- Transaction execution
- State synchronization
- Core blockchain functionality

However, it severely disrupts external applications relying on the indexer API for real-time transaction data.

## Likelihood Explanation

**Likelihood: High**

- No authentication or special privileges required
- Attacker only needs network access to the gRPC endpoint
- Single request triggers the vulnerability
- Trivial to construct the malicious payload
- No rate limiting prevents repeated attacks
- Attack can be automated for persistent DoS

The barrier to exploitation is extremely low, making this a practical attack vector against any publicly exposed indexer gRPC service.

## Recommendation

Add bounds validation before calling `standardize_address()`. The fix should validate the address length before attempting standardization:

**Option 1: Validate in `standardize_address()`**
```rust
pub fn standardize_address(address: &str) -> String {
    let trimmed = address.strip_prefix("0x").unwrap_or(address);
    
    // Validate length to prevent panic
    if trimmed.len() > 64 {
        // Return as-is or handle error appropriately
        let mut result = String::with_capacity(address.len() + 2);
        result.push_str("0x");
        result.push_str(trimmed);
        return result;
    }
    
    // ... rest of existing logic
}
```

**Option 2: Add validation in `MoveStructTagFilter::validate_state()`** [7](#0-6) 

Add address format validation:
```rust
fn validate_state(&self) -> Result<(), FilterError> {
    if self.address.is_none() && self.module.is_none() && self.name.is_none() {
        return Err(anyhow!("At least one of address, module or name must be set").into());
    }
    
    // Validate address format if present
    if let Some(ref addr) = self.address {
        let trimmed = addr.strip_prefix("0x").unwrap_or(addr);
        if trimmed.len() > 64 {
            return Err(anyhow!("Address must not exceed 64 hex characters").into());
        }
    }
    
    Ok(())
}
```

**Recommended approach:** Combine both - add bounds checking in `standardize_address()` to prevent panics, and add validation in `validate_state()` to reject malformed filters early with clear error messages.

## Proof of Concept

```rust
#[test]
#[should_panic(expected = "attempt to subtract with overflow")]
fn test_oversized_address_panic() {
    use aptos_protos::indexer::v1::{EventFilter, MoveStructTagFilter};
    use aptos_transaction_filter::filters::event::EventFilter as RustEventFilter;
    
    // Create malformed proto with address > 64 hex chars
    let malformed_address = "0x".to_string() + &"a".repeat(100);
    
    let proto_filter = EventFilter {
        struct_type: Some(MoveStructTagFilter {
            address: Some(malformed_address),
            module: None,
            name: None,
        }),
        data_substring_filter: None,
    };
    
    // This conversion will panic during standardize_address()
    let _rust_filter: RustEventFilter = proto_filter.into();
}

#[test]
fn test_oversized_address_via_grpc_flow() {
    use aptos_protos::indexer::v1::{
        BooleanTransactionFilter, EventFilter, MoveStructTagFilter,
        boolean_transaction_filter, ApiFilter, api_filter,
    };
    use aptos_transaction_filter::BooleanTransactionFilter as RustFilter;
    
    let malformed_address = "0x".to_string() + &"b".repeat(100);
    
    let proto = BooleanTransactionFilter {
        filter: Some(boolean_transaction_filter::Filter::ApiFilter(
            ApiFilter {
                filter: Some(api_filter::Filter::EventFilter(
                    EventFilter {
                        struct_type: Some(MoveStructTagFilter {
                            address: Some(malformed_address),
                            module: Some("test".to_string()),
                            name: None,
                        }),
                        data_substring_filter: None,
                    }
                ))
            }
        ))
    };
    
    // This will panic when new_from_proto attempts conversion
    let result = std::panic::catch_unwind(|| {
        RustFilter::new_from_proto(proto, Some(10000))
    });
    
    assert!(result.is_err(), "Expected panic from oversized address");
}
```

To reproduce in a live environment:
1. Deploy an indexer gRPC service
2. Send a `GetTransactionsRequest` with the malformed `EventFilter` shown above
3. Observe service crash with panic message

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/filter_utils.rs (L9-15)
```rust
pub fn parse_transaction_filter(
    proto_filter: aptos_protos::indexer::v1::BooleanTransactionFilter,
    max_filter_size_bytes: usize,
) -> Result<BooleanTransactionFilter, Status> {
    BooleanTransactionFilter::new_from_proto(proto_filter, Some(max_filter_size_bytes))
        .map_err(|e| Status::invalid_argument(format!("Invalid transaction_filter: {e:?}.")))
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

**File:** ecosystem/indexer-grpc/transaction-filter/src/boolean_transaction_filter.rs (L454-461)
```rust
impl Filterable<Transaction> for APIFilter {
    fn validate_state(&self) -> Result<(), FilterError> {
        match self {
            APIFilter::TransactionRootFilter(filter) => filter.is_valid(),
            APIFilter::UserTransactionFilter(filter) => filter.is_valid(),
            APIFilter::EventFilter(filter) => filter.is_valid(),
        }
    }
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

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/move_module.rs (L48-62)
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
}
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/move_module.rs (L74-81)
```rust
impl Filterable<MoveStructTag> for MoveStructTagFilter {
    #[inline]
    fn validate_state(&self) -> Result<(), FilterError> {
        if self.address.is_none() && self.module.is_none() && self.name.is_none() {
            return Err(anyhow!("At least one of address, module or name must be set").into());
        };
        Ok(())
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
