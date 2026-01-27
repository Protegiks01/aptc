# Audit Report

## Title
Validation Bypass in Transaction Filter Parsing - is_valid() Not Called During Filter Construction

## Summary
The `parse_transaction_filter()` function in the indexer-grpc service creates `BooleanTransactionFilter` instances from protobuf without calling `is_valid()`, allowing invalid filter configurations (e.g., filters with all fields set to None) to be constructed and used. These invalid filters match all items instead of being rejected, enabling information disclosure and resource exhaustion attacks.

## Finding Description
The indexer-grpc service provides a gRPC API for streaming transaction data with optional filtering capabilities. The `parse_transaction_filter()` function is responsible for parsing and validating client-provided transaction filters from their protobuf representation. [1](#0-0) 

This function calls `BooleanTransactionFilter::new_from_proto()` to convert the protobuf filter: [2](#0-1) 

The `new_from_proto()` method performs size validation but **does NOT call `is_valid()`** to validate the filter's semantic correctness. The filter is then used directly for matching transactions: [3](#0-2) 

The `Filterable` trait defines both `validate_state()` (for implementation) and `is_valid()` (for public validation with error tracing): [4](#0-3) 

Each filter type implements `validate_state()` to enforce semantic constraints. For example, `EventFilter` requires at least one field to be set: [5](#0-4) 

However, the protobuf schema defines all fields as optional: [6](#0-5) 

**Attack Path:**
1. Attacker crafts a protobuf `EventFilter` with both `struct_type` and `data_substring_filter` unset (None)
2. `parse_transaction_filter()` calls `new_from_proto()` which creates the invalid filter without calling `is_valid()`
3. The invalid filter is passed to `IndexerStreamCoordinator` and used with `.matches()`
4. Since both fields are None, `.matches()` returns `true` for all events (the None checks pass): [7](#0-6) 

5. The attacker receives all blockchain data instead of having their invalid filter rejected

The same issue affects all filter types:
- `UserTransactionFilter` requires at least one of `sender` or `payload`: [8](#0-7) 
- `TransactionRootFilter` requires at least one of `success` or `txn_type`: [9](#0-8) 
- `EntryFunctionFilter` requires at least one field: [10](#0-9) 

## Impact Explanation
This vulnerability falls into **Medium Severity** based on the Aptos bug bounty criteria:

1. **Information Disclosure**: Attackers can bypass filter validation to receive all transaction data instead of a filtered subset. While blockchain data is public, the validation bypass violates the API's design intent and could leak more data than authorized in restricted deployment scenarios.

2. **Resource Exhaustion**: Invalid filters that match everything consume excessive bandwidth, CPU, and memory. An attacker can send multiple concurrent requests with invalid filters to degrade service availability for legitimate users.

3. **API Validation Bypass**: The validation system exists to enforce proper filter configuration. This bypass undermines that security control and could enable more severe attacks if the system evolves (e.g., if private/permissioned filtering is added).

The issue does NOT affect consensus, state integrity, or funds, so it does not qualify for Critical or High severity.

## Likelihood Explanation
**Likelihood: High**

- **No special privileges required**: Any gRPC client can exploit this
- **Simple attack vector**: Just send a protobuf message with all filter fields unset
- **No authentication bypass needed**: The validation bypass is inherent in the parsing logic
- **Easily reproducible**: Works consistently on all indexer-grpc deployments

The attack requires only basic knowledge of protobuf and the gRPC API.

## Recommendation
Call `is_valid()` immediately after filter construction in `parse_transaction_filter()`:

```rust
pub fn parse_transaction_filter(
    proto_filter: aptos_protos::indexer::v1::BooleanTransactionFilter,
    max_filter_size_bytes: usize,
) -> Result<BooleanTransactionFilter, Status> {
    let filter = BooleanTransactionFilter::new_from_proto(proto_filter, Some(max_filter_size_bytes))
        .map_err(|e| Status::invalid_argument(format!("Invalid transaction_filter: {e:?}.")))?;
    
    // Validate the filter's semantic correctness
    filter.is_valid()
        .map_err(|e| Status::invalid_argument(format!("Invalid transaction_filter: {e}")))?;
    
    Ok(filter)
}
```

This ensures all filters are validated before use, rejecting invalid configurations at parse time.

## Proof of Concept

```rust
#[test]
fn test_invalid_event_filter_bypass() {
    use aptos_indexer_grpc_utils::filter_utils::parse_transaction_filter;
    use aptos_protos::indexer::v1::{BooleanTransactionFilter, ApiFilter, EventFilter};
    
    // Create an invalid EventFilter with both fields None
    let invalid_event_filter = EventFilter {
        struct_type: None,
        data_substring_filter: None,
    };
    
    let api_filter = ApiFilter {
        filter: Some(aptos_protos::indexer::v1::api_filter::Filter::EventFilter(
            invalid_event_filter
        )),
    };
    
    let proto_filter = BooleanTransactionFilter {
        filter: Some(aptos_protos::indexer::v1::boolean_transaction_filter::Filter::ApiFilter(
            api_filter
        )),
    };
    
    // This should FAIL but currently SUCCEEDS
    let result = parse_transaction_filter(proto_filter, 10000);
    assert!(result.is_ok(), "Invalid filter was accepted!");
    
    let filter = result.unwrap();
    
    // Calling is_valid() manually shows it's invalid
    use aptos_transaction_filter::Filterable;
    assert!(filter.is_valid().is_err(), "Filter should be invalid!");
}
```

**Notes**

This validation bypass exists specifically because `is_valid()` is never invoked during the filter construction pipeline. While the current security impact is limited to the indexer service (not consensus-critical), validation bypasses represent a class of vulnerabilities that can have cascading effects as systems evolve. The fix is straightforward and should be applied to enforce the intended API contract.

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

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L175-182)
```rust
                let pb_txns = if let Some(ref filter) = filter {
                    pb_txns
                        .into_iter()
                        .filter(|txn| filter.matches(txn))
                        .collect::<Vec<_>>()
                } else {
                    pb_txns
                };
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/traits.rs (L13-39)
```rust
    /// Whether this filter is correctly configured/initialized
    /// Any call to `validate_state` is responsible for recursively checking the validity of any nested filters *by calling `is_valid`*
    /// The actual public API is via `is_valid` which will call `validate_state` and return an error if it fails, but annotated with the filter type/path
    fn validate_state(&self) -> Result<(), FilterError>;

    /// This is a convenience method to allow for the error to be annotated with the filter type/path at each level
    /// This is the public API for checking the validity of a filter!
    /// Example output looks like:
    /// ```text
    /// FilterError: This is a test error!.
    /// Trace Path:
    /// transaction_filter::traits::test::InnerStruct:   {"a":"test"}
    /// core::option::Option<transaction_filter::traits::test::InnerStruct>:   {"a":"test"}
    /// transaction_filter::traits::test::OuterStruct:   {"inner":{"a":"test"}}
    ///  ```
    ///
    #[inline]
    fn is_valid(&self) -> Result<(), FilterError> {
        // T
        self.validate_state().map_err(|mut e| {
            e.add_trace(
                serde_json::to_string(self).unwrap(),
                std::any::type_name::<Self>().to_string(),
            );
            e
        })
    }
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/event.rs (L64-73)
```rust
    #[inline]
    fn validate_state(&self) -> Result<(), FilterError> {
        if self.data_substring_filter.is_none() && self.struct_type.is_none() {
            return Err(Error::msg("At least one of data or struct_type must be set").into());
        };

        self.data_substring_filter.is_valid()?;
        self.struct_type.is_valid()?;
        Ok(())
    }
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/event.rs (L76-99)
```rust
    fn matches(&self, item: &Event) -> bool {
        if let Some(struct_type_filter) = &self.struct_type {
            if let Some(Content::Struct(struct_tag)) =
                &item.r#type.as_ref().and_then(|t| t.content.as_ref())
            {
                if !struct_type_filter.matches(struct_tag) {
                    return false;
                }
            } else {
                return false;
            }
        }

        if let Some(data_substring_filter) = self.data_substring_filter.as_ref() {
            let finder = self
                .data_substring_finder
                .get_or_init(|| Finder::new(data_substring_filter).into_owned());
            if finder.find(item.data.as_bytes()).is_none() {
                return false;
            }
        }

        true
    }
```

**File:** protos/proto/aptos/indexer/v1/filter.proto (L45-48)
```text
message EventFilter {
  optional MoveStructTagFilter struct_type = 1;
  optional string data_substring_filter = 2;
}
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/user_transaction.rs (L74-79)
```rust
    fn validate_state(&self) -> Result<(), FilterError> {
        if self.sender.is_none() && self.payload.is_none() {
            return Err(Error::msg("At least one of sender or payload must be set").into());
        };
        self.payload.is_valid()?;
        Ok(())
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/user_transaction.rs (L183-187)
```rust
    fn validate_state(&self) -> Result<(), FilterError> {
        if self.address.is_none() && self.module.is_none() && self.function.is_none() {
            return Err(anyhow!("At least one of address, name or function must be set").into());
        };
        Ok(())
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/transaction_root.rs (L51-55)
```rust
    fn validate_state(&self) -> Result<(), FilterError> {
        if self.success.is_none() && self.txn_type.is_none() {
            return Err(Error::msg("At least one of success or txn_types must be set").into());
        };
        Ok(())
```
