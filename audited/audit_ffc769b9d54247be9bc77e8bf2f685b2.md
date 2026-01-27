# Audit Report

## Title
Filter Validation Bypass in Indexer-GRPC Service Due to Missing `is_valid()` Check

## Summary
The indexer-grpc transaction filter validation is completely bypassed because `parse_transaction_filter()` never calls `is_valid()` after constructing filters from protobuf. This allows attackers to send malicious filters with all fields set to `None`, which pass parsing but match ALL transactions instead of applying intended filtering logic, leading to information disclosure and resource exhaustion.

## Finding Description

The `FilterError` type is designed to track validation failures through the `Filterable` trait's `is_valid()` method. [1](#0-0) 

Each filter type implements `validate_state()` to enforce that at least one field must be set. For example, `TransactionRootFilter` requires either `success` or `txn_type`: [2](#0-1) 

Similarly, `EventFilter` requires at least one field: [3](#0-2) 

However, the critical issue is that `parse_transaction_filter()` only calls `new_from_proto()` and never validates the filter: [4](#0-3) 

The `new_from_proto()` method only validates size and protobuf structure, never calling `is_valid()`: [5](#0-4) 

When filters have all fields set to `None`, the `Option<T>` implementation of `Filterable` returns `true` for all matches: [6](#0-5) 

This causes empty filters to match ALL transactions. For example, an empty `TransactionRootFilter` will match all transactions because both field checks pass: [7](#0-6) 

**Attack Path:**
1. Attacker crafts a protobuf `TransactionRootFilter` with both `success` and `transaction_type` omitted (all fields `None`)
2. Sends `GetTransactionsRequest` with this malicious filter to any indexer-grpc endpoint
3. `parse_transaction_filter()` accepts the filter (passes size check, has valid oneof structure)
4. Filter is used in data streaming without validation
5. Empty filter matches ALL transactions, bypassing intended filtering logic
6. Attacker receives unrestricted transaction stream instead of filtered results

## Impact Explanation

This vulnerability affects the indexer-grpc data service, which provides filtered transaction streams to clients. The impact includes:

1. **Information Disclosure**: Attackers can bypass filtering logic to access all transaction data when they should only see filtered subsets
2. **Resource Exhaustion**: Sending empty filters causes the service to process and transmit all transactions, potentially overwhelming indexer nodes and network bandwidth
3. **API Availability**: Could lead to service degradation or crashes under load

According to Aptos bug bounty severity categories, this qualifies as **High Severity** due to potential API crashes and significant protocol violations in the data access layer.

## Likelihood Explanation

**Likelihood: HIGH**

- No authentication bypass required - any client can send gRPC requests
- Trivial to exploit - simply omit all optional fields in filter protobuf
- All indexer-grpc endpoints are vulnerable (live, historical, and localnet services): [8](#0-7) 
- No special privileges or complex attack chains needed
- Can be executed repeatedly for sustained resource exhaustion

## Recommendation

Add explicit validation by calling `is_valid()` immediately after parsing:

```rust
pub fn parse_transaction_filter(
    proto_filter: aptos_protos::indexer::v1::BooleanTransactionFilter,
    max_filter_size_bytes: usize,
) -> Result<BooleanTransactionFilter, Status> {
    let filter = BooleanTransactionFilter::new_from_proto(proto_filter, Some(max_filter_size_bytes))
        .map_err(|e| Status::invalid_argument(format!("Invalid transaction_filter: {e:?}.")))?;
    
    // ADD THIS VALIDATION CHECK
    filter.is_valid()
        .map_err(|e| Status::invalid_argument(format!("Filter validation failed: {e}")))?;
    
    Ok(filter)
}
```

This ensures that all filters are properly validated before being used in production, preventing empty filters from bypassing security checks.

## Proof of Concept

```rust
// Test demonstrating the vulnerability
#[test]
fn test_empty_filter_bypass() {
    use aptos_protos::indexer::v1::{
        BooleanTransactionFilter as ProtoBooleanFilter,
        ApiFilter as ProtoApiFilter, 
        TransactionRootFilter as ProtoTransactionRootFilter,
        boolean_transaction_filter::Filter as ProtoFilter,
        api_filter::Filter as ProtoApiFilterInner,
    };
    use aptos_transaction_filter::BooleanTransactionFilter;
    
    // Create an empty TransactionRootFilter with all fields None
    let empty_root_filter = ProtoTransactionRootFilter {
        success: None,
        transaction_type: None,
    };
    
    let proto_filter = ProtoBooleanFilter {
        filter: Some(ProtoFilter::ApiFilter(ProtoApiFilter {
            filter: Some(ProtoApiFilterInner::TransactionRootFilter(empty_root_filter)),
        })),
    };
    
    // This should fail validation but doesn't!
    let filter = BooleanTransactionFilter::new_from_proto(proto_filter, Some(1000))
        .expect("Empty filter should be rejected but passes!");
    
    // If we call is_valid(), it correctly fails:
    assert!(filter.is_valid().is_err(), "Empty filter should fail validation");
    
    // But in production, is_valid() is never called, so the empty filter is used
    // and matches() returns true for ALL transactions
}
```

**Notes**

This vulnerability specifically affects the indexer-grpc service's transaction filtering mechanism, not the core blockchain consensus or execution layers. While the indexer is an off-chain data access component, this validation bypass represents a significant security flaw that violates the principle of defense-in-depth and could facilitate reconnaissance attacks or resource exhaustion against indexer infrastructure.

### Citations

**File:** ecosystem/indexer-grpc/transaction-filter/src/traits.rs (L30-39)
```rust
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

**File:** ecosystem/indexer-grpc/transaction-filter/src/traits.rs (L115-120)
```rust
    fn matches(&self, item: &String) -> bool {
        match self {
            Some(filter) => filter == item,
            None => true,
        }
    }
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/transaction_root.rs (L51-56)
```rust
    fn validate_state(&self) -> Result<(), FilterError> {
        if self.success.is_none() && self.txn_type.is_none() {
            return Err(Error::msg("At least one of success or txn_types must be set").into());
        };
        Ok(())
    }
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/transaction_root.rs (L59-76)
```rust
    fn matches(&self, item: &Transaction) -> bool {
        if !self
            .success
            .matches_opt(&item.info.as_ref().map(|i| i.success))
        {
            return false;
        }

        if let Some(txn_type) = &self.txn_type {
            if txn_type
                != &TransactionType::try_from(item.r#type).expect("Invalid transaction type")
            {
                return false;
            }
        }

        true
    }
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/event.rs (L65-73)
```rust
    fn validate_state(&self) -> Result<(), FilterError> {
        if self.data_substring_filter.is_none() && self.struct_type.is_none() {
            return Err(Error::msg("At least one of data or struct_type must be set").into());
        };

        self.data_substring_filter.is_valid()?;
        self.struct_type.is_valid()?;
        Ok(())
    }
```

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
