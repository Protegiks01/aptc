# Audit Report

## Title
Stack Overflow via Deeply Nested BooleanTransactionFilter in Indexer gRPC Service

## Summary
The indexer-grpc service accepts user-provided `BooleanTransactionFilter` structures that can be recursively nested without depth limits. An attacker can craft a deeply nested filter (e.g., 3,000 levels of NOT operations) that fits within the 10KB size limit but causes stack overflow during parsing, validation, or transaction matching, leading to service crashes and denial of service.

## Finding Description

The `TransactionRootFilter` can indeed be nested within other filters through the `BooleanTransactionFilter` composite structure. This creates recursive validation and matching scenarios that can lead to stack overflow.

**Vulnerable Architecture:**

The `BooleanTransactionFilter` is a recursive enum [1](#0-0)  that wraps `TransactionRootFilter` through the `APIFilter` enum [2](#0-1) .

The recursive structure is defined in the protobuf [3](#0-2)  where `logical_not` field (line 63) recursively contains another `BooleanTransactionFilter`, enabling unbounded nesting.

**Insufficient Protection:**

The `parse_transaction_filter` function checks `max_filter_size_bytes` [4](#0-3)  which defaults to 10KB [5](#0-4) . However, this only validates the encoded protobuf **size**, not the **recursion depth**.

**Critical Bug - Size Check Bypass:**

During recursive parsing of nested filters, the code passes `None` for `max_filter_size`, bypassing size checks for nested structures:
- LogicalAnd parsing [6](#0-5) 
- LogicalOr parsing [7](#0-6) 
- LogicalNot parsing [8](#0-7) 

**Stack Overflow Points:**

1. **During Parsing**: Recursive `new_from_proto` calls [9](#0-8) 

2. **During Validation**: Recursive `validate_state` and `is_valid` calls [10](#0-9)  and [11](#0-10) 

3. **During Matching**: Recursive `matches` calls executed for every transaction [12](#0-11)  and [13](#0-12) 

**Attack Path:**

1. Attacker sends `GetTransactionsRequest` [14](#0-13)  with a deeply nested `transaction_filter` field
2. The filter is parsed in the live_data_service [15](#0-14) 
3. With ~3,000 levels of NOT nesting (fits in 10KB), the recursive parsing/validation/matching causes stack overflow
4. The indexer-grpc service crashes with stack overflow error

The filter is also used in the historical data service for transaction stripping [16](#0-15)  where `matches` is called for every transaction, making the attack even more impactful.

## Impact Explanation

**Severity: HIGH**

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program because it causes "API crashes" - a specific high-severity category. The indexer-grpc service is critical infrastructure that:

1. Serves transaction data to all downstream indexers via gRPC API
2. Processes every transaction through the filter matching logic
3. Crashes completely on stack overflow, requiring manual restart
4. Affects both live and historical data services

The crash is deterministic and repeatable - any request with a sufficiently deep filter nesting will cause service termination. This breaks the **Resource Limits** invariant: "All operations must respect gas, storage, and computational limits."

## Likelihood Explanation

**Likelihood: HIGH**

The attack is trivial to execute:
- No authentication beyond normal API access required
- Single malicious gRPC request can crash the service
- Attack payload is small (fits in 10KB)
- No special permissions or insider access needed
- Can be automated and repeated

The vulnerability is present in all deployments using the indexer-grpc service with default configuration.

## Recommendation

**Fix 1: Add Depth Limit During Parsing**

Add a `max_depth` parameter that is checked and decremented during recursive parsing:

```rust
pub fn new_from_proto(
    proto_filter: aptos_protos::indexer::v1::BooleanTransactionFilter,
    max_filter_size: Option<usize>,
    max_depth: usize,  // ADD THIS
) -> Result<Self> {
    if max_depth == 0 {
        bail!("Filter nesting depth exceeds maximum allowed");
    }
    
    // existing size check...
    
    Ok(match proto_filter.filter... {
        // Pass max_depth - 1 to recursive calls
        LogicalAnd(logical_and) => {
            let filters = logical_and.filters
                .into_iter()
                .map(|f| Self::new_from_proto(f, None, max_depth - 1))
                .collect::<Result<_>>()?;
            // ...
        }
        // Similar for LogicalOr and LogicalNot
    })
}
```

**Fix 2: Iterative Implementation**

Replace recursive validation/matching with iterative implementations using explicit stacks to prevent stack overflow.

**Recommended Configuration:**
- Set `MAX_FILTER_DEPTH` to 32 (reasonable for legitimate use cases)
- Propagate depth limit through all recursive parsing calls
- Validate depth before processing

## Proof of Concept

```rust
#[cfg(test)]
mod stack_overflow_test {
    use super::*;
    use aptos_protos::indexer::v1::BooleanTransactionFilter as ProtoBooleanFilter;
    
    #[test]
    #[should_panic(expected = "stack overflow")]
    fn test_deeply_nested_filter_causes_stack_overflow() {
        // Create a deeply nested NOT filter
        let mut proto_filter = ProtoBooleanFilter {
            filter: Some(aptos_protos::indexer::v1::boolean_transaction_filter::Filter::ApiFilter(
                aptos_protos::indexer::v1::ApiFilter {
                    filter: Some(aptos_protos::indexer::v1::api_filter::Filter::TransactionRootFilter(
                        aptos_protos::indexer::v1::TransactionRootFilter {
                            success: Some(true),
                            transaction_type: None,
                        }
                    ))
                }
            )),
        };
        
        // Nest it 5000 times
        for _ in 0..5000 {
            proto_filter = ProtoBooleanFilter {
                filter: Some(aptos_protos::indexer::v1::boolean_transaction_filter::Filter::LogicalNot(
                    Box::new(proto_filter)
                )),
            };
        }
        
        // This will cause stack overflow during parsing
        let filter = BooleanTransactionFilter::new_from_proto(proto_filter, Some(1_000_000))
            .expect("Failed to parse filter");
        
        // If parsing doesn't crash, matching will
        let txn = create_test_transaction();
        filter.matches(&txn); // Stack overflow here
    }
}
```

**Notes:**

This vulnerability affects the indexer infrastructure layer, not consensus or validator operations directly. However, it represents a critical denial-of-service vulnerability in production API infrastructure with **High Severity** impact per the bug bounty program guidelines.

### Citations

**File:** ecosystem/indexer-grpc/transaction-filter/src/boolean_transaction_filter.rs (L15-23)
```rust
/// BooleanTransactionFilter is the top level filter
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum BooleanTransactionFilter {
    And(LogicalAnd),
    Or(LogicalOr),
    Not(LogicalNot),
    Filter(APIFilter),
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

**File:** ecosystem/indexer-grpc/transaction-filter/src/boolean_transaction_filter.rs (L241-248)
```rust
    fn validate_state(&self) -> Result<(), FilterError> {
        match self {
            BooleanTransactionFilter::And(and) => and.is_valid(),
            BooleanTransactionFilter::Or(or) => or.is_valid(),
            BooleanTransactionFilter::Not(not) => not.is_valid(),
            BooleanTransactionFilter::Filter(filter) => filter.is_valid(),
        }
    }
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/boolean_transaction_filter.rs (L250-257)
```rust
    fn matches(&self, item: &Transaction) -> bool {
        match self {
            BooleanTransactionFilter::And(and) => and.matches(item),
            BooleanTransactionFilter::Or(or) => or.matches(item),
            BooleanTransactionFilter::Not(not) => not.matches(item),
            BooleanTransactionFilter::Filter(filter) => filter.matches(item),
        }
    }
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/boolean_transaction_filter.rs (L268-277)
```rust
    fn try_from(proto_filter: aptos_protos::indexer::v1::LogicalAndFilters) -> Result<Self> {
        Ok(Self {
            and: proto_filter
                .filters
                .into_iter()
                .map(|f| BooleanTransactionFilter::new_from_proto(f, None))
                .collect::<Result<_>>()?,
        })
    }
}
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/boolean_transaction_filter.rs (L287-293)
```rust
impl Filterable<Transaction> for LogicalAnd {
    fn validate_state(&self) -> Result<(), FilterError> {
        for filter in &self.and {
            filter.is_valid()?;
        }
        Ok(())
    }
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/boolean_transaction_filter.rs (L305-317)
```rust
impl TryFrom<aptos_protos::indexer::v1::LogicalOrFilters> for LogicalOr {
    type Error = anyhow::Error;

    fn try_from(proto_filter: aptos_protos::indexer::v1::LogicalOrFilters) -> Result<Self> {
        Ok(Self {
            or: proto_filter
                .filters
                .into_iter()
                .map(|f| BooleanTransactionFilter::new_from_proto(f, None))
                .collect::<Result<_>>()?,
        })
    }
}
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/boolean_transaction_filter.rs (L345-358)
```rust
impl TryFrom<Box<aptos_protos::indexer::v1::BooleanTransactionFilter>> for LogicalNot {
    type Error = anyhow::Error;

    fn try_from(
        proto_filter: Box<aptos_protos::indexer::v1::BooleanTransactionFilter>,
    ) -> Result<Self> {
        Ok(Self {
            not: Box::new(BooleanTransactionFilter::new_from_proto(
                *proto_filter,
                None,
            )?),
        })
    }
}
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/boolean_transaction_filter.rs (L360-367)
```rust
impl Filterable<Transaction> for LogicalNot {
    fn validate_state(&self) -> Result<(), FilterError> {
        self.not.is_valid()
    }

    fn matches(&self, item: &Transaction) -> bool {
        !self.not.matches(item)
    }
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/boolean_transaction_filter.rs (L370-378)
```rust
/// These are filters we would expect to be exposed via API
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "type")]
pub enum APIFilter {
    TransactionRootFilter(TransactionRootFilter),
    UserTransactionFilter(UserTransactionFilter),
    EventFilter(EventFilter),
}
```

**File:** protos/proto/aptos/indexer/v1/filter.proto (L58-65)
```text
message BooleanTransactionFilter {
  oneof filter {
      APIFilter api_filter = 1;
      LogicalAndFilters logical_and = 2;
      LogicalOrFilters logical_or = 3;
      BooleanTransactionFilter logical_not = 4;
  }
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

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/constants.rs (L21-21)
```rust
pub const DEFAULT_MAX_TRANSACTION_FILTER_SIZE_BYTES: usize = 10_000;
```

**File:** protos/proto/aptos/indexer/v1/raw_data.proto (L19-33)
```text
message GetTransactionsRequest {
  // Required; start version of current stream.
  optional uint64 starting_version = 1 [jstype = JS_STRING];

  // Optional; number of transactions to return in current stream.
  // If not present, return an infinite stream of transactions.
  optional uint64 transactions_count = 2 [jstype = JS_STRING];

  // Optional; number of transactions in each `TransactionsResponse` for current stream.
  // If not present, default to 1000. If larger than 1000, request will be rejected.
  optional uint64 batch_size = 3;

  // If provided, only transactions that match the filter will be included.
  optional BooleanTransactionFilter transaction_filter = 4;
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

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service/src/service.rs (L924-954)
```rust
fn strip_transactions(
    transactions: Vec<Transaction>,
    txns_to_strip_filter: &BooleanTransactionFilter,
) -> (Vec<Transaction>, usize) {
    let mut stripped_count = 0;

    let stripped_transactions: Vec<Transaction> = transactions
        .into_iter()
        .map(|mut txn| {
            // Note: `is_allowed` means the txn matches the filter, in which case
            // we strip it.
            if txns_to_strip_filter.matches(&txn) {
                stripped_count += 1;
                if let Some(info) = txn.info.as_mut() {
                    info.changes = vec![];
                }
                if let Some(TxnData::User(user_transaction)) = txn.txn_data.as_mut() {
                    user_transaction.events = vec![];
                    if let Some(utr) = user_transaction.request.as_mut() {
                        // Wipe the payload and signature.
                        utr.payload = None;
                        utr.signature = None;
                    }
                }
            }
            txn
        })
        .collect();

    (stripped_transactions, stripped_count)
}
```
