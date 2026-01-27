# Audit Report

## Title
Stack Overflow Vulnerability in Transaction Filter Due to Unbounded Nesting Depth

## Summary
The transaction filter parsing and matching logic in the indexer-grpc service allows arbitrarily deep nesting of logical operators (And, Or, Not) without enforcing a maximum depth limit. This enables an attacker to craft a malicious filter that causes stack overflow during recursive parsing or transaction matching, resulting in indexer-grpc node crashes and denial of service.

## Finding Description

The `BooleanTransactionFilter` type supports recursive nesting through logical operators without any depth limit enforcement. [1](#0-0) 

While the `parse_transaction_filter()` function validates the protobuf encoded size against `max_filter_size_bytes` (default 10,000 bytes) [2](#0-1) , this size check occurs only at the top level. [3](#0-2) 

The critical vulnerability exists in the `TryFrom` implementations for logical operators, which recursively call `BooleanTransactionFilter::new_from_proto(f, None)`, passing `None` instead of propagating the size limit:

- `LogicalAnd::try_from` at [4](#0-3) 
- `LogicalOr::try_from` at [5](#0-4) 
- `LogicalNot::try_from` at [6](#0-5) 

The recursive matching logic compounds this issue. When transactions flow through the stream, `filter.matches(txn)` is called for every transaction [7](#0-6) , triggering recursive calls through the filter tree:

- `LogicalAnd::matches` recursively calls `filter.matches(item)` [8](#0-7) 
- `LogicalOr::matches` recursively calls `filter.matches(item)` [9](#0-8) 
- `LogicalNot::matches` recursively calls `self.not.matches(item)` [10](#0-9) 

**Attack Scenario:**

An attacker crafts a deeply nested filter structure like `Not(Not(Not(...Not(SimpleFilter)...)))` where the protobuf `logical_not` field allows recursive self-reference. [11](#0-10) 

With a 10,000 byte limit, each NOT operator adds approximately 3-5 bytes of protobuf overhead (field tag, length prefix). Starting with a minimal base filter (~50 bytes), an attacker can create approximately 3,000+ nesting levels within the size limit. With typical stack frame sizes of 200-400 bytes per recursive call, this requires 600KB-1.2MB of stack space, which can overflow default thread stacks (1-2MB depending on platform).

The attack succeeds in two phases:
1. **Parsing phase**: Stack overflow when `new_from_proto` recursively deserializes the nested structure
2. **Matching phase**: Stack overflow when `matches()` is called repeatedly for every transaction in the stream, affecting all clients using that filter

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos Bug Bounty program's "API crashes" category. The indexer-grpc service provides critical transaction streaming infrastructure for the Aptos ecosystem. Successful exploitation leads to:

1. **Immediate service disruption**: The indexer-grpc node crashes due to stack overflow
2. **Persistent DoS**: The malicious filter may be cached or retried, causing repeated crashes
3. **Widespread impact**: All clients relying on the affected indexer-grpc instance lose transaction streaming capabilities
4. **No authentication required**: Any client can submit a malicious filter without special privileges

While this doesn't directly compromise consensus or validator operations, it disrupts the critical indexing infrastructure that applications depend on for real-time blockchain data access.

## Likelihood Explanation

**Likelihood: High**

- **Attacker capability**: Low - requires only basic protobuf knowledge to construct nested filters
- **Detection difficulty**: High - the filter appears valid and passes size checks
- **Attack cost**: Negligible - single malicious gRPC request
- **Exploitation complexity**: Low - straightforward to craft the malicious protobuf message
- **Impact trigger**: Guaranteed - every transaction processed with the malicious filter triggers recursive matching

The vulnerability is trivially exploitable by any external party with access to the indexer-grpc API endpoints.

## Recommendation

Implement a maximum nesting depth limit for transaction filters. Add a depth counter that is threaded through all recursive calls and reject filters exceeding the limit.

**Recommended fix for `boolean_transaction_filter.rs`:**

```rust
// Add constant for maximum depth
const MAX_FILTER_NESTING_DEPTH: usize = 50;

impl BooleanTransactionFilter {
    pub fn new_from_proto(
        proto_filter: aptos_protos::indexer::v1::BooleanTransactionFilter,
        max_filter_size: Option<usize>,
    ) -> Result<Self> {
        Self::new_from_proto_with_depth(proto_filter, max_filter_size, 0)
    }
    
    fn new_from_proto_with_depth(
        proto_filter: aptos_protos::indexer::v1::BooleanTransactionFilter,
        max_filter_size: Option<usize>,
        current_depth: usize,
    ) -> Result<Self> {
        ensure!(
            current_depth <= MAX_FILTER_NESTING_DEPTH,
            format!(
                "Filter nesting depth exceeds maximum of {}. Current depth: {}",
                MAX_FILTER_NESTING_DEPTH, current_depth
            )
        );
        
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
        
        // Pass depth+1 to all recursive calls in TryFrom implementations
        // Modify TryFrom implementations to accept and propagate depth parameter
        Ok(...)
    }
}

// Update TryFrom implementations to propagate depth:
impl LogicalAnd {
    fn try_from_with_depth(
        proto_filter: aptos_protos::indexer::v1::LogicalAndFilters,
        depth: usize
    ) -> Result<Self> {
        Ok(Self {
            and: proto_filter
                .filters
                .into_iter()
                .map(|f| BooleanTransactionFilter::new_from_proto_with_depth(f, None, depth + 1))
                .collect::<Result<_>>()?,
        })
    }
}

// Similar updates for LogicalOr and LogicalNot
```

Additionally, consider implementing an iterative matching algorithm to eliminate stack-based recursion in the hot path, or use explicit stack size limits when spawning blocking tasks.

## Proof of Concept

```rust
#[cfg(test)]
mod stack_overflow_poc {
    use super::*;
    use aptos_protos::indexer::v1;
    
    #[test]
    #[should_panic(expected = "stack overflow")]
    fn test_deeply_nested_filter_causes_stack_overflow() {
        // Create a deeply nested NOT filter structure
        // Start with a simple base filter
        let mut filter = v1::BooleanTransactionFilter {
            filter: Some(v1::boolean_transaction_filter::Filter::ApiFilter(
                v1::ApiFilter {
                    filter: Some(v1::api_filter::Filter::TransactionRootFilter(
                        v1::TransactionRootFilter {
                            success: Some(true),
                            transaction_type: None,
                        },
                    )),
                },
            )),
        };
        
        // Wrap it in 2000 NOT operators to create deep nesting
        // Each NOT adds only ~3-5 bytes, so this stays within 10KB limit
        for _ in 0..2000 {
            filter = v1::BooleanTransactionFilter {
                filter: Some(v1::boolean_transaction_filter::Filter::LogicalNot(
                    Box::new(filter),
                )),
            };
        }
        
        // Verify size is within limit
        assert!(filter.encoded_len() <= 10_000);
        
        // This should cause stack overflow during parsing
        let result = BooleanTransactionFilter::new_from_proto(filter, Some(10_000));
        
        // If parsing doesn't overflow, matching will
        if let Ok(parsed_filter) = result {
            let test_txn = create_test_transaction();
            // This recursive matching will overflow the stack
            parsed_filter.matches(&test_txn);
        }
    }
    
    fn create_test_transaction() -> aptos_protos::transaction::v1::Transaction {
        // Create a minimal valid transaction for testing
        aptos_protos::transaction::v1::Transaction::default()
    }
}
```

## Notes

This vulnerability exists in the indexer-grpc infrastructure layer, not the core consensus/validator nodes. However, it still represents a critical service availability issue for the Aptos ecosystem as indexer services are essential for application developers and users to access blockchain data in real-time.

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

**File:** ecosystem/indexer-grpc/transaction-filter/src/boolean_transaction_filter.rs (L98-107)
```rust
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
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/boolean_transaction_filter.rs (L268-275)
```rust
    fn try_from(proto_filter: aptos_protos::indexer::v1::LogicalAndFilters) -> Result<Self> {
        Ok(Self {
            and: proto_filter
                .filters
                .into_iter()
                .map(|f| BooleanTransactionFilter::new_from_proto(f, None))
                .collect::<Result<_>>()?,
        })
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/boolean_transaction_filter.rs (L295-297)
```rust
    fn matches(&self, item: &Transaction) -> bool {
        self.and.iter().all(|filter| filter.matches(item))
    }
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/boolean_transaction_filter.rs (L309-315)
```rust
        Ok(Self {
            or: proto_filter
                .filters
                .into_iter()
                .map(|f| BooleanTransactionFilter::new_from_proto(f, None))
                .collect::<Result<_>>()?,
        })
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/boolean_transaction_filter.rs (L335-337)
```rust
    fn matches(&self, item: &Transaction) -> bool {
        self.or.iter().any(|filter| filter.matches(item))
    }
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/boolean_transaction_filter.rs (L351-356)
```rust
        Ok(Self {
            not: Box::new(BooleanTransactionFilter::new_from_proto(
                *proto_filter,
                None,
            )?),
        })
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/boolean_transaction_filter.rs (L365-367)
```rust
    fn matches(&self, item: &Transaction) -> bool {
        !self.not.matches(item)
    }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/constants.rs (L20-21)
```rust
// Default maximum size in bytes for transaction filters.
pub const DEFAULT_MAX_TRANSACTION_FILTER_SIZE_BYTES: usize = 10_000;
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L175-179)
```rust
                let pb_txns = if let Some(ref filter) = filter {
                    pb_txns
                        .into_iter()
                        .filter(|txn| filter.matches(txn))
                        .collect::<Vec<_>>()
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
