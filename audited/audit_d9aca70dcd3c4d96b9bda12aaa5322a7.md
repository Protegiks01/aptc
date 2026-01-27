# Audit Report

## Title
Stack Overflow DoS in Indexer-GRPC Transaction Filter via Unbounded NOT Operation Nesting

## Summary
The transaction filter parsing in the indexer-grpc service lacks depth limits on nested `not()` operations, allowing attackers to trigger stack overflow by submitting deeply nested filter expressions. This can crash the indexer-grpc service, causing denial of service for data consumers.

## Finding Description

The `BooleanTransactionFilter` in the indexer-grpc service allows clients to submit complex filter expressions to query blockchain transactions. The filter supports logical operations including NOT, which creates nested filter structures. [1](#0-0) 

Each `not()` operation allocates a `Box<BooleanTransactionFilter>`, creating recursive nesting. The vulnerability has two components:

**1. Inadequate Size Validation:**
The `new_from_proto()` function checks the protobuf encoded size against `max_filter_size`: [2](#0-1) 

However, this check only validates the serialized message size (default 10,000 bytes), not the logical nesting depth. Due to protobuf's compact encoding, thousands of nested NOT operations can fit within 10KB.

**2. Unbounded Recursion in Nested Parsing:**
When parsing nested filters, the recursive calls bypass the size check by passing `None`: [3](#0-2) 

This creates two recursive attack vectors:
- **Parsing recursion**: `new_from_proto` → `LogicalNot::try_from` → `new_from_proto` (unbounded)
- **Evaluation recursion**: `matches()` → `LogicalNot::matches()` → `matches()` (unbounded) [4](#0-3) 

**Attack Path:**
1. Attacker constructs protobuf message with ~5,000 nested NOT operations (fits in <10KB)
2. Client sends `GetTransactionsRequest` with malicious filter to indexer-grpc service
3. Service accepts filter (encoded size < 10KB limit) [5](#0-4) 

4. Parsing triggers stack overflow via unbounded `new_from_proto` recursion
5. Indexer-grpc service crashes

## Impact Explanation

**Severity: Medium**

This vulnerability allows DoS attacks against the indexer-grpc service, an off-chain data indexing component. While this can disrupt data availability for ecosystem applications, it does NOT affect:
- Blockchain consensus or validator operations
- On-chain state or transaction execution  
- Funds or asset security
- Core blockchain infrastructure

The impact is limited to auxiliary infrastructure per the bug bounty criteria. While "API crashes" is listed under High severity, this applies to critical node APIs, not auxiliary indexer services that don't affect blockchain operations.

## Likelihood Explanation

**Likelihood: High**

The attack is trivial to execute:
- No authentication required beyond normal API access
- Payload easily constructed (simple nested protobuf structure)
- Deterministic crash on any indexer-grpc instance
- Low resource cost for attacker (~10KB payload)

## Recommendation

Implement depth limits for filter nesting:

```rust
pub fn new_from_proto(
    proto_filter: aptos_protos::indexer::v1::BooleanTransactionFilter,
    max_filter_size: Option<usize>,
    max_depth: usize,  // Add depth parameter
) -> Result<Self> {
    if max_depth == 0 {
        return Err(anyhow!("Filter nesting depth exceeded maximum"));
    }
    
    // existing size check...
    
    Ok(match proto_filter.filter.ok_or(...)? {
        // Pass decremented depth to recursive calls
        Filter::LogicalAnd(logical_and) => {
            let filters = logical_and.filters
                .into_iter()
                .map(|f| Self::new_from_proto(f, max_filter_size, max_depth - 1))
                .collect::<Result<_>>()?;
            BooleanTransactionFilter::And(LogicalAnd { and: filters })
        },
        Filter::LogicalNot(logical_not) => {
            BooleanTransactionFilter::Not(LogicalNot {
                not: Box::new(Self::new_from_proto(*logical_not, max_filter_size, max_depth - 1)?)
            })
        },
        // Similar for LogicalOr...
    })
}
```

Set reasonable limit (e.g., 50 levels) in the entry point: [6](#0-5) 

## Proof of Concept

```rust
#[test]
fn test_deeply_nested_not_overflow() {
    use aptos_protos::indexer::v1::BooleanTransactionFilter as ProtoBTF;
    use aptos_protos::indexer::v1::boolean_transaction_filter::Filter;
    use aptos_protos::indexer::v1::{ApiFilter, TransactionRootFilter};
    
    // Build deeply nested NOT filter
    let mut filter = ProtoBTF {
        filter: Some(Filter::ApiFilter(ApiFilter {
            filter: Some(aptos_protos::indexer::v1::api_filter::Filter::TransactionRootFilter(
                TransactionRootFilter { success: Some(true), transaction_type: None }
            ))
        }))
    };
    
    // Nest 5000 NOT operations
    for _ in 0..5000 {
        filter = ProtoBTF {
            filter: Some(Filter::LogicalNot(Box::new(filter)))
        };
    }
    
    // Encoded size is small (~10KB), passes size check
    println!("Encoded size: {} bytes", filter.encoded_len());
    assert!(filter.encoded_len() < 10_000);
    
    // But parsing triggers stack overflow
    let result = BooleanTransactionFilter::new_from_proto(filter, Some(10_000));
    // This will crash with stack overflow in unprotected code
}
```

## Notes

This vulnerability exists in the indexer-grpc auxiliary infrastructure, not in critical blockchain consensus or execution paths. While it enables DoS attacks against data indexing services, it does not compromise blockchain security, validator operations, or on-chain state. The severity is Medium per bug bounty criteria as it affects non-critical infrastructure availability rather than core protocol security.

### Citations

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

**File:** ecosystem/indexer-grpc/transaction-filter/src/boolean_transaction_filter.rs (L213-217)
```rust
    pub fn not(self) -> Self {
        BooleanTransactionFilter::Not(LogicalNot {
            not: Box::new(self),
        })
    }
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/boolean_transaction_filter.rs (L345-357)
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
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/boolean_transaction_filter.rs (L360-368)
```rust
impl Filterable<Transaction> for LogicalNot {
    fn validate_state(&self) -> Result<(), FilterError> {
        self.not.is_valid()
    }

    fn matches(&self, item: &Transaction) -> bool {
        !self.not.matches(item)
    }
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/constants.rs (L21-21)
```rust
pub const DEFAULT_MAX_TRANSACTION_FILTER_SIZE_BYTES: usize = 10_000;
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
