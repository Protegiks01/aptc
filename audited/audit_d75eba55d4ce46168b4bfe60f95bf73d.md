# Audit Report

## Title
Empty LogicalOr Filter Validation Bypass Allows Unrestricted Transaction Stream Access

## Summary
The `LogicalOrFilters` implementation does not validate against empty filter vectors, allowing clients to craft logically degenerate filters (e.g., `NOT(OR())` or `OR(AND())`) that match all transactions, effectively bypassing the intended filtering mechanism in the indexer gRPC service.

## Finding Description

The Aptos indexer gRPC service uses `BooleanTransactionFilter` to allow clients to filter transaction streams. The `LogicalOr` implementation uses `.any()` on an empty iterator, which returns `false` by Rust semantics, while `LogicalAnd` uses `.all()`, which returns `true`. [1](#0-0) 

The validation logic only checks that each filter in the vector is valid, but never validates that the vector is non-empty: [2](#0-1) 

When filters are parsed from client requests, no additional validation occurs beyond size limits: [3](#0-2) [4](#0-3) 

The parsed filter is then used to retain only matching transactions before sending to clients: [5](#0-4) 

**Attack Vector:**
An attacker can construct filters like:
- `NOT(OR())` → evaluates to `NOT(false)` = `true` (matches everything)
- `OR(AND())` → evaluates to `OR(true)` = `true` (matches everything)

These bypass the filtering mechanism, allowing the client to receive all transactions regardless of the intended filter criteria.

## Impact Explanation

This issue falls under **Low Severity** per the Aptos bug bounty criteria as a "non-critical implementation bug."

While this allows filter bypass, the impact is limited:
1. The indexer gRPC service is a data query interface, not a consensus-critical component
2. No blockchain invariants are violated (consensus, state, funds remain secure)
3. The vulnerability only affects bandwidth optimization, not access control
4. Clients could alternatively connect without filters and receive all data anyway

The behavior does not lead to funds loss, consensus violations, or state corruption. It's a validation gap that allows logically degenerate filters rather than a fundamental security flaw.

## Likelihood Explanation

**High likelihood** that this can be exploited, as:
- Any client can send crafted filters via `GetTransactionsRequest`
- No authentication or special privileges required
- Construction is trivial: wrap an empty OR in a NOT operator
- The vulnerability is present in all deployments of the indexer service

However, the **practical impact is low** since the indexer is designed for open data access and filters are client-side optimizations rather than security boundaries.

## Recommendation

Add validation to reject empty filter vectors in both `LogicalAnd` and `LogicalOr`:

```rust
impl Filterable<Transaction> for LogicalOr {
    fn validate_state(&self) -> Result<(), FilterError> {
        if self.or.is_empty() {
            return Err(FilterError::from(anyhow!(
                "LogicalOr filter cannot have empty filters vector"
            )));
        }
        for filter in &self.or {
            filter.is_valid()?;
        }
        Ok(())
    }
    // ... matches() unchanged
}

impl Filterable<Transaction> for LogicalAnd {
    fn validate_state(&self) -> Result<(), FilterError> {
        if self.and.is_empty() {
            return Err(FilterError::from(anyhow!(
                "LogicalAnd filter cannot have empty filters vector"
            )));
        }
        for filter in &self.and {
            filter.is_valid()?;
        }
        Ok(())
    }
    // ... matches() unchanged
}
```

Additionally, call `.is_valid()` after parsing:

```rust
pub fn new_from_proto(
    proto_filter: aptos_protos::indexer::v1::BooleanTransactionFilter,
    max_filter_size: Option<usize>,
) -> Result<Self> {
    // ... existing size validation ...
    let filter = match proto_filter.filter.ok_or(...)? {
        // ... existing match arms ...
    };
    filter.is_valid()?; // Add validation call
    Ok(filter)
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod empty_filter_bypass_poc {
    use super::*;
    use aptos_protos::transaction::v1::Transaction;
    
    #[test]
    fn test_empty_or_with_not_matches_all() {
        // Create an empty OR filter wrapped in NOT
        let empty_or = LogicalOr { or: vec![] };
        let not_empty_or = LogicalNot {
            not: Box::new(BooleanTransactionFilter::Or(empty_or)),
        };
        
        // Create a test transaction
        let test_txn = Transaction::default();
        
        // Empty OR matches nothing (returns false)
        let or_filter = BooleanTransactionFilter::Or(LogicalOr { or: vec![] });
        assert_eq!(or_filter.matches(&test_txn), false);
        
        // NOT(empty OR) matches everything (returns true)
        let not_or_filter = BooleanTransactionFilter::Not(not_empty_or);
        assert_eq!(not_or_filter.matches(&test_txn), true);
        
        // This bypasses filtering - all transactions match!
    }
    
    #[test]
    fn test_or_with_empty_and_matches_all() {
        // Create OR containing empty AND
        let empty_and = LogicalAnd { and: vec![] };
        let or_with_empty_and = LogicalOr {
            or: vec![BooleanTransactionFilter::And(empty_and)],
        };
        
        let test_txn = Transaction::default();
        
        // Empty AND matches everything (returns true)
        let and_filter = BooleanTransactionFilter::And(LogicalAnd { and: vec![] });
        assert_eq!(and_filter.matches(&test_txn), true);
        
        // OR(empty AND) also matches everything
        let or_filter = BooleanTransactionFilter::Or(or_with_empty_and);
        assert_eq!(or_filter.matches(&test_txn), true);
    }
}
```

**Notes:**

This vulnerability exists in the indexer's transaction filtering logic but has limited security impact since:
1. The indexer gRPC service is not consensus-critical
2. Filters are bandwidth optimizations, not security boundaries
3. The mathematical behavior (empty OR = false, empty AND = true) is technically correct per boolean algebra
4. Missing validation allows degenerate filters but doesn't break blockchain invariants

The issue should be fixed to prevent client confusion and potential DoS through requesting all transactions, but it does not pose a critical security risk to the blockchain's core safety guarantees.

### Citations

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

**File:** ecosystem/indexer-grpc/transaction-filter/src/boolean_transaction_filter.rs (L327-333)
```rust
impl Filterable<Transaction> for LogicalOr {
    fn validate_state(&self) -> Result<(), FilterError> {
        for filter in &self.or {
            filter.is_valid()?;
        }
        Ok(())
    }
```

**File:** ecosystem/indexer-grpc/transaction-filter/src/boolean_transaction_filter.rs (L335-337)
```rust
    fn matches(&self, item: &Transaction) -> bool {
        self.or.iter().any(|filter| filter.matches(item))
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

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/file_store_operator_v2/file_store_reader.rs (L140-142)
```rust
                if let Some(ref filter) = filter {
                    transactions.retain(|t| filter.matches(t));
                }
```
