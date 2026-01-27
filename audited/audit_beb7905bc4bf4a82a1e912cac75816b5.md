# Audit Report

## Title
Indexer gRPC Service Crash on Unknown Transaction Type

## Summary
The `TransactionRootFilter::matches()` method in the indexer gRPC transaction filter uses `.expect()` on `TransactionType::try_from()`, causing the entire indexer service to panic and crash when encountering unknown transaction type values. This creates a denial-of-service condition triggered by protocol upgrades or malformed transaction data.

## Finding Description
The vulnerability exists in the transaction filtering logic: [1](#0-0) 

The `TransactionType` enum is a prost-generated protobuf enumeration with defined values: [2](#0-1) 

When `try_from()` receives an i32 value not in the enum (e.g., 5-19, 22+), it returns an `Err(DecodeError)`. The `.expect()` call then panics with "Invalid transaction type".

This panic occurs during transaction stream processing in the IndexerStreamCoordinator: [3](#0-2) 

The panic in the `spawn_blocking` task causes `try_join_all` to fail, which triggers a panic that crashes the entire service: [4](#0-3) 

**Attack Scenario:**
1. Blockchain protocol adds a new transaction type (e.g., `TRANSACTION_TYPE_NEW = 22`) via upgrade
2. Updated validator nodes begin producing blocks with this new transaction type
3. Indexer nodes running old code encounter transactions with `type = 22`
4. Filter attempts conversion: `TransactionType::try_from(22)` returns `Err`
5. `.expect()` panics with "Invalid transaction type"
6. Panic propagates through task failure → `try_join_all` error → coordinator panic
7. Entire indexer gRPC service crashes
8. All client subscriptions are terminated

## Impact Explanation
This qualifies as **High Severity** per Aptos bug bounty criteria:
- **API crashes**: Complete crash of the indexer gRPC fullnode service
- **Service unavailability**: All downstream clients lose access to transaction streaming
- **Cascading failures**: Any system depending on the indexer API becomes unavailable

While this doesn't directly affect consensus or validator block production, it represents a significant availability failure for the indexer infrastructure, which is critical for dApps, wallets, and monitoring systems.

## Likelihood Explanation
**Likelihood: High**

This vulnerability will definitely occur during normal protocol evolution:
- **Protocol upgrades**: Any addition of new transaction types triggers the panic
- **No attacker required**: Legitimate blockchain operation causes the failure
- **Widespread impact**: All indexer nodes running outdated code will crash simultaneously
- **Difficult recovery**: Requires code update and redeployment, cannot be fixed with restart alone

The prost library's default behavior for unknown enum values is to return an error, which is the correct safety mechanism. The vulnerability arises from improper error handling with `.expect()` in application code.

## Recommendation
Replace the `.expect()` with graceful error handling. The filter should either:

**Option 1 - Skip unknown types (recommended):**
```rust
if let Some(txn_type) = &self.txn_type {
    match TransactionType::try_from(item.r#type) {
        Ok(actual_type) if txn_type != &actual_type => return false,
        Err(_) => {
            // Unknown transaction type - allow through filter
            // Log warning for monitoring
        }
        _ => {} // Type matches or is unknown, continue
    }
}
```

**Option 2 - Reject unknown types:**
```rust
if let Some(txn_type) = &self.txn_type {
    let actual_type = match TransactionType::try_from(item.r#type) {
        Ok(t) => t,
        Err(_) => return false, // Reject unknown types
    };
    if txn_type != &actual_type {
        return false;
    }
}
```

Option 1 is preferred as it maintains forward compatibility with protocol upgrades.

## Proof of Concept

```rust
// Test demonstrating the panic
#[cfg(test)]
mod test {
    use super::*;
    use aptos_protos::transaction::v1::{Transaction, transaction::TransactionType};
    
    #[test]
    #[should_panic(expected = "Invalid transaction type")]
    fn test_unknown_transaction_type_panics() {
        let filter = TransactionRootFilter {
            success: None,
            txn_type: Some(TransactionType::User),
        };
        
        let mut transaction = Transaction {
            r#type: 22, // Unknown transaction type (future type)
            ..Default::default()
        };
        
        // This will panic, crashing the indexer
        filter.matches(&transaction);
    }
    
    #[test]
    fn test_transaction_type_values() {
        // Valid types: 0, 1, 2, 3, 4, 20, 21
        // Any value outside this set will cause panic
        assert!(TransactionType::try_from(5).is_err()); // Invalid
        assert!(TransactionType::try_from(22).is_err()); // Invalid (future type)
    }
}
```

**Notes**

This vulnerability demonstrates a common pattern in Rust error handling where `.expect()` or `.unwrap()` on fallible operations creates crash conditions. The prost library correctly returns `Result` types for conversions, but the application code fails to handle the error case. This is particularly critical in long-running services like indexers where crashes have significant operational impact.

The fix requires updating the codebase to handle unknown transaction types gracefully, allowing the indexer to continue operating during protocol transitions. This change should be coupled with monitoring/alerting for unknown types to detect protocol mismatches early.

### Citations

**File:** ecosystem/indexer-grpc/transaction-filter/src/filters/transaction_root.rs (L67-73)
```rust
        if let Some(txn_type) = &self.txn_type {
            if txn_type
                != &TransactionType::try_from(item.r#type).expect("Invalid transaction type")
            {
                return false;
            }
        }
```

**File:** protos/proto/aptos/transaction/v1/transaction.proto (L47-56)
```text
  enum TransactionType {
    TRANSACTION_TYPE_UNSPECIFIED = 0;
    TRANSACTION_TYPE_GENESIS = 1;
    TRANSACTION_TYPE_BLOCK_METADATA = 2;
    TRANSACTION_TYPE_STATE_CHECKPOINT = 3;
    TRANSACTION_TYPE_USER = 4;
    // values 5-19 skipped for no reason
    TRANSACTION_TYPE_VALIDATOR = 20;
    TRANSACTION_TYPE_BLOCK_EPILOGUE = 21;
  }
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L175-179)
```rust
                let pb_txns = if let Some(ref filter) = filter {
                    pb_txns
                        .into_iter()
                        .filter(|txn| filter.matches(txn))
                        .collect::<Vec<_>>()
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/stream_coordinator.rs (L202-208)
```rust
        let responses = match futures::future::try_join_all(tasks).await {
            Ok(res) => res.into_iter().flatten().collect::<Vec<_>>(),
            Err(err) => panic!(
                "[Indexer Fullnode] Error processing transaction batches: {:?}",
                err
            ),
        };
```
