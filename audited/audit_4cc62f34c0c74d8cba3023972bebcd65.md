# Audit Report

## Title
Mempool Capacity Information Disclosure via HTTP 507 Insufficient Storage Error

## Summary
The Aptos API exposes detailed mempool capacity metrics (current size and maximum capacity) through HTTP 507 error responses when transaction submission fails due to mempool saturation. This information disclosure aids attackers in planning precise DoS attacks targeting mempool exhaustion.

## Finding Description

The vulnerability exists in the error handling chain from mempool transaction rejection to API response:

When the mempool reaches capacity, it returns a status with detailed metrics: [1](#0-0) 

This message is preserved through the error conversion chain and exposed via the REST API. The conversion occurs in two places:

1. Both `MempoolIsFull` and `TooManyTransactions` codes are converted to `AptosErrorCode::MempoolIsFull` with the original message intact: [2](#0-1) 

2. This error code triggers an HTTP 507 Insufficient Storage response: [3](#0-2) 

The disclosed information includes:
- **Global mempool**: "Mempool is full. Mempool size: X, Capacity: Y"
- **Per-account limits**: "Mempool over capacity for account. Number of seq number transactions from account: X Capacity per account: Y" [4](#0-3) 

This violates the security principle of minimizing information disclosure about internal system state that could aid adversarial planning.

## Impact Explanation

This is a **Low Severity** issue per Aptos bug bounty criteria: "Minor information leaks."

The vulnerability enables attackers to:
1. **Precisely measure mempool capacity** without probing
2. **Monitor real-time mempool utilization** to optimize attack timing
3. **Understand per-account transaction limits** for distributed attacks
4. **Coordinate multi-source DoS attacks** with exact capacity knowledge

While this doesn't directly cause harm, it significantly reduces the reconnaissance effort required for mempool exhaustion attacks, allowing attackers to:
- Calculate exact transaction volumes needed to saturate the mempool
- Time attacks to periods of high natural load (when mempool is near capacity)
- Distribute attack traffic across accounts to bypass per-account limits

## Likelihood Explanation

**Likelihood: High**

The vulnerability is trivially exploitable:
1. **No special privileges required** - any user can submit transactions
2. **No complex exploit needed** - simply submit transactions until rejected
3. **Information is immediately disclosed** - no timing or side-channel analysis needed
4. **Occurs naturally during high load** - legitimate users will encounter this during network congestion

The information disclosure is deterministic and always occurs when capacity limits are exceeded.

## Recommendation

Replace detailed capacity metrics with generic error messages that don't reveal internal system state:

**For global mempool capacity:**
```rust
return MempoolStatus::new(MempoolStatusCode::MempoolIsFull).with_message(
    "Mempool is currently at capacity. Please retry later.".to_string()
);
```

**For per-account limits:**
```rust
return MempoolStatus::new(MempoolStatusCode::TooManyTransactions).with_message(
    "Account has too many pending transactions. Please wait for existing transactions to be processed.".to_string()
);
```

This maintains error reporting functionality while preventing information disclosure. Internal monitoring systems should log detailed metrics separately rather than exposing them to external users.

## Proof of Concept

```rust
#[tokio::test]
async fn test_mempool_capacity_disclosure() {
    // Setup: Create a node with small mempool capacity for testing
    let mut config = NodeConfig::default();
    config.mempool.capacity = 10;  // Set low capacity
    let node = start_test_node(config).await;
    
    // Step 1: Fill the mempool by submitting transactions
    let mut transactions = vec![];
    for i in 0..10 {
        let txn = create_test_transaction(i);
        node.submit_transaction(txn).await.unwrap();
        transactions.push(txn);
    }
    
    // Step 2: Submit one more transaction to exceed capacity
    let overflow_txn = create_test_transaction(11);
    let result = node.submit_transaction(overflow_txn).await;
    
    // Step 3: Verify the error response contains capacity information
    match result {
        Err(ApiError::InsufficientStorage(msg)) => {
            // The vulnerability: error message contains exact capacity numbers
            assert!(msg.contains("Mempool size:"));
            assert!(msg.contains("Capacity:"));
            
            // An attacker can parse these values:
            let capacity = extract_capacity_from_message(&msg);
            println!("Disclosed mempool capacity: {}", capacity);
            
            // This allows precise DoS attack planning
            assert_eq!(capacity, 10);
        },
        _ => panic!("Expected InsufficientStorage error"),
    }
}

fn extract_capacity_from_message(msg: &str) -> usize {
    // Parse "Mempool is full. Mempool size: X, Capacity: Y"
    msg.split("Capacity: ")
        .nth(1)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap()
}
```

**Attack Scenario:**
1. Attacker submits transactions until receiving 507 error
2. Parse response to learn exact capacity (e.g., "Capacity: 5000")
3. Calculate: need 5000 transactions to saturate mempool
4. Launch coordinated attack with 5000+ transactions from multiple accounts
5. Monitor error messages to track saturation progress in real-time

## Notes

While mempool capacity configuration may be publicly documented, real-time capacity and utilization metrics should not be exposed to untrusted users. The current implementation essentially provides a free reconnaissance service to potential attackers. Even though an attacker could probe capacity empirically, requiring active probing increases attack cost and detection probability compared to passive information disclosure.

### Citations

**File:** mempool/src/core_mempool/transaction_store.rs (L312-316)
```rust
            return MempoolStatus::new(MempoolStatusCode::MempoolIsFull).with_message(format!(
                "Mempool is full. Mempool size: {}, Capacity: {}",
                self.system_ttl_index.size(),
                self.capacity,
            ));
```

**File:** mempool/src/core_mempool/transaction_store.rs (L325-331)
```rust
                        return MempoolStatus::new(MempoolStatusCode::TooManyTransactions).with_message(
                            format!(
                                "Mempool over capacity for account. Number of seq number transactions from account: {} Capacity per account: {}",
                                txns.seq_num_txns_len() ,
                                self.capacity_per_user,
                            ),
                        );
```

**File:** api/src/transactions.rs (L1449-1453)
```rust
            MempoolStatusCode::MempoolIsFull | MempoolStatusCode::TooManyTransactions => {
                Err(AptosError::new_with_error_code(
                    &mempool_status.message,
                    AptosErrorCode::MempoolIsFull,
                ))
```

**File:** api/src/transactions.rs (L1549-1554)
```rust
                AptosErrorCode::MempoolIsFull => Err(
                    SubmitTransactionError::insufficient_storage_from_aptos_error(
                        error,
                        ledger_info,
                    ),
                ),
```
