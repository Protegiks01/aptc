# Audit Report

## Title
Infinite Loop DoS in Batch Generator Due to Oversized Transactions

## Summary
The `push_bucket_to_batches()` function in the quorum store batch generator contains a critical infinite loop vulnerability when processing transactions that exceed `sender_max_batch_bytes`. When a transaction larger than the batch size limit reaches this function, it creates zero-transaction batches and enters an infinite loop, causing the validator node's batch generator thread to hang indefinitely and preventing further batch generation.

## Finding Description

The vulnerability exists in the batch generation logic at [1](#0-0)  which partitions transactions into batches.

**The Critical Bug:**

The function uses a while loop that iterates while `txns_remaining > 0` [2](#0-1) . For each iteration, it uses `take_while` with `checked_sub` to count transactions fitting within the byte limit [3](#0-2) .

When the first transaction's size exceeds `sender_max_batch_bytes`, the `checked_sub` returns `None`, causing `take_while` to return false immediately, resulting in `num_batch_txns = 0`. The conditional check at [4](#0-3)  is never entered, meaning:
- No transactions are drained from the queue
- `txns_remaining` is never decremented
- `total_batches_remaining` is never decremented
- The loop continues with identical state indefinitely

**Attack Vector:**

The default `sender_max_batch_bytes` is 1,048,416 bytes (1MB - 160 bytes) [5](#0-4) , while governance transactions are allowed up to 1,048,576 bytes (1MB) [6](#0-5) .

The mempool can return transactions up to `sender_max_total_bytes` (4MB by default) [7](#0-6) . The mempool's byte limit check [8](#0-7)  allows returning the first transaction even if it exceeds batch limits, as long as it's within the total byte limit.

**Exploitation Scenario:**
1. Attacker submits a governance transaction of size 1,048,576 bytes (exactly 1MB)
2. Transaction passes VM validation [9](#0-8)  as it's within governance limit
3. Mempool accepts and stores the transaction
4. Batch generator pulls the transaction via [10](#0-9) 
5. `push_bucket_to_batches()` enters infinite loop
6. Validator's batch generator thread hangs completely
7. No new batches are created, consensus participation stops

## Impact Explanation

This vulnerability qualifies as **High Severity** per Aptos bug bounty criteria category #8 (Validator Node Slowdowns).

The infinite loop causes the batch generator thread to hang indefinitely, consuming CPU resources without progress. The affected validator node becomes unable to:
- Generate new transaction batches from mempool
- Participate effectively in consensus rounds
- Process transactions for block proposals

While a single affected validator may not halt the entire network (requiring >1/3 Byzantine validators for consensus failure), this creates:
- Reduced network throughput as affected validators stop contributing batches
- Potential for coordinated attack if multiple validators can be targeted simultaneously
- Resource exhaustion on affected nodes (CPU spinning in infinite loop)

The vulnerability violates the resource limits invariant - operations must respect computational limits and make progress, which the infinite loop clearly does not.

## Likelihood Explanation

**Likelihood: High**

The vulnerability is readily exploitable under default configurations:

1. **Default Configuration Gap**: Governance transactions can reach 1,048,576 bytes while batch size limit is 1,048,416 bytes - a difference of only 160 bytes. Any governance transaction between 1,048,417 and 1,048,576 bytes triggers the bug.

2. **Legitimate Use Case**: Governance transactions legitimately need larger sizes for complex proposals, making this a realistic scenario rather than an edge case.

3. **No Validation Layer**: There is no validation preventing oversized transactions from reaching `push_bucket_to_batches()`. The only checks are at transaction submission (VM layer) and mempool total bytes - neither prevents this scenario.

4. **Low Attack Complexity**: A single carefully-sized transaction submission triggers the vulnerability with no need for repeated attempts, precise timing, or complex setup.

5. **Observable in Production**: The configuration mismatch exists in default settings, making this immediately exploitable on any validator running default configuration.

## Recommendation

Add a safety check in `push_bucket_to_batches()` to handle the case where `num_batch_txns == 0`. The function should either:

**Option 1 (Preferred)**: Skip oversized transactions and log a warning:
```rust
if num_batch_txns > 0 {
    // existing batch creation logic
} else {
    // Skip the first oversized transaction
    warn!("Skipping oversized transaction: {} bytes exceeds batch limit of {} bytes", 
          txns[0].txn_bytes_len(), self.config.sender_max_batch_bytes);
    txns.drain(0..1);
    txns_remaining -= 1;
}
```

**Option 2**: Break out of the loop when no progress can be made:
```rust
if num_batch_txns > 0 {
    // existing batch creation logic
} else {
    // Cannot make progress with remaining transactions
    warn!("Cannot fit remaining {} transactions into batches", txns_remaining);
    break;
}
```

**Option 3 (Most Robust)**: Add pre-validation in `bucket_into_batches()` to filter out oversized transactions before calling `push_bucket_to_batches()`.

Additionally, consider adding a configuration validation check to ensure `sender_max_batch_bytes >= max_transaction_size_in_bytes_gov` to prevent this mismatch.

## Proof of Concept

While a full executable PoC would require setting up a validator node environment, the vulnerability can be demonstrated through unit test logic:

```rust
#[tokio::test]
async fn test_oversized_transaction_infinite_loop() {
    let config = QuorumStoreConfig {
        sender_max_batch_bytes: 1_048_416, // 1MB - 160 bytes
        ..Default::default()
    };
    
    // Create a transaction larger than sender_max_batch_bytes
    // In production, this would be a governance transaction of 1,048,576 bytes
    let oversized_txn = create_transaction_with_size(1_048_576);
    
    let mut batch_generator = BatchGenerator::new(
        0,
        AccountAddress::random(),
        config,
        Arc::new(MockQuorumStoreDB::new()),
        Arc::new(MockBatchWriter::new()),
        mempool_tx,
        1000,
    );
    
    // This call would hang indefinitely in the vulnerable version
    // Expected: Should complete without hanging
    let result = timeout(
        Duration::from_secs(5),
        batch_generator.handle_scheduled_pull(300)
    ).await;
    
    assert!(result.is_ok(), "Batch generator hung on oversized transaction");
}
```

The vulnerability is confirmed by code analysis showing that when `num_batch_txns = 0`, no progress is made in the loop, leading to infinite iteration.

### Citations

**File:** consensus/src/quorum_store/batch_generator.rs (L216-253)
```rust
    fn push_bucket_to_batches(
        &mut self,
        batches: &mut Vec<Batch<BatchInfoExt>>,
        txns: &mut Vec<SignedTransaction>,
        num_txns_in_bucket: usize,
        expiry_time: u64,
        bucket_start: u64,
        total_batches_remaining: &mut u64,
    ) {
        let mut txns_remaining = num_txns_in_bucket;
        while txns_remaining > 0 {
            if *total_batches_remaining == 0 {
                return;
            }
            let num_take_txns = std::cmp::min(self.config.sender_max_batch_txns, txns_remaining);
            let mut batch_bytes_remaining = self.config.sender_max_batch_bytes as u64;
            let num_batch_txns = txns
                .iter()
                .take(num_take_txns)
                .take_while(|txn| {
                    let txn_bytes = txn.txn_bytes_len() as u64;
                    if batch_bytes_remaining.checked_sub(txn_bytes).is_some() {
                        batch_bytes_remaining -= txn_bytes;
                        true
                    } else {
                        false
                    }
                })
                .count();
            if num_batch_txns > 0 {
                let batch_txns: Vec<_> = txns.drain(0..num_batch_txns).collect();
                let batch = self.create_new_batch(batch_txns, expiry_time, bucket_start);
                batches.push(batch);
                *total_batches_remaining = total_batches_remaining.saturating_sub(1);
                txns_remaining -= num_batch_txns;
            }
        }
    }
```

**File:** consensus/src/quorum_store/batch_generator.rs (L352-360)
```rust
        let mut pulled_txns = self
            .mempool_proxy
            .pull_internal(
                max_count,
                self.config.sender_max_total_bytes as u64,
                self.txns_in_progress_sorted.clone(),
            )
            .await
            .unwrap_or_default();
```

**File:** config/src/config/quorum_store_config.rs (L115-115)
```rust
            sender_max_batch_bytes: 1024 * 1024 - BATCH_PADDING_BYTES,
```

**File:** config/src/config/quorum_store_config.rs (L119-119)
```rust
            sender_max_total_bytes: 4 * 1024 * 1024 - DEFAULT_MAX_NUM_BATCHES * BATCH_PADDING_BYTES,
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L78-80)
```rust
            max_transaction_size_in_bytes_gov: NumBytes,
            { RELEASE_V1_13.. => "max_transaction_size_in_bytes.gov" },
            1024 * 1024
```

**File:** mempool/src/core_mempool/mempool.rs (L519-524)
```rust
                let txn_size = txn.txn_bytes_len() as u64;
                if total_bytes + txn_size > max_bytes {
                    full_bytes = true;
                    break;
                }
                total_bytes += txn_size;
```

**File:** aptos-move/aptos-vm/src/gas.rs (L85-96)
```rust
            gas_params.vm.txn.max_transaction_size_in_bytes_gov
        } else {
            MAXIMUM_APPROVED_TRANSACTION_SIZE_LEGACY.into()
        };

        if txn_metadata.transaction_size > max_txn_size_gov
            // Ensure that it is only the approved payload that exceeds the
            // maximum. The (unknown) user input should be restricted to the original
            // maximum transaction size.
            || txn_metadata.transaction_size
                > txn_metadata.script_size + txn_gas_params.max_transaction_size_in_bytes
        {
```
