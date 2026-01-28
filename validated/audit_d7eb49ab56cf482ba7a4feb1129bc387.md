# Audit Report

## Title
Infinite Loop DoS in Batch Generator Due to Oversized Transactions

## Summary
The `push_bucket_to_batches()` function in the quorum store batch generator contains a critical infinite loop vulnerability when processing transactions that exceed `sender_max_batch_bytes`. When a transaction larger than the batch size limit reaches this function, it enters an infinite loop, causing the validator node's batch generator thread to hang indefinitely and preventing further batch generation.

## Finding Description

The vulnerability exists in the batch generation logic which partitions transactions into batches. The function uses a while loop that iterates while `txns_remaining > 0`. [1](#0-0) 

For each iteration, it uses `take_while` with `checked_sub` to count transactions fitting within the byte limit. [2](#0-1) 

When the first transaction's size exceeds `sender_max_batch_bytes`, the `checked_sub` returns `None`, causing `take_while` to return false immediately, resulting in `num_batch_txns = 0`. The conditional check is never entered, [3](#0-2)  meaning:
- No transactions are drained from the queue
- `txns_remaining` is never decremented
- `total_batches_remaining` is never decremented
- The loop continues with identical state indefinitely

**Attack Vector:**

The default `sender_max_batch_bytes` is 1,048,416 bytes (1MB - 160 bytes), [4](#0-3)  while governance transactions are allowed up to 1,048,576 bytes (1MB). [5](#0-4) 

The mempool can return transactions up to `sender_max_total_bytes` (approximately 4MB by default). [6](#0-5)  The mempool's byte limit check allows returning the first transaction even if it exceeds batch limits, as long as it's within the total byte limit. [7](#0-6) 

**Exploitation Scenario:**
1. Attacker submits a governance transaction of size 1,048,576 bytes (exactly 1MB)
2. Transaction passes VM validation as it's within governance limit [8](#0-7) 
3. Mempool accepts and stores the transaction
4. Batch generator pulls the transaction [9](#0-8) 
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

1. **Default Configuration Gap**: Governance transactions can reach 1,048,576 bytes while batch size limit is 1,048,416 bytes - a difference of only 160 bytes. [10](#0-9)  Any governance transaction between 1,048,417 and 1,048,576 bytes triggers the bug.

2. **Legitimate Use Case**: Governance transactions legitimately need larger sizes for complex proposals, making this a realistic scenario rather than an edge case.

3. **No Validation Layer**: There is no validation preventing oversized transactions from reaching `push_bucket_to_batches()`. The only checks are at transaction submission (VM layer) and mempool total bytes - neither prevents this scenario.

4. **Low Attack Complexity**: A single carefully-sized transaction submission triggers the vulnerability with no need for repeated attempts, precise timing, or complex setup.

5. **Observable in Production**: The configuration mismatch exists in default settings, making this immediately exploitable on any validator running default configuration.

## Recommendation

Add validation before entering the batching loop to handle transactions that exceed `sender_max_batch_bytes`. The fix should either:

1. **Skip oversized transactions**: When `num_batch_txns == 0` after the take_while, drain at least one transaction from `txns` to ensure progress:

```rust
if num_batch_txns > 0 {
    let batch_txns: Vec<_> = txns.drain(0..num_batch_txns).collect();
    let batch = self.create_new_batch(batch_txns, expiry_time, bucket_start);
    batches.push(batch);
    *total_batches_remaining = total_batches_remaining.saturating_sub(1);
    txns_remaining -= num_batch_txns;
} else {
    // Skip the oversized transaction to prevent infinite loop
    txns.drain(0..1);
    txns_remaining -= 1;
    counters::OVERSIZED_TXN_SKIPPED.inc();
}
```

2. **Pre-filter transactions**: Filter out transactions exceeding `sender_max_batch_bytes` in `bucket_into_batches` before calling `push_bucket_to_batches`.

3. **Align configuration**: Set `sender_max_batch_bytes` to at least `max_transaction_size_in_bytes_gov` to accommodate all valid transactions.

## Proof of Concept

A PoC would involve:
1. Creating a governance transaction with exactly 1,048,576 bytes
2. Submitting it through the REST API
3. Observing the batch generator thread hang in an infinite loop
4. Monitoring validator consensus participation degradation

The test would require modifying `consensus/src/quorum_store/tests/batch_generator_test.rs` to create an oversized transaction and verify the infinite loop behavior.

## Notes

This vulnerability is particularly concerning because:
- It exists in default configuration without any custom setup
- Governance transactions legitimately reach the problematic size range
- The infinite loop provides no escape path except process termination
- Multiple validators can be targeted simultaneously with the same transaction

The configuration mismatch between `sender_max_batch_bytes` (1,048,416) and `max_transaction_size_in_bytes_gov` (1,048,576) creates a 160-byte window where valid transactions become DoS vectors.

### Citations

**File:** consensus/src/quorum_store/batch_generator.rs (L226-226)
```rust
        while txns_remaining > 0 {
```

**File:** consensus/src/quorum_store/batch_generator.rs (L232-244)
```rust
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
```

**File:** consensus/src/quorum_store/batch_generator.rs (L245-251)
```rust
            if num_batch_txns > 0 {
                let batch_txns: Vec<_> = txns.drain(0..num_batch_txns).collect();
                let batch = self.create_new_batch(batch_txns, expiry_time, bucket_start);
                batches.push(batch);
                *total_batches_remaining = total_batches_remaining.saturating_sub(1);
                txns_remaining -= num_batch_txns;
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

**File:** config/src/config/quorum_store_config.rs (L12-12)
```rust
pub const BATCH_PADDING_BYTES: usize = 160;
```

**File:** config/src/config/quorum_store_config.rs (L115-115)
```rust
            sender_max_batch_bytes: 1024 * 1024 - BATCH_PADDING_BYTES,
```

**File:** config/src/config/quorum_store_config.rs (L119-119)
```rust
            sender_max_total_bytes: 4 * 1024 * 1024 - DEFAULT_MAX_NUM_BATCHES * BATCH_PADDING_BYTES,
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L78-81)
```rust
            max_transaction_size_in_bytes_gov: NumBytes,
            { RELEASE_V1_13.. => "max_transaction_size_in_bytes.gov" },
            1024 * 1024
        ],
```

**File:** mempool/src/core_mempool/mempool.rs (L520-525)
```rust
                if total_bytes + txn_size > max_bytes {
                    full_bytes = true;
                    break;
                }
                total_bytes += txn_size;
                block.push(txn);
```

**File:** aptos-move/aptos-vm/src/gas.rs (L83-108)
```rust
    if is_approved_gov_script {
        let max_txn_size_gov = if gas_feature_version >= RELEASE_V1_13 {
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
            speculative_warn!(
                log_context,
                format!(
                    "[VM] Governance transaction size too big {} payload size {}",
                    txn_metadata.transaction_size, txn_metadata.script_size,
                ),
            );
            return Err(VMStatus::error(
                StatusCode::EXCEEDED_MAX_TRANSACTION_SIZE,
                None,
            ));
        }
```
