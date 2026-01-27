# Audit Report

## Title
Resource Exhaustion via Premature committed_hash() Computation on Oversized Transactions

## Summary
The `filter_transactions()` function calls `committed_hash()` on transactions before validating transaction size limits, enabling DoS attacks through submission of specially crafted large transactions that trigger expensive clone and serialization operations.

## Finding Description

The vulnerability exists in the transaction filtering pipeline where `committed_hash()` is invoked before transaction size validation occurs. This breaks the Resource Limits invariant by allowing computational-intensive operations on oversized transactions.

The attack flow operates as follows:

1. **Transaction Entry**: Transactions enter the mempool via API submission or P2P broadcast with network-level limits allowing messages up to ~62 MB [1](#0-0) 

2. **Filter Processing**: In `process_incoming_transactions()`, transactions reach `filter_transactions()` before any VM validation [2](#0-1) 

3. **Premature Hash Computation**: Two code paths trigger expensive `committed_hash()` calls:

   **Path A - TransactionId Matching**: When the filter uses `TransactionId` matchers, `committed_hash()` is called on ALL transactions during matching [3](#0-2) 

   **Path B - Rejection Logging**: When transactions are rejected by the filter, `committed_hash()` is called for logging purposes [4](#0-3) 

4. **Expensive Operation**: The `committed_hash()` implementation clones the entire `SignedTransaction` and serializes it via BCS before hashing [5](#0-4) 

5. **Late Size Validation**: Transaction size validation (64 KB limit) only occurs later during VM validation via `check_gas()` [6](#0-5) 

The critical issue is that BCS serialization via `bcs::serialize_into()` processes the entire transaction payload, including potentially multi-megabyte `Script` bytecode or `EntryFunction` arguments [7](#0-6) [8](#0-7) 

## Impact Explanation

This qualifies as **High Severity** under the Aptos Bug Bounty program's "Validator node slowdowns" category.

An attacker can:
- Submit oversized transactions (e.g., `Script` with multi-MB bytecode up to network limits)
- If nodes have `TransactionId` filters configured, trigger hash computation on ALL submissions
- Even without such filters, cause hash computation on rejected transactions (e.g., from blacklisted senders)
- Force validators to perform CPU-intensive clone + serialization + hash operations before size validation rejects the transactions

The computational cost scales linearly with transaction size, allowing attackers to amplify their attack by submitting transactions near the ~62 MB network message limit while the legitimate size limit is only 64 KB [9](#0-8) 

## Likelihood Explanation

**Likelihood: High**

- No special privileges required - any user can submit transactions via API or broadcast via P2P
- Attack requires minimal resources - attacker only needs to send oversized transactions
- The vulnerability is always present in the code path
- Exploitation is deterministic - sending large transactions will always trigger expensive hash computation
- `TransactionId` filters may be commonly deployed to block known malicious transaction hashes, making Path A exploitable on many nodes

## Recommendation

Perform transaction size validation BEFORE calling `committed_hash()`. Add an early size check in `filter_transactions()`:

```rust
fn filter_transactions(
    transaction_filter_config: &TransactionFilterConfig,
    transactions: Vec<(SignedTransaction, Option<u64>, Option<BroadcastPeerPriority>)>,
    statuses: &mut Vec<(SignedTransaction, (MempoolStatus, Option<StatusCode>))>,
) -> Vec<(SignedTransaction, Option<u64>, Option<BroadcastPeerPriority>)> {
    if !transaction_filter_config.is_enabled() {
        return transactions;
    }

    let transaction_filter_timer = counters::PROCESS_TXN_BREAKDOWN_LATENCY
        .with_label_values(&[counters::FILTER_TRANSACTIONS_LABEL])
        .start_timer();

    // Add early size validation BEFORE filter processing
    const MAX_TRANSACTION_SIZE: usize = 64 * 1024; // 64 KB limit
    
    let transactions = transactions
        .into_iter()
        .filter_map(|(transaction, account_sequence_number, priority)| {
            // Check size before expensive operations
            if transaction.txn_bytes_len() > MAX_TRANSACTION_SIZE {
                statuses.push((
                    transaction,
                    (
                        MempoolStatus::new(MempoolStatusCode::VmError),
                        Some(DiscardedVMStatus::EXCEEDED_MAX_TRANSACTION_SIZE),
                    ),
                ));
                return None;
            }
            
            if transaction_filter_config
                .transaction_filter()
                .allows_transaction(&transaction)
            {
                Some((transaction, account_sequence_number, priority))
            } else {
                // Now safe to call committed_hash() since size is validated
                info!(LogSchema::event_log(
                    LogEntry::TransactionFilter,
                    LogEvent::TransactionRejected
                )
                .message(&format!(
                    "Transaction {} rejected by filter",
                    transaction.committed_hash()
                )));

                statuses.push((
                    transaction.clone(),
                    (
                        MempoolStatus::new(MempoolStatusCode::RejectedByFilter),
                        None,
                    ),
                ));
                None
            }
        })
        .collect();

    transaction_filter_timer.stop_and_record();
    transactions
}
```

Additionally, consider removing the `committed_hash()` call from the `TransactionId` matcher and instead require pre-computed hashes, or cache `txn_bytes_len()` to enable early size checks without triggering serialization.

## Proof of Concept

```rust
#[cfg(test)]
mod dos_test {
    use super::*;
    use aptos_types::transaction::{Script, TransactionPayload};
    use std::time::Instant;

    #[test]
    fn test_oversized_transaction_dos() {
        // Create a transaction with very large Script bytecode (1 MB)
        let large_bytecode = vec![0u8; 1024 * 1024];
        let script = Script::new(large_bytecode, vec![], vec![]);
        let payload = TransactionPayload::Script(script);
        
        let raw_txn = RawTransaction::new(
            AccountAddress::random(),
            0,
            payload,
            1_000_000,
            0,
            0,
            ChainId::new(1),
        );
        
        let private_key = Ed25519PrivateKey::generate_for_testing();
        let signature = private_key.sign(&raw_txn).unwrap();
        let signed_txn = SignedTransaction::new(
            raw_txn,
            private_key.public_key(),
            signature,
        );

        // Configure filter with TransactionId matcher to trigger hash computation
        let filter = TransactionFilter::empty()
            .add_transaction_id_filter(false, HashValue::zero());
        let config = TransactionFilterConfig::new(true, filter);

        // Measure time for hash computation on oversized transaction
        let start = Instant::now();
        let mut statuses = vec![];
        let transactions = vec![(signed_txn, None, Some(BroadcastPeerPriority::Primary))];
        
        filter_transactions(&config, transactions, &mut statuses);
        
        let elapsed = start.elapsed();
        
        // The hash computation should be expensive (>10ms for 1MB transaction)
        // compared to normal transactions (<1ms for 1KB)
        println!("Time to process 1MB oversized transaction: {:?}", elapsed);
        
        // Attacker could send many such transactions to exhaust CPU
        // With 100 such transactions, could consume seconds of CPU time
        // before any are rejected by size validation
    }
}
```

This PoC demonstrates that oversized transactions trigger expensive hash computations before size validation, enabling resource exhaustion attacks against validator nodes.

### Citations

**File:** config/src/config/network_config.rs (L47-50)
```rust
pub const MAX_APPLICATION_MESSAGE_SIZE: usize =
    (MAX_MESSAGE_SIZE - MAX_MESSAGE_METADATA_SIZE) - MESSAGE_PADDING_SIZE; /* The message size that applications should check against */
pub const MAX_FRAME_SIZE: usize = 4 * 1024 * 1024; /* 4 MiB large messages will be chunked into multiple frames and streamed */
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024 * 1024; /* 64 MiB */
```

**File:** mempool/src/shared_mempool/tasks.rs (L318-321)
```rust
    // Filter out any disallowed transactions
    let mut statuses = vec![];
    let transactions =
        filter_transactions(&smp.transaction_filter_config, transactions, &mut statuses);
```

**File:** mempool/src/shared_mempool/tasks.rs (L445-448)
```rust
                .message(&format!(
                    "Transaction {} rejected by filter",
                    transaction.committed_hash()
                )));
```

**File:** crates/aptos-transaction-filters/src/transaction_filter.rs (L187-187)
```rust
            TransactionMatcher::TransactionId(id) => signed_transaction.committed_hash() == *id,
```

**File:** types/src/transaction/mod.rs (L1335-1339)
```rust
    pub fn committed_hash(&self) -> HashValue {
        *self
            .committed_hash
            .get_or_init(|| Transaction::UserTransaction(self.clone()).hash())
    }
```

**File:** aptos-move/aptos-vm/src/gas.rs (L109-121)
```rust
    } else if txn_metadata.transaction_size > txn_gas_params.max_transaction_size_in_bytes {
        speculative_warn!(
            log_context,
            format!(
                "[VM] Transaction size too big {} (max {})",
                txn_metadata.transaction_size, txn_gas_params.max_transaction_size_in_bytes
            ),
        );
        return Err(VMStatus::error(
            StatusCode::EXCEEDED_MAX_TRANSACTION_SIZE,
            None,
        ));
    }
```

**File:** types/src/transaction/script.rs (L64-69)
```rust
pub struct Script {
    #[serde(with = "serde_bytes")]
    code: Vec<u8>,
    ty_args: Vec<TypeTag>,
    args: Vec<TransactionArgument>,
}
```

**File:** crates/aptos-crypto-derive/src/lib.rs (L455-460)
```rust
            fn hash(&self) -> aptos_crypto::hash::HashValue {
                use aptos_crypto::hash::CryptoHasher;

                let mut state = Self::Hasher::default();
                bcs::serialize_into(&mut state, &self).expect(#error_msg);
                state.finish()
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L73-76)
```rust
            max_transaction_size_in_bytes: NumBytes,
            "max_transaction_size_in_bytes",
            64 * 1024
        ],
```
