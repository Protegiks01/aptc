# Audit Report

## Title
Batch Transaction Poisoning Attack in Quorum Store Enables Transaction Censorship and Validator Resource Exhaustion

## Summary
The `BatchCoordinator::handle_batches_msg()` function implements an all-or-nothing batch filtering policy where a single rejected transaction causes all batches in the message to be dropped. This creates a transaction poisoning attack vector where adversaries can intentionally inject filtered transactions to grief legitimate transactions and prevent batch certification.

## Finding Description

The quorum store batch filtering mechanism in `handle_batches_msg()` rejects entire batch messages when any single transaction fails the filter check: [1](#0-0) 

When transaction filters are enabled, this code iterates through all transactions in all batches. Upon finding any transaction that `!transaction_filter.allows_transaction()`, it immediately logs an error and returns, dropping all batches without signing them.

**Attack Flow:**

1. **Batch Creation Phase**: A validator's `BatchGenerator` pulls transactions from mempool, which may contain both legitimate transactions (from honest users) and malicious transactions (from the attacker) that will trigger filter rejections. [2](#0-1) 

2. **Batch Broadcasting**: The validator creates batches containing this mixed transaction set and broadcasts them to all validators.

3. **Batch Rejection**: Validators with transaction filters enabled reject the entire batch message, refusing to sign it. No `SignedBatchInfo` is created, and no notification is sent back to the author.

4. **Proof Failure**: The batch author cannot collect 2f+1 signatures (quorum) to form a valid `ProofOfStore` certificate if enough validators (> 1/3) reject the batch.

5. **Transaction Censorship**: Without a `ProofOfStore`, the batch cannot be included in consensus blocks, effectively censoring all legitimate transactions in that batch.

6. **Continuous DoS**: Since no feedback mechanism exists, the originating validator continues pulling the same transactions from mempool, repeatedly creating poisoned batches that get rejected.

**Design Flaw**: The codebase includes a `filter_batch_transactions()` method designed for partial filtering: [3](#0-2) 

This method can filter individual transactions while preserving legitimate ones, but it is **not used** in the production `BatchCoordinator` implementation.

**Invariant Violations:**

- **Liveness Violation**: Legitimate transactions are indefinitely delayed or censored despite being valid
- **Resource Exhaustion**: Validators waste CPU/network resources processing and rejecting poisoned batches repeatedly
- **Griefing Attack Surface**: Single malicious transaction can block arbitrary numbers of legitimate transactions

## Impact Explanation

This vulnerability qualifies as **High Severity** per Aptos bug bounty criteria:

1. **Validator Node Slowdowns**: Continuous processing and rejection of poisoned batches wastes validator resources (CPU, network bandwidth, storage I/O for mempool operations).

2. **Significant Protocol Violations**: The quorum store's fundamental purpose—to efficiently batch and certify transactions—is subverted. Legitimate transactions are censored despite being valid and properly signed.

3. **Amplification Factor**: A single malicious transaction (costing minimal gas) can poison batches containing hundreds of legitimate transactions, creating a force multiplier for the attacker.

**Scope Conditions:**
- Impact materializes when transaction filters are enabled (`transaction_filter_config.is_enabled() == true`)
- Severity increases with the number of validators running filters
- If > 1/3 validators have compatible filter rules, batches cannot achieve quorum certification

While filters are disabled by default, their intended use cases (regulatory compliance, spam prevention, emergency response) make this a realistic production concern.

## Likelihood Explanation

**Likelihood: MEDIUM to HIGH** (when filters are deployed)

**Prerequisites:**
1. Transaction filters must be enabled on validators (controlled by `BatchTransactionFilterConfig`)
2. Attacker must submit transactions to mempool (trivial - standard operation)
3. Attacker must know or infer filter rules (may be publicly disclosed for transparency/compliance)

**Feasibility:**

The attack requires no special privileges:
- Transaction submission to mempool is open to all users
- Validators naturally batch transactions from mempool without inspecting filter compatibility
- No rate limiting prevents repeated submission of filtered transactions

**Real-World Scenarios:**

Filters would likely be enabled for:
- **Regulatory Compliance**: Blocking transactions from sanctioned addresses
- **Spam Prevention**: Denying transactions from known malicious contracts  
- **Emergency Response**: Temporarily censoring exploit-related transactions during incidents

In these scenarios, filter rules may be publicly known (OFAC lists) or easily inferred through trial transactions, making exploitation straightforward.

## Recommendation

**Implement partial batch filtering instead of all-or-nothing rejection:**

Replace the current rejection logic in `handle_batches_msg()` with per-transaction filtering:

```rust
// In handle_batches_msg(), around lines 189-213:
if self.transaction_filter_config.is_enabled() {
    let transaction_filter = &self.transaction_filter_config.batch_transaction_filter();
    let mut filtered_batches = Vec::new();
    
    for mut batch in batches.into_iter() {
        // Filter transactions within this batch
        let filtered_txns = transaction_filter.filter_batch_transactions(
            batch.batch_info().batch_id(),
            batch.author(),
            *batch.digest(),
            batch.txns().to_vec()
        );
        
        if filtered_txns.is_empty() {
            // Entire batch was filtered - drop it
            counters::RECEIVED_BATCH_FULLY_REJECTED_BY_FILTER.inc();
            continue;
        }
        
        if filtered_txns.len() < batch.txns().len() {
            // Partial filtering occurred - log and create modified batch
            warn!(
                "Filtered {} transactions from batch {}, {} remaining",
                batch.txns().len() - filtered_txns.len(),
                batch.batch_info().batch_id(),
                filtered_txns.len()
            );
            counters::RECEIVED_BATCH_PARTIALLY_FILTERED.inc();
            
            // Create new batch with filtered transactions
            batch = recreate_batch_with_txns(batch, filtered_txns);
        }
        
        filtered_batches.push(batch);
    }
    
    batches = filtered_batches;
}
```

**Additional Improvements:**

1. **Feedback Mechanism**: Implement `SignedBatchInfo` rejection messages that specify which transactions were filtered, allowing batch authors to adjust future batches.

2. **Filter Consistency Check**: Validators should check filter configuration compatibility during epoch changes to prevent unintentional censorship from configuration drift.

3. **Metrics Enhancement**: Add detailed counters for partial vs. full batch rejection to enable monitoring of filter effectiveness.

## Proof of Concept

```rust
// Integration test demonstrating transaction poisoning attack
#[tokio::test]
async fn test_batch_poisoning_attack() {
    use aptos_types::{
        account_address::AccountAddress,
        transaction::SignedTransaction,
    };
    use aptos_transaction_filters::batch_transaction_filter::BatchTransactionFilter;
    use aptos_config::config::BatchTransactionFilterConfig;
    
    // Setup: Create a batch coordinator with a filter that denies transactions
    // from a specific address (simulating a sanctioned address)
    let attacker_address = AccountAddress::from_hex_literal("0xBAD").unwrap();
    let filter = BatchTransactionFilter::empty()
        .add_sender_filter(false, attacker_address); // Deny this sender
    
    let filter_config = BatchTransactionFilterConfig::new(true, filter);
    let mut batch_coordinator = create_batch_coordinator(filter_config);
    
    // Step 1: Attacker submits malicious transaction from filtered address
    let malicious_txn = create_signed_transaction(attacker_address, /* ... */);
    submit_to_mempool(malicious_txn);
    
    // Step 2: Honest users submit 100 legitimate transactions
    let legitimate_txns: Vec<SignedTransaction> = (0..100)
        .map(|i| create_signed_transaction(
            AccountAddress::from_hex_literal(&format!("0x{:x}", i)).unwrap(),
            /* ... */
        ))
        .collect();
    
    for txn in legitimate_txns {
        submit_to_mempool(txn);
    }
    
    // Step 3: Validator creates batch from mempool (pulls both malicious and legitimate)
    let batch_generator = create_batch_generator();
    let batches = batch_generator.handle_scheduled_pull(101).await;
    
    // Verify batch contains mixed transactions
    assert_eq!(batches[0].txns().len(), 101);
    
    // Step 4: Batch coordinator receives and processes batch
    let author = PeerId::random();
    batch_coordinator.handle_batches_msg(author, batches).await;
    
    // Step 5: Verify all batches were dropped (no signatures created)
    // Check that RECEIVED_BATCH_REJECTED_BY_FILTER counter was incremented
    assert_eq!(
        counters::RECEIVED_BATCH_REJECTED_BY_FILTER.get(),
        1,
        "Batch should have been rejected due to one malicious transaction"
    );
    
    // Step 6: Verify legitimate transactions were not signed
    // (cannot form ProofOfStore, cannot be included in blocks)
    let batch_store = get_batch_store();
    assert!(
        batch_store.get_signed_batch_info(batches[0].batch_info().batch_id()).is_none(),
        "No SignedBatchInfo created - legitimate transactions censored"
    );
    
    // Impact: 100 legitimate transactions blocked by 1 malicious transaction
    println!("Attack successful: 1 malicious txn blocked 100 legitimate txns");
}
```

**Notes:**

- The vulnerability exists in the current implementation's all-or-nothing approach to batch filtering
- When filters are enabled, a single filtered transaction causes complete batch rejection
- The `filter_batch_transactions()` method provides the correct partial filtering approach but is unused
- This creates a griefing vector for transaction censorship and validator resource waste
- The severity is HIGH when filters are deployed, as it enables unprivileged attackers to disrupt transaction processing at scale

### Citations

**File:** consensus/src/quorum_store/batch_coordinator.rs (L189-213)
```rust
        // Filter the transactions in the batches. If any transaction is rejected,
        // the message will be dropped, and all batches will be rejected.
        if self.transaction_filter_config.is_enabled() {
            let transaction_filter = &self.transaction_filter_config.batch_transaction_filter();
            for batch in batches.iter() {
                for transaction in batch.txns() {
                    if !transaction_filter.allows_transaction(
                        batch.batch_info().batch_id(),
                        batch.author(),
                        batch.digest(),
                        transaction,
                    ) {
                        error!(
                            "Transaction {}, in batch {}, from {}, was rejected by the filter. Dropping {} batches!",
                            transaction.committed_hash(),
                            batch.batch_info().batch_id(),
                            author.short_str().as_str(),
                            batches.len()
                        );
                        counters::RECEIVED_BATCH_REJECTED_BY_FILTER.inc();
                        return;
                    }
                }
            }
        }
```

**File:** consensus/src/quorum_store/batch_generator.rs (L342-390)
```rust
    pub(crate) async fn handle_scheduled_pull(
        &mut self,
        max_count: u64,
    ) -> Vec<Batch<BatchInfoExt>> {
        counters::BATCH_PULL_EXCLUDED_TXNS.observe(self.txns_in_progress_sorted.len() as f64);
        trace!(
            "QS: excluding txs len: {:?}",
            self.txns_in_progress_sorted.len()
        );

        let mut pulled_txns = self
            .mempool_proxy
            .pull_internal(
                max_count,
                self.config.sender_max_total_bytes as u64,
                self.txns_in_progress_sorted.clone(),
            )
            .await
            .unwrap_or_default();

        trace!("QS: pulled_txns len: {:?}", pulled_txns.len());

        if pulled_txns.is_empty() {
            counters::PULLED_EMPTY_TXNS_COUNT.inc();
            // Quorum store metrics
            counters::CREATED_EMPTY_BATCHES_COUNT.inc();

            counters::EMPTY_BATCH_CREATION_DURATION
                .observe_duration(self.last_end_batch_time.elapsed());
            self.last_end_batch_time = Instant::now();
            return vec![];
        } else {
            counters::PULLED_TXNS_COUNT.inc();
            counters::PULLED_TXNS_NUM.observe(pulled_txns.len() as f64);
            if pulled_txns.len() as u64 == max_count {
                counters::BATCH_PULL_FULL_TXNS.observe(max_count as f64)
            }
        }
        counters::BATCH_CREATION_DURATION.observe_duration(self.last_end_batch_time.elapsed());

        let bucket_compute_start = Instant::now();
        let expiry_time = aptos_infallible::duration_since_epoch().as_micros() as u64
            + self.config.batch_expiry_gap_when_init_usecs;
        let batches = self.bucket_into_batches(&mut pulled_txns, expiry_time);
        self.last_end_batch_time = Instant::now();
        counters::BATCH_CREATION_COMPUTE_LATENCY.observe_duration(bucket_compute_start.elapsed());

        batches
    }
```

**File:** crates/aptos-transaction-filters/src/batch_transaction_filter.rs (L67-79)
```rust
    /// Filters the transactions in the given batch and returns only those that are allowed
    pub fn filter_batch_transactions(
        &self,
        batch_id: BatchId,
        batch_author: PeerId,
        batch_digest: HashValue,
        transactions: Vec<SignedTransaction>,
    ) -> Vec<SignedTransaction> {
        transactions
            .into_iter()
            .filter(|txn| self.allows_transaction(batch_id, batch_author, &batch_digest, txn))
            .collect()
    }
```
