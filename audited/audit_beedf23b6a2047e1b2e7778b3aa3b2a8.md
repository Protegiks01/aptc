# Audit Report

## Title
Transaction Lifecycle Inconsistency: Failed MempoolError Notifications Cause Repeated Re-execution of Rejected Transactions

## Summary
The `MempoolNotifier` in consensus can fail to notify mempool about rejected transactions due to channel saturation or timeout, causing these transactions to remain in mempool and be repeatedly re-executed by consensus, leading to resource exhaustion and potential denial-of-service conditions.

## Finding Description

The vulnerability exists in the coordination mechanism between consensus and mempool for handling rejected transactions. When consensus executes a block containing transactions that fail execution, it attempts to notify mempool via `MempoolNotifier.notify_failed_txn()` to remove these transactions. However, this notification can fail in multiple ways:

**Failure Point 1: Channel Send Failure** [1](#0-0) 

The channel has a buffer size of only 1: [2](#0-1) 

When mempool is processing another request (e.g., `GetBatchRequest`), the `try_send` fails immediately with a channel full error, returning a `MempoolError`.

**Failure Point 2: Timeout** [3](#0-2) 

With a default timeout of 1000ms: [4](#0-3) 

If mempool is under load or slow to respond, the callback times out and returns a `MempoolError`.

**Critical Flaw: Silent Error Handling** [5](#0-4) 

When the notification fails, the error is merely logged and the pipeline continues. The transactions are never removed from mempool.

**Transaction Re-execution Cycle**
When a block commits (regardless of transaction execution results), all batches are removed from the exclude list: [6](#0-5) 

This cleanup happens via commit notification: [7](#0-6) 

Since mempool never received the rejection notification, it still contains these failed transactions. On the next batch pull, consensus excludes only transactions currently in progress: [8](#0-7) 

The previously-failed transactions are no longer excluded, so they get pulled again, fail execution again, and the cycle repeats until the transaction's TTL expires.

**Attack Scenario:**
1. Attacker submits transactions that pass VM validation but fail execution (e.g., with `SEQUENCE_NUMBER_TOO_OLD`, `INSUFFICIENT_BALANCE`, or other execution failures)
2. Consensus pulls these transactions from mempool and executes them
3. Transactions fail execution; consensus attempts to notify mempool via `RejectNotification`
4. If mempool is busy processing another request or is under load, the notification fails (channel full or timeout)
5. Error is logged but consensus continues; block commits with these failed transactions
6. Batch cleanup removes transactions from `txns_in_progress_sorted` (exclude list)
7. On next pull, mempool returns the same failed transactions (they were never removed from mempool)
8. Consensus re-executes them, they fail again, notification fails again
9. Cycle repeats until transaction TTL expires

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty program based on:

1. **State Inconsistencies**: The transaction lifecycle is broken - consensus believes transactions are rejected while mempool believes they're still valid. This violates the state consistency invariant.

2. **Resource Exhaustion**: Failed transactions are re-executed repeatedly, wasting:
   - **Computational Resources**: VM execution of the same failing transactions
   - **Network Bandwidth**: Re-broadcasting transactions between mempool and consensus
   - **Storage**: Failed transactions remain in mempool until TTL expiration

3. **Denial-of-Service Potential**: An attacker can craft many transactions that pass validation but fail execution, causing validators to waste resources on repeated re-execution.

4. **Limited by TTL**: The impact is bounded by transaction TTL (system timeout), providing eventual cleanup via garbage collection: [9](#0-8) 

This does not constitute Critical severity (no fund loss or consensus break) or High severity (no permanent node slowdown), but clearly fits Medium severity criteria for "state inconsistencies requiring intervention" and resource waste.

## Likelihood Explanation

This vulnerability has **HIGH likelihood** of occurring in production environments:

1. **Small Channel Buffer**: The channel buffer size of 1 means any concurrent processing causes immediate send failures
2. **Reasonable Timeout**: 1000ms timeout can be exceeded under load
3. **Natural Conditions**: Does not require malicious intent - can occur naturally when:
   - Mempool is processing large batch requests
   - Network latency delays callback responses  
   - System is under high transaction load
   - Legitimate transactions fail execution (e.g., due to state changes between validation and execution)

4. **No Retry Mechanism**: The code has no retry logic or queuing for failed notifications
5. **Silent Failure**: The error is only logged, making it difficult to detect in production

## Recommendation

Implement a robust retry mechanism with persistent tracking of rejected transactions:

**Solution 1: Reliable Notification Queue**
```rust
// In consensus/src/txn_notifier.rs
pub struct MempoolNotifier {
    consensus_to_mempool_sender: mpsc::Sender<QuorumStoreRequest>,
    mempool_executed_txn_timeout_ms: u64,
    // Add persistent queue for failed notifications
    pending_rejections: Arc<Mutex<Vec<RejectedTransactionSummary>>>,
}

impl TxnNotifier for MempoolNotifier {
    async fn notify_failed_txn(&self, txns: &[SignedTransaction], statuses: &[TransactionStatus]) -> Result<(), MempoolError> {
        // ... existing validation code ...
        
        let mut rejected_txns = vec![];
        for (txn, status) in user_txns.iter().zip_eq(user_txn_statuses) {
            if let TransactionStatus::Discard(reason) = status {
                rejected_txns.push(RejectedTransactionSummary { /* ... */ });
            }
        }
        
        if rejected_txns.is_empty() {
            return Ok(());
        }
        
        // Try to send with retries
        const MAX_RETRIES: usize = 3;
        for attempt in 0..MAX_RETRIES {
            let (callback, callback_rcv) = oneshot::channel();
            let req = QuorumStoreRequest::RejectNotification(rejected_txns.clone(), callback);
            
            match self.consensus_to_mempool_sender.clone().try_send(req) {
                Ok(_) => {
                    match timeout(Duration::from_millis(self.mempool_executed_txn_timeout_ms), callback_rcv).await {
                        Ok(Ok(_)) => return Ok(()),
                        Err(_) if attempt < MAX_RETRIES - 1 => {
                            warn!("Mempool notification timeout, retrying...");
                            tokio::time::sleep(Duration::from_millis(100 * (attempt as u64 + 1))).await;
                            continue;
                        },
                        _ => break,
                    }
                },
                Err(_) if attempt < MAX_RETRIES - 1 => {
                    warn!("Mempool channel full, retrying...");
                    tokio::time::sleep(Duration::from_millis(100 * (attempt as u64 + 1))).await;
                    continue;
                },
                Err(e) => return Err(anyhow::Error::from(e).into()),
            }
        }
        
        // If all retries fail, store for later retry
        self.pending_rejections.lock().extend(rejected_txns);
        Err(format_err!("Failed to notify mempool after {} retries", MAX_RETRIES).into())
    }
}
```

**Solution 2: Increase Channel Buffer and Timeout**
```rust
// In aptos-node/src/services.rs
const INTRA_NODE_CHANNEL_BUFFER_SIZE: usize = 128; // Increase from 1 to 128

// In config/src/config/consensus_config.rs
mempool_executed_txn_timeout_ms: 5000, // Increase from 1000 to 5000
```

**Solution 3: Make Notification Failure Block Consensus**
```rust
// In consensus/src/pipeline/pipeline_builder.rs
if let Err(e) = mempool_notifier.notify_failed_txn(&txns, user_txn_status).await {
    error!(error = ?e, "Failed to notify mempool of rejected txns");
    // Block until notification succeeds
    return Err(anyhow!("Mempool notification required for transaction lifecycle consistency: {:?}", e))?;
}
```

**Recommended Approach**: Combine Solution 1 (retry logic) with Solution 2 (increased buffer/timeout) to provide defense-in-depth.

## Proof of Concept

```rust
#[tokio::test]
async fn test_mempool_notification_failure_causes_reexecution() {
    // Setup test environment with small channel buffer
    let (consensus_to_mempool_tx, mut mempool_rx) = mpsc::channel(1);
    let mempool_notifier = MempoolNotifier::new(consensus_to_mempool_tx, 1000);
    
    // Create a transaction that will fail execution
    let failing_txn = create_transaction_with_invalid_sequence();
    let failed_status = TransactionStatus::Discard(DiscardedVMStatus::SEQUENCE_NUMBER_TOO_OLD);
    
    // Block the mempool channel by not consuming messages
    // This simulates mempool being busy processing another request
    
    // Step 1: Try to notify mempool about failed transaction
    let result = mempool_notifier.notify_failed_txn(&[failing_txn.clone()], &[failed_status]).await;
    
    // Verify notification failed due to channel full
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), /* channel error */));
    
    // Step 2: Simulate batch cleanup after block commit
    let mut batch_generator = create_batch_generator();
    batch_generator.remove_batch_in_progress(peer_id, batch_id);
    
    // Verify transaction is no longer in exclude list
    assert!(!batch_generator.txns_in_progress_sorted.contains_key(&txn_summary));
    
    // Step 3: Pull from mempool again
    let pulled_txns = mempool_proxy.pull_internal(max_count, max_bytes, exclude_transactions).await?;
    
    // Verify the same failed transaction is pulled again
    assert!(pulled_txns.contains(&failing_txn));
    
    // Step 4: Execute and fail again
    let execution_result = executor.execute_block(pulled_txns);
    assert!(execution_result.contains_failure(&failing_txn));
    
    // This cycle repeats until TTL expiration
}
```

**Notes**
The vulnerability occurs at the intersection of three components: consensus transaction notification, mempool coordination, and batch tracking. The root cause is insufficient error handling and lack of retry mechanisms for critical coordination messages. The small channel buffer (size=1) makes this highly likely to occur under normal production loads, not just under attack conditions.

### Citations

**File:** consensus/src/txn_notifier.rs (L82-85)
```rust
        self.consensus_to_mempool_sender
            .clone()
            .try_send(req)
            .map_err(anyhow::Error::from)?;
```

**File:** consensus/src/txn_notifier.rs (L87-95)
```rust
        if let Err(e) = monitor!(
            "notify_mempool",
            timeout(
                Duration::from_millis(self.mempool_executed_txn_timeout_ms),
                callback_rcv
            )
            .await
        ) {
            Err(format_err!("[consensus] txn notifier did not receive ACK for commit notification sent to mempool on time: {:?}", e).into())
```

**File:** aptos-node/src/services.rs (L47-47)
```rust
const INTRA_NODE_CHANNEL_BUFFER_SIZE: usize = 1;
```

**File:** config/src/config/consensus_config.rs (L233-233)
```rust
            mempool_executed_txn_timeout_ms: 1000,
```

**File:** consensus/src/pipeline/pipeline_builder.rs (L964-971)
```rust
            if let Err(e) = mempool_notifier
                .notify_failed_txn(&txns, user_txn_status)
                .await
            {
                error!(
                    error = ?e, "Failed to notify mempool of rejected txns",
                );
            }
```

**File:** consensus/src/quorum_store/batch_generator.rs (L342-360)
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
```

**File:** consensus/src/quorum_store/batch_generator.rs (L528-532)
```rust
                            for (author, batch_id) in batches.iter().map(|b| (b.author(), b.batch_id())) {
                                if self.remove_batch_in_progress(author, batch_id) {
                                    counters::BATCH_IN_PROGRESS_COMMITTED.inc();
                                }
                            }
```

**File:** consensus/src/payload_manager/quorum_store_payload_manager.rs (L168-208)
```rust
    fn notify_commit(&self, block_timestamp: u64, payloads: Vec<Payload>) {
        self.batch_reader
            .update_certified_timestamp(block_timestamp);

        let batches: Vec<_> = payloads
            .into_iter()
            .flat_map(|payload| match payload {
                Payload::DirectMempool(_) => {
                    unreachable!("InQuorumStore should be used");
                },
                Payload::InQuorumStore(proof_with_status) => proof_with_status
                    .proofs
                    .iter()
                    .map(|proof| proof.info().clone().into())
                    .collect::<Vec<_>>(),
                Payload::InQuorumStoreWithLimit(proof_with_status) => proof_with_status
                    .proof_with_data
                    .proofs
                    .iter()
                    .map(|proof| proof.info().clone().into())
                    .collect::<Vec<_>>(),
                Payload::QuorumStoreInlineHybrid(inline_batches, proof_with_data, _)
                | Payload::QuorumStoreInlineHybridV2(inline_batches, proof_with_data, _) => {
                    inline_batches
                        .iter()
                        .map(|(batch_info, _)| batch_info.clone().into())
                        .chain(
                            proof_with_data
                                .proofs
                                .iter()
                                .map(|proof| proof.info().clone().into()),
                        )
                        .collect::<Vec<_>>()
                },
                Payload::OptQuorumStore(OptQuorumStorePayload::V1(p)) => p.get_all_batch_infos(),
                Payload::OptQuorumStore(OptQuorumStorePayload::V2(p)) => p.get_all_batch_infos(),
            })
            .collect();

        self.commit_notifier.notify(block_timestamp, batches);
    }
```

**File:** mempool/src/core_mempool/mempool.rs (L590-593)
```rust
    pub(crate) fn gc(&mut self) {
        let now = aptos_infallible::duration_since_epoch();
        self.transactions.gc_by_system_ttl(now);
    }
```
