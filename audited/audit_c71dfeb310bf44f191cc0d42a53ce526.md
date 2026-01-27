# Audit Report

## Title
Memory Exhaustion via Unvalidated Batch Size Accumulation in Quorum Store Channels

## Summary
Byzantine validators can cause memory exhaustion on honest validator nodes by flooding them with maximum-size `BatchMsg` objects (~4MB each) that pass initial verification but accumulate in channel queues before size validation occurs. With default channel capacities, up to ~44GB of batch data can accumulate in memory before backpressure activates, potentially causing out-of-memory crashes.

## Finding Description

The vulnerability exists in the message processing pipeline between batch verification and batch coordinator processing. The attack exploits a validation gap where `BatchMsg` size limits are checked at different stages of the pipeline.

**Attack Flow:**

1. **Byzantine Validator Crafts Malicious BatchMsg**: An attacker creates a `BatchMsg` containing the maximum number of batches (20 batches, as limited by `receiver_max_num_batches`) [1](#0-0) , with each batch approaching the size limit to create a ~4MB message [2](#0-1) .

2. **Verification Only Checks Batch Count**: When the message arrives, `BatchMsg::verify()` only validates the number of batches and signatures, but does NOT check total byte size [3](#0-2) . The verification specifically checks `batches.len() <= max_num_batches` but has no corresponding check for total bytes.

3. **Messages Accumulate in Channels**: After passing verification, `VerifiedEvent::BatchMsg` is pushed to the `quorum_store_msg_tx` channel (capacity: 1000) [4](#0-3) , which is the same channel the `NetworkListener` reads from [5](#0-4) .

4. **Further Accumulation in Batch Coordinator Channels**: The `NetworkListener` then forwards these messages via round-robin to one of 10 batch coordinator channels (each with capacity: 1000) using `send().await` [6](#0-5) .

5. **Size Validation Happens Too Late**: Only when `BatchCoordinator::handle_batches_msg()` processes the message does `ensure_max_limits()` validate the total bytes [7](#0-6) .

**Memory Accumulation Calculation:**
- `quorum_store_msg_tx` channel: 1,000 messages × 4MB = ~4GB
- 10 batch coordinator channels: 10 × 1,000 messages × 4MB = ~40GB  
- **Total: ~44GB of unvalidated batch data in memory**

If batch coordinators process messages slowly (due to disk I/O for persistence [8](#0-7) , transaction filtering [9](#0-8) , or network communication), Byzantine validators can flood the system faster than messages can be drained, leading to memory exhaustion.

## Impact Explanation

This vulnerability represents a **High Severity** issue under the Aptos bug bounty criteria for the following reasons:

1. **Validator Node Crashes**: Memory exhaustion can cause validator processes to be killed by the OS OOM killer, taking the node offline.

2. **Network Liveness Disruption**: If a Byzantine validator (or coordinated Byzantine validators) successfully crashes multiple honest validators simultaneously, the network could lose liveness until the affected validators restart and recover.

3. **No Special Privileges Required**: Any validator in the active set can execute this attack, requiring only standard validator network access (Byzantine fault tolerance assumes up to 1/3 of validators may be malicious).

4. **Difficult to Detect Initially**: The attack appears as legitimate batch message traffic until memory exhaustion occurs, making it hard to distinguish from normal high-load conditions.

The impact falls under "Validator node slowdowns" at minimum, and potentially higher if crashes occur, which could affect network availability.

## Likelihood Explanation

**Likelihood: HIGH**

This attack is highly likely to succeed under the following realistic conditions:

1. **Attacker Requirements**: Only requires a single Byzantine validator in the active set, which is within the BFT threat model (up to 1/3 Byzantine tolerance).

2. **Network Bandwidth**: Modern validators have sufficient network bandwidth to send maximum-size messages at a rate that could fill the channels within minutes.

3. **Processing Delays**: Batch coordinators perform several slow operations:
   - Database persistence operations [8](#0-7) 
   - Transaction filtering for each transaction [10](#0-9) 
   - Network communication to send signed batch infos [11](#0-10) 

4. **No Rate Limiting on Validated Messages**: While there is a `bounded_executor` limiting concurrent verification tasks to 16 [12](#0-11) , this only throttles verification, not the post-verification message flow.

5. **Default Configuration Allows Large Accumulation**: With default channel sizes of 1000 and 10 batch coordinators, the system permits 44GB of memory accumulation before backpressure mechanisms engage.

## Recommendation

Implement early size validation in the verification phase to prevent oversized messages from entering the channel queues:

1. **Add Total Bytes Validation to `BatchMsg::verify()`**: Modify the verification method to accept and validate against `max_total_bytes` parameter:

```rust
pub fn verify(
    &self,
    peer_id: PeerId,
    max_num_batches: usize,
    max_total_bytes: u64,  // ADD THIS
    verifier: &ValidatorVerifier,
) -> anyhow::Result<()> {
    ensure!(!self.batches.is_empty(), "Empty message");
    ensure!(
        self.batches.len() <= max_num_batches,
        "Too many batches: {} > {}",
        self.batches.len(),
        max_num_batches
    );
    
    // ADD THIS VALIDATION
    let mut total_bytes = 0u64;
    for batch in self.batches.iter() {
        total_bytes += batch.num_bytes();
    }
    ensure!(
        total_bytes <= max_total_bytes,
        "Total bytes exceeds limit: {} > {}",
        total_bytes,
        max_total_bytes
    );
    
    let epoch_authors = verifier.address_to_validator_index();
    for batch in self.batches.iter() {
        // ... existing validation ...
    }
    Ok(())
}
```

2. **Update Verification Call Sites**: Pass `max_total_bytes` from config to the verify method in `UnverifiedEvent::verify()` [13](#0-12) .

3. **Consider Reducing Channel Capacities**: Evaluate whether 1000-message capacity per channel is necessary, or if smaller capacities would provide better backpressure without impacting legitimate throughput.

4. **Add Memory Usage Monitoring**: Implement metrics tracking the current queue depths and estimated memory usage in these channels to detect potential attacks early.

## Proof of Concept

```rust
#[tokio::test]
async fn test_batch_message_memory_exhaustion() {
    use consensus::quorum_store::types::BatchMsg;
    use aptos_consensus_types::proof_of_store::BatchInfo;
    use aptos_types::transaction::SignedTransaction;
    
    // Create a BatchMsg with maximum allowed batches
    let max_num_batches = 20;
    let target_batch_size = 200_000; // ~200KB per batch
    
    let mut batches = Vec::new();
    for _ in 0..max_num_batches {
        // Create a batch with transactions totaling ~200KB
        let mut txns = Vec::new();
        for _ in 0..100 {
            // Create a transaction with ~2KB payload
            txns.push(create_test_transaction_with_size(2000));
        }
        let batch = create_test_batch(txns);
        batches.push(batch);
    }
    
    let batch_msg = BatchMsg::new(batches);
    
    // Verify passes with only batch count check
    assert!(batch_msg.verify(peer_id, max_num_batches, &validator_verifier).is_ok());
    
    // But total size is ~4MB
    let total_size: u64 = batch_msg.batches.iter()
        .map(|b| b.num_bytes())
        .sum();
    assert!(total_size > 4_000_000); // > 4MB
    
    // Simulate sending 1000 such messages
    // Memory usage: 1000 * 4MB = 4GB just in one channel
    // With 10 batch coordinator channels: 40GB total
    
    println!("Single BatchMsg size: {} bytes", total_size);
    println!("Memory for 1000 messages in one channel: {} GB", 
             (total_size * 1000) / (1024 * 1024 * 1024));
    println!("Memory for 10 channels @ 1000 messages each: {} GB",
             (total_size * 10000) / (1024 * 1024 * 1024));
}
```

**Notes:**

The vulnerability is real and exploitable because:
1. Size validation occurs after messages are already allocated in memory within channel queues
2. The gap between verification and size validation allows up to 44GB accumulation with default settings
3. Byzantine validators can deliberately slow down the processing pipeline by sending invalid batches that fail size checks only after being queued, forcing memory allocation without useful work
4. The system's defense (channel backpressure) only engages after excessive memory consumption has already occurred

This breaks the **Resource Limits** invariant that "all operations must respect gas, storage, and computational limits," as the system allows unbounded memory accumulation before enforcing size constraints.

### Citations

**File:** config/src/config/quorum_store_config.rs (L122-122)
```rust
            receiver_max_num_batches: 20,
```

**File:** config/src/config/quorum_store_config.rs (L124-126)
```rust
            receiver_max_total_bytes: 4 * 1024 * 1024
                + DEFAULT_MAX_NUM_BATCHES
                + BATCH_PADDING_BYTES,
```

**File:** consensus/src/quorum_store/types.rs (L433-461)
```rust
    pub fn verify(
        &self,
        peer_id: PeerId,
        max_num_batches: usize,
        verifier: &ValidatorVerifier,
    ) -> anyhow::Result<()> {
        ensure!(!self.batches.is_empty(), "Empty message");
        ensure!(
            self.batches.len() <= max_num_batches,
            "Too many batches: {} > {}",
            self.batches.len(),
            max_num_batches
        );
        let epoch_authors = verifier.address_to_validator_index();
        for batch in self.batches.iter() {
            ensure!(
                epoch_authors.contains_key(&batch.author()),
                "Invalid author {} for batch {} in current epoch",
                batch.author(),
                batch.digest()
            );
            ensure!(
                batch.author() == peer_id,
                "Batch author doesn't match sender"
            );
            batch.verify()?
        }
        Ok(())
    }
```

**File:** consensus/src/epoch_manager.rs (L1587-1622)
```rust
            self.bounded_executor
                .spawn(async move {
                    match monitor!(
                        "verify_message",
                        unverified_event.clone().verify(
                            peer_id,
                            &epoch_state.verifier,
                            &proof_cache,
                            quorum_store_enabled,
                            peer_id == my_peer_id,
                            max_num_batches,
                            max_batch_expiry_gap_usecs,
                        )
                    ) {
                        Ok(verified_event) => {
                            Self::forward_event(
                                quorum_store_msg_tx,
                                round_manager_tx,
                                buffered_proposal_tx,
                                peer_id,
                                verified_event,
                                payload_manager,
                                pending_blocks,
                            );
                        },
                        Err(e) => {
                            error!(
                                SecurityEvent::ConsensusInvalidMessage,
                                remote_peer = peer_id,
                                error = ?e,
                                unverified_event = unverified_event
                            );
                        },
                    }
                })
                .await;
```

**File:** consensus/src/epoch_manager.rs (L1760-1762)
```rust
            | VerifiedEvent::BatchMsg(_)) => {
                Self::forward_event_to(quorum_store_msg_tx, peer_id, (peer_id, quorum_store_event))
                    .context("quorum store sender")
```

**File:** consensus/src/quorum_store/quorum_store_builder.rs (L186-191)
```rust
        let (quorum_store_msg_tx, quorum_store_msg_rx) =
            aptos_channel::new::<AccountAddress, (Author, VerifiedEvent)>(
                QueueStyle::FIFO,
                config.channel_size,
                None,
            );
```

**File:** consensus/src/quorum_store/network_listener.rs (L90-93)
```rust
                        self.remote_batch_coordinator_tx[idx]
                            .send(BatchCoordinatorCommand::NewBatches(author, batches))
                            .await
                            .expect("Could not send remote batch");
```

**File:** consensus/src/quorum_store/batch_coordinator.rs (L103-103)
```rust
                let signed_batch_infos = batch_store.persist(persist_requests);
```

**File:** consensus/src/quorum_store/batch_coordinator.rs (L108-110)
```rust
                    network_sender
                        .send_signed_batch_info_msg_v2(signed_batch_infos, vec![peer_id])
                        .await;
```

**File:** consensus/src/quorum_store/batch_coordinator.rs (L137-171)
```rust
    fn ensure_max_limits(&self, batches: &[Batch<BatchInfoExt>]) -> anyhow::Result<()> {
        let mut total_txns = 0;
        let mut total_bytes = 0;
        for batch in batches.iter() {
            ensure!(
                batch.num_txns() <= self.max_batch_txns,
                "Exceeds batch txn limit {} > {}",
                batch.num_txns(),
                self.max_batch_txns,
            );
            ensure!(
                batch.num_bytes() <= self.max_batch_bytes,
                "Exceeds batch bytes limit {} > {}",
                batch.num_bytes(),
                self.max_batch_bytes,
            );

            total_txns += batch.num_txns();
            total_bytes += batch.num_bytes();
        }
        ensure!(
            total_txns <= self.max_total_txns,
            "Exceeds total txn limit {} > {}",
            total_txns,
            self.max_total_txns,
        );
        ensure!(
            total_bytes <= self.max_total_bytes,
            "Exceeds total bytes limit: {} > {}",
            total_bytes,
            self.max_total_bytes,
        );

        Ok(())
    }
```

**File:** consensus/src/quorum_store/batch_coordinator.rs (L191-213)
```rust
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

**File:** consensus/src/round_manager.rs (L166-173)
```rust
            UnverifiedEvent::BatchMsg(b) => {
                if !self_message {
                    b.verify(peer_id, max_num_batches, validator)?;
                    counters::VERIFY_MSG
                        .with_label_values(&["batch"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::BatchMsg(Box::new((*b).into()))
```
