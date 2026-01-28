# Audit Report

## Title
Unbounded Batch Accumulation via Far-Future Expiration Time Manipulation in Quorum Store

## Summary
A malicious validator can send `BatchMsg` messages with expiration times set to `u64::MAX`, bypassing all expiration cleanup mechanisms. This causes unbounded memory accumulation in honest validators, leading to performance degradation and potential node crashes.

## Finding Description

The vulnerability exists in the asymmetric validation of batch expiration times between `BatchMsg` and `SignedBatchInfo` message types in the Quorum Store protocol.

**Attack Flow:**

1. **Malicious Batch Creation**: A Byzantine validator creates batches with `expiration = u64::MAX` and broadcasts them via `BatchMsg` to honest validators.

2. **Verification Bypass**: When `UnverifiedEvent::verify()` processes the incoming `BatchMsg`, it calls `BatchMsg::verify()` without the `max_batch_expiry_gap_usecs` parameter: [1](#0-0) 

The `BatchMsg::verify()` method only validates batch count limits, author validity, and payload integrity—no expiration upper bound check: [2](#0-1) 

The `Batch::verify()` method validates payload hash, transaction counts, and gas prices but does not check expiration bounds: [3](#0-2) 

3. **Storage Without Upper Bound Validation**: The batch is stored in `BatchStore::save()`, which only verifies `expiration > last_certified_time`: [4](#0-3) 

Since `u64::MAX > last_certified_time`, the batch is accepted and cached.

4. **Propagation to ProofManager**: The batch info is forwarded to `ProofManager` via `ProofManagerCommand::ReceiveBatches`: [5](#0-4) 

5. **Insertion into BatchProofQueue**: The batch is inserted with the malicious expiration: [6](#0-5) 

6. **Expiration Cleanup Bypass**: When blocks commit, `handle_updated_block_timestamp()` calls `self.expirations.expire(block_timestamp)`: [7](#0-6) 

Since `u64::MAX >> block_timestamp`, these batches are never expired.

7. **Garbage Collection Bypass**: The periodic GC checks `item.info.expiration() > timestamp`: [8](#0-7) 

For `u64::MAX` expiration, this is always true, preventing garbage collection.

**Contrast with SignedBatchInfo Protection**: 

`SignedBatchInfo` messages have upper-bound validation that rejects far-future expirations: [9](#0-8) 

This validation is called for `SignedBatchInfo` messages but not for `BatchMsg` messages: [10](#0-9) 

## Impact Explanation

**Severity: HIGH**

This vulnerability enables resource exhaustion attacks against honest validators, qualifying as **High Severity** ($50,000 tier) under the Aptos Bug Bounty program's "Validator node slowdowns" category.

**Concrete Impacts:**

1. **Unbounded Memory Growth**: Each malicious batch permanently consumes memory in multiple data structures:
   - `BatchStore::db_cache` (DashMap)
   - `BatchProofQueue::items` (HashMap)
   - `BatchProofQueue::author_to_batches` (HashMap of BTrees)
   - `BatchProofQueue::expirations` (TimeExpirations index)

2. **Validator Performance Degradation**: Growing data structures degrade lookup performance and increase processing latency, directly impacting consensus participation and block production.

3. **Potential Node Crashes**: Continued accumulation can exhaust system memory, causing validator nodes to crash and reducing network decentralization.

4. **No Economic Deterrent**: The attacker incurs no stake slashing or penalties, as batches with invalid expiration times are not detected as Byzantine behavior.

## Likelihood Explanation

**Likelihood: HIGH**

1. **Low Attack Complexity**: Constructing a `BatchMsg` with `expiration = u64::MAX` requires minimal effort from any validator in the current epoch.

2. **Single Validator Attack**: Only one malicious or compromised validator is needed (< 1/3 Byzantine validators, within BFT threat model).

3. **Immediate and Cumulative Impact**: Each malicious batch permanently increases memory usage until manual intervention.

4. **Detection Difficulty**: Operators may not immediately notice slow memory growth until performance degradation becomes severe.

## Recommendation

Add upper-bound validation for batch expiration times in `BatchMsg::verify()`, similar to the existing validation in `SignedBatchInfo::verify()`:

```rust
pub fn verify(
    &self,
    peer_id: PeerId,
    max_num_batches: usize,
    max_batch_expiry_gap_usecs: u64,
    verifier: &ValidatorVerifier,
) -> anyhow::Result<()> {
    ensure!(!self.batches.is_empty(), "Empty message");
    ensure!(
        self.batches.len() <= max_num_batches,
        "Too many batches: {} > {}",
        self.batches.len(),
        max_num_batches
    );
    
    let current_time = aptos_infallible::duration_since_epoch().as_micros() as u64;
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
        
        // Add expiration upper bound check
        ensure!(
            batch.expiration() <= current_time + max_batch_expiry_gap_usecs,
            "Batch expiration too far in future: {} > {}",
            batch.expiration(),
            current_time + max_batch_expiry_gap_usecs
        );
        
        batch.verify()?
    }
    Ok(())
}
```

Update the call site in `UnverifiedEvent::verify()` to pass `max_batch_expiry_gap_usecs`:

```rust
UnverifiedEvent::BatchMsgV2(b) => {
    if !self_message {
        b.verify(peer_id, max_num_batches, max_batch_expiry_gap_usecs, validator)?;
        // ...
    }
    VerifiedEvent::BatchMsg(b)
}
```

## Proof of Concept

The vulnerability can be demonstrated by:

1. Creating a `BatchMsg` with `expiration = u64::MAX`
2. Sending it through the network to honest validators
3. Observing that the batch bypasses all expiration checks and is permanently cached
4. Monitoring memory growth in `BatchStore::db_cache` and `BatchProofQueue` data structures

Since the malicious batch never expires, it remains in memory indefinitely, consuming resources without providing any value to consensus.

## Notes

This vulnerability demonstrates a critical gap in the validation asymmetry between `BatchMsg` (received from peers) and `SignedBatchInfo` (signatures for own batches). While `SignedBatchInfo` correctly validates expiration upper bounds, `BatchMsg` lacks this essential check, enabling a single Byzantine validator to cause unbounded memory accumulation across the network.

### Citations

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

**File:** consensus/src/round_manager.rs (L184-196)
```rust
            UnverifiedEvent::SignedBatchInfo(sd) => {
                if !self_message {
                    sd.verify(
                        peer_id,
                        max_num_batches,
                        max_batch_expiry_gap_usecs,
                        validator,
                    )?;
                    counters::VERIFY_MSG
                        .with_label_values(&["signed_batch"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::SignedBatchInfo(Box::new((*sd).into()))
```

**File:** consensus/src/quorum_store/types.rs (L262-290)
```rust
    pub fn verify(&self) -> anyhow::Result<()> {
        ensure!(
            self.payload.author() == self.author(),
            "Payload author doesn't match the info"
        );
        ensure!(
            self.payload.hash() == *self.digest(),
            "Payload hash doesn't match the digest"
        );
        ensure!(
            self.payload.num_txns() as u64 == self.num_txns(),
            "Payload num txns doesn't match batch info"
        );
        ensure!(
            self.payload.num_bytes() as u64 == self.num_bytes(),
            "Payload num bytes doesn't match batch info"
        );
        for txn in self.payload.txns() {
            ensure!(
                txn.gas_unit_price() >= self.gas_bucket_start(),
                "Payload gas unit price doesn't match batch info"
            );
            ensure!(
                !txn.payload().is_encrypted_variant(),
                "Encrypted transaction is not supported yet"
            );
        }
        Ok(())
    }
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

**File:** consensus/src/quorum_store/batch_store.rs (L419-439)
```rust
    pub(crate) fn save(&self, value: &PersistedValue<BatchInfoExt>) -> anyhow::Result<bool> {
        let last_certified_time = self.last_certified_time();
        if value.expiration() > last_certified_time {
            fail_point!("quorum_store::save", |_| {
                // Skip caching and storing value to the db
                Ok(false)
            });
            counters::GAP_BETWEEN_BATCH_EXPIRATION_AND_CURRENT_TIME_WHEN_SAVE.observe(
                Duration::from_micros(value.expiration() - last_certified_time).as_secs_f64(),
            );

            return self.insert_to_cache(value);
        }
        counters::NUM_BATCH_EXPIRED_WHEN_SAVE.inc();
        bail!(
            "Incorrect expiration {} in epoch {}, last committed timestamp {}",
            value.expiration(),
            self.epoch(),
            last_certified_time,
        );
    }
```

**File:** consensus/src/quorum_store/batch_coordinator.rs (L131-133)
```rust
            let _ = sender_to_proof_manager
                .send(ProofManagerCommand::ReceiveBatches(batches))
                .await;
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L278-283)
```rust
            self.author_to_batches
                .entry(batch_info.author())
                .or_default()
                .insert(batch_sort_key.clone(), batch_info.clone());
            self.expirations
                .add_item(batch_sort_key, batch_info.expiration());
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L324-339)
```rust
    fn gc_expired_batch_summaries_without_proofs(&mut self) {
        let timestamp = aptos_infallible::duration_since_epoch().as_micros() as u64;
        self.items.retain(|_, item| {
            if item.is_committed() || item.proof.is_some() || item.info.expiration() > timestamp {
                true
            } else {
                self.author_to_batches
                    .get_mut(&item.info.author())
                    .map(|queue| queue.remove(&BatchSortKey::from_info(&item.info)));
                counters::GARBAGE_COLLECTED_IN_PROOF_QUEUE_COUNTER
                    .with_label_values(&["expired_batch_without_proof"])
                    .inc();
                false
            }
        });
    }
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L716-729)
```rust
    pub(crate) fn handle_updated_block_timestamp(&mut self, block_timestamp: u64) {
        // tolerate asynchronous notification
        if self.latest_block_timestamp > block_timestamp {
            return;
        }
        let start = Instant::now();
        self.latest_block_timestamp = block_timestamp;
        if let Some(time_lag) = aptos_infallible::duration_since_epoch()
            .checked_sub(Duration::from_micros(block_timestamp))
        {
            counters::TIME_LAG_IN_BATCH_PROOF_QUEUE.observe_duration(time_lag);
        }

        let expired = self.expirations.expire(block_timestamp);
```

**File:** consensus/consensus-types/src/proof_of_store.rs (L459-482)
```rust
    pub fn verify(
        &self,
        sender: PeerId,
        max_batch_expiry_gap_usecs: u64,
        validator: &ValidatorVerifier,
    ) -> anyhow::Result<()> {
        if sender != self.signer {
            bail!("Sender {} mismatch signer {}", sender, self.signer);
        }

        if self.expiration()
            > aptos_infallible::duration_since_epoch().as_micros() as u64
                + max_batch_expiry_gap_usecs
        {
            bail!(
                "Batch expiration too far in future: {} > {}",
                self.expiration(),
                aptos_infallible::duration_since_epoch().as_micros() as u64
                    + max_batch_expiry_gap_usecs
            );
        }

        Ok(validator.optimistic_verify(self.signer, &self.info, &self.signature)?)
    }
```
