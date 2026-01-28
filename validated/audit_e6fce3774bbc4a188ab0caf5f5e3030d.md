# Audit Report

## Title
Unbounded Batch Accumulation via Far-Future Expiration Time Manipulation in Quorum Store

## Summary
A malicious validator can send `BatchMsg` messages with expiration times set to `u64::MAX`, bypassing expiration-based cleanup mechanisms. This causes indefinite accumulation of batches in honest validators' memory structures, leading to performance degradation and potential resource exhaustion.

## Finding Description

The vulnerability exists due to asymmetric validation of batch expiration times between `BatchMsg` and `SignedBatchInfo` message types in the Quorum Store protocol.

**Attack Flow:**

1. **Malicious Batch Creation**: A Byzantine validator creates batches with `expiration = u64::MAX` and broadcasts them via `BatchMsg` to honest validators.

2. **Verification Bypass**: When `UnverifiedEvent::verify()` processes incoming `BatchMsg`, it calls `BatchMsg::verify()` with only three parameters (peer_id, max_num_batches, validator), explicitly excluding the `max_batch_expiry_gap_usecs` parameter that would validate expiration upper bounds. [1](#0-0) 

   The `BatchMsg::verify()` method only validates batch count limits, author validity, and calls `batch.verify()` for each batch—it performs no expiration upper bound checks. [2](#0-1) 

   The `Batch::verify()` method validates payload hash, transaction counts, and gas prices but does not check expiration bounds at all. [3](#0-2) 

3. **Storage Without Upper Bound Validation**: The batch is stored via `BatchStore::save()`, which only verifies `expiration > last_certified_time`. Since `u64::MAX > last_certified_time` is always true, the batch is accepted and cached. [4](#0-3) 

4. **Propagation to ProofManager**: Batches are forwarded to `ProofManager` via `ProofManagerCommand::ReceiveBatches`. [5](#0-4) 

5. **Insertion into BatchProofQueue**: The `ProofManager` inserts these batches into `BatchProofQueue` with the malicious expiration time intact. [6](#0-5) 

6. **Expiration Cleanup Bypass**: When blocks commit, `handle_updated_block_timestamp()` calls `self.expirations.expire(block_timestamp)` to clean up expired batches. However, the `TimeExpirations::expire()` method only removes items where `expiration <= certified_time`. Since `u64::MAX > block_timestamp` is always true, these batches are never expired. [7](#0-6) 

7. **Garbage Collection Bypass**: The periodic garbage collection in `populate_cache_and_gc_expired_batches_v1` checks `if expiration < gc_timestamp`. For batches with `expiration = u64::MAX`, this condition is always false, preventing garbage collection. [8](#0-7) 

**Contrast with SignedBatchInfo Protection**: 

`SignedBatchInfo::verify()` includes explicit upper-bound validation that rejects batches with expiration times exceeding `current_time + max_batch_expiry_gap_usecs`. [9](#0-8) 

This validation is called for `SignedBatchInfo` messages with the `max_batch_expiry_gap_usecs` parameter, but not for `BatchMsg` messages. [10](#0-9) 

## Impact Explanation

**Severity: HIGH**

This vulnerability enables resource exhaustion attacks against honest validators, qualifying as **High Severity** under the Aptos Bug Bounty program's "Validator node slowdowns" category.

**Concrete Impacts:**

1. **Persistent Memory Accumulation**: Each malicious batch permanently consumes memory in multiple data structures (BatchStore::db_cache, BatchProofQueue::items, BatchProofQueue::author_to_batches, BatchProofQueue::expirations) as they are never cleaned up by expiration-based mechanisms.

2. **Per-Peer Quota Exhaustion**: While BatchStore implements per-peer quotas (120MB memory, 300MB db, 300k batches), malicious batches permanently occupy this quota space since they never expire, preventing legitimate batches from being stored. [11](#0-10) 

3. **Validator Performance Degradation**: Growing data structures degrade lookup performance and increase processing latency, directly impacting consensus participation and block production efficiency.

4. **Multiple Validator Attack Surface**: If multiple validators are compromised (still < 1/3 Byzantine), the cumulative effect multiplies, as each malicious validator can exhaust their per-peer quotas on every honest node.

5. **No Economic Deterrent**: The attacker incurs no stake slashing or penalties, as batches with manipulated expiration times are not detected as Byzantine behavior.

## Likelihood Explanation

**Likelihood: HIGH**

1. **Low Attack Complexity**: Constructing a `BatchMsg` with `expiration = u64::MAX` requires minimal effort from any validator in the current epoch—simply setting a field value.

2. **Single Validator Attack**: Only one malicious or compromised validator is needed (< 1/3 Byzantine validators, within BFT threat model).

3. **Permanent Impact**: Each malicious batch permanently increases resource usage until manual node restart or intervention, with no automatic cleanup mechanism.

4. **Detection Difficulty**: Operators may not immediately notice gradual memory/quota exhaustion until performance degradation becomes severe or quotas are completely filled.

## Recommendation

Implement expiration upper-bound validation for `BatchMsg::verify()` similar to `SignedBatchInfo::verify()`:

1. Add `max_batch_expiry_gap_usecs` parameter to `BatchMsg::verify()` method signature
2. Validate each batch's expiration: `batch.expiration() <= current_time + max_batch_expiry_gap_usecs`
3. Reject entire `BatchMsg` if any batch has far-future expiration
4. Pass the validation parameter through the call chain from `UnverifiedEvent::verify()`

Example fix in `consensus/src/quorum_store/types.rs`:
```rust
pub fn verify(
    &self,
    peer_id: PeerId,
    max_num_batches: usize,
    max_batch_expiry_gap_usecs: u64,
    verifier: &ValidatorVerifier,
) -> anyhow::Result<()> {
    // ... existing checks ...
    let current_time = aptos_infallible::duration_since_epoch().as_micros() as u64;
    for batch in self.batches.iter() {
        ensure!(
            batch.expiration() <= current_time + max_batch_expiry_gap_usecs,
            "Batch expiration too far in future: {} > {}",
            batch.expiration(),
            current_time + max_batch_expiry_gap_usecs
        );
        // ... existing validation ...
    }
    Ok(())
}
```

## Proof of Concept

A malicious validator can execute this attack by:

1. Creating a batch with `expiration = u64::MAX` 
2. Broadcasting via `BatchMsg` to honest validators
3. Honest validators accept and store the batch (passes all validation)
4. The batch permanently consumes quota space and memory
5. Expiration-based cleanup mechanisms never remove it (`u64::MAX > any_timestamp`)
6. Repeated attacks exhaust per-peer quotas, preventing legitimate batch storage

The vulnerability can be verified by inspecting the code paths and observing that no validation prevents `u64::MAX` expiration in the `BatchMsg` flow, while the same value would be rejected in the `SignedBatchInfo` flow.

## Notes

While `BatchStore` implements per-peer quotas that provide some upper bound on resource consumption, this does not fully mitigate the vulnerability because:
1. Malicious batches permanently occupy quota space (never expire)
2. Multiple malicious validators can exhaust quotas on all honest nodes
3. `BatchProofQueue` structures lack similar quota protections
4. The core issue—asymmetric validation allowing far-future expirations—remains a protocol-level flaw that violates the principle of consistent message validation across similar message types

### Citations

**File:** consensus/src/round_manager.rs (L166-174)
```rust
            UnverifiedEvent::BatchMsg(b) => {
                if !self_message {
                    b.verify(peer_id, max_num_batches, validator)?;
                    counters::VERIFY_MSG
                        .with_label_values(&["batch"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::BatchMsg(Box::new((*b).into()))
            },
```

**File:** consensus/src/round_manager.rs (L184-197)
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
            },
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

**File:** consensus/src/quorum_store/batch_store.rs (L263-280)
```rust
        let gc_timestamp = last_certified_time.saturating_sub(expiration_buffer_usecs);
        for (digest, value) in db_content {
            let expiration = value.expiration();

            trace!(
                "QS: Batchreader recovery content exp {:?}, digest {}",
                expiration,
                digest
            );

            if expiration < gc_timestamp {
                expired_keys.push(digest);
            } else {
                batch_store
                    .insert_to_cache(&value.into())
                    .expect("Storage limit exceeded upon BatchReader construction");
            }
        }
```

**File:** consensus/src/quorum_store/batch_store.rs (L383-391)
```rust
            let value_to_be_stored = if self
                .peer_quota
                .entry(author)
                .or_insert(QuotaManager::new(
                    self.db_quota,
                    self.memory_quota,
                    self.batch_quota,
                ))
                .update_quota(value.num_bytes() as usize)?
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

**File:** consensus/src/quorum_store/proof_manager.rs (L80-86)
```rust
    pub(crate) fn receive_batches(
        &mut self,
        batch_summaries: Vec<(BatchInfoExt, Vec<TxnSummaryWithExpiration>)>,
    ) {
        self.batch_proof_queue.insert_batches(batch_summaries);
        self.update_remaining_txns_and_proofs();
    }
```

**File:** consensus/src/quorum_store/utils.rs (L78-89)
```rust
    pub(crate) fn expire(&mut self, certified_time: u64) -> HashSet<I> {
        let mut ret = HashSet::new();
        while let Some((Reverse(t), _)) = self.expiries.peek() {
            if *t <= certified_time {
                let (_, item) = self.expiries.pop().unwrap();
                ret.insert(item);
            } else {
                break;
            }
        }
        ret
    }
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
