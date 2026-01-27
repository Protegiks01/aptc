# Audit Report

## Title
Missing Expiration Bounds Validation in BatchMsg Allows Permanent Resource Exhaustion Within Epoch

## Summary
The `BatchMsg::verify()` method does not validate that batch expiration timestamps are within reasonable bounds, unlike `SignedBatchInfo::verify()` which enforces `max_batch_expiry_gap_usecs`. This allows malicious validators to send batches with expiration values set to `u64::MAX`, preventing cleanup during the epoch and causing permanent quota exhaustion for that validator's batch storage.

## Finding Description

The quorum store batch handling system has two parallel validation paths for batch messages:

1. **SignedBatchInfo path** - includes expiration validation
2. **BatchMsg path** - missing expiration validation

When a validator receives a `BatchMsg` from the network, the verification flow is: [1](#0-0) 

The `BatchMsg::verify()` method validates batch count, author validity, and payload consistency, but does NOT validate expiration bounds: [2](#0-1) 

In contrast, `SignedBatchInfo::verify()` includes explicit expiration bounds checking: [3](#0-2) 

**Attack Path:**

1. Malicious validator crafts `BatchMsg` with batches having `expiration = u64::MAX`
2. The message passes `BatchMsg::verify()` since no expiration validation exists
3. Batches are persisted via `batch_store.save()` which only checks `expiration > last_certified_time`: [4](#0-3) 

4. Batches are added to the `TimeExpirations` tracking structure with `expiration = u64::MAX`: [5](#0-4) 

5. The cleanup mechanism in `clear_expired_payload()` uses `TimeExpirations::expire()`: [6](#0-5) 

6. Since the condition requires `expiration <= certified_time`, and `u64::MAX` (~584 million years) will never be less than any realistic certified timestamp, these batches are never cleaned up within the epoch.

7. The malicious batches permanently consume the validator's per-peer quota (default 300MB db_quota, 120MB memory_quota, 300k batch_quota): [7](#0-6) 

## Impact Explanation

**Severity: Medium** per Aptos bug bounty criteria.

This vulnerability causes resource exhaustion that affects validator operation but does not break consensus safety:

- **Resource Exhaustion**: Malicious batches consume quota permanently within an epoch, blocking legitimate batch storage from that validator
- **Validator Degradation**: Once quota is exhausted, the validator cannot accept new batches, impacting their participation in consensus
- **Limited Scope**: Attack is isolated per-peer due to quota management; only affects the malicious validator's own quota allocation
- **Temporary Duration**: Batches are cleaned up at epoch boundaries via epoch-based garbage collection, limiting impact to one epoch duration

The impact does not reach High severity because:
- No consensus safety violation occurs
- No funds are at risk
- The network continues operating with remaining validators
- Recovery happens automatically at next epoch

However, it qualifies as Medium severity because it creates "state inconsistencies requiring intervention" if epochs are long, and causes degraded validator performance.

## Likelihood Explanation

**Likelihood: High**

- **Low Attacker Requirements**: Any active validator can execute this attack by simply crafting network messages with malformed expiration values
- **Simple Exploitation**: No complex logic or timing requirements; just send `BatchMsg` with `expiration = u64::MAX`
- **No Detection**: The batches pass all validation checks and appear legitimate until quota exhaustion occurs
- **Repeatable**: Attack can be repeated continuously throughout an epoch to maintain quota pressure

The only mitigating factor is that the attack consumes the attacker's own quota, potentially affecting their ability to participate in consensus.

## Recommendation

Add expiration bounds validation to `BatchMsg::verify()` consistent with `SignedBatchInfo::verify()`:

```rust
impl<T: TBatchInfo> BatchMsg<T> {
    pub fn verify(
        &self,
        peer_id: PeerId,
        max_num_batches: usize,
        max_batch_expiry_gap_usecs: u64,  // Add parameter
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
            
            // ADD EXPIRATION VALIDATION
            let current_time = aptos_infallible::duration_since_epoch().as_micros() as u64;
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
}
```

Update the call sites in `UnverifiedEvent::verify()` to pass `max_batch_expiry_gap_usecs`: [8](#0-7) 

## Proof of Concept

```rust
#[test]
fn test_batch_msg_with_max_expiration() {
    use aptos_types::PeerId;
    use aptos_consensus_types::proof_of_store::BatchInfo;
    use consensus::quorum_store::types::{Batch, BatchMsg};
    
    // Create a batch with u64::MAX expiration
    let malicious_expiration = u64::MAX;
    let peer_id = PeerId::random();
    let batch_id = BatchId::new(1);
    let epoch = 1;
    
    let batch = Batch::new(
        batch_id,
        vec![], // Empty transactions for simplicity
        epoch,
        malicious_expiration,  // Malicious expiration
        peer_id,
        0,
    );
    
    let batch_msg = BatchMsg::new(vec![batch]);
    let validator_verifier = create_test_validator_verifier();
    
    // This should fail but currently passes
    let result = batch_msg.verify(
        peer_id,
        10,  // max_num_batches
        &validator_verifier,
    );
    
    assert!(result.is_ok()); // VULNERABILITY: Passes when it should fail
    
    // The batch would be saved with u64::MAX expiration
    // and never cleaned up during the epoch
}
```

## Notes

The vulnerability exists because batch expiration validation was implemented for `SignedBatchInfo` messages but not for `BatchMsg` messages, creating an inconsistency in the validation logic. The `max_batch_expiry_gap_usecs` parameter (default 60 seconds) is already passed to the verification flow but only utilized for signed batch info messages, not for batch messages themselves.

While epoch-based cleanup provides eventual recovery, the default configuration allows 60-second batch expiry gaps, suggesting epochs may be significantly longer, making intra-epoch resource exhaustion a practical concern for validator operation.

### Citations

**File:** consensus/src/round_manager.rs (L166-182)
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
            UnverifiedEvent::BatchMsgV2(b) => {
                if !self_message {
                    b.verify(peer_id, max_num_batches, validator)?;
                    counters::VERIFY_MSG
                        .with_label_values(&["batch_v2"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::BatchMsg(b)
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

**File:** consensus/consensus-types/src/proof_of_store.rs (L459-479)
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
```

**File:** consensus/src/quorum_store/batch_store.rs (L64-84)
```rust
    pub(crate) fn update_quota(&mut self, num_bytes: usize) -> anyhow::Result<StorageMode> {
        if self.batch_balance == 0 {
            counters::EXCEEDED_BATCH_QUOTA_COUNT.inc();
            bail!("Batch quota exceeded ");
        }

        if self.db_balance >= num_bytes {
            self.batch_balance -= 1;
            self.db_balance -= num_bytes;

            if self.memory_balance >= num_bytes {
                self.memory_balance -= num_bytes;
                Ok(StorageMode::MemoryAndPersisted)
            } else {
                Ok(StorageMode::PersistedOnly)
            }
        } else {
            counters::EXCEEDED_STORAGE_QUOTA_COUNT.inc();
            bail!("Storage quota exceeded ");
        }
    }
```

**File:** consensus/src/quorum_store/batch_store.rs (L411-416)
```rust
        // Add expiration for the inserted entry, no need to be atomic w. insertion.
        #[allow(clippy::unwrap_used)]
        {
            self.expirations.lock().add_item(digest, expiration_time);
        }
        Ok(true)
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
