# Audit Report

## Title
Cache-Database Inconsistency in BatchStore Due to TOCTOU Race Condition in Concurrent Persist Operations

## Summary
The `BatchStore` implementation in the quorum store consensus component contains a Time-of-Check-Time-of-Use (TOCTOU) race condition that allows concurrent persist operations for the same batch digest with different expirations to create cache-database inconsistencies. This can lead to premature batch expiration and node-specific liveness degradation after restarts.

## Finding Description

The vulnerability exists in the `BatchCoordinator` and `BatchStore` interaction where concurrent batch persistence operations are not properly synchronized:

**Root Cause - Non-Atomic Check-Then-Act Pattern:**

The `persist_and_send_digests` method spawns independent tokio tasks without synchronization between concurrent persist operations for the same digest. [1](#0-0) 

In `persist_inner`, the cache update via `insert_to_cache` and the database write are not atomic. The DashMap entry lock is held only during the cache update, but released before the database write occurs. [2](#0-1) [3](#0-2) 

**Attack Vector - Digest Without Expiration Binding:**

The batch digest is computed from the payload hash, which only includes author and transactions - NOT the expiration field. [4](#0-3) 

The `Batch::verify()` method validates that payload hash matches the digest, but does NOT verify the expiration field is cryptographically bound to the payload. [5](#0-4) 

**Race Condition Execution Flow:**

When two concurrent persist operations occur for the same digest with different expirations:

1. Both threads acquire the DashMap lock sequentially and update the cache
2. The cache replacement logic allows a higher expiration to replace a lower one [6](#0-5) 
3. Both threads write to the database without synchronization [3](#0-2) 
4. Due to last-write-wins semantics, the database may contain a different expiration than the cache

**Exploitation Path:**

A Byzantine validator can exploit this by:
1. Creating a batch with digest `D` and payload `P`
2. Sending two signed batch messages with the same digest but different expirations (`T1` and `T2 > T1`)
3. Both messages are processed concurrently by spawned tokio tasks
4. The race condition causes cache-DB divergence
5. When the victim validator restarts, it reloads batches from the database [7](#0-6) 
6. The stale expiration from the database is loaded into the cache
7. The batch may expire prematurely, before consensus uses it
8. The validator cannot execute blocks containing this batch, causing node-specific liveness issues

## Impact Explanation

This vulnerability qualifies as **HIGH severity** per Aptos Bug Bounty criteria:

**Validator Node Slowdowns (High):** When a batch expires prematurely due to stale database data after restart, the validator cannot execute blocks containing that batch. The expiration validation logic rejects expired batches. [8](#0-7) [9](#0-8) 

The validator must either re-fetch from peers (causing slowdown) or state-sync (causing major slowdown) to recover. This creates a denial-of-service vector against individual validators through state corruption.

**Protocol Correctness Violation:** The cache-database inconsistency violates the fundamental assumption that persistent state accurately reflects batch metadata. This is a critical correctness property for consensus systems, as different nodes may have different batch expiration times after restarts, leading to non-deterministic behavior.

## Likelihood Explanation

**Likelihood: MEDIUM**

**Requirements for exploitation:**
- Attacker must be a validator in the active validator set (Byzantine validator assumption - within threat model for < 1/3 validators)
- Attacker must send the same batch payload with different expiration metadata (feasible - validator controls signing key)
- Race condition must occur with precise timing (moderate probability under concurrent load)
- Victim node must restart to load stale data from database (occurs regularly for upgrades, crashes, or maintenance)

**Feasibility:** Byzantine validators are explicitly part of the Aptos threat model. The signature verification covers the entire `BatchInfo` including expiration, [10](#0-9)  but a Byzantine validator can create multiple valid signatures for the same digest with different expirations since they control their signing key. Concurrent processing in `BatchCoordinator` makes race conditions likely under load.

**Mitigating factors:** Requires multiple attempts to reliably trigger the race, impact only manifests after restart, and victim can recover through state sync.

## Recommendation

Implement atomic cache-DB updates with proper synchronization:

1. **Add digest-level locking**: Introduce a distributed lock or mutex per digest to serialize all persist operations for the same digest
2. **Atomic updates**: Ensure cache and DB updates occur within the same critical section
3. **Expiration binding**: Consider including expiration in the digest computation to cryptographically bind it to the payload
4. **Deduplication**: Add a check to reject concurrent persist requests for the same digest if one is already in progress

## Proof of Concept

The PoC requires a Byzantine validator to send two `BatchMsg` messages with the same digest but different expirations to trigger the race condition. The concurrent processing by spawned tokio tasks creates the cache-DB inconsistency, which manifests as premature batch expiration after validator restart.

**Notes:**
- This vulnerability is exploitable within the standard Aptos threat model (< 1/3 Byzantine validators)
- The race condition is more likely under high concurrent load
- Impact is node-specific and requires victim validator restart to manifest
- Validator can recover through state sync, but experiences significant slowdown

### Citations

**File:** consensus/src/quorum_store/batch_coordinator.rs (L90-90)
```rust
        tokio::spawn(async move {
```

**File:** consensus/src/quorum_store/batch_store.rs (L245-290)
```rust
    fn populate_cache_and_gc_expired_batches_v1(
        db: Arc<dyn QuorumStoreStorage>,
        current_epoch: u64,
        last_certified_time: u64,
        expiration_buffer_usecs: u64,
        batch_store: &BatchStore,
    ) {
        let db_content = db
            .get_all_batches()
            .expect("failed to read v1 data from db");
        info!(
            epoch = current_epoch,
            "QS: Read v1 batches from storage. Len: {}, Last Cerified Time: {}",
            db_content.len(),
            last_certified_time
        );

        let mut expired_keys = Vec::new();
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

        info!(
            "QS: Batch store bootstrap expired keys len {}",
            expired_keys.len()
        );
        tokio::task::spawn_blocking(move || {
            db.delete_batches(expired_keys)
                .expect("Deletion of expired keys should not fail");
        });
    }
```

**File:** consensus/src/quorum_store/batch_store.rs (L366-409)
```rust
        {
            // Acquire dashmap internal lock on the entry corresponding to the digest.
            let cache_entry = self.db_cache.entry(digest);

            if let Occupied(entry) = &cache_entry {
                match entry.get().expiration().cmp(&expiration_time) {
                    std::cmp::Ordering::Equal => return Ok(false),
                    std::cmp::Ordering::Greater => {
                        debug!(
                            "QS: already have the digest with higher expiration {}",
                            digest
                        );
                        return Ok(false);
                    },
                    std::cmp::Ordering::Less => {},
                }
            };
            let value_to_be_stored = if self
                .peer_quota
                .entry(author)
                .or_insert(QuotaManager::new(
                    self.db_quota,
                    self.memory_quota,
                    self.batch_quota,
                ))
                .update_quota(value.num_bytes() as usize)?
                == StorageMode::PersistedOnly
            {
                PersistedValue::new(value.batch_info().clone(), None)
            } else {
                value.clone()
            };

            match cache_entry {
                Occupied(entry) => {
                    let (k, prev_value) = entry.replace_entry(value_to_be_stored);
                    debug_assert!(k == digest);
                    self.free_quota(prev_value);
                },
                Vacant(slot) => {
                    slot.insert(value_to_be_stored);
                },
            }
        }
```

**File:** consensus/src/quorum_store/batch_store.rs (L419-438)
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
```

**File:** consensus/src/quorum_store/batch_store.rs (L443-472)
```rust
    pub(crate) fn clear_expired_payload(&self, certified_time: u64) -> Vec<HashValue> {
        // To help slow nodes catch up via execution without going to state sync we keep the blocks for 60 extra seconds
        // after the expiration time. This will help remote peers fetch batches that just expired but are within their
        // execution window.
        let expiration_time = certified_time.saturating_sub(self.expiration_buffer_usecs);
        let expired_digests = self.expirations.lock().expire(expiration_time);
        let mut ret = Vec::new();
        for h in expired_digests {
            let removed_value = match self.db_cache.entry(h) {
                Occupied(entry) => {
                    // We need to check up-to-date expiration again because receiving the same
                    // digest with a higher expiration would update the persisted value and
                    // effectively extend the expiration.
                    if entry.get().expiration() <= expiration_time {
                        self.persist_subscribers.remove(entry.get().digest());
                        Some(entry.remove())
                    } else {
                        None
                    }
                },
                Vacant(_) => unreachable!("Expired entry not in cache"),
            };
            // No longer holding the lock on db_cache entry.
            if let Some(value) = removed_value {
                self.free_quota(value);
                ret.push(h);
            }
        }
        ret
    }
```

**File:** consensus/src/quorum_store/batch_store.rs (L500-513)
```rust
                if needs_db {
                    if !batch_info.is_v2() {
                        let persist_request =
                            persist_request.try_into().expect("Must be a V1 batch");
                        #[allow(clippy::unwrap_in_result)]
                        self.db
                            .save_batch(persist_request)
                            .expect("Could not write to DB");
                    } else {
                        #[allow(clippy::unwrap_in_result)]
                        self.db
                            .save_batch_v2(persist_request)
                            .expect("Could not write to DB")
                    }
```

**File:** consensus/consensus-types/src/common.rs (L708-724)
```rust
pub struct BatchPayload {
    author: PeerId,
    txns: Vec<SignedTransaction>,
    #[serde(skip)]
    num_bytes: OnceCell<usize>,
}

impl CryptoHash for BatchPayload {
    type Hasher = BatchPayloadHasher;

    fn hash(&self) -> HashValue {
        let mut state = Self::Hasher::new();
        let bytes = bcs::to_bytes(&self).expect("Unable to serialize batch payload");
        self.num_bytes.get_or_init(|| bytes.len());
        state.update(&bytes);
        state.finish()
    }
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
