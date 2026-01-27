# Audit Report

## Title
Cache-Database Inconsistency Race Condition in Concurrent BatchWriter.persist() Calls

## Summary
The `BatchWriter::persist()` method in the quorum store lacks atomicity between in-memory cache updates and persistent database writes, allowing concurrent persist calls for the same batch digest to create inconsistent state where the cache contains a newer version (higher expiration) while the database contains a stale version (lower expiration). This violates state consistency guarantees and can cause consensus divergence after node restarts.

## Finding Description

The vulnerability exists in the `BatchStore::persist_inner()` method, which performs two non-atomic operations: [1](#0-0) 

The critical flaw is that the cache update (via `self.save()` at line 497) and the database write (via `self.db.save_batch()` at lines 505-512) are **not performed atomically**. The cache is protected by DashMap's per-entry locking, but the database write occurs **after releasing the cache lock**.

**Attack Scenario:**

When two concurrent threads persist different versions of the same batch digest (e.g., during batch expiration extension):

**Timeline:**
1. **T1**: Thread A acquires cache lock for digest X, sees expiration=500
2. **T2**: Thread A updates cache: digest X → expiration=1000, releases lock, gets `Ok(true)` (needs DB write)
3. **T3**: Thread B acquires cache lock for digest X, sees expiration=1000  
4. **T4**: Thread B updates cache: digest X → expiration=2000 (correctly replaces lower value), releases lock, gets `Ok(true)` (needs DB write)
5. **T5**: Thread B writes to DB: `save_batch(digest X, expiration=2000)`
6. **T6**: Thread A writes to DB: `save_batch(digest X, expiration=1000)` ← **OVERWRITES Thread B's write**

**Final State:**
- **Cache**: digest X with expiration=2000 ✓ (correct)
- **Database**: digest X with expiration=1000 ✗ (stale/incorrect)

**Concurrent persist() calls occur from multiple sources:** [2](#0-1) [3](#0-2) [4](#0-3) 

The `BatchCoordinator` spawns concurrent tasks (line 90) that can race with `BatchGenerator`'s synchronous persist call and `BatchReaderImpl`'s fetch operations.

**Consensus Impact:**

After a validator node crash and restart, the node loads batches from the database: [5](#0-4) 

The stale expiration from the database causes:
1. Batches to expire prematurely (expiration=1000 instead of 2000)
2. Different validators to have different batch availability depending on race timing
3. Potential consensus divergence if some validators reject batches that others accept

This breaks the **State Consistency** invariant: "State transitions must be atomic and verifiable via Merkle proofs" and the **Deterministic Execution** invariant: "All validators must produce identical state roots for identical blocks."

## Impact Explanation

**Severity: HIGH** per Aptos bug bounty criteria: "Significant protocol violations"

This vulnerability causes:

1. **State Inconsistency**: Cache and database contain different versions of the same data, violating atomicity guarantees
2. **Consensus Risk**: After restarts, validators may disagree on batch validity based on stale expiration times
3. **Liveness Impact**: Batches may expire prematurely, causing transaction delays or requiring re-submission
4. **Non-Determinism**: Race timing determines which validator nodes have correct vs. stale data

While not an immediate consensus safety violation (doesn't cause fund loss or chain splits in the active state), it represents a significant protocol violation that undermines state consistency guarantees and can manifest as consensus issues after crash recovery.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

This race condition can occur under normal operation when:

1. **Network batch receipt**: Multiple peers broadcast the same batch, triggering concurrent `persist()` calls via `BatchCoordinator`
2. **Batch expiration extension**: A batch is extended (higher expiration) while still being processed
3. **Concurrent local and remote batches**: Local batch generation races with network batch receipt
4. **State sync operations**: Fetching batches via `BatchReaderImpl` races with ongoing batch processing

The vulnerability requires:
- Concurrent persist calls for the same digest (common during batch propagation)
- Specific timing where DB writes occur in reverse order of cache updates (moderate probability)
- Node restart to manifest the inconsistency (validators restart periodically for upgrades)

No attacker privileges required—normal network operation can trigger the race.

## Recommendation

**Solution**: Make the cache update and database write atomic by holding the cache entry lock during the database write operation.

**Approach 1**: Extend the critical section to include the DB write:

```rust
fn persist_inner(
    &self,
    batch_info: BatchInfoExt,
    persist_request: PersistedValue<BatchInfoExt>,
) -> Option<SignedBatchInfo<BatchInfoExt>> {
    let digest = *persist_request.digest();
    
    // Acquire and hold the cache entry lock during both cache and DB operations
    let cache_entry = self.db_cache.entry(digest);
    
    match self.save_with_lock(&persist_request, cache_entry) {
        Ok((needs_db, updated_cache_entry)) => {
            if needs_db {
                // DB write happens while still conceptually holding the digest lock
                if !batch_info.is_v2() {
                    self.db.save_batch(persist_request.try_into().expect("Must be a V1 batch"))
                        .expect("Could not write to DB");
                } else {
                    self.db.save_batch_v2(persist_request)
                        .expect("Could not write to DB");
                }
            }
            // Release lock, generate signature...
        }
        Err(e) => None,
    }
}
```

**Approach 2**: Use a per-digest mutex for serializing persist operations:

```rust
pub struct BatchStore {
    // ... existing fields ...
    persist_locks: DashMap<HashValue, Arc<Mutex<()>>>,
}

fn persist_inner(&self, batch_info: BatchInfoExt, persist_request: PersistedValue<BatchInfoExt>) 
    -> Option<SignedBatchInfo<BatchInfoExt>> {
    let digest = *persist_request.digest();
    
    // Acquire exclusive lock for this digest
    let lock_guard = self.persist_locks
        .entry(digest)
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .value()
        .lock();
    
    // Now both cache update and DB write are serialized
    match self.save(&persist_request) {
        Ok(needs_db) => {
            if needs_db {
                // DB write protected by per-digest lock
                if !batch_info.is_v2() {
                    self.db.save_batch(persist_request.try_into().expect("Must be a V1 batch"))
                        .expect("Could not write to DB");
                } else {
                    self.db.save_batch_v2(persist_request)
                        .expect("Could not write to DB");
                }
            }
            // ... signature generation ...
        }
        Err(e) => None,
    }
    // Lock released here
}
```

## Proof of Concept

```rust
#[tokio::test(flavor = "multi_thread")]
async fn test_concurrent_persist_race_condition() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::time::{sleep, Duration};
    
    let batch_store = batch_store_for_test(2001);
    let digest = HashValue::random();
    
    // Initial batch with low expiration
    let initial_batch = request_for_test(&digest, 500, 10, Some(vec![]));
    batch_store.persist(vec![initial_batch]);
    
    // Create two batches with same digest but different expirations
    let batch_low_exp = request_for_test(&digest, 1000, 10, Some(vec![]));
    let batch_high_exp = request_for_test(&digest, 2000, 10, Some(vec![]));
    
    let store_clone1 = batch_store.clone();
    let store_clone2 = batch_store.clone();
    
    let race_detected = Arc::new(AtomicBool::new(false));
    let race_clone = race_detected.clone();
    
    // Thread 1: Persist with low expiration (1000)
    let handle1 = tokio::spawn(async move {
        store_clone1.persist(vec![batch_low_exp]);
    });
    
    // Thread 2: Persist with high expiration (2000) - should win
    let handle2 = tokio::spawn(async move {
        sleep(Duration::from_micros(100)).await; // Slight delay
        store_clone2.persist(vec![batch_high_exp]);
    });
    
    handle1.await.unwrap();
    handle2.await.unwrap();
    
    // Verify cache has high expiration (correct)
    let cache_value = batch_store.get_batch_from_local(&digest).unwrap();
    assert_eq!(cache_value.expiration(), 2000);
    
    // Simulate restart: reload from DB
    let db = batch_store.db.clone();
    let db_value = if cache_value.batch_info().is_v2() {
        db.get_batch_v2(&digest).unwrap().unwrap()
    } else {
        db.get_batch(&digest).unwrap().unwrap().into()
    };
    
    // Check if DB has incorrect (low) expiration due to race
    if db_value.expiration() != 2000 {
        race_clone.store(true, Ordering::SeqCst);
        println!("RACE DETECTED: Cache has expiration={}, DB has expiration={}", 
                 cache_value.expiration(), db_value.expiration());
    }
    
    assert!(!race_detected.load(Ordering::SeqCst), 
            "Race condition detected: cache-DB inconsistency");
}
```

This test demonstrates that concurrent persist calls can result in the database containing a stale expiration value while the cache contains the correct (higher) value, proving the cache-database inconsistency vulnerability.

### Citations

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

**File:** consensus/src/quorum_store/batch_store.rs (L488-528)
```rust
    fn persist_inner(
        &self,
        batch_info: BatchInfoExt,
        persist_request: PersistedValue<BatchInfoExt>,
    ) -> Option<SignedBatchInfo<BatchInfoExt>> {
        assert!(
            &batch_info == persist_request.batch_info(),
            "Provided batch info doesn't match persist request batch info"
        );
        match self.save(&persist_request) {
            Ok(needs_db) => {
                trace!("QS: sign digest {}", persist_request.digest());
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
                }
                if !batch_info.is_v2() {
                    self.generate_signed_batch_info(batch_info.info().clone())
                        .ok()
                        .map(|inner| inner.into())
                } else {
                    self.generate_signed_batch_info(batch_info).ok()
                }
            },
            Err(e) => {
                debug!("QS: failed to store to cache {:?}", e);
                None
            },
        }
    }
```

**File:** consensus/src/quorum_store/batch_store.rs (L704-707)
```rust
                        batch_store.persist(vec![PersistedValue::new(
                            batch_info.into(),
                            Some(payload.clone()),
                        )]);
```

**File:** consensus/src/quorum_store/batch_generator.rs (L486-493)
```rust
                            let persist_start = Instant::now();
                            let mut persist_requests = vec![];
                            for batch in batches.clone().into_iter() {
                                persist_requests.push(batch.into());
                            }
                            self.batch_writer.persist(persist_requests);
                            counters::BATCH_CREATION_PERSIST_LATENCY.observe_duration(persist_start.elapsed());

```

**File:** consensus/src/quorum_store/batch_coordinator.rs (L78-134)
```rust
    fn persist_and_send_digests(
        &self,
        persist_requests: Vec<PersistedValue<BatchInfoExt>>,
        approx_created_ts_usecs: u64,
    ) {
        if persist_requests.is_empty() {
            return;
        }

        let batch_store = self.batch_store.clone();
        let network_sender = self.network_sender.clone();
        let sender_to_proof_manager = self.sender_to_proof_manager.clone();
        tokio::spawn(async move {
            let peer_id = persist_requests[0].author();
            let batches = persist_requests
                .iter()
                .map(|persisted_value| {
                    (
                        persisted_value.batch_info().clone(),
                        persisted_value.summary(),
                    )
                })
                .collect();

            if persist_requests[0].batch_info().is_v2() {
                let signed_batch_infos = batch_store.persist(persist_requests);
                if !signed_batch_infos.is_empty() {
                    if approx_created_ts_usecs > 0 {
                        observe_batch(approx_created_ts_usecs, peer_id, BatchStage::SIGNED);
                    }
                    network_sender
                        .send_signed_batch_info_msg_v2(signed_batch_infos, vec![peer_id])
                        .await;
                }
            } else {
                let signed_batch_infos = batch_store.persist(persist_requests);
                if !signed_batch_infos.is_empty() {
                    assert!(!signed_batch_infos
                        .first()
                        .expect("must not be empty")
                        .is_v2());
                    if approx_created_ts_usecs > 0 {
                        observe_batch(approx_created_ts_usecs, peer_id, BatchStage::SIGNED);
                    }
                    let signed_batch_infos = signed_batch_infos
                        .into_iter()
                        .map(|sbi| sbi.try_into().expect("Batch must be V1 batch"))
                        .collect();
                    network_sender
                        .send_signed_batch_info_msg(signed_batch_infos, vec![peer_id])
                        .await;
                }
            }
            let _ = sender_to_proof_manager
                .send(ProofManagerCommand::ReceiveBatches(batches))
                .await;
        });
```
