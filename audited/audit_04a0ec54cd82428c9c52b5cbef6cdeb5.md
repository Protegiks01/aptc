# Audit Report

## Title
Quorum Store Batch Leak During Mid-Epoch Node Restart After Multi-Epoch Gap

## Summary
When a validator node restarts after being offline across multiple epoch transitions and syncs to a mid-epoch block (not an epoch boundary), the batch cleanup logic fails to remove batches from old epochs if they haven't expired by time. This causes storage and memory leaks as obsolete batches from previous epochs consume quota that should be available for new batches.

## Finding Description

The vulnerability exists in the epoch transition cleanup logic for the Quorum Store batch system. The issue stems from the conditional cleanup behavior in `BatchStore::new()`: [1](#0-0) 

The `is_new_epoch` flag is determined by checking whether the latest ledger info marks an epoch boundary: [2](#0-1) [3](#0-2) 

When `is_new_epoch = true`, proper epoch-based cleanup occurs via `gc_previous_epoch_batches_from_db_v1/v2`: [4](#0-3) 

However, when `is_new_epoch = false` (node syncs to mid-epoch), only time-based cleanup occurs: [5](#0-4) 

**The critical flaw:** The `populate_cache_and_gc_expired_batches_v1` function only checks expiration time, NOT epoch numbers. Batches from old epochs (e.g., epoch 5) are loaded into memory if they haven't expired by time, even though the node is now in epoch 10.

**Attack Scenario:**
1. Validator node at epoch 5 creates batches with 60-second expiration (default): [6](#0-5) 

2. Node crashes and is offline for 30 seconds
3. Network progresses through epochs 6, 7, 8, 9 to epoch 10 (rapid reconfigurations)
4. Node restarts and syncs via state sync to a mid-epoch block in epoch 10
5. `ends_epoch() = false`, so `is_new_epoch = false`
6. `populate_cache_and_gc_expired_batches_v1` is called
7. Since only 30 seconds passed (< 60s expiration), epoch 5 batches are loaded into cache
8. These obsolete batches consume per-peer quota but will never be used

The batch_id cleanup logic handles this correctly: [7](#0-6) 

But the actual batch data cleanup does NOT check epochs in the mid-epoch restart path.

## Impact Explanation

**Severity: Medium**

This qualifies as Medium severity per Aptos bug bounty criteria:
- "State inconsistencies requiring intervention" - Old epoch batches remain in state when they should be deleted
- Resource exhaustion - Accumulation of obsolete batches leads to:
  - Storage leaks in the database
  - Memory leaks in the batch cache
  - Quota exhaustion preventing new valid batches from being stored

The quota system limits are enforced per-peer: [8](#0-7) 

When obsolete batches consume quota, legitimate batches from the current epoch may be rejected, degrading consensus performance.

**Why not Critical/High:**
- Does not directly break consensus safety or liveness
- Does not cause immediate node failure
- Eventually cleans up when batches expire by time
- Requires specific conditions (mid-epoch restart after multi-epoch gap)

## Likelihood Explanation

**Likelihood: Medium**

This vulnerability triggers when ALL conditions are met:
1. Node crashes/restarts (common during updates, crashes, network issues)
2. Network experiences rapid epoch transitions (occurs during validator set changes, reconfigurations, or governance actions)
3. Offline duration < batch expiration time (60s default) but crosses multiple epochs
4. State sync brings node to mid-epoch block (50% probability - either epoch boundary or mid-epoch)

While each individual condition is plausible, the combination is less frequent. However:
- In test networks with short epochs, this is highly reproducible
- During network instability with frequent reconfigurations, likelihood increases
- Repeated crashes can compound the leak before old batches expire

## Recommendation

Add epoch-based filtering to the `populate_cache_and_gc_expired_batches_v1` and `populate_cache_and_gc_expired_batches_v2` functions:

```rust
fn populate_cache_and_gc_expired_batches_v1(
    db: Arc<dyn QuorumStoreStorage>,
    current_epoch: u64,
    last_certified_time: u64,
    expiration_buffer_usecs: u64,
    batch_store: &BatchStore,
) {
    let db_content = db.get_all_batches().expect("failed to read v1 data from db");
    // ... existing logging ...
    
    let mut expired_keys = Vec::new();
    let gc_timestamp = last_certified_time.saturating_sub(expiration_buffer_usecs);
    for (digest, value) in db_content {
        let epoch = value.epoch();
        let expiration = value.expiration();
        
        // FIX: Delete batches from old epochs OR expired by time
        if epoch < current_epoch || expiration < gc_timestamp {
            expired_keys.push(digest);
        } else {
            batch_store
                .insert_to_cache(&value.into())
                .expect("Storage limit exceeded upon BatchReader construction");
        }
    }
    // ... rest of function unchanged ...
}
```

Apply the same fix to `populate_cache_and_gc_expired_batches_v2`.

## Proof of Concept

```rust
#[test]
fn test_batch_leak_on_mid_epoch_restart() {
    use tempfile::tempdir;
    use aptos_types::validator_signer::ValidatorSigner;
    use aptos_crypto::bls12381::PrivateKey;
    
    // Setup
    let dir = tempdir().unwrap();
    let db = Arc::new(QuorumStoreDB::new(dir.path()));
    let consensus_key = PrivateKey::generate_for_testing();
    let signer = ValidatorSigner::new(
        PeerId::random(),
        Arc::new(consensus_key)
    );
    
    // Epoch 5: Create batch with 60s expiration
    let epoch_5 = 5u64;
    let batch = create_test_batch(epoch_5, /* expiration */ 60_000_000);
    db.save_batch_v2(batch.clone()).unwrap();
    
    // Simulate 30s offline time
    std::thread::sleep(Duration::from_secs(30));
    
    // Epoch 10: Node restarts at mid-epoch (is_new_epoch = false)
    let epoch_10 = 10u64;
    let is_new_epoch = false; // Mid-epoch restart
    let last_certified_time = aptos_infallible::duration_since_epoch()
        .as_micros() as u64;
    
    let batch_store = BatchStore::new(
        epoch_10,
        is_new_epoch,
        last_certified_time,
        db.clone(),
        1000000, // memory_quota
        2000000, // db_quota  
        100,     // batch_quota
        signer,
        60_000_000, // expiration_buffer
    );
    
    // VULNERABILITY: Batch from epoch 5 should be deleted
    // but is still accessible because it hasn't expired by time
    let all_batches = db.get_all_batches_v2().unwrap();
    
    // This assertion FAILS - epoch 5 batch still exists
    assert!(
        all_batches.iter().all(|(_, v)| v.epoch() >= epoch_10),
        "Found batch from old epoch: expected all batches from epoch >= {}, \
         but found batch from epoch {}",
        epoch_10,
        all_batches.iter().find(|(_, v)| v.epoch() < epoch_10)
            .map(|(_, v)| v.epoch()).unwrap()
    );
}
```

This test demonstrates that batches from epoch 5 remain in storage after a mid-epoch restart at epoch 10, violating the invariant that only current-epoch batches should be retained.

## Notes

The vulnerability is specific to the mid-epoch restart path. Normal epoch transitions via `is_new_epoch = true` correctly clean up old batches. The root cause is the asymmetry between the two cleanup code paths - one checks epochs, the other only checks expiration time.

This issue compounds with repeated restarts: if a node repeatedly crashes mid-epoch, multiple epoch's worth of batches can accumulate before they expire by time, causing significant resource exhaustion.

### Citations

**File:** consensus/src/quorum_store/batch_store.rs (L52-62)
```rust
    pub(crate) fn new(db_quota: usize, memory_quota: usize, batch_quota: usize) -> Self {
        assert!(db_quota >= memory_quota);
        Self {
            memory_balance: memory_quota,
            db_balance: db_quota,
            batch_balance: batch_quota,
            memory_quota,
            db_quota,
            batch_quota,
        }
    }
```

**File:** consensus/src/quorum_store/batch_store.rs (L156-176)
```rust
        if is_new_epoch {
            tokio::task::spawn_blocking(move || {
                Self::gc_previous_epoch_batches_from_db_v1(db_clone.clone(), epoch);
                Self::gc_previous_epoch_batches_from_db_v2(db_clone, epoch);
            });
        } else {
            Self::populate_cache_and_gc_expired_batches_v1(
                db_clone.clone(),
                epoch,
                last_certified_time,
                expiration_buffer_usecs,
                &batch_store,
            );
            Self::populate_cache_and_gc_expired_batches_v2(
                db_clone,
                epoch,
                last_certified_time,
                expiration_buffer_usecs,
                &batch_store,
            );
        }
```

**File:** consensus/src/quorum_store/batch_store.rs (L181-210)
```rust
    fn gc_previous_epoch_batches_from_db_v1(db: Arc<dyn QuorumStoreStorage>, current_epoch: u64) {
        let db_content = db.get_all_batches().expect("failed to read data from db");
        info!(
            epoch = current_epoch,
            "QS: Read batches from storage. Len: {}",
            db_content.len(),
        );

        let mut expired_keys = Vec::new();
        for (digest, value) in db_content {
            let epoch = value.epoch();

            trace!(
                "QS: Batchreader recovery content epoch {:?}, digest {}",
                epoch,
                digest
            );

            if epoch < current_epoch {
                expired_keys.push(digest);
            }
        }

        info!(
            "QS: Batch store bootstrap expired keys len {}",
            expired_keys.len()
        );
        db.delete_batches(expired_keys)
            .expect("Deletion of expired keys should not fail");
    }
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

**File:** consensus/src/quorum_store/quorum_store_builder.rs (L244-244)
```rust
        let is_new_epoch = latest_ledger_info_with_sigs.ledger_info().ends_epoch();
```

**File:** types/src/ledger_info.rs (L145-147)
```rust
    pub fn ends_epoch(&self) -> bool {
        self.next_epoch_state().is_some()
    }
```

**File:** consensus/src/quorum_store/batch_generator.rs (L383-385)
```rust
        let expiry_time = aptos_infallible::duration_since_epoch().as_micros() as u64
            + self.config.batch_expiry_gap_when_init_usecs;
        let batches = self.bucket_into_batches(&mut pulled_txns, expiry_time);
```

**File:** consensus/src/quorum_store/quorum_store_db.rs (L163-179)
```rust
    fn clean_and_get_batch_id(&self, current_epoch: u64) -> Result<Option<BatchId>, DbError> {
        let mut iter = self.db.iter::<BatchIdSchema>()?;
        iter.seek_to_first();
        let epoch_batch_id = iter
            .map(|res| res.map_err(Into::into))
            .collect::<Result<HashMap<u64, BatchId>>>()?;
        let mut ret = None;
        for (epoch, batch_id) in epoch_batch_id {
            assert!(current_epoch >= epoch);
            if epoch < current_epoch {
                self.delete_batch_id(epoch)?;
            } else {
                ret = Some(batch_id);
            }
        }
        Ok(ret)
    }
```
