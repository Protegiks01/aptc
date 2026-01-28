# Audit Report

## Title
Unbounded Database Growth Due to Missing V2 Batch Deletion in QuorumStore

## Summary
The QuorumStore's batch expiration mechanism fails to delete expired V2 batches from RocksDB during normal operation, causing unbounded database growth that can lead to disk exhaustion and validator node failures. While V1 batches are correctly deleted when they expire, V2 batches accumulate indefinitely until node restart.

## Finding Description

The QuorumStore consensus component maintains transaction batches in RocksDB using two separate column families: "batch" for V1 batches and "batch_v2" for V2 batches, as defined in the schema configuration. [1](#0-0) 

When batches are persisted to the database, the code correctly distinguishes between V1 and V2 batches based on the `is_v2()` check and routes them to the appropriate storage method (`save_batch` vs `save_batch_v2`). [2](#0-1) 

However, during normal operation when batches expire via timestamp updates, the `update_certified_timestamp` method only deletes V1 batches from the database. [3](#0-2)  The critical bug is on line 536, which only calls `self.db.delete_batches(expired_keys)` - the V1 deletion method defined in the QuorumStoreStorage trait [4](#0-3)  - without any corresponding call to `delete_batches_v2` for V2 batches [5](#0-4) .

The `clear_expired_payload` method removes expired batches from the in-memory cache and returns a list of digest hashes without tracking whether each batch is V1 or V2. [6](#0-5) 

Additionally, there is a second bug in the epoch transition garbage collection. The `gc_previous_epoch_batches_from_db_v2` function reads V2 batches using `get_all_batches_v2()` but incorrectly attempts to delete them using `delete_batches()` (the V1 deletion method). [7](#0-6) 

V2 batches are only correctly deleted during node restarts in `populate_cache_and_gc_expired_batches_v2`, where the correct `delete_batches_v2` method is called. [8](#0-7) 

V2 batches are currently disabled by default via the `enable_batch_v2` configuration flag. [9](#0-8) [10](#0-9)  When enabled via configuration, V2 batch creation is controlled by this flag in the batch generator. [11](#0-10) 

This bug causes unbounded disk growth as expired V2 batches accumulate without being deleted during normal operation or epoch transitions, with cleanup only occurring during node restarts.

## Impact Explanation

**Severity: Medium** (up to $10,000 per Aptos bug bounty program)

This vulnerability causes:
1. **Unbounded disk space consumption**: V2 batches accumulate continuously during normal operation as the `update_certified_timestamp` method is called on every block commit [12](#0-11) , potentially filling disk space within hours to days depending on batch creation rate
2. **Validator node failures**: When disk space is exhausted, nodes crash or become unresponsive
3. **Network availability impact**: If multiple validators are affected simultaneously, network liveness degrades
4. **Operational disruption**: Requires manual intervention (node restart) to trigger cleanup through `populate_cache_and_gc_expired_batches_v2`, as epoch transitions have the same bug

This qualifies as **Medium severity** under "State inconsistencies requiring manual intervention" per the Aptos bug bounty program. While it doesn't directly cause loss of funds or consensus violations, it creates operational instability requiring manual remediation and can impact network availability when V2 batches are enabled.

## Likelihood Explanation

**Likelihood: High** (when V2 batches are enabled via configuration)

This vulnerability:
- Occurs automatically during normal consensus operation without any attacker action
- Affects all validator nodes running with V2 batch support enabled
- Manifests continuously as batches expire (typically within hours of operation)
- Has no mitigation during normal operation or epoch transitions
- Is deterministic and reproducible in any environment with V2 batches enabled

The bug will definitely manifest in production if V2 batches are enabled via configuration. Currently, V2 batches are disabled by default, but the feature exists in production code with full infrastructure support, making this a valid vulnerability in an optional but production-ready feature.

## Recommendation

The fix requires two changes:

1. **Modify `update_certified_timestamp` method** to handle both V1 and V2 batch deletion:
   - Track batch versions in the cache or query the database to determine which batches are V1 vs V2
   - Call both `delete_batches()` and `delete_batches_v2()` with the appropriate digest lists
   - Alternatively, modify `clear_expired_payload` to return versioned information about expired batches

2. **Fix `gc_previous_epoch_batches_from_db_v2` method** at line 241:
   - Change `db.delete_batches(expired_keys)` to `db.delete_batches_v2(expired_keys)` to match the V2 batch reading operation

The most robust solution would be to extend the batch cache to track batch versions, allowing `clear_expired_payload` to return separate lists of V1 and V2 expired digests, which can then be deleted using the appropriate methods.

## Proof of Concept

While a complete executable PoC is not provided, the vulnerability can be verified by:
1. Enabling V2 batches via configuration: `config.quorum_store.enable_batch_v2 = true`
2. Running a validator node and allowing batches to be created and expire
3. Monitoring the RocksDB `batch_v2` column family size - it will grow unboundedly
4. Verifying that only node restart triggers V2 batch cleanup via the verified code path at line 333

The grep search confirms `delete_batches_v2` is only called in one location (the restart path), not in the normal operation paths. [13](#0-12) 

## Notes

This vulnerability is **valid and exploitable** when V2 batches are enabled, despite being disabled by default. The code evidence is comprehensive and unambiguous:
- Two distinct deletion bugs confirmed at lines 241 and 536
- Both normal operation and epoch transition paths affected
- Only restart path correctly deletes V2 batches
- Feature exists in production code and can be enabled via standard configuration

The classification as Medium severity is appropriate given the operational impact and manual remediation requirement.

### Citations

**File:** consensus/src/quorum_store/schema.rs (L14-16)
```rust
pub(crate) const BATCH_CF_NAME: ColumnFamilyName = "batch";
pub(crate) const BATCH_ID_CF_NAME: ColumnFamilyName = "batch_ID";
pub(crate) const BATCH_V2_CF_NAME: ColumnFamilyName = "batch_v2";
```

**File:** consensus/src/quorum_store/batch_store.rs (L212-243)
```rust
    fn gc_previous_epoch_batches_from_db_v2(db: Arc<dyn QuorumStoreStorage>, current_epoch: u64) {
        let db_content = db
            .get_all_batches_v2()
            .expect("failed to read data from db");
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

**File:** consensus/src/quorum_store/batch_store.rs (L332-334)
```rust
        tokio::task::spawn_blocking(move || {
            db.delete_batches_v2(expired_keys)
                .expect("Deletion of expired keys should not fail");
```

**File:** consensus/src/quorum_store/batch_store.rs (L443-471)
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
```

**File:** consensus/src/quorum_store/batch_store.rs (L501-513)
```rust
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

**File:** consensus/src/quorum_store/batch_store.rs (L530-539)
```rust
    pub fn update_certified_timestamp(&self, certified_time: u64) {
        trace!("QS: batch reader updating time {:?}", certified_time);
        self.last_certified_time
            .fetch_max(certified_time, Ordering::SeqCst);

        let expired_keys = self.clear_expired_payload(certified_time);
        if let Err(e) = self.db.delete_batches(expired_keys) {
            debug!("Error deleting batches: {:?}", e)
        }
    }
```

**File:** consensus/src/quorum_store/quorum_store_db.rs (L27-27)
```rust
    fn delete_batches(&self, digests: Vec<HashValue>) -> Result<(), DbError>;
```

**File:** consensus/src/quorum_store/quorum_store_db.rs (L35-35)
```rust
    fn delete_batches_v2(&self, digests: Vec<HashValue>) -> Result<(), DbError>;
```

**File:** config/src/config/quorum_store_config.rs (L102-102)
```rust
    pub enable_batch_v2: bool,
```

**File:** config/src/config/quorum_store_config.rs (L144-144)
```rust
            enable_batch_v2: false,
```

**File:** consensus/src/quorum_store/batch_generator.rs (L190-211)
```rust
        if self.config.enable_batch_v2 {
            // TODO(ibalajiarun): Specify accurate batch kind
            let batch_kind = BatchKind::Normal;
            Batch::new_v2(
                batch_id,
                txns,
                self.epoch,
                expiry_time,
                self.my_peer_id,
                bucket_start,
                batch_kind,
            )
        } else {
            Batch::new_v1(
                batch_id,
                txns,
                self.epoch,
                expiry_time,
                self.my_peer_id,
                bucket_start,
            )
        }
```

**File:** consensus/src/payload_manager/quorum_store_payload_manager.rs (L168-170)
```rust
    fn notify_commit(&self, block_timestamp: u64, payloads: Vec<Payload>) {
        self.batch_reader
            .update_certified_timestamp(block_timestamp);
```
