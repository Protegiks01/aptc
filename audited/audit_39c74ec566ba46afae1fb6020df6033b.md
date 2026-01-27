# Audit Report

## Title
Shard-Indexer State Inconsistency Detection Bypass in verify_state_kvs()

## Summary
The `verify_state_kvs()` validation function in `storage/aptosdb/src/db_debugger/validation.rs` has two critical flaws: (1) it performs only unidirectional consistency checking (shard → indexer, not indexer → shard), and (2) it returns success even when inconsistencies are detected. This allows state keys to exist in shards without corresponding internal indexer entries (and vice versa) without triggering validation errors, leading to incomplete API query results and undetectable state inconsistencies.

## Finding Description

The internal indexer (`StateKeysSchema`) is populated only for state key creations and modifications, not deletions. [1](#0-0) 

Meanwhile, state shards store all write operations including deletions as tombstones (None values). [2](#0-1) 

The `verify_state_kvs()` function loads all keys from the internal indexer into memory and then validates each shard. [3](#0-2) 

However, the validation only checks in ONE direction - it verifies that keys present in shards exist in the internal indexer. [4](#0-3) 

**Critical Flaw #1: Unidirectional Validation**
The function never checks whether all keys in the internal indexer actually exist in any shard. If a key exists in `StateKeysSchema` but was never written to (or was removed from) the shards due to database corruption, crashes, or race conditions, this inconsistency remains completely undetected.

**Critical Flaw #2: Silent Failure on Detected Inconsistencies**
Even when the function detects keys in shards that are missing from the internal indexer, it only prints a message and increments a counter - it still returns `Ok(())`. [5](#0-4) 

**Exploitation Path:**
The API uses `PrefixedStateValueIterator` which relies on the internal indexer to enumerate state keys. [6](#0-5) 

When inconsistencies exist:
- **Keys in indexer but not in shards**: The iterator finds the key in `StateKeysSchema`, but `get_state_value_by_version()` returns None, causing the key to be silently skipped. Users receive incomplete query results.
- **Keys in shards but not in indexer**: The iterator never sees these keys at all. Users miss valid state data entirely.

Both scenarios violate the **State Consistency** invariant (#4) and can occur through:
1. Database corruption affecting one database but not the other
2. System crashes between writing to shards and indexer (no atomic transaction)
3. Race conditions in the sharded write path
4. Bugs in the indexing logic

## Impact Explanation

This is **High Severity** under the Aptos bug bounty criteria for the following reasons:

1. **Significant Protocol Violation**: The validation function is designed to ensure state consistency between sharded storage and the internal indexer. Its failure to properly detect and report inconsistencies means operators cannot trust their database integrity checks.

2. **API Data Integrity**: The internal indexer is critical for prefix-based state queries used by the API layer. [7](#0-6)  Undetected inconsistencies lead to:
   - Missing state keys in API responses
   - Silent data omission without error indication
   - Potential application-level failures due to incomplete data

3. **Operational Blindness**: Operators running validation checks receive false confirmation of database consistency (returns `Ok()` even with inconsistencies), preventing them from detecting and addressing real storage corruption.

4. **Persistence**: Once inconsistencies occur, they persist indefinitely since the validation tool provides false assurance of correctness.

## Likelihood Explanation

**Likelihood: Medium to High**

The vulnerability is inherent in the validation function's design and will activate whenever:

1. **Database divergence occurs** through:
   - Hardware failures causing partial writes
   - Process crashes between shard and indexer updates
   - Filesystem or RocksDB corruption affecting one DB but not the other

2. **Operator validation runs** to check database integrity - they receive misleading results

3. **API queries execute** against inconsistent state - they return incomplete results

The lack of atomic transactions between the sharded state DB and the internal indexer DB makes divergence scenarios realistic in production environments, especially during:
- High-volume transaction processing
- Database restarts or failovers
- Storage subsystem errors
- State synchronization operations

## Recommendation

**Fix 1: Implement Bidirectional Validation**

Modify `verify_state_kvs()` to check both directions: [8](#0-7) 

Add reverse validation after line 144:
```rust
// Check for keys in internal indexer that are missing from all shards
let mut orphaned_keys = 0;
for state_key_hash in &all_internal_keys {
    let mut found_in_any_shard = false;
    for shard_id in 0..16 {
        let shard = state_kv_db.db_shard(shard_id);
        let mut iter = shard.iter::<StateValueByKeyHashSchema>()?;
        iter.seek(&(*state_key_hash, target_ledger_version))?;
        if let Some(((hash, version), _)) = iter.next().transpose()? {
            if hash == *state_key_hash && version <= target_ledger_version {
                found_in_any_shard = true;
                break;
            }
        }
    }
    if !found_in_any_shard {
        orphaned_keys += 1;
        println!("State key in indexer not found in any shard: {:?}", state_key_hash);
    }
}
if orphaned_keys > 0 {
    return Err(AptosDbError::Other(format!(
        "Found {} keys in internal indexer missing from shards", orphaned_keys
    )));
}
```

**Fix 2: Return Error on Inconsistencies** [9](#0-8) 

Change the return to fail when inconsistencies are detected:
```rust
if missing_keys > 0 {
    return Err(AptosDbError::Other(format!(
        "Found {} keys in shard missing from internal indexer", missing_keys
    )));
}
Ok(())
```

**Fix 3: Add Atomic Write Guarantees**

Implement a two-phase commit or write-ahead log to ensure atomic updates across both databases, preventing inconsistencies from occurring in the first place.

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use aptos_temppath::TempPath;
    use aptos_types::state_store::state_key::StateKey;
    use aptos_crypto::HashValue;
    
    #[test]
    fn test_undetected_indexer_orphan() {
        // Setup: Create state DB and internal indexer
        let db_path = TempPath::new();
        let indexer_path = TempPath::new();
        
        // Simulate inconsistency: Add key to internal indexer but not to shards
        let internal_db = open_internal_indexer_db(
            indexer_path.path(), 
            &RocksdbConfig::default()
        ).unwrap();
        
        let orphan_key = StateKey::raw(b"orphan_key");
        let mut batch = SchemaBatch::new();
        batch.put::<StateKeysSchema>(&orphan_key, &()).unwrap();
        internal_db.write_schemas(batch).unwrap();
        
        // Run validation - should detect but currently doesn't
        let result = verify_state_kvs(
            db_path.path(),
            &internal_db,
            1000
        );
        
        // BUG: Returns Ok() even though key in indexer doesn't exist in shards
        assert!(result.is_ok()); // This should fail but doesn't
        
        // The orphaned key will cause API queries to skip it silently
        // when get_state_value_by_version returns None
    }
    
    #[test]
    fn test_detected_but_not_errored_shard_orphan() {
        // Setup databases
        let db_path = TempPath::new();
        let indexer_path = TempPath::new();
        
        let storage_dir = StorageDirPaths::from_path(db_path.path());
        let state_kv_db = StateKvDb::open_sharded(
            &storage_dir,
            RocksdbConfig::default(),
            None, None, false
        ).unwrap();
        
        // Add key to shard but not to internal indexer
        let orphan_key = StateKey::raw(b"shard_orphan");
        let shard = state_kv_db.db_shard(orphan_key.get_shard_id());
        let mut batch = shard.new_native_batch();
        batch.put::<StateValueByKeyHashSchema>(
            &(orphan_key.hash(), 100),
            &Some(StateValue::from(b"value".to_vec()))
        ).unwrap();
        shard.write_schemas(batch).unwrap();
        
        let internal_db = open_internal_indexer_db(
            indexer_path.path(),
            &RocksdbConfig::default()
        ).unwrap();
        
        // Run validation
        let result = verify_state_kvs(
            db_path.path(),
            &internal_db,
            1000
        );
        
        // BUG: Returns Ok() and only prints, doesn't error
        assert!(result.is_ok()); // Should fail but doesn't
        // Console shows "State key hash not found in internal db" but validation passes
    }
}
```

## Notes

The validation function's dual flaws create a comprehensive blind spot in Aptos database integrity checking. The unidirectional validation combined with silent success on detected inconsistencies means that state divergence between shards and the internal indexer can occur and persist without operator awareness. This particularly affects API correctness via `PrefixedStateValueIterator`, which depends on the internal indexer for state key enumeration but fetches values from shards, causing incomplete results when inconsistencies exist.

The root cause extends beyond the validation function to the lack of atomic transaction guarantees between the independent shard and indexer databases, making inconsistencies possible during crashes, corruption, or race conditions in the write path.

### Citations

**File:** storage/indexer/src/db_indexer.rs (L489-496)
```rust
            if self.indexer_db.statekeys_enabled() {
                writeset.write_op_iter().for_each(|(state_key, write_op)| {
                    if write_op.is_creation() || write_op.is_modification() {
                        batch
                            .put::<StateKeysSchema>(state_key, &())
                            .expect("Failed to put state keys to a batch");
                    }
                });
```

**File:** storage/aptosdb/src/state_store/mod.rs (L830-840)
```rust
                        if self.state_kv_db.enabled_sharding() {
                            batch.put::<StateValueByKeyHashSchema>(
                                &(CryptoHash::hash(*key), version),
                                &write_op.as_state_value_opt().cloned(),
                            )
                        } else {
                            batch.put::<StateValueSchema>(
                                &((*key).clone(), version),
                                &write_op.as_state_value_opt().cloned(),
                            )
                        }
```

**File:** storage/aptosdb/src/db_debugger/validation.rs (L114-146)
```rust
pub fn verify_state_kvs(
    db_root_path: &Path,
    internal_db: &DB,
    target_ledger_version: u64,
) -> Result<()> {
    println!("Validating db statekeys");
    let storage_dir = StorageDirPaths::from_path(db_root_path);
    let state_kv_db =
        StateKvDb::open_sharded(&storage_dir, RocksdbConfig::default(), None, None, false)?;

    //read all statekeys from internal db and store them in mem
    let mut all_internal_keys = HashSet::new();
    let mut iter = internal_db.iter::<StateKeysSchema>()?;
    iter.seek_to_first();
    for (key_ind, state_key_res) in iter.enumerate() {
        let state_key = state_key_res?.0;
        let state_key_hash = state_key.hash();
        all_internal_keys.insert(state_key_hash);
        if key_ind % 10_000_000 == 0 {
            println!("Processed {} keys", key_ind);
        }
    }
    println!(
        "Number of state keys in internal db: {}",
        all_internal_keys.len()
    );
    for shard_id in 0..16 {
        let shard = state_kv_db.db_shard(shard_id);
        println!("Validating state_kv for shard {}", shard_id);
        verify_state_kv(shard, &all_internal_keys, target_ledger_version)?;
    }
    Ok(())
}
```

**File:** storage/aptosdb/src/db_debugger/validation.rs (L157-191)
```rust
fn verify_state_kv(
    shard: &DB,
    all_internal_keys: &HashSet<HashValue>,
    target_ledger_version: u64,
) -> Result<()> {
    let read_opts = ReadOptions::default();
    let mut iter = shard.iter_with_opts::<StateValueByKeyHashSchema>(read_opts)?;
    // print a message every 10k keys
    let mut counter = 0;
    iter.seek_to_first();
    let mut missing_keys = 0;
    for value in iter {
        let (state_key_hash, version) = value?.0;
        if version > target_ledger_version {
            continue;
        }
        // check if the state key hash is present in the internal db
        if !all_internal_keys.contains(&state_key_hash) {
            missing_keys += 1;
            println!(
                "State key hash not found in internal db: {:?}, version: {}",
                state_key_hash, version
            );
        }
        counter += 1;
        if counter as usize % SAMPLE_RATE == 0 {
            println!(
                "Processed {} keys, the current sample is {} at version {}",
                counter, state_key_hash, version
            );
        }
    }
    println!("Number of missing keys: {}", missing_keys);
    Ok(())
}
```

**File:** storage/indexer/src/utils.rs (L34-74)
```rust
        let mut state_keys_iter = indexer_db.iter_with_opts::<StateKeysSchema>(read_opt)?;
        if let Some(first_key) = first_key {
            state_keys_iter.seek(&first_key)?;
        } else {
            state_keys_iter.seek(&&key_prefix)?;
        };
        Ok(Self {
            state_keys_iter,
            main_db: main_db_reader,
            key_prefix,
            desired_version,
            is_finished: false,
        })
    }

    pub fn next_impl(&mut self) -> anyhow::Result<Option<(StateKey, StateValue)>> {
        let iter = &mut self.state_keys_iter;
        if self.is_finished {
            return Ok(None);
        }
        while let Some((state_key, _)) = iter.next().transpose()? {
            if !self.key_prefix.is_prefix(&state_key)? {
                self.is_finished = true;
                return Ok(None);
            }

            match self
                .main_db
                .get_state_value_by_version(&state_key, self.desired_version)?
            {
                Some(state_value) => {
                    return Ok(Some((state_key, state_value)));
                },
                None => {
                    // state key doesn't have value before the desired version, continue to next state key
                    continue;
                },
            }
        }
        Ok(None)
    }
```

**File:** api/src/context.rs (L446-457)
```rust
                    .get_prefixed_state_value_iterator(
                        &StateKeyPrefix::from(address),
                        None,
                        version,
                    )?
                    .map(|item| item.map_err(|err| anyhow!(err.to_string()))),
            )
        } else {
            self.indexer_reader
                .as_ref()
                .ok_or_else(|| format_err!("Indexer reader doesn't exist"))?
                .get_prefixed_state_value_iterator(&StateKeyPrefix::from(address), None, version)?
```
