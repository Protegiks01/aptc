# Audit Report

## Title
Shard-Indexer Consistency Validation Silently Fails to Detect Inconsistencies

## Summary
The `verify_state_kvs()` validation function in the database debugger tool fails to properly detect and report shard-indexer inconsistencies. When state keys exist in shards but are missing from the internal indexer, the function only prints warnings but returns success (Ok()). Additionally, it never checks the reverse direction (keys in indexer but missing from shards), allowing critical state inconsistencies to go completely undetected.

## Finding Description

The `verify_state_kvs()` function is designed to validate consistency between the sharded state key-value database and the internal indexer. However, it contains two critical flaws:

**Flaw 1: Missing Keys Only Logged, Never Reported as Errors** [1](#0-0) 

The `verify_state_kv()` function iterates through state keys in each shard and checks if they exist in the internal indexer. When keys are missing from the indexer (line 174), it only prints them (lines 176-179) and increments a counter (line 175). Critically, line 190 returns `Ok(())` unconditionally, regardless of how many keys are missing. This means validation always succeeds even when inconsistencies are detected.

**Flaw 2: One-Directional Validation Only** [2](#0-1) 

The validation only checks if shard keys exist in the indexer (shard → indexer). It never verifies that keys in the indexer actually exist in the shards (indexer → shard). This means phantom keys in the indexer are never detected.

**Root Cause: Deletions Never Indexed** [3](#0-2) 

State keys are only written to the internal indexer on creation or modification, never on deletion. Deleted keys remain in the indexer forever, creating permanent inconsistency.

**Impact: API Returns Incomplete State** [4](#0-3) 

The `PrefixedStateValueIterator` used by API queries relies on the internal indexer to enumerate state keys. When keys exist in shards but not in the indexer, they are invisible to API queries (line 54 only iterates indexer keys). This breaks state enumeration APIs, returning incomplete data to users. [5](#0-4) 

All write operations including deletions are written to shards (line 833: `write_op.as_state_value_opt().cloned()` returns None for deletions), but deletions are never reflected in the indexer, causing guaranteed inconsistency.

## Impact Explanation

This qualifies as **High Severity** under "Significant protocol violations" because:

1. **State Consistency Invariant Broken**: The validation function fails its primary purpose - detecting state inconsistencies. This violates the fundamental invariant that "State transitions must be atomic and verifiable."

2. **API Data Integrity Compromise**: When sharded storage is enabled, API queries using `PrefixedStateValueIterator` return incomplete state. Applications and users receive partial data without any error indication, potentially leading to incorrect decisions.

3. **Cross-Node Inconsistency Risk**: Different nodes could have different indexer states (due to configuration issues, crashes during indexing, or bugs). Since validation passes despite inconsistencies, nodes could serve different API responses for the same queries.

4. **Operational Blindness**: Operators running the validation tool (`aptos-debugger aptos-db debug indexer-validation validate-indexer-db`) receive false confidence that their databases are consistent when they are not. [6](#0-5) 

## Likelihood Explanation

**High Likelihood** of occurrence:

1. **Configuration Changes**: If `statekeys_enabled()` is toggled or misconfigured during node operation, keys written during disabled periods are never indexed.

2. **Operational Issues**: Database crashes, partial writes, or indexer failures during normal operation create inconsistencies.

3. **Deletion Pattern**: ANY state key deletion creates permanent inconsistency since deletions are never indexed but remain in shards.

4. **Production Usage**: The internal indexer is actively used in production for API queries when storage sharding is enabled, making this a real operational concern.

## Recommendation

**Fix 1: Return Error on Inconsistencies**

Modify `verify_state_kv()` to return an error when missing keys are detected:

```rust
pub fn verify_state_kv(
    shard: &DB,
    all_internal_keys: &HashSet<HashValue>,
    target_ledger_version: u64,
) -> Result<()> {
    // ... existing iteration code ...
    
    if missing_keys > 0 {
        bail!("Found {} state keys in shard but missing from internal indexer", missing_keys);
    }
    Ok(())
}
```

**Fix 2: Add Reverse Direction Check**

Add validation that all indexer keys exist in shards:

```rust
// After checking shard → indexer, check indexer → shards
let mut keys_in_indexer_not_in_shards = 0;
for key_hash in all_internal_keys.iter() {
    // Check if key exists in any shard at any version <= target
    let exists = check_key_in_shards(state_kv_db, key_hash, target_ledger_version)?;
    if !exists {
        keys_in_indexer_not_in_shards += 1;
        println!("State key in indexer but missing from shards: {:?}", key_hash);
    }
}
if keys_in_indexer_not_in_shards > 0 {
    bail!("Found {} state keys in indexer but missing from shards", keys_in_indexer_not_in_shards);
}
```

**Fix 3: Handle Deletions in Indexer**

Either remove deleted keys from the indexer, or modify validation to account for keys that have been deleted in shards.

## Proof of Concept

```bash
# Setup: Create a node with sharded storage and internal indexer
# 1. Start node with indexer disabled
./aptos-node --config config_no_indexer.yaml

# 2. Submit transactions that create state keys
# These keys go to shards but NOT to indexer

# 3. Stop node, enable indexer
./aptos-node --config config_with_indexer.yaml

# 4. Submit more transactions - these ARE indexed

# 5. Run validation tool
aptos-debugger aptos-db debug indexer-validation validate-indexer-db \
  --db-root-path /path/to/db \
  --internal-indexer-db-path /path/to/indexer \
  --target-version 1000000

# Expected: Should FAIL with error about missing keys
# Actual: Prints warnings but returns SUCCESS (exit code 0)

# 6. Query API for state by prefix - gets incomplete results
curl -X GET "http://localhost:8080/v1/accounts/0x1/resources"
# Returns only resources created after indexer was enabled
# Missing resources created before indexer was enabled
```

The validation passes despite clear inconsistency, and API queries return incomplete state.

## Notes

- This is primarily a **validation tooling bug** rather than a directly exploitable vulnerability
- The bug doesn't CREATE inconsistencies, but allows them to go UNDETECTED
- Real exploitation requires pre-existing operational issues (config problems, crashes, bugs)
- The impact is indirect: broken validation → undetected inconsistencies → incomplete API responses
- The internal indexer is optional infrastructure, not part of consensus, so this doesn't break consensus safety
- However, it does violate state consistency guarantees for API users who rely on complete state enumeration

### Citations

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

**File:** storage/indexer/src/db_indexer.rs (L489-497)
```rust
            if self.indexer_db.statekeys_enabled() {
                writeset.write_op_iter().for_each(|(state_key, write_op)| {
                    if write_op.is_creation() || write_op.is_modification() {
                        batch
                            .put::<StateKeysSchema>(state_key, &())
                            .expect("Failed to put state keys to a batch");
                    }
                });
            }
```

**File:** storage/indexer/src/utils.rs (L49-74)
```rust
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

**File:** storage/aptosdb/src/state_store/mod.rs (L809-843)
```rust
    pub fn put_state_values(
        &self,
        state_update_refs: &PerVersionStateUpdateRefs,
        sharded_state_kv_batches: &mut ShardedStateKvSchemaBatch,
    ) -> Result<()> {
        let _timer = OTHER_TIMERS_SECONDS.timer_with(&["add_state_kv_batch"]);

        // TODO(aldenhu): put by refs; batch put
        sharded_state_kv_batches
            .par_iter_mut()
            .zip_eq(state_update_refs.shards.par_iter())
            .try_for_each(|(batch, updates)| {
                updates
                    .iter()
                    .filter_map(|(key, update)| {
                        update
                            .state_op
                            .as_write_op_opt()
                            .map(|write_op| (key, update.version, write_op))
                    })
                    .try_for_each(|(key, version, write_op)| {
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
                    })
            })
    }
```

**File:** storage/aptosdb/src/db_debugger/mod.rs (L38-42)
```rust
    #[clap(subcommand)]
    Examine(examine::Cmd),

    #[clap(subcommand)]
    IndexerValidation(validation::Cmd),
```
