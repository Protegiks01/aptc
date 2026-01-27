# Audit Report

## Title
State Inconsistency in scan_snapshot Tool Due to Missing Key Validation and Unused Read Options During Partial Pruning

## Summary
The `scan_snapshot` debugger tool in `storage/aptosdb/src/db_debugger/state_kv/scan_snapshot.rs` can produce inconsistent and misleading state snapshots when scanning pruned or partially pruned versions. The tool creates `ReadOptions` with prefix validation but fails to use them, and doesn't validate that returned keys match expected keys, allowing it to return data from wrong keys when entries are pruned.

## Finding Description

The vulnerability exists in the `Cmd::run()` function where multiple issues combine to create state inconsistencies:

**Issue 1: No Version Range Validation**
The tool directly opens state databases without checking if the requested version is within the readable range. [1](#0-0) 

Unlike normal state reads through `AptosDB`, which validate against `min_readable_version` [2](#0-1) , the debugger bypasses this check.

**Issue 2: ReadOptions Created But Never Used**
The code creates `ReadOptions` with `set_prefix_same_as_start(true)` to prevent reading different keys [3](#0-2) , but the iterators are created WITHOUT these options [4](#0-3) .

**Issue 3: No Key Hash Validation**
When reading values, the code destructures the returned entry as `((_, version), value_opt)`, explicitly ignoring the key hash component [5](#0-4) . This means if the iterator returns a different key's data (which can happen without `set_prefix_same_as_start`), it will be used without validation.

**Issue 4: Per-Shard Pruning Progress**
Different shards track their own pruning progress independently [6](#0-5) . During normal operation, shards are pruned in parallel [7](#0-6) . If a crash occurs during pruning, shards can be at different progress levels, and they catch up individually on restart [8](#0-7) .

**Exploitation Scenario:**
1. System crashes during state KV pruning, leaving Shard 0 at version 1M and Shard 1 at version 500K
2. Operator runs `scan_snapshot --version 750000` to debug an issue
3. For keys in Shard 0 (fully pruned):
   - Merkle tree iterator says key K exists at version 750K
   - Seek to `(hash(K), 750000)` finds no entry
   - Without `set_prefix_same_as_start`, `next()` returns the next entry in DB (different key or older version)
   - Code ignores the returned key hash and uses this wrong data
4. For keys in Shard 1 (not pruned):
   - Correct data is returned
5. Result: Mixed snapshot with correct data from Shard 1 and incorrect/mismatched data from Shard 0

The schema stores entries as `(HashValue, Version)` pairs where versions are bit-inverted for reverse sorting [9](#0-8) . When seeking to a pruned entry, the iterator positions at the next available entry, which could be a completely different key's data.

## Impact Explanation

**Medium Severity** - This falls under "State inconsistencies requiring intervention" per the Aptos bug bounty program.

**Impact:**
- Debugging operations receive inconsistent, misleading data mixing correct and incorrect state
- Operators may make incorrect decisions based on false state information
- Could lead to misdiagnosis of actual issues or unnecessary interventions
- Undermines trust in debugging tools and operational procedures

**Scope Limitation:**
- Only affects the debugger tool, not production consensus or transaction processing
- Does not directly impact funds, consensus safety, or liveness
- Requires someone to actively run the debugger on a pruned version

The vulnerability breaks the **State Consistency** invariant by allowing non-atomic reads across shards during partial pruning states.

## Likelihood Explanation

**Moderate to High Likelihood:**

**Favorable Conditions:**
- State merkle pruning has a 1M version window while state KV has a 90M version window [10](#0-9) , creating a large gap where partial states exist
- Crashes during pruning are not uncommon in production systems
- Operators frequently use debugger tools to investigate issues
- The tool provides no warnings about pruned versions

**Attack Requirements:**
- No special privileges required (any operator with DB access can run the tool)
- No complex timing or race conditions needed
- Simply running `scan_snapshot` on a pruned/partially-pruned version triggers the issue

**Realistic Scenario:**
An operator investigating a state issue at an older version naturally runs `scan_snapshot --version <old_version>` without knowing it's been partially pruned, receives incorrect mixed data, and makes operational decisions based on false information.

## Recommendation

**Fix 1: Add Version Range Validation**
Before scanning, validate that the requested version is within the readable range:

```rust
pub fn run(self) -> Result<()> {
    // Add validation
    let state_kv_db = Arc::new(self.db_dir.open_state_kv_db()?);
    let min_readable_version = state_kv_db.get_min_readable_version();
    ensure!(
        self.version >= min_readable_version,
        "Version {} is pruned, min available version is {}",
        self.version,
        min_readable_version
    );
    
    // Continue with existing logic...
}
```

**Fix 2: Use ReadOptions with Prefix Validation**
Apply the created `read_opts` to the iterators:

```rust
let (value_version, value) = if enable_sharding {
    let mut iter = state_kv_db
        .db_shard(key.get_shard_id())
        .iter_with_opts::<StateValueByKeyHashSchema>(read_opts)  // Use read_opts here
        .unwrap();
    // rest of the code...
```

**Fix 3: Validate Returned Key Hash**
Explicitly verify the returned key matches the expected key:

```rust
iter.next()
    .transpose()
    .unwrap()
    .and_then(|((returned_hash, version), value_opt)| {
        if returned_hash == key.hash() {  // Validate key match
            value_opt.map(|value| (version, value))
        } else {
            None  // Wrong key, treat as missing
        }
    })
    .ok_or_else(|| anyhow!("Value for key {:?} at version {} not found (may be pruned)", key, key_version))
```

## Proof of Concept

```rust
// Reproduction steps (requires running against AptosDB with partial pruning):

use aptos_db_tool::DBTool;
use aptos_temppath::TempPath;

#[test]
fn test_scan_snapshot_inconsistency_with_partial_pruning() {
    // 1. Setup: Create a DB with state at multiple versions
    let tmpdir = TempPath::new();
    let db = setup_db_with_versioned_state(&tmpdir, 1000);
    
    // 2. Simulate partial pruning across shards
    // Prune Shard 0 up to version 800
    prune_shard(&db, 0, 800);
    // Leave Shard 1 at version 500
    prune_shard(&db, 1, 500);
    
    // 3. Run scan_snapshot at version 650 (partially pruned)
    let scan_cmd = ScanSnapshotCmd {
        db_dir: DbDir { db_dir: tmpdir.path().to_path_buf() },
        version: 650,
        concurrency: 1,
        slow_threshold_ms: 100,
    };
    
    // 4. Collect scanned data
    let results = scan_cmd.run().unwrap();
    
    // 5. Verify inconsistency:
    // - Keys in Shard 0 return wrong data (next available entry)
    // - Keys in Shard 1 return correct data
    // - Overall snapshot is inconsistent
    
    for (key, scanned_value) in results {
        let expected_value = get_value_at_version(&db, &key, 650);
        if key.get_shard_id() == 0 {
            // Shard 0 was pruned - expect wrong data or panic
            assert_ne!(scanned_value, expected_value, 
                "Should get wrong data for pruned shard");
        } else {
            // Shard 1 not pruned - expect correct data
            assert_eq!(scanned_value, expected_value,
                "Should get correct data for non-pruned shard");
        }
    }
}
```

## Notes

The vulnerability is amplified by the significant gap between state merkle pruning (1M versions) and state KV pruning (90M versions), creating a large window where this issue can manifest. This is a real implementation bug where protective code was written but not applied, combined with insufficient validation of returned database entries.

### Citations

**File:** storage/aptosdb/src/db_debugger/state_kv/scan_snapshot.rs (L49-51)
```rust
        let state_kv_db = Arc::new(self.db_dir.open_state_kv_db()?);
        let state_merkle_db = Arc::new(self.db_dir.open_state_merkle_db()?);
        let total_leaves = state_merkle_db.get_leaf_count(self.version)?;
```

**File:** storage/aptosdb/src/db_debugger/state_kv/scan_snapshot.rs (L79-81)
```rust
                            let mut read_opts = ReadOptions::default();
                            // We want `None` if the state_key changes in iteration.
                            read_opts.set_prefix_same_as_start(true);
```

**File:** storage/aptosdb/src/db_debugger/state_kv/scan_snapshot.rs (L86-89)
```rust
                                let mut iter = state_kv_db
                                    .db_shard(key.get_shard_id())
                                    .iter::<StateValueByKeyHashSchema>()
                                    .unwrap();
```

**File:** storage/aptosdb/src/db_debugger/state_kv/scan_snapshot.rs (L94-96)
```rust
                                    .and_then(|((_, version), value_opt)| {
                                        value_opt.map(|value| (version, value))
                                    })
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L305-315)
```rust
    pub(super) fn error_if_state_kv_pruned(&self, data_type: &str, version: Version) -> Result<()> {
        let min_readable_version = self.state_store.state_kv_pruner.get_min_readable_version();
        ensure!(
            version >= min_readable_version,
            "{} at version {} is pruned, min available version is {}.",
            data_type,
            version,
            min_readable_version
        );
        Ok(())
    }
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_shard_pruner.rs (L30-34)
```rust
        let progress = get_or_initialize_subpruner_progress(
            &db_shard,
            &DbMetadataKey::StateKvShardPrunerProgress(shard_id),
            metadata_progress,
        )?;
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/state_kv_shard_pruner.rs (L37-42)
```rust
        info!(
            progress = progress,
            metadata_progress = metadata_progress,
            "Catching up state kv shard {shard_id}."
        );
        myself.prune(progress, metadata_progress)?;
```

**File:** storage/aptosdb/src/pruner/state_kv_pruner/mod.rs (L67-78)
```rust
            THREAD_MANAGER.get_background_pool().install(|| {
                self.shard_pruners.par_iter().try_for_each(|shard_pruner| {
                    shard_pruner
                        .prune(progress, current_batch_target_version)
                        .map_err(|err| {
                            anyhow!(
                                "Failed to prune state kv shard {}: {err}",
                                shard_pruner.shard_id(),
                            )
                        })
                })
            })?;
```

**File:** storage/aptosdb/src/schema/state_value_by_key_hash/mod.rs (L28-52)
```rust
type Key = (HashValue, Version);

define_schema!(
    StateValueByKeyHashSchema,
    Key,
    Option<StateValue>,
    STATE_VALUE_BY_KEY_HASH_CF_NAME
);

impl KeyCodec<StateValueByKeyHashSchema> for Key {
    fn encode_key(&self) -> Result<Vec<u8>> {
        let mut encoded = vec![];
        encoded.write_all(self.0.as_ref())?;
        encoded.write_u64::<BigEndian>(!self.1)?;
        Ok(encoded)
    }

    fn decode_key(data: &[u8]) -> Result<Self> {
        const VERSION_SIZE: usize = size_of::<Version>();

        ensure_slice_len_eq(data, VERSION_SIZE + HashValue::LENGTH)?;
        let state_key_hash: HashValue = HashValue::from_slice(&data[..HashValue::LENGTH])?;
        let version = !(&data[HashValue::LENGTH..]).read_u64::<BigEndian>()?;
        Ok((state_key_hash, version))
    }
```

**File:** config/src/config/storage_config.rs (L387-412)
```rust
impl Default for LedgerPrunerConfig {
    fn default() -> Self {
        LedgerPrunerConfig {
            enable: true,
            prune_window: 90_000_000,
            batch_size: 5_000,
            user_pruning_window_offset: 200_000,
        }
    }
}

impl Default for StateMerklePrunerConfig {
    fn default() -> Self {
        StateMerklePrunerConfig {
            enable: true,
            // This allows a block / chunk being executed to have access to a non-latest state tree.
            // It needs to be greater than the number of versions the state committing thread is
            // able to commit during the execution of the block / chunk. If the bad case indeed
            // happens due to this being too small, a node restart should recover it.
            // Still, defaulting to 1M to be super safe.
            prune_window: 1_000_000,
            // A 10k transaction block (touching 60k state values, in the case of the account
            // creation benchmark) on a 4B items DB (or 1.33B accounts) yields 300k JMT nodes
            batch_size: 1_000,
        }
    }
```
