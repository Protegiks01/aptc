# Audit Report

## Title
Archive Database Corruption via Hot State Deletion in replay-on-archive Tool

## Summary
The `Verifier::new()` function in `replay_on_archive.rs` opens AptosDB in write mode with default `HotStateConfig` settings, which has `delete_on_restart: true`. This causes unintended deletion of hot state merkle database directories when storage sharding is enabled, corrupting archive databases used for transaction replay verification.

## Finding Description

The vulnerability exists in the database initialization sequence within `Verifier::new()`: [1](#0-0) 

The first open uses `HotStateConfig::default()` which sets `delete_on_restart: true`: [2](#0-1) 

When storage sharding is enabled, this triggers creation of a hot state merkle database: [3](#0-2) 

The `StateMerkleDb::new()` function passes `delete_on_restart` through to `open_db`: [4](#0-3) 

When `delete_on_restart` is true, the entire hot state database directory is deleted: [5](#0-4) 

**Breaking Invariant:** This violates **State Consistency** (Invariant #4) - state transitions must be atomic and verifiable via Merkle proofs. Deleting the hot state merkle database can make historical state verification impossible and creates an inconsistent archive.

**Production Impact:** This tool is used in production CI/CD workflows for mainnet/testnet verification: [6](#0-5) 

## Impact Explanation

This qualifies as **Medium Severity** per Aptos bug bounty criteria: "State inconsistencies requiring intervention."

The impact includes:
1. **Archive Database Corruption**: Hot state merkle tree data is permanently deleted from archives
2. **Verification Failure**: Transaction replay may produce incorrect results or fail due to missing state data
3. **Operational Disruption**: Production verification workflows on mainnet/testnet could corrupt critical archive databases
4. **State Proof Invalidation**: Merkle proofs become unverifiable if hot state data is missing

While this doesn't directly affect consensus or live validator nodes, it compromises the integrity of historical state verification infrastructure.

## Likelihood Explanation

**HIGH likelihood** of occurrence:
- The bug triggers automatically whenever the tool runs with storage sharding enabled (default configuration for mainnet/testnet)
- No special conditions or attacker actions required
- Affects standard operational workflows (GitHub Actions CI/CD)
- Archive databases with hot state data will be corrupted on first replay attempt

## Recommendation

**Fix:** Remove the write-mode initialization attempt, or explicitly set `delete_on_restart: false` for the first open attempt:

```rust
pub fn new(config: &Opt) -> Result<Self> {
    // Remove the write-mode initialization or use delete_on_restart: false
    {
        if let Err(e) = panic::catch_unwind(|| {
            AptosDB::open(
                StorageDirPaths::from_path(config.db_dir.as_path()),
                false,
                NO_OP_STORAGE_PRUNER_CONFIG,
                config.rocksdb_opt.clone().into(),
                false,
                BUFFERED_STATE_TARGET_ITEMS,
                DEFAULT_MAX_NUM_NODES_PER_LRU_CACHE_SHARD,
                None,
                HotStateConfig {
                    delete_on_restart: false,  // FIX: Never delete on restart for archive verification
                    ..Default::default()
                },
            )
        }) {
            warn!("Unable to open AptosDB in write mode: {:?}", e);
        };
    }
    
    // Continue with read-only open...
```

**Better approach:** Since the tool is read-only by design (transaction replay verification), the write-mode initialization should be removed entirely if not strictly necessary for column family creation.

## Proof of Concept

```rust
// Reproduction steps:
// 1. Create an archive database with storage sharding enabled and hot state data
// 2. Run replay-on-archive tool:
//    aptos-debugger aptos-db replay-on-archive \
//      --target-db-dir /path/to/archive \
//      --start-version 0 \
//      --end-version 1000 \
//      --enable-storage-sharding
// 3. Observe hot state merkle database deletion in logs
// 4. Verify hot state directory is missing after first open
// 5. Transaction replay fails or produces incorrect results due to missing state

// Expected behavior:
// - Hot state directory exists before tool run
// - File: /path/to/archive/hot_state_merkle_db/metadata/
// - File: /path/to/archive/hot_state_merkle_db/shard_*/

// Actual behavior after bug:
// - std::fs::remove_dir_all() deletes entire hot state merkle db directory
// - Subsequent read-only open cannot access hot state data
// - Archive database is corrupted
```

## Notes

- This issue only affects archives with `enable_storage_sharding: true` (mainnet/testnet production configuration)
- The comment "Open in write mode to create any new DBs necessary" suggests the intent was initialization, but the `HotStateConfig::default()` setting has the unintended side effect of deletion
- The deletion is wrapped in `panic::catch_unwind` but still executes successfully before the second (read-only) open
- The second open with `delete_on_restart: false` is correct but cannot undo the damage from the first open

### Citations

**File:** storage/db-tool/src/replay_on_archive.rs (L151-168)
```rust
        // Open in write mode to create any new DBs necessary.
        {
            if let Err(e) = panic::catch_unwind(|| {
                AptosDB::open(
                    StorageDirPaths::from_path(config.db_dir.as_path()),
                    false,
                    NO_OP_STORAGE_PRUNER_CONFIG,
                    config.rocksdb_opt.clone().into(),
                    false,
                    BUFFERED_STATE_TARGET_ITEMS,
                    DEFAULT_MAX_NUM_NODES_PER_LRU_CACHE_SHARD,
                    None,
                    HotStateConfig::default(),
                )
            }) {
                warn!("Unable to open AptosDB in write mode: {:?}", e);
            };
        }
```

**File:** config/src/config/storage_config.rs (L256-264)
```rust
impl Default for HotStateConfig {
    fn default() -> Self {
        Self {
            max_items_per_shard: 250_000,
            refresh_interval_versions: 100_000,
            delete_on_restart: true,
            compute_root_hash: true,
        }
    }
```

**File:** storage/aptosdb/src/db/mod.rs (L130-143)
```rust
        let hot_state_merkle_db = if !readonly && rocksdb_configs.enable_storage_sharding {
            Some(StateMerkleDb::new(
                db_paths,
                rocksdb_configs,
                env,
                block_cache,
                readonly,
                max_num_nodes_per_lru_cache_shard,
                /* is_hot = */ true,
                reset_hot_state,
            )?)
        } else {
            None
        };
```

**File:** storage/aptosdb/src/state_merkle_db.rs (L97-100)
```rust
        assert!(
            !delete_on_restart || is_hot,
            "Only hot state can be cleared on restart"
        );
```

**File:** storage/aptosdb/src/state_merkle_db.rs (L717-721)
```rust
        if delete_on_restart {
            ensure!(!readonly, "Should not reset DB in read-only mode.");
            info!("delete_on_restart is true. Removing {path:?} entirely.");
            std::fs::remove_dir_all(&path).unwrap_or(());
        }
```

**File:** .github/workflows/replay-verify-mainnet.yaml (L1-6)
```yaml
# This defines a workflow to replay transactions on the given chain with the latest aptos node software.
# In order to trigger it go to the Actions Tab of the Repo, click "replay-verify" and then "Run Workflow".
#
# On PR, a single test case will run. On workflow_dispatch, you may specify the CHAIN_NAME to verify.

name: "Replay-verify on archive: Mainnet"
```
