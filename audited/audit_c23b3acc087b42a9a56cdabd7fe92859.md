# Audit Report

## Title
Storage Usage Underreporting via Pruned Metadata Leading to Storage Exhaustion Through Underpriced Gas

## Summary
When storage sharding is enabled, the system silently returns zero storage usage values if version metadata has been pruned, causing storage gas prices to be set to minimum levels and enabling storage exhaustion attacks.

## Finding Description

The Aptos blockchain uses dynamic storage gas pricing based on actual storage utilization. The `native_get_usage()` function in the native state storage module retrieves current storage usage (items and bytes) which feeds into gas price calculations via `storage_gas::on_reconfig()`. [1](#0-0) 

This native function retrieves usage data from the state resolver, which ultimately queries the database for `StateStorageUsage` at a specific version. [2](#0-1) 

**The Critical Flaw**: When `skip_usage` is true (set when storage sharding is enabled), if version metadata is missing from the database, the system returns `StateStorageUsage::new_untracked()` instead of erroring. [3](#0-2) 

The `Untracked` variant returns **zero** for both `items()` and `bytes()` calls. This occurs even though real storage usage may be in the terabytes.

**How Version Data Gets Pruned**: The ledger metadata pruner explicitly deletes `VersionDataSchema` entries during pruning operations: [4](#0-3) 

**Attack Vector**: During node initialization or restart, the system loads the base state from the latest snapshot: [5](#0-4) 

At line 586, if the snapshot version's metadata has been pruned and `skip_usage=true`, it gets zero usage values. This creates a `State` object with zero usage that becomes the base for block execution.

**Storage Sharding Enables Silent Failure**: The `skip_usage` flag is set when storage sharding is enabled: [6](#0-5) 

**Gas Price Manipulation**: These zero values propagate to the Move framework where `storage_gas::on_reconfig()` calculates gas prices based on utilization ratio: [7](#0-6) 

With zero reported usage against target usage (2 billion items, 1TB), the utilization ratio becomes 0%, setting all storage operation costs to their minimum values. [8](#0-7) 

## Impact Explanation

**High Severity** - This breaks critical invariant #9 (Resource Limits) and enables storage exhaustion attacks:

1. **Storage Exhaustion**: With minimum gas prices, attackers can create massive amounts of state data (resources, table entries) at negligible cost
2. **Network Degradation**: Bloated state increases sync times, memory usage, and disk requirements for all validators
3. **Economic Attack**: The gas pricing mechanism becomes ineffective, removing the economic barrier to state spam
4. **Validator Operation Impact**: Nodes may run out of disk space or experience severe performance degradation

While not consensus-breaking, this qualifies as "Significant protocol violations" and "Validator node slowdowns" under High Severity criteria.

## Likelihood Explanation

**Medium-to-High Likelihood** in production environments:

1. **Storage Sharding is Production Feature**: Enabled via `rocksdb_configs.enable_storage_sharding` for performance
2. **Pruning is Standard Operation**: Nodes routinely prune old data to manage disk usage
3. **Timing Window Exists**: If pruner runs aggressively between snapshot creation and node restart, the condition triggers
4. **Silent Failure**: No error is raised, making detection difficult until storage exhaustion symptoms appear
5. **Persistent Effect**: Once wrong usage is recorded at epoch boundary, it persists for the entire next epoch

## Recommendation

**Immediate Fix**: Never silently return zero usage when data is missing. Always fail-fast:

```rust
fn get_state_storage_usage(&self, version: Option<Version>) -> Result<StateStorageUsage> {
    version.map_or(Ok(StateStorageUsage::zero()), |version| {
        self.ledger_db.metadata_db().get_usage(version)
            .with_context(|| format!("VersionData at {version} is missing - cannot initialize state safely"))
    })
}
```

**Longer-term Solutions**:
1. Coordinate pruning with snapshot management - never prune metadata for the latest checkpoint
2. Store usage data redundantly or separately from prunable version metadata  
3. Add validation at epoch boundaries to detect anomalous usage drops
4. Implement minimum gas price floors independent of reported usage

## Proof of Concept

```rust
#[test]
fn test_pruned_usage_causes_zero_gas_prices() {
    // 1. Setup: Initialize DB with storage sharding enabled
    let config = RocksdbConfigs {
        enable_storage_sharding: true,
        ..Default::default()
    };
    let db = AptosDB::open(test_path, false, pruner_config, config, ...);
    
    // 2. Write state with real usage (e.g., 1GB, 1M items)
    let usage = StateStorageUsage::new(1_000_000, 1_000_000_000);
    // ... commit state with usage ...
    
    // 3. Create snapshot at version V
    // ... create snapshot ...
    
    // 4. Advance ledger and run pruner to delete version V's metadata
    // ... execute transactions ...
    // ... run ledger pruner targeting version > V ...
    
    // 5. Restart node - initialization reads from pruned snapshot
    drop(db);
    let db = AptosDB::open(test_path, false, pruner_config, config, ...);
    
    // 6. Execute epoch boundary transaction
    let metadata = BlockMetadata::new(..., new_epoch, ...);
    let (state_view, _) = db.get_persisted_state()?;
    
    // 7. native_get_usage() is called via on_new_block()
    // Expected: Should error or return real usage
    // Actual: Returns (0, 0) due to Untracked variant
    
    // 8. Verify storage gas prices are set to minimum
    // ... check StorageGas resource ...
    assert!(gas.per_item_create == MIN_GAS); // Should be higher based on real usage
}
```

## Notes

The root cause is the combination of: (1) storage sharding enabling `skip_usage` flag, (2) aggressive pruning removing version metadata, and (3) silent fallback to zero values instead of failing safely. This breaks the storage economics model and enables resource exhaustion attacks.

### Citations

**File:** aptos-move/framework/src/natives/state_storage.rs (L59-79)
```rust
fn native_get_usage(
    context: &mut SafeNativeContext,
    _ty_args: &[Type],
    _args: VecDeque<Value>,
) -> SafeNativeResult<SmallVec<[Value; 1]>> {
    assert!(_ty_args.is_empty());
    assert!(_args.is_empty());

    context.charge(STATE_STORAGE_GET_USAGE_BASE_COST)?;

    let ctx = context.extensions().get::<NativeStateStorageContext>();
    let usage = ctx.resolver.get_usage().map_err(|err| {
        PartialVMError::new(StatusCode::VM_EXTENSION_ERROR)
            .with_message(format!("Failed to get state storage usage: {}", err))
    })?;

    Ok(smallvec![Value::struct_(Struct::pack(vec![
        Value::u64(usage.items() as u64),
        Value::u64(usage.bytes() as u64),
    ]))])
}
```

**File:** storage/aptosdb/src/state_store/mod.rs (L238-248)
```rust
    fn get_state_storage_usage(&self, version: Option<Version>) -> Result<StateStorageUsage> {
        version.map_or(Ok(StateStorageUsage::zero()), |version| {
            Ok(match self.ledger_db.metadata_db().get_usage(version) {
                Ok(data) => data,
                _ => {
                    ensure!(self.skip_usage, "VersionData at {version} is missing.");
                    StateStorageUsage::new_untracked()
                },
            })
        })
    }
```

**File:** storage/aptosdb/src/state_store/mod.rs (L552-593)
```rust
    fn create_buffered_state_from_latest_snapshot(
        state_db: &Arc<StateDb>,
        buffered_state_target_items: usize,
        hack_for_tests: bool,
        check_max_versions_after_snapshot: bool,
        out_current_state: Arc<Mutex<LedgerStateWithSummary>>,
        out_persisted_state: PersistedState,
        hot_state_config: HotStateConfig,
    ) -> Result<BufferedState> {
        let num_transactions = state_db
            .ledger_db
            .metadata_db()
            .get_synced_version()?
            .map_or(0, |v| v + 1);

        let latest_snapshot_version = state_db
            .state_merkle_db
            .get_state_snapshot_version_before(Version::MAX)
            .expect("Failed to query latest node on initialization.");

        info!(
            num_transactions = num_transactions,
            latest_snapshot_version = latest_snapshot_version,
            "Initializing BufferedState."
        );
        // TODO(HotState): read hot root hash from DB.
        let latest_snapshot_root_hash = if let Some(version) = latest_snapshot_version {
            state_db
                .state_merkle_db
                .get_root_hash(version)
                .expect("Failed to query latest checkpoint root hash on initialization.")
        } else {
            *SPARSE_MERKLE_PLACEHOLDER_HASH
        };
        let usage = state_db.get_state_storage_usage(latest_snapshot_version)?;
        let state = StateWithSummary::new_at_version(
            latest_snapshot_version,
            *SPARSE_MERKLE_PLACEHOLDER_HASH, // TODO(HotState): for now hot state always starts from empty upon restart.
            latest_snapshot_root_hash,
            usage,
            hot_state_config,
        );
```

**File:** types/src/state_store/state_storage_usage.rs (L22-42)
```rust
    pub fn new_untracked() -> Self {
        Self::Untracked
    }

    pub fn is_untracked(&self) -> bool {
        matches!(self, Self::Untracked)
    }

    pub fn items(&self) -> usize {
        match self {
            Self::Tracked { items, .. } => *items,
            Self::Untracked => 0,
        }
    }

    pub fn bytes(&self) -> usize {
        match self {
            Self::Tracked { bytes, .. } => *bytes,
            Self::Untracked => 0,
        }
    }
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/ledger_metadata_pruner.rs (L42-56)
```rust
    pub(in crate::pruner) fn prune(
        &self,
        current_progress: Version,
        target_version: Version,
    ) -> Result<()> {
        let mut batch = SchemaBatch::new();
        for version in current_progress..target_version {
            batch.delete::<VersionDataSchema>(&version)?;
        }
        batch.put::<DbMetadataSchema>(
            &DbMetadataKey::LedgerPrunerProgress,
            &DbMetadataValue::Version(target_version),
        )?;
        self.ledger_metadata_db.write_schemas(batch)
    }
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L148-160)
```rust
        let mut myself = Self::new_with_dbs(
            ledger_db,
            hot_state_merkle_db,
            state_merkle_db,
            state_kv_db,
            pruner_config,
            buffered_state_target_items,
            readonly,
            empty_buffered_state_for_restore,
            rocksdb_configs.enable_storage_sharding,
            internal_indexer_db,
            hot_state_config,
        );
```

**File:** aptos-move/framework/aptos-framework/sources/storage_gas.move (L453-496)
```text
    fun calculate_gas(max_usage: u64, current_usage: u64, curve: &GasCurve): u64 {
        let capped_current_usage = if (current_usage > max_usage) max_usage else current_usage;
        let points = &curve.points;
        let num_points = vector::length(points);
        let current_usage_bps = capped_current_usage * BASIS_POINT_DENOMINATION / max_usage;

        // Check the corner case that current_usage_bps drops before the first point.
        let (left, right) = if (num_points == 0) {
            (&Point { x: 0, y: 0 }, &Point { x: BASIS_POINT_DENOMINATION, y: BASIS_POINT_DENOMINATION })
        } else if (current_usage_bps < vector::borrow(points, 0).x) {
            (&Point { x: 0, y: 0 }, vector::borrow(points, 0))
        } else if (vector::borrow(points, num_points - 1).x <= current_usage_bps) {
            (vector::borrow(points, num_points - 1), &Point { x: BASIS_POINT_DENOMINATION, y: BASIS_POINT_DENOMINATION })
        } else {
            let (i, j) = (0, num_points - 2);
            while ({
                spec {
                    invariant i <= j;
                    invariant j < num_points - 1;
                    invariant points[i].x <= current_usage_bps;
                    invariant current_usage_bps < points[j + 1].x;
                };
                i < j
            }) {
                let mid = j - (j - i) / 2;
                if (current_usage_bps < vector::borrow(points, mid).x) {
                    spec {
                        // j is strictly decreasing.
                        assert mid - 1 < j;
                    };
                    j = mid - 1;
                } else {
                    spec {
                        // i is strictly increasing.
                        assert i < mid;
                    };
                    i = mid;
                };
            };
            (vector::borrow(points, i), vector::borrow(points, i + 1))
        };
        let y_interpolated = interpolate(left.x, right.x, left.y, right.y, current_usage_bps);
        interpolate(0, BASIS_POINT_DENOMINATION, curve.min_gas, curve.max_gas, y_interpolated)
    }
```

**File:** aptos-move/framework/aptos-framework/sources/storage_gas.move (L515-533)
```text
    public(friend) fun on_reconfig() acquires StorageGas, StorageGasConfig {
        assert!(
            exists<StorageGasConfig>(@aptos_framework),
            error::not_found(ESTORAGE_GAS_CONFIG)
        );
        assert!(
            exists<StorageGas>(@aptos_framework),
            error::not_found(ESTORAGE_GAS)
        );
        let (items, bytes) = state_storage::current_items_and_bytes();
        let gas_config = borrow_global<StorageGasConfig>(@aptos_framework);
        let gas = borrow_global_mut<StorageGas>(@aptos_framework);
        gas.per_item_read = calculate_read_gas(&gas_config.item_config, items);
        gas.per_item_create = calculate_create_gas(&gas_config.item_config, items);
        gas.per_item_write = calculate_write_gas(&gas_config.item_config, items);
        gas.per_byte_read = calculate_read_gas(&gas_config.byte_config, bytes);
        gas.per_byte_create = calculate_create_gas(&gas_config.byte_config, bytes);
        gas.per_byte_write = calculate_write_gas(&gas_config.byte_config, bytes);
    }
```
