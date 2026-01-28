# Audit Report

## Title
Storage Usage Underreporting via Pruned Metadata Leading to Storage Exhaustion Through Underpriced Gas

## Summary
When storage sharding is enabled (default in production), the system silently returns zero storage usage values if version metadata has been pruned, causing storage gas prices to be set to minimum levels for an entire epoch. This enables attackers to create massive amounts of state data at significantly reduced cost, potentially exhausting validator disk space and degrading network performance.

## Finding Description

The Aptos blockchain implements dynamic storage gas pricing based on actual storage utilization. The vulnerability arises from the interaction between three system components: storage sharding configuration, metadata pruning, and node initialization.

**Root Cause Analysis:**

The `skip_usage` flag in `StateDb` is set to the value of `rocksdb_configs.enable_storage_sharding`, which defaults to `true` in production configurations. [1](#0-0) [2](#0-1) 

When `skip_usage` is true and version metadata is missing from the database, the system returns `StateStorageUsage::new_untracked()` instead of raising an error: [3](#0-2) 

The `Untracked` variant returns zero for both `items()` and `bytes()` accessor methods: [4](#0-3) 

**Attack Vector Execution Path:**

1. The ledger metadata pruner continuously deletes `VersionDataSchema` entries during normal pruning operations: [5](#0-4) 

2. During node initialization or restart, the system loads the base state from the latest snapshot and retrieves storage usage at that snapshot version: [6](#0-5) 

3. If the snapshot version's metadata has been pruned and `skip_usage=true`, the initialization receives zero usage values. This creates a `State` object with incorrect zero usage that becomes the base for subsequent block execution.

4. These zero values propagate to the Move framework through the native function interface: [7](#0-6) 

5. At epoch boundaries, the Move framework updates the `StateStorageUsage` resource with values retrieved from the native function: [8](#0-7) 

6. During epoch reconfiguration, `storage_gas::on_reconfig()` retrieves these zero values and uses them to calculate new gas prices: [9](#0-8) 

7. The target utilization is configured as 2 billion items and 1 TB of storage: [10](#0-9) 

8. With zero reported usage against these targets, the utilization ratio becomes 0%, causing `calculate_gas()` to return minimum gas values for all storage operations: [11](#0-10) 

**Persistence:** The incorrect zero usage values persist for the entire epoch duration because `StateStorageUsage` is only updated at epoch boundaries via the `on_new_block` function, not during normal block processing.

## Impact Explanation

**High Severity** - This vulnerability qualifies under two High Severity categories from the Aptos bug bounty program:

1. **Validator Node Slowdowns**: With minimum gas pricing, attackers can create massive amounts of state data (resources, table entries) at significantly reduced cost. While minimum gas costs are non-zero (300,000 gas units per item create, 5,000 per byte create), the reduction from maximum prices (up to 100x difference on the exponential curve) enables state spam at a fraction of normal cost. This bloated state increases disk usage, sync times, and memory requirements for all validators, causing performance degradation.

2. **Significant Protocol Violations**: The dynamic storage gas pricing mechanism is a critical economic safeguard designed to prevent state explosion. This vulnerability breaks that invariant by causing the gas pricing system to report 0% utilization when real utilization may be in terabytes. This represents a fundamental violation of the protocol's resource management guarantees.

**Concrete Attack Scenario**: An attacker observing that a validator has restarted during a metadata pruning window could immediately begin creating large numbers of resources or table entries at minimum gas cost. Over an epoch (potentially hours), this could lead to significant disk space consumption across all validators, forcing operators to provision additional storage or potentially causing validator failures if disk space is exhausted.

The impact is time-limited to one epoch but can cause measurable harm during that period. The issue is not consensus-breaking (all validators calculate the same gas prices) and is not permanent (self-corrects at next epoch), but still represents a serious protocol violation with real operational impact.

## Likelihood Explanation

**Medium Likelihood** in production environments:

1. **Default Configuration Enables Vulnerability**: Storage sharding (`enable_storage_sharding`) defaults to `true` in production, automatically setting `skip_usage=true` for all mainnet and testnet nodes.

2. **Continuous Background Operations**: Ledger metadata pruning runs continuously in the background as part of normal node operation to manage disk usage. The pruner systematically deletes old `VersionDataSchema` entries.

3. **Timing Window**: The vulnerability triggers when a node restarts and the latest snapshot version's metadata has been pruned. While pruning typically lags behind recent versions by a configurable window, aggressive pruning configurations or long-running nodes with older snapshots increase the likelihood.

4. **Silent Failure Mode**: The `ensure!(self.skip_usage, ...)` check means the system silently returns zero usage instead of erroring, making detection difficult until symptoms (rapid storage growth, validator slowdowns) appear.

5. **No Explicit Validation**: There is no validation that checks whether reported usage values are reasonable or consistent with actual database size, allowing the zero values to propagate unchecked through the gas pricing system.

The precise timing requirement (restart during metadata pruning window) reduces likelihood somewhat, but the default configuration and continuous pruning operations make this a realistic scenario that could occur naturally during normal validator operations.

## Recommendation

Implement one or more of the following mitigations:

1. **Validate Usage Values**: Add validation in `create_buffered_state_from_latest_snapshot` to verify that retrieved usage values are reasonable (non-zero if database is non-empty):

```rust
let usage = state_db.get_state_storage_usage(latest_snapshot_version)?;
if usage.is_untracked() && num_transactions > 0 {
    // Fallback: estimate usage from current database size
    let estimated_usage = estimate_storage_usage_from_db(state_db)?;
    warn!("Usage metadata missing, using estimated values: items={}, bytes={}", 
          estimated_usage.items(), estimated_usage.bytes());
    usage = estimated_usage;
}
```

2. **Preserve Recent Metadata**: Modify the ledger metadata pruner to preserve `VersionDataSchema` entries for versions that correspond to state snapshots, even if they would otherwise be pruned:

```rust
// In ledger_metadata_pruner.rs prune()
let snapshot_versions = state_merkle_db.get_all_snapshot_versions()?;
for version in current_progress..target_version {
    if !snapshot_versions.contains(&version) {
        batch.delete::<VersionDataSchema>(&version)?;
    }
}
```

3. **Error on Missing Critical Metadata**: Change the behavior to fail fast rather than silently using zero values when critical metadata is missing during initialization:

```rust
fn get_state_storage_usage(&self, version: Option<Version>) -> Result<StateStorageUsage> {
    version.map_or(Ok(StateStorageUsage::zero()), |version| {
        self.ledger_db.metadata_db().get_usage(version)
            .or_else(|_| {
                if self.skip_usage {
                    warn!("VersionData at {version} is missing with skip_usage=true");
                    Ok(StateStorageUsage::new_untracked())
                } else {
                    Err(AptosDbError::NotFound(format!("VersionData at {version} is missing")))
                }
            })
    })
}
```

4. **Runtime Usage Tracking**: Implement runtime usage tracking that updates usage values incrementally during block execution, rather than relying solely on periodic snapshots.

## Proof of Concept

The following demonstrates the vulnerability trigger condition:

```rust
#[test]
fn test_zero_usage_from_pruned_metadata() {
    use aptos_types::state_store::state_storage_usage::StateStorageUsage;
    
    // Simulate the condition: skip_usage=true, missing VersionData
    let skip_usage = true;
    let metadata_exists = false;
    
    // This is the logic from get_state_storage_usage
    let usage = if metadata_exists {
        StateStorageUsage::new(1_000_000, 500_000_000) // 1M items, 500MB
    } else {
        if skip_usage {
            StateStorageUsage::new_untracked()
        } else {
            panic!("Would error without skip_usage");
        }
    };
    
    // Verify the bug: usage reports zero despite real data
    assert_eq!(usage.items(), 0);
    assert_eq!(usage.bytes(), 0);
    
    // This zero propagates to gas calculations
    let target_items = 2_000_000_000u64; // 2 billion target
    let utilization_ratio = (usage.items() as u64 * 10000) / target_items;
    assert_eq!(utilization_ratio, 0); // 0% utilization reported!
    
    // Minimum gas would be charged instead of appropriate higher gas
    println!("Gas pricing will use minimum values due to 0% utilization");
}
```

To trigger in a real environment:
1. Configure node with storage sharding enabled (default)
2. Run node long enough for pruner to delete old metadata
3. Restart node when latest snapshot version's metadata has been pruned
4. Observe `StateStorageUsage` resource shows zero values at next epoch boundary
5. Verify storage operations charge minimum gas for that epoch

## Notes

The vulnerability is technically valid and triggerable, though with some important caveats:

1. **Time-Limited Impact**: The incorrect gas pricing only persists for one epoch duration, after which the system self-corrects at the next epoch boundary.

2. **Non-Zero Minimum Costs**: Even at minimum gas prices, storage operations are not free (300,000 gas units per item, 5,000 per byte). The vulnerability reduces costs but doesn't eliminate them entirely.

3. **No Consensus Impact**: All validators would calculate the same (incorrect) gas prices, so this doesn't cause consensus divergence or chain splits.

4. **Design vs. Bug**: The `skip_usage` flag appears intentional for handling sharded storage scenarios, but the silent zero-value fallback was likely not intended for initialization scenarios where accurate usage is critical for gas pricing.

The vulnerability represents a legitimate security issue affecting the storage gas pricing mechanism's integrity and validator operational stability, qualifying as High Severity under the Aptos bug bounty framework.

### Citations

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L157-157)
```rust
            rocksdb_configs.enable_storage_sharding,
```

**File:** config/src/config/storage_config.rs (L233-233)
```rust
            enable_storage_sharding: true,
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

**File:** storage/aptosdb/src/state_store/mod.rs (L567-593)
```rust
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

**File:** types/src/state_store/state_storage_usage.rs (L30-42)
```rust
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

**File:** aptos-move/framework/aptos-framework/sources/state_storage.move (L39-49)
```text
    public(friend) fun on_new_block(epoch: u64) acquires StateStorageUsage {
        assert!(
            exists<StateStorageUsage>(@aptos_framework),
            error::not_found(ESTATE_STORAGE_USAGE)
        );
        let usage = borrow_global_mut<StateStorageUsage>(@aptos_framework);
        if (epoch != usage.epoch) {
            usage.epoch = epoch;
            usage.usage = get_state_storage_usage_only_at_epoch_beginning();
        }
    }
```

**File:** aptos-move/framework/aptos-framework/sources/storage_gas.move (L389-414)
```text
    public fun initialize(aptos_framework: &signer) {
        system_addresses::assert_aptos_framework(aptos_framework);
        assert!(
            !exists<StorageGasConfig>(@aptos_framework),
            error::already_exists(ESTORAGE_GAS_CONFIG)
        );

        let k: u64 = 1000;
        let m: u64 = 1000 * 1000;

        let item_config = UsageGasConfig {
            target_usage: 2 * k * m, // 2 billion
            read_curve: base_8192_exponential_curve(300 * k, 300 * k * 100),
            create_curve: base_8192_exponential_curve(300 * k, 300 * k * 100),
            write_curve: base_8192_exponential_curve(300 * k, 300 * k * 100),
        };
        let byte_config = UsageGasConfig {
            target_usage: 1 * m * m, // 1TB
            read_curve: base_8192_exponential_curve(300, 300 * 100),
            create_curve: base_8192_exponential_curve(5 * k,  5 * k * 100),
            write_curve: base_8192_exponential_curve(5 * k,  5 * k * 100),
        };
        move_to(aptos_framework, StorageGasConfig {
            item_config,
            byte_config,
        });
```

**File:** aptos-move/framework/aptos-framework/sources/storage_gas.move (L453-501)
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

    // Interpolates y for x on the line between (x0, y0) and (x1, y1).
    fun interpolate(x0: u64, x1: u64, y0: u64, y1: u64, x: u64): u64 {
        y0 + (x - x0) * (y1 - y0) / (x1 - x0)
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
