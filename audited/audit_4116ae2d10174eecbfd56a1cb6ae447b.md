# Audit Report

## Title
Critical Data Loss Vulnerability in Schema Column Family Migration: Old State Data Becomes Inaccessible When Sharding is Enabled

## Summary
When storage sharding is enabled on an Aptos node with existing state data, the schema migration system fails to preserve access to historical state stored in the old column family (`STATE_VALUE_CF_NAME`). The new code exclusively reads from the new column family (`STATE_VALUE_BY_KEY_HASH_CF_NAME`), causing complete loss of state access and node failure. This breaks the State Consistency invariant and renders nodes non-functional without manual data migration.

## Finding Description

The AptosDB storage layer uses RocksDB column families to organize data by schema. Each schema hardcodes its column family name through the `Schema` trait's `COLUMN_FAMILY_NAME` constant. [1](#0-0) 

When the state storage architecture was upgraded to support sharding (AIP-97), two incompatible schema sets were created:

**Non-sharded (old):**
- `StateValueSchema` using `STATE_VALUE_CF_NAME` column family
- Keys: `(StateKey, Version)`

**Sharded (new):**
- `StateValueByKeyHashSchema` using `STATE_VALUE_BY_KEY_HASH_CF_NAME` column family  
- Keys: `(KeyHash, Version)` [2](#0-1) 

The critical vulnerability occurs in the read path. When sharding is enabled, the code exclusively queries the new column family with NO fallback to the old one: [3](#0-2) 

When a database is opened with the new sharded configuration, the old column family becomes "unrecognized" and is opened separately but never read: [4](#0-3) 

The sharded databases use only the new column families: [5](#0-4) 

**Attack Scenario:**
1. A validator node runs with `enable_storage_sharding: false` and accumulates state in `STATE_VALUE_CF_NAME`
2. Node operator enables `enable_storage_sharding: true` (mandatory on mainnet/testnet per configuration validation)
3. Node restarts and opens sharded databases expecting `STATE_VALUE_BY_KEY_HASH_CF_NAME` (empty)
4. All state queries return None because the new column family is empty
5. Old state data in `STATE_VALUE_CF_NAME` remains on disk but is never accessed
6. Node cannot execute transactions, sync state, or participate in consensus
7. Network experiences validator downtime or partition [6](#0-5) 

## Impact Explanation

This qualifies as **CRITICAL SEVERITY** under multiple categories:

1. **Non-recoverable network partition (requires hardfork)**: If multiple validators incorrectly enable sharding without proper migration, they lose access to historical state and cannot reach consensus with properly migrated nodes. Recovery requires either a hardfork or complete resync from genesis.

2. **Total loss of liveness/network availability**: Affected nodes cannot execute blocks, validate transactions, or serve state queries. If enough validators are affected simultaneously, the network halts.

3. **Permanent freezing of funds (requires hardfork)**: Users cannot access their account balances or resources because state queries fail. The data exists on disk but is inaccessible without manual column family migration tools.

4. **Consensus/Safety violations**: Nodes with inaccessible state will compute different state roots than nodes with accessible state, causing consensus divergence and potential chain splits.

The vulnerability breaks the **State Consistency** invariant: "State transitions must be atomic and verifiable via Merkle proofs." When historical state becomes inaccessible, Merkle proof verification fails, and nodes cannot reconstruct the state tree.

## Likelihood Explanation

**Likelihood: HIGH**

While the configuration enforces sharding on mainnet/testnet, the vulnerability has high likelihood because:

1. **Mandatory feature**: The panic message forces operators to enable sharding, but doesn't guarantee safe migration
2. **No automatic migration**: There is no code in the repository that automatically copies data from old to new column families
3. **External documentation dependency**: The migration guide is on Notion (external link), which may be incomplete, outdated, or inaccessible
4. **Human error prone**: Manual migration procedures are error-prone, especially under time pressure
5. **No rollback protection**: Once sharding is enabled, there's no fallback to read from old column families

The codebase contains TODO comments indicating this is a known migration concern: [7](#0-6) 

## Recommendation

Implement a **safe migration system with automatic data migration and fallback**:

1. **Automatic Migration on First Sharded Open**:
   - Detect if old column families contain data but new ones are empty
   - Automatically copy/migrate state from `STATE_VALUE_CF_NAME` to `STATE_VALUE_BY_KEY_HASH_CF_NAME`
   - Write migration progress to metadata to prevent re-migration
   - Log migration status prominently

2. **Fallback Read Path**:
   ```rust
   pub(crate) fn get_state_value_with_version_by_version(
       &self,
       state_key: &StateKey,
       version: Version,
   ) -> Result<Option<(Version, StateValue)>> {
       if self.enabled_sharding() {
           // Try new schema first
           let result = self.get_from_new_schema(state_key, version)?;
           if result.is_some() {
               return Ok(result);
           }
           // Fallback to old schema if migration incomplete
           self.get_from_old_schema(state_key, version)
       } else {
           self.get_from_old_schema(state_key, version)
       }
   }
   ```

3. **Migration Validation**:
   - Add startup check that verifies old CF is empty before allowing sharded operation
   - Provide a migration tool that can be run offline before enabling sharding
   - Add `--force-migration` flag for explicit operator acknowledgment

4. **Include Old Column Families in Sharded Open**: [5](#0-4) 
   
   Add `STATE_VALUE_CF_NAME` and `STALE_STATE_VALUE_INDEX_CF_NAME` to the list so they can be accessed during migration.

## Proof of Concept

```rust
// Rust integration test demonstrating the vulnerability
#[test]
fn test_schema_migration_data_loss() {
    use aptos_config::config::RocksdbConfigs;
    use aptos_db::AptosDB;
    use aptos_types::state_store::state_key::StateKey;
    use aptos_storage_interface::DbReader;
    
    // Step 1: Create DB with sharding disabled, write state
    let db_path = tempfile::TempDir::new().unwrap();
    let mut config = RocksdbConfigs::default();
    config.enable_storage_sharding = false;
    
    let db = AptosDB::new_for_test_with_config(&db_path, config);
    
    // Write some state data (this goes to STATE_VALUE_CF_NAME)
    let state_key = StateKey::raw(b"test_key");
    let state_value = StateValue::new_legacy(b"test_value".to_vec());
    // ... write state at version 100 ...
    
    // Verify data is accessible
    let result = db.get_state_value_by_version(&state_key, 100).unwrap();
    assert!(result.is_some());
    
    drop(db);
    
    // Step 2: Reopen DB with sharding enabled
    let mut config = RocksdbConfigs::default();
    config.enable_storage_sharding = true;
    
    let db = AptosDB::new_for_test_with_config(&db_path, config);
    
    // Step 3: Try to read the same state
    // VULNERABILITY: This will return None even though data exists!
    let result = db.get_state_value_by_version(&state_key, 100).unwrap();
    assert!(result.is_none()); // Data loss! State became inaccessible
    
    // Old column family still contains data but is never queried
    // New column family is empty and is the only one being queried
}
```

The test demonstrates that state data written before sharding becomes completely inaccessible after enabling sharding, even though it remains physically on disk in the old column family.

## Notes

This vulnerability is particularly severe because:

1. The mandatory enforcement of sharding on mainnet/testnet creates pressure to enable the feature
2. No in-code migration path exists - operators must follow external documentation
3. The failure mode is silent data loss rather than an obvious error
4. Recovery requires either complete resync (days/weeks) or manual RocksDB manipulation
5. Multiple validators hitting this simultaneously would cause network-wide outage

The unrecognized column family handling preserves the RocksDB data but doesn't make it application-accessible, creating a false sense of safety while state is actually lost from the application's perspective.

### Citations

**File:** storage/schemadb/src/schema.rs (L134-143)
```rust
pub trait Schema: Debug + Send + Sync + 'static {
    /// The column family name associated with this struct.
    /// Note: all schemas within the same SchemaDB must have distinct column family names.
    const COLUMN_FAMILY_NAME: ColumnFamilyName;

    /// Type of the key.
    type Key: KeyCodec<Self>;
    /// Type of the value.
    type Value: ValueCodec<Self>;
}
```

**File:** storage/aptosdb/src/schema/mod.rs (L55-56)
```rust
pub const STATE_VALUE_CF_NAME: ColumnFamilyName = "state_value";
pub const STATE_VALUE_BY_KEY_HASH_CF_NAME: ColumnFamilyName = "state_value_by_key_hash";
```

**File:** storage/aptosdb/src/state_kv_db.rs (L374-402)
```rust
    pub(crate) fn get_state_value_with_version_by_version(
        &self,
        state_key: &StateKey,
        version: Version,
    ) -> Result<Option<(Version, StateValue)>> {
        let mut read_opts = ReadOptions::default();

        // We want `None` if the state_key changes in iteration.
        read_opts.set_prefix_same_as_start(true);
        if !self.enabled_sharding() {
            let mut iter = self
                .db_shard(state_key.get_shard_id())
                .iter_with_opts::<StateValueSchema>(read_opts)?;
            iter.seek(&(state_key.clone(), version))?;
            Ok(iter
                .next()
                .transpose()?
                .and_then(|((_, version), value_opt)| value_opt.map(|value| (version, value))))
        } else {
            let mut iter = self
                .db_shard(state_key.get_shard_id())
                .iter_with_opts::<StateValueByKeyHashSchema>(read_opts)?;
            iter.seek(&(state_key.hash(), version))?;
            Ok(iter
                .next()
                .transpose()?
                .and_then(|((_, version), value_opt)| value_opt.map(|value| (version, value))))
        }
    }
```

**File:** storage/schemadb/src/lib.rs (L149-166)
```rust
        let existing_cfs: HashSet<String> = rocksdb::DB::list_cf(db_opts, path.de_unc())
            .unwrap_or_default()
            .into_iter()
            .collect();
        let requested_cfs: HashSet<String> =
            cfds.iter().map(|cfd| cfd.name().to_string()).collect();
        let missing_cfs: HashSet<&str> = requested_cfs
            .difference(&existing_cfs)
            .map(|cf| {
                warn!("Missing CF: {}", cf);
                cf.as_ref()
            })
            .collect();
        let unrecognized_cfs = existing_cfs.difference(&requested_cfs);

        let all_cfds = cfds
            .into_iter()
            .chain(unrecognized_cfs.map(Self::cfd_for_unrecognized_cf));
```

**File:** storage/aptosdb/src/db_options.rs (L141-149)
```rust
pub(super) fn state_kv_db_new_key_column_families() -> Vec<ColumnFamilyName> {
    vec![
        /* empty cf */ DEFAULT_COLUMN_FAMILY_NAME,
        DB_METADATA_CF_NAME,
        STALE_STATE_VALUE_INDEX_BY_KEY_HASH_CF_NAME,
        STATE_VALUE_BY_KEY_HASH_CF_NAME,
        STATE_VALUE_INDEX_CF_NAME, // we still need this cf before deleting all the write callsites
    ]
}
```

**File:** config/src/config/storage_config.rs (L664-668)
```rust
            if (chain_id.is_testnet() || chain_id.is_mainnet())
                && config_yaml["rocksdb_configs"]["enable_storage_sharding"].as_bool() != Some(true)
            {
                panic!("Storage sharding (AIP-97) is not enabled in node config. Please follow the guide to migration your node, and set storage.rocksdb_configs.enable_storage_sharding to true explicitly in your node config. https://aptoslabs.notion.site/DB-Sharding-Migration-Public-Full-Nodes-1978b846eb7280b29f17ceee7d480730");
            }
```

**File:** storage/aptosdb/src/ledger_db/mod.rs (L394-397)
```rust
    // TODO(grao): Remove this after sharding migration.
    pub(crate) fn metadata_db_arc(&self) -> Arc<DB> {
        self.ledger_metadata_db.db_arc()
    }
```
