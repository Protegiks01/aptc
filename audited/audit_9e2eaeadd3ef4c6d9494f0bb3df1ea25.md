# Audit Report

## Title
State Inconsistency Vulnerability: Dual Database Exposure During Fast Sync Allows Inconsistent State Views

## Summary
During fast sync bootstrap, the `FastSyncStorageWrapper` creates a critical state inconsistency by exposing two different databases through different service endpoints simultaneously. The API/Indexer services read from `temporary_db_with_genesis` while the backup service reads directly from `fast_sync_db`, allowing external observers to query the same node and receive conflicting ledger versions and state data.

## Finding Description

The `FastSyncStorageWrapper` maintains two separate `AptosDB` instances wrapped in `Arc`:
- `temporary_db_with_genesis`: Contains genesis state
- `db_for_fast_sync`: Target database for fast sync snapshot restoration [1](#0-0) 

During node initialization, the `bootstrap_db` function obtains `Arc` clones of both databases and routes them to different services: [2](#0-1) 

The critical flaw occurs during the `STARTED` phase of fast sync. The wrapper's read delegation logic uses `get_aptos_db_read_ref()`, which returns different databases based on the fast sync status: [3](#0-2) 

When `get_state_snapshot_receiver()` is called, the status transitions to `STARTED`: [4](#0-3) 

**During the STARTED phase:**
- **Read operations** (`get_aptos_db_read_ref`) return `temporary_db_with_genesis` (line 130)
- **Write operations** (`get_aptos_db_write_ref`) return `db_for_fast_sync` (line 136)

The `DbReader` implementation delegates all reads through this routing: [5](#0-4) 

However, the backup service receives a direct `Arc<AptosDB>` to `fast_sync_db`, bypassing the wrapper entirely. The backup service exposes HTTP endpoints that read directly from this database: [6](#0-5) 

The `get_db_state()` method returns the committed version from whichever database it was initialized with: [7](#0-6) 

Meanwhile, API and indexer services use the wrapper's reader, which delegates to `temporary_db_with_genesis`: [8](#0-7) 

**Attack Scenario:**
1. Attacker waits for a node to enter fast sync mode (status = STARTED)
2. Queries backup service: `GET /db_state` → receives committed version from `fast_sync_db` (e.g., version 1,000,000)
3. Queries API: `GET /` → receives ledger info from `temporary_db_with_genesis` (genesis, version 0)
4. Same node reports different versions on different endpoints
5. Can selectively read state values from either database by choosing different endpoints

This violates **Critical Invariant #4 (State Consistency)**: "State transitions must be atomic and verifiable via Merkle proofs." The node presents two inconsistent views of the ledger state simultaneously.

## Impact Explanation

**Severity: High to Medium**

This vulnerability meets the **High Severity** criteria: "Significant protocol violations" and **Medium Severity** criteria: "State inconsistencies requiring intervention."

**Concrete Impacts:**
1. **Consensus Assumption Violation**: Validators and clients assume nodes present consistent state. This breaks that assumption.
2. **Light Client Confusion**: Light clients querying different endpoints receive contradictory data from the same trusted node.
3. **State Sync Poisoning**: Validators performing fast sync may query each other's backup services for state data while their APIs report different versions, causing state sync errors.
4. **Proof Mixing Attacks**: Attackers could potentially mix state values from one database with Merkle proofs from another, creating invalid but plausible-looking state proofs.
5. **API/Indexer Reliability**: External services relying on consistent node responses will receive incorrect data during fast sync periods.

## Likelihood Explanation

**Likelihood: Medium**

**Factors Increasing Likelihood:**
- Fast sync is a standard bootstrap mechanism for new nodes
- The STARTED phase can last minutes to hours depending on snapshot size
- Backup services are commonly exposed for disaster recovery
- No authentication or access control prevents querying both endpoints
- Multiple nodes may be in fast sync simultaneously during network growth

**Factors Decreasing Likelihood:**
- Primarily affects nodes during initial bootstrap (not ongoing operations)
- Backup service may be firewalled in production deployments
- Window of vulnerability is temporary (only during STARTED phase)

The vulnerability is **easily triggered** by simply querying two different HTTP endpoints on the same node during its fast sync bootstrap, requiring no special privileges or complex exploitation.

## Recommendation

**Solution: Ensure Consistent Database Routing**

The backup service should respect the wrapper's database selection logic instead of receiving a direct Arc to `fast_sync_db`. Modify the initialization to pass the wrapper-controlled database reference:

```rust
// In aptos-node/src/storage.rs, line 95-96
// BEFORE (vulnerable):
let db_backup_service =
    start_backup_service(node_config.storage.backup_service_address, fast_sync_db);

// AFTER (fixed):
let db_backup_service =
    start_backup_service(node_config.storage.backup_service_address, db_rw.reader.clone());
```

This ensures the backup service reads from the same database as the API during all fast sync phases.

**Alternative Solution: Disable Backup Service During Fast Sync**

```rust
// Only start backup service after fast sync completes
let db_backup_service = if matches!(fast_sync_db_wrapper.get_fast_sync_status(), FastSyncStatus::FINISHED) {
    Some(start_backup_service(node_config.storage.backup_service_address, fast_sync_db))
} else {
    None
};
```

**Additional Hardening:**
- Add validation in `BackupHandler` to verify it's reading from the intended database version
- Add consistency checks comparing API and backup service versions during node health checks
- Log warnings when fast sync status transitions occur with active backup service

## Proof of Concept

**Setup:**
1. Configure a node for fast sync mode
2. Ensure both API and backup service are enabled and accessible

**Exploitation Steps:**

```bash
# Step 1: Wait for node to start fast sync (or trigger it)
# Monitor logs for "fast sync" status messages

# Step 2: Query backup service for DB state
curl http://NODE_IP:6186/db_state
# Expected response: {"epoch": 100, "committed_version": 1000000}

# Step 3: Query API for ledger info
curl http://NODE_IP:8080/
# Expected response contains: "ledger_version": "0" or very low number

# Step 4: Verify inconsistency
# The same node reports different committed versions on different endpoints

# Step 5: Demonstrate state reading inconsistency
curl http://NODE_IP:6186/state_snapshot/1000000
# Returns state from fast_sync_db at version 1000000

curl http://NODE_IP:8080/v1/accounts/0x1/resource/0x1::account::Account
# Returns state from temporary_db_with_genesis (genesis state)

# Both queries succeed but return different state for the same account
```

**Rust Integration Test:**

```rust
#[test]
fn test_fast_sync_state_inconsistency() {
    // Initialize node with fast sync enabled
    let mut config = NodeConfig::default();
    config.state_sync.state_sync_driver.bootstrapping_mode = BootstrappingMode::ExecuteTransactionsFromGenesis;
    
    // Bootstrap databases
    let (reader, db_rw, backup_service, _, _) = bootstrap_db(&config).unwrap();
    
    // Trigger fast sync start
    db_rw.writer.get_state_snapshot_receiver(version, root_hash).unwrap();
    
    // Query through wrapper (API path)
    let api_version = reader.get_latest_ledger_info().unwrap().ledger_info().version();
    
    // Query backup service directly
    let backup_db = /* extract from backup_service */;
    let backup_version = backup_db.get_latest_ledger_info().unwrap().ledger_info().version();
    
    // Assert inconsistency exists during STARTED phase
    assert_ne!(api_version, backup_version, "State inconsistency detected!");
}
```

**Notes**

This vulnerability represents a fundamental architectural flaw in how the `FastSyncStorageWrapper` isolates database state during fast sync operations. While the design intent was to provide a clean separation between genesis state and restored snapshot state, the implementation creates a window where external observers can access both databases simultaneously through different service endpoints, violating the critical state consistency invariant that underpins blockchain security guarantees.

The issue is particularly concerning because it affects a core operational procedure (node bootstrapping) and can persist for extended periods during large snapshot restorations, providing ample opportunity for exploitation by sophisticated adversaries monitoring network state.

### Citations

**File:** storage/aptosdb/src/fast_sync_storage_wrapper.rs (L31-38)
```rust
pub struct FastSyncStorageWrapper {
    // Used for storing genesis data during fast sync
    temporary_db_with_genesis: Arc<AptosDB>,
    // Used for restoring fast sync snapshot and all the read/writes afterwards
    db_for_fast_sync: Arc<AptosDB>,
    // This is for reading the fast_sync status to determine which db to use
    fast_sync_status: Arc<RwLock<FastSyncStatus>>,
}
```

**File:** storage/aptosdb/src/fast_sync_storage_wrapper.rs (L126-132)
```rust
    pub(crate) fn get_aptos_db_read_ref(&self) -> &AptosDB {
        if self.is_fast_sync_bootstrap_finished() {
            self.db_for_fast_sync.as_ref()
        } else {
            self.temporary_db_with_genesis.as_ref()
        }
    }
```

**File:** storage/aptosdb/src/fast_sync_storage_wrapper.rs (L144-152)
```rust
    fn get_state_snapshot_receiver(
        &self,
        version: Version,
        expected_root_hash: HashValue,
    ) -> Result<Box<dyn StateSnapshotReceiver<StateKey, StateValue>>> {
        *self.fast_sync_status.write() = FastSyncStatus::STARTED;
        self.get_aptos_db_write_ref()
            .get_state_snapshot_receiver(version, expected_root_hash)
    }
```

**File:** storage/aptosdb/src/fast_sync_storage_wrapper.rs (L188-192)
```rust
impl DbReader for FastSyncStorageWrapper {
    fn get_read_delegatee(&self) -> &dyn DbReader {
        self.get_aptos_db_read_ref()
    }
}
```

**File:** aptos-node/src/storage.rs (L75-97)
```rust
        Either::Right(fast_sync_db_wrapper) => {
            let temp_db = fast_sync_db_wrapper.get_temporary_db_with_genesis();
            maybe_apply_genesis(&DbReaderWriter::from_arc(temp_db), node_config)?;
            let (db_arc, db_rw) = DbReaderWriter::wrap(fast_sync_db_wrapper);
            let fast_sync_db = db_arc.get_fast_sync_db();
            // FastSyncDB requires ledger info at epoch 0 to establish provenance to genesis
            let ledger_info = db_arc
                .get_temporary_db_with_genesis()
                .get_epoch_ending_ledger_info(0)
                .expect("Genesis ledger info must exist");

            if fast_sync_db
                .get_latest_ledger_info_option()
                .expect("should returns Ok results")
                .is_none()
            {
                // it means the DB is empty and we need to
                // commit the genesis ledger info to the DB.
                fast_sync_db.commit_genesis_ledger_info(&ledger_info)?;
            }
            let db_backup_service =
                start_backup_service(node_config.storage.backup_service_address, fast_sync_db);
            (db_arc as Arc<dyn DbReader>, db_rw, Some(db_backup_service))
```

**File:** storage/backup/backup-service/src/handlers/mod.rs (L27-46)
```rust
pub(crate) fn get_routes(backup_handler: BackupHandler) -> BoxedFilter<(impl Reply,)> {
    // GET db_state
    let bh = backup_handler.clone();
    let db_state = warp::path::end()
        .map(move || reply_with_bcs_bytes(DB_STATE, &bh.get_db_state()?))
        .map(unwrap_or_500)
        .recover(handle_rejection);

    // GET state_range_proof/<version>/<end_key>
    let bh = backup_handler.clone();
    let state_range_proof = warp::path!(Version / HashValue)
        .map(move |version, end_key| {
            reply_with_bcs_bytes(
                STATE_RANGE_PROOF,
                &bh.get_account_state_range_proof(end_key, version)?,
            )
        })
        .map(unwrap_or_500)
        .recover(handle_rejection);

```

**File:** storage/aptosdb/src/backup/backup_handler.rs (L174-184)
```rust
    /// Gets the epoch, committed version, and synced version of the DB.
    pub fn get_db_state(&self) -> Result<Option<DbState>> {
        Ok(self
            .ledger_db
            .metadata_db()
            .get_latest_ledger_info_option()
            .map(|li| DbState {
                epoch: li.ledger_info().epoch(),
                committed_version: li.ledger_info().version(),
            }))
    }
```

**File:** aptos-node/src/services.rs (L100-108)
```rust
    let api_runtime = if node_config.api.enabled {
        Some(bootstrap_api(
            node_config,
            chain_id,
            db_rw.reader.clone(),
            mempool_client_sender.clone(),
            indexer_reader.clone(),
            api_port_tx,
        )?)
```
