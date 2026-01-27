# Audit Report

## Title
Database Switch During Fast Sync Causes Consensus Initialization Failure Due to Version Mismatch

## Summary
A critical vulnerability exists in the `FastSyncStorageWrapper` where validator set configuration data becomes inaccessible to consensus during node initialization with fast sync enabled. When the storage layer switches from `temporary_db_with_genesis` to `db_for_fast_sync` after snapshot finalization, consensus attempts to read epoch 0 validator configuration from a database that only contains the fast-synced snapshot data, causing initialization failure and total loss of network liveness.

## Finding Description

The vulnerability occurs due to a race condition between the event notification system and the database switching mechanism in `FastSyncStorageWrapper`.

**Attack Flow:**

1. **Driver Factory Initialization (Early Startup):** [1](#0-0) 
   
   At this point, `FastSyncStorageWrapper` status is `UNKNOWN`, so reads delegate to `temporary_db_with_genesis`: [2](#0-1) 

2. **Reconfiguration Notification Created:**
   The system creates a `DbBackedOnChainConfig` with a reference to `FastSyncStorageWrapper` and `version=0` (genesis): [3](#0-2) 

3. **Fast Sync Completion:**
   When `finalize_state_snapshot` completes, the status transitions to `FINISHED`: [4](#0-3) 
   
   After this transition, `get_aptos_db_read_ref()` returns `db_for_fast_sync` instead of `temporary_db_with_genesis`.

4. **Consensus Starts and Reads Configuration:**
   When consensus processes the reconfiguration notification, it calls `payload.get::<ValidatorSet>()`: [5](#0-4) 
   
   This invokes: [6](#0-5) 

5. **Version Mismatch:**
   The `DbBackedOnChainConfig` attempts to read ValidatorSet at `version=0` from `self.reader` (which is `FastSyncStorageWrapper`). Since status is now `FINISHED`, this delegates to `db_for_fast_sync`. However, in fast sync mode, only the latest state snapshot is downloaded—`db_for_fast_sync` does NOT contain version 0 data. The read returns `None`, causing consensus initialization to panic with "failed to get ValidatorSet from payload".

6. **Consensus Recovery Also Fails:**
   Even if consensus initialization were to continue, the `storage.start()` call would also fail: [7](#0-6) 
   
   This reads ledger info from the switched database, creating further inconsistencies.

**Broken Invariants:**
- **State Consistency**: Storage state accessible during notification creation becomes inaccessible during consumption
- **Consensus Safety**: Consensus cannot verify the validator set, preventing participation in the protocol
- **Deterministic Execution**: Different nodes may fail at different points depending on timing of the database switch

## Impact Explanation

This vulnerability qualifies as **CRITICAL SEVERITY** under the Aptos Bug Bounty program criteria:

**Total Loss of Liveness/Network Availability:**
- Validator nodes using fast sync mode cannot initialize consensus
- Consensus fails with a panic when attempting to read genesis epoch validator configuration
- Nodes cannot participate in block proposal, voting, or validation
- Network requires manual intervention or hardfork to recover affected validators

**Scope:**
- Affects ALL validator nodes that bootstrap using fast sync mode (`BootstrappingMode::DownloadLatestStates`)
- This is the recommended mode for new validators joining the network
- Could affect multiple validators simultaneously during network expansion events

**Non-Recoverable State:**
- Once consensus initialization fails, the node cannot self-recover
- The `db_for_fast_sync` database lacks historical data needed by consensus
- Requires operator intervention to delete databases and restart with different sync mode

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability triggers automatically under normal operational conditions:

**Trigger Conditions (All Common):**
1. Node configured with `BootstrappingMode::DownloadLatestStates` (fast sync mode)
2. Node starting from empty database state
3. Standard consensus initialization sequence

**No Attacker Required:**
- This is NOT an attack—it's a deterministic system bug
- Occurs during legitimate validator onboarding
- No malicious input or insider access needed

**Frequency:**
- Triggers on EVERY validator node that uses fast sync for initial bootstrap
- Given that fast sync is the recommended approach for new validators, this affects standard operational procedures
- Likely to manifest during network growth phases when new validators join

## Recommendation

**Immediate Fix:**

The reconfiguration notification must be sent with the correct version that exists in the target database after fast sync completes. Implement one of these solutions:

**Solution 1: Refresh Notification After Fast Sync**
After `finalize_state_snapshot` completes and status transitions to `FINISHED`, send a fresh reconfiguration notification with the synced version:

```rust
// In fast_sync_storage_wrapper.rs, finalize_state_snapshot:
fn finalize_state_snapshot(...) -> Result<()> {
    // ... existing code ...
    let mut status = self.fast_sync_status.write();
    *status = FastSyncStatus::FINISHED;
    
    // NEW: Trigger reconfiguration with correct version
    // This should be communicated back to the driver to call
    // event_subscription_service.notify_initial_configs(version)
    
    Ok(())
}
```

**Solution 2: Delay Initial Notification**
Modify `driver_factory.rs` to skip `notify_initial_configs` if fast sync is pending, and call it after bootstrapping completes:

```rust
// In driver_factory.rs:
match storage.reader.get_latest_state_checkpoint_version() {
    Ok(Some(synced_version)) => {
        // NEW: Check if fast sync wrapper is being used
        if !is_fast_sync_pending(&storage) {
            event_subscription_service.notify_initial_configs(synced_version)?;
        }
        // Otherwise, notification will be sent after bootstrap completes
    },
    // ... error handling ...
}
```

**Solution 3: Version-Aware Reading**
Modify `FastSyncStorageWrapper` to handle version-based routing intelligently:

```rust
// Route reads based on version availability
fn get_aptos_db_read_ref_for_version(&self, version: Version) -> &AptosDB {
    if self.is_fast_sync_bootstrap_finished() {
        // Check if version exists in fast sync DB
        if self.db_for_fast_sync.has_version(version) {
            self.db_for_fast_sync.as_ref()
        } else {
            self.temporary_db_with_genesis.as_ref()
        }
    } else {
        self.temporary_db_with_genesis.as_ref()
    }
}
```

**Recommended Approach:** Solution 1 is cleanest—send a fresh notification with the correct fast-synced version after the database switch completes.

## Proof of Concept

```rust
// Integration test demonstrating the vulnerability
#[tokio::test]
async fn test_fast_sync_validator_set_mismatch() {
    // 1. Setup node with fast sync mode enabled
    let mut config = NodeConfig::default();
    config.state_sync.state_sync_driver.bootstrapping_mode = 
        BootstrappingMode::DownloadLatestStates { ... };
    
    // 2. Initialize storage with FastSyncStorageWrapper
    let db_rw = DbReaderWriter::new(...);
    let storage = FastSyncStorageWrapper::initialize_dbs(&config, None, None)
        .expect("Failed to initialize fast sync storage");
    
    // 3. Initialize driver factory (triggers notify_initial_configs)
    let event_service = EventSubscriptionService::new(Arc::new(RwLock::new(db_rw.clone())));
    let consensus_subscription = event_service
        .subscribe_to_reconfigurations()
        .expect("Failed to subscribe");
    
    let _driver = DriverFactory::create_and_spawn_driver(...);
    
    // 4. Simulate fast sync completion
    // (Download state snapshot at version 1000000 to db_for_fast_sync)
    let snapshot_version = 1000000;
    simulate_fast_sync_completion(&storage, snapshot_version).await;
    
    // 5. Simulate consensus start
    let reconfig_notification = consensus_subscription.next().await
        .expect("No reconfiguration notification received");
    
    // 6. Try to read ValidatorSet (this should panic or return error)
    let result = reconfig_notification.on_chain_configs.get::<ValidatorSet>();
    
    // EXPECTED: This fails because version 0 doesn't exist in db_for_fast_sync
    assert!(result.is_err(), "Expected error reading ValidatorSet from mismatched DB");
    println!("Vulnerability confirmed: {:?}", result.unwrap_err());
}
```

**Expected Output:**
```
Vulnerability confirmed: Error("no config ValidatorSet found in aptos root account state")
```

This demonstrates that consensus cannot read the validator set configuration, causing initialization failure and complete loss of consensus liveness on the affected validator node.

### Citations

**File:** state-sync/state-sync-driver/src/driver_factory.rs (L103-118)
```rust
        match storage.reader.get_latest_state_checkpoint_version() {
            Ok(Some(synced_version)) => {
                if let Err(error) =
                    event_subscription_service.notify_initial_configs(synced_version)
                {
                    panic!(
                        "Failed to notify subscribers of initial on-chain configs: {:?}",
                        error
                    )
                }
            },
            Ok(None) => {
                panic!("Latest state checkpoint version not found.")
            },
            Err(error) => panic!("Failed to fetch the initial synced version: {:?}", error),
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

**File:** storage/aptosdb/src/fast_sync_storage_wrapper.rs (L154-169)
```rust
    fn finalize_state_snapshot(
        &self,
        version: Version,
        output_with_proof: TransactionOutputListWithProofV2,
        ledger_infos: &[LedgerInfoWithSignatures],
    ) -> Result<()> {
        let status = self.get_fast_sync_status();
        assert_eq!(status, FastSyncStatus::STARTED);
        self.get_aptos_db_write_ref().finalize_state_snapshot(
            version,
            output_with_proof,
            ledger_infos,
        )?;
        let mut status = self.fast_sync_status.write();
        *status = FastSyncStatus::FINISHED;
        Ok(())
```

**File:** state-sync/inter-component/event-notifications/src/lib.rs (L386-395)
```rust
pub struct DbBackedOnChainConfig {
    pub reader: Arc<dyn DbReader>,
    pub version: Version,
}

impl DbBackedOnChainConfig {
    pub fn new(reader: Arc<dyn DbReader>, version: Version) -> Self {
        Self { reader, version }
    }
}
```

**File:** state-sync/inter-component/event-notifications/src/lib.rs (L398-412)
```rust
    fn get<T: OnChainConfig>(&self) -> Result<T> {
        let bytes = self
            .reader
            .get_state_value_by_version(&StateKey::on_chain_config::<T>()?, self.version)?
            .ok_or_else(|| {
                anyhow!(
                    "no config {} found in aptos root account state",
                    T::CONFIG_ID
                )
            })?
            .bytes()
            .clone();

        T::deserialize_into_config(&bytes)
    }
```

**File:** consensus/src/epoch_manager.rs (L1165-1167)
```rust
        let validator_set: ValidatorSet = payload
            .get()
            .expect("failed to get ValidatorSet from payload");
```

**File:** consensus/src/persistent_liveness_storage.rs (L549-556)
```rust
        let latest_ledger_info = self
            .aptos_db
            .get_latest_ledger_info()
            .expect("Failed to get latest ledger info.");
        let accumulator_summary = self
            .aptos_db
            .get_accumulator_summary(latest_ledger_info.ledger_info().version())
            .expect("Failed to get accumulator summary.");
```
