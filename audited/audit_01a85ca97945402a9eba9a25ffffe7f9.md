# Audit Report

## Title
Consensus Observer Startup Panic Due to Unsafe `expect()` on Empty Database

## Summary
The `ObserverBlockData::new()` function in the consensus observer module uses an unsafe `.expect()` call on `get_latest_ledger_info()`, causing an unrecoverable panic when the database is uninitialized. This prevents consensus observer nodes from bootstrapping via state sync when joining existing networks with an empty database.

## Finding Description

The vulnerability exists in the consensus observer initialization code where `ObserverBlockData::new()` unconditionally expects storage to contain ledger information: [1](#0-0) 

This function is called during `ConsensusObserver::new()` as part of the node startup sequence: [2](#0-1) 

The `get_latest_ledger_info()` method returns an error when the database has no ledger information: [3](#0-2) [4](#0-3) 

**Attack Path:**

1. A consensus observer node is deployed to join an existing Aptos network
2. The node is configured without genesis transaction (expecting to sync from network via state sync)
3. During startup, database initialization succeeds but applies no genesis: [5](#0-4) 

4. The startup sequence proceeds to consensus observer creation: [6](#0-5) [7](#0-6) 

5. `ObserverBlockData::new()` calls `db_reader.get_latest_ledger_info().expect(...)` which panics because the database contains no ledger info
6. The entire observer node crashes before it can begin state syncing from the network

This violates the design expectation that consensus observers can join existing networks via state sync without requiring local genesis initialization.

## Impact Explanation

**Severity: High** per Aptos bug bounty criteria ("Validator node slowdowns / API crashes / Significant protocol violations")

**Impact:**
- **Total Observer Node Unavailability**: The panic occurs during the initialization path, causing the entire observer runtime to crash
- **Cannot Join Network**: Observer nodes cannot bootstrap via state sync because they crash before state sync can retrieve any data
- **Operational DoS**: Legitimate deployments of consensus observers to join existing networks are blocked
- **No Recovery Path**: Without genesis data or manual database population, the node cannot start

While consensus observers don't participate in consensus voting, they are part of the broader consensus ecosystem and forward blocks to execution. This panic prevents them from fulfilling their role.

## Likelihood Explanation

**Likelihood: Medium to High**

This issue will occur in any deployment scenario where:
- A consensus observer node is joining an existing network (common operational scenario)
- The database is empty (first startup or after data loss)
- No genesis transaction is configured (expected when joining via state sync)

The Aptos documentation and configuration suggest that observers can join networks via state sync, making this a realistic operational scenario. The code even explicitly acknowledges this with the message "This is fine only if you don't expect to apply it" when genesis is not provided.

## Recommendation

Replace the unsafe `.expect()` call with proper error handling that allows the observer to initialize with an empty ledger info and bootstrap via state sync:

```rust
pub fn new(
    consensus_observer_config: ConsensusObserverConfig,
    db_reader: Arc<dyn DbReader>,
) -> Self {
    // Get the latest ledger info from storage (or use a default if unavailable)
    let root = db_reader
        .get_latest_ledger_info()
        .unwrap_or_else(|_| {
            // Create a dummy/empty ledger info for uninitialized databases
            // The observer will update this once it syncs from the network
            warn!("No ledger info found in storage. Observer will bootstrap via state sync.");
            create_empty_ledger_info()
        });

    // Create the observer block data
    Self::new_with_root(consensus_observer_config, root)
}
```

Alternatively, defer the ledger info retrieval until after state sync has initialized:

```rust
pub fn new(
    consensus_observer_config: ConsensusObserverConfig,
    db_reader: Arc<dyn DbReader>,
) -> Result<Self, Error> {
    // Attempt to get latest ledger info, return error if unavailable
    let root = db_reader
        .get_latest_ledger_info()
        .map_err(|e| Error::StorageError(format!("Failed to read ledger info: {}", e)))?;
    
    Ok(Self::new_with_root(consensus_observer_config, root))
}
```

Then handle this error in the caller by allowing the observer to initialize after state sync completes initial bootstrapping.

## Proof of Concept

**Reproduction Steps:**

1. Configure an Aptos node as a consensus observer without genesis transaction:
```yaml
consensus_observer:
  observer_enabled: true
  
execution:
  genesis_waypoint: null  # No genesis configured
```

2. Start the node with an empty database directory

3. Observe the panic during startup:
```
thread 'tokio-runtime-worker' panicked at 'Failed to read latest ledger info from storage!', 
consensus/src/consensus_observer/observer/block_data.rs:62:14
```

4. The observer runtime crashes and the node cannot start

**Expected Behavior:**
The observer should start successfully, wait for state sync to retrieve initial data from the network, then begin observing consensus.

**Actual Behavior:**
The observer panics during initialization and never becomes operational.

## Notes

This vulnerability specifically affects consensus observer nodes, not validator nodes. Validators require genesis and would fail earlier in the startup sequence. However, observers are explicitly designed to join existing networks via state sync, making this a critical operational issue for the consensus observer feature.

The fix requires careful consideration of the bootstrap flow to ensure the observer can initialize with minimal state and update once state sync provides actual network data.

### Citations

**File:** consensus/src/consensus_observer/observer/block_data.rs (L55-66)
```rust
    pub fn new(
        consensus_observer_config: ConsensusObserverConfig,
        db_reader: Arc<dyn DbReader>,
    ) -> Self {
        // Get the latest ledger info from storage
        let root = db_reader
            .get_latest_ledger_info()
            .expect("Failed to read latest ledger info from storage!");

        // Create the observer block data
        Self::new_with_root(consensus_observer_config, root)
    }
```

**File:** consensus/src/consensus_observer/observer/consensus_observer.rs (L94-154)
```rust
    pub fn new(
        node_config: NodeConfig,
        consensus_observer_client: Arc<
            ConsensusObserverClient<NetworkClient<ConsensusObserverMessage>>,
        >,
        db_reader: Arc<dyn DbReader>,
        execution_client: Arc<dyn TExecutionClient>,
        state_sync_notification_sender: UnboundedSender<StateSyncNotification>,
        reconfig_events: Option<ReconfigNotificationListener<DbBackedOnChainConfig>>,
        consensus_publisher: Option<Arc<ConsensusPublisher>>,
        time_service: TimeService,
    ) -> Self {
        // Get the consensus observer config
        let consensus_observer_config = node_config.consensus_observer;

        // Create the observer fallback manager
        let observer_fallback_manager = ObserverFallbackManager::new(
            consensus_observer_config,
            db_reader.clone(),
            time_service.clone(),
        );

        // Create the state sync manager
        let state_sync_manager = StateSyncManager::new(
            consensus_observer_config,
            execution_client.clone(),
            state_sync_notification_sender,
        );

        // Create the subscription manager
        let subscription_manager = SubscriptionManager::new(
            consensus_observer_client,
            consensus_observer_config,
            consensus_publisher.clone(),
            db_reader.clone(),
            time_service.clone(),
        );

        // Create the observer epoch state
        let reconfig_events =
            reconfig_events.expect("Reconfig events should exist for the consensus observer!");
        let observer_epoch_state =
            ObserverEpochState::new(node_config, reconfig_events, consensus_publisher);

        // Create the observer block data
        let observer_block_data = Arc::new(Mutex::new(ObserverBlockData::new(
            consensus_observer_config,
            db_reader,
        )));

        // Create the consensus observer
        Self {
            execution_client,
            observer_block_data,
            observer_epoch_state,
            observer_fallback_manager,
            state_sync_manager,
            subscription_manager,
            pipeline_builder: None,
        }
    }
```

**File:** storage/storage-interface/src/lib.rs (L526-530)
```rust
    fn get_latest_ledger_info(&self) -> Result<LedgerInfoWithSignatures> {
        self.get_latest_ledger_info_option().and_then(|opt| {
            opt.ok_or_else(|| AptosDbError::Other("Latest LedgerInfo not found.".to_string()))
        })
    }
```

**File:** storage/aptosdb/src/ledger_db/ledger_metadata_db.rs (L107-110)
```rust
    pub(crate) fn get_latest_ledger_info(&self) -> Result<LedgerInfoWithSignatures> {
        self.get_latest_ledger_info_option()
            .ok_or_else(|| AptosDbError::NotFound(String::from("Genesis LedgerInfo")))
    }
```

**File:** aptos-node/src/storage.rs (L34-42)
```rust
    if let Some(genesis) = get_genesis_txn(node_config) {
        let ledger_info_opt =
            maybe_bootstrap::<AptosVMBlockExecutor>(db_rw, genesis, genesis_waypoint)
                .map_err(|err| anyhow!("DB failed to bootstrap {}", err))?;
        Ok(ledger_info_opt)
    } else {
        info ! ("Genesis txn not provided! This is fine only if you don't expect to apply it. Otherwise, the config is incorrect!");
        Ok(None)
    }
```

**File:** aptos-node/src/lib.rs (L704-705)
```rust
    let (db_rw, backup_service, genesis_waypoint, indexer_db_opt, update_receiver) =
        storage::initialize_database_and_checkpoints(&mut node_config)?;
```

**File:** aptos-node/src/lib.rs (L824-838)
```rust
    // Wait until state sync has been initialized
    debug!("Waiting until state sync is initialized!");
    state_sync_runtimes.block_until_initialized();
    debug!("State sync initialization complete.");

    // Create the consensus observer and publisher (if enabled)
    let (consensus_observer_runtime, consensus_publisher_runtime, consensus_publisher) =
        consensus::create_consensus_observer_and_publisher(
            &node_config,
            consensus_observer_network_interfaces,
            consensus_notifier.clone(),
            consensus_to_mempool_sender.clone(),
            db_rw.clone(),
            consensus_observer_reconfig_subscription,
        );
```
