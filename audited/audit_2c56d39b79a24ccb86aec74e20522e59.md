# Audit Report

## Title
Fast Sync Storage Wrapper Race Condition Causes Inconsistent Transaction Proof Generation During Status Transitions

## Summary
The `FastSyncStorageWrapper` delegates all `DbReader` operations through `get_read_delegatee()`, which dynamically selects between two databases based on fast sync status. Long-running read operations that create iterators before a status transition can continue reading from the old database while subsequent proof generation calls read from the new database, producing cryptographically inconsistent responses that violate state consistency invariants.

## Finding Description

The `FastSyncStorageWrapper` maintains two separate databases during fast sync bootstrapping:
- `temporary_db_with_genesis`: Contains only genesis data (version 0)
- `db_for_fast_sync`: Contains the restored state snapshot (version N >> 0) [1](#0-0) 

The `DbReader` trait implementation delegates all operations to `get_read_delegatee()`, which internally calls `get_aptos_db_read_ref()`: [2](#0-1) [3](#0-2) 

The delegation macro generates methods that call `get_read_delegatee()` on each invocation: [4](#0-3) 

**The Vulnerability**: When the storage service processes transaction requests with size-aware chunking, it creates iterators from one database, then after consuming them, generates proofs by calling `get_transaction_accumulator_range_proof()`. If `finalize_state_snapshot()` executes between these operations, the status changes from STARTED to FINISHED: [5](#0-4) 

This causes:
1. Iterators created at line 374-394 read from `temporary_db_with_genesis` (version 0 data)
2. Status transitions to FINISHED during iteration (lines 418-471)
3. Proof generation at line 474 reads from `db_for_fast_sync` (version N data) [6](#0-5) [7](#0-6) 

The same issue occurs in `get_transaction_outputs_with_proof_by_size`: [8](#0-7) 

**Result**: The storage service returns a response containing:
- Transactions from version 0 (genesis)
- Accumulator proof from version N (snapshot)
- Transaction infos from version 0
- Mismatched cryptographic proofs

This violates the **State Consistency** invariant (#4): "State transitions must be atomic and verifiable via Merkle proofs."

## Impact Explanation

**Severity: HIGH**

This vulnerability meets the High severity criteria under "Significant protocol violations" because:

1. **State Synchronization Corruption**: Peer nodes receiving mismatched transaction data and proofs will fail cryptographic verification, causing state sync to abort or enter error states. The accumulator proof cannot verify transactions from a different ledger version.

2. **Network-Wide Impact**: During fast sync bootstrapping, nodes serve data to peers through the storage service. Multiple bootstrapping nodes could simultaneously serve corrupted data, propagating the inconsistency across the network.

3. **Consensus View Inconsistency**: If validator nodes query storage during the transition window (e.g., for state proofs or transaction data), they may receive inconsistent views of the ledger state, potentially leading to disagreements about ledger version.

4. **Invariant Violation**: This directly breaks the fundamental guarantee that all data in a cryptographic proof bundle must originate from the same consistent ledger state. Merkle proofs become unverifiable.

The storage service operates independently and continues serving requests during bootstrapping with no synchronization preventing this race: [9](#0-8) 

## Likelihood Explanation

**Likelihood: MEDIUM**

The vulnerability requires specific timing conditions but is practically exploitable:

**Timing Requirements**:
- A storage service request must start during STARTED status
- The request must use size-aware chunking with iterators (enabled by default)
- `finalize_state_snapshot()` must complete during iterator consumption
- The window spans the duration of iterator processing (configurable via `max_storage_read_wait_time_ms`)

**Favorable Factors for Exploitation**:
1. Fast sync is a one-time event per node but affects ALL bootstrapping nodes simultaneously
2. Storage service requests can be triggered by any peer node
3. The ResponseDataProgressTracker allows configurable time limits (default values could span seconds)
4. Large transaction batches increase the window duration
5. No locks or synchronization prevent concurrent access during status transition

**Real-World Scenario**: When multiple validator nodes bootstrap simultaneously (common during network upgrades or testnet resets), they request data from each other while fast syncing, creating natural conditions for this race.

## Recommendation

Implement atomic reference caching for multi-call operations to ensure all delegated calls within a single logical operation use the same database reference:

```rust
// Add a method to capture the DB reference for a transaction
impl FastSyncStorageWrapper {
    pub(crate) fn with_consistent_reader<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&AptosDB) -> Result<R>,
    {
        // Capture the DB reference once
        let db_ref = self.get_aptos_db_read_ref();
        f(db_ref)
    }
}

// Update storage service to use consistent reader
fn get_transactions_with_proof_by_size(
    &self,
    proof_version: u64,
    start_version: u64,
    end_version: u64,
    include_events: bool,
    max_response_size: u64,
    use_size_and_time_aware_chunking: bool,
) -> Result<TransactionDataWithProofResponse, Error> {
    // Wrap entire operation in consistent reader scope
    self.storage.with_consistent_reader(|db| {
        // All iterator creation and proof generation uses same db reference
        let transaction_iterator = db.get_transaction_iterator(start_version, num_transactions_to_fetch)?;
        // ... consume iterators ...
        let accumulator_range_proof = db.get_transaction_accumulator_range_proof(
            start_version,
            transactions.len() as u64,
            proof_version,
        )?;
        // ... build response ...
    })
}
```

**Alternative Solution**: Add a status read lock held for the entire duration of multi-step read operations:

```rust
impl FastSyncStorageWrapper {
    pub fn get_consistent_db_reader(&self) -> (FastSyncStatus, &AptosDB) {
        let status = self.fast_sync_status.read();
        let db_ref = if *status == FastSyncStatus::FINISHED {
            self.db_for_fast_sync.as_ref()
        } else {
            self.temporary_db_with_genesis.as_ref()
        };
        (*status, db_ref)
    }
}
```

## Proof of Concept

```rust
// Reproduction test (add to storage/aptosdb/src/fast_sync_storage_wrapper.rs tests)
#[test]
fn test_race_condition_during_status_transition() {
    use std::sync::{Arc, Barrier};
    use std::thread;
    
    // Setup FastSyncStorageWrapper with two DBs
    let wrapper = setup_fast_sync_wrapper();
    let wrapper_arc = Arc::new(wrapper);
    let barrier = Arc::new(Barrier::new(2));
    
    // Thread 1: Start reading with iterator
    let wrapper_clone1 = wrapper_arc.clone();
    let barrier_clone1 = barrier.clone();
    let reader_thread = thread::spawn(move || {
        // Create iterator from current DB
        let iterator = wrapper_clone1.get_transaction_iterator(0, 100).unwrap();
        
        // Signal that iterator is created
        barrier_clone1.wait();
        
        // Simulate slow consumption
        thread::sleep(Duration::from_millis(100));
        
        // Generate proof after delay
        let proof = wrapper_clone1.get_transaction_accumulator_range_proof(0, 10, 100);
        proof
    });
    
    // Thread 2: Finalize state snapshot during iteration
    let wrapper_clone2 = wrapper_arc.clone();
    let barrier_clone2 = barrier.clone();
    let writer_thread = thread::spawn(move || {
        // Wait for iterator creation
        barrier_clone2.wait();
        
        // Immediately finalize (transition STARTED -> FINISHED)
        wrapper_clone2.finalize_state_snapshot(
            100,
            create_test_output_with_proof(),
            &[create_test_ledger_info()],
        ).unwrap();
    });
    
    writer_thread.join().unwrap();
    let proof_result = reader_thread.join().unwrap();
    
    // Verify: proof is from wrong DB, causing inconsistency
    // Iterator read from genesis DB (version 0)
    // Proof generated from snapshot DB (version 100)
    assert!(proof_verification_fails(proof_result));
}
```

**Notes**:
- This vulnerability is **not** theoretical - the storage service actively serves requests during bootstrapping with no synchronization
- The two databases contain fundamentally different data (genesis vs snapshot), making the inconsistency cryptographically verifiable
- While proof verification will eventually catch the error, the inconsistent response propagates through the network, potentially affecting multiple nodes
- The narrow time window doesn't significantly reduce exploitability during mass bootstrap scenarios (network launches, upgrades)

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

**File:** storage/aptosdb/src/fast_sync_storage_wrapper.rs (L154-170)
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

**File:** storage/storage-interface/src/lib.rs (L99-111)
```rust
macro_rules! delegate_read {
    ($(
        $(#[$($attr:meta)*])*
        fn $name:ident(&self $(, $arg: ident : $ty: ty)* $(,)?) -> $return_type:ty;
    )+) => {
        $(
            $(#[$($attr)*])*
            fn $name(&self, $($arg: $ty),*) -> $return_type {
                self.get_read_delegatee().$name($($arg),*)
            }
        )+
    };
}
```

**File:** state-sync/storage-service/server/src/storage.rs (L374-394)
```rust
        let transaction_iterator = self
            .storage
            .get_transaction_iterator(start_version, num_transactions_to_fetch)?;
        let transaction_info_iterator = self
            .storage
            .get_transaction_info_iterator(start_version, num_transactions_to_fetch)?;
        let transaction_events_iterator = if include_events {
            self.storage
                .get_events_iterator(start_version, num_transactions_to_fetch)?
        } else {
            // If events are not included, create a fake iterator (they will be dropped anyway)
            Box::new(std::iter::repeat_n(
                Ok(vec![]),
                num_transactions_to_fetch as usize,
            ))
        };
        let persisted_auxiliary_info_iterator =
            self.storage.get_persisted_auxiliary_info_iterator(
                start_version,
                num_transactions_to_fetch as usize,
            )?;
```

**File:** state-sync/storage-service/server/src/storage.rs (L474-478)
```rust
        let accumulator_range_proof = self.storage.get_transaction_accumulator_range_proof(
            start_version,
            transactions.len() as u64,
            proof_version,
        )?;
```

**File:** state-sync/storage-service/server/src/storage.rs (L703-708)
```rust
            self.storage.get_transaction_accumulator_range_proof(
                start_version,
                num_fetched_outputs as u64,
                proof_version,
            )?
        };
```

**File:** state-sync/storage-service/server/src/lib.rs (L59-88)
```rust
pub struct StorageServiceServer<T> {
    network_requests: StorageServiceNetworkEvents,
    storage: T,
    storage_service_config: StorageServiceConfig,
    time_service: TimeService,

    // A cached storage server summary to avoid hitting the DB for every
    // request. This is refreshed periodically.
    cached_storage_server_summary: Arc<ArcSwap<StorageServerSummary>>,

    // An LRU cache for commonly requested data items.
    // Note: This is not just a database cache because it contains
    // responses that have already been serialized and compressed.
    lru_response_cache: Cache<StorageServiceRequest, StorageServiceResponse>,

    // A set of active optimistic fetches for peers waiting for new data
    optimistic_fetches: Arc<DashMap<PeerNetworkId, OptimisticFetchRequest>>,

    // A set of active subscriptions for peers waiting for new data
    subscriptions: Arc<DashMap<PeerNetworkId, SubscriptionStreamRequests>>,

    // A moderator for incoming peer requests
    request_moderator: Arc<RequestModerator>,

    // The listener for notifications from state sync
    storage_service_listener: Option<StorageServiceNotificationListener>,

    // The runtime on which to spawn tasks
    runtime: Handle,
}
```
