# Audit Report

## Title
Fast Sync Storage Wrapper Race Condition Causes Inconsistent Transaction Proof Generation During Status Transitions

## Summary
The `FastSyncStorageWrapper` delegates all `DbReader` operations through `get_read_delegatee()`, which dynamically selects between two databases based on fast sync status. Long-running read operations that create iterators before a status transition can continue reading from the old database while subsequent proof generation calls read from the new database, producing cryptographically inconsistent responses that violate state consistency invariants.

## Finding Description

The `FastSyncStorageWrapper` maintains two separate databases during fast sync bootstrapping: `temporary_db_with_genesis` (containing only genesis data at version 0) and `db_for_fast_sync` (containing the restored state snapshot at version N). [1](#0-0) 

The `DbReader` trait implementation delegates all operations to `get_read_delegatee()`, which internally calls `get_aptos_db_read_ref()` that switches between databases based on the `is_fast_sync_bootstrap_finished()` status check. [2](#0-1) [3](#0-2) 

The `delegate_read!` macro generates methods that call `get_read_delegatee()` on each individual invocation, not once per logical operation. [4](#0-3) 

**The Race Condition:** When the storage service processes transaction requests with size-aware chunking, it creates iterators from the storage, iterates through them (potentially for seconds based on `ResponseDataProgressTracker` timeout), then generates proofs by calling `get_transaction_accumulator_range_proof()`. [5](#0-4) [6](#0-5) 

The iterator creation binds to a specific AptosDB instance based on the lifetime `'_`, meaning it captures a reference to the database returned by `get_read_delegatee()` at that moment. [7](#0-6) 

If `finalize_state_snapshot()` executes during the iteration phase, it transitions the status from STARTED to FINISHED. [8](#0-7)  The subsequent call to `get_transaction_accumulator_range_proof()` will invoke `get_read_delegatee()` again, which now returns a reference to the different database.

The same pattern exists in `get_transaction_outputs_with_proof_by_size`. [9](#0-8) 

**Result:** The storage service returns transactions from version 0 (genesis) paired with accumulator proofs from version N (snapshot), creating cryptographically inconsistent responses that will fail verification at peer nodes.

**Critical Detail:** The storage service server and state sync driver start concurrently with no synchronization. [10](#0-9)  The storage service immediately handles network requests from peers while fast sync bootstrapping executes independently. [11](#0-10) 

## Impact Explanation

**Severity: HIGH**

This vulnerability qualifies as HIGH severity under "Significant protocol violations" because:

1. **State Synchronization Corruption**: Peer nodes receiving mismatched transaction data and proofs will fail cryptographic verification. The accumulator proof from version N cannot verify transactions from version 0, causing state sync to abort or enter error states.

2. **Network-Wide Impact**: During fast sync bootstrapping, nodes serve data to peers through the storage service. Multiple bootstrapping nodes could simultaneously serve corrupted data, propagating the inconsistency across the network during critical synchronization operations.

3. **Protocol Guarantee Violation**: This directly breaks the fundamental guarantee that all data in a cryptographic proof bundle must originate from the same consistent ledger state, making Merkle proofs unverifiable and violating state consistency invariants.

The storage service operates independently with concurrent request handling and no synchronization preventing this race condition with the fast sync finalization process.

## Likelihood Explanation

**Likelihood: MEDIUM**

The vulnerability requires specific timing conditions but is practically exploitable:

**Timing Requirements:**
- A storage service request must start during STARTED status
- The request must use size-aware chunking with iterators (enabled by default)
- `finalize_state_snapshot()` must complete during iterator consumption
- The window spans the duration of iterator processing, which is bounded by `max_storage_read_wait_time_ms` (default 10 seconds)

**Favorable Factors for Exploitation:**
1. Fast sync is a common operation when bootstrapping new nodes
2. Storage service requests can be triggered by any peer node
3. The `ResponseDataProgressTracker` allows configurable time limits that create non-trivial exploitation windows
4. Large transaction batches increase the window duration
5. No locks or synchronization prevent concurrent access during status transition
6. The `fast_sync_status` RwLock only protects the status value itself, not the entire read operation

**Real-World Scenario:** When multiple validator nodes bootstrap simultaneously (common during network upgrades or testnet resets), they naturally request data from each other while fast syncing, creating conditions for this race to occur.

## Recommendation

Implement one of the following solutions:

**Option 1 - Reference Counting with Atomic Status:**
Replace the status check mechanism with a reference-counted approach where operations acquire a "snapshot reference" at the start and hold it for the entire duration:

```rust
pub struct FastSyncStorageWrapper {
    temporary_db_with_genesis: Arc<AptosDB>,
    db_for_fast_sync: Arc<AptosDB>,
    current_db: Arc<RwLock<Arc<AptosDB>>>,
}

impl FastSyncStorageWrapper {
    fn get_aptos_db_read_ref(&self) -> Arc<AptosDB> {
        Arc::clone(&*self.current_db.read())
    }
    
    fn finalize_state_snapshot(...) -> Result<()> {
        // Wait for all ongoing operations to complete
        // before switching the database reference
        *self.current_db.write() = self.db_for_fast_sync.clone();
        ...
    }
}
```

**Option 2 - Pause Storage Service During Finalization:**
Add synchronization to prevent new storage service requests from starting during the critical transition period:

```rust
pub struct FastSyncStorageWrapper {
    ...
    operation_lock: Arc<RwLock<()>>,
}

impl DbReader for FastSyncStorageWrapper {
    fn get_read_delegatee(&self) -> &dyn DbReader {
        let _guard = self.operation_lock.read();
        self.get_aptos_db_read_ref()
    }
}

impl DbWriter for FastSyncStorageWrapper {
    fn finalize_state_snapshot(...) -> Result<()> {
        let _guard = self.operation_lock.write(); // Blocks new operations
        // Status transition now atomic with respect to operations
        ...
    }
}
```

**Option 3 - Single Atomic Operation:**
Modify the storage service methods to acquire a single consistent database reference for the entire operation rather than calling `get_read_delegatee()` multiple times.

## Proof of Concept

While a complete PoC would require setting up a full Aptos node environment, the vulnerability can be demonstrated through the following test scenario:

```rust
#[tokio::test]
async fn test_fast_sync_race_condition() {
    // 1. Initialize FastSyncStorageWrapper with STARTED status
    // 2. Spawn task 1: Storage service request that:
    //    - Calls get_transaction_iterator (gets temporary_db)
    //    - Sleeps/delays during iteration
    //    - Calls get_transaction_accumulator_range_proof
    // 3. Spawn task 2: During task 1's delay, call finalize_state_snapshot
    // 4. Verify that task 1 receives mismatched data:
    //    - Transactions from temporary_db_with_genesis (version 0)
    //    - Proofs from db_for_fast_sync (version N)
    // 5. Attempt to verify the proof against the transactions
    // 6. Assert that verification fails due to mismatch
}
```

The race condition is evident from the code structure where iterator creation and proof generation call `get_read_delegatee()` independently with no atomicity guarantee across the logical operation.

## Notes

This vulnerability is specific to the fast sync bootstrapping mode and only affects nodes during their initial synchronization phase. However, given that multiple nodes often bootstrap simultaneously during network events, the impact can be network-wide during these critical periods. The lack of synchronization between the storage service (which serves peer requests) and the state sync driver (which manages bootstrapping) is the root cause enabling this race condition.

### Citations

**File:** storage/aptosdb/src/fast_sync_storage_wrapper.rs (L30-38)
```rust
/// This is a wrapper around [AptosDB] that is used to bootstrap the node for fast sync mode
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

**File:** state-sync/storage-service/server/src/storage.rs (L373-394)
```rust
        // Get the iterators for the transaction, info, events and persisted auxiliary infos
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

**File:** state-sync/storage-service/server/src/storage.rs (L409-416)
```rust
        // Create a response progress tracker
        let mut response_progress_tracker = ResponseDataProgressTracker::new(
            num_transactions_to_fetch,
            max_response_size,
            self.config.max_storage_read_wait_time_ms,
            self.time_service.clone(),
        );

```

**File:** state-sync/storage-service/server/src/storage.rs (L418-478)
```rust
        while !response_progress_tracker.is_response_complete() {
            match multizip_iterator.next() {
                Some((Ok(transaction), Ok(info), Ok(events), Ok(persisted_auxiliary_info))) => {
                    // Calculate the number of serialized bytes for the data items
                    let num_transaction_bytes = get_num_serialized_bytes(&transaction)
                        .map_err(|error| Error::UnexpectedErrorEncountered(error.to_string()))?;
                    let num_info_bytes = get_num_serialized_bytes(&info)
                        .map_err(|error| Error::UnexpectedErrorEncountered(error.to_string()))?;
                    let num_events_bytes = get_num_serialized_bytes(&events)
                        .map_err(|error| Error::UnexpectedErrorEncountered(error.to_string()))?;
                    let num_auxiliary_info_bytes =
                        get_num_serialized_bytes(&persisted_auxiliary_info).map_err(|error| {
                            Error::UnexpectedErrorEncountered(error.to_string())
                        })?;

                    // Add the data items to the lists
                    let total_serialized_bytes = num_transaction_bytes
                        + num_info_bytes
                        + num_events_bytes
                        + num_auxiliary_info_bytes;
                    if response_progress_tracker
                        .data_items_fits_in_response(true, total_serialized_bytes)
                    {
                        transactions.push(transaction);
                        transaction_infos.push(info);
                        transaction_events.push(events);
                        persisted_auxiliary_infos.push(persisted_auxiliary_info);

                        response_progress_tracker.add_data_item(total_serialized_bytes);
                    } else {
                        break; // Cannot add any more data items
                    }
                },
                Some((Err(error), _, _, _))
                | Some((_, Err(error), _, _))
                | Some((_, _, Err(error), _))
                | Some((_, _, _, Err(error))) => {
                    return Err(Error::StorageErrorEncountered(error.to_string()));
                },
                None => {
                    // Log a warning that the iterators did not contain all the expected data
                    warn!(
                        "The iterators for transactions, transaction infos, events and \
                        persisted auxiliary infos are missing data! Start version: {:?}, \
                        end version: {:?}, num transactions to fetch: {:?}, num fetched: {:?}.",
                        start_version,
                        end_version,
                        num_transactions_to_fetch,
                        transactions.len()
                    );
                    break;
                },
            }
        }

        // Create the transaction info list with proof
        let accumulator_range_proof = self.storage.get_transaction_accumulator_range_proof(
            start_version,
            transactions.len() as u64,
            proof_version,
        )?;
```

**File:** state-sync/storage-service/server/src/storage.rs (L593-708)
```rust
        let transaction_iterator = self
            .storage
            .get_transaction_iterator(start_version, num_outputs_to_fetch)?;
        let transaction_info_iterator = self
            .storage
            .get_transaction_info_iterator(start_version, num_outputs_to_fetch)?;
        let transaction_write_set_iterator = self
            .storage
            .get_write_set_iterator(start_version, num_outputs_to_fetch)?;
        let transaction_events_iterator = self
            .storage
            .get_events_iterator(start_version, num_outputs_to_fetch)?;
        let persisted_auxiliary_info_iterator = self
            .storage
            .get_persisted_auxiliary_info_iterator(start_version, num_outputs_to_fetch as usize)?;
        let mut multizip_iterator = itertools::multizip((
            transaction_iterator,
            transaction_info_iterator,
            transaction_write_set_iterator,
            transaction_events_iterator,
            persisted_auxiliary_info_iterator,
        ));

        // Initialize the fetched data items
        let mut transactions_and_outputs = vec![];
        let mut transaction_infos = vec![];
        let mut persisted_auxiliary_infos = vec![];

        // Create a response progress tracker
        let mut response_progress_tracker = ResponseDataProgressTracker::new(
            num_outputs_to_fetch,
            max_response_size,
            self.config.max_storage_read_wait_time_ms,
            self.time_service.clone(),
        );

        // Fetch as many transaction outputs as possible
        while !response_progress_tracker.is_response_complete() {
            match multizip_iterator.next() {
                Some((
                    Ok(transaction),
                    Ok(info),
                    Ok(write_set),
                    Ok(events),
                    Ok(persisted_auxiliary_info),
                )) => {
                    // Create the transaction output
                    let output = TransactionOutput::new(
                        write_set,
                        events,
                        info.gas_used(),
                        info.status().clone().into(),
                        TransactionAuxiliaryData::None, // Auxiliary data is no longer supported
                    );

                    // Calculate the number of serialized bytes for the data items
                    let num_transaction_bytes = get_num_serialized_bytes(&transaction)
                        .map_err(|error| Error::UnexpectedErrorEncountered(error.to_string()))?;
                    let num_info_bytes = get_num_serialized_bytes(&info)
                        .map_err(|error| Error::UnexpectedErrorEncountered(error.to_string()))?;
                    let num_output_bytes = get_num_serialized_bytes(&output)
                        .map_err(|error| Error::UnexpectedErrorEncountered(error.to_string()))?;
                    let num_auxiliary_info_bytes =
                        get_num_serialized_bytes(&persisted_auxiliary_info).map_err(|error| {
                            Error::UnexpectedErrorEncountered(error.to_string())
                        })?;

                    // Add the data items to the lists
                    let total_serialized_bytes = num_transaction_bytes
                        + num_info_bytes
                        + num_output_bytes
                        + num_auxiliary_info_bytes;
                    if response_progress_tracker.data_items_fits_in_response(
                        !is_transaction_or_output_request,
                        total_serialized_bytes,
                    ) {
                        transactions_and_outputs.push((transaction, output));
                        transaction_infos.push(info);
                        persisted_auxiliary_infos.push(persisted_auxiliary_info);

                        response_progress_tracker.add_data_item(total_serialized_bytes);
                    } else {
                        break; // Cannot add any more data items
                    }
                },
                Some((Err(error), _, _, _, _))
                | Some((_, Err(error), _, _, _))
                | Some((_, _, Err(error), _, _))
                | Some((_, _, _, Err(error), _))
                | Some((_, _, _, _, Err(error))) => {
                    return Err(Error::StorageErrorEncountered(error.to_string()));
                },
                None => {
                    // Log a warning that the iterators did not contain all the expected data
                    warn!(
                        "The iterators for transactions, transaction infos, write sets, events, \
                        auxiliary data and persisted auxiliary infos are missing data! Start version: {:?}, \
                        end version: {:?}, num outputs to fetch: {:?}, num fetched: {:?}.",
                        start_version, end_version, num_outputs_to_fetch, transactions_and_outputs.len()
                    );
                    break;
                },
            }
        }

        // Create the transaction output list with proof
        let num_fetched_outputs = transactions_and_outputs.len();
        let accumulator_range_proof = if num_fetched_outputs == 0 {
            AccumulatorRangeProof::new_empty() // Return an empty proof if no outputs were fetched
        } else {
            self.storage.get_transaction_accumulator_range_proof(
                start_version,
                num_fetched_outputs as u64,
                proof_version,
            )?
        };
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L477-492)
```rust
    fn get_transaction_iterator(
        &self,
        start_version: Version,
        limit: u64,
    ) -> Result<Box<dyn Iterator<Item = Result<Transaction>> + '_>> {
        gauged_api("get_transaction_iterator", || {
            error_if_too_many_requested(limit, MAX_REQUEST_LIMIT)?;
            self.error_if_ledger_pruned("Transaction", start_version)?;

            let iter = self
                .ledger_db
                .transaction_db()
                .get_transaction_iter(start_version, limit as usize)?;
            Ok(Box::new(iter) as Box<dyn Iterator<Item = Result<Transaction>> + '_>)
        })
    }
```

**File:** aptos-node/src/state_sync.rs (L174-198)
```rust
    // Start the state sync storage service
    let storage_service_runtime = setup_state_sync_storage_service(
        state_sync_config,
        peers_and_metadata,
        network_service_events,
        &db_rw,
        storage_service_listener,
    )?;

    // Create the state sync driver factory
    let state_sync = DriverFactory::create_and_spawn_driver(
        true,
        node_config,
        waypoint,
        db_rw,
        chunk_executor,
        mempool_notifier,
        storage_service_notifier,
        metadata_storage,
        consensus_listener,
        event_subscription_service,
        aptos_data_client.clone(),
        streaming_service_client,
        TimeService::real(),
    );
```
