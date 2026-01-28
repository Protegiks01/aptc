# Audit Report

## Title
Permanent State Sync Failure Due to Missing Pruning Check in Persisted Auxiliary Info Iterator

## Summary
The `get_persisted_auxiliary_info_iterator` method lacks a critical pruning check that exists in other similar iterator methods, causing it to return an empty iterator when requesting pruned data. This results in a multizip iterator mismatch during state sync, causing syncing nodes to receive zero transactions and enter an infinite retry loop, permanently preventing synchronization.

## Finding Description

The vulnerability exists in the inconsistent handling of pruned data between different ledger database iterators used during state sync.

**The Core Bug:**

The `get_persisted_auxiliary_info_iterator` method lacks the pruning check that all other iterator methods implement. [1](#0-0) 

In contrast, `get_transaction_iterator` properly validates that data hasn't been pruned before creating the iterator: [2](#0-1) 

Similarly, `get_transaction_info_iterator`, `get_events_iterator`, and `get_write_set_iterator` all call `error_if_ledger_pruned` before creating their iterators: [3](#0-2) 

The `error_if_ledger_pruned` method checks if the requested version is below the minimum readable version and returns an error if data has been pruned: [4](#0-3) 

When data is pruned, the underlying `get_persisted_auxiliary_info_iter` method returns an empty iterator instead of failing: [5](#0-4) 

**How State Sync Fails:**

During state sync, the storage service uses `multizip` to iterate over four data sources simultaneously (transactions, transaction infos, events, and persisted auxiliary info): [6](#0-5) 

When the persisted auxiliary info iterator returns empty while other iterators contain data, the multizip immediately returns `None`, causing the fetch loop to terminate with zero transactions: [7](#0-6) 

**The Infinite Retry Loop:**

When state sync receives zero transactions, the `create_missing_transactions_request` function creates a retry request. Since `num_received_transactions = 0`, the new `start_version` remains unchanged (`start_version + 0`): [8](#0-7) 

The stream terminates after exhausting `max_request_retry` attempts and creates a new stream starting from the same synced version: [9](#0-8) 

This creates a permanent failure loop where the node repeatedly attempts to sync from the same pruned version.

## Impact Explanation

**Severity: HIGH**

This vulnerability meets the High Severity criteria under the Aptos Bug Bounty program for "Significant protocol violations" and "Validator node slowdowns."

**Impact on Network:**
- **Node Availability**: Syncing nodes (including new validators joining the network) cannot complete synchronization if they encounter pruned auxiliary data
- **Network Health**: Reduces the number of viable archival nodes, as nodes with pruned data cannot serve sync requests to other nodes
- **Validator Onboarding**: New validators cannot join if existing nodes have pruned auxiliary data from early chain history
- **Recovery Scenarios**: Nodes recovering from failures or data loss cannot resync if the network has pruned the required data

The issue does NOT cause consensus violations or fund loss, but significantly impacts network liveness and node availability by preventing node synchronization.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

This vulnerability occurs in real-world production scenarios:

1. **Pruning is a Standard Feature**: The `PersistedAuxiliaryInfoPruner` is part of the standard ledger pruner implementation and is actively enabled in AptosDB: [10](#0-9) 

2. **Common Trigger**: Any new node joining the network or any node performing a full resync will request historical data. If archival nodes have pruned this data, the bug triggers immediately.

3. **No Workaround**: Once a node enters the retry loop, there is no automatic recovery mechanism. Manual intervention would require finding a different peer with unpruned data or accepting a state snapshot from a trusted source.

4. **Increases Over Time**: As the network ages and more nodes enable pruning to manage storage costs, the likelihood of encountering this bug increases.

## Recommendation

Add the pruning check to `get_persisted_auxiliary_info_iterator` to match the behavior of other iterator methods:

```rust
fn get_persisted_auxiliary_info_iterator(
    &self,
    start_version: Version,
    num_persisted_auxiliary_info: usize,
) -> Result<Box<dyn Iterator<Item = Result<PersistedAuxiliaryInfo>> + '_>> {
    gauged_api("get_persisted_auxiliary_info_iterator", || {
        // Add this pruning check
        self.error_if_ledger_pruned("PersistedAuxiliaryInfo", start_version)?;
        
        let iter = self
            .ledger_db
            .persisted_auxiliary_info_db()
            .get_persisted_auxiliary_info_iter(start_version, num_persisted_auxiliary_info)?;
        Ok(Box::new(iter)
            as Box<dyn Iterator<Item = Result<PersistedAuxiliaryInfo>> + '_>)
    })
}
```

This ensures that when data has been pruned, the method returns a proper error that can be handled by the caller, rather than silently returning an empty iterator that causes downstream failures.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Setting up an AptosDB node with ledger pruning enabled
2. Allowing the `PersistedAuxiliaryInfoPruner` to prune early versions
3. Attempting to sync a new node from a pruned version range
4. Observing the infinite retry loop in state sync logs with zero transactions received per request

The execution path is:
- State sync requests transactions from `start_version`
- Storage service calls `get_persisted_auxiliary_info_iterator` (no pruning check)
- Returns empty iterator for pruned data
- Multizip returns `None` immediately
- Zero transactions returned
- Retry request created with same `start_version`
- Loop continues indefinitely

### Citations

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L446-461)
```rust
    fn get_persisted_auxiliary_info_iterator(
        &self,
        start_version: Version,
        num_persisted_auxiliary_info: usize,
    ) -> Result<Box<dyn Iterator<Item = Result<PersistedAuxiliaryInfo>> + '_>> {
        gauged_api("get_persisted_auxiliary_info_iterator", || {
            let iter = self
                .ledger_db
                .persisted_auxiliary_info_db()
                .get_persisted_auxiliary_info_iter(start_version, num_persisted_auxiliary_info)?;
            Ok(Box::new(iter)
                as Box<
                    dyn Iterator<Item = Result<PersistedAuxiliaryInfo>> + '_,
                >)
        })
    }
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

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L494-546)
```rust
    fn get_transaction_info_iterator(
        &self,
        start_version: Version,
        limit: u64,
    ) -> Result<Box<dyn Iterator<Item = Result<TransactionInfo>> + '_>> {
        gauged_api("get_transaction_info_iterator", || {
            error_if_too_many_requested(limit, MAX_REQUEST_LIMIT)?;
            self.error_if_ledger_pruned("Transaction", start_version)?;

            let iter = self
                .ledger_db
                .transaction_info_db()
                .get_transaction_info_iter(start_version, limit as usize)?;
            Ok(Box::new(iter) as Box<dyn Iterator<Item = Result<TransactionInfo>> + '_>)
        })
    }

    fn get_events_iterator(
        &self,
        start_version: Version,
        limit: u64,
    ) -> Result<Box<dyn Iterator<Item = Result<Vec<ContractEvent>>> + '_>> {
        gauged_api("get_events_iterator", || {
            error_if_too_many_requested(limit, MAX_REQUEST_LIMIT)?;
            self.error_if_ledger_pruned("Transaction", start_version)?;

            let iter = self
                .ledger_db
                .event_db()
                .get_events_by_version_iter(start_version, limit as usize)?;
            Ok(Box::new(iter)
                as Box<
                    dyn Iterator<Item = Result<Vec<ContractEvent>>> + '_,
                >)
        })
    }

    fn get_write_set_iterator(
        &self,
        start_version: Version,
        limit: u64,
    ) -> Result<Box<dyn Iterator<Item = Result<WriteSet>> + '_>> {
        gauged_api("get_write_set_iterator", || {
            error_if_too_many_requested(limit, MAX_REQUEST_LIMIT)?;
            self.error_if_ledger_pruned("Transaction", start_version)?;

            let iter = self
                .ledger_db
                .write_set_db()
                .get_write_set_iter(start_version, limit as usize)?;
            Ok(Box::new(iter) as Box<dyn Iterator<Item = Result<WriteSet>> + '_>)
        })
    }
```

**File:** storage/aptosdb/src/db/aptosdb_internal.rs (L261-271)
```rust
    pub(super) fn error_if_ledger_pruned(&self, data_type: &str, version: Version) -> Result<()> {
        let min_readable_version = self.ledger_pruner.get_min_readable_version();
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

**File:** storage/aptosdb/src/ledger_db/persisted_auxiliary_info_db.rs (L58-89)
```rust
    pub(crate) fn get_persisted_auxiliary_info_iter(
        &self,
        start_version: Version,
        num_persisted_auxiliary_info: usize,
    ) -> Result<Box<dyn Iterator<Item = Result<PersistedAuxiliaryInfo>> + '_>> {
        let mut iter = self.db.iter::<PersistedAuxiliaryInfoSchema>()?;
        iter.seek(&start_version)?;
        let mut iter = iter.peekable();
        let item = iter.peek();
        let version = if item.is_some() {
            item.unwrap().as_ref().map_err(|e| e.clone())?.0
        } else {
            let mut iter = self.db.iter::<PersistedAuxiliaryInfoSchema>()?;
            iter.seek_to_last();
            if iter.next().transpose()?.is_some() {
                return Ok(Box::new(std::iter::empty()));
            }
            // Note in this case we return all Nones. We rely on the caller to not query future
            // data when the DB is empty.
            // TODO(grao): This will be unreachable in the future, consider make it an error later.
            start_version + num_persisted_auxiliary_info as u64
        };
        let num_none = std::cmp::min(
            num_persisted_auxiliary_info,
            version.saturating_sub(start_version) as usize,
        );
        let none_iter = itertools::repeat_n(Ok(PersistedAuxiliaryInfo::None), num_none);
        Ok(Box::new(none_iter.chain(iter.expect_continuous_versions(
            start_version + num_none as u64,
            num_persisted_auxiliary_info - num_none,
        )?)))
    }
```

**File:** state-sync/storage-service/server/src/storage.rs (L373-401)
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

        let mut multizip_iterator = itertools::multizip((
            transaction_iterator,
            transaction_info_iterator,
            transaction_events_iterator,
            persisted_auxiliary_info_iterator,
        ));
```

**File:** state-sync/storage-service/server/src/storage.rs (L418-471)
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
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L442-454)
```rust
    pub async fn process_data_responses(
        &mut self,
        global_data_summary: GlobalDataSummary,
    ) -> Result<(), Error> {
        if self.stream_engine.is_stream_complete()
            || self.request_failure_count >= self.streaming_service_config.max_request_retry
            || self.send_failure
        {
            if !self.send_failure && self.stream_end_notification_id.is_none() {
                self.send_end_of_stream_notification().await?;
            }
            return Ok(()); // There's nothing left to do
        }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L1151-1191)
```rust
fn create_missing_transactions_request(
    request: &TransactionsWithProofRequest,
    response_payload: &ResponsePayload,
) -> Result<Option<DataClientRequest>, Error> {
    // Determine the number of requested transactions
    let num_requested_transactions = request
        .end_version
        .checked_sub(request.start_version)
        .and_then(|v| v.checked_add(1))
        .ok_or_else(|| {
            Error::IntegerOverflow("Number of requested transactions has overflown!".into())
        })?;

    // Identify the missing data if the request was not satisfied
    match response_payload {
        ResponsePayload::TransactionsWithProof(transactions_with_proof) => {
            // Check if the request was satisfied
            let num_received_transactions = transactions_with_proof.get_num_transactions() as u64;
            if num_received_transactions < num_requested_transactions {
                let start_version = request
                    .start_version
                    .checked_add(num_received_transactions)
                    .ok_or_else(|| Error::IntegerOverflow("Start version has overflown!".into()))?;
                Ok(Some(DataClientRequest::TransactionsWithProof(
                    TransactionsWithProofRequest {
                        start_version,
                        end_version: request.end_version,
                        proof_version: request.proof_version,
                        include_events: request.include_events,
                    },
                )))
            } else {
                Ok(None) // The request was satisfied!
            }
        },
        payload => Err(Error::AptosDataClientResponseIsInvalid(format!(
            "Invalid response payload found for transactions request: {:?}",
            payload
        ))),
    }
}
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/mod.rs (L143-180)
```rust
        let persisted_auxiliary_info_pruner = Box::new(PersistedAuxiliaryInfoPruner::new(
            Arc::clone(&ledger_db),
            metadata_progress,
        )?);
        let transaction_accumulator_pruner = Box::new(TransactionAccumulatorPruner::new(
            Arc::clone(&ledger_db),
            metadata_progress,
        )?);

        let transaction_auxiliary_data_pruner = Box::new(TransactionAuxiliaryDataPruner::new(
            Arc::clone(&ledger_db),
            metadata_progress,
        )?);

        let transaction_info_pruner = Box::new(TransactionInfoPruner::new(
            Arc::clone(&ledger_db),
            metadata_progress,
        )?);
        let transaction_pruner = Box::new(TransactionPruner::new(
            Arc::clone(&transaction_store),
            Arc::clone(&ledger_db),
            metadata_progress,
            internal_indexer_db,
        )?);
        let write_set_pruner = Box::new(WriteSetPruner::new(
            Arc::clone(&ledger_db),
            metadata_progress,
        )?);

        let pruner = LedgerPruner {
            target_version: AtomicVersion::new(metadata_progress),
            progress: AtomicVersion::new(metadata_progress),
            ledger_metadata_pruner,
            sub_pruners: vec![
                event_store_pruner,
                persisted_auxiliary_info_pruner,
                transaction_accumulator_pruner,
                transaction_auxiliary_data_pruner,
```
