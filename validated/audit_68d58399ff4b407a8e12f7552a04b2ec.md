# Audit Report

## Title
State Sync Infinite Loop on Non-Existent Transaction Request with start_version=end_version

## Summary
When requesting a single transaction using `TransactionsWithProofRequest` where `start_version = end_version` for a transaction that doesn't exist in storage, the new size-aware chunking implementation returns an empty transaction list instead of an error. This causes the data streaming service client to enter an infinite loop, repeatedly requesting the same non-existent transaction, leading to complete state sync liveness failure.

## Finding Description

The vulnerability exists in the state synchronization system when size-aware chunking is enabled (default for non-mainnet networks). The `TransactionsWithProofRequest` struct supports requesting a single transaction by setting `start_version = end_version`. [1](#0-0) 

The configuration enables size-aware chunking for all non-mainnet networks by default: [2](#0-1) [3](#0-2) 

**The Two Code Paths:**

**1. New Size-Aware Chunking Implementation:**

When enabled, the storage service uses iterator-based fetching: [4](#0-3) 

The implementation creates iterators that wrap `ContinuousVersionIter`: [5](#0-4) 

When a transaction doesn't exist, `ContinuousVersionIter` returns `None` (not an error): [6](#0-5) 

The storage service handles this by logging a warning and breaking, returning whatever transactions were fetched (potentially zero): [7](#0-6) 

**2. Legacy Implementation:**

The legacy path calls `get_transaction()` which properly returns `AptosDbError::NotFound`: [8](#0-7) 

This error propagates through the legacy fetching path: [9](#0-8) 

**The Infinite Loop Mechanism:**

The data streaming service client validates responses and creates missing data requests when fewer transactions are received than expected: [10](#0-9) 

When 1 transaction is requested but 0 are received, this creates a new request for the same version (lines 1170-1181).

**Critical Issue:** The `request_missing_data()` function does NOT increment the `request_failure_count`: [11](#0-10) 

Only `resend_data_client_request()` increments the failure counter (line 734 is the only place where `request_failure_count` is incremented): [12](#0-11) 

The retry limit is enforced by checking `request_failure_count`: [13](#0-12) 

Since missing data requests never increment the failure counter, the retry limit is never reached, creating an infinite loop.

## Impact Explanation

This vulnerability qualifies as **Medium Severity** per the Aptos bug bounty criteria for "State inconsistencies requiring manual intervention":

1. **Complete State Sync Liveness Failure**: The affected node cannot sync past the missing transaction, halting all state synchronization progress
2. **Resource Exhaustion**: The infinite loop consumes CPU cycles and network bandwidth indefinitely
3. **Node Unavailability**: The node cannot participate in consensus or serve API requests effectively
4. **No Automatic Recovery**: The loop continues until manual intervention or node restart

While not causing consensus safety violations or fund loss directly, this breaks the critical **State Consistency** invariant by preventing nodes from maintaining synchronized state with the network. This matches the Medium severity category: "Limited Protocol Violations - State inconsistencies requiring manual intervention."

## Likelihood Explanation

**High Likelihood** - This vulnerability can be triggered in several realistic scenarios:

1. **Transaction Pruning**: A client requests a transaction version that has been pruned from storage
2. **Version Beyond Ledger**: A client requests a future transaction version (beyond current ledger version)
3. **Network Configuration**: The vulnerability is active on all non-mainnet networks (testnet, devnet) where size-aware chunking is enabled by default
4. **No Authentication Required**: Any client can send transaction requests without special privileges
5. **Common Operation**: Requesting single transactions is a normal state sync operation during synchronization

## Recommendation

Modify the size-aware chunking implementation to handle missing data consistently with the legacy path. When iterators return `None` for the first requested item, return an error instead of an empty list:

```rust
// In get_transactions_with_proof_by_size(), after line 418:
match multizip_iterator.next() {
    Some((Ok(transaction), Ok(info), Ok(events), Ok(persisted_auxiliary_info))) => {
        // existing logic...
    },
    Some((Err(error), _, _, _)) | ... => {
        return Err(Error::StorageErrorEncountered(error.to_string()));
    },
    None => {
        // If no data at all was fetched, return an error instead of empty list
        if transactions.is_empty() {
            return Err(Error::StorageErrorEncountered(format!(
                "No transaction found at version {}", start_version
            )));
        }
        break;
    },
}
```

Alternatively, increment `request_failure_count` for missing data requests that repeatedly request the same data, or add a separate counter for missing data retries.

## Proof of Concept

To reproduce:
1. Configure a testnet node with size-aware chunking enabled (default)
2. Request a transaction at a version that has been pruned: `TransactionsWithProofRequest { start_version: 100, end_version: 100, ... }`
3. Observe the node enters an infinite loop requesting the same non-existent transaction
4. Check logs for repeated warnings: "The iterators for transactions... are missing data!"
5. Verify `request_failure_count` never increments past initial failures
6. Node remains stuck indefinitely until manual restart

### Citations

**File:** state-sync/storage-service/types/src/requests.rs (L362-367)
```rust
pub struct TransactionsWithProofRequest {
    pub proof_version: u64,   // The version the proof should be relative to
    pub start_version: u64,   // The starting version of the transaction list
    pub end_version: u64,     // The ending version of the transaction list (inclusive)
    pub include_events: bool, // Whether or not to include events in the response
}
```

**File:** config/src/config/state_sync_config.rs (L12-14)
```rust
// Whether to enable size and time-aware chunking (for non-production networks).
// Note: once this becomes stable, we should enable it for all networks (e.g., Mainnet).
const ENABLE_SIZE_AND_TIME_AWARE_CHUNKING: bool = true;
```

**File:** config/src/config/state_sync_config.rs (L620-629)
```rust
        // Potentially enable size and time-aware chunking for all networks except Mainnet
        let mut modified_config = false;
        if let Some(chain_id) = chain_id {
            if ENABLE_SIZE_AND_TIME_AWARE_CHUNKING
                && !chain_id.is_mainnet()
                && local_storage_config_yaml["enable_size_and_time_aware_chunking"].is_null()
            {
                storage_service_config.enable_size_and_time_aware_chunking = true;
                modified_config = true;
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

**File:** state-sync/storage-service/server/src/storage.rs (L457-470)
```rust
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
```

**File:** state-sync/storage-service/server/src/storage.rs (L1075-1090)
```rust
    fn get_transactions_with_proof(
        &self,
        proof_version: u64,
        start_version: u64,
        end_version: u64,
        include_events: bool,
    ) -> aptos_storage_service_types::Result<TransactionDataWithProofResponse, Error> {
        self.get_transactions_with_proof_by_size(
            proof_version,
            start_version,
            end_version,
            include_events,
            self.config.max_network_chunk_bytes,
            self.config.enable_size_and_time_aware_chunking,
        )
    }
```

**File:** storage/aptosdb/src/utils/iterators.rs (L40-63)
```rust
    fn next_impl(&mut self) -> Result<Option<T>> {
        if self.expected_next_version >= self.end_version {
            return Ok(None);
        }

        let ret = match self.inner.next().transpose()? {
            Some((version, transaction)) => {
                ensure!(
                    version == self.expected_next_version,
                    "{} iterator: first version {}, expecting version {}, got {} from underlying iterator.",
                    std::any::type_name::<T>(),
                    self.first_version,
                    self.expected_next_version,
                    version,
                );
                self.expected_next_version += 1;
                Some(transaction)
            },
            None => None,
        };

        Ok(ret)
    }
}
```

**File:** storage/aptosdb/src/ledger_db/transaction_db.rs (L56-60)
```rust
    pub(crate) fn get_transaction(&self, version: Version) -> Result<Transaction> {
        self.db
            .get::<TransactionSchema>(&version)?
            .ok_or_else(|| AptosDbError::NotFound(format!("Txn {version}")))
    }
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L284-286)
```rust
            let txns = (start_version..start_version + limit)
                .map(|version| self.ledger_db.transaction_db().get_transaction(version))
                .collect::<Result<Vec<_>>>()?;
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L446-448)
```rust
        if self.stream_engine.is_stream_complete()
            || self.request_failure_count >= self.streaming_service_config.max_request_retry
            || self.send_failure
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L649-676)
```rust
    fn request_missing_data(
        &mut self,
        data_client_request: &DataClientRequest,
        response_payload: &ResponsePayload,
    ) -> Result<bool, Error> {
        // Identify if any missing data needs to be requested
        if let Some(missing_data_request) =
            create_missing_data_request(data_client_request, response_payload)?
        {
            // Increment the missing client request counter
            increment_counter(
                &metrics::SENT_DATA_REQUESTS_FOR_MISSING_DATA,
                data_client_request.get_label(),
            );

            // Send the missing data request
            let pending_client_response =
                self.send_client_request(false, missing_data_request.clone());

            // Push the pending response to the front of the queue
            self.get_sent_data_requests()?
                .push_front(pending_client_response);

            return Ok(true); // Missing data was requested
        }

        Ok(false) // No missing data was requested
    }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L729-744)
```rust
    fn resend_data_client_request(
        &mut self,
        data_client_request: &DataClientRequest,
    ) -> Result<(), Error> {
        // Increment the number of client failures for this request
        self.request_failure_count += 1;

        // Resend the client request
        let pending_client_response = self.send_client_request(true, data_client_request.clone());

        // Push the pending response to the head of the sent requests queue
        self.get_sent_data_requests()?
            .push_front(pending_client_response);

        Ok(())
    }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L1151-1184)
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
```
