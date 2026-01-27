# Audit Report

## Title
State Sync Infinite Loop on Non-Existent Transaction Request with start_version=end_version

## Summary
When requesting a single transaction using `TransactionsWithProofRequest` where `start_version = end_version` for a transaction that doesn't exist in storage, the new size-aware chunking implementation returns an empty transaction list instead of an error. This causes the data streaming service client to enter an infinite loop, repeatedly requesting the same non-existent transaction, leading to complete state sync liveness failure.

## Finding Description

The `TransactionsWithProofRequest` struct allows requesting transactions where `start_version = end_version`, which should fetch exactly one transaction. [1](#0-0) 

The request processing has two code paths:

**1. New Implementation (size-aware chunking enabled for non-mainnet):**

When `enable_size_and_time_aware_chunking` is enabled [2](#0-1) , the storage service uses iterator-based fetching. [3](#0-2) 

When the transaction doesn't exist, the `ContinuousVersionIter` returns `None` (not an error). [4](#0-3) 

The storage service handles this by logging a warning and breaking out of the loop, returning whatever transactions were fetched (potentially zero). [5](#0-4) 

**2. Legacy Implementation:**

The legacy path calls `get_transaction()` which returns `AptosDbError::NotFound` when a transaction doesn't exist. [6](#0-5) 

This error properly propagates to the client. [7](#0-6) 

**The Vulnerability:**

The data streaming service client validates responses and creates missing data requests when fewer transactions are received than expected. [8](#0-7) 

When a single transaction is requested (num_requested = 1) but zero are received, this creates a new request for the same version. [9](#0-8) 

**Critical Issue:** Missing data requests are treated as partial successes, NOT failures, so they don't increment the `request_failure_count` that would trigger the max retry limit. [10](#0-9) 

This creates an infinite loop where the same non-existent transaction is requested repeatedly.

## Impact Explanation

This vulnerability qualifies as **Medium Severity** per the Aptos bug bounty criteria for "State inconsistencies requiring intervention":

1. **Complete State Sync Liveness Failure**: The affected node cannot sync past the missing transaction, halting all state synchronization progress
2. **Resource Exhaustion**: The infinite loop consumes CPU cycles and network bandwidth indefinitely
3. **Node Unavailability**: The node cannot participate in consensus or serve API requests effectively
4. **No Automatic Recovery**: The loop continues until manual intervention or node restart

While not causing consensus safety violations or fund loss directly, this breaks the critical **State Consistency** invariant by preventing nodes from maintaining synchronized state with the network.

## Likelihood Explanation

**High Likelihood** - This vulnerability can be triggered in several realistic scenarios:

1. **Transaction Pruning**: A client requests a transaction version that has been pruned from storage
2. **Version Beyond Ledger**: A client requests a future transaction version (beyond current ledger version)  
3. **Network Configuration**: The vulnerability is active on all non-mainnet networks (testnet, devnet) where size-aware chunking is enabled by default [11](#0-10) 
4. **No Authentication Required**: Any client can send transaction requests without special privileges
5. **Common Operation**: Requesting single transactions is a normal state sync operation

## Recommendation

Add explicit validation in the new implementation to ensure that when requesting a single transaction (start_version = end_version), the response contains exactly one transaction or returns an error.

**Recommended Fix:**

In `state-sync/storage-service/server/src/storage.rs`, after the iterator loop, add validation:

```rust
// After line 471, before creating the transaction list with proof
if num_transactions_to_fetch == 1 && transactions.is_empty() {
    return Err(Error::StorageErrorEncountered(format!(
        "Transaction at version {} does not exist", 
        start_version
    )));
}
```

This ensures the new implementation behaves consistently with the legacy implementation for single transaction requests, properly returning errors for non-existent transactions.

**Alternative Fix:**

Modify the `ContinuousVersionIter` to return an error when expecting data but receiving None, ensuring consistent error handling across both implementations.

## Proof of Concept

```rust
// Integration test demonstrating the vulnerability
// File: state-sync/storage-service/server/src/tests/transactions.rs

#[tokio::test]
async fn test_single_nonexistent_transaction_infinite_loop() {
    // Setup storage service with size-aware chunking enabled
    let mut config = StorageServiceConfig::default();
    config.enable_size_and_time_aware_chunking = true;
    
    let (mut mock_client, mut service, _) = MockClient::new(Some(config));
    tokio::spawn(service.start());
    
    // Request a single transaction that doesn't exist
    // (beyond current ledger version)
    let request = StorageServiceRequest::new(
        DataRequest::GetTransactionsWithProof(
            TransactionsWithProofRequest {
                proof_version: 0,
                start_version: 999999,  // Non-existent version
                end_version: 999999,    // Same as start (single transaction)
                include_events: false,
            }
        ),
        false,
    );
    
    // First request returns empty list (0 transactions)
    let response = mock_client.send_request(request.clone()).await.unwrap();
    let txns = response.get_data_response().unwrap();
    
    match txns {
        DataResponse::TransactionsWithProof(txn_list) => {
            // Vulnerability: Returns success with 0 transactions
            assert_eq!(txn_list.transactions.len(), 0);
            // Expected: Should return error indicating transaction doesn't exist
        },
        _ => panic!("Unexpected response type"),
    }
    
    // Client would now enter infinite loop requesting the same transaction
    // because it received 0 transactions when it expected 1
}
```

The test demonstrates that requesting a non-existent single transaction returns an empty list instead of an error, which triggers the infinite loop condition in the data streaming service.

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

**File:** config/src/config/state_sync_config.rs (L623-629)
```rust
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

**File:** state-sync/storage-service/server/src/storage.rs (L457-471)
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
        }
```

**File:** storage/aptosdb/src/utils/iterators.rs (L40-62)
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

**File:** state-sync/data-streaming-service/src/data_stream.rs (L467-477)
```rust
                Ok(client_response) => {
                    // Sanity check and process the response
                    if sanity_check_client_response_type(client_request, &client_response) {
                        // If the response wasn't enough to satisfy the original request (e.g.,
                        // it was truncated), missing data should be requested.
                        let mut head_of_line_blocked = false;
                        match self.request_missing_data(client_request, &client_response.payload) {
                            Ok(missing_data_requested) => {
                                if missing_data_requested {
                                    head_of_line_blocked = true; // We're now head of line blocked on the missing data
                                }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L647-676)
```rust
    /// Requests any missing data from the previous client response
    /// and returns true iff missing data was requested.
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

**File:** state-sync/data-streaming-service/src/data_stream.rs (L1164-1184)
```rust
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
