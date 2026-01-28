# Audit Report

## Title
State Sync Infinite Loop on Non-Existent Transaction Request with start_version=end_version

## Summary
When requesting a single transaction using `TransactionsWithProofRequest` where `start_version = end_version` for a transaction that doesn't exist in storage, the new size-aware chunking implementation returns an empty transaction list instead of an error. This causes the data streaming service client to enter an infinite loop, repeatedly requesting the same non-existent transaction, leading to complete state sync liveness failure.

## Finding Description

The vulnerability exists in the state synchronization system's handling of non-existent transactions when size-aware chunking is enabled.

**Request Structure**: The `TransactionsWithProofRequest` struct allows `start_version = end_version` to request a single transaction, with no validation preventing this pattern. [1](#0-0) 

**Configuration**: Size-aware chunking is automatically enabled for all non-mainnet networks (testnet, devnet) by the config optimizer when `ENABLE_SIZE_AND_TIME_AWARE_CHUNKING` is true and the chain is not mainnet. [2](#0-1) [3](#0-2) 

**New Implementation Behavior**: When size-aware chunking is enabled, the storage service uses iterator-based fetching in `get_transactions_with_proof_by_size`. [4](#0-3)  The `ContinuousVersionIter` returns `Ok(None)` (not an error) when a transaction doesn't exist, as the iterator simply reaches its end. [5](#0-4)  The storage service handles this by logging a warning and breaking out of the loop, returning an empty transaction list instead of propagating an error. [6](#0-5) 

**Legacy Implementation Behavior**: The legacy path calls `get_transaction()` which returns `AptosDbError::NotFound` when a transaction doesn't exist. [7](#0-6)  This error properly propagates to the client and triggers retry logic with failure counting via `handle_data_client_error` and `resend_data_client_request`.

**The Infinite Loop**: When the client receives fewer transactions than requested, it calls `request_missing_data` which invokes `create_missing_transactions_request`. [8](#0-7)  For a request of version X that returns 0 transactions, the calculation `start_version + num_received_transactions` results in `X + 0 = X`, creating a new request for the same version. [9](#0-8)  The `request_missing_data()` function sends this request but critically does NOT increment `request_failure_count`. [10](#0-9)  In contrast, actual request failures increment this counter via `resend_data_client_request()`. [11](#0-10)  The stream only terminates when `request_failure_count >= max_request_retry`. [12](#0-11)  Since missing data requests never increment this counter, the loop continues indefinitely.

## Impact Explanation

This vulnerability qualifies as **Medium Severity** per the Aptos bug bounty criteria for "State inconsistencies requiring manual intervention":

1. **Complete State Sync Liveness Failure**: The affected node cannot sync past the missing transaction, halting all state synchronization progress
2. **Resource Exhaustion**: The infinite loop consumes CPU cycles and network bandwidth indefinitely  
3. **Node Unavailability**: The node cannot participate in consensus or serve API requests effectively while blocked
4. **No Automatic Recovery**: The loop continues until manual intervention or node restart

While not causing consensus safety violations or fund loss directly, this breaks the critical state consistency invariant by preventing nodes from maintaining synchronized state with the network. This represents a temporary liveness issue affecting individual nodes, fitting the Medium severity classification for limited protocol violations requiring manual intervention.

## Likelihood Explanation

**High Likelihood** - This vulnerability can be triggered in several realistic scenarios:

1. **Transaction Pruning**: Nodes regularly prune old transactions as part of normal operations. A client requesting a pruned transaction version will trigger this bug naturally during sync operations.
2. **Version Beyond Ledger**: A client requesting a future transaction version (beyond current ledger version) triggers this condition during normal catch-up sync.
3. **Network Configuration**: The vulnerability is active on all non-mainnet networks (testnet, devnet) where size-aware chunking is enabled by default via the config optimizer.
4. **No Authentication Required**: Any network peer can send transaction requests without special privileges through the standard state sync protocol.
5. **Common Operation**: Requesting single transactions (`start_version = end_version`) is a normal state sync operation during catch-up and incremental sync.

The combination of automatic enablement on test networks and natural triggering conditions (pruning, normal sync operations) makes this highly likely to occur in production environments.

## Recommendation

Modify the size-aware chunking implementation in `get_transactions_with_proof_by_size` to return an error when the iterator completes without retrieving any requested transactions, matching the behavior of the legacy implementation:

```rust
None => {
    // If no transactions were fetched when at least one was expected,
    // return an error instead of an empty list
    if transactions.is_empty() && num_transactions_to_fetch > 0 {
        return Err(Error::StorageErrorEncountered(format!(
            "No transactions found for requested range. Start version: {}, end version: {}",
            start_version, end_version
        )));
    }
    warn!("...");  // Existing warning for partial data
    break;
}
```

This ensures that requests for non-existent transactions trigger the error handling path with proper failure counting, allowing the stream to terminate after `max_request_retry` attempts instead of looping indefinitely.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Configuring a node with size-aware chunking enabled (automatic on testnet/devnet)
2. Requesting a single transaction at a version that has been pruned or doesn't exist
3. Observing the infinite loop in logs showing repeated requests for the same version
4. Confirming `request_failure_count` never increments and the stream never terminates

A full PoC would require setting up a state sync client on a test network and monitoring the request patterns when requesting pruned transaction versions, demonstrating the infinite retry loop without failure count incrementation.

## Notes

This vulnerability represents a regression introduced by the size-aware chunking feature. The legacy implementation correctly handles missing transactions by returning `AptosDbError::NotFound`, which triggers proper error handling and retry limits. The new implementation's use of iterators that return `None` (end of iteration) rather than errors for missing data breaks this error propagation chain, creating the infinite loop condition. The fix requires aligning the iterator-based implementation's error handling with the legacy behavior when no data is available for a valid request range.

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

**File:** config/src/config/state_sync_config.rs (L14-14)
```rust
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

**File:** state-sync/storage-service/server/src/storage.rs (L347-395)
```rust
    fn get_transactions_with_proof_by_size(
        &self,
        proof_version: u64,
        start_version: u64,
        end_version: u64,
        include_events: bool,
        max_response_size: u64,
        use_size_and_time_aware_chunking: bool,
    ) -> Result<TransactionDataWithProofResponse, Error> {
        // Calculate the number of transactions to fetch
        let expected_num_transactions = inclusive_range_len(start_version, end_version)?;
        let max_num_transactions = self.config.max_transaction_chunk_size;
        let num_transactions_to_fetch = min(expected_num_transactions, max_num_transactions);

        // If size and time-aware chunking are disabled, use the legacy implementation
        if !use_size_and_time_aware_chunking {
            return self.get_transactions_with_proof_by_size_legacy(
                proof_version,
                start_version,
                end_version,
                num_transactions_to_fetch,
                include_events,
                max_response_size,
            );
        }

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

**File:** state-sync/storage-service/server/src/storage.rs (L457-469)
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

**File:** state-sync/data-streaming-service/src/data_stream.rs (L446-454)
```rust
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

**File:** state-sync/data-streaming-service/src/data_stream.rs (L473-476)
```rust
                        match self.request_missing_data(client_request, &client_response.payload) {
                            Ok(missing_data_requested) => {
                                if missing_data_requested {
                                    head_of_line_blocked = true; // We're now head of line blocked on the missing data
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

**File:** state-sync/data-streaming-service/src/data_stream.rs (L1168-1181)
```rust
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
```
