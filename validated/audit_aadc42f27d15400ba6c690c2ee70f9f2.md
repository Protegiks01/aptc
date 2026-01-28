Based on my systematic validation of this security claim against the Aptos Core codebase, I have verified all technical assertions and determined this is a valid vulnerability.

# Audit Report

## Title
Memory Exhaustion in Legacy State Sync Transaction Data Fetching

## Summary
The storage service's legacy implementation allocates potentially gigabytes of transaction output data into memory before checking size limits, enabling memory exhaustion attacks on validators and fullnodes through legitimate state synchronization requests.

## Finding Description

The vulnerability exists in the state sync storage service's legacy data fetching path. The `enable_size_and_time_aware_chunking` configuration flag defaults to `false` for all nodes [1](#0-0) , and the config optimizer explicitly excludes mainnet from enabling the safer implementation [2](#0-1) .

When a peer requests transaction output data, the client specifies `max_response_bytes` of 20 MiB [3](#0-2) , which the server caps at 40 MiB [4](#0-3) . The server determines the number of transaction outputs to fetch (up to 3,000 by default) [5](#0-4) .

**The Critical Flaw**: When legacy implementation is active, the server calls `get_transaction_outputs_with_proof_by_size_legacy()` [6](#0-5) , which invokes `self.storage.get_transaction_outputs()` [7](#0-6) . This database method uses `.collect::<Result<Vec<_>>>()?` to load **ALL requested transaction outputs into memory at once** [8](#0-7) .

Only **after** loading all data does the code check if it exceeds the size limit [9](#0-8) . If it overflows, the code retries with half the transaction count, but the memory allocation has already occurred [10](#0-9) .

Each Aptos transaction can contain up to 10 MB of write set data [11](#0-10) . With 3,000 transactions × 10 MB = **30 GB potential memory allocation**, far exceeding the 40 MiB response limit.

The storage service processes each request in a separate blocking task [12](#0-11) , allowing concurrent requests to multiply memory consumption. The request moderator only tracks invalid requests [13](#0-12) , not legitimate requests that trigger excessive memory usage.

A malicious peer can identify blockchain versions containing large transactions (smart contract deployments, governance proposals) and send concurrent requests targeting those versions. Each request triggers gigabytes of memory allocation before the size check occurs, potentially causing validator slowdowns or OOM termination.

## Impact Explanation

This qualifies as **High Severity** under Aptos bug bounty criteria for "Validator Node Slowdowns" through "DoS through resource exhaustion." The vulnerability causes:

1. **Validator node slowdowns**: Excessive memory allocation creates memory pressure affecting consensus participation
2. **Potential OOM kills**: Multiple concurrent requests can exhaust available memory, causing node crashes
3. **Availability impact**: Affects validator liveness and network stability

The impact is amplified because: (1) legacy path is mainnet default, (2) no per-request memory limits exist before database fetching, (3) request moderator doesn't prevent memory-heavy valid requests, and (4) multiple concurrent requests multiply the effect with concurrent task execution.

## Likelihood Explanation

**Likelihood: High**

The attack requires only:
- Operating as a network peer (easily achievable, no special access)
- Knowledge of blockchain versions with large transactions (publicly available blockchain data)
- Sending standard state sync protocol requests

The vulnerability is highly exploitable because: (1) state sync requests are normal peer behavior, (2) legacy implementation is active by default on mainnet, (3) large transactions naturally exist in blockchain history, and (4) the vulnerability is triggered through standard protocol operations without requiring sophisticated techniques.

## Recommendation

Enable size-and-time-aware chunking for mainnet by modifying the config optimizer to include mainnet chains, or implement pre-allocation size checks in the legacy path before calling `get_transaction_outputs()`. The safer approach is to check serialized sizes using iterators before collecting into vectors, similar to the newer implementation [14](#0-13) .

Alternatively, implement a server-side memory budget tracker that monitors cumulative memory allocation across all active requests and applies backpressure when approaching system limits.

## Proof of Concept

A proof of concept would involve:
1. Identifying blockchain versions with transactions containing large write sets (e.g., framework upgrades)
2. Sending concurrent `TransactionOutputsWithProofRequest` messages targeting those versions
3. Monitoring server memory consumption during processing
4. Observing memory spikes before size validation occurs

The vulnerability can be triggered through normal state sync protocol operations without requiring malformed inputs or special privileges.

## Notes

This is a protocol-level resource exhaustion vulnerability, not a network-level DoS attack. The fix requires modifying the protocol implementation to check sizes before loading data, distinguishing it from rate-limiting solutions that address network flooding attacks.

### Citations

**File:** config/src/config/state_sync_config.rs (L27-27)
```rust
const MAX_TRANSACTION_OUTPUT_CHUNK_SIZE: u64 = 3000;
```

**File:** config/src/config/state_sync_config.rs (L163-163)
```rust
    /// Maximum number of invalid requests per peer
```

**File:** config/src/config/state_sync_config.rs (L198-198)
```rust
            enable_size_and_time_aware_chunking: false,
```

**File:** config/src/config/state_sync_config.rs (L205-205)
```rust
            max_network_chunk_bytes_v2: SERVER_MAX_MESSAGE_SIZE_V2 as u64,
```

**File:** config/src/config/state_sync_config.rs (L472-472)
```rust
            max_response_bytes: CLIENT_MAX_MESSAGE_SIZE_V2 as u64,
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

**File:** state-sync/storage-service/server/src/storage.rs (L582-588)
```rust
            return self.get_transaction_outputs_with_proof_by_size_legacy(
                proof_version,
                start_version,
                end_version,
                num_outputs_to_fetch,
                max_response_size,
            );
```

**File:** state-sync/storage-service/server/src/storage.rs (L591-735)
```rust
        // Get the iterators for the transaction, info, write set, events,
        // auxiliary data and persisted auxiliary infos.
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
        let transaction_info_list_with_proof =
            TransactionInfoListWithProof::new(accumulator_range_proof, transaction_infos);
        let transaction_output_list_with_proof = TransactionOutputListWithProof::new(
            transactions_and_outputs,
            Some(start_version),
            transaction_info_list_with_proof,
        );

        // Update the data truncation metrics
        response_progress_tracker.update_data_truncation_metrics(
            DataResponse::get_transaction_outputs_with_proof_v2_label(),
        );

        // Create the transaction data with proof response
        let output_list_with_proof_v2 =
            TransactionOutputListWithProofV2::new(TransactionOutputListWithAuxiliaryInfos::new(
                transaction_output_list_with_proof,
                persisted_auxiliary_infos,
            ));
        let response = TransactionDataWithProofResponse {
            transaction_data_response_type: TransactionDataResponseType::TransactionOutputData,
            transaction_list_with_proof: None,
            transaction_output_list_with_proof: Some(output_list_with_proof_v2),
        };

        Ok(response)
    }
```

**File:** state-sync/storage-service/server/src/storage.rs (L748-752)
```rust
            let output_list_with_proof = self.storage.get_transaction_outputs(
                start_version,
                num_outputs_to_fetch,
                proof_version,
            )?;
```

**File:** state-sync/storage-service/server/src/storage.rs (L762-767)
```rust
            // Attempt to divide up the request if it overflows the message size
            let (overflow_frame, num_bytes) =
                check_overflow_network_frame(&response, max_response_size)?;
            if !overflow_frame {
                return Ok(response);
            } else {
```

**File:** state-sync/storage-service/server/src/storage.rs (L772-776)
```rust
                let new_num_outputs_to_fetch = num_outputs_to_fetch / 2;
                debug!("The request for {:?} outputs was too large (num bytes: {:?}, limit: {:?}). Retrying with {:?}.",
                    num_outputs_to_fetch, num_bytes, max_response_size, new_num_outputs_to_fetch);
                num_outputs_to_fetch = new_num_outputs_to_fetch; // Try again with half the amount of data
            }
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L391-422)
```rust
            let (txn_infos, txns_and_outputs, persisted_aux_info) = (start_version
                ..start_version + limit)
                .map(|version| {
                    let txn_info = self
                        .ledger_db
                        .transaction_info_db()
                        .get_transaction_info(version)?;
                    let events = self.ledger_db.event_db().get_events_by_version(version)?;
                    let write_set = self.ledger_db.write_set_db().get_write_set(version)?;
                    let txn = self.ledger_db.transaction_db().get_transaction(version)?;
                    let auxiliary_data = self
                        .ledger_db
                        .transaction_auxiliary_data_db()
                        .get_transaction_auxiliary_data(version)?
                        .unwrap_or_default();
                    let txn_output = TransactionOutput::new(
                        write_set,
                        events,
                        txn_info.gas_used(),
                        txn_info.status().clone().into(),
                        auxiliary_data,
                    );
                    let persisted_aux_info = self
                        .ledger_db
                        .persisted_auxiliary_info_db()
                        .get_persisted_auxiliary_info(version)?
                        .unwrap_or(PersistedAuxiliaryInfo::None);
                    Ok((txn_info, (txn, txn_output), persisted_aux_info))
                })
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .multiunzip();
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L159-162)
```rust
            max_bytes_all_write_ops_per_transaction: NumBytes,
            { 5.. => "max_bytes_all_write_ops_per_transaction" },
            10 << 20, // all write ops from a single transaction are 10MB max
        ],
```

**File:** state-sync/storage-service/server/src/lib.rs (L401-418)
```rust
            self.runtime.spawn_blocking(move || {
                Handler::new(
                    cached_storage_server_summary,
                    optimistic_fetches,
                    lru_response_cache,
                    request_moderator,
                    storage,
                    subscriptions,
                    time_service,
                )
                .process_request_and_respond(
                    config,
                    network_request.peer_network_id,
                    network_request.protocol_id,
                    network_request.storage_service_request,
                    network_request.response_sender,
                );
            });
```
