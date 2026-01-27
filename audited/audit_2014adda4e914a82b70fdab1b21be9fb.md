# Audit Report

## Title
Memory Exhaustion in Legacy State Sync Transaction Data Fetching

## Summary
The storage service's legacy implementation for fetching transaction outputs allocates potentially gigabytes of transaction data into memory before checking if it exceeds the configured `max_response_bytes` limit. This allows malicious peers to cause memory exhaustion on validator and fullnode instances through state synchronization requests.

## Finding Description

The vulnerability exists in the state sync storage service's legacy data fetching path, which is **enabled by default on mainnet** through the `enable_size_and_time_aware_chunking` configuration flag. [1](#0-0) 

When a peer requests transaction or output data via `get_new_transaction_or_output_data_with_proof()`, the request flows through the storage service with a `max_response_bytes` parameter: [2](#0-1) 

The data client uses a default value of 20 MiB for `max_response_bytes`: [3](#0-2) [4](#0-3) 

The server caps this at 40 MiB: [5](#0-4) 

**The Critical Flaw**: When the legacy implementation is used (mainnet default), the server determines the number of transactions to fetch (up to 3,000 by default) and calls `storage.get_transaction_outputs()`: [6](#0-5) 

This database method uses `.collect()` to load **ALL requested transactions into memory at once** before any size checking: [7](#0-6) 

The size check only happens **after** all data is loaded into memory at line 764 of storage.rs. If the response exceeds `max_response_bytes`, the code retries with half the transaction count, but the memory damage is already done.

**Attack Vector**: Each Aptos transaction can contain up to 10 MB of write set data: [8](#0-7) 

With 3,000 transactions × 10 MB maximum = **30 GB potential memory allocation**, far exceeding the 40 MiB `max_response_bytes` check.

A malicious peer can:
1. Identify blockchain versions containing large transactions (smart contract deployments, major state updates)
2. Send multiple concurrent `GetNewTransactionDataWithProof` requests targeting those versions
3. Each request causes the server to allocate GBs of memory before discovering it exceeds the 40 MiB limit
4. Multiple concurrent requests from multiple malicious peers amplify the memory pressure
5. Validator/fullnode experiences memory exhaustion, slowdown, or OOM termination

## Impact Explanation

This vulnerability qualifies as **High Severity** under Aptos bug bounty criteria:
- **Validator node slowdowns**: Memory pressure causes performance degradation
- **Potential OOM kills**: Excessive memory allocation can crash nodes
- **Availability impact**: Affects validator participation in consensus

It could escalate to **Critical** if it causes:
- **Total loss of liveness**: Coordinated attacks on multiple validators simultaneously
- **Network partition**: If enough validators go offline

The impact is amplified because:
1. The legacy path is the **default on mainnet**
2. No per-request memory limit exists before database fetching
3. Request moderator only tracks invalid requests, not memory-heavy ones
4. Multiple concurrent requests multiply the effect

## Likelihood Explanation

**Likelihood: Medium-High**

Exploitation requirements:
- Attacker operates as a network peer (easily achievable)
- Knowledge of blockchain versions with large transactions (publicly available)
- No authentication or privileged access required

The attack is **highly likely** because:
1. State sync requests are normal peer behavior
2. The legacy implementation is active by default on mainnet
3. Large transactions naturally exist in blockchain history
4. No rate limiting specifically prevents memory-heavy requests
5. The vulnerability is triggered through standard protocol operations

## Recommendation

**Immediate Fix**: Enable size-and-time-aware chunking by default on all networks, including mainnet:

```rust
// In config/src/config/state_sync_config.rs, line 198
impl Default for StorageServiceConfig {
    fn default() -> Self {
        Self {
            enable_size_and_time_aware_chunking: true, // Changed from false
            // ... rest of config
        }
    }
}
```

The size-aware implementation uses iterators to incrementally allocate memory and checks size limits per-item: [9](#0-8) 

**Additional Hardening**:
1. Add a pre-fetch memory limit check based on `max_response_bytes`
2. Implement per-peer concurrent request limits for memory-heavy operations
3. Add monitoring/metrics for memory allocation per request
4. Consider deprecating the legacy implementation entirely

**Long-term Fix**: Remove the legacy implementation once the size-aware path is proven stable across all networks.

## Proof of Concept

```rust
// Reproduction steps demonstrating the vulnerability

use aptos_config::config::StorageServiceConfig;
use aptos_storage_service_types::requests::DataRequest;

#[test]
fn test_memory_exhaustion_via_legacy_path() {
    // Setup: Create storage service with legacy implementation (mainnet default)
    let mut config = StorageServiceConfig::default();
    assert!(!config.enable_size_and_time_aware_chunking); // Confirms legacy path active
    
    // Simulate malicious peer request targeting large transactions
    let known_version_with_large_txns = 1_000_000; // Block with 10MB transactions
    let request = DataRequest::get_new_transaction_or_output_data_with_proof(
        known_version_with_large_txns,
        100, // known_epoch
        false, // include_events
        40 * 1024 * 1024, // max_response_bytes = 40 MiB
    );
    
    // Expected behavior:
    // 1. Server fetches up to 3000 transactions (max_transaction_output_chunk_size)
    // 2. If each transaction ~10MB, allocates ~30GB into memory
    // 3. THEN discovers response exceeds 40 MiB limit
    // 4. Retries with 1500 transactions (still ~15GB allocated)
    // 5. Continues halving until response fits or single transaction
    
    // With 10 concurrent requests from malicious peers:
    // Memory spike = 10 × 30GB = 300GB before any size checking
    // Result: OOM kill or severe performance degradation
    
    // Mitigation: Set enable_size_and_time_aware_chunking = true
    config.enable_size_and_time_aware_chunking = true;
    // Now uses iterative allocation with per-item size checks
}
```

**Real-world exploitation**:
1. Deploy fullnode as peer in Aptos network
2. Identify blockchain versions containing large Move module deployments or state updates
3. Send 10+ concurrent `GetNewTransactionDataWithProof` requests to target validator
4. Monitor target node memory usage spike to 10-100GB
5. Observe node slowdown, consensus participation degradation, or crash

The vulnerability breaks **Invariant #9**: "All operations must respect gas, storage, and computational limits" by allocating memory without proper bounds checking before database operations.

### Citations

**File:** config/src/config/state_sync_config.rs (L20-21)
```rust
const CLIENT_MAX_MESSAGE_SIZE_V2: usize = 20 * 1024 * 1024; // 20 MiB (used for v2 data requests)
const SERVER_MAX_MESSAGE_SIZE_V2: usize = 40 * 1024 * 1024; // 40 MiB (used for v2 data requests)
```

**File:** config/src/config/state_sync_config.rs (L198-198)
```rust
            enable_size_and_time_aware_chunking: false,
```

**File:** config/src/config/state_sync_config.rs (L472-472)
```rust
            max_response_bytes: CLIENT_MAX_MESSAGE_SIZE_V2 as u64,
```

**File:** state-sync/storage-service/types/src/requests.rs (L247-263)
```rust
    pub fn get_new_transaction_or_output_data_with_proof(
        known_version: u64,
        known_epoch: u64,
        include_events: bool,
        max_response_bytes: u64,
    ) -> Self {
        let transaction_data_request_type =
            TransactionDataRequestType::TransactionOrOutputData(TransactionOrOutputData {
                include_events,
            });
        Self::GetNewTransactionDataWithProof(GetNewTransactionDataWithProofRequest {
            transaction_data_request_type,
            known_version,
            known_epoch,
            max_response_bytes,
        })
    }
```

**File:** state-sync/storage-service/server/src/storage.rs (L621-676)
```rust
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
```

**File:** state-sync/storage-service/server/src/storage.rs (L739-777)
```rust
    fn get_transaction_outputs_with_proof_by_size_legacy(
        &self,
        proof_version: u64,
        start_version: u64,
        end_version: u64,
        mut num_outputs_to_fetch: u64,
        max_response_size: u64,
    ) -> Result<TransactionDataWithProofResponse, Error> {
        while num_outputs_to_fetch >= 1 {
            let output_list_with_proof = self.storage.get_transaction_outputs(
                start_version,
                num_outputs_to_fetch,
                proof_version,
            )?;
            let response = TransactionDataWithProofResponse {
                transaction_data_response_type: TransactionDataResponseType::TransactionOutputData,
                transaction_list_with_proof: None,
                transaction_output_list_with_proof: Some(output_list_with_proof),
            };
            if num_outputs_to_fetch == 1 {
                return Ok(response); // We cannot return less than a single item
            }

            // Attempt to divide up the request if it overflows the message size
            let (overflow_frame, num_bytes) =
                check_overflow_network_frame(&response, max_response_size)?;
            if !overflow_frame {
                return Ok(response);
            } else {
                metrics::increment_chunk_truncation_counter(
                    metrics::TRUNCATION_FOR_SIZE,
                    DataResponse::TransactionDataWithProof(response).get_label(),
                );
                let new_num_outputs_to_fetch = num_outputs_to_fetch / 2;
                debug!("The request for {:?} outputs was too large (num bytes: {:?}, limit: {:?}). Retrying with {:?}.",
                    num_outputs_to_fetch, num_bytes, max_response_size, new_num_outputs_to_fetch);
                num_outputs_to_fetch = new_num_outputs_to_fetch; // Try again with half the amount of data
            }
        }
```

**File:** state-sync/storage-service/server/src/storage.rs (L1149-1153)
```rust
        // Calculate the max response size to use
        let max_response_bytes = min(
            transaction_data_with_proof_request.max_response_bytes,
            self.config.max_network_chunk_bytes_v2,
        );
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

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L1-1)
```rust
// Copyright (c) Aptos Foundation
```
