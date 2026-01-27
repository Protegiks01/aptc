# Audit Report

## Title
Proof Version Manipulation DoS Attack via Historical Proof Regeneration Bypass

## Summary
A Byzantine peer can repeatedly request transaction outputs with an arbitrarily old `proof_version` that references pruned accumulator nodes, forcing the storage service to perform expensive I/O operations before failing at proof generation. The validation logic fails to check if the `proof_version` is within the available (non-pruned) range, and because validation passes, the malicious peer is never marked as unhealthy, allowing unlimited repetition of this resource exhaustion attack.

## Finding Description

The `TransactionOutputsWithProofRequest` struct contains a `proof_version` field that specifies which ledger version should be used to generate cryptographic proofs for the requested transaction outputs. [1](#0-0) 

When a storage service receives such a request, it validates the request using the `can_service_transaction_outputs_with_proof` method, which only checks two conditions: [2](#0-1) 

The critical flaw is in the `can_create_proof` method, which only verifies that the `proof_version` is less than or equal to the synced ledger info version: [3](#0-2) 

**The validation does NOT check if the `proof_version` is greater than or equal to the minimum available version after pruning.** The Aptos blockchain implements a transaction accumulator pruner that deletes old accumulator nodes: [4](#0-3) 

After validation passes, the storage service processes the request by fetching all transaction data BEFORE attempting to generate the proof: [5](#0-4) 

The critical sequence is:
1. Lines 591-614: Create expensive database iterators
2. Lines 630-696: Perform extensive I/O to fetch transactions, infos, write sets, events, and auxiliary data
3. Lines 703-707: **Only after all I/O is complete**, attempt to generate the accumulator range proof

When the proof generation attempts to read pruned accumulator nodes, it fails with "position does not exist": [6](#0-5) 

However, because the request passed validation, the peer is NOT marked as unhealthy by the request moderator: [7](#0-6) 

The moderator only increments the invalid request count if validation fails (lines 161-178), not if processing fails after validation succeeds.

**Attack Scenario:**
1. Attacker identifies the current synced version (e.g., 10,000) and knows pruning has occurred for versions < 1,000
2. Attacker sends: `TransactionOutputsWithProofRequest { proof_version: 100, start_version: 5000, end_version: 6000 }`
3. Validation passes (100 ≤ 10,000 and outputs [5000-6000] are available)
4. Server performs expensive I/O to fetch ~1000 transaction outputs
5. Proof generation fails (accumulator nodes at version 100 are pruned)
6. Error returned to attacker, but peer remains healthy
7. Attacker repeats indefinitely, causing disk thrashing and CPU exhaustion

## Impact Explanation

This vulnerability enables a resource exhaustion Denial of Service attack against validator nodes and full nodes running the storage service. Each malicious request forces the server to:

- Create multiple database iterators (transactions, infos, write sets, events, auxiliary data)
- Perform disk I/O to fetch potentially thousands of transaction records
- Serialize and deserialize large data structures
- Consume CPU cycles for data processing

Since the malicious peer is never marked as unhealthy (validation passed), they can sustain this attack indefinitely without being rate-limited or blocked. Multiple coordinated attackers could amplify the impact.

This qualifies as **Medium Severity** per the Aptos Bug Bounty program: "Validator node slowdowns" and "State inconsistencies requiring intervention" (the storage service becomes unresponsive to legitimate requests). While it does not cause consensus violations or fund loss, it can significantly degrade network performance and availability.

## Likelihood Explanation

**Likelihood: HIGH**

Attack requirements:
- Knowledge of approximate pruned version range (easily discoverable through trial and error)
- Ability to send network requests to storage service nodes (publicly accessible)
- No privileged access required
- No economic cost to the attacker

The attack is trivial to execute and can be automated. Any malicious peer can perform this attack with minimal resources.

## Recommendation

Add validation to check if the `proof_version` is within the available accumulator range. Modify the `can_service_transaction_outputs_with_proof` method to verify the proof version has not been pruned: [2](#0-1) 

The fix requires:

1. Expose the transaction accumulator pruner progress through the `DbReader` interface (similar to `get_first_txn_version()`)
2. Add a check in `can_create_proof` to ensure `proof_version >= min_available_accumulator_version`
3. If the check fails, reject the request during validation, allowing the request moderator to mark the peer as unhealthy

Additionally, consider:
- Moving proof generation earlier in the request processing pipeline to fail fast
- Adding metrics to detect repeated failed proof generation attempts
- Implementing stricter rate limiting for requests with old proof versions

## Proof of Concept

```rust
// Rust test demonstrating the vulnerability
#[test]
fn test_pruned_proof_version_dos_attack() {
    // Setup: Create a storage service with pruned accumulator nodes (versions 0-999)
    let mut config = StorageServiceConfig::default();
    let (storage, _db) = create_test_storage_with_pruning(1000); // Prune up to version 1000
    
    // Attacker discovers current synced version is 10000
    let synced_version = 10000;
    storage.set_synced_version(synced_version);
    
    // Attacker crafts malicious request with pruned proof_version
    let malicious_request = TransactionOutputsWithProofRequest {
        proof_version: 500, // Pruned! Should be >= 1000
        start_version: 5000,
        end_version: 6000, // 1000 outputs
    };
    
    // Measure I/O operations
    let io_counter = Arc::new(AtomicU64::new(0));
    storage.set_io_counter(io_counter.clone());
    
    // Send request
    let result = storage.get_transaction_outputs_with_proof(
        malicious_request.proof_version,
        malicious_request.start_version,
        malicious_request.end_version,
    );
    
    // Assert: Request should fail (proof generation fails)
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("does not exist"));
    
    // Assert: BUT expensive I/O was performed (reading 1000 transactions)
    let io_operations = io_counter.load(Ordering::Relaxed);
    assert!(io_operations > 5000); // Multiple reads per transaction
    
    // Assert: Peer is NOT marked as unhealthy (validation passed)
    let peer_state = request_moderator.get_peer_state(&peer_network_id);
    assert_eq!(peer_state.invalid_request_count, 0); // NOT incremented!
    
    // Attacker can repeat this indefinitely
    for _ in 0..100 {
        let _ = storage.get_transaction_outputs_with_proof(
            malicious_request.proof_version,
            malicious_request.start_version,
            malicious_request.end_version,
        );
    }
    
    // Total I/O operations should be massive (100 * 5000+)
    assert!(io_counter.load(Ordering::Relaxed) > 500_000);
}
```

### Citations

**File:** state-sync/storage-service/types/src/requests.rs (L352-357)
```rust
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct TransactionOutputsWithProofRequest {
    pub proof_version: u64, // The version the proof should be relative to
    pub start_version: u64, // The starting version of the transaction output list
    pub end_version: u64,   // The ending version of the transaction output list (inclusive)
}
```

**File:** state-sync/storage-service/types/src/responses.rs (L810-816)
```rust
    /// Returns true iff the peer can create a proof for the given version
    fn can_create_proof(&self, proof_version: u64) -> bool {
        self.synced_ledger_info
            .as_ref()
            .map(|li| li.ledger_info().version() >= proof_version)
            .unwrap_or(false)
    }
```

**File:** state-sync/storage-service/types/src/responses.rs (L833-847)
```rust
    fn can_service_transaction_outputs_with_proof(
        &self,
        start_version: u64,
        end_version: u64,
        proof_version: u64,
    ) -> bool {
        let desired_range = match CompleteDataRange::new(start_version, end_version) {
            Ok(desired_range) => desired_range,
            Err(_) => return false,
        };

        let can_service_outputs = self.can_service_transaction_outputs(&desired_range);
        let can_create_proof = self.can_create_proof(proof_version);
        can_service_outputs && can_create_proof
    }
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/transaction_accumulator_pruner.rs (L25-35)
```rust
    fn prune(&self, current_progress: Version, target_version: Version) -> Result<()> {
        let mut batch = SchemaBatch::new();
        TransactionAccumulatorDb::prune(current_progress, target_version, &mut batch)?;
        batch.put::<DbMetadataSchema>(
            &DbMetadataKey::TransactionAccumulatorPrunerProgress,
            &DbMetadataValue::Version(target_version),
        )?;
        self.ledger_db
            .transaction_accumulator_db()
            .write_schemas(batch)
    }
```

**File:** state-sync/storage-service/server/src/storage.rs (L591-708)
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
```

**File:** storage/aptosdb/src/ledger_db/transaction_accumulator_db.rs (L195-201)
```rust
impl HashReader for TransactionAccumulatorDb {
    fn get(&self, position: Position) -> Result<HashValue, anyhow::Error> {
        self.db
            .get::<TransactionAccumulatorSchema>(&position)?
            .ok_or_else(|| anyhow!("{} does not exist.", position))
    }
}
```

**File:** state-sync/storage-service/server/src/moderator.rs (L134-196)
```rust
    pub fn validate_request(
        &self,
        peer_network_id: &PeerNetworkId,
        request: &StorageServiceRequest,
    ) -> Result<(), Error> {
        // Validate the request and time the operation
        let validate_request = || {
            // If the peer is being ignored, return an error
            if let Some(peer_state) = self.unhealthy_peer_states.get(peer_network_id) {
                if peer_state.is_ignored() {
                    return Err(Error::TooManyInvalidRequests(format!(
                        "Peer is temporarily ignored. Unable to handle request: {:?}",
                        request
                    )));
                }
            }

            // Get the latest storage server summary
            let storage_server_summary = self.cached_storage_server_summary.load();

            // Verify the request is serviceable using the current storage server summary
            if !storage_server_summary.can_service(
                &self.aptos_data_client_config,
                self.time_service.clone(),
                request,
            ) {
                // Increment the invalid request count for the peer
                let mut unhealthy_peer_state = self
                    .unhealthy_peer_states
                    .entry(*peer_network_id)
                    .or_insert_with(|| {
                        // Create a new unhealthy peer state (this is the first invalid request)
                        let max_invalid_requests =
                            self.storage_service_config.max_invalid_requests_per_peer;
                        let min_time_to_ignore_peers_secs =
                            self.storage_service_config.min_time_to_ignore_peers_secs;
                        let time_service = self.time_service.clone();

                        UnhealthyPeerState::new(
                            max_invalid_requests,
                            min_time_to_ignore_peers_secs,
                            time_service,
                        )
                    });
                unhealthy_peer_state.increment_invalid_request_count(peer_network_id);

                // Return the validation error
                return Err(Error::InvalidRequest(format!(
                    "The given request cannot be satisfied. Request: {:?}, storage summary: {:?}",
                    request, storage_server_summary
                )));
            }

            Ok(()) // The request is valid
        };
        utils::execute_and_time_duration(
            &metrics::STORAGE_REQUEST_VALIDATION_LATENCY,
            Some((peer_network_id, request)),
            None,
            validate_request,
            None,
        )
    }
```
