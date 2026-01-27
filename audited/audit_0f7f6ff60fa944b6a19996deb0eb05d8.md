# Audit Report

## Title
Storage Iterator Missing Data Handling Allows Silent Database Corruption to Propagate

## Summary
When storage iterators return `None` prematurely due to missing data, the storage service logs only a warning and serves partial data instead of propagating an error. This allows nodes with corrupted or inconsistent storage to continue operating and serving data, potentially causing state sync failures for downstream nodes.

## Finding Description

At lines 685-693 in `get_transaction_outputs_with_proof_by_size()`, when the multizip iterator returns `None` (indicating one or more underlying iterators ran out of data before reaching the expected count), the code logs a warning and breaks the loop: [1](#0-0) 

The function then proceeds to create a valid response with partial data: [2](#0-1) 

The storage service uses five synchronized iterators (transaction, transaction_info, write_set, events, persisted_auxiliary_info) that should all return the same number of items. If any iterator returns `None` early, this indicates **database inconsistency** - different storage tables have different version ranges.

This same pattern appears in three other functions:
- `get_transactions_with_proof_by_size()` [3](#0-2) 
- `get_epoch_ending_ledger_infos_by_size()` [4](#0-3) 
- `get_state_value_chunk_with_proof_by_size()` [5](#0-4) 

While pruning is checked before creating iterators [6](#0-5) , storage inconsistency within the non-pruned range is not treated as an error.

The client-side data streaming service detects incomplete responses and requests missing data: [7](#0-6) 

However, if storage corruption is widespread across serving nodes, syncing nodes become stuck in an infinite retry loop.

## Impact Explanation

This issue qualifies as **High Severity** under the Aptos bug bounty criteria for:
- **"Validator node slowdowns"**: Syncing nodes attempting to fetch data from corrupted nodes experience significant delays and resource waste through repeated failed sync attempts
- **"Significant protocol violations"**: Database integrity is a critical invariant - storage inconsistency should be treated as a fatal error requiring immediate operator intervention

The violation breaks the **State Consistency** invariant: nodes with corrupted storage should fail-fast and refuse to serve data rather than silently propagating partial/incomplete data that wastes network resources.

## Likelihood Explanation

**Medium-Low likelihood** due to requiring storage corruption:
- **Trigger conditions**: Disk corruption, incomplete writes during crashes, concurrent access bugs, or manual database manipulation
- **Not directly exploitable**: External attackers cannot directly cause storage corruption without other vulnerabilities
- **Operational impact**: When it occurs, corrupted nodes remain operational instead of failing, making debugging difficult and allowing corruption to persist

## Recommendation

Storage inconsistency should be treated as a **fatal error**:

```rust
None => {
    // Storage inconsistency detected - different tables have different version ranges
    return Err(Error::StorageErrorEncountered(format!(
        "Database inconsistency detected: iterators returned different amounts of data. \
        Start version: {:?}, end version: {:?}, num outputs requested: {:?}, num fetched: {:?}. \
        This indicates critical storage corruption - node should be taken offline for repair.",
        start_version, end_version, num_outputs_to_fetch, transactions_and_outputs.len()
    )));
},
```

Additionally:
1. Log at ERROR level with operator alerts
2. Increment a critical metrics counter for monitoring
3. Consider adding a circuit breaker that stops serving after repeated inconsistencies
4. Document operator procedures for storage verification and repair

## Proof of Concept

```rust
// Test demonstrating the issue (simplified)
#[test]
fn test_storage_inconsistency_returns_error() {
    // Setup: Create a mock storage with inconsistent data
    // - Transactions exist for versions 100-200
    // - Write sets only exist for versions 100-150
    let mock_storage = create_corrupted_storage();
    
    // Request transaction outputs for versions 100-200
    let result = storage_reader.get_transaction_outputs_with_proof(
        200, // proof_version
        100, // start_version  
        200, // end_version
    );
    
    // Expected: Should return an error due to storage inconsistency
    // Actual: Returns Ok with partial data (versions 100-150) and only logs warning
    assert!(result.is_err(), "Storage inconsistency should return error, not partial data");
}
```

The current implementation would return `Ok(response)` with only 51 outputs instead of the requested 101, with storage corruption hidden behind a warning log.

## Notes

While this vulnerability requires pre-existing storage corruption (not directly triggerable by external attackers), it represents a **significant defensive programming failure**. The fail-fast principle demands that database integrity violations halt operations immediately. Continuing to serve partial data:

1. **Hides critical errors** from operators
2. **Wastes network resources** as clients retry indefinitely
3. **Prevents proper error handling** at higher layers
4. **Allows corrupted nodes** to remain in service

This meets High Severity criteria as it affects validator availability and represents a significant protocol violation when storage invariants are breached.

### Citations

**File:** state-sync/storage-service/server/src/storage.rs (L276-286)
```rust
                None => {
                    // Log a warning that the iterator did not contain all the expected data
                    warn!(
                        "The epoch ending ledger info iterator is missing data! \
                        Start epoch: {:?}, expected end epoch: {:?}, num ledger infos to fetch: {:?}",
                        start_epoch, expected_end_epoch, num_ledger_infos_to_fetch
                    );
                    break;
                },
            }
        }
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

**File:** state-sync/storage-service/server/src/storage.rs (L685-693)
```rust
                None => {
                    // Log a warning that the iterators did not contain all the expected data
                    warn!(
                        "The iterators for transactions, transaction infos, write sets, events, \
                        auxiliary data and persisted auxiliary infos are missing data! Start version: {:?}, \
                        end version: {:?}, num outputs to fetch: {:?}, num fetched: {:?}.",
                        start_version, end_version, num_outputs_to_fetch, transactions_and_outputs.len()
                    );
                    break;
```

**File:** state-sync/storage-service/server/src/storage.rs (L698-734)
```rust
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
```

**File:** state-sync/storage-service/server/src/storage.rs (L963-973)
```rust
                None => {
                    // Log a warning that the iterator did not contain all the expected data
                    warn!(
                        "The state value iterator is missing data! Version: {:?}, \
                        start index: {:?}, end index: {:?}, num state values to fetch: {:?}",
                        version, start_index, end_index, num_state_values_to_fetch
                    );
                    break;
                },
            }
        }
```

**File:** storage/aptosdb/src/db/aptosdb_reader.rs (L484-484)
```rust
            self.error_if_ledger_pruned("Transaction", start_version)?;
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L1196-1235)
```rust
fn create_missing_transaction_outputs_request(
    request: &TransactionOutputsWithProofRequest,
    response_payload: &ResponsePayload,
) -> Result<Option<DataClientRequest>, Error> {
    // Determine the number of requested transaction outputs
    let num_requested_outputs = request
        .end_version
        .checked_sub(request.start_version)
        .and_then(|v| v.checked_add(1))
        .ok_or_else(|| {
            Error::IntegerOverflow("Number of requested transaction outputs has overflown!".into())
        })?;

    // Identify the missing data if the request was not satisfied
    match response_payload {
        ResponsePayload::TransactionOutputsWithProof(transaction_outputs_with_proof) => {
            // Check if the request was satisfied
            let num_received_outputs = transaction_outputs_with_proof.get_num_outputs() as u64;
            if num_received_outputs < num_requested_outputs {
                let start_version = request
                    .start_version
                    .checked_add(num_received_outputs)
                    .ok_or_else(|| Error::IntegerOverflow("Start version has overflown!".into()))?;
                Ok(Some(DataClientRequest::TransactionOutputsWithProof(
                    TransactionOutputsWithProofRequest {
                        start_version,
                        end_version: request.end_version,
                        proof_version: request.proof_version,
                    },
                )))
            } else {
                Ok(None) // The request was satisfied!
            }
        },
        payload => Err(Error::AptosDataClientResponseIsInvalid(format!(
            "Invalid response payload found for transaction outputs request: {:?}",
            payload
        ))),
    }
}
```
