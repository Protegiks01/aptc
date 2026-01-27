# Audit Report

## Title
State Sync Version Range Processing Inconsistency - Mixed Transaction Execution and Output Application

## Summary
The `TransactionsOrOutputsWithProofRequest` handling in the state sync data streaming service allows a single version range to be processed inconsistently across chunks, where some versions are executed as transactions while others are applied as outputs. This breaks deterministic execution guarantees and can lead to state divergence between nodes.

## Finding Description

The vulnerability exists in how missing data requests are created for incomplete `TransactionsOrOutputsWithProofRequest` responses. When a response is partial, the system creates a new request for the missing data without preserving the response type (transactions vs outputs) from the initial chunk. [1](#0-0) 

The critical flaw is that `create_missing_transactions_or_outputs_request()` always creates another `TransactionsOrOutputsWithProofRequest` for missing data, regardless of whether the first response was `TransactionsWithProof` or `TransactionOutputsWithProof`. This allows the response type to change mid-stream.

The sanity check accepts both response types as valid: [2](#0-1) 

On the storage server side, the decision to return transactions vs outputs depends on network frame size and can vary between peers: [3](#0-2) 

When different peers have different network configurations, they return different response types for the same request. This creates an attack scenario where:

1. Node requests versions 100-200 using `TransactionsOrOutputsWithProofRequest`
2. Peer A returns `TransactionsWithProof` for versions 100-150 (partial)
3. Missing data request created for versions 151-200 (still a `TransactionsOrOutputsWithProofRequest`)
4. Peer B returns `TransactionOutputsWithProof` for versions 151-200

In `ExecuteOrApplyFromGenesis` bootstrapping mode or `ExecuteTransactionsOrApplyOutputs` continuous syncing mode, these different response types are processed differently: [4](#0-3) 

The same issue exists in continuous syncing: [5](#0-4) 

This means versions 100-150 are **executed** (full VM processing) while versions 151-200 are **applied** (outputs applied without execution). Different nodes querying different peers could process the same version ranges through different code paths, violating the deterministic execution invariant.

## Impact Explanation

**Critical Severity** - This vulnerability breaks the fundamental "Deterministic Execution" invariant that all validators must produce identical state roots for identical blocks.

The impact includes:

1. **State Divergence Risk**: Different nodes can end up with different internal states for the same version range if there are any subtle differences between the execution and application paths
2. **Non-Deterministic Sync Behavior**: Nodes take different code paths to reach the same state, making the system harder to verify and debug
3. **Increased Attack Surface**: Any bug in either the execution or application path will only affect nodes that happened to use that path
4. **Consensus Safety Concerns**: While both paths verify proofs cryptographically, any implementation difference could cause nodes to fork

This qualifies as a **Consensus/Safety violation** under the Critical severity category, as it undermines the deterministic execution guarantee essential for blockchain consensus.

## Likelihood Explanation

**High Likelihood** - This issue occurs naturally in normal operation without requiring malicious behavior:

1. Different peers legitimately have different network configurations and storage implementations
2. The storage service's fallback logic from outputs to transactions is deterministic but varies by peer capabilities
3. Nodes in `ExecuteOrApplyFromGenesis` or `ExecuteTransactionsOrApplyOutputs` modes (the default configurations) are affected
4. No special attacker capabilities required beyond normal peer network participation

The default configuration explicitly enables this mixed-mode processing: [6](#0-5) 

## Recommendation

The missing data request should preserve the response type from the initial chunk to ensure consistency within a single version range. Modify `create_missing_transactions_or_outputs_request()` to:

1. Track whether the first response was transactions or outputs
2. Create a type-specific request (`TransactionsWithProofRequest` or `TransactionOutputsWithProofRequest`) for missing data
3. Only use `TransactionsOrOutputsWithProofRequest` for the initial request

Alternatively, the stream engine should track the data type of the first received chunk and reject subsequent chunks of a different type for the same logical request range.

Example fix pseudocode:

```rust
fn create_missing_transactions_or_outputs_request(
    request: &TransactionsOrOutputsWithProofRequest,
    response_payload: &ResponsePayload,
) -> Result<Option<DataClientRequest>, Error> {
    // ... existing code ...
    
    if num_received_data_items < num_request_data_items {
        let start_version = request.start_version
            .checked_add(num_received_data_items)
            .ok_or_else(|| Error::IntegerOverflow("Start version has overflown!".into()))?;
        
        // FIX: Preserve response type for consistency
        let missing_request = match response_payload {
            ResponsePayload::TransactionsWithProof(_) => {
                DataClientRequest::TransactionsWithProof(TransactionsWithProofRequest {
                    start_version,
                    end_version: request.end_version,
                    proof_version: request.proof_version,
                    include_events: request.include_events,
                })
            },
            ResponsePayload::TransactionOutputsWithProof(_) => {
                DataClientRequest::TransactionOutputsWithProof(TransactionOutputsWithProofRequest {
                    start_version,
                    end_version: request.end_version,
                    proof_version: request.proof_version,
                })
            },
            _ => return Err(Error::AptosDataClientResponseIsInvalid(...))
        };
        Ok(Some(missing_request))
    } else {
        Ok(None)
    }
}
```

## Proof of Concept

The vulnerability can be demonstrated with an integration test that:

1. Configures two mock peers with different `max_transaction_output_chunk_size` settings
2. Creates a `TransactionsOrOutputsWithProofRequest` for a version range
3. Routes the initial request to Peer A (returns transactions)
4. Routes the missing data request to Peer B (returns outputs due to size constraints)
5. Verifies that the node processes the same version range through different code paths (execute vs apply)
6. Demonstrates that the stream engine accepts both response types without rejecting the inconsistency

A full integration test would require mocking the storage service and data client layers to simulate the different peer responses, then verifying that the bootstrapper/continuous syncer processes the chunks through different execution paths without raising an error.

### Citations

**File:** state-sync/data-streaming-service/src/data_stream.rs (L1240-1288)
```rust
fn create_missing_transactions_or_outputs_request(
    request: &TransactionsOrOutputsWithProofRequest,
    response_payload: &ResponsePayload,
) -> Result<Option<DataClientRequest>, Error> {
    // Determine the number of requested transactions or outputs
    let num_request_data_items = request
        .end_version
        .checked_sub(request.start_version)
        .and_then(|v| v.checked_add(1))
        .ok_or_else(|| {
            Error::IntegerOverflow(
                "Number of requested transactions or outputs has overflown!".into(),
            )
        })?;

    // Calculate the number of received data items
    let num_received_data_items = match response_payload {
        ResponsePayload::TransactionsWithProof(transactions_with_proof) => {
            transactions_with_proof.get_num_transactions() as u64
        },
        ResponsePayload::TransactionOutputsWithProof(transaction_outputs_with_proof) => {
            transaction_outputs_with_proof.get_num_outputs() as u64
        },
        payload => {
            return Err(Error::AptosDataClientResponseIsInvalid(format!(
                "Invalid response payload found for transactions or outputs request: {:?}",
                payload
            )))
        },
    };

    // Identify the missing data if the request was not satisfied
    if num_received_data_items < num_request_data_items {
        let start_version = request
            .start_version
            .checked_add(num_received_data_items)
            .ok_or_else(|| Error::IntegerOverflow("Start version has overflown!".into()))?;
        Ok(Some(DataClientRequest::TransactionsOrOutputsWithProof(
            TransactionsOrOutputsWithProofRequest {
                start_version,
                end_version: request.end_version,
                proof_version: request.proof_version,
                include_events: request.include_events,
            },
        )))
    } else {
        Ok(None) // The request was satisfied!
    }
}
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L1369-1377)
```rust
        DataClientRequest::TransactionsOrOutputsWithProof(_) => {
            matches!(
                data_client_response.payload,
                ResponsePayload::TransactionsWithProof(_)
            ) || matches!(
                data_client_response.payload,
                ResponsePayload::TransactionOutputsWithProof(_)
            )
        },
```

**File:** state-sync/storage-service/server/src/storage.rs (L787-840)
```rust
    fn get_transactions_or_outputs_with_proof_by_size(
        &self,
        proof_version: u64,
        start_version: u64,
        end_version: u64,
        include_events: bool,
        max_num_output_reductions: u64,
        max_response_size: u64,
        use_size_and_time_aware_chunking: bool,
    ) -> Result<TransactionDataWithProofResponse, Error> {
        // Calculate the number of transaction outputs to fetch
        let expected_num_outputs = inclusive_range_len(start_version, end_version)?;
        let max_num_outputs = self.config.max_transaction_output_chunk_size;
        let num_outputs_to_fetch = min(expected_num_outputs, max_num_outputs);

        // If size and time-aware chunking are disabled, use the legacy implementation
        if !use_size_and_time_aware_chunking {
            return self.get_transactions_or_outputs_with_proof_by_size_legacy(
                proof_version,
                start_version,
                end_version,
                num_outputs_to_fetch,
                include_events,
                max_num_output_reductions,
                max_response_size,
            );
        }

        // Fetch the transaction outputs with proof
        let response = self.get_transaction_outputs_with_proof_by_size(
            proof_version,
            start_version,
            end_version,
            max_response_size,
            true, // This is a transaction or output request
            use_size_and_time_aware_chunking,
        )?;

        // If the request was fully satisfied (all items were fetched), return the response
        if let Some(output_list_with_proof) = response.transaction_output_list_with_proof.as_ref() {
            if num_outputs_to_fetch == output_list_with_proof.get_num_outputs() as u64 {
                return Ok(response);
            }
        }

        // Otherwise, return as many transactions as possible
        self.get_transactions_with_proof_by_size(
            proof_version,
            start_version,
            end_version,
            include_events,
            max_response_size,
            use_size_and_time_aware_chunking,
        )
```

**File:** state-sync/state-sync-driver/src/bootstrapper.rs (L1220-1249)
```rust
            BootstrappingMode::ExecuteOrApplyFromGenesis => {
                if let Some(transaction_list_with_proof) = transaction_list_with_proof {
                    utils::execute_transactions(
                        &mut self.storage_synchronizer,
                        notification_metadata,
                        proof_ledger_info,
                        end_of_epoch_ledger_info,
                        transaction_list_with_proof,
                    )
                    .await?
                } else if let Some(transaction_outputs_with_proof) = transaction_outputs_with_proof
                {
                    utils::apply_transaction_outputs(
                        &mut self.storage_synchronizer,
                        notification_metadata,
                        proof_ledger_info,
                        end_of_epoch_ledger_info,
                        transaction_outputs_with_proof,
                    )
                    .await?
                } else {
                    self.reset_active_stream(Some(NotificationAndFeedback::new(
                        notification_metadata.notification_id,
                        NotificationFeedback::PayloadTypeIsIncorrect,
                    )))
                    .await?;
                    return Err(Error::InvalidPayload(
                        "Did not receive transactions or outputs with proof!".into(),
                    ));
                }
```

**File:** state-sync/state-sync-driver/src/continuous_syncer.rs (L344-374)
```rust
            ContinuousSyncingMode::ExecuteTransactionsOrApplyOutputs => {
                if let Some(transaction_list_with_proof) = transaction_list_with_proof {
                    utils::execute_transactions(
                        &mut self.storage_synchronizer,
                        notification_metadata,
                        ledger_info_with_signatures.clone(),
                        None,
                        transaction_list_with_proof,
                    )
                    .await?
                } else if let Some(transaction_outputs_with_proof) = transaction_outputs_with_proof
                {
                    utils::apply_transaction_outputs(
                        &mut self.storage_synchronizer,
                        notification_metadata,
                        ledger_info_with_signatures.clone(),
                        None,
                        transaction_outputs_with_proof,
                    )
                    .await?
                } else {
                    self.reset_active_stream(Some(NotificationAndFeedback::new(
                        notification_metadata.notification_id,
                        NotificationFeedback::PayloadTypeIsIncorrect,
                    )))
                    .await?;
                    return Err(Error::InvalidPayload(
                        "No transactions or output with proof was provided!".into(),
                    ));
                }
            },
```

**File:** config/src/config/state_sync_config.rs (L134-150)
```rust
impl Default for StateSyncDriverConfig {
    fn default() -> Self {
        Self {
            bootstrapping_mode: BootstrappingMode::ExecuteOrApplyFromGenesis,
            commit_notification_timeout_ms: 5000,
            continuous_syncing_mode: ContinuousSyncingMode::ExecuteTransactionsOrApplyOutputs,
            enable_auto_bootstrapping: false,
            fallback_to_output_syncing_secs: 180, // 3 minutes
            progress_check_interval_ms: 100,
            max_connection_deadline_secs: 10,
            max_consecutive_stream_notifications: 10,
            max_num_stream_timeouts: 12,
            max_pending_data_chunks: 50,
            max_pending_mempool_notifications: 100,
            max_stream_wait_time_ms: 5000,
            num_versions_to_skip_snapshot_sync: 400_000_000, // At 5k TPS, this allows a node to fail for about 24 hours.
        }
```
