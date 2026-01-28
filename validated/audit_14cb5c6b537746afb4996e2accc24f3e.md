# Audit Report

## Title
Missing Proof Version Validation Enables Resource Exhaustion Attack on Storage Service

## Summary
The storage service request validation layer does not verify that `proof_version >= end_version`, allowing malicious peers to craft requests that pass validation but fail during proof generation. This bypasses the invalid request tracking mechanism, enabling sustained resource exhaustion attacks without rate-limiting.

## Finding Description

The storage service request constructor creates a `GetTransactionDataWithProofRequest` without validating the relationship between `proof_version` and `end_version`: [1](#0-0) 

A transaction accumulator range proof can only be generated when the proof version is at or after all transactions being proven. This invariant is enforced in the accumulator layer, which validates that `last_leaf_index < self.num_leaves`: [2](#0-1) 

However, the request validation layer only checks that the `proof_version` is available in storage (`synced_ledger_info.version() >= proof_version`), but does NOT validate the relationship between `proof_version` and `end_version`: [3](#0-2) [4](#0-3) [5](#0-4) 

**Attack Flow:**
1. Attacker creates request with `start_version=100, end_version=200, proof_version=150` (proof_version < end_version)
2. Request passes `can_service()` validation because both the data range and proof version are individually available
3. Server processes request and fetches transaction data from storage
4. When generating the proof, the accumulator validation fails
5. Error is converted to `StorageErrorEncountered`: [6](#0-5) 

6. This error is then converted to `InternalError`, NOT `InvalidRequest`: [7](#0-6) 

7. Critically, the peer's invalid request count is NOT incremented because only validation failures (when `can_service()` returns false) increment this counter: [8](#0-7) 

## Impact Explanation

This is a **High Severity** issue per the Aptos bug bounty criteria:

**Validator Node Slowdowns**: Malicious peers can repeatedly send invalid requests that force storage servers to perform expensive I/O operations (fetching transaction data from disk, deserialization) before discovering the request is invalid. With max chunk sizes of thousands of transactions, each invalid request consumes significant resources.

**Bypasses Invalid Request Tracking**: The error is misclassified as an internal error rather than an invalid request, so the malicious peer is not penalized. The request moderator only increments invalid request counts and ignores peers when they send too many `InvalidRequest` errors, not internal errors.

**Resource Exhaustion Vector**: An attacker can amplify the attack by sending many such requests without being rate-limited, causing sustained resource consumption on storage service nodes critical for state synchronization.

## Likelihood Explanation

**Likelihood: High**

- **Trivial to Exploit**: Requires only setting `proof_version < end_version` in the request parameters
- **No Authentication Required**: Any network peer can send storage service requests
- **Not Rate-Limited**: Invalid requests bypass the invalid request counting mechanism
- **Amplifiable**: Can send multiple concurrent requests to multiple storage servers
- **Affects All Deployments**: This is a fundamental validation gap in the storage service protocol

## Recommendation

Add validation to the `can_service()` method to check that `proof_version >= end_version` before processing the request. Specifically, modify the `can_service_transactions_with_proof`, `can_service_transaction_outputs_with_proof`, and `can_service_transactions_or_outputs_with_proof` methods to include this check.

## Proof of Concept

A test case can be created by sending a `GetTransactionDataWithProofRequest` with `proof_version < end_version` to demonstrate that:
1. The request passes `can_service()` validation
2. The server fetches transaction data
3. The proof generation fails with a storage error
4. The error is classified as `InternalError`
5. The invalid request count is not incremented

## Notes

This vulnerability exploits a validation gap in the storage service protocol layer, not a simple network flooding attack. The existing security mechanisms (request validation and rate-limiting) are designed to prevent such resource exhaustion, but this vulnerability bypasses both through a missing validation check. The fix is protocol-level validation, distinguishing this from network-level DoS mitigation.

### Citations

**File:** state-sync/storage-service/types/src/requests.rs (L158-174)
```rust
    pub fn get_transaction_data_with_proof(
        proof_version: u64,
        start_version: u64,
        end_version: u64,
        include_events: bool,
        max_response_bytes: u64,
    ) -> Self {
        let transaction_data_request_type =
            TransactionDataRequestType::TransactionData(TransactionData { include_events });
        Self::GetTransactionDataWithProof(GetTransactionDataWithProofRequest {
            transaction_data_request_type,
            proof_version,
            start_version,
            end_version,
            max_response_bytes,
        })
    }
```

**File:** storage/accumulator/src/lib.rs (L424-429)
```rust
        ensure!(
            last_leaf_index < self.num_leaves,
            "Invalid last_leaf_index: {}, num_leaves: {}",
            last_leaf_index,
            self.num_leaves,
        );
```

**File:** state-sync/storage-service/types/src/responses.rs (L777-795)
```rust
            GetTransactionDataWithProof(request) => match request.transaction_data_request_type {
                TransactionDataRequestType::TransactionData(_) => self
                    .can_service_transactions_with_proof(
                        request.start_version,
                        request.end_version,
                        request.proof_version,
                    ),
                TransactionDataRequestType::TransactionOutputData => self
                    .can_service_transaction_outputs_with_proof(
                        request.start_version,
                        request.end_version,
                        request.proof_version,
                    ),
                TransactionDataRequestType::TransactionOrOutputData(_) => self
                    .can_service_transactions_or_outputs_with_proof(
                        request.start_version,
                        request.end_version,
                        request.proof_version,
                    ),
```

**File:** state-sync/storage-service/types/src/responses.rs (L811-816)
```rust
    fn can_create_proof(&self, proof_version: u64) -> bool {
        self.synced_ledger_info
            .as_ref()
            .map(|li| li.ledger_info().version() >= proof_version)
            .unwrap_or(false)
    }
```

**File:** state-sync/storage-service/types/src/responses.rs (L868-882)
```rust
    fn can_service_transactions_with_proof(
        &self,
        start_version: u64,
        end_version: u64,
        proof_version: u64,
    ) -> bool {
        let desired_range = match CompleteDataRange::new(start_version, end_version) {
            Ok(desired_range) => desired_range,
            Err(_) => return false,
        };

        let can_service_transactions = self.can_service_transactions(&desired_range);
        let can_create_proof = self.can_create_proof(proof_version);
        can_service_transactions && can_create_proof
    }
```

**File:** state-sync/storage-service/server/src/error.rs (L43-46)
```rust
impl From<aptos_storage_interface::AptosDbError> for Error {
    fn from(error: aptos_storage_interface::AptosDbError) -> Self {
        Error::StorageErrorEncountered(error.to_string())
    }
```

**File:** state-sync/storage-service/server/src/handler.rs (L196-202)
```rust
        process_result.map_err(|error| match error {
            Error::InvalidRequest(error) => StorageServiceError::InvalidRequest(error),
            Error::TooManyInvalidRequests(error) => {
                StorageServiceError::TooManyInvalidRequests(error)
            },
            error => StorageServiceError::InternalError(error.to_string()),
        })
```

**File:** state-sync/storage-service/server/src/moderator.rs (L155-185)
```rust
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
```
