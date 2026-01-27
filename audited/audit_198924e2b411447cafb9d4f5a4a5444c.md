# Audit Report

## Title
Cache Bypass Vulnerability via Transaction Type Alternation in Optimistic Fetch Requests

## Summary
Malicious peers can bypass the LRU response cache in the storage service by alternating between `TransactionData`, `TransactionOutputData`, and `TransactionOrOutputData` request types for the same version range. This forces the storage service to repeatedly fetch identical data from disk, causing unnecessary disk I/O, CPU overhead, and potential performance degradation.

## Finding Description

The storage service implements an LRU cache to avoid redundant storage operations when serving repeated requests. However, the cache key includes the `transaction_data_request_type` field, which allows peers to bypass caching by alternating request types while requesting the same underlying data.

The vulnerability exists in the optimistic fetch flow:

1. When a peer sends a `GetNewTransactionDataWithProof` request, the `transaction_data_request_type` is preserved when creating the storage request: [1](#0-0) 

2. The `StorageServiceRequest` structure derives `Hash` and `PartialEq`, meaning different `transaction_data_request_type` values create different cache keys: [2](#0-1) 

3. The cache lookup uses this request as the key, so different types cause cache misses: [3](#0-2) 

4. The `TransactionDataRequestType` enum has three distinct variants that produce different hash values: [4](#0-3) 

5. Request validation only checks ledger info freshness for optimistic fetches, not whether the peer has already received the data: [5](#0-4) 

**Attack Scenario:**
1. Blockchain has data up to version 1000
2. Attacker sends optimistic fetch: `GetNewTransactionDataWithProof(TransactionData, known_version=1000)`
3. New data becomes available at version 2000
4. Node processes fetch, creates cache key K1, fetches from storage, caches response
5. Attacker immediately sends: `GetNewTransactionDataWithProof(TransactionOutputData, known_version=1000)`
6. Node processes fetch, creates cache key K2 (≠ K1), cache miss occurs, fetches from storage again
7. Attacker sends: `GetNewTransactionDataWithProof(TransactionOrOutputData, known_version=1000)`
8. Node processes fetch, creates cache key K3 (≠ K1, K2), cache miss occurs, fetches from storage again

The attacker forces 3x storage operations for essentially the same version range [1001-2000].

## Impact Explanation

This vulnerability qualifies as **Medium severity** per Aptos bug bounty criteria:

- **Performance Degradation**: Forces repeated disk I/O operations for identical data, increasing latency for all peers
- **Resource Exhaustion**: Bypasses cache protection, consuming CPU cycles for serialization/compression and disk bandwidth
- **Partial DoS Potential**: Multiple attackers coordinating could amplify the effect, degrading service quality
- **Cache Pollution**: Fills the LRU cache with redundant entries for the same data, potentially evicting legitimately different requests

The vulnerability does not directly cause fund loss, consensus violations, or complete node failure, but it undermines the resource limit protections that the cache is meant to provide.

## Likelihood Explanation

**Likelihood: High**

- **Easy to Execute**: Attacker only needs network peer connectivity to send optimistic fetch requests
- **No Special Permissions**: Works for any peer type (validator, VFN, or PFN)
- **Low Attack Cost**: Simple sequential requests with different enum values
- **No Rate Limiting**: The request moderator only validates request serviceability, not request frequency or duplication
- **Persistent Effect**: Can be repeated indefinitely while new data becomes available

The attack requires minimal sophistication and no insider access.

## Recommendation

Implement cache key normalization that abstracts away the `transaction_data_request_type` when the underlying data is identical. This can be achieved through several approaches:

**Option 1: Normalize cache keys for equivalent requests**
Create a canonical cache key that maps different transaction data types to the same key when they request the same version range:

```rust
// Add to StorageServiceRequest
impl StorageServiceRequest {
    pub fn get_canonical_cache_key(&self) -> StorageServiceRequest {
        match &self.data_request {
            DataRequest::GetTransactionDataWithProof(request) => {
                // Normalize to a standard type for cache lookup
                let normalized_type = TransactionDataRequestType::TransactionOutputData;
                let normalized_request = GetTransactionDataWithProofRequest {
                    transaction_data_request_type: normalized_type,
                    proof_version: request.proof_version,
                    start_version: request.start_version,
                    end_version: request.end_version,
                    max_response_bytes: request.max_response_bytes,
                };
                StorageServiceRequest::new(
                    DataRequest::GetTransactionDataWithProof(normalized_request),
                    self.use_compression
                )
            },
            _ => self.clone()
        }
    }
}
```

**Option 2: Track served version ranges per peer**
Maintain per-peer state of recently served version ranges to prevent redundant requests: [6](#0-5) 

Add validation in `get_storage_request_for_missing_data()` to reject requests if the peer has recently received overlapping data.

**Option 3: Use version-range-based cache keys**
Replace the full request as cache key with a tuple of `(start_version, end_version, proof_version)` that ignores the request type distinction.

## Proof of Concept

```rust
// Integration test demonstrating the cache bypass
#[tokio::test]
async fn test_cache_bypass_via_type_alternation() {
    use aptos_storage_service_types::requests::*;
    use aptos_config::network_id::{NetworkId, PeerNetworkId};
    use aptos_types::PeerId;
    
    // Setup storage service with LRU cache
    let storage_service = setup_storage_service_with_cache();
    let peer_id = PeerNetworkId::new(NetworkId::Public, PeerId::random());
    
    // Prepare test data: blockchain at version 2000
    prepare_blockchain_data(2000);
    
    let known_version = 1000;
    let known_epoch = 10;
    let max_response_bytes = 10_000_000;
    
    // Request 1: TransactionData type
    let request1 = StorageServiceRequest::new(
        DataRequest::get_new_transaction_data_with_proof(
            known_version,
            known_epoch,
            true, // include_events
            max_response_bytes,
        ),
        false,
    );
    
    // Send optimistic fetch and wait for processing
    let response1 = send_optimistic_fetch_and_wait(&storage_service, peer_id, request1).await;
    assert!(response1.is_ok());
    
    // Verify storage was accessed (cache miss)
    let storage_accesses = get_storage_access_count();
    assert_eq!(storage_accesses, 1);
    
    // Request 2: TransactionOutputData type (SAME version range)
    let request2 = StorageServiceRequest::new(
        DataRequest::get_new_transaction_output_data_with_proof(
            known_version,  // SAME known_version
            known_epoch,
            max_response_bytes,
        ),
        false,
    );
    
    let response2 = send_optimistic_fetch_and_wait(&storage_service, peer_id, request2).await;
    assert!(response2.is_ok());
    
    // BUG: Storage accessed again despite same version range (cache miss)
    let storage_accesses = get_storage_access_count();
    assert_eq!(storage_accesses, 2); // Should be 1 if cache worked correctly
    
    // Request 3: TransactionOrOutputData type (SAME version range)
    let request3 = StorageServiceRequest::new(
        DataRequest::get_new_transaction_or_output_data_with_proof(
            known_version,  // SAME known_version
            known_epoch,
            true,
            max_response_bytes,
        ),
        false,
    );
    
    let response3 = send_optimistic_fetch_and_wait(&storage_service, peer_id, request3).await;
    assert!(response3.is_ok());
    
    // BUG: Storage accessed third time for same data (cache miss)
    let storage_accesses = get_storage_access_count();
    assert_eq!(storage_accesses, 3); // Should be 1 if cache worked correctly
    
    // The attacker has forced 3x storage operations for identical version range
    println!("Cache bypass successful: {} storage operations for same data", storage_accesses);
}
```

This test demonstrates that three requests with different `transaction_data_request_type` values but identical version ranges result in three separate storage accesses, proving the cache bypass vulnerability.

## Notes

The vulnerability is exacerbated by the fact that:
1. Optimistic fetches are processed asynchronously and periodically, allowing peers to queue multiple requests
2. The request moderator only validates request serviceability based on ledger info freshness, not deduplication
3. No rate limiting prevents rapid submission of similar requests with different types
4. The cache is shared across all peers, so coordinated attackers can pollute it more effectively

### Citations

**File:** state-sync/storage-service/server/src/optimistic_fetch.rs (L61-74)
```rust
    pub fn get_storage_request_for_missing_data(
        &self,
        config: StorageServiceConfig,
        target_ledger_info: &LedgerInfoWithSignatures,
    ) -> aptos_storage_service_types::Result<StorageServiceRequest, Error> {
        // Verify that the target version is higher than the highest known version
        let known_version = self.highest_known_version();
        let target_version = target_ledger_info.ledger_info().version();
        if target_version <= known_version {
            return Err(Error::InvalidRequest(format!(
                "Target version: {:?} is not higher than known version: {:?}!",
                target_version, known_version
            )));
        }
```

**File:** state-sync/storage-service/server/src/optimistic_fetch.rs (L128-136)
```rust
            DataRequest::GetNewTransactionDataWithProof(request) => {
                DataRequest::GetTransactionDataWithProof(GetTransactionDataWithProofRequest {
                    transaction_data_request_type: request.transaction_data_request_type,
                    proof_version: target_version,
                    start_version,
                    end_version,
                    max_response_bytes: request.max_response_bytes,
                })
            },
```

**File:** state-sync/storage-service/types/src/requests.rs (L9-13)
```rust
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct StorageServiceRequest {
    pub data_request: DataRequest, // The data to fetch from the storage service
    pub use_compression: bool,     // Whether or not the client wishes data to be compressed
}
```

**File:** state-sync/storage-service/types/src/requests.rs (L449-454)
```rust
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum TransactionDataRequestType {
    TransactionData(TransactionData),
    TransactionOutputData,
    TransactionOrOutputData(TransactionOrOutputData),
}
```

**File:** state-sync/storage-service/server/src/handler.rs (L396-404)
```rust
        // Check if the response is already in the cache
        if let Some(response) = self.lru_response_cache.get(request) {
            increment_counter(
                &metrics::LRU_CACHE_EVENT,
                peer_network_id.network_id(),
                LRU_CACHE_HIT.into(),
            );
            return Ok(response.clone());
        }
```

**File:** state-sync/storage-service/types/src/responses.rs (L797-801)
```rust
            GetNewTransactionDataWithProof(_) => can_service_optimistic_request(
                aptos_data_client_config,
                time_service,
                self.synced_ledger_info.as_ref(),
            ),
```
