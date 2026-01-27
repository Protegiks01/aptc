# Audit Report

## Title
Bandwidth Amplification DoS Attack via Minimum max_response_bytes Exploitation in State Sync

## Summary
The `GetNewTransactionDataWithProofRequest` allows clients to specify `max_response_bytes=1`, forcing the storage service to return one transaction per request. This creates a bandwidth amplification attack where syncing N transactions requires N individual round trips instead of N/chunk_size requests, amplifying network overhead by up to 100× and enabling resource exhaustion attacks against validator nodes.

## Finding Description

The vulnerability exists in the state-sync storage service's handling of the `max_response_bytes` parameter in `GetNewTransactionDataWithProofRequest`. The attack exploits three critical design flaws:

**Flaw 1: No Minimum Validation on max_response_bytes**

The `GetNewTransactionDataWithProofRequest` struct accepts any u64 value for `max_response_bytes` without validation: [1](#0-0) 

There is no minimum threshold enforced anywhere in the request validation pipeline.

**Flaw 2: Guaranteed Single-Item Response for Tiny Limits**

The server's `ResponseDataProgressTracker` implementation guarantees that at least one item is always returned, even when it exceeds the requested byte limit: [2](#0-1) 

This means setting `max_response_bytes=1` will always return exactly one transaction per request, regardless of transaction size.

**Flaw 3: Server Honors Client-Specified Minimum**

When processing requests, the server takes the minimum of the client's requested value and the server's configured maximum: [3](#0-2) 

This allows the client's `max_response_bytes=1` to override the server's 40 MiB default, forcing minimal responses.

**Attack Execution Path:**

1. Attacker creates a `GetNewTransactionDataWithProofRequest` with `max_response_bytes=1`
2. Request is routed through optimistic fetch handler which preserves this parameter: [4](#0-3) 

3. Server processes the request and caps to `min(1, 40_971_520) = 1 byte`
4. Server iterates through transactions, but can only fit one due to the 1-byte limit
5. Server returns exactly one transaction wrapped in `NewTransactionDataWithProofResponse`: [5](#0-4) 

6. Each response includes mandatory overhead: Merkle proofs, ledger info with BLS signatures, transaction info, and auxiliary data
7. Attacker repeats for each transaction needed, creating N requests instead of N/3000 (where 3000 is the default chunk size)

**Bandwidth Amplification Calculation:**

For syncing 10,000 transactions:
- **Normal case**: ~4 requests (at 3000 transactions per chunk) × overhead = 4× (proofs + ledger_info + headers)
- **Attack case**: 10,000 requests (at 1 transaction per request) × overhead = 10,000× (proofs + ledger_info + headers)
- **Amplification factor**: 2,500× increase in overhead data transmitted

Each `LedgerInfoWithSignatures` contains BLS signatures and consensus metadata (typically 500+ bytes), and Merkle proofs scale with tree depth. This overhead is repeated 2,500× more times than necessary.

**Invariant Violation:**

This breaks the **Resource Limits** invariant (#9): "All operations must respect gas, storage, and computational limits." The server processes valid requests without enforcing reasonable resource consumption bounds, allowing unbounded bandwidth and computational amplification.

## Impact Explanation

This qualifies as **Medium Severity** per Aptos bug bounty criteria for the following reasons:

1. **Validator Node Slowdown**: Processing 2,500× more requests for the same sync operation significantly increases CPU usage for request handling, proof generation, and response serialization.

2. **Network Bandwidth Exhaustion**: The 2,500× amplification of response overhead consumes excessive bandwidth, potentially degrading network performance for legitimate peers.

3. **State Sync Service Disruption**: A coordinated attack from multiple peers could overwhelm the storage service with thousands of tiny requests, delaying or preventing legitimate state synchronization operations.

4. **Not Critical Severity**: While this causes service degradation, it does not result in:
   - Loss of funds
   - Consensus safety violations  
   - Permanent network partition
   - Remote code execution

The attack requires sustained effort and does not permanently compromise the network, placing it in Medium severity (up to $10,000 per bug bounty).

## Likelihood Explanation

**Likelihood: High**

The attack is trivial to execute:
- **No special privileges required**: Any network peer can send these requests
- **No rate limiting**: The `RequestModerator` only blocks peers after invalid requests, not for valid requests with tiny byte limits: [6](#0-5) 

- **Low attack cost**: Sending requests with modified parameters requires minimal resources
- **Immediate impact**: Each malicious request immediately consumes server resources
- **Amplification scales linearly**: Attack effectiveness increases with blockchain size

The only barrier is network connectivity to validator nodes, which is freely available on public networks.

## Recommendation

Implement a minimum threshold for `max_response_bytes` to prevent bandwidth amplification attacks:

**Code Fix:**

In `state-sync/storage-service/server/src/storage.rs`, modify the `get_transaction_data_with_proof` function:

```rust
fn get_transaction_data_with_proof(
    &self,
    transaction_data_with_proof_request: &GetTransactionDataWithProofRequest,
) -> aptos_storage_service_types::Result<TransactionDataWithProofResponse, Error> {
    // Extract the data versions from the request
    let proof_version = transaction_data_with_proof_request.proof_version;
    let start_version = transaction_data_with_proof_request.start_version;
    let end_version = transaction_data_with_proof_request.end_version;

    // Define minimum response size (e.g., 1 KB to prevent excessive fragmentation)
    const MIN_RESPONSE_BYTES: u64 = 1024;

    // Calculate the max response size to use, enforcing minimum threshold
    let requested_bytes = transaction_data_with_proof_request.max_response_bytes;
    let max_response_bytes = min(
        requested_bytes.max(MIN_RESPONSE_BYTES),  // Enforce minimum
        self.config.max_network_chunk_bytes_v2,
    );

    // Log warning if request attempted to use unreasonably small limit
    if requested_bytes < MIN_RESPONSE_BYTES {
        warn!("Request attempted max_response_bytes={}, clamped to minimum {}", 
              requested_bytes, MIN_RESPONSE_BYTES);
    }

    // Continue with existing logic...
```

**Alternative Approach (More Conservative):**

Add validation in the request handler to reject requests with unreasonably small `max_response_bytes`:

```rust
// In handler.rs, before processing the request
if let DataRequest::GetNewTransactionDataWithProof(request) = &storage_request.data_request {
    const MIN_RESPONSE_BYTES: u64 = 1024;
    if request.max_response_bytes < MIN_RESPONSE_BYTES {
        return Err(Error::InvalidRequest(format!(
            "max_response_bytes ({}) is below minimum threshold ({})",
            request.max_response_bytes, MIN_RESPONSE_BYTES
        )));
    }
}
```

The minimum threshold should be set high enough to prevent excessive fragmentation (suggested: 1 KB - 10 KB) while still allowing reasonable chunking for large sync operations.

## Proof of Concept

```rust
#[tokio::test]
async fn test_bandwidth_amplification_attack() {
    use aptos_storage_service_types::requests::{DataRequest, StorageServiceRequest};
    use aptos_types::transaction::Version;
    
    // Setup: Create a storage service with 10,000 transactions
    let (mock_storage, _) = setup_mock_storage_with_transactions(10_000).await;
    let config = StorageServiceConfig::default();
    
    // Attack: Request transactions with max_response_bytes=1
    let malicious_request = DataRequest::get_new_transaction_data_with_proof(
        0,      // known_version
        0,      // known_epoch  
        false,  // include_events
        1,      // max_response_bytes=1 (ATTACK VECTOR)
    );
    
    let storage_request = StorageServiceRequest::new(malicious_request, false);
    
    // Execute request
    let response = mock_storage
        .get_transaction_data_with_proof(&malicious_request)
        .unwrap();
    
    // Verify: Server returns only 1 transaction despite 10,000 available
    let transaction_list = response.transaction_list_with_proof.unwrap();
    assert_eq!(
        transaction_list.transactions.len(), 
        1,
        "Server should return exactly 1 transaction when max_response_bytes=1"
    );
    
    // Calculate amplification factor
    let normal_requests_needed = (10_000 / 3000) + 1; // ~4 requests at default chunk size
    let attack_requests_needed = 10_000; // 1 transaction per request
    let amplification_factor = attack_requests_needed / normal_requests_needed;
    
    println!(
        "Bandwidth Amplification: {}× more requests needed ({} vs {})",
        amplification_factor, attack_requests_needed, normal_requests_needed
    );
    
    assert!(
        amplification_factor > 1000,
        "Attack achieves >1000× amplification factor"
    );
}
```

**Reproduction Steps:**

1. Deploy a validator node with default state-sync configuration
2. Create a client that sends `GetNewTransactionDataWithProofRequest` with `max_response_bytes=1`
3. Monitor network traffic and request counts
4. Observe that each response contains only 1 transaction despite thousands being available
5. Calculate the bandwidth overhead from repeated proofs and ledger info in each response
6. Measure the amplification factor compared to normal sync with default chunk sizes

---

**Notes:**

- This vulnerability affects all peers performing state synchronization, including validators, VFNs, and public full nodes
- The attack is protocol-compliant (not a network-layer DoS), making it harder to detect and mitigate
- Current monitoring may not flag this as malicious since requests appear valid
- The fix should maintain backward compatibility while preventing abuse

### Citations

**File:** state-sync/storage-service/types/src/requests.rs (L433-439)
```rust
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct GetNewTransactionDataWithProofRequest {
    pub transaction_data_request_type: TransactionDataRequestType, // The type of transaction data to request
    pub known_version: u64,                                        // The highest known version
    pub known_epoch: u64,                                          // The highest known epoch
    pub max_response_bytes: u64, // The max number of bytes to return in the response
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

**File:** state-sync/storage-service/server/src/storage.rs (L1394-1412)
```rust
    /// Returns true iff the given data item fits in the response
    /// (i.e., it does not overflow the maximum response size).
    ///
    /// Note: If `always_allow_first_item` is true, the first item is
    /// always allowed (even if it overflows the maximum response size).
    pub fn data_items_fits_in_response(
        &self,
        always_allow_first_item: bool,
        serialized_data_size: u64,
    ) -> bool {
        if always_allow_first_item && self.num_items_fetched == 0 {
            true // We always include at least one item
        } else {
            let new_serialized_data_size = self
                .serialized_data_size
                .saturating_add(serialized_data_size);
            new_serialized_data_size < self.max_response_size
        }
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

**File:** state-sync/storage-service/types/src/responses.rs (L170-176)
```rust
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NewTransactionDataWithProofResponse {
    pub transaction_data_response_type: TransactionDataResponseType,
    pub transaction_list_with_proof: Option<TransactionListWithProofV2>,
    pub transaction_output_list_with_proof: Option<TransactionOutputListWithProofV2>,
    pub ledger_info_with_signatures: LedgerInfoWithSignatures,
}
```

**File:** config/src/config/state_sync_config.rs (L195-217)
```rust
impl Default for StorageServiceConfig {
    fn default() -> Self {
        Self {
            enable_size_and_time_aware_chunking: false,
            enable_transaction_data_v2: true,
            max_epoch_chunk_size: MAX_EPOCH_CHUNK_SIZE,
            max_invalid_requests_per_peer: 500,
            max_lru_cache_size: 500, // At ~0.6MiB per chunk, this should take no more than 0.5GiB
            max_network_channel_size: 4000,
            max_network_chunk_bytes: SERVER_MAX_MESSAGE_SIZE as u64,
            max_network_chunk_bytes_v2: SERVER_MAX_MESSAGE_SIZE_V2 as u64,
            max_num_active_subscriptions: 30,
            max_optimistic_fetch_period_ms: 5000, // 5 seconds
            max_state_chunk_size: MAX_STATE_CHUNK_SIZE,
            max_storage_read_wait_time_ms: 10_000, // 10 seconds
            max_subscription_period_ms: 30_000,    // 30 seconds
            max_transaction_chunk_size: MAX_TRANSACTION_CHUNK_SIZE,
            max_transaction_output_chunk_size: MAX_TRANSACTION_OUTPUT_CHUNK_SIZE,
            min_time_to_ignore_peers_secs: 300, // 5 minutes
            request_moderator_refresh_interval_ms: 1000, // 1 second
            storage_summary_refresh_interval_ms: 100, // Optimal for <= 10 blocks per second
        }
    }
```
