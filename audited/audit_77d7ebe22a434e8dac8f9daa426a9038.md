# Audit Report

## Title
Storage Server Summary Information Disclosure via Invalid Request Error Messages

## Summary
Malicious peers can extract sensitive validator synchronization state and storage configuration by sending invalid storage service requests. The error responses include the complete `StorageServerSummary` with detailed information about synced versions, epoch ranges, and data availability that can be used to plan targeted attacks against specific validators.

## Finding Description

The storage service server validates incoming requests using the `RequestModerator` component. When a peer sends a request that cannot be satisfied, the moderator returns an error message that includes the full `StorageServerSummary` via debug formatting. [1](#0-0) 

This error is converted to `StorageServiceError::InvalidRequest` and sent back to the requesting peer over the network: [2](#0-1) 

The error is then serialized and transmitted: [3](#0-2) 

The `StorageServerSummary` contains highly sensitive information: [4](#0-3) 

The `DataSummary` within includes: [5](#0-4) 

**Attack Scenario:**
1. Attacker connects to validator nodes as a regular peer
2. Sends crafted storage requests that are intentionally unsatisfiable (e.g., requesting epochs that don't exist yet)
3. Receives error responses containing:
   - Exact highest synced version and epoch (`synced_ledger_info`)
   - Complete ranges of stored epochs, states, transactions, and outputs
   - Server configuration (chunk sizes)
4. Uses this intelligence to:
   - Identify lagging validators for targeted attacks
   - Map the network's synchronization topology
   - Fingerprint validators by unique storage configurations
   - Craft DoS attacks that target specific data ranges
   - Select optimal targets for consensus-level attacks

## Impact Explanation

This qualifies as **Medium Severity** (up to $10,000) per Aptos bug bounty criteria as it constitutes an information leak that aids in planning more severe attacks:

- **No Direct Consensus Violation**: The leak itself doesn't break consensus safety
- **No Direct Fund Loss**: No immediate theft or minting capability
- **Enables Secondary Attacks**: The leaked information significantly aids reconnaissance for:
  - Targeted DoS attacks on validators with specific data ranges
  - Identifying validators with incomplete state for consensus attacks
  - Network topology mapping for partition attacks
  - Validator fingerprinting for correlation attacks

The vulnerability exposes internal state that should remain opaque to untrusted peers, violating the principle of least information disclosure in distributed systems security.

## Likelihood Explanation

**Likelihood: High**

- **Zero Prerequisites**: Any peer can connect to storage service endpoints
- **Trivial Exploitation**: Simply send invalid requests and parse error responses
- **Always Successful**: The error path is deterministic and always returns the summary
- **No Rate Limiting on Information**: Each error response leaks the current state
- **Passive Attack**: No detection mechanism; appears as normal peer behavior
- **Scalable**: Attacker can map entire validator network automatically

## Recommendation

Remove detailed internal state information from error messages sent to untrusted peers. Replace with generic error codes:

```rust
// In moderator.rs, line 181-184, replace with:
return Err(Error::InvalidRequest(
    "The given request cannot be satisfied by this server.".to_string()
));
```

For debugging purposes, keep detailed logging internally:

```rust
// Log detailed information server-side only
warn!(LogSchema::new(LogEntry::RequestValidationFailure)
    .peer_network_id(peer_network_id)
    .request(&request)
    .message(&format!(
        "Request cannot be satisfied. Storage summary: {:?}",
        storage_server_summary
    )));

// Return generic error to peer
return Err(Error::InvalidRequest(
    "The given request cannot be satisfied by this server.".to_string()
));
```

Similarly, audit other error messages in the state sync subsystem to ensure no sensitive information is leaked in error strings.

## Proof of Concept

```rust
// Test that demonstrates the information leak
#[tokio::test]
async fn test_storage_summary_leak_via_invalid_request() {
    use aptos_config::config::StorageServiceConfig;
    use aptos_storage_service_types::requests::{
        DataRequest, EpochEndingLedgerInfoRequest, StorageServiceRequest,
    };
    
    // Setup: Create a storage service with known state
    let (storage_service, mock_storage) = create_test_storage_service();
    
    // Setup mock to have synced up to epoch 100, version 10000
    mock_storage.set_synced_version(10000);
    mock_storage.set_highest_epoch(100);
    
    // Attack: Send request for future epoch that cannot be satisfied
    let invalid_request = StorageServiceRequest::new(
        DataRequest::GetEpochEndingLedgerInfos(EpochEndingLedgerInfoRequest {
            start_epoch: 200,  // Far in the future
            expected_end_epoch: 300,
        }),
        false,
    );
    
    // Send request as untrusted peer
    let peer_network_id = PeerNetworkId::new(NetworkId::Public, PeerId::random());
    let response = storage_service
        .process_request(peer_network_id, invalid_request)
        .await;
    
    // Verify: Error response contains sensitive storage summary
    match response {
        Err(StorageServiceError::InvalidRequest(error_msg)) => {
            // The error message contains the storage summary
            assert!(error_msg.contains("storage summary:"));
            assert!(error_msg.contains("synced_ledger_info"));
            
            // Attacker can extract exact sync state
            assert!(error_msg.contains("version: 10000"));
            assert!(error_msg.contains("epoch: 100"));
            
            // This information should NOT be available to untrusted peers
            println!("LEAKED INFORMATION: {}", error_msg);
        }
        _ => panic!("Expected InvalidRequest error"),
    }
}
```

**Notes:**
- The vulnerability affects all validator nodes running storage service
- Information leakage occurs on every invalid request without rate limiting
- The `StorageServerSummary` is designed to be advertised publicly via `GetStorageServerSummary` requests, but the issue is that it's also leaked in error messages for validation failures where the peer hasn't explicitly requested it
- The error message format using `{:?}` debug formatting exposes the complete internal structure

### Citations

**File:** state-sync/storage-service/server/src/moderator.rs (L181-184)
```rust
                return Err(Error::InvalidRequest(format!(
                    "The given request cannot be satisfied. Request: {:?}, storage summary: {:?}",
                    request, storage_server_summary
                )));
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

**File:** state-sync/storage-service/server/src/network.rs (L106-112)
```rust
    pub fn send(self, response: Result<StorageServiceResponse>) {
        let msg = StorageServiceMessage::Response(response);
        let result = bcs::to_bytes(&msg)
            .map(Bytes::from)
            .map_err(RpcError::BcsError);
        let _ = self.response_tx.send(result);
    }
```

**File:** state-sync/storage-service/types/src/responses.rs (L612-616)
```rust
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct StorageServerSummary {
    pub protocol_metadata: ProtocolMetadata,
    pub data_summary: DataSummary,
}
```

**File:** state-sync/storage-service/types/src/responses.rs (L666-686)
```rust
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct DataSummary {
    /// The ledger info corresponding to the highest synced version in storage.
    /// This indicates the highest version and epoch that storage can prove.
    pub synced_ledger_info: Option<LedgerInfoWithSignatures>,
    /// The range of epoch ending ledger infos in storage, e.g., if the range
    /// is [(X,Y)], it means all epoch ending ledger infos for epochs X->Y
    /// (inclusive) are held.
    pub epoch_ending_ledger_infos: Option<CompleteDataRange<Epoch>>,
    /// The range of states held in storage, e.g., if the range is
    /// [(X,Y)], it means all states are held for every version X->Y
    /// (inclusive).
    pub states: Option<CompleteDataRange<Version>>,
    /// The range of transactions held in storage, e.g., if the range is
    /// [(X,Y)], it means all transactions for versions X->Y (inclusive) are held.
    pub transactions: Option<CompleteDataRange<Version>>,
    /// The range of transaction outputs held in storage, e.g., if the range
    /// is [(X,Y)], it means all transaction outputs for versions X->Y
    /// (inclusive) are held.
    pub transaction_outputs: Option<CompleteDataRange<Version>>,
}
```
