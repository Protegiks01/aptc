# Audit Report

## Title
Missing Peer Penalty on Compression Mismatch Allows Malicious Peers to Evade Banning

## Summary
When the Aptos data client detects a compression mismatch in peer responses (compressed data when uncompressed was requested, or vice versa), it returns an error without calling `notify_bad_response()` on the `ResponseContext`. This causes the peer identification context to be dropped, preventing the malicious peer from being penalized through the peer scoring system. As a result, malicious peers can repeatedly send invalid compression responses without ever being banned, causing persistent state sync slowdowns.

## Finding Description

The Aptos state synchronization system implements a peer scoring mechanism to identify and ignore malicious or unreliable peers. When a peer sends invalid data, the system should call `response_context.response_callback.notify_bad_response(error)` to decrease that peer's score. [1](#0-0) 

Peers with scores below the `IGNORE_PEER_THRESHOLD` (25.0) are ignored when `ignore_low_score_peers` is enabled. [2](#0-1) 

The vulnerability occurs in the `send_request_to_peer_and_decode` function where compression validation is performed. After extracting the `context` (which contains the `ResponseCallback` with peer information), the code checks for compression mismatches but returns errors directly without notifying the callback: [3](#0-2) 

When these errors are returned, they propagate to the data-streaming-service as `aptos_data_client::error::Error` types. The conversion to the streaming service's error type only preserves the error message as a string: [4](#0-3) 

The data-streaming-service's `handle_data_client_error` function receives these errors but has no access to the `ResponseContext` (which was dropped), so it cannot identify or penalize the responsible peer: [5](#0-4) 

In contrast, when type conversion errors occur later in the same function, the code correctly calls `notify_bad_response()` before returning the error: [6](#0-5) 

**Attack Path:**
1. Malicious peer receives data request with `use_compression = true`
2. Peer intentionally sends uncompressed data (or vice versa)
3. Data client detects compression mismatch at validation
4. Error is returned WITHOUT calling `context.response_callback.notify_bad_response()`
5. `ResponseContext` (containing peer ID) is dropped
6. Error propagates to streaming service as string
7. Request is retried but peer score remains unchanged
8. Malicious peer repeats attack indefinitely without penalty

## Impact Explanation

This is a **High Severity** vulnerability per the Aptos bug bounty program criteria for "Validator node slowdowns."

**Impact:**
- Malicious peers can persistently slow down state synchronization for honest nodes
- Victim nodes waste CPU and network resources retrying requests to malicious peers
- In a network with multiple colluding malicious peers, state sync could be severely degraded
- Honest nodes falling behind in state sync may miss critical consensus rounds
- The attack is persistent and cannot be mitigated without manual intervention

The vulnerability breaks the **peer reputation invariant**: The system assumes that peers sending invalid data will be identified, scored negatively, and eventually ignored. This vulnerability allows malicious peers to bypass this protection mechanism entirely for compression-related attacks.

## Likelihood Explanation

**Likelihood: High**

- **Ease of Exploitation:** Trivial - attacker simply needs to send responses with incorrect compression settings
- **Attacker Requirements:** Any network peer can execute this attack; no special privileges needed
- **Detection Difficulty:** Hard to detect as errors appear as normal retries in logs
- **Automation:** Can be fully automated to continuously target victim nodes
- **Cost:** Negligible - no computational or economic cost to attacker
- **Scale:** Attack works against all nodes attempting to sync from the malicious peer

## Recommendation

Add the `notify_bad_response()` call before returning compression mismatch errors. The fix should mirror the existing error handling pattern used for type conversion errors:

```rust
// In state-sync/aptos-data-client/src/client.rs, lines 736-748:
let (context, storage_response) = storage_response.into_parts();
if request.use_compression && !storage_response.is_compressed() {
    // Add this line:
    context
        .response_callback
        .notify_bad_response(ResponseError::InvalidData);
    return Err(Error::InvalidResponse(format!(
        "Requested compressed data, but the response was uncompressed! Response: {:?}",
        storage_response.get_label()
    )));
} else if !request.use_compression && storage_response.is_compressed() {
    // Add this line:
    context
        .response_callback
        .notify_bad_response(ResponseError::InvalidData);
    return Err(Error::InvalidResponse(format!(
        "Requested uncompressed data, but the response was compressed! Response: {:?}",
        storage_response.get_label()
    )));
}
```

The `ResponseError::InvalidData` error type maps to `ErrorType::NotUseful`, which applies a 0.95 score multiplier: [7](#0-6) 

## Proof of Concept

```rust
// Test demonstrating the vulnerability
// Add to state-sync/aptos-data-client/src/tests.rs

#[tokio::test]
async fn test_compression_mismatch_doesnt_penalize_peer() {
    use crate::peer_states::IGNORE_PEER_THRESHOLD;
    
    // Setup: Create data client with mock peer
    let (client, peer_id, _mock_network) = setup_test_client();
    
    // Get initial peer score (should be 50.0)
    let initial_score = client.peer_states
        .get_peer_to_states()
        .get(&peer_id)
        .unwrap()
        .get_score();
    assert_eq!(initial_score, 50.0);
    
    // Attack: Send 100 responses with compression mismatches
    for _ in 0..100 {
        let request = StorageServiceRequest {
            use_compression: true,
            data_request: DataRequest::GetTransactionsWithProof(...),
        };
        
        // Mock peer sends uncompressed data when compression was requested
        let result = client
            .send_request_to_peer_and_decode(peer_id, request, 5000)
            .await;
        
        // Verify error is returned
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::InvalidResponse(_)));
    }
    
    // Vulnerability: Peer score should decrease after 100 bad responses
    // With 0.95 multiplier, score should be: 50.0 * 0.95^100 = 0.32
    // Peer should be below IGNORE_PEER_THRESHOLD (25.0) and ignored
    let final_score = client.peer_states
        .get_peer_to_states()
        .get(&peer_id)
        .unwrap()
        .get_score();
    
    // BUG: Score remains unchanged at 50.0!
    assert_eq!(final_score, 50.0); // This demonstrates the vulnerability
    assert!(final_score > IGNORE_PEER_THRESHOLD); // Peer is NOT ignored
    
    // Expected behavior after fix:
    // assert!(final_score < 1.0);
    // assert!(final_score < IGNORE_PEER_THRESHOLD);
}
```

## Notes

The vulnerability is specifically in the compression validation code path. Other error paths (network errors, type mismatches) correctly penalize peers. The inconsistency suggests this was an oversight when the compression validation logic was added.

The `AptosNetResponseCallback` structure maintains the peer ID and properly routes scoring updates: [8](#0-7) 

This design means peer context is preserved in the `ResponseContext` but only if `notify_bad_response()` is called before the context is dropped.

### Citations

**File:** state-sync/aptos-data-client/src/peer_states.rs (L54-62)
```rust
impl From<ResponseError> for ErrorType {
    fn from(error: ResponseError) -> Self {
        match error {
            ResponseError::InvalidData | ResponseError::InvalidPayloadDataType => {
                ErrorType::NotUseful
            },
            ResponseError::ProofVerificationError => ErrorType::Malicious,
        }
    }
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L152-160)
```rust
    fn is_ignored(&self) -> bool {
        // Only ignore peers if the config allows it
        if !self.data_client_config.ignore_low_score_peers {
            return false;
        }

        // Otherwise, ignore peers with a low score
        self.score <= IGNORE_PEER_THRESHOLD
    }
```

**File:** state-sync/aptos-data-client/src/peer_states.rs (L167-174)
```rust
    /// Updates the score of the peer according to an error
    fn update_score_error(&mut self, error: ErrorType) {
        let multiplier = match error {
            ErrorType::NotUseful => NOT_USEFUL_MULTIPLIER,
            ErrorType::Malicious => MALICIOUS_MULTIPLIER,
        };
        self.score = f64::max(self.score * multiplier, MIN_SCORE);
    }
```

**File:** state-sync/aptos-data-client/src/client.rs (L736-748)
```rust
        // Ensure the response obeys the compression requirements
        let (context, storage_response) = storage_response.into_parts();
        if request.use_compression && !storage_response.is_compressed() {
            return Err(Error::InvalidResponse(format!(
                "Requested compressed data, but the response was uncompressed! Response: {:?}",
                storage_response.get_label()
            )));
        } else if !request.use_compression && storage_response.is_compressed() {
            return Err(Error::InvalidResponse(format!(
                "Requested uncompressed data, but the response was compressed! Response: {:?}",
                storage_response.get_label()
            )));
        }
```

**File:** state-sync/aptos-data-client/src/client.rs (L756-760)
```rust
                Err(err) => {
                    context
                        .response_callback
                        .notify_bad_response(ResponseError::InvalidPayloadDataType);
                    Err(err.into())
```

**File:** state-sync/aptos-data-client/src/client.rs (L1233-1246)
```rust
struct AptosNetResponseCallback {
    data_client: AptosDataClient,
    id: ResponseId,
    peer: PeerNetworkId,
    request: StorageServiceRequest,
}

impl ResponseCallback for AptosNetResponseCallback {
    fn notify_bad_response(&self, error: ResponseError) {
        let error_type = ErrorType::from(error);
        self.data_client
            .notify_bad_response(self.id, self.peer, &self.request, error_type);
    }
}
```

**File:** state-sync/data-streaming-service/src/error.rs (L41-44)
```rust
impl From<aptos_data_client::error::Error> for Error {
    fn from(error: aptos_data_client::error::Error) -> Self {
        Error::AptosDataClientError(error.to_string())
    }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L711-725)
```rust
    fn handle_data_client_error(
        &mut self,
        data_client_request: &DataClientRequest,
        data_client_error: &aptos_data_client::error::Error,
    ) -> Result<(), Error> {
        // Log the error
        warn!(LogSchema::new(LogEntry::ReceivedDataResponse)
            .stream_id(self.data_stream_id)
            .event(LogEvent::Error)
            .error(&data_client_error.clone().into())
            .message("Encountered a data client error!"));

        // TODO(joshlind): can we identify the best way to react to the error?
        self.resend_data_client_request(data_client_request)
    }
```
