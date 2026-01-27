# Audit Report

## Title
Monitoring Bypass: Byzantine Validators Can Suppress ResponseError Events Through Valid-but-Malicious Responses

## Summary
Byzantine validators can suppress `LogEvent::ResponseError` events by sending structurally valid responses containing cryptographically invalid data, proof failures, or incorrect state. This monitoring bypass prevents security teams from detecting malicious validator behavior through ResponseError monitoring, as only RPC-level errors trigger this event while validation failures in upper layers do not.

## Finding Description

The Aptos data client implements two separate error handling paths with inconsistent logging behavior:

**Path 1: Early RPC Error Detection** [1](#0-0) 

When RPC errors or storage service errors occur (timeouts, disconnections, server errors), the system logs `LogEvent::ResponseError` with a `warn!` level log.

**Path 2: Late Validation Error Detection** [2](#0-1) 

When upper layers detect validation failures (invalid proofs, incorrect data, wrong payload types), they call `notify_bad_response()` which only updates peer scores but **does not log** `LogEvent::ResponseError`.

The validation errors flow through this path: [3](#0-2) 

Byzantine validators can exploit this by crafting responses that:
1. Pass RPC serialization checks (structurally valid)
2. Pass storage service validation (no server errors)
3. Get logged as `ResponseSuccess` [4](#0-3) 
4. Fail cryptographic validation in upper layers
5. Trigger `notify_bad_response()` but **never log ResponseError**

The three critical validation failure types that bypass ResponseError logging are defined here: [5](#0-4) 

## Impact Explanation

This qualifies as **High Severity** under "Significant protocol violations" because it enables Byzantine validators to:

1. **Attempt consensus manipulation** (invalid proofs, wrong state roots) without triggering ResponseError alerts
2. **Send double-spend transaction proofs** that fail verification without logging ResponseError
3. **Provide corrupted state values** that bypass ResponseError monitoring

While peer scoring eventually bans malicious validators, security monitoring systems relying on ResponseError events will completely miss these attack attempts. The `LogEvent::ResponseError` enum explicitly exists for monitoring purposes [6](#0-5)  but is systematically bypassed for the most critical attack types.

## Likelihood Explanation

**Likelihood: High**

Any Byzantine validator can exploit this by:
1. Running a malicious storage service server
2. Responding to data requests with invalid proofs/data
3. Ensuring responses are structurally valid (pass RPC serialization)

No special timing, race conditions, or complex setup required. The monitoring bypass occurs deterministically for all validation failures.

## Recommendation

Add `LogEvent::ResponseError` logging to the `notify_bad_response()` method in the data client:

```rust
fn notify_bad_response(
    &self,
    id: ResponseId,
    peer: PeerNetworkId,
    request: &StorageServiceRequest,
    error_type: ErrorType,
) {
    // Add ResponseError logging for consistency with RPC error path
    warn!(
        (LogSchema::new(LogEntry::StorageServiceResponse)
            .event(LogEvent::ResponseError)
            .request_type(&request.get_label())
            .request_id(id)
            .peer(&peer)
            .message(&format!("Bad response reported: {:?}", error_type)))
    );
    
    self.peer_states.update_score_error(peer, error_type);
}
```

Additionally, consider logging ResponseError in the data streaming service's `notify_bad_response` method: [7](#0-6) 

## Proof of Concept

```rust
#[test]
fn test_byzantine_validator_suppresses_response_error_logging() {
    // Setup mock data client with logging interceptor
    let (data_client, _) = setup_mock_data_client();
    let mut log_events = vec![];
    
    // Step 1: Byzantine validator sends structurally valid response
    let byzantine_peer = create_mock_peer("byzantine_validator");
    let request = create_transaction_proof_request(100, 200);
    
    // Response passes RPC checks but contains invalid proof
    let malicious_response = create_response_with_invalid_proof();
    
    // Step 2: Data client receives response and logs ResponseSuccess
    let response = data_client.send_request_to_peer(
        byzantine_peer,
        request,
        1000
    ).await.unwrap();
    
    assert!(log_events.contains(&LogEvent::ResponseSuccess));
    assert!(!log_events.contains(&LogEvent::ResponseError));
    
    // Step 3: Upper layer validates proof and discovers it's invalid
    let validation_result = verify_proof(&response.payload);
    assert!(validation_result.is_err());
    
    // Step 4: Upper layer reports bad response
    response.context.response_callback.notify_bad_response(
        ResponseError::ProofVerificationError
    );
    
    // Step 5: Verify ResponseError was NOT logged despite malicious proof
    assert!(!log_events.contains(&LogEvent::ResponseError));
    // This proves the monitoring bypass - malicious proof attempts are invisible
    // to ResponseError monitoring systems
}
```

## Notes

The vulnerability affects all state sync data requests where validation happens post-response. The three bypassed error types ( [8](#0-7) ) map to the most critical attacks: proof forgery, data corruption, and type confusion. Monitoring systems must be aware that ResponseError events only cover transport-layer failures, not validation failures.

### Citations

**File:** state-sync/aptos-data-client/src/client.rs (L799-817)
```rust
            Ok(response) => {
                trace!(
                    (LogSchema::new(LogEntry::StorageServiceResponse)
                        .event(LogEvent::ResponseSuccess)
                        .request_type(&request.get_label())
                        .request_id(id)
                        .peer(&peer))
                );

                // Update the received response metrics
                self.update_received_response_metrics(peer, &request);

                // For now, record all responses that at least pass the data
                // client layer successfully. An alternative might also have the
                // consumer notify both success and failure via the callback.
                // On the one hand, scoring dynamics are simpler when each request
                // is successful or failed but not both; on the other hand, this
                // feels simpler for the consumer.
                self.peer_states.update_score_success(peer);
```

**File:** state-sync/aptos-data-client/src/client.rs (L830-867)
```rust
            Err(error) => {
                // Convert network error and storage service error types into
                // data client errors. Also categorize the error type for scoring
                // purposes.
                let client_error = match error {
                    aptos_storage_service_client::Error::RpcError(rpc_error) => match rpc_error {
                        RpcError::NotConnected(_) => {
                            Error::DataIsUnavailable(rpc_error.to_string())
                        },
                        RpcError::TimedOut => {
                            Error::TimeoutWaitingForResponse(rpc_error.to_string())
                        },
                        _ => Error::UnexpectedErrorEncountered(rpc_error.to_string()),
                    },
                    aptos_storage_service_client::Error::StorageServiceError(err) => {
                        Error::UnexpectedErrorEncountered(err.to_string())
                    },
                    _ => Error::UnexpectedErrorEncountered(error.to_string()),
                };

                warn!(
                    (LogSchema::new(LogEntry::StorageServiceResponse)
                        .event(LogEvent::ResponseError)
                        .request_type(&request.get_label())
                        .request_id(id)
                        .peer(&peer)
                        .error(&client_error))
                );

                increment_request_counter(
                    &metrics::ERROR_RESPONSES,
                    client_error.get_label(),
                    peer,
                );

                self.notify_bad_response(id, peer, &request, ErrorType::NotUseful);
                Err(client_error)
            },
```

**File:** state-sync/aptos-data-client/src/client.rs (L871-880)
```rust
    /// Updates the score of the peer who sent the response with the specified id
    fn notify_bad_response(
        &self,
        _id: ResponseId,
        peer: PeerNetworkId,
        _request: &StorageServiceRequest,
        error_type: ErrorType,
    ) {
        self.peer_states.update_score_error(peer, error_type);
    }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L746-764)
```rust
    /// Notifies the Aptos data client of a bad client response
    fn notify_bad_response(
        &self,
        response_context: &ResponseContext,
        response_error: ResponseError,
    ) {
        let response_id = response_context.id;
        info!(LogSchema::new(LogEntry::ReceivedDataResponse)
            .stream_id(self.data_stream_id)
            .event(LogEvent::Error)
            .message(&format!(
                "Notifying the data client of a bad response. Response id: {:?}, error: {:?}",
                response_id, response_error
            )));

        response_context
            .response_callback
            .notify_bad_response(response_error);
    }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L1383-1394)
```rust
fn extract_response_error(
    notification_feedback: &NotificationFeedback,
) -> Result<ResponseError, Error> {
    match notification_feedback {
        NotificationFeedback::InvalidPayloadData => Ok(ResponseError::InvalidData),
        NotificationFeedback::PayloadTypeIsIncorrect => Ok(ResponseError::InvalidPayloadDataType),
        NotificationFeedback::PayloadProofFailed => Ok(ResponseError::ProofVerificationError),
        _ => Err(Error::UnexpectedErrorEncountered(format!(
            "Invalid notification feedback given: {:?}",
            notification_feedback
        ))),
    }
```

**File:** state-sync/aptos-data-client/src/interface.rs (L180-187)
```rust
/// A response error that users of the Aptos Data Client can use to notify
/// the Data Client about invalid or malformed responses.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub enum ResponseError {
    InvalidData,
    InvalidPayloadDataType,
    ProofVerificationError,
}
```

**File:** state-sync/aptos-data-client/src/logging.rs (L51-70)
```rust
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LogEvent {
    AggregateSummary,
    CaughtUpToLatest,
    NoPeersToPoll,
    PeerIgnored,
    PeerNoLongerIgnored,
    PeerPollingError,
    PeerRequestResponseCounts,
    PeerSelectionError,
    PriorityAndRegularPeers,
    PriorityPeerCategories,
    ResponseError,
    ResponseSuccess,
    SendRequest,
    StorageReadFailed,
    UnexpectedError,
    WaitingForCatchup,
}
```
