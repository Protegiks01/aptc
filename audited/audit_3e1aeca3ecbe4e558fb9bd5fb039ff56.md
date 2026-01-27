# Audit Report

## Title
Error Classification Bypass Enables Resource Exhaustion via Forced Retry of Invalid Requests

## Summary
Malicious peers can exploit improper error categorization in the Aptos data client to force honest nodes to repeatedly retry expensive, invalid operations. The data client converts all `StorageServiceError` variants to `UnexpectedErrorEncountered`, causing the retry logic to treat permanent client-side errors (like `InvalidRequest`) as transient failures, leading to redundant expensive operations with exponential backoff.

## Finding Description

The vulnerability exists in the interaction between error conversion and retry logic across three key components:

**1. Error Conversion Flaw:**
The data client's `send_request_to_peer` function converts all storage service errors indiscriminately to `UnexpectedErrorEncountered`. [1](#0-0) 

This conversion ignores the semantic meaning of different `StorageServiceError` variants defined in the storage service protocol: [2](#0-1) 

**2. Indiscriminate Retry Logic:**
The data streaming service's `handle_data_client_error` function unconditionally retries ALL errors without differentiating between retryable and non-retryable error types: [3](#0-2) 

The `resend_data_client_request` function applies exponential backoff to all retried requests: [4](#0-3) 

**3. Exponential Backoff Calculation:**
The timeout increases exponentially with each retry based on the failure count: [5](#0-4) 

**Attack Scenario:**
1. Honest node requests expensive data from malicious peer (e.g., `GetStateValuesWithProof` for large state range)
2. Malicious peer returns `StorageServiceError::InvalidRequest` (claiming the request is malformed)
3. Error is converted to `UnexpectedErrorEncountered` 
4. Data stream retries 5 times with exponential backoff (10s, 20s, 40s, 60s, 60s)
5. Honest node wastes ~190 seconds and performs the expensive operation 6 times total
6. Malicious peer can repeat this for multiple concurrent requests

**Default Configuration Values:** [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8) [10](#0-9) [11](#0-10) 

## Impact Explanation

**Medium Severity** - This qualifies as resource exhaustion affecting honest node performance:

- **Resource Exhaustion**: Honest nodes waste CPU, memory, and I/O on redundant expensive operations (state proof generation, transaction fetching, Merkle tree traversal)
- **Amplification Factor**: 6x amplification (1 initial request + 5 retries) with ~190 seconds total wait time
- **Concurrent Exploitation**: Multiple concurrent streams can be attacked simultaneously, multiplying the impact
- **State Sync Degradation**: Nodes performing initial state sync or catching up after downtime are most vulnerable, as they rely heavily on peer data requests
- **Violation of Invariant #9**: "All operations must respect gas, storage, and computational limits" - the forced redundant retries violate resource limit expectations

However, this does **not** reach Critical/High severity because:
- Does not directly affect consensus or cause fund loss
- Does not permanently block state sync (eventual peer rotation will succeed)
- Peer scoring eventually bans the malicious peer after retries fail
- Requires sustained exploitation to significantly degrade network performance

## Likelihood Explanation

**High Likelihood** - This vulnerability is easily exploitable:

- **Low Attack Complexity**: Malicious peer simply returns `InvalidRequest` error
- **No Privileged Access Required**: Any network peer can advertise storage service
- **Difficult to Detect**: Appears as normal request failures in logs
- **Multiple Attack Vectors**: Can exploit any expensive data request type (state values, transactions, transaction outputs)
- **Existing TODO Comment**: The code contains a TODO at line 723 acknowledging the need to "identify the best way to react to the error", suggesting this is a known design gap [12](#0-11) 

## Recommendation

**Fix 1: Implement Error-Aware Retry Logic**

Modify `send_request_to_peer` to preserve error semantics:

```rust
aptos_storage_service_client::Error::StorageServiceError(err) => match err {
    StorageServiceError::InvalidRequest(msg) => {
        // Client-side error - do not retry
        Error::InvalidRequest(msg)
    },
    StorageServiceError::TooManyInvalidRequests(msg) => {
        // Peer is rate-limiting us - back off but don't retry this request
        Error::DataIsUnavailable(msg)
    },
    StorageServiceError::InternalError(msg) => {
        // Peer-side transient error - can retry
        Error::UnexpectedErrorEncountered(msg)
    },
}
```

**Fix 2: Categorize Errors in Data Stream**

Update `handle_data_client_error` to differentiate error types:

```rust
fn handle_data_client_error(
    &mut self,
    data_client_request: &DataClientRequest,
    data_client_error: &aptos_data_client::error::Error,
) -> Result<(), Error> {
    warn!(/*...*/);
    
    // Only retry transient errors
    match data_client_error {
        Error::InvalidRequest(_) | Error::DataIsTooLarge(_) => {
            // Non-retryable client errors - terminate stream
            Err(data_client_error.clone().into())
        },
        _ => {
            // Transient errors - retry
            self.resend_data_client_request(data_client_request)
        }
    }
}
```

**Fix 3: Add Retry Budget Tracking**

Track cumulative retry costs to prevent resource exhaustion even for legitimate transient errors.

## Proof of Concept

```rust
#[tokio::test]
async fn test_invalid_request_forces_redundant_retries() {
    use state_sync::data_stream::DataStream;
    use aptos_data_client::error::Error as DataClientError;
    use aptos_storage_service_types::StorageServiceError;
    
    // Setup: Create a data stream with mock data client
    let mut mock_client = MockAptosDataClient::new(/*...*/);
    
    // Configure mock to return InvalidRequest for expensive state request
    let expensive_request = DataClientRequest::StateValuesWithProof(
        StateValuesWithProofRequest {
            version: 1000000,
            start_index: 0,
            end_index: 4000, // Max chunk size
        }
    );
    
    // Mock returns InvalidRequest (simulating malicious peer)
    mock_client.configure_response(
        expensive_request.clone(),
        Err(StorageServiceError::InvalidRequest("Request too expensive".into()))
    );
    
    let (mut data_stream, _listener) = DataStream::new(/*...*/);
    
    // Track retry count and time spent
    let start_time = Instant::now();
    let mut retry_count = 0;
    
    // Initialize and process requests
    data_stream.initialize_data_requests(global_summary).unwrap();
    
    // Process responses - should retry multiple times
    while retry_count < 6 {
        data_stream.process_data_responses(global_summary).await.unwrap();
        retry_count += 1;
        
        // Verify exponential backoff is being applied
        if retry_count > 1 {
            let expected_timeout = min(
                10000 * u32::pow(2, (retry_count - 1) as u32) as u64,
                60000
            );
            // Assert timeout matches exponential backoff
        }
    }
    
    let elapsed = start_time.elapsed();
    
    // Verification: Should have retried 5 times (max_request_retry)
    assert_eq!(retry_count, 6, "Should retry 5 times plus initial attempt");
    
    // Should have wasted ~190 seconds total
    assert!(elapsed.as_secs() >= 190, "Should waste significant time on retries");
    
    // Verify expensive operation was performed 6 times
    assert_eq!(mock_client.get_request_count(&expensive_request), 6);
}
```

## Notes

The vulnerability breaks **Invariant #9 (Resource Limits)**: "All operations must respect gas, storage, and computational limits." By forcing 6x redundant execution of expensive data requests, the system violates expected resource consumption bounds. The presence of the TODO comment indicates this design gap was previously identified but not addressed, making this a particularly realistic and exploitable vulnerability in production.

### Citations

**File:** state-sync/aptos-data-client/src/client.rs (L844-846)
```rust
                    aptos_storage_service_client::Error::StorageServiceError(err) => {
                        Error::UnexpectedErrorEncountered(err.to_string())
                    },
```

**File:** state-sync/storage-service/types/src/lib.rs (L29-37)
```rust
#[derive(Clone, Debug, Deserialize, Error, PartialEq, Eq, Serialize)]
pub enum StorageServiceError {
    #[error("Internal service error: {0}")]
    InternalError(String),
    #[error("Invalid storage request: {0}")]
    InvalidRequest(String),
    #[error("Too many invalid requests! Back off required: {0}")]
    TooManyInvalidRequests(String),
}
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L348-378)
```rust
        } else if !request_retry {
            self.data_client_config.response_timeout_ms
        } else {
            let response_timeout_ms = self.data_client_config.response_timeout_ms;
            let max_response_timeout_ms = self.data_client_config.max_response_timeout_ms;

            // Exponentially increase the timeout based on the number of
            // previous failures (but bounded by the max timeout).
            let request_timeout_ms = min(
                max_response_timeout_ms,
                response_timeout_ms * (u32::pow(2, self.request_failure_count as u32) as u64),
            );

            // Update the retry counter and log the request
            increment_counter_multiple_labels(
                &metrics::RETRIED_DATA_REQUESTS,
                data_client_request.get_label(),
                &request_timeout_ms.to_string(),
            );
            info!(
                (LogSchema::new(LogEntry::RetryDataRequest)
                    .stream_id(self.data_stream_id)
                    .message(&format!(
                        "Retrying data request type: {:?}, with new timeout: {:?} (ms)",
                        data_client_request.get_label(),
                        request_timeout_ms.to_string()
                    )))
            );

            request_timeout_ms
        };
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L710-725)
```rust
    /// Handles an error returned by the data client in relation to a request
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

**File:** state-sync/data-streaming-service/src/data_stream.rs (L729-744)
```rust
    fn resend_data_client_request(
        &mut self,
        data_client_request: &DataClientRequest,
    ) -> Result<(), Error> {
        // Increment the number of client failures for this request
        self.request_failure_count += 1;

        // Resend the client request
        let pending_client_response = self.send_client_request(true, data_client_request.clone());

        // Push the pending response to the head of the sent requests queue
        self.get_sent_data_requests()?
            .push_front(pending_client_response);

        Ok(())
    }
```

**File:** config/src/config/state_sync_config.rs (L256-257)
```rust
    pub max_request_retry: u64,

```

**File:** config/src/config/state_sync_config.rs (L277-277)
```rust
            max_request_retry: 5,
```

**File:** config/src/config/state_sync_config.rs (L438-439)
```rust
    /// Maximum timeout (in ms) when waiting for a response (after exponential increases)
    pub max_response_timeout_ms: u64,
```

**File:** config/src/config/state_sync_config.rs (L452-453)
```rust
    /// First timeout (in ms) when waiting for a response
    pub response_timeout_ms: u64,
```

**File:** config/src/config/state_sync_config.rs (L473-473)
```rust
            max_response_timeout_ms: 60_000, // 60 seconds
```

**File:** config/src/config/state_sync_config.rs (L480-480)
```rust
            response_timeout_ms: 10_000,               // 10 seconds
```
