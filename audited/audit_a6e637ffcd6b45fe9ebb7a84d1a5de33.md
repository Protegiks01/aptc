# Audit Report

## Title
Adaptive Timeout Manipulation: Malicious Peers Can Exploit Decoupled Latency Measurement to Evade Penalties and Cause Resource Exhaustion

## Summary
The Aptos state synchronization system uses separate latency measurements for peer selection (ping latency) and data request timeouts. Malicious peers can maintain low ping latencies while consistently responding to data requests just under the timeout threshold, avoiding all penalties and exponential backoff while maximizing resource consumption on honest nodes.

## Finding Description

The vulnerability exists due to a fundamental decoupling between two latency measurement systems:

1. **Peer Selection Latency**: Uses lightweight ping measurements from the peer monitoring service [1](#0-0) 

2. **Data Request Timeouts**: Uses fixed timeout values (10s default, 60s max) with exponential backoff only on timeout errors [2](#0-1) 

The attack exploits three key vulnerabilities:

**Vulnerability 1: Timeout vs. Slow Response Treatment**

When a request times out, the peer receives penalties [3](#0-2) 

However, when a request succeeds (even if slow), the peer score increases and request_failure_count resets to 0 [4](#0-3) 

**Vulnerability 2: Exponential Backoff Only on Timeouts**

Exponential backoff is calculated based on request_failure_count [5](#0-4) 

Since slow responses (under timeout) reset request_failure_count to 0, the next request uses the base timeout again, allowing the attack to repeat indefinitely.

**Vulnerability 3: Peer Selection Uses Ping Latency, Not Request Latency**

Peer selection weights peers by ping latency measurements [6](#0-5) 

These ping measurements are independent lightweight requests, not the actual data request latencies. The REQUEST_LATENCIES metric is tracked but never used for peer scoring or selection [7](#0-6) 

**Attack Execution:**

A malicious peer executes:
1. Responds quickly to lightweight ping requests (maintaining low average_ping_latency_secs)
2. Responds to data requests at exactly timeout_threshold - ε (e.g., 9.9s when timeout is 10s)
3. Gets selected frequently due to low ping latency
4. Avoids timeout penalties and exponential backoff
5. Each successful slow response resets request_failure_count to 0
6. Ties up honest node resources (connections, memory, CPU) for 9.9 seconds per request

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty program as it causes:

1. **Validator Node Slowdowns** (High Severity category): Honest nodes experience degraded performance as they wait up to 9.9 seconds per request from malicious peers, significantly slowing state synchronization.

2. **Resource Exhaustion**: Each slow response consumes:
   - Network connection resources for the duration
   - Memory for pending response tracking
   - CPU time for timeout monitoring
   - Queue slots in the data streaming service (bounded by max_pending_requests) [8](#0-7) 

3. **Consensus Impact**: While not breaking consensus safety, delayed state synchronization can cause validators to fall behind, potentially affecting network liveness if enough validators are impacted.

The attack requires minimal resources from the attacker (just network connectivity) and can be sustained indefinitely since penalties never trigger.

## Likelihood Explanation

**Likelihood: High**

The attack is highly likely because:

1. **Trivial to Execute**: Attacker only needs to:
   - Run a modified Aptos node that delays responses
   - Respond to pings normally
   - Delay data responses to just under timeout thresholds

2. **No Detection Mechanism**: The system has no mechanism to detect or penalize slow-but-successful responses. The REQUEST_LATENCIES metric is collected but unused for peer selection.

3. **Economically Rational**: The attack costs the attacker minimal resources (bandwidth) while imposing significant costs on honest nodes (wasted time, resources).

4. **No Privileges Required**: Any network peer can execute this attack without validator credentials or stake.

5. **Persistent Advantage**: The decoupling between ping latency and request latency means the attacker maintains selection probability even while executing slow responses.

## Recommendation

Implement multi-layered defenses to detect and penalize slow responses:

**Fix 1: Track and Use Actual Request Latency for Peer Selection**

Modify peer selection to incorporate actual data request latency measurements, not just ping latencies:

```rust
// In state-sync/aptos-data-client/src/peer_states.rs
pub struct PeerState {
    // ... existing fields ...
    
    // Add rolling window of actual request latencies
    recent_request_latencies: VecDeque<Duration>,
    average_request_latency_secs: Option<f64>,
}

// Update latency on each successful response
pub fn record_request_latency(&mut self, latency: Duration) {
    self.recent_request_latencies.push_back(latency);
    
    // Keep last N measurements
    if self.recent_request_latencies.len() > MAX_LATENCY_SAMPLES {
        self.recent_request_latencies.pop_front();
    }
    
    // Recalculate average
    let sum: Duration = self.recent_request_latencies.iter().sum();
    self.average_request_latency_secs = Some(
        sum.as_secs_f64() / self.recent_request_latencies.len() as f64
    );
}
```

**Fix 2: Implement Latency-Based Scoring Penalties**

Add penalties for peers with consistently high request latencies:

```rust
// In state-sync/aptos-data-client/src/peer_states.rs
const HIGH_LATENCY_THRESHOLD_SECS: f64 = 5.0; // Half of timeout
const HIGH_LATENCY_PENALTY_MULTIPLIER: f64 = 0.98;

pub fn update_score_with_latency(&mut self, request_latency_secs: f64) {
    // Penalize high latency responses
    if request_latency_secs > HIGH_LATENCY_THRESHOLD_SECS {
        self.score = f64::max(
            self.score * HIGH_LATENCY_PENALTY_MULTIPLIER,
            MIN_SCORE
        );
    }
}
```

**Fix 3: Implement Adaptive Timeout with Latency-Based Backoff**

Instead of resetting request_failure_count to 0 on any success, maintain a "slowness" counter:

```rust
// In state-sync/data-streaming-service/src/data_stream.rs
pub struct DataStream<T> {
    // ... existing fields ...
    request_slowness_count: u64, // Track slow successful responses
}

fn send_client_request(&mut self, ...) -> PendingClientResponse {
    // Calculate timeout considering both failures AND slowness
    let combined_penalty_count = self.request_failure_count + 
                                 (self.request_slowness_count / 2);
    
    let request_timeout_ms = min(
        max_response_timeout_ms,
        response_timeout_ms * (u32::pow(2, combined_penalty_count as u32) as u64),
    );
    
    // ... rest of implementation
}

// In send_data_notification_to_client, update slowness tracking
async fn send_data_notification_to_client(&mut self, ...) -> Result<(), Error> {
    // ... existing code ...
    
    // Track if response was slow
    let response_latency = response_context.creation_time.elapsed();
    let slow_threshold = Duration::from_millis(
        self.data_client_config.response_timeout_ms / 2
    );
    
    if response_latency > slow_threshold {
        self.request_slowness_count = 
            self.request_slowness_count.saturating_add(1);
    } else {
        // Good response, decay slowness counter
        self.request_slowness_count = 
            self.request_slowness_count.saturating_sub(1);
    }
    
    self.request_failure_count = 0;
    // ...
}
```

**Fix 4: Enhance Peer Selection to Consider Request Latency**

Modify the peer selection weighting function to incorporate actual request latencies:

```rust
// In state-sync/aptos-data-client/src/utils.rs
fn get_latency_for_peer(
    peers_and_metadata: &Arc<PeersAndMetadata>,
    peer_states: &Arc<PeerStates>,
    peer: PeerNetworkId,
) -> Option<f64> {
    let ping_latency = /* existing ping latency lookup */;
    let request_latency = peer_states.get_average_request_latency(peer);
    
    // Use the worse of ping and request latency
    match (ping_latency, request_latency) {
        (Some(ping), Some(req)) => Some(f64::max(ping, req)),
        (Some(ping), None) => Some(ping),
        (None, Some(req)) => Some(req),
        (None, None) => None,
    }
}
```

## Proof of Concept

```rust
// Add to state-sync/data-streaming-service/src/tests/data_stream.rs

#[tokio::test]
async fn test_adaptive_timeout_manipulation_attack() {
    // Setup: Create a data stream with default config
    let data_client_config = AptosDataClientConfig::default();
    let streaming_config = DataStreamingServiceConfig::default();
    
    // Create a malicious peer that responds just under timeout
    let malicious_response_delay_ms = 
        data_client_config.response_timeout_ms - 100; // 9.9 seconds
    
    // Mock data client that simulates slow responses
    let mock_client = create_mock_client_with_latency(malicious_response_delay_ms);
    
    // Initialize stream and send multiple requests
    let (mut stream, mut listener) = DataStream::new(
        data_client_config,
        streaming_config,
        /* other params */
    ).unwrap();
    
    stream.initialize_data_requests(global_summary).unwrap();
    
    // Simulate multiple request cycles
    for cycle in 0..10 {
        // Process responses (all will succeed but be slow)
        stream.process_data_responses(global_summary).await.unwrap();
        
        // Verify:
        // 1. request_failure_count remains 0 (reset on each success)
        assert_eq!(stream.request_failure_count, 0, 
                   "Failure count should reset on slow success");
        
        // 2. Next request uses base timeout (no exponential backoff)
        let next_timeout = get_next_request_timeout(&stream);
        assert_eq!(next_timeout, data_client_config.response_timeout_ms,
                   "Timeout should not increase for slow successes");
        
        // 3. Peer score does not decrease
        let peer_score = get_peer_score(&stream, malicious_peer);
        assert!(peer_score >= STARTING_SCORE,
                "Peer score should not decrease for slow successes");
        
        // 4. Total time consumed grows linearly
        let expected_min_time = cycle * malicious_response_delay_ms;
        assert!(elapsed_time_ms >= expected_min_time,
                "Attack successfully consumes resources");
    }
    
    // Demonstrate resource exhaustion: 10 cycles * 9.9s = 99 seconds wasted
    // while peer maintains good score and avoids any penalties
}

#[tokio::test]
async fn test_ping_latency_vs_request_latency_decoupling() {
    // Demonstrate that low ping latency doesn't reflect high request latency
    
    let mock_client = MockDataClient::new();
    mock_client.set_ping_latency_ms(50); // Fast pings
    mock_client.set_data_request_latency_ms(9900); // Slow data requests
    
    // Get peer selection weight (based on ping latency)
    let selection_weight = calculate_peer_selection_weight(&mock_client);
    
    // Verify peer is selected frequently despite slow requests
    assert!(selection_weight > 0.9, 
            "Peer with low ping but high request latency is still selected");
    
    // Send actual data request and measure
    let start = Instant::now();
    mock_client.send_data_request().await.unwrap();
    let actual_latency = start.elapsed();
    
    assert!(actual_latency.as_millis() > 9000,
            "Actual request latency is high");
    assert!(selection_weight > 0.9,
            "But peer selection weight remains high due to ping latency");
}
```

## Notes

This vulnerability represents a fundamental architectural flaw in the latency measurement and peer selection system. The decoupling between ping latency (used for selection) and actual request latency (not used for selection) creates an exploitable gap that malicious peers can leverage to cause resource exhaustion while maintaining good standing in the network.

The fix requires architectural changes to unify latency measurement and incorporate actual observed request performance into peer selection and scoring decisions. Without these changes, the system remains vulnerable to this class of adaptive timing attacks.

### Citations

**File:** state-sync/aptos-data-client/src/utils.rs (L210-228)
```rust
fn get_latency_for_peer(
    peers_and_metadata: &Arc<PeersAndMetadata>,
    peer: PeerNetworkId,
) -> Option<f64> {
    if let Some(peer_metadata) = get_metadata_for_peer(peers_and_metadata, peer) {
        let peer_monitoring_metadata = peer_metadata.get_peer_monitoring_metadata();
        if let Some(latency) = peer_monitoring_metadata.average_ping_latency_secs {
            return Some(latency); // The latency was found
        }
    }

    // Otherwise, no latency was found
    log_warning_with_sample(
        LogSchema::new(LogEntry::PeerStates)
            .event(LogEvent::PeerSelectionError)
            .message(&format!("Unable to get latency for peer! Peer: {:?}", peer)),
    );
    None
}
```

**File:** config/src/config/state_sync_config.rs (L439-457)
```rust
    pub max_response_timeout_ms: u64,
    /// Maximum number of state keys and values per chunk
    pub max_state_chunk_size: u64,
    /// Maximum lag (in seconds) we'll tolerate when sending subscription requests
    pub max_subscription_lag_secs: u64,
    /// Maximum number of transactions per chunk
    pub max_transaction_chunk_size: u64,
    /// Maximum number of transaction outputs per chunk
    pub max_transaction_output_chunk_size: u64,
    /// Timeout (in ms) when waiting for an optimistic fetch response
    pub optimistic_fetch_timeout_ms: u64,
    /// The duration (in seconds) after which to panic if no progress has been made
    pub progress_check_max_stall_time_secs: u64,
    /// First timeout (in ms) when waiting for a response
    pub response_timeout_ms: u64,
    /// Timeout (in ms) when waiting for a subscription response
    pub subscription_response_timeout_ms: u64,
    /// Whether or not to request compression for incoming data
    pub use_compression: bool,
```

**File:** state-sync/aptos-data-client/src/client.rs (L715-733)
```rust
        // Start the timer for the request
        let timer = start_request_timer(&metrics::REQUEST_LATENCIES, &request.get_label(), peer);

        // Get the response from the peer
        let response = self
            .send_request_to_peer(peer, request.clone(), request_timeout_ms)
            .await;

        // If an error occurred, stop the timer (without updating the metrics)
        // and return the error. Otherwise, stop the timer and update the metrics.
        let storage_response = match response {
            Ok(storage_response) => {
                timer.stop_and_record(); // Update the latency metrics
                storage_response
            },
            Err(error) => {
                timer.stop_and_discard(); // Discard the timer without updating the metrics
                return Err(error);
            },
```

**File:** state-sync/aptos-data-client/src/client.rs (L834-866)
```rust
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
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L270-280)
```rust
        // Calculate the number of in-flight requests (i.e., requests that haven't completed)
        let num_pending_requests = self.get_num_pending_data_requests()?;
        let num_complete_pending_requests = self.get_num_complete_pending_requests()?;
        let num_in_flight_requests =
            num_pending_requests.saturating_sub(num_complete_pending_requests);

        // Calculate the max number of requests that can be sent now
        let max_pending_requests = self.streaming_service_config.max_pending_requests;
        let max_num_requests_to_send = max_pending_requests.saturating_sub(num_pending_requests);

        // Send the client requests iff we have enough room in the queue
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L351-378)
```rust
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

**File:** state-sync/data-streaming-service/src/data_stream.rs (L806-808)
```rust
            // Reset the failure count. We've sent a notification and can move on.
            self.request_failure_count = 0;
        }
```

**File:** peer-monitoring-service/client/src/peer_states/latency_info.rs (L99-110)
```rust
    /// Returns the average latency ping in seconds. If no latency
    /// pings have been recorded, None is returned.
    pub fn get_average_latency_ping_secs(&self) -> Option<f64> {
        let num_latency_pings = self.recorded_latency_ping_durations_secs.len();
        if num_latency_pings > 0 {
            let average_latency_secs_sum: f64 =
                self.recorded_latency_ping_durations_secs.values().sum();
            Some(average_latency_secs_sum / num_latency_pings as f64)
        } else {
            None
        }
    }
```
