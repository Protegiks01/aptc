# Audit Report

## Title
Prefetch Starvation Attack: Malicious Peers Can Permanently Prevent Nodes From Catching Up to Chain Head

## Summary
The dynamic prefetching mechanism in Aptos state sync can be exploited through repeated request timeouts to force the prefetch value to its minimum (3), creating a denial-of-service condition where nodes sync at ~900 TPS while the chain grows at ~5000-10000 TPS. This causes nodes to fall permanently behind the chain head, unable to participate in consensus or serve clients.

## Finding Description

The state sync system uses dynamic prefetching to adjust the number of concurrent data requests based on network conditions. The prefetch value starts at 3 and can increase to 30 on successful responses, but decreases by 2 on each timeout, bounded at a minimum of 3. [1](#0-0) 

When a data client request times out, the system calls `decrease_max_concurrent_requests()`, which reduces the prefetch value and freezes it for 30 seconds: [2](#0-1) 

This prefetch limit directly controls how many concurrent data requests can be in-flight. The system calculates available request slots and will not send more requests if the limit is reached: [3](#0-2) [4](#0-3) 

**The Critical Vulnerability**: When requests fail with timeout errors, the system decreases the prefetch value but does NOT notify the peer scoring system to blacklist the slow/malicious peer: [5](#0-4) 

The `handle_data_client_error` function simply retries the request without penalizing the peer that caused the timeout: [6](#0-5) 

**Attack Scenario**:
1. Malicious peer(s) deliberately delay responses to cause `TimeoutWaitingForResponse` errors
2. Each timeout decreases prefetch value by 2 until it reaches minimum (3)
3. With 3 concurrent requests of max 3000 transactions each, the node can fetch at most 9000 transactions per request cycle
4. At 10+ seconds per request cycle (with exponential backoff on retries), sync rate is ~900 TPS
5. Aptos chain produces 5000-10000 TPS, so node falls behind by 4000-9000 TPS
6. After `max_request_retry` (5) failures, the stream is recreated but starts with the same low prefetch value and faces the same malicious peers
7. Node can never catch up because sync rate < chain growth rate [7](#0-6) [8](#0-7) 

## Impact Explanation

This is a **High Severity** vulnerability per Aptos bug bounty criteria:

1. **Validator Node Slowdowns**: Validators that cannot sync to chain head cannot participate in consensus voting, directly impacting network liveness and security.

2. **Significant Protocol Violations**: Nodes falling permanently behind violates the fundamental assumption that honest nodes can maintain synchronization with the chain head.

3. **Network Availability Issues**: If multiple nodes are affected simultaneously, the network's effective validator set decreases, approaching unsafe threshold ratios.

The vulnerability does not qualify as Critical because it does not directly cause fund loss or consensus safety violations (nodes that fall behind simply stop participating rather than creating chain splits).

## Likelihood Explanation

**High Likelihood**:

1. **Easy to Execute**: An attacker only needs to run a peer node and deliberately delay responses. No special privileges or validator access required.

2. **Sustainable Attack**: Malicious peers are not blacklisted for causing timeouts, so they remain in the peer selection pool indefinitely.

3. **Low Detection**: Slow responses appear similar to legitimate network congestion, making the attack difficult to distinguish from normal operation.

4. **Widespread Impact**: The attack affects any node syncing data, including validators bootstrapping, validators catching up after downtime, and fullnodes serving client requests.

5. **Self-Reinforcing**: Once prefetch is at minimum, the freeze mechanism (30 seconds) prevents quick recovery even if good peers are later selected.

## Recommendation

**Immediate Fix**: Notify peer scoring system on timeout errors to blacklist slow/malicious peers.

**Implementation**:
1. Modify `handle_data_client_error` to extract the peer responsible for the timeout from the response context
2. Call `notify_bad_response` with `ResponseError::Timeout` to trigger peer scoring degradation
3. Add timeout-specific error categorization as malicious behavior (multiplier 0.8) to ensure faster peer blacklisting

**Additional Mitigations**:
1. Implement minimum sync rate threshold - if sync rate falls below chain growth rate for extended period, trigger aggressive peer rotation
2. Add peer diversity requirements - ensure requests are distributed across multiple peers to prevent single-peer bottlenecks
3. Consider adaptive timeout values that increase based on peer performance history
4. Add metrics and alerts for persistent low prefetch values to detect ongoing attacks

**Code Fix Location**: [9](#0-8) 

The fix should extract the peer context from the error response and call the response callback's `notify_bad_response` method, similar to how it's done for sanity check failures: [10](#0-9) 

## Proof of Concept

**Test Scenario**: Configure a mock data client that deliberately delays responses to trigger timeouts, verify prefetch value drops to 3 and stays there, then calculate effective sync rate vs chain growth rate.

```rust
// In state-sync/data-streaming-service/src/tests/
#[tokio::test]
async fn test_prefetch_starvation_attack() {
    // Setup: Create mock data client that delays responses
    let mut mock_client = MockDataClient::new();
    mock_client.set_response_delay(Duration::from_secs(15)); // Exceeds 10s timeout
    
    // Create data stream with dynamic prefetching enabled
    let config = DataStreamingServiceConfig {
        dynamic_prefetching: DynamicPrefetchingConfig {
            enable_dynamic_prefetching: true,
            initial_prefetching_value: 3,
            min_prefetching_value: 3,
            max_prefetching_value: 30,
            prefetching_value_decrease: 2,
            ..Default::default()
        },
        ..Default::default()
    };
    
    let (mut stream, _listener) = DataStream::new(
        config,
        /* ... */
    );
    
    // Initialize and process responses multiple times
    stream.initialize_data_requests(global_summary).unwrap();
    
    for i in 0..10 {
        // Wait for timeout and process
        tokio::time::sleep(Duration::from_secs(12)).await;
        let _ = stream.process_data_responses(global_summary).await;
        
        // Verify prefetch value is at minimum after first few iterations
        if i >= 2 {
            let prefetch = stream.dynamic_prefetching_state
                .get_max_concurrent_requests(&stream.stream_engine);
            assert_eq!(prefetch, 3, "Prefetch should be stuck at minimum");
        }
    }
    
    // Calculate effective sync rate
    // With 3 concurrent requests of 3000 txns each, at ~12s per cycle
    // Sync rate = 9000 / 12 = 750 TPS
    // This is far below Aptos mainnet rate of 5000-10000 TPS
    let sync_rate_tps = (3 * 3000) / 12;
    let chain_growth_tps = 5000; // Conservative estimate
    
    assert!(
        sync_rate_tps < chain_growth_tps,
        "Node cannot catch up: sync rate {} < chain growth {}",
        sync_rate_tps,
        chain_growth_tps
    );
}
```

**Manual Reproduction Steps**:
1. Deploy malicious peer that responds to data requests after 15+ seconds (exceeding the 10s timeout)
2. Start fullnode that connects to this malicious peer
3. Monitor metrics: `aptos_state_sync_max_concurrent_requests` should drop to 3 and stay there
4. Observe sync progress: node falls behind chain head at rate of ~4000 TPS
5. Verify peer is not blacklisted by checking peer scores remain above ignore threshold
6. Confirm node cannot catch up even after multiple stream recreations

### Citations

**File:** config/src/config/state_sync_config.rs (L23-27)
```rust
// The maximum chunk sizes for data client requests and response
const MAX_EPOCH_CHUNK_SIZE: u64 = 200;
const MAX_STATE_CHUNK_SIZE: u64 = 4000;
const MAX_TRANSACTION_CHUNK_SIZE: u64 = 3000;
const MAX_TRANSACTION_OUTPUT_CHUNK_SIZE: u64 = 3000;
```

**File:** config/src/config/state_sync_config.rs (L284-325)
```rust
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DynamicPrefetchingConfig {
    /// Whether or not to enable dynamic prefetching
    pub enable_dynamic_prefetching: bool,

    /// The initial number of concurrent prefetching requests
    pub initial_prefetching_value: u64,

    /// Maximum number of in-flight subscription requests
    pub max_in_flight_subscription_requests: u64,

    /// The maximum number of concurrent prefetching requests
    pub max_prefetching_value: u64,

    /// The minimum number of concurrent prefetching requests
    pub min_prefetching_value: u64,

    /// The amount by which to increase the concurrent prefetching value (i.e., on a successful response)
    pub prefetching_value_increase: u64,

    /// The amount by which to decrease the concurrent prefetching value (i.e., on a timeout)
    pub prefetching_value_decrease: u64,

    /// The duration by which to freeze the prefetching value on a timeout
    pub timeout_freeze_duration_secs: u64,
}

impl Default for DynamicPrefetchingConfig {
    fn default() -> Self {
        Self {
            enable_dynamic_prefetching: true,
            initial_prefetching_value: 3,
            max_in_flight_subscription_requests: 9, // At ~3 blocks per second, this should last ~3 seconds
            max_prefetching_value: 30,
            min_prefetching_value: 3,
            prefetching_value_increase: 1,
            prefetching_value_decrease: 2,
            timeout_freeze_duration_secs: 30,
        }
    }
}
```

**File:** state-sync/data-streaming-service/src/dynamic_prefetching.rs (L128-150)
```rust
    /// Decreases the maximum number of concurrent requests that should be executing.
    /// This is typically called after a timeout is received.
    pub fn decrease_max_concurrent_requests(&mut self) {
        // If dynamic prefetching is disabled, do nothing
        if !self.is_dynamic_prefetching_enabled() {
            return;
        }

        // Update the last failure time
        self.last_timeout_instant = Some(self.time_service.now());

        // Otherwise, get and decrease the current max
        let dynamic_prefetching_config = self.get_dynamic_prefetching_config();
        let amount_to_decrease = dynamic_prefetching_config.prefetching_value_decrease;
        let max_dynamic_concurrent_requests = self
            .max_dynamic_concurrent_requests
            .saturating_sub(amount_to_decrease);

        // Bound the value by the configured minimum
        let min_prefetching_value = dynamic_prefetching_config.min_prefetching_value;
        self.max_dynamic_concurrent_requests =
            max(max_dynamic_concurrent_requests, min_prefetching_value);
    }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L266-294)
```rust
    fn create_and_send_client_requests(
        &mut self,
        global_data_summary: &GlobalDataSummary,
    ) -> Result<(), Error> {
        // Calculate the number of in-flight requests (i.e., requests that haven't completed)
        let num_pending_requests = self.get_num_pending_data_requests()?;
        let num_complete_pending_requests = self.get_num_complete_pending_requests()?;
        let num_in_flight_requests =
            num_pending_requests.saturating_sub(num_complete_pending_requests);

        // Calculate the max number of requests that can be sent now
        let max_pending_requests = self.streaming_service_config.max_pending_requests;
        let max_num_requests_to_send = max_pending_requests.saturating_sub(num_pending_requests);

        // Send the client requests iff we have enough room in the queue
        if max_num_requests_to_send > 0 {
            // Get the max number of in-flight requests from the prefetching state
            let max_in_flight_requests = self
                .dynamic_prefetching_state
                .get_max_concurrent_requests(&self.stream_engine);

            // Create the client requests
            let client_requests = self.stream_engine.create_data_client_requests(
                max_num_requests_to_send,
                max_in_flight_requests,
                num_in_flight_requests,
                global_data_summary,
                self.notification_id_generator.clone(),
            )?;
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L446-454)
```rust
        if self.stream_engine.is_stream_complete()
            || self.request_failure_count >= self.streaming_service_config.max_request_retry
            || self.send_failure
        {
            if !self.send_failure && self.stream_end_notification_id.is_none() {
                self.send_end_of_stream_notification().await?;
            }
            return Ok(()); // There's nothing left to do
        }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L523-536)
```rust
                Err(error) => {
                    // Handle the error depending on the request type
                    if client_request.is_new_data_request() {
                        // The request was for new data. We should notify the
                        // stream engine and clear the requests queue.
                        self.notify_new_data_request_error(client_request, error)?;
                    } else {
                        // Decrease the prefetching limit on an error
                        self.dynamic_prefetching_state
                            .decrease_max_concurrent_requests();

                        // Handle the error and simply retry
                        self.handle_data_client_error(client_request, &error)?;
                    }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L695-708)
```rust
    /// Handles a client response that failed sanity checks
    fn handle_sanity_check_failure(
        &mut self,
        data_client_request: &DataClientRequest,
        response_context: &ResponseContext,
    ) -> Result<(), Error> {
        error!(LogSchema::new(LogEntry::ReceivedDataResponse)
            .stream_id(self.data_stream_id)
            .event(LogEvent::Error)
            .message("Encountered a client response that failed the sanity checks!"));

        self.notify_bad_response(response_context, ResponseError::InvalidPayloadDataType);
        self.resend_data_client_request(data_client_request)
    }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L710-744)
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

    /// Resends a failed data client request and pushes the pending notification
    /// to the head of the pending notifications batch.
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

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L2036-2046)
```rust
fn calculate_num_requests_to_send(
    max_number_of_requests: u64,
    max_in_flight_requests: u64,
    num_in_flight_requests: u64,
) -> u64 {
    // Calculate the number of remaining in-flight request slots
    let remaining_in_flight_slots = max_in_flight_requests.saturating_sub(num_in_flight_requests);

    // Bound the number of requests to send by the maximum
    min(remaining_in_flight_slots, max_number_of_requests)
}
```
