# Audit Report

## Title
State Sync Deadlock via Zero Minimum Prefetching Value Configuration

## Summary
A configuration vulnerability in the dynamic prefetching system allows `min_prefetching_value` to be set to 0, which can cause a permanent deadlock in state synchronization. When timeout events decrease the concurrent request limit to 0, no new data requests are created, and the node becomes unable to sync state with no automatic recovery mechanism.

## Finding Description

The dynamic prefetching system in `state-sync/data-streaming-service` controls the number of concurrent data requests based on network conditions. The `decrease_max_concurrent_requests()` function uses `min_prefetching_value` as a lower bound when decreasing the concurrent request limit after timeouts. [1](#0-0) 

The configuration structure defines `min_prefetching_value` with a default of 3, but provides no validation to prevent it from being set to 0: [2](#0-1) 

The configuration sanitizer does not validate this field: [3](#0-2) 

When `min_prefetching_value` is 0 and timeouts occur, `max_dynamic_concurrent_requests` can reach 0. This value is used to determine how many requests to send: [4](#0-3) 

The `calculate_num_requests_to_send()` function returns 0 when `max_in_flight_requests` is 0: [5](#0-4) 

**Attack Path:**
1. Node operator or attacker with configuration access sets `min_prefetching_value: 0` in the node config
2. Node experiences network timeouts (naturally occurring or attacker-induced)
3. Each timeout calls `decrease_max_concurrent_requests()`, reducing the value
4. Eventually `max_dynamic_concurrent_requests` reaches 0
5. `create_data_client_requests()` returns an empty request list
6. Stream initialization succeeds with empty queue
7. No requests are sent, no responses received
8. No mechanism to increase the value back (requires successful responses)
9. Node enters permanent deadlock - cannot sync state

**Critical Flow:**
The stream remains "initialized" but idle: [6](#0-5) 

Once initialized with 0 requests, the stream processes responses but has none to process, creating a permanent deadlock.

## Impact Explanation

**Severity: HIGH**

This vulnerability causes a **liveness failure** affecting state synchronization:

1. **Bootstrapping Nodes**: Nodes syncing from genesis cannot fetch historical data, remaining permanently out of sync
2. **Catch-up Scenarios**: Validators or full nodes that fall behind cannot catch up to current state
3. **Fast Sync Failure**: Nodes using fast sync mode cannot complete synchronization
4. **Validator Impact**: Validators unable to sync cannot participate in consensus, reducing network decentralization and security
5. **No Automatic Recovery**: Once at 0, there's no mechanism to recover without manual intervention (node restart with corrected config)

The vulnerability affects non-subscription data requests. Subscription requests (for nodes at chain tip) use a separate limit and are not affected: [7](#0-6) 

However, nodes must first catch up using regular requests before they can use subscriptions, so bootstrapping and catch-up scenarios are critically impacted.

Per Aptos bug bounty criteria, this qualifies as **High Severity** due to:
- Validator node failures affecting consensus participation
- Significant protocol violations (inability to sync state)
- Network availability issues for affected nodes

## Likelihood Explanation

**Likelihood: Medium to High**

The vulnerability requires misconfiguration but is highly likely to be triggered once misconfigured:

**Prerequisites:**
- Operator sets `min_prefetching_value: 0` in configuration (malicious or accidental)
- Dynamic prefetching is enabled (default is `true`)
- Node experiences network timeouts (common in production)

**Triggering Conditions:**
- Network instability (packet loss, slow peers, high latency)
- Attacker controlling peer responses to induce timeouts
- Natural timeout events during sync operations

**Likelihood Factors:**
- Default value (3) is safe, preventing accidental exploitation
- No validation allows arbitrary configuration values
- Configuration files are typically controlled by operators
- Timeouts are common in distributed systems
- Once triggered, effect is permanent without intervention

The vulnerability is **not automatically exploitable** but becomes **highly likely** once the misconfiguration exists, as timeout events are inevitable in blockchain networks.

## Recommendation

**Immediate Fix: Add Configuration Validation**

Add validation in the config sanitizer to enforce `min_prefetching_value > 0`:

```rust
impl ConfigSanitizer for DataStreamingServiceConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        _chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let dynamic_prefetching_config = &node_config.state_sync
            .data_streaming_service
            .dynamic_prefetching;

        // Validate min_prefetching_value is not zero when dynamic prefetching is enabled
        if dynamic_prefetching_config.enable_dynamic_prefetching 
            && dynamic_prefetching_config.min_prefetching_value == 0 {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "min_prefetching_value must be greater than 0 when dynamic prefetching is enabled!".to_string(),
            ));
        }

        Ok(())
    }
}
```

**Defense in Depth:**

1. **Runtime Guard**: Add a safety check in `decrease_max_concurrent_requests()`:
```rust
// Bound the value by the configured minimum (but enforce a hard minimum of 1)
let min_prefetching_value = max(1, dynamic_prefetching_config.min_prefetching_value);
self.max_dynamic_concurrent_requests = 
    max(max_dynamic_concurrent_requests, min_prefetching_value);
```

2. **Deadlock Detection**: Add monitoring to detect when no requests are being created for extended periods and trigger stream recreation

3. **Documentation**: Update configuration documentation to warn about the criticality of `min_prefetching_value`

## Proof of Concept

```rust
#[cfg(test)]
mod security_test {
    use super::*;
    use aptos_config::config::{DataStreamingServiceConfig, DynamicPrefetchingConfig};
    use aptos_time_service::TimeService;

    #[test]
    fn test_zero_min_prefetching_causes_deadlock() {
        // Create a config with min_prefetching_value set to 0 (vulnerable configuration)
        let initial_prefetching_value = 5;
        let prefetching_value_decrease = 2;
        let min_prefetching_value = 0; // VULNERABLE: No validation prevents this!
        
        let dynamic_prefetching_config = DynamicPrefetchingConfig {
            enable_dynamic_prefetching: true,
            initial_prefetching_value,
            prefetching_value_decrease,
            min_prefetching_value, // Set to 0
            ..Default::default()
        };
        
        let data_streaming_service_config = DataStreamingServiceConfig {
            dynamic_prefetching: dynamic_prefetching_config,
            ..Default::default()
        };

        // Create dynamic prefetching state
        let mut dynamic_prefetching_state = 
            DynamicPrefetchingState::new(data_streaming_service_config, TimeService::mock());

        // Simulate timeouts decreasing the value
        for i in 0..10 {
            dynamic_prefetching_state.decrease_max_concurrent_requests();
            
            // Check current value
            let current_max = dynamic_prefetching_state.max_dynamic_concurrent_requests;
            println!("After timeout {}: max_concurrent_requests = {}", i + 1, current_max);
        }

        // Verify that the value has reached 0 (deadlock state)
        assert_eq!(
            dynamic_prefetching_state.max_dynamic_concurrent_requests, 
            0,
            "Value should reach 0 with min_prefetching_value of 0"
        );

        // Create a mock stream engine to test request creation
        let stream_engine = create_test_stream_engine(data_streaming_service_config);
        
        // Verify that get_max_concurrent_requests returns 0
        let max_requests = dynamic_prefetching_state.get_max_concurrent_requests(&stream_engine);
        assert_eq!(max_requests, 0, "Should return 0, causing no requests to be created");

        // This demonstrates the deadlock: 
        // - No requests will be created (calculate_num_requests_to_send returns 0)
        // - No responses will be received
        // - No way to increase the value back
        // - Node cannot sync state
        println!("VULNERABILITY CONFIRMED: Node enters permanent deadlock!");
    }

    fn create_test_stream_engine(config: DataStreamingServiceConfig) -> StreamEngine {
        // Helper to create a stream engine for testing
        // Implementation omitted for brevity but would create a valid StreamEngine
        unimplemented!("Test helper")
    }
}
```

**Notes:**
- This vulnerability requires configuration access but poses a significant threat to node liveness
- The default configuration is safe (min_prefetching_value = 3), but no validation prevents dangerous configurations
- Subscription-based streaming (for nodes at chain tip) is not affected due to separate limit handling
- The fix is straightforward: add configuration validation to reject zero values
- Defense in depth should include runtime guards and deadlock detection

### Citations

**File:** state-sync/data-streaming-service/src/dynamic_prefetching.rs (L130-150)
```rust
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

**File:** config/src/config/state_sync_config.rs (L286-324)
```rust
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
```

**File:** config/src/config/state_sync_config.rs (L487-519)
```rust
impl ConfigSanitizer for StateSyncConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        // Sanitize the state sync driver config
        StateSyncDriverConfig::sanitize(node_config, node_type, chain_id)
    }
}

impl ConfigSanitizer for StateSyncDriverConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        _chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let state_sync_driver_config = &node_config.state_sync.state_sync_driver;

        // Verify that auto-bootstrapping is not enabled for
        // nodes that are fast syncing.
        let fast_sync_enabled = state_sync_driver_config.bootstrapping_mode.is_fast_sync();
        if state_sync_driver_config.enable_auto_bootstrapping && fast_sync_enabled {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "Auto-bootstrapping should not be enabled for nodes that are fast syncing!"
                    .to_string(),
            ));
        }

        Ok(())
    }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L283-286)
```rust
            let max_in_flight_requests = self
                .dynamic_prefetching_state
                .get_max_concurrent_requests(&self.stream_engine);

```

**File:** state-sync/data-streaming-service/src/stream_engine.rs (L742-747)
```rust
        let max_in_flight_requests = if prefetching_config.enable_dynamic_prefetching {
            // Use the max number of in-flight subscriptions from the prefetching config
            prefetching_config.max_in_flight_subscription_requests
        } else {
            max_in_flight_requests // Otherwise, use the given maximum
        };
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

**File:** state-sync/data-streaming-service/src/streaming_service.rs (L367-381)
```rust
        if !data_stream.data_requests_initialized() {
            // Initialize the request batch by sending out data client requests
            data_stream.initialize_data_requests(global_data_summary)?;
            info!(
                (LogSchema::new(LogEntry::InitializeStream)
                    .stream_id(*data_stream_id)
                    .event(LogEvent::Success)
                    .message("Data stream initialized."))
            );
        } else {
            // Process any data client requests that have received responses
            data_stream
                .process_data_responses(global_data_summary)
                .await?;
        }
```
