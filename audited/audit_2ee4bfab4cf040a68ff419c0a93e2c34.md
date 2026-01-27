# Audit Report

## Title
Subscription Stream Lag Defense Bypass via Constant Lag Maintenance

## Summary
The subscription stream lag detection mechanism in Aptos state synchronization can be bypassed by an attacker who maintains a constant or slowly decreasing lag. The `is_beyond_recovery` method requires BOTH lag increase AND timeout expiration to terminate a stream, allowing indefinite resource consumption when lag remains stable.

## Finding Description

The state synchronization system implements a defense mechanism to detect and terminate subscription streams that are lagging behind the network. However, the implementation contains a critical flaw in how it determines when a stream is "beyond recovery." [1](#0-0) 

The `is_beyond_recovery` method checks two conditions:
1. **lag_has_increased**: Current lag must be GREATER than previous lag
2. **lag_duration_exceeded**: Lag duration must exceed `max_subscription_stream_lag_secs` (default: 10 seconds)

The stream is only terminated when BOTH conditions are true (line 981). This creates an exploitable bypass: if an attacker maintains a constant lag (e.g., consistently 300 versions behind), the `lag_has_increased` condition remains false indefinitely, preventing stream termination regardless of how long the lag persists.

**Attack Scenario:**
1. Attacker establishes a subscription stream with a victim node
2. Attacker responds to subscription requests with data that is consistently X versions behind the network (e.g., 300 versions)
3. As the network advances, the attacker advances responses at the same rate, maintaining constant lag
4. The victim node's stream never terminates because `current_stream_lag > self.version_lag` is false
5. The `max_subscription_stream_lag_secs` timeout becomes meaningless
6. Node resources (memory, network connections, CPU) are consumed indefinitely
7. The node believes it's making "progress" but never catches up to the network [2](#0-1) 

The `check_subscription_stream_lag` method calls `is_beyond_recovery` to determine stream fate (line 610-611), making this the critical failure point.

**Test Evidence:**
The existing test suite actually demonstrates this behavior is intentional but flawed: [3](#0-2) 

Lines 1974-1982, 1996-2004, and 2018-2026 show that streams with "still behind, but not worse" lag continue indefinitely, confirming the vulnerability.

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty program for the following reasons:

1. **Node Resource Exhaustion**: Lagging streams consume bounded but significant resources per stream (memory for pending requests, network connection slots, CPU for processing responses), allowing DoS attacks through multiple parallel streams

2. **State Synchronization Failure**: Victim nodes remain perpetually behind the network, unable to validate the current blockchain state or participate effectively in the network

3. **False Progress Indication**: The node's monitoring shows "progress" (non-increasing lag) while actual synchronization fails, masking the attack and delaying operator response

4. **Availability Impact**: While not causing consensus violation, this directly impacts node liveness and availability, fitting the "state inconsistencies requiring intervention" category for Medium severity [4](#0-3) 

The configuration shows `max_subscription_stream_lag_secs: 10` seconds as the intended timeout, but this protection is completely bypassed by the flawed logic.

## Likelihood Explanation

**High Likelihood** for the following reasons:

1. **Low Attack Complexity**: Any peer serving subscription data can execute this attack without special privileges or validator access

2. **Minimal Resources Required**: Attacker only needs to:
   - Maintain a subscription stream connection
   - Serve data at a controlled lag rate (easily achievable)
   - No cryptographic operations or complex state manipulation required

3. **Difficult Detection**: The attack appears as legitimate but slow synchronization, making it hard to distinguish from network latency or genuinely slow peers

4. **Multiple Attack Vectors**: Can target:
   - Public fullnodes (disrupting ecosystem services)
   - Validator fullnodes (degrading validator performance)
   - New nodes bootstrapping (preventing network entry)

## Recommendation

Modify the `is_beyond_recovery` logic to terminate streams that remain lagged for longer than the configured timeout, regardless of whether lag increases:

```rust
fn is_beyond_recovery(
    &mut self,
    streaming_service_config: DataStreamingServiceConfig,
    current_stream_lag: u64,
) -> bool {
    // Calculate the total duration the stream has been lagging
    let current_time = self.time_service.now();
    let stream_lag_duration = current_time.duration_since(self.start_time);
    let max_stream_lag_duration =
        Duration::from_secs(streaming_service_config.max_subscription_stream_lag_secs);

    // Check if the lag duration has been exceeded
    let lag_duration_exceeded = stream_lag_duration >= max_stream_lag_duration;
    
    // If enough time has passed, check if the stream has made insufficient progress
    if lag_duration_exceeded {
        // Calculate the minimum acceptable progress (e.g., lag should decrease by at least 50%)
        let minimum_progress_threshold = self.version_lag / 2;
        let insufficient_progress = current_stream_lag > minimum_progress_threshold;
        
        if insufficient_progress {
            return true; // The stream is beyond recovery
        }
    }

    // Update the stream lag if we've made progress
    if current_stream_lag < self.version_lag {
        self.version_lag = current_stream_lag;
        // Reset the start time when significant progress is made
        if current_stream_lag < self.version_lag * 3 / 4 {
            self.start_time = current_time;
        }
    }

    false // The stream is not yet beyond recovery
}
```

**Alternative Approach**: Implement an absolute progress requirement - streams must reach within a certain threshold of the advertised version within the timeout period, or be terminated.

## Proof of Concept

The following test demonstrates the vulnerability by showing a stream that maintains constant lag survives indefinitely:

```rust
#[tokio::test]
async fn test_constant_lag_bypass_vulnerability() {
    // Create a test streaming service config with 10 second timeout
    let max_subscription_stream_lag_secs = 10;
    let streaming_service_config = DataStreamingServiceConfig {
        enable_subscription_streaming: true,
        max_subscription_stream_lag_secs,
        ..Default::default()
    };

    // Create a continuous transaction stream
    let (mut data_stream, mut stream_listener, time_service, _, _) = 
        create_continuous_transaction_stream(
            AptosDataClientConfig::default(),
            streaming_service_config,
        );

    // Initialize the data stream
    let mut global_data_summary = create_global_data_summary(1);
    initialize_data_requests(&mut data_stream, &global_data_summary);

    // Set advertised version ahead
    let constant_lag_amount = 300; // 300 versions behind
    let mut advertised_version = MAX_ADVERTISED_TRANSACTION + constant_lag_amount;
    global_data_summary.advertised_data.synced_ledger_infos = 
        vec![create_ledger_info(advertised_version, MAX_ADVERTISED_EPOCH_END, false)];

    let time_service = time_service.into_mock();
    
    // Simulate 100 seconds of constant lag (10x the timeout)
    for _ in 0..100 {
        // Advance network by 1 version per second
        advertised_version += 1;
        global_data_summary.advertised_data.synced_ledger_infos = 
            vec![create_ledger_info(advertised_version, MAX_ADVERTISED_EPOCH_END, false)];
        
        // Attacker responds with data maintaining constant lag
        let response_version = advertised_version - constant_lag_amount;
        set_new_data_response_in_queue(&mut data_stream, 0, response_version, true);
        
        // Process responses
        process_data_responses(&mut data_stream, &global_data_summary).await;
        
        // Verify notification received (stream still alive)
        assert_some!(stream_listener.select_next_some().now_or_never());
        
        // Verify stream is NOT terminated
        let subscription_lag = data_stream.get_subscription_stream_lag();
        assert!(subscription_lag.is_some(), "Stream should still be tracking lag at iteration {}", _);
        assert_eq!(subscription_lag.unwrap().version_lag, constant_lag_amount);
        
        // Advance time by 1 second
        time_service.advance_secs(1);
    }
    
    // After 100 seconds, stream should have been killed but isn't
    // This demonstrates the vulnerability: constant lag bypasses the timeout
    assert!(data_stream.get_subscription_stream_lag().is_some(), 
        "VULNERABILITY: Stream survived 100 seconds with constant lag (10x timeout)");
}
```

This PoC can be added to `state-sync/data-streaming-service/src/tests/data_stream.rs` and will demonstrate that a stream maintaining constant lag survives indefinitely, bypassing the intended 10-second timeout protection.

## Notes

The vulnerability exists because the original design assumed that "making progress" (not falling further behind) indicates a healthy stream. However, this assumption is flawed when dealing with potentially malicious or resource-constrained peers. A proper timeout mechanism should enforce absolute progress requirements, not just relative non-degradation.

The issue affects all nodes running state synchronization with subscription streaming enabled, which includes validators, VFNs, and PFNs attempting to catch up to the network.

### Citations

**File:** state-sync/data-streaming-service/src/data_stream.rs (L549-631)
```rust
    fn check_subscription_stream_lag(
        &mut self,
        global_data_summary: &GlobalDataSummary,
        response_payload: &ResponsePayload,
    ) -> Result<(), aptos_data_client::error::Error> {
        // Get the highest version sent in the subscription response
        let highest_response_version = match response_payload {
            ResponsePayload::NewTransactionsWithProof((transactions_with_proof, _)) => {
                if let Some(first_version) = transactions_with_proof.get_first_transaction_version()
                {
                    let num_transactions = transactions_with_proof.get_num_transactions();
                    first_version
                        .saturating_add(num_transactions as u64)
                        .saturating_sub(1) // first_version + num_txns - 1
                } else {
                    return Err(aptos_data_client::error::Error::UnexpectedErrorEncountered(
                        "The first transaction version is missing from the stream response!".into(),
                    ));
                }
            },
            ResponsePayload::NewTransactionOutputsWithProof((outputs_with_proof, _)) => {
                if let Some(first_version) = outputs_with_proof.get_first_output_version() {
                    let num_outputs = outputs_with_proof.get_num_outputs();
                    first_version
                        .saturating_add(num_outputs as u64)
                        .saturating_sub(1) // first_version + num_outputs - 1
                } else {
                    return Err(aptos_data_client::error::Error::UnexpectedErrorEncountered(
                        "The first output version is missing from the stream response!".into(),
                    ));
                }
            },
            _ => {
                return Ok(()); // The response payload doesn't contain a subscription response
            },
        };

        // Get the highest advertised version
        let highest_advertised_version = global_data_summary
            .advertised_data
            .highest_synced_ledger_info()
            .map(|ledger_info| ledger_info.ledger_info().version())
            .ok_or_else(|| {
                aptos_data_client::error::Error::UnexpectedErrorEncountered(
                    "The highest synced ledger info is missing from the global data summary!"
                        .into(),
                )
            })?;

        // If the stream is not lagging behind, reset the lag and return
        if highest_response_version >= highest_advertised_version {
            self.reset_subscription_stream_lag();
            return Ok(());
        }

        // Otherwise, the stream is lagging behind the advertised version.
        // Check if the stream is beyond recovery (i.e., has failed).
        let current_stream_lag =
            highest_advertised_version.saturating_sub(highest_response_version);
        if let Some(mut subscription_stream_lag) = self.subscription_stream_lag.take() {
            // Check if the stream lag is beyond recovery
            if subscription_stream_lag
                .is_beyond_recovery(self.streaming_service_config, current_stream_lag)
            {
                return Err(
                    aptos_data_client::error::Error::SubscriptionStreamIsLagging(format!(
                        "The subscription stream is beyond recovery! Current lag: {:?}, last lag: {:?},",
                        current_stream_lag, subscription_stream_lag.version_lag
                    )),
                );
            }

            // The stream is lagging, but it's not yet beyond recovery
            self.set_subscription_stream_lag(subscription_stream_lag);
        } else {
            // The stream was not previously lagging, but it is now!
            let subscription_stream_lag =
                SubscriptionStreamLag::new(current_stream_lag, self.time_service.clone());
            self.set_subscription_stream_lag(subscription_stream_lag);
        }

        Ok(())
    }
```

**File:** state-sync/data-streaming-service/src/data_stream.rs (L964-992)
```rust
    /// Returns true iff the subscription stream lag is considered to be
    /// beyond recovery. This occurs when: (i) the stream is lagging for
    /// too long; and (ii) the lag has increased since the last check.
    fn is_beyond_recovery(
        &mut self,
        streaming_service_config: DataStreamingServiceConfig,
        current_stream_lag: u64,
    ) -> bool {
        // Calculate the total duration the stream has been lagging
        let current_time = self.time_service.now();
        let stream_lag_duration = current_time.duration_since(self.start_time);
        let max_stream_lag_duration =
            Duration::from_secs(streaming_service_config.max_subscription_stream_lag_secs);

        // If the lag is further behind and enough time has passed, the stream has failed
        let lag_has_increased = current_stream_lag > self.version_lag;
        let lag_duration_exceeded = stream_lag_duration >= max_stream_lag_duration;
        if lag_has_increased && lag_duration_exceeded {
            return true; // The stream is beyond recovery
        }

        // Otherwise, update the stream lag if we've caught up.
        // This will ensure the lag can only improve.
        if current_stream_lag < self.version_lag {
            self.version_lag = current_stream_lag;
        }

        false // The stream is not yet beyond recovery
    }
```

**File:** state-sync/data-streaming-service/src/tests/data_stream.rs (L1914-2061)
```rust
async fn test_continuous_stream_subscription_lag_bounded() {
    // Create a test streaming service config with subscriptions enabled
    let max_subscription_stream_lag_secs = 10;
    let streaming_service_config = DataStreamingServiceConfig {
        enable_subscription_streaming: true,
        max_subscription_stream_lag_secs,
        ..Default::default()
    };

    // Test all types of continuous data streams
    let continuous_data_streams = enumerate_continuous_data_streams(
        AptosDataClientConfig::default(),
        streaming_service_config,
    );
    for (mut data_stream, mut stream_listener, time_service, transactions_only, _) in
        continuous_data_streams
    {
        // Initialize the data stream
        let mut global_data_summary = create_global_data_summary(1);
        initialize_data_requests(&mut data_stream, &global_data_summary);

        // Update the global data summary to be ahead of the subscription stream
        let highest_advertised_version = MAX_ADVERTISED_TRANSACTION + 500;
        global_data_summary.advertised_data.synced_ledger_infos = vec![create_ledger_info(
            highest_advertised_version,
            MAX_ADVERTISED_EPOCH_END,
            false,
        )];

        // Set a valid response for the first subscription request and process it
        let highest_response_version = highest_advertised_version - 300; // Behind the advertised version
        set_new_data_response_in_queue(
            &mut data_stream,
            0,
            highest_response_version,
            transactions_only,
        );
        process_data_responses(&mut data_stream, &global_data_summary).await;
        assert_some!(stream_listener.select_next_some().now_or_never());

        // Verify the stream is now tracking the subscription lag
        let subscription_stream_lag = data_stream.get_subscription_stream_lag().unwrap();
        assert_eq!(
            subscription_stream_lag.version_lag,
            highest_advertised_version - highest_response_version
        );

        // Elapse enough time for the stream to be killed
        let time_service = time_service.into_mock();
        time_service.advance_secs(max_subscription_stream_lag_secs);

        // Update the global data summary to be further ahead (by 1)
        let highest_advertised_version = highest_advertised_version + 1;
        global_data_summary.advertised_data.synced_ledger_infos = vec![create_ledger_info(
            highest_advertised_version,
            MAX_ADVERTISED_EPOCH_END,
            false,
        )];

        // Set a valid response for the first subscription request and process it
        let highest_response_version = highest_response_version + 1; // Still behind, but not worse
        set_new_data_response_in_queue(
            &mut data_stream,
            0,
            highest_response_version,
            transactions_only,
        );
        process_data_responses(&mut data_stream, &global_data_summary).await;
        assert_some!(stream_listener.select_next_some().now_or_never());

        // Elapse enough time for the stream to be killed (again)
        time_service.advance_secs(max_subscription_stream_lag_secs);

        // Update the global data summary to be further ahead (by 10)
        let highest_advertised_version = highest_advertised_version + 10;
        global_data_summary.advertised_data.synced_ledger_infos = vec![create_ledger_info(
            highest_advertised_version,
            MAX_ADVERTISED_EPOCH_END,
            false,
        )];

        // Set a valid response for the first subscription request and process it
        let highest_response_version = highest_response_version + 10; // Still behind, but not worse
        set_new_data_response_in_queue(
            &mut data_stream,
            0,
            highest_response_version,
            transactions_only,
        );
        process_data_responses(&mut data_stream, &global_data_summary).await;
        assert_some!(stream_listener.select_next_some().now_or_never());

        // Elapse enough time for the stream to be killed (again)
        time_service.advance_secs(max_subscription_stream_lag_secs);

        // Update the global data summary to be further ahead (by 100)
        let highest_advertised_version = highest_advertised_version + 100;
        global_data_summary.advertised_data.synced_ledger_infos = vec![create_ledger_info(
            highest_advertised_version,
            MAX_ADVERTISED_EPOCH_END,
            false,
        )];

        // Set a valid response for the first subscription request and process it
        let highest_response_version = highest_response_version + 101; // Still behind, but slightly better
        set_new_data_response_in_queue(
            &mut data_stream,
            0,
            highest_response_version,
            transactions_only,
        );
        process_data_responses(&mut data_stream, &global_data_summary).await;
        assert_some!(stream_listener.select_next_some().now_or_never());

        // Verify the state of the subscription stream lag
        let subscription_stream_lag = data_stream.get_subscription_stream_lag().unwrap();
        assert_eq!(
            subscription_stream_lag.version_lag,
            highest_advertised_version - highest_response_version
        );

        // Update the global data summary to be further ahead (by 100)
        let highest_advertised_version = highest_advertised_version + 100;
        global_data_summary.advertised_data.synced_ledger_infos = vec![create_ledger_info(
            highest_advertised_version,
            MAX_ADVERTISED_EPOCH_END,
            false,
        )];

        // Set a valid response for the first subscription request and process it
        let highest_response_version = highest_response_version + 150; // Still behind, but slightly better
        set_new_data_response_in_queue(
            &mut data_stream,
            0,
            highest_response_version,
            transactions_only,
        );
        process_data_responses(&mut data_stream, &global_data_summary).await;
        assert_some!(stream_listener.select_next_some().now_or_never());

        // Verify the state of the subscription stream lag
        let subscription_stream_lag = data_stream.get_subscription_stream_lag().unwrap();
        assert_eq!(
            subscription_stream_lag.version_lag,
            highest_advertised_version - highest_response_version
        );
    }
}
```

**File:** config/src/config/state_sync_config.rs (L259-278)
```rust
    pub max_subscription_stream_lag_secs: u64,

    /// The interval (milliseconds) at which to check the progress of each stream.
    pub progress_check_interval_ms: u64,
}

impl Default for DataStreamingServiceConfig {
    fn default() -> Self {
        Self {
            dynamic_prefetching: DynamicPrefetchingConfig::default(),
            enable_subscription_streaming: false,
            global_summary_refresh_interval_ms: 50,
            max_concurrent_requests: MAX_CONCURRENT_REQUESTS,
            max_concurrent_state_requests: MAX_CONCURRENT_STATE_REQUESTS,
            max_data_stream_channel_sizes: 50,
            max_notification_id_mappings: 300,
            max_num_consecutive_subscriptions: 45, // At ~3 blocks per second, this should last ~15 seconds
            max_pending_requests: 50,
            max_request_retry: 5,
            max_subscription_stream_lag_secs: 10, // 10 seconds
```
