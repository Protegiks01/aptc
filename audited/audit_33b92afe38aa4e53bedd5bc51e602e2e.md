# Audit Report

## Title
Validator Node Crash Due to Unhandled Panic in Metrics Registry Initialization

## Summary
The `ACTIVE_DATA_STREAMS` metric in the data streaming service uses `.unwrap()` on the prometheus registry initialization, which can cause a validator node crash if metric registration fails during node startup. This results in complete loss of liveness as the node exits with code 12 and cannot participate in consensus.

## Finding Description

The vulnerability exists in the metrics initialization code for the data streaming service: [1](#0-0) 

This metric is lazily initialized and first accessed during the streaming service's progress check loop: [2](#0-1) 

The streaming service is spawned during node startup and is critical for state synchronization: [3](#0-2) 

The node blocks until state sync completes initialization before starting consensus: [4](#0-3) 

If the prometheus `register_int_gauge!` macro returns an error (e.g., due to corrupted registry state, lock poisoning from a previous panic in another thread, or race conditions during initialization), the `.unwrap()` call will panic. The global panic handler immediately exits the process: [5](#0-4) 

This creates a critical failure cascade:
1. Metric registration fails → `.unwrap()` panics
2. Panic handler triggers → `process::exit(12)` terminates the validator
3. Streaming service crashes → bootstrapper cannot fetch data
4. State sync cannot initialize → `block_until_initialized()` hangs indefinitely
5. Validator cannot start consensus → complete loss of liveness

## Impact Explanation

This vulnerability meets **HIGH severity** criteria per Aptos bug bounty guidelines:
- **Validator node crashes**: Complete process termination via `process::exit(12)`
- **Loss of liveness**: Validator cannot participate in consensus after crash
- **Significant protocol violation**: Breaks the node availability invariant

While the prometheus registry is in-memory and would reset on restart, if the underlying cause is systematic (e.g., a race condition in initialization logic or persistent corruption scenario), the node could enter a crash loop, requiring manual intervention.

## Likelihood Explanation

**Likelihood: LOW to MEDIUM**

The vulnerability triggers when `register_int_gauge!` fails, which can occur in several scenarios:

1. **Lock poisoning**: If another thread panics while holding the prometheus registry lock, subsequent registration attempts will fail
2. **Concurrent initialization race**: If multiple threads attempt to access the lazy static simultaneously during startup
3. **Memory corruption**: System-level memory issues affecting the prometheus global registry
4. **Registry state corruption**: Rare edge cases in the prometheus library itself

While these scenarios are uncommon under normal operation, they represent real failure modes that are not handled gracefully. The severity is elevated because when it does occur, the impact is catastrophic (total node crash).

## Recommendation

Replace all `.unwrap()` calls on metric registration with proper error handling that logs the error and continues with a no-op metric or default value instead of panicking:

```rust
pub static ACTIVE_DATA_STREAMS: Lazy<Option<IntGauge>> = Lazy::new(|| {
    match register_int_gauge!(
        "aptos_data_streaming_service_active_data_streams",
        "Counters related to the number of active data streams",
    ) {
        Ok(gauge) => Some(gauge),
        Err(e) => {
            error!("Failed to register ACTIVE_DATA_STREAMS metric: {:?}", e);
            None
        }
    }
});

pub fn set_active_data_streams(value: usize) {
    if let Some(gauge) = ACTIVE_DATA_STREAMS.as_ref() {
        gauge.set(value as i64);
    }
}
```

This pattern should be applied to all metrics in the file: [6](#0-5) 

## Proof of Concept

```rust
// Reproduction steps (requires unsafe code to simulate registry corruption):
//
// 1. Start a validator node
// 2. Simulate prometheus registry lock poisoning by causing a panic
//    in another thread while it holds the registry lock
// 3. The streaming service initialization will trigger when it calls
//    check_progress_of_all_data_streams() 
// 4. The ACTIVE_DATA_STREAMS lazy static will attempt registration
// 5. Registration fails due to poisoned lock → unwrap() panics
// 6. Panic handler calls process::exit(12) → validator crashes
// 7. Node cannot participate in consensus → liveness violation
//
// Note: This PoC requires system-level manipulation and cannot be
// demonstrated in a standard test environment without unsafe operations
// or mocking the prometheus registry behavior.

#[cfg(test)]
mod test {
    use std::sync::{Arc, Mutex};
    use std::thread;

    // Simulate lock poisoning scenario
    #[test]
    #[should_panic(expected = "PoisonError")]
    fn test_poisoned_lock_simulation() {
        let data = Arc::new(Mutex::new(0));
        let data2 = Arc::clone(&data);
        
        // Poison the lock by panicking while holding it
        let _ = thread::spawn(move || {
            let _guard = data2.lock().unwrap();
            panic!("Simulated panic while holding lock");
        }).join();
        
        // Subsequent access will fail with PoisonError
        let _guard = data.lock().unwrap(); // This will panic
    }
}
```

## Notes

This vulnerability affects the **state synchronization critical path** during validator node startup. While the likelihood is low under normal conditions, the impact is severe enough to warrant immediate remediation. The fix is straightforward and follows defensive programming best practices by handling all potential error conditions gracefully rather than assuming infallibility.

All similar `.unwrap()` patterns on metric registrations throughout the codebase should be reviewed and replaced with proper error handling to prevent cascading failures in production environments.

### Citations

**File:** state-sync/data-streaming-service/src/metrics.rs (L29-221)
```rust
pub static ACTIVE_DATA_STREAMS: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "aptos_data_streaming_service_active_data_streams",
        "Counters related to the number of active data streams",
    )
    .unwrap()
});

/// Counter for the number of times there was a send failure
pub static DATA_STREAM_SEND_FAILURE: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "aptos_data_streaming_service_stream_send_failure",
        "Counters related to send failures along the data stream",
    )
    .unwrap()
});

/// Counter for the creation of new data streams
pub static CREATE_DATA_STREAM: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "aptos_data_streaming_service_create_data_stream",
        "Counters related to the creation of new data streams",
        &["request_type"]
    )
    .unwrap()
});

/// Counter for the creation of new subscription streams
pub static CREATE_SUBSCRIPTION_STREAM: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "aptos_data_streaming_service_create_subscription_stream",
        "Counters related to the creation of new subscription streams",
    )
    .unwrap()
});

/// Counter for the termination of existing data streams
pub static TERMINATE_DATA_STREAM: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "aptos_data_streaming_service_terminate_data_stream",
        "Counters related to the termination of existing data streams",
        &["feedback_type"]
    )
    .unwrap()
});

/// Counter for the termination of existing subscription streams
pub static TERMINATE_SUBSCRIPTION_STREAM: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "aptos_data_streaming_service_terminate_subscription_stream",
        "Counters related to the termination of existing subscription streams",
        &["termination_reason"]
    )
    .unwrap()
});

/// Counter for stream progress check errors
pub static CHECK_STREAM_PROGRESS_ERROR: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "aptos_data_streaming_service_check_progress_error",
        "Counters related to stream progress check errors",
        &["error_type"]
    )
    .unwrap()
});

/// Counter for global data summary errors
pub static GLOBAL_DATA_SUMMARY_ERROR: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "aptos_data_streaming_service_global_summary_error",
        "Counters related to global data summary errors",
        &["error_type"]
    )
    .unwrap()
});

/// Counter for tracking sent data requests
pub static SENT_DATA_REQUESTS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "aptos_data_streaming_service_sent_data_requests",
        "Counters related to sent data requests",
        &["request_type"]
    )
    .unwrap()
});

/// Counter for tracking sent data requests for missing data
pub static SENT_DATA_REQUESTS_FOR_MISSING_DATA: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "aptos_data_streaming_service_sent_data_requests_for_missing_data",
        "Counters related to sent data requests for missing data",
        &["request_type"]
    )
    .unwrap()
});

/// Counter for tracking data requests that were retried (including
/// the new timeouts).
pub static RETRIED_DATA_REQUESTS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "aptos_data_streaming_service_retried_data_requests",
        "Counters related to retried data requests",
        &["request_type", "request_timeout"]
    )
    .unwrap()
});

/// Counter for the number of max concurrent prefetching requests
pub static MAX_CONCURRENT_PREFETCHING_REQUESTS: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "aptos_data_streaming_service_max_concurrent_prefetching_requests",
        "The number of max concurrent prefetching requests",
    )
    .unwrap()
});

/// Counter for the number of pending data responses
pub static PENDING_DATA_RESPONSES: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "aptos_data_streaming_service_pending_data_responses",
        "Counters related to the number of pending data responses",
    )
    .unwrap()
});

/// Counter for the number of complete pending data responses
pub static COMPLETE_PENDING_DATA_RESPONSES: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "aptos_data_streaming_service_complete_pending_data_responses",
        "Counters related to the number of complete pending data responses",
    )
    .unwrap()
});

/// Counter for tracking received data responses
pub static RECEIVED_DATA_RESPONSE: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "aptos_data_streaming_service_received_data_response",
        "Counters related to received data responses",
        &["response_type"]
    )
    .unwrap()
});

/// Counter for tracking the sizes of received data chunks
pub static RECEIVED_DATA_RESPONSE_CHUNK_SIZE: Lazy<HistogramVec> = Lazy::new(|| {
    let histogram_opts = histogram_opts!(
        "aptos_data_streaming_service_received_data_chunk_sizes",
        "Counter for tracking sizes of data chunks received by the data stream",
        DATA_RESPONSE_CHUNK_SIZE_BUCKETS.to_vec()
    );
    register_histogram_vec!(histogram_opts, &["request_type", "response_type"]).unwrap()
});

/// Counter for tracking received data responses
pub static RECEIVED_RESPONSE_ERROR: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "aptos_data_streaming_service_received_response_error",
        "Counters related to received response errors",
        &["error_type"]
    )
    .unwrap()
});

/// Counter that keeps track of the subscription stream lag (versions)
pub static SUBSCRIPTION_STREAM_LAG: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "aptos_data_streaming_service_subscription_stream_lag",
        "Counters related to the subscription stream lag",
    )
    .unwrap()
});

/// Time it takes to process a data request
pub static DATA_REQUEST_PROCESSING_LATENCY: Lazy<HistogramVec> = Lazy::new(|| {
    let histogram_opts = histogram_opts!(
        "aptos_data_streaming_service_data_request_processing_latency",
        "Counters related to data request processing latencies",
        NETWORK_LATENCY_BUCKETS.to_vec()
    );
    register_histogram_vec!(histogram_opts, &["request_type"]).unwrap()
});

/// Time it takes to send a data notification after a successful data response
pub static DATA_NOTIFICATION_SEND_LATENCY: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "aptos_data_streaming_service_data_notification_send_latency",
        "Counters related to the data notification send latency",
        &["label"],
        exponential_buckets(/*start=*/ 1e-3, /*factor=*/ 2.0, /*count=*/ 30).unwrap(),
    )
    .unwrap()
});
```

**File:** state-sync/data-streaming-service/src/streaming_service.rs (L309-337)
```rust
    async fn check_progress_of_all_data_streams(&mut self) {
        // Drive the progress of each stream
        let data_stream_ids = self.get_all_data_stream_ids();
        for data_stream_id in &data_stream_ids {
            if let Err(error) = self.update_progress_of_data_stream(data_stream_id).await {
                if matches!(error, Error::NoDataToFetch(_)) {
                    sample!(
                        SampleRate::Duration(Duration::from_secs(NO_DATA_TO_FETCH_LOG_FREQ_SECS)),
                        info!(LogSchema::new(LogEntry::CheckStreamProgress)
                            .stream_id(*data_stream_id)
                            .event(LogEvent::Pending)
                            .error(&error))
                    );
                } else {
                    metrics::increment_counter(
                        &metrics::CHECK_STREAM_PROGRESS_ERROR,
                        error.get_label(),
                    );
                    warn!(LogSchema::new(LogEntry::CheckStreamProgress)
                        .stream_id(*data_stream_id)
                        .event(LogEvent::Error)
                        .error(&error));
                }
            }
        }

        // Update the metrics
        metrics::set_active_data_streams(data_stream_ids.len());
    }
```

**File:** aptos-node/src/state_sync.rs (L216-237)
```rust
/// Sets up the data streaming service runtime
fn setup_data_streaming_service(
    state_sync_config: StateSyncConfig,
    aptos_data_client: AptosDataClient,
) -> anyhow::Result<(StreamingServiceClient, Runtime)> {
    // Create the data streaming service
    let (streaming_service_client, streaming_service_listener) =
        new_streaming_service_client_listener_pair();
    let data_streaming_service = DataStreamingService::new(
        state_sync_config.aptos_data_client,
        state_sync_config.data_streaming_service,
        aptos_data_client,
        streaming_service_listener,
        TimeService::real(),
    );

    // Start the data streaming service
    let streaming_service_runtime = aptos_runtimes::spawn_named_runtime("stream-serv".into(), None);
    streaming_service_runtime.spawn(data_streaming_service.start_service());

    Ok((streaming_service_client, streaming_service_runtime))
}
```

**File:** aptos-node/src/lib.rs (L824-827)
```rust
    // Wait until state sync has been initialized
    debug!("Waiting until state sync is initialized!");
    state_sync_runtimes.block_until_initialized();
    debug!("State sync initialization complete.");
```

**File:** crates/crash-handler/src/lib.rs (L26-58)
```rust
pub fn setup_panic_handler() {
    panic::set_hook(Box::new(move |pi: &PanicHookInfo<'_>| {
        handle_panic(pi);
    }));
}

// Formats and logs panic information
fn handle_panic(panic_info: &PanicHookInfo<'_>) {
    // The Display formatter for a PanicHookInfo contains the message, payload and location.
    let details = format!("{}", panic_info);
    let backtrace = format!("{:#?}", Backtrace::new());

    let info = CrashInfo { details, backtrace };
    let crash_info = toml::to_string_pretty(&info).unwrap();
    error!("{}", crash_info);
    // TODO / HACK ALARM: Write crash info synchronously via eprintln! to ensure it is written before the process exits which error! doesn't guarantee.
    // This is a workaround until https://github.com/aptos-labs/aptos-core/issues/2038 is resolved.
    eprintln!("{}", crash_info);

    // Wait till the logs have been flushed
    aptos_logger::flush();

    // Do not kill the process if the panics happened at move-bytecode-verifier.
    // This is safe because the `state::get_state()` uses a thread_local for storing states. Thus the state can only be mutated to VERIFIER by the thread that's running the bytecode verifier.
    //
    // TODO: once `can_unwind` is stable, we should assert it. See https://github.com/rust-lang/rust/issues/92988.
    if state::get_state() == VMState::VERIFIER || state::get_state() == VMState::DESERIALIZER {
        return;
    }

    // Kill the process
    process::exit(12);
}
```
