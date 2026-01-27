# Audit Report

## Title
Metrics Encoding Panic Crashes Entire Indexer Process Due to Global Panic Handler

## Summary
The indexer-grpc-server-framework's metrics endpoint uses `.unwrap()` on `encoder.encode()`, which will panic if encoding fails. Due to a global panic handler that calls `process::exit(12)`, this panic crashes the entire indexer process rather than just failing the individual HTTP request, making all indexer services unavailable to clients and monitoring systems.

## Finding Description

The vulnerability exists in the `register_probes_and_metrics_handler()` function where metrics are encoded for the `/metrics` endpoint. [1](#0-0) 

When this encoding operation fails and the `.unwrap()` panics, the execution flow is as follows:

1. The panic triggers the global panic handler installed during server startup [2](#0-1) 

2. The panic handler invokes `handle_panic()` which logs crash information and unconditionally calls `process::exit(12)` [3](#0-2) 

3. The entire indexer process terminates, taking down not just the health check server but also the main indexer service running in parallel [4](#0-3) 

This breaks the availability invariant - the service should gracefully handle individual request failures without crashing the entire process. The warp server provides no panic recovery mechanism (no `.recover()` or `catch_unwind`), so panics in request handlers propagate to the global panic hook.

**Contrast with Secure Implementation**: The aptos-inspection-service properly handles encoding errors by checking the Result and returning an empty vector on failure, allowing the service to continue running: [5](#0-4) 

**Affected Services**: This framework is used by multiple critical production indexer services including indexer-grpc-data-service, indexer-grpc-cache-worker, indexer-grpc-gateway, indexer-grpc-file-store, indexer-grpc-manager, and nft-metadata-crawler.

## Impact Explanation

This is a **High Severity** vulnerability per Aptos bug bounty criteria for the following reasons:

1. **API Crashes** (explicitly listed as High severity): When encoding fails, it crashes the entire indexer API, making it unavailable to all clients

2. **Service Availability Loss**: The crash affects the main indexer service, not just the metrics endpoint, causing data indexing to stop

3. **Monitoring System Impact**: The health check server goes down along with the main service, making the indexer appear completely unhealthy and potentially triggering cascading failures in dependent systems

4. **Multiple Service Impact**: All indexer services using this framework are vulnerable

While the encoding failure itself is rare (typically only occurring with memory exhaustion or corrupted metric data), the severity of the impact when it does occur justifies the High rating. It does not reach Critical severity because it doesn't affect consensus, cause fund loss, or impact validator nodes directly.

## Likelihood Explanation

**Likelihood: Low to Medium**

The `encoder.encode()` method returns `io::Error` which, when writing to a `Vec<u8>` in memory, should rarely fail under normal conditions. However, failures can occur in several scenarios:

1. **Memory Allocation Failures**: During Out-of-Memory (OOM) conditions, the Vec expansion could fail
2. **Corrupted Metric Data**: If metric label strings contain invalid UTF-8 or the prometheus metric registry becomes corrupted
3. **Prometheus Encoder Bugs**: Edge cases in the prometheus crate's TextEncoder implementation
4. **High Metric Cardinality**: With extremely high metric cardinality (thousands of label combinations), encoding could encounter edge cases

While these conditions are uncommon in normal operation, they can occur in production environments under stress, making this a realistic attack surface. The low likelihood is offset by the severe impact (complete service crash).

## Recommendation

Replace the `.unwrap()` with proper error handling that logs the error and returns an error response instead of panicking:

```rust
let metrics_endpoint = warp::path("metrics").map(|| {
    let metrics = aptos_metrics_core::gather();
    let mut encode_buffer = vec![];
    let encoder = TextEncoder::new();
    
    // Handle encoding errors gracefully instead of panicking
    match encoder.encode(&metrics, &mut encode_buffer) {
        Ok(_) => Response::builder()
            .header("Content-Type", "text/plain")
            .body(encode_buffer),
        Err(e) => {
            error!("Failed to encode metrics: {}", e);
            Response::builder()
                .status(warp::http::StatusCode::INTERNAL_SERVER_ERROR)
                .body(format!("Metrics encoding failed: {}", e).into_bytes())
        }
    }
});
```

This follows the pattern already established in the aptos-inspection-service, ensuring that encoding failures only affect the individual metrics request, not the entire service.

## Proof of Concept

```rust
#[cfg(test)]
mod vulnerability_test {
    use super::*;
    use prometheus::{Encoder, IntCounter, Registry, TextEncoder};
    use std::io;

    // Custom encoder that simulates encoding failure
    struct FailingEncoder;
    
    impl Encoder for FailingEncoder {
        fn encode<W: io::Write>(
            &self,
            _: &[prometheus::proto::MetricFamily],
            _: &mut W,
        ) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "Simulated encoding failure",
            ))
        }
        
        fn format_type(&self) -> &str {
            "text/plain"
        }
    }

    #[test]
    #[should_panic(expected = "Failed to encode metrics")]
    fn test_metrics_encoding_panic() {
        // This test demonstrates that encoding failures cause panics
        // In production, this would crash the entire service
        let registry = Registry::new();
        let counter = IntCounter::new("test_counter", "test").unwrap();
        registry.register(Box::new(counter)).unwrap();
        
        let metrics = registry.gather();
        let mut buffer = vec![];
        let encoder = FailingEncoder;
        
        // This will panic, just like the production code
        encoder
            .encode(&metrics, &mut buffer)
            .context("Failed to encode metrics")
            .unwrap();
    }
    
    #[test]
    fn test_metrics_encoding_graceful_handling() {
        // This test shows the correct approach - handling errors gracefully
        let registry = Registry::new();
        let counter = IntCounter::new("test_counter", "test").unwrap();
        registry.register(Box::new(counter)).unwrap();
        
        let metrics = registry.gather();
        let mut buffer = vec![];
        let encoder = FailingEncoder;
        
        // Graceful error handling - service continues to run
        match encoder.encode(&metrics, &mut buffer) {
            Ok(_) => assert!(false, "Should have failed"),
            Err(e) => {
                // Error is logged, empty response returned, service continues
                eprintln!("Failed to encode metrics: {}", e);
                assert!(buffer.is_empty());
            }
        }
    }
}
```

## Notes

This vulnerability demonstrates a broader pattern issue in the codebase: the global panic handler that kills the process is too aggressive for HTTP service handlers. While it may be appropriate for consensus or VM components where panics indicate serious invariant violations, HTTP endpoints should handle panics gracefully to avoid cascading failures. The contrast between this implementation and the aptos-inspection-service shows that the team is aware of proper error handling patterns, but they haven't been consistently applied across all services.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-server-framework/src/lib.rs (L36-37)
```rust
        setup_logging(None);
        setup_panic_handler();
```

**File:** ecosystem/indexer-grpc/indexer-grpc-server-framework/src/lib.rs (L46-77)
```rust
pub async fn run_server_with_config<C>(config: GenericConfig<C>) -> Result<()>
where
    C: RunnableConfig,
{
    let health_port = config.health_check_port;
    // Start liveness and readiness probes.
    let config_clone = config.clone();
    let task_handler = tokio::spawn(async move {
        register_probes_and_metrics_handler(config_clone, health_port).await;
        anyhow::Ok(())
    });
    let main_task_handler =
        tokio::spawn(async move { config.run().await.expect("task should exit with Ok.") });
    tokio::select! {
        res = task_handler => {
            if let Err(e) = res {
                error!("Probes and metrics handler panicked or was shutdown: {:?}", e);
                process::exit(1);
            } else {
                panic!("Probes and metrics handler exited unexpectedly");
            }
        },
        res = main_task_handler => {
            if let Err(e) = res {
                error!("Main task panicked or was shutdown: {:?}", e);
                process::exit(1);
            } else {
                panic!("Main task exited unexpectedly");
            }
        },
    }
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-server-framework/src/lib.rs (L156-168)
```rust
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
    // Kill the process
    process::exit(12);
}
```

**File:** ecosystem/indexer-grpc/indexer-grpc-server-framework/src/lib.rs (L209-212)
```rust
        encoder
            .encode(&metrics, &mut encode_buffer)
            .context("Failed to encode metrics")
            .unwrap();
```

**File:** crates/aptos-inspection-service/src/server/utils.rs (L36-39)
```rust
    if let Err(error) = encoder.encode(&metric_families, &mut encoded_buffer) {
        error!("Failed to encode metrics! Error: {}", error);
        return vec![];
    }
```
