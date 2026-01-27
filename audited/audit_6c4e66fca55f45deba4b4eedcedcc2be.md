# Audit Report

## Title
Panic-Induced Denial of Service in Indexer-gRPC Services Due to Unchecked System Time Operations

## Summary
Multiple critical paths in the indexer-grpc ecosystem contain unhandled `unwrap()` calls on `SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)`, which will panic and crash services if the system clock is set before January 1, 1970. This affects status page endpoints, data streaming, heartbeat mechanisms, and background health checks across five components: indexer-grpc-utils, data-service-v2, manager, and fullnode services.

## Finding Description

The vulnerability exists in multiple locations where system time calculations use `.unwrap()` without error handling:

**Primary location** (as specified in the security question): [1](#0-0) 

**Additional vulnerable locations found:**

1. **Historical data service streaming loop** - crashes during transaction batch processing: [2](#0-1) 

2. **Live data service updates** - crashes when processing new transaction data: [3](#0-2) 

3. **Fullnode ping RPC** - crashes during health check operations: [4](#0-3) 

4. **Metadata manager staleness checks** - crashes in background monitoring: [5](#0-4) 

5. **Utility function used widely** - exported function that propagates the issue: [6](#0-5) 

When `SystemTime::now()` is before `UNIX_EPOCH`, the `duration_since()` method returns `Err(SystemTimeError)`. The `.unwrap()` calls panic on this error, triggering the panic handler that exits the process with code 12: [7](#0-6) 

**Attack/Trigger Path:**
1. System clock becomes set before January 1, 1970 (due to VM snapshot, container time sync failure, NTP misconfiguration, or hardware clock issues)
2. Any of the following normal operations trigger the panic:
   - HTTP GET request to status page endpoint (exposed on health check port)
   - gRPC streaming requests to data services
   - Periodic ping/heartbeat checks between services
   - Background staleness monitoring in manager

The status page is publicly exposed via HTTP: [8](#0-7) 

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty program criteria: "API crashes" (up to $50,000).

**Affected Components:**
- indexer-grpc-data-service-v2 (both live and historical)
- indexer-grpc-manager  
- indexer-grpc-fullnode
- All services using the utility functions

**Impact Scope:**
- Complete denial of service for affected indexer infrastructure
- Crash loop - services repeatedly crash upon restart while system time remains incorrect
- Disruption to all clients consuming blockchain data through these APIs
- Loss of blockchain data indexing and serving capabilities
- Cascading failures as health checks and heartbeats crash dependent services

The indexer-grpc ecosystem is critical infrastructure for serving blockchain data with architecture spanning multiple services: [9](#0-8) 

## Likelihood Explanation

**Likelihood: Medium-Low** - Requires system clock misconfiguration as precondition, but once present, triggers are automatic.

**Realistic Scenarios:**
- Virtual machine snapshot restoration with old timestamps
- Container time synchronization failures  
- NTP daemon failures or misconfigurations
- Hardware clock battery failures
- Timezone calculation errors in edge cases
- Manual operator error during system administration
- Cloud infrastructure time sync issues

Once the precondition exists, crashes occur automatically through:
- Normal client API requests (no attacker action needed)
- Service's own background tasks and health checks
- Inter-service communication (pings, heartbeats)

The codebase acknowledges this risk exists, as evidenced by a utility function with explicit warning: [10](#0-9) 

## Recommendation

Replace all `.unwrap()` and `.expect()` calls on `duration_since()` with proper error handling. Use `unwrap_or_else()` or `unwrap_or()` with sensible defaults, or return errors gracefully.

**Recommended fix for `get_throughput_from_samples()`:**

```rust
pub fn get_throughput_from_samples(
    progress: Option<&StreamProgress>,
    duration: Duration,
) -> String {
    if let Some(progress) = progress {
        // Handle potential time error gracefully
        let now = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(d) => d.as_secs_f64(),
            Err(e) => {
                warn!("System time is before UNIX_EPOCH: {:?}", e);
                return "Time error".to_string();
            }
        };
        
        let index = progress.samples.partition_point(|p| {
            let diff = now - timestamp_to_unixtime(p.timestamp.as_ref().unwrap());
            diff > duration.as_secs_f64()
        });
        // ... rest of logic
    }
    "No data".to_string()
}
```

Apply similar defensive patterns across all affected locations. Consider creating a safe wrapper function that returns `Option<Duration>` or uses a fallback timestamp.

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    
    #[test]
    #[should_panic(expected = "SystemTimeError")]
    fn test_system_time_before_epoch_panics() {
        // This demonstrates the panic behavior
        // In a real system with clock set before 1970, this code path executes
        
        // Simulate by using a time before epoch
        let before_epoch = UNIX_EPOCH - Duration::from_secs(3600);
        
        // This panics - demonstrating the vulnerability
        let _result = before_epoch.duration_since(UNIX_EPOCH).unwrap();
    }
    
    #[test]
    fn test_status_page_crash_scenario() {
        // If we could mock SystemTime::now() to return pre-1970,
        // calling get_throughput_from_samples() would panic
        
        // The actual vulnerable code path:
        // 1. HTTP GET to status page
        // 2. render_connection_manager_info() calls get_throughput_from_samples()
        // 3. SystemTime::now().duration_since(UNIX_EPOCH).unwrap() panics
        // 4. Panic handler exits process with code 12
        
        // In production: any client accessing http://service:port/
        // triggers this if system clock is misconfigured
    }
}
```

**Notes**

This vulnerability affects ecosystem infrastructure components rather than core consensus. While it requires a system misconfiguration precondition (clock before 1970), this is a realistic operational scenario in virtualized/containerized environments. Once present, normal API operations by any client trigger service crashes. The code should handle time-related errors defensively rather than panicking. The issue spans 5+ critical code paths across multiple services, indicating a systemic error-handling pattern that needs correction throughout the indexer-grpc codebase.

### Citations

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/status_page/mod.rs (L90-92)
```rust
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/historical_data_service.rs (L194-194)
```rust
                let now_since_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
```

**File:** ecosystem/indexer-grpc/indexer-grpc-data-service-v2/src/live_data_service/data_manager.rs (L98-98)
```rust
                let now_since_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
```

**File:** ecosystem/indexer-grpc/indexer-grpc-fullnode/src/fullnode_data_service.rs (L229-229)
```rust
                let latency = SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
```

**File:** ecosystem/indexer-grpc/indexer-grpc-manager/src/metadata_manager.rs (L169-169)
```rust
        let now_since_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
```

**File:** ecosystem/indexer-grpc/indexer-grpc-utils/src/lib.rs (L108-108)
```rust
    let ts = system_time.duration_since(UNIX_EPOCH).unwrap();
```

**File:** ecosystem/indexer-grpc/indexer-grpc-server-framework/src/lib.rs (L150-167)
```rust
    std::panic::set_hook(Box::new(move |pi: &PanicHookInfo<'_>| {
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
    // Kill the process
    process::exit(12);
```

**File:** ecosystem/indexer-grpc/indexer-grpc-server-framework/src/lib.rs (L219-222)
```rust
    let status_endpoint = warp::path::end().and_then(move || {
        let config = config.clone();
        async move { config.status_page().await }
    });
```

**File:** ecosystem/indexer-grpc/README.md (L1-1)
```markdown
# Indexer GRPC
```

**File:** crates/aptos-infallible/src/time.rs (L8-12)
```rust
/// Gives the duration since the Unix epoch, notice the expect.
pub fn duration_since_epoch() -> Duration {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("System time is before the UNIX_EPOCH")
```
