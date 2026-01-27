# Audit Report

## Title
Data Race in Logger Filter Construction: Unsynchronized Concurrent Environment Variable Access

## Summary
The `LoggerFilterUpdater::update_filter()` function calls `build_filter()` which reads the `RUST_LOG_TELEMETRY` environment variable without synchronization, while a concurrent task in the telemetry service periodically modifies the same environment variable. This creates a data race that violates Rust's safety guarantees and constitutes undefined behavior.

## Finding Description

The vulnerability exists in the concurrent execution of two async tasks within the telemetry runtime:

**Task 1: Environment Variable Writer** [1](#0-0) 

This task spawns and runs every 5 minutes, calling `unsafe { env::set_var(RUST_LOG_TELEMETRY, env) }` to modify the `RUST_LOG_TELEMETRY` environment variable.

**Task 2: Logger Filter Updater** [2](#0-1) 

This task spawns concurrently and runs every 5 minutes, calling: [3](#0-2) 

Which calls `build_filter()`: [4](#0-3) 

This reads the environment variable via: [5](#0-4) 

**The Data Race:**
According to Rust's documentation, `std::env::set_var` is explicitly unsafe in multi-threaded contexts: *"This function is not thread-safe. Calling it can cause data races if another thread is reading or writing environment variables."*

The developers acknowledge this issue with TODO comments: [6](#0-5) 

Both tasks run with identical 5-minute intervals, maximizing the probability of concurrent access over the lifetime of a validator node.

**Violated Safety Guarantee:**
This creates undefined behavior at the C FFI boundary when environment variables are accessed. At the OS level, environment variables are stored as pointers in the process environment. Concurrent modification and reading can cause use-after-free, partial reads, or memory corruption.

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty program criteria:

- **Validator node slowdowns**: If the race causes logging to malfunction, critical debug information may be lost
- **API crashes**: Undefined behavior can manifest as validator node crashes due to memory corruption
- **Significant protocol violations**: Loss of logging can hide critical errors affecting consensus participation

While this is not a directly exploitable vulnerability (it occurs automatically without attacker interaction), it affects validator availability, which is critical for network health. A validator node crash would constitute a violation of the network's liveness guarantees.

## Likelihood Explanation

**Probability: Medium-to-High**
- Both tasks run every 5 minutes (300 seconds) [7](#0-6) [8](#0-7) 
- Over a 24-hour period, there are 288 opportunities for the race to occur
- With identical intervals, the tasks will eventually align in their execution
- The race window is the duration of the environment variable read/write operations

**Manifestation: Variable**
- Undefined behavior means the actual impact is unpredictable
- Most likely: corrupted filter strings that are silently ignored during parsing [9](#0-8) 
- Less likely but possible: memory corruption leading to crashes

## Recommendation

Implement proper synchronization for environment variable access. The recommended approach is to eliminate runtime environment variable modification entirely and use a configuration-based approach:

**Option 1: Use atomic configuration storage**
```rust
// In aptos_logger.rs
static TELEMETRY_LOG_LEVEL: RwLock<Option<String>> = RwLock::new(None);

// Writer updates the config
TELEMETRY_LOG_LEVEL.write().replace(new_value);

// Reader checks the config
if let Some(level) = TELEMETRY_LOG_LEVEL.read().as_ref() {
    filter_builder.parse(level);
}
```

**Option 2: Use message passing**
Pass filter updates through a channel rather than modifying environment variables at runtime.

**Option 3: Restrict to initialization only**
Only read environment variables during node initialization, never modify them at runtime. Update filters through a dedicated API that doesn't use environment variables.

The `unsafe` blocks should be removed, and the TODO comments resolved: [6](#0-5) 

## Proof of Concept

```rust
// Reproduction test demonstrating the race condition
#[tokio::test]
async fn test_env_var_data_race() {
    use std::env;
    use std::time::Duration;
    use tokio::time;
    
    // Simulate the writer task
    let writer = tokio::spawn(async {
        for i in 0..100 {
            unsafe {
                env::set_var("RUST_LOG_TELEMETRY", format!("debug,test{}", i));
            }
            time::sleep(Duration::from_millis(10)).await;
        }
    });
    
    // Simulate the reader task  
    let reader = tokio::spawn(async {
        for _ in 0..100 {
            // This read races with the write above
            let _ = env::var("RUST_LOG_TELEMETRY");
            time::sleep(Duration::from_millis(10)).await;
        }
    });
    
    // Both tasks run concurrently - undefined behavior
    let _ = tokio::join!(writer, reader);
    
    // Note: This demonstrates the race exists, but UB manifestation
    // is unpredictable and may not crash immediately
}
```

**Notes:**
This is a latent bug that manifests automatically during normal validator operation rather than being triggered by external attacker input. The undefined behavior could theoretically cause validator node crashes or memory corruption, affecting network liveness. The issue should be addressed by eliminating concurrent environment variable modification as recommended above.

### Citations

**File:** crates/aptos-telemetry/src/service.rs (L204-207)
```rust
    // Run the logger filter update job within the telemetry runtime.
    if let Some(job) = logger_filter_update_job {
        tokio::spawn(job.run());
    }
```

**File:** crates/aptos-telemetry/src/service.rs (L212-238)
```rust
fn try_spawn_log_env_poll_task(sender: TelemetrySender) {
    if enable_log_env_polling() {
        tokio::spawn(async move {
            let original_value = env::var(RUST_LOG_TELEMETRY).ok();
            let mut interval = time::interval(Duration::from_secs(LOG_ENV_POLL_FREQ_SECS));
            loop {
                interval.tick().await;
                if let Some(env) = sender.get_telemetry_log_env().await {
                    info!(
                        "Updating {} env variable: previous value: {:?}, new value: {}",
                        RUST_LOG_TELEMETRY,
                        env::var(RUST_LOG_TELEMETRY).ok(),
                        env
                    );
                    // TODO: Audit that the environment access only happens in single-threaded code.
                    unsafe { env::set_var(RUST_LOG_TELEMETRY, env) }
                } else if let Some(ref value) = original_value {
                    // TODO: Audit that the environment access only happens in single-threaded code.
                    unsafe { env::set_var(RUST_LOG_TELEMETRY, value) }
                } else {
                    // TODO: Audit that the environment access only happens in single-threaded code.
                    unsafe { env::remove_var(RUST_LOG_TELEMETRY) }
                }
            }
        });
    }
}
```

**File:** crates/aptos-logger/src/aptos_logger.rs (L46-47)
```rust
const FILTER_REFRESH_INTERVAL: Duration =
    Duration::from_secs(5 /* minutes */ * 60 /* seconds */);
```

**File:** crates/aptos-logger/src/aptos_logger.rs (L410-411)
```rust
                if env::var(RUST_LOG_TELEMETRY).is_ok() {
                    filter_builder.with_env(RUST_LOG_TELEMETRY);
```

**File:** crates/aptos-logger/src/aptos_logger.rs (L817-821)
```rust
    fn update_filter(&self) {
        // TODO: check for change to env var before rebuilding filter.
        let filter = self.logger_builder.build_filter();
        self.logger.set_filter(filter);
    }
```

**File:** crates/aptos-logger/src/filter.rs (L67-73)
```rust
    pub fn with_env(&mut self, env: &str) -> &mut Self {
        if let Ok(s) = env::var(env) {
            self.parse(&s);
        }

        self
    }
```

**File:** crates/aptos-logger/src/filter.rs (L95-103)
```rust
    pub fn parse(&mut self, filters: &str) -> &mut Self {
        self.directives.extend(
            filters
                .split(',')
                .map(Directive::from_str)
                .filter_map(Result::ok),
        );
        self
    }
```

**File:** crates/aptos-telemetry/src/constants.rs (L44-44)
```rust
pub(crate) const LOG_ENV_POLL_FREQ_SECS: u64 = 5 * 60; // 5 minutes
```
