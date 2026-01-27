# Audit Report

## Title
Telemetry Service Configuration Injection Leading to Undefined Behavior and Performance Degradation via Unvalidated RUST_LOG_TELEMETRY Environment Variable

## Summary
The `get_telemetry_log_env()` function returns an unvalidated string from the telemetry service that is directly injected into the `RUST_LOG_TELEMETRY` environment variable using unsafe code in a multi-threaded context. A compromised telemetry service can inject arbitrary logging configurations causing undefined behavior from data races and severe performance degradation on validator nodes.

## Finding Description

The vulnerability chain consists of three critical components:

1. **Unvalidated Input**: The `get_telemetry_log_env()` function fetches an arbitrary string from the remote telemetry service without any validation, sanitization, or length limits. [1](#0-0) 

2. **Unsafe Environment Variable Modification**: The returned string is directly set as the `RUST_LOG_TELEMETRY` environment variable using `unsafe { env::set_var() }` in an async tokio task, which operates in a multi-threaded context. The code includes TODO comments acknowledging that thread safety has not been audited. [2](#0-1) 

3. **Concurrent Access Without Synchronization**: The `LoggerFilterUpdater` periodically reads this environment variable every 5 minutes from a different thread to rebuild the logging filter. [3](#0-2) [4](#0-3) 

**Attack Scenario**: A compromised Aptos telemetry service (or malicious insider) can inject a malicious filter string such as `"trace"` which enables TRACE-level logging for all modules. This causes:

- **Undefined Behavior**: Rust's `std::env::set_var` is inherently unsafe in multi-threaded programs. Concurrent modifications and reads of environment variables can cause data races and undefined behavior per Rust documentation.

- **Performance Degradation**: TRACE-level logging across all modules causes massive CPU overhead for log formatting and serialization, even though the actual log transmission is non-blocking. The `LoggerService` must process every log entry through `json_format()` for telemetry. [5](#0-4) 

- **Information Disclosure**: Verbose logging exposes internal validator state, consensus messages, and potentially sensitive cryptographic material to the telemetry service.

**Violation of Secure Coding Guidelines**: The code violates Aptos's secure coding standards which require SAFETY comments justifying unsafe code, not TODO comments deferring the safety audit. [6](#0-5) 

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program:

- **Validator Node Slowdowns**: Enabling TRACE logging on all modules causes significant CPU overhead for log formatting, even though log transmission is non-blocking. Each log entry must be serialized to JSON format before attempting transmission.

- **Undefined Behavior Risk**: The unsafe concurrent environment variable access violates Rust's safety guarantees and can lead to unpredictable behavior, potentially including crashes or memory corruption.

- **Information Disclosure**: Attackers gain access to detailed internal validator state, consensus round information, and operational details through verbose logging.

While this does not directly break consensus safety (validators would still reach agreement), it degrades validator performance and violates the Resource Limits invariant that "all operations must respect computational limits."

## Likelihood Explanation

**Likelihood: Medium-High**

**Prerequisites**:
- Validators must have telemetry enabled (common in production)
- Validators must allow log environment polling (enabled by default unless `APTOS_DISABLE_LOG_ENV_POLLING` is set)
- Compromise of the Aptos telemetry service infrastructure OR malicious Aptos insider

**Frequency**: The polling occurs every 5 minutes, giving attackers regular opportunities to modify the configuration. [7](#0-6) 

**Detection Difficulty**: The attack is logged but may not be noticed immediately since configuration changes appear as normal telemetry operations. [8](#0-7) 

## Recommendation

**Immediate Mitigation**:
1. Add input validation to reject malformed or excessively permissive filter strings
2. Implement a whitelist of allowed log levels and module patterns
3. Replace unsafe environment variable modification with a thread-safe configuration mechanism

**Proper Fix**:
```rust
// In sender.rs - add validation
pub(crate) async fn get_telemetry_log_env(&self) -> Option<String> {
    let response = self
        .send_authenticated_request(/*...*/)
        .await;

    match response {
        Ok(response) => match error_for_status_with_body(response).await {
            Ok(response) => {
                let env_value = response.json::<Option<String>>().await.unwrap_or_default();
                // VALIDATION: Only accept safe, bounded filter strings
                env_value.and_then(|v| validate_log_filter(&v).ok())
            },
            Err(e) => { /*...*/ None },
        },
        Err(e) => { /*...*/ None },
    }
}

fn validate_log_filter(filter: &str) -> Result<String, &'static str> {
    // Reject if too long
    if filter.len() > 1024 {
        return Err("Filter too long");
    }
    
    // Parse and validate directives
    let directives: Vec<&str> = filter.split(',').collect();
    for directive in directives {
        // Only allow info/warn/error, not debug/trace
        if directive.contains("trace") || directive.contains("debug") {
            return Err("Trace/debug logging not allowed from remote config");
        }
    }
    
    Ok(filter.to_string())
}
```

**Alternative Fix**: Remove the remote configuration feature entirely and rely only on local environment variables set by operators, eliminating the external injection vector.

## Proof of Concept

```rust
// Proof of Concept Test - Add to crates/aptos-telemetry/src/sender.rs tests

#[tokio::test]
async fn test_malicious_log_env_injection() {
    use httpmock::MockServer;
    use crate::sender::TelemetrySender;
    
    let server = MockServer::start();
    
    // Attacker-controlled telemetry service returns malicious filter
    let mock = server.mock(|when, then| {
        when.method("GET")
            .header("Authorization", "Bearer SECRET_JWT_TOKEN")
            .path("/api/v1/config/env/telemetry-log");
        then.status(200)
            .json_body_obj(&Some("trace".to_string())); // Enable TRACE for all modules
    });

    let node_config = NodeConfig::default();
    let client = TelemetrySender::new(
        Url::parse(&server.base_url()).expect("unable to parse base url"),
        ChainId::default(),
        &node_config,
    );
    {
        *client.auth_context.token.write() = Some("SECRET_JWT_TOKEN".into());
    }

    // Fetch malicious configuration
    let result = client.get_telemetry_log_env().await;
    
    mock.assert();
    
    // Demonstrate: No validation occurs, malicious value is returned
    assert_eq!(result, Some("trace".to_string()));
    
    // In production, this would be set as environment variable via:
    // unsafe { env::set_var(RUST_LOG_TELEMETRY, "trace") }
    // Causing performance degradation and undefined behavior from concurrent access
}
```

## Notes

The vulnerability is particularly concerning because:

1. **Trust Boundary Violation**: The telemetry service is treated as a trusted configuration source despite being an external network service
2. **TODO Comments Indicate Known Issue**: The code contains explicit TODO comments acknowledging the thread safety audit has not been completed
3. **Centralized Attack Point**: Compromising a single telemetry service affects all validators connected to it
4. **Silent Degradation**: Performance impact may not trigger immediate alerts, allowing sustained attack

The authentication mechanism (Noise protocol) protects against MITM attacks but not against a compromised telemetry service itself.

### Citations

**File:** crates/aptos-telemetry/src/sender.rs (L381-404)
```rust
    pub(crate) async fn get_telemetry_log_env(&self) -> Option<String> {
        let response = self
            .send_authenticated_request(
                self.client.get(
                    self.build_path("config/env/telemetry-log")
                        .expect("unable to build telemetry path for config/env/telemetry-log"),
                ),
            )
            .await;

        match response {
            Ok(response) => match error_for_status_with_body(response).await {
                Ok(response) => response.json::<Option<String>>().await.unwrap_or_default(),
                Err(e) => {
                    debug!("Unable to get telemetry log env: {}", e);
                    None
                },
            },
            Err(e) => {
                debug!("Unable to check chain access {}", e);
                None
            },
        }
    }
```

**File:** crates/aptos-telemetry/src/service.rs (L219-227)
```rust
                if let Some(env) = sender.get_telemetry_log_env().await {
                    info!(
                        "Updating {} env variable: previous value: {:?}, new value: {}",
                        RUST_LOG_TELEMETRY,
                        env::var(RUST_LOG_TELEMETRY).ok(),
                        env
                    );
                    // TODO: Audit that the environment access only happens in single-threaded code.
                    unsafe { env::set_var(RUST_LOG_TELEMETRY, env) }
```

**File:** crates/aptos-logger/src/aptos_logger.rs (L46-47)
```rust
const FILTER_REFRESH_INTERVAL: Duration =
    Duration::from_secs(5 /* minutes */ * 60 /* seconds */);
```

**File:** crates/aptos-logger/src/aptos_logger.rs (L408-420)
```rust

            if self.is_async && self.remote_log_tx.is_some() {
                if env::var(RUST_LOG_TELEMETRY).is_ok() {
                    filter_builder.with_env(RUST_LOG_TELEMETRY);
                } else {
                    filter_builder.filter_level(self.telemetry_level.into());
                }
            } else {
                filter_builder.filter_level(LevelFilter::Off);
            }

            filter_builder.build()
        };
```

**File:** crates/aptos-logger/src/aptos_logger.rs (L642-653)
```rust
                    if let Some(writer) = &mut telemetry_writer {
                        if self
                            .facade
                            .filter
                            .read()
                            .telemetry_filter
                            .enabled(&entry.metadata)
                        {
                            let s = json_format(&entry).expect("Unable to format");
                            let _ = writer.write(s);
                        }
                    }
```

**File:** RUST_SECURE_CODING.md (L55-65)
```markdown
### Unsafe Code

Never use `unsafe` blocks unless as a last resort. Justify their use in a comment, detailing how the code is effectively safe to deploy.

```rust
  foo(
      // SAFETY:
      // This is a valid safety comment
      unsafe { *x }
  )
```
```

**File:** crates/aptos-telemetry/src/constants.rs (L44-44)
```rust
pub(crate) const LOG_ENV_POLL_FREQ_SECS: u64 = 5 * 60; // 5 minutes
```
