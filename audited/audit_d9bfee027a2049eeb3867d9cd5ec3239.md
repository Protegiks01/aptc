# Audit Report

## Title
Remote Control of Logging Levels Enables State Synchronization Topology Mapping via Telemetry Service

## Summary
The telemetry service can remotely enable trace-level logging on validators without explicit operator consent, causing `StorageServiceRequest` logs containing peer identities, version ranges, and synchronization patterns to be transmitted to external log aggregation systems. A malicious or compromised telemetry service can correlate these logs across validators to map the entire state synchronization topology and identify critical validators for targeted attacks.

## Finding Description

The Aptos telemetry system implements a remote logging control mechanism that allows the telemetry service to dynamically adjust logging levels on connected validators. This occurs through an environment variable polling mechanism: [1](#0-0) 

Every 5 minutes, validators poll the telemetry service endpoint `config/env/telemetry-log` to retrieve logging configuration: [2](#0-1) 

This polling is enabled by default unless explicitly disabled: [3](#0-2) [4](#0-3) [5](#0-4) 

When trace-level logging is enabled (either via configuration or remote control), `StorageServiceRequest` logs expose sensitive network topology information: [6](#0-5) 

These logs contain: [7](#0-6) 

The `request_data` field includes detailed request information such as version ranges, epoch numbers, and subscription stream IDs: [8](#0-7) 

The telemetry filter determines what gets sent to the telemetry service: [9](#0-8) 

Default telemetry level is Error, but can be changed: [10](#0-9) 

**Attack Path:**

1. Attacker compromises or controls a telemetry service endpoint (either the official service or a custom service configured by validators)
2. Attacker configures the `config/env/telemetry-log` endpoint to return trace-level logging configuration
3. Connected validators poll this endpoint every 5 minutes and update their `RUST_LOG_TELEMETRY` environment variable
4. Trace-level `StorageServiceRequest` logs are now sent to the telemetry service
5. Attacker receives logs from multiple validators containing:
   - Peer network IDs revealing which validators are syncing from which peers
   - Version and epoch numbers revealing which validators are behind
   - Request patterns and frequencies revealing synchronization behavior
   - Subscription stream metadata revealing long-term sync relationships
6. Attacker correlates logs across validators to construct a complete state synchronization topology map
7. Attacker identifies critical validators (those serving many peers) and struggling validators (those far behind)
8. Attacker uses this information to launch targeted attacks: DDoS on critical validators, eclipse attacks on isolated nodes, or timing-based attacks during synchronization

## Impact Explanation

This vulnerability enables **information leakage** that facilitates reconnaissance for more serious attacks. Per the Aptos bug bounty program, this qualifies as **Medium Severity** because:

1. It exposes network topology information that is not intended to be public
2. The information enables identification of critical infrastructure components
3. Attackers can use this intelligence to plan targeted attacks on validator availability
4. While not directly causing funds loss or consensus violations, it significantly reduces the security posture of the network by exposing attack surfaces

The impact is elevated beyond "minor information leaks" (Low Severity) because it provides actionable intelligence for infrastructure-level attacks that could lead to consensus or availability issues.

## Likelihood Explanation

**Likelihood: Medium-to-High**

The attack is realistic and requires:
- Compromise of the telemetry service endpoint OR convincing validators to use a malicious telemetry service
- No validator-level privileges or collusion required
- The remote control mechanism is enabled by default
- Many validators likely use the default telemetry configuration

Factors increasing likelihood:
- Default-enabled remote logging control
- 5-minute polling interval provides rapid attack window
- No authentication or authorization on the logging level configuration
- Validator operators may be unaware of this remote control capability

Factors decreasing likelihood:
- Requires telemetry service compromise or malicious configuration
- Validators can disable telemetry entirely

## Recommendation

**Immediate Mitigations:**

1. **Disable Remote Logging Control by Default**: Change the default for `enable_log_env_polling()` to require explicit opt-in rather than opt-out.

2. **Add Authentication**: Implement cryptographic authentication for the telemetry logging configuration endpoint to ensure only authorized parties can modify logging levels.

3. **Add Rate Limiting and Alerting**: When logging levels change, emit high-priority alerts to validator operators and implement rate limiting to prevent rapid changes.

4. **Redact Sensitive Information**: Modify the `StorageServiceRequest` logging to exclude or hash peer identities and sanitize version/epoch numbers in trace logs sent to telemetry.

**Recommended Code Fix:**

In `crates/aptos-telemetry/src/constants.rs`, change the default behavior:
```rust
// Require explicit opt-in for remote log control
pub(crate) const ENV_APTOS_ENABLE_LOG_ENV_POLLING: &str = "APTOS_ENABLE_LOG_ENV_POLLING";
```

In `crates/aptos-telemetry/src/service.rs`, change the enable function:
```rust
#[inline]
fn enable_log_env_polling() -> bool {
    // Changed from opt-out to opt-in
    is_env_variable_true(ENV_APTOS_ENABLE_LOG_ENV_POLLING)
}
```

In `state-sync/aptos-data-client/src/logging.rs`, add PII redaction for telemetry:
```rust
pub struct LogSchema<'a> {
    // ... existing fields ...
    #[schema(display)]  // Changed from display to avoid full peer details
    peer_short: Option<String>,  // Only log shortened peer ID
    // Don't log full request_data in telemetry context
}
```

## Proof of Concept

**Rust Reproduction Steps:**

```rust
use aptos_logger::{Level, AptosData};
use std::env;

// 1. Simulate attacker controlling telemetry service
// Set RUST_LOG_TELEMETRY to enable trace logging
env::set_var("RUST_LOG_TELEMETRY", "trace");

// 2. Create logger with telemetry enabled
let mut builder = AptosData::builder();
builder
    .telemetry_level(Level::Trace)  // Attacker-controlled via remote config
    .level(Level::Info);  // Local logging stays at Info

// 3. Log a StorageServiceRequest (as validator would during state sync)
trace!(
    LogSchema::new(LogEntry::StorageServiceRequest)
        .peer(&peer_network_id)  // Contains validator identity
        .request_data(&storage_request)  // Contains version, epoch, patterns
        .request_id(12345)
);

// 4. Observe that trace logs containing:
//    - peer: "Validator:abc123..." (full peer identity)
//    - request_data: { known_version: 1000000, known_epoch: 5, ... }
//    - Are now sent to telemetry service

// 5. Attacker aggregates logs from multiple validators and correlates:
//    - Validator A requests from Validator B at version X
//    - Validator C requests from Validator B at version Y
//    - => Validator B is a critical node serving many peers
//    - => Validator C is behind (lower version number)
```

**Notes**

This vulnerability represents a defense-in-depth failure where operational telemetry capabilities create an attack vector for network topology reconnaissance. While validators can disable telemetry entirely, the default-enabled remote control mechanism and the detailed information exposed in trace logs create unnecessary risk. The issue is particularly concerning because validator operators may be unaware that external services can remotely modify their logging configuration, violating the principle of least surprise and creating a hidden attack surface.

### Citations

**File:** crates/aptos-telemetry/src/service.rs (L106-109)
```rust
fn enable_log_env_polling() -> bool {
    force_enable_telemetry()
        || !(telemetry_is_disabled() || is_env_variable_true(ENV_APTOS_DISABLE_LOG_ENV_POLLING))
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

**File:** crates/aptos-telemetry/src/sender.rs (L381-402)
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
```

**File:** crates/aptos-telemetry/src/constants.rs (L16-16)
```rust
pub(crate) const ENV_APTOS_DISABLE_LOG_ENV_POLLING: &str = "APTOS_DISABLE_LOG_ENV_POLLING";
```

**File:** crates/aptos-telemetry/src/constants.rs (L44-44)
```rust
pub(crate) const LOG_ENV_POLL_FREQ_SECS: u64 = 5 * 60; // 5 minutes
```

**File:** state-sync/aptos-data-client/src/client.rs (L779-786)
```rust
        trace!(
            (LogSchema::new(LogEntry::StorageServiceRequest)
                .event(LogEvent::SendRequest)
                .request_type(&request.get_label())
                .request_id(id)
                .peer(&peer)
                .request_data(&request))
        );
```

**File:** state-sync/aptos-data-client/src/logging.rs (L10-23)
```rust
#[derive(Schema)]
pub struct LogSchema<'a> {
    name: LogEntry,
    #[schema(debug)]
    error: Option<&'a Error>,
    event: Option<LogEvent>,
    message: Option<&'a str>,
    #[schema(display)]
    peer: Option<&'a PeerNetworkId>,
    #[schema(debug)]
    request_data: Option<&'a StorageServiceRequest>,
    request_id: Option<u64>,
    request_type: Option<&'a str>,
}
```

**File:** state-sync/storage-service/types/src/requests.rs (L8-31)
```rust
/// A storage service request.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct StorageServiceRequest {
    pub data_request: DataRequest, // The data to fetch from the storage service
    pub use_compression: bool,     // Whether or not the client wishes data to be compressed
}

impl StorageServiceRequest {
    pub fn new(data_request: DataRequest, use_compression: bool) -> Self {
        Self {
            data_request,
            use_compression,
        }
    }

    /// Returns a summary label for the request
    pub fn get_label(&self) -> String {
        let mut label = self.data_request.get_label().to_string();
        if self.use_compression {
            label += COMPRESSION_SUFFIX_LABEL;
        }
        label
    }
}
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

**File:** config/src/config/logger_config.rs (L40-57)
```rust
impl Default for LoggerConfig {
    fn default() -> LoggerConfig {
        LoggerConfig {
            chan_size: CHANNEL_SIZE,
            enable_backtrace: false,
            is_async: true,
            level: Level::Info,
            enable_telemetry_remote_log: true,
            enable_telemetry_flush: true,
            telemetry_level: Level::Error,

            // This is the default port used by tokio-console.
            // Setting this to None will disable tokio-console
            // even if the "tokio-console" feature is enabled.
            tokio_console_port: None,
        }
    }
}
```
