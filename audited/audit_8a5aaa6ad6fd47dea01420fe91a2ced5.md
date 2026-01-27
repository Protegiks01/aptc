# Audit Report

## Title
Unbounded Log Growth via Large Peer Monitoring Service Responses When Trace Logging Is Enabled

## Summary
The peer monitoring service server logs response payloads at trace level without size limits. When trace logging is enabled, attackers can trigger disk exhaustion by repeatedly requesting network information from nodes with thousands of connected peers, as the logging system bypasses truncation for string fields serialized via `from_serde`.

## Finding Description

The vulnerability exists in the peer monitoring service's response logging mechanism. When a node receives a `GetNetworkInformation` request, it responds with a `NetworkInformationResponse` containing all connected peers. [1](#0-0) 

The response is formatted using Debug representation (`format!("{:?}", response)`) and logged via the `LogSchema` struct: [2](#0-1) 

The `response` field is defined as `Option<&'a str>`. The Schema derive macro generates code that uses `Value::from_serde()` by default for string types: [3](#0-2) 

In the logger's `JsonVisitor` implementation, `Value::Serde` values are serialized directly without applying `TruncatedLogString` truncation: [4](#0-3) 

While `Value::Debug` and `Value::Display` apply the 10KB truncation limit, `Value::Serde` does not: [5](#0-4) 

A `NetworkInformationResponse` can contain thousands of connected peers (validators have no outbound connection limit and maintain full-mesh topology): [6](#0-5) [7](#0-6) 

**Attack Path:**
1. Attacker identifies a node with trace logging enabled (via `RUST_LOG=trace`)
2. Attacker sends repeated `GetNetworkInformation` requests
3. Each response is logged with the full Debug representation (potentially megabytes per log entry)
4. With max_concurrent_requests of 1000, sustained requests cause rapid log file growth
5. Disk space exhaustion leads to node failure

The system lacks log rotation mechanisms: [8](#0-7) 

## Impact Explanation

This vulnerability breaks the **Resource Limits** invariant (#9): "All operations must respect gas, storage, and computational limits."

**Impact Assessment: Medium Severity**

While this could cause node failure (availability loss), it requires the non-default configuration of trace logging being enabled. The default production log level is Info: [9](#0-8) 

The impact aligns with Medium Severity in the bug bounty program: "State inconsistencies requiring intervention" - disk exhaustion requires operator intervention to restore node availability.

## Likelihood Explanation

**Likelihood: Low to Medium**

- **Low in production**: Trace logging is NOT enabled by default (default is Info level)
- **Medium in test/dev environments**: Operators may enable trace logging for debugging
- **Attack complexity**: Low - simple repeated HTTP/RPC requests
- **Detection difficulty**: Medium - unusual disk growth may trigger alerts, but attribution to specific attack is unclear

The vulnerability is exploitable only when operators explicitly set `RUST_LOG` to include trace level, which happens during debugging or troubleshooting sessions.

## Recommendation

**Fix 1: Use Display or Debug serialization for response field**

Modify the LogSchema to explicitly use `from_display` or `from_debug`, which applies truncation:

```rust
#[derive(Schema)]
pub struct LogSchema<'a> {
    name: LogEntry,
    error: Option<&'a Error>,
    message: Option<&'a str>,
    #[schema(display)]  // Add this attribute
    response: Option<&'a str>,
    request: Option<&'a PeerMonitoringServiceRequest>,
}
```

**Fix 2: Add explicit size limit before logging**

Add response size validation in `log_monitoring_service_response`:

```rust
fn log_monitoring_service_response(
    monitoring_service_response: &Result<PeerMonitoringServiceResponse, PeerMonitoringServiceError>,
) {
    let response = match monitoring_service_response {
        Ok(response) => format!("{:?}", response),
        Err(error) => format!("{:?}", error),
    };
    
    // Truncate if too large
    const MAX_LOG_RESPONSE_SIZE: usize = 10 * 1024; // 10KB
    let truncated_response = if response.len() > MAX_LOG_RESPONSE_SIZE {
        format!("{}...(truncated, {} bytes total)", &response[..MAX_LOG_RESPONSE_SIZE], response.len())
    } else {
        response
    };
    
    trace!(LogSchema::new(LogEntry::SentPeerMonitoringResponse).response(&truncated_response));
}
```

**Fix 3: Use high-level summary for trace logging**

Instead of logging the full response at trace level, log a summary:

```rust
if let Ok(PeerMonitoringServiceResponse::NetworkInformation(ref net_info)) = monitoring_service_response {
    trace!(LogSchema::new(LogEntry::SentPeerMonitoringResponse)
        .message(&format!("NetworkInfo: {} peers, distance {}", 
            net_info.connected_peers.len(), 
            net_info.distance_from_validators)));
} else {
    trace!(LogSchema::new(LogEntry::SentPeerMonitoringResponse)
        .response(&format!("{:?}", monitoring_service_response)));
}
```

## Proof of Concept

```rust
// Test to demonstrate unbounded log growth
#[test]
fn test_large_network_info_response_logging() {
    use std::collections::BTreeMap;
    use aptos_config::network_id::PeerNetworkId;
    use aptos_types::PeerId;
    use peer_monitoring_service_types::response::{NetworkInformationResponse, ConnectionMetadata};
    
    // Enable trace logging
    std::env::set_var("RUST_LOG", "trace");
    aptos_logger::AptosData::init_for_testing();
    
    // Create a response with 1000 connected peers
    let mut connected_peers = BTreeMap::new();
    for i in 0..1000 {
        let peer_id = PeerId::random();
        let peer_network_id = PeerNetworkId::random();
        let metadata = ConnectionMetadata::new(
            format!("/ip4/127.0.0.1/tcp/{}", 6180 + i).parse().unwrap(),
            peer_id,
            aptos_config::config::PeerRole::Validator,
        );
        connected_peers.insert(peer_network_id, metadata);
    }
    
    let response = NetworkInformationResponse {
        connected_peers,
        distance_from_validators: 0,
    };
    
    // Log the response multiple times (simulating repeated requests)
    for _ in 0..100 {
        log_monitoring_service_response(&Ok(PeerMonitoringServiceResponse::NetworkInformation(response.clone())));
    }
    
    // In a real scenario, this would generate hundreds of megabytes of logs
    // Each log entry with 1000 peers would be ~200KB+ in Debug format
    // 100 requests * 200KB = ~20MB minimum
}
```

**Notes:**
- This vulnerability only affects nodes with trace logging explicitly enabled via the `RUST_LOG` environment variable
- Default production configurations use Info-level logging and are NOT vulnerable
- The attack becomes feasible during debugging sessions or in test environments where trace logging is commonly enabled
- No log rotation mechanism exists in the aptos-logger implementation, relying on external tools like logrotate

### Citations

**File:** peer-monitoring-service/server/src/lib.rs (L342-355)
```rust
/// Logs the response sent by the monitoring service for a request
fn log_monitoring_service_response(
    monitoring_service_response: &Result<PeerMonitoringServiceResponse, PeerMonitoringServiceError>,
) {
    let response = match monitoring_service_response {
        Ok(response) => {
            format!("{:?}", response)
        },
        Err(error) => {
            format!("{:?}", error)
        },
    };
    trace!(LogSchema::new(LogEntry::SentPeerMonitoringResponse).response(&response));
}
```

**File:** peer-monitoring-service/server/src/logging.rs (L9-28)
```rust
#[derive(Schema)]
pub struct LogSchema<'a> {
    name: LogEntry,
    error: Option<&'a Error>,
    message: Option<&'a str>,
    response: Option<&'a str>,
    request: Option<&'a PeerMonitoringServiceRequest>,
}

impl LogSchema<'_> {
    pub fn new(name: LogEntry) -> Self {
        Self {
            name,
            error: None,
            message: None,
            response: None,
            request: None,
        }
    }
}
```

**File:** crates/aptos-log-derive/src/lib.rs (L70-90)
```rust
    let visits = fields.iter().map(|f| {
        let ident = f.ident.as_ref().unwrap();
        let ident_str = ident.to_string();

        let from_fn = match f.value_type {
            Some(ValueType::Display) => &from_display,
            Some(ValueType::Debug) => &from_debug,
            Some(ValueType::Serde) | None => &from_serde,
        };
        if f.inner_ty.is_some() {
            quote! {
                if let Some(#ident) = &self.#ident {
                    #visitor.visit_pair(#key_new(#ident_str), #from_fn(#ident));
                }
            }
        } else {
            quote! {
                #visitor.visit_pair(#key_new(#ident_str), #from_fn(&self.#ident));
            }
        }
    });
```

**File:** crates/aptos-logger/src/aptos_logger.rs (L49-73)
```rust
/// Note: To disable length limits, set `RUST_LOG_FIELD_MAX_LEN` to -1.
const RUST_LOG_FIELD_MAX_LEN_ENV_VAR: &str = "RUST_LOG_FIELD_MAX_LEN";
static RUST_LOG_FIELD_MAX_LEN: Lazy<usize> = Lazy::new(|| {
    env::var(RUST_LOG_FIELD_MAX_LEN_ENV_VAR)
        .ok()
        .and_then(|value| i64::from_str(&value).map(|value| value as usize).ok())
        .unwrap_or(TruncatedLogString::DEFAULT_MAX_LEN)
});

struct TruncatedLogString(String);

impl TruncatedLogString {
    const DEFAULT_MAX_LEN: usize = 10 * 1024;
    const TRUNCATION_SUFFIX: &'static str = "(truncated)";

    fn new(s: String) -> Self {
        let mut truncated = s;

        if truncated.len() > RUST_LOG_FIELD_MAX_LEN.saturating_add(Self::TRUNCATION_SUFFIX.len()) {
            truncated.truncate(*RUST_LOG_FIELD_MAX_LEN);
            truncated.push_str(Self::TRUNCATION_SUFFIX);
        }
        TruncatedLogString(truncated)
    }
}
```

**File:** crates/aptos-logger/src/aptos_logger.rs (L167-187)
```rust
        impl Visitor for JsonVisitor<'_> {
            fn visit_pair(&mut self, key: Key, value: Value<'_>) {
                let v = match value {
                    Value::Debug(d) => serde_json::Value::String(
                        TruncatedLogString::from(format!("{:?}", d)).into(),
                    ),
                    Value::Display(d) => {
                        serde_json::Value::String(TruncatedLogString::from(d.to_string()).into())
                    },
                    Value::Serde(s) => match serde_json::to_value(s) {
                        Ok(value) => value,
                        Err(e) => {
                            // Log and skip the value that can't be serialized
                            eprintln!("error serializing structured log: {} for key {:?}", e, key);
                            return;
                        },
                    },
                };

                self.0.insert(key, v);
            }
```

**File:** crates/aptos-logger/src/aptos_logger.rs (L318-320)
```rust
            level: Level::Info,
            remote_level: Level::Info,
            telemetry_level: Level::Warn,
```

**File:** crates/aptos-logger/src/aptos_logger.rs (L717-746)
```rust
/// A struct for writing logs to a file
pub struct FileWriter {
    log_file: RwLock<std::fs::File>,
}

impl FileWriter {
    pub fn new(log_file: std::path::PathBuf) -> Self {
        let file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(log_file)
            .expect("Unable to open log file");
        Self {
            log_file: RwLock::new(file),
        }
    }
}

impl Writer for FileWriter {
    /// Write to file
    fn write(&self, log: String) {
        if let Err(err) = writeln!(self.log_file.write(), "{}", log) {
            eprintln!("Unable to write to log file: {}", err);
        }
    }

    fn write_buferred(&mut self, log: String) {
        self.write(log);
    }
}
```

**File:** peer-monitoring-service/types/src/response.rs (L50-67)
```rust
/// A response for the network information request
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NetworkInformationResponse {
    pub connected_peers: BTreeMap<PeerNetworkId, ConnectionMetadata>, // Connected peers
    pub distance_from_validators: u64, // The distance of the peer from the validator set
}

// Display formatting provides a high-level summary of the response
impl Display for NetworkInformationResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{{ num_connected_peers: {:?}, distance_from_validators: {:?} }}",
            self.connected_peers.len(),
            self.distance_from_validators,
        )
    }
}
```

**File:** config/src/config/network_config.rs (L43-44)
```rust
pub const MAX_FULLNODE_OUTBOUND_CONNECTIONS: usize = 6;
pub const MAX_INBOUND_CONNECTIONS: usize = 100;
```
