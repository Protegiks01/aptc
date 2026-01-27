# Audit Report

## Title
Information Disclosure: Validator Network Topology and IP Addresses Leaked Through Unsanitized Logging

## Summary
The `Event::dispatch()` mechanism in the Aptos logging infrastructure does not perform any sanitization of sensitive validator network data before logging. Validator IP addresses, DNS names, network topology, peer identities, and connection metadata are logged in plaintext to both local files and remote telemetry endpoints, enabling attackers with log access to map the entire validator network and conduct targeted attacks.

## Finding Description

The logging pipeline in Aptos Core exposes sensitive validator network information through multiple unsanitized code paths:

**1. Event Dispatch Without Sanitization** [1](#0-0) 

The `Event::dispatch()` function accepts arbitrary structured data through the `keys_and_values` parameter and passes it directly to the logger without any filtering or sanitization mechanism.

**2. NetworkSchema Exposes Full Network Addresses** [2](#0-1) 

The `NetworkSchema` structure contains `network_address` and `remote_peer` fields that capture complete network topology information.

**3. Network Addresses Display Full IP Information** [3](#0-2) [4](#0-3) 

NetworkAddress Display implementation outputs complete addresses including IP addresses, DNS names, TCP ports, and x25519 public keys in formats like `/ip4/10.0.0.16/tcp/6180/noise-ik/<pubkey>/handshake/1`.

**4. Actual Logging of Sensitive Data** [5](#0-4) 

Validator nodes actively log network addresses when dialing peers, exposing the IP address and connection details. [6](#0-5) 

The entire `discovered_peers` data structure is logged periodically, containing all known validator network addresses, public keys, roles, and ping latencies.

**5. DiscoveredPeerSet Contains Complete Network Topology** [7](#0-6) [8](#0-7) 

The `DiscoveredPeer` structure stores complete network information including addresses, public keys, validator roles, and connection metadata, all of which get logged without sanitization.

**6. No Sanitization in Log Entry Creation** [9](#0-8) 

The `LogEntry::new()` function visits all schemas and serializes values directly using Display, Debug, or Serde without any sanitization checks.

**7. Logs Exported to Multiple Destinations** [10](#0-9) 

Log entries are written to both local files and remote telemetry endpoints without filtering, making the sensitive data accessible through multiple attack vectors.

**8. Consensus Also Logs Validator Identities** [11](#0-10) 

Consensus operations log validator `Author` (which is `AccountAddress`) and `remote_peer` information, enabling correlation of validator identities with network addresses.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program criteria for the following reasons:

**Direct Security Impact:**
- **Validator Deanonymization**: Attackers can correlate validator account addresses with IP addresses, breaking operational anonymity
- **Network Topology Mapping**: Complete validator network topology is exposed, showing connection patterns and peer relationships
- **Targeted Attack Enablement**: Knowledge of validator IPs enables:
  - Targeted DDoS attacks against specific validators
  - Sybil attacks by surrounding target validators
  - Eclipse attacks by controlling network connections
  - Physical infrastructure attacks if IP geolocation reveals datacenter locations

**Attack Vectors:**
1. Compromise of log aggregation systems (common in production deployments)
2. Filesystem access on validator nodes through other vulnerabilities
3. Access to remote telemetry endpoints (less secure than validator nodes themselves)
4. Insider threats at monitoring/logging service providers
5. Misconfigured log storage permissions

**Severity Classification:**
This falls under "Significant protocol violations" in the High Severity category ($50,000 range) because:
- It compromises validator operational security
- It enables follow-on attacks that could affect consensus and liveness
- It violates the security principle that validator network topology should not be publicly observable
- The information disclosed has direct utility for sophisticated attacks on network infrastructure

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to be exploited because:

1. **Logs are Generated Continuously**: Every validator node constantly generates logs containing this information during normal operation
2. **Multiple Access Points**: Logs are written to local files AND remote telemetry endpoints, multiplying the attack surface
3. **Common Operational Practices**: Organizations typically aggregate logs from multiple sources into centralized logging systems (ELK stack, Splunk, etc.), which become high-value targets
4. **Lower Security Perimeter**: Log storage and telemetry systems often have weaker security controls than validator nodes themselves
5. **No Detection**: Since logging is normal behavior, information disclosure leaves no trace
6. **Persistent Exposure**: Historical logs may remain accessible long after being written, extending the window of vulnerability

## Recommendation

Implement a comprehensive log sanitization layer before data reaches the logging system:

**1. Create a Sanitization Interface:**

Add a `Sanitizable` trait that sensitive types must implement:
```rust
pub trait Sanitizable {
    fn sanitize(&self) -> String;
}
```

**2. Implement Sanitization for NetworkAddress:**

Override the logging behavior to show only necessary information:
```rust
impl Sanitizable for NetworkAddress {
    fn sanitize(&self) -> String {
        // Only log protocol types, not actual addresses
        let protocols: Vec<&str> = self.0.iter()
            .map(|p| match p {
                Protocol::Ip4(_) => "ip4",
                Protocol::Ip6(_) => "ip6", 
                Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) => "dns",
                Protocol::Tcp(_) => "tcp",
                Protocol::Memory(_) => "memory",
                Protocol::NoiseIK(_) => "noise-ik",
                Protocol::Handshake(v) => return format!("handshake/{}", v),
            })
            .collect();
        format!("/{}", protocols.join("/"))
    }
}
```

**3. Sanitize Peer IDs:**

For AccountAddress/PeerId, only log a short prefix:
```rust
impl Sanitizable for AccountAddress {
    fn sanitize(&self) -> String {
        format!("{}...", self.short_str())
    }
}
```

**4. Update LogEntry Creation:**

Modify the `JsonVisitor` to check for sanitizable values and apply sanitization before logging:
```rust
impl Visitor for JsonVisitor<'_> {
    fn visit_pair(&mut self, key: Key, value: Value<'_>) {
        let v = match value {
            Value::Debug(d) => {
                // Check if type implements Sanitizable
                if key.as_str().contains("address") || key.as_str().contains("peer") {
                    serde_json::Value::String("[REDACTED]".to_string())
                } else {
                    serde_json::Value::String(
                        TruncatedLogString::from(format!("{:?}", d)).into()
                    )
                }
            },
            // ... rest of implementation
        };
        self.0.insert(key, v);
    }
}
```

**5. Add Configuration Flag:**

Provide an environment variable to enable full logging only in non-production environments:
```rust
const ENABLE_VERBOSE_LOGGING: &str = "APTOS_ENABLE_VERBOSE_LOGGING";

fn should_sanitize() -> bool {
    env::var(ENABLE_VERBOSE_LOGGING).is_err()
}
```

## Proof of Concept

**Reproduction Steps:**

1. Start an Aptos validator node with standard configuration
2. Enable file logging in the configuration
3. Wait for the node to establish peer connections
4. Examine the log file for sensitive information:

```bash
# Start validator node
aptos-node -f validator-config.yaml

# Wait 60 seconds for connectivity checks
sleep 60

# Search for network address disclosures
grep -i "Dialing peer" /var/log/aptos-node.log
# Output will show: "Dialing peer 0xABCD1234 at /ip4/192.168.1.100/tcp/6180/..."

grep -i "Active discovered peers" /var/log/aptos-node.log  
# Output will show complete peer set with all network addresses

# Search for validator identity correlations
grep -i "remote_peer" /var/log/aptos-node.log | grep -i "network_address"
# Output correlates validator account addresses with IP addresses
```

**Expected Results:**
The logs will contain entries like:
```
2024-01-15T10:30:45.123456Z INFO [network] Dialing peer 0a1b2c3d at /ip4/203.0.113.42/tcp/6180/noise-ik/0x8f9e8d7c6b5a4938271605f4e3d2c1b0a9f8e7d6c5b4a39281706f5e4d3c2b1a0/handshake/1
2024-01-15T10:31:00.456789Z INFO [network] Active discovered peers: {"peer_set": {"0a1b2c3d": {"addrs": [["/ip4/203.0.113.42/tcp/6180/..."]], "role": "Validator", "ping_latency_secs": 0.045}}}
```

This demonstrates that sensitive network topology information is being logged without any sanitization, allowing anyone with access to these logs to map the validator network infrastructure.

**Notes**

The vulnerability specifically affects validator network infrastructure security rather than direct consensus safety. However, the information disclosed through unsanitized logs enables sophisticated attacks that could ultimately compromise validator operations and network stability. The lack of any sanitization mechanism in the `Event::dispatch()` pipeline represents a fundamental oversight in the logging architecture that should be addressed through the implementation of a comprehensive sanitization layer for all sensitive blockchain data before it reaches log outputs.

### Citations

**File:** crates/aptos-logger/src/event.rs (L29-36)
```rust
    pub fn dispatch(
        metadata: &'a Metadata,
        message: Option<fmt::Arguments<'a>>,
        keys_and_values: &'a [&'a dyn Schema],
    ) {
        let event = Event::new(metadata, message, keys_and_values);
        crate::logger::dispatch(&event)
    }
```

**File:** network/framework/src/logging.rs (L32-45)
```rust
#[derive(Schema)]
pub struct NetworkSchema<'a> {
    connection_id: Option<&'a ConnectionId>,
    #[schema(display)]
    connection_origin: Option<&'a ConnectionOrigin>,
    #[schema(display)]
    discovery_source: Option<&'a DiscoverySource>,
    message: Option<String>,
    #[schema(display)]
    network_address: Option<&'a NetworkAddress>,
    network_context: &'a NetworkContext,
    #[schema(display)]
    remote_peer: Option<&'a PeerId>,
}
```

**File:** types/src/network_address/mod.rs (L514-520)
```rust
impl fmt::Display for NetworkAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for protocol in self.0.iter() {
            protocol.fmt(f)?;
        }
        Ok(())
    }
```

**File:** types/src/network_address/mod.rs (L598-618)
```rust
impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use self::Protocol::*;
        match self {
            Ip4(addr) => write!(f, "/ip4/{}", addr),
            Ip6(addr) => write!(f, "/ip6/{}", addr),
            Dns(domain) => write!(f, "/dns/{}", domain),
            Dns4(domain) => write!(f, "/dns4/{}", domain),
            Dns6(domain) => write!(f, "/dns6/{}", domain),
            Tcp(port) => write!(f, "/tcp/{}", port),
            Memory(port) => write!(f, "/memory/{}", port),
            NoiseIK(pubkey) => write!(
                f,
                "/noise-ik/{}",
                pubkey
                    .to_encoded_string()
                    .expect("ValidCryptoMaterialStringExt::to_encoded_string is infallible")
            ),
            Handshake(version) => write!(f, "/handshake/{}", version),
        }
    }
```

**File:** network/framework/src/connectivity_manager/mod.rs (L177-179)
```rust
struct DiscoveredPeerSet {
    peer_set: HashMap<PeerId, DiscoveredPeer>,
}
```

**File:** network/framework/src/connectivity_manager/mod.rs (L232-241)
```rust
#[derive(Clone, Debug, PartialEq, Serialize)]
struct DiscoveredPeer {
    role: PeerRole,
    addrs: Addresses,
    keys: PublicKeys,
    /// The last time the node was dialed
    last_dial_time: SystemTime,
    /// The calculated peer ping latency (secs)
    ping_latency_secs: Option<f64>,
}
```

**File:** network/framework/src/connectivity_manager/mod.rs (L775-783)
```rust
                    info!(
                        NetworkSchema::new(&network_context)
                            .remote_peer(&peer_id)
                            .network_address(&addr),
                        "{} Dialing peer {} at {}",
                        network_context,
                        peer_id.short_str(),
                        addr
                    );
```

**File:** network/framework/src/connectivity_manager/mod.rs (L819-823)
```rust
            info!(
                NetworkSchema::new(&self.network_context),
                discovered_peers = ?self.discovered_peers,
                "Active discovered peers"
            )
```

**File:** crates/aptos-logger/src/aptos_logger.rs (L162-188)
```rust
    fn new(event: &Event, thread_name: Option<&str>, enable_backtrace: bool) -> Self {
        use crate::{Value, Visitor};

        struct JsonVisitor<'a>(&'a mut BTreeMap<Key, serde_json::Value>);

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
        }
```

**File:** crates/aptos-logger/src/aptos_logger.rs (L550-564)
```rust
    fn send_entry(&self, entry: LogEntry) {
        if let Some(printer) = &self.printer {
            let s = (self.formatter)(&entry).expect("Unable to format");
            printer.write(s);
        }

        if let Some(sender) = &self.sender {
            if sender
                .try_send(LoggerServiceEvent::LogEntry(entry))
                .is_err()
            {
                STRUCT_LOG_QUEUE_ERROR_COUNT.inc();
            }
        }
    }
```

**File:** consensus/src/logging.rs (L10-18)
```rust
#[derive(Schema)]
pub struct LogSchema {
    event: LogEvent,
    author: Option<Author>,
    remote_peer: Option<Author>,
    epoch: Option<u64>,
    round: Option<Round>,
    id: Option<HashValue>,
}
```
