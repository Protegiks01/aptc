# Audit Report

## Title
Validator Network Address Information Leakage Through Prometheus Metrics Endpoint

## Summary
The Aptos node inspection service exposes private IP addresses and port numbers of validator nodes through the publicly accessible Prometheus metrics endpoint at `/metrics` (port 9101). The `NETWORK_HANDLER_TIMER` metric includes a `node_addr` label that contains complete SocketAddr information (IP:port) used for validator-to-validator communication in the safety-rules component, potentially enabling network reconnaissance attacks.

## Finding Description

The vulnerability exists in the metrics collection system used by the `secure-net` networking layer, which handles communication between validator consensus components. When the `NETWORK_HANDLER_TIMER` histogram metric is created, it uses the raw SocketAddr (IP address and port) as a label dimension without any sanitization or redaction. [1](#0-0) 

This metric is then populated with the actual node addresses in two locations:

1. In the gRPC network service inbound message handler: [2](#0-1) 

2. In the outbound message handler: [3](#0-2) 

These metrics are collected by the Prometheus gathering system and exposed through the inspection service's `/metrics` endpoint: [4](#0-3) 

The inspection service is configured by default to listen on all network interfaces (0.0.0.0): [5](#0-4) 

The secure-net library is used specifically for validator communication in the consensus safety-rules component: [6](#0-5) 

An attacker who can reach the inspection service endpoint can query the metrics and extract internal IP addresses and ports used by validators for consensus communication.

## Impact Explanation

This vulnerability is classified as **Low to Medium severity** based on the Aptos bug bounty criteria:

- **Low Severity criteria**: "Minor information leaks" (up to $1,000)
- **Medium Severity criteria**: "State inconsistencies requiring intervention" (up to $10,000)

For validators specifically, this information leakage has elevated impact because:

1. **Network Reconnaissance**: Exposes internal network topology and private IP addressing schemes used by validators
2. **Targeted Attack Surface**: Provides attackers with exact IP:port combinations to target for network-level attacks
3. **Infrastructure Fingerprinting**: Reveals which validators are using specific network configurations
4. **Operational Security Violation**: Contradicts security best practices for production blockchain infrastructure

While this does not directly compromise consensus safety, fund security, or cause immediate harm, it provides valuable reconnaissance information that could facilitate more sophisticated attacks if combined with other vulnerabilities.

## Likelihood Explanation

**Likelihood: HIGH**

This issue affects all validator nodes that:
1. Use the default inspection service configuration (listens on 0.0.0.0:9101)
2. Run the safety-rules component with remote service mode
3. Do not have external firewall rules blocking port 9101

The exploitation is trivial:
- No authentication required
- No special tools needed (simple HTTP GET request)
- Information is automatically collected and exposed
- Works against any validator with accessible metrics endpoint

The only mitigation would be network-level access controls (firewalls), which are not enforced by the Aptos node software itself.

## Recommendation

Implement metric label sanitization to prevent sensitive network information from being exposed. There are several approaches:

**Option 1: Redact IP addresses in metric labels**
```rust
pub static NETWORK_HANDLER_TIMER: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "network_handler_timer",
        "The time spent in processing messages",
        &["node_type", "name"], // Remove node_addr, add node_type instead
        exponential_buckets(/*start=*/ 1e-3, /*factor=*/ 2.0, /*count=*/ 20).unwrap(),
    )
    .unwrap()
});

// Use a generic label like "validator" or "remote" instead of IP address
_timer = NETWORK_HANDLER_TIMER
    .with_label_values(&["validator", "inbound_msgs"])
    .start_timer();
```

**Option 2: Use hashed or anonymized identifiers**
```rust
use sha2::{Sha256, Digest};

fn anonymize_address(addr: &SocketAddr) -> String {
    let mut hasher = Sha256::new();
    hasher.update(addr.to_string().as_bytes());
    format!("{:x}", hasher.finalize())[..8].to_string()
}

_timer = NETWORK_HANDLER_TIMER
    .with_label_values(&[&anonymize_address(&socket_addr), "outbound_msgs"])
    .start_timer();
```

**Option 3: Add access controls to inspection service**
Implement authentication for the `/metrics` endpoint or restrict it to internal monitoring systems only. Update the default configuration to listen on localhost (127.0.0.1) instead of all interfaces (0.0.0.0):

```rust
fn default() -> InspectionServiceConfig {
    InspectionServiceConfig {
        address: "127.0.0.1".to_string(), // Changed from "0.0.0.0"
        port: 9101,
        expose_configuration: false,
        expose_identity_information: true,
        expose_peer_information: true,
        expose_system_information: true,
    }
}
```

## Proof of Concept

**Step 1: Start an Aptos validator node with default configuration**

```bash
# Run an Aptos node with default inspection service settings
cargo run -p aptos-node -- --config validator.yaml
```

**Step 2: Query the metrics endpoint**

```bash
# From any machine that can reach the validator
curl http://<validator-ip>:9101/metrics | grep network_handler_timer
```

**Expected output showing IP address leakage:**
```
network_handler_timer_seconds_bucket{node_addr="10.0.1.5:6180",name="inbound_msgs",le="0.001"} 0
network_handler_timer_seconds_bucket{node_addr="10.0.1.5:6180",name="outbound_msgs",le="0.001"} 0
network_handler_timer_seconds_bucket{node_addr="192.168.1.10:6180",name="inbound_msgs",le="0.002"} 5
```

The output reveals the internal IP addresses (10.0.1.5, 192.168.1.10) and ports (6180) used for validator communication.

**Rust test to verify metric label exposure:**

```rust
#[cfg(test)]
mod test_metric_exposure {
    use super::*;
    use prometheus::Encoder;
    
    #[test]
    fn test_network_handler_timer_exposes_addresses() {
        let test_addr = "10.0.1.5:6180";
        let timer = NETWORK_HANDLER_TIMER
            .with_label_values(&[test_addr, "test"])
            .start_timer();
        drop(timer);
        
        // Gather metrics
        let encoder = prometheus::TextEncoder::new();
        let metric_families = prometheus::gather();
        let mut buffer = vec![];
        encoder.encode(&metric_families, &mut buffer).unwrap();
        let output = String::from_utf8(buffer).unwrap();
        
        // Verify that the IP address is exposed in the output
        assert!(output.contains("10.0.1.5:6180"));
    }
}
```

## Notes

This vulnerability is specifically relevant to validator nodes running in production environments where network topology information should be protected. While the inspection service is designed for debugging and monitoring, the default configuration makes it accessible from any network interface, which is inappropriate for sensitive validator infrastructure.

Operators should immediately:
1. Configure firewall rules to restrict access to port 9101 to trusted monitoring systems only
2. Consider changing the inspection service address to 127.0.0.1 in production deployments
3. Review all exposed metrics for similar information leakage issues

### Citations

**File:** secure/net/src/network_controller/metrics.rs (L7-20)
```rust
pub static NETWORK_HANDLER_TIMER: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        // metric name
        "network_handler_timer",
        // metric description
        "The time spent in processing: \
         1. outbound_msgs: sending messages to remote nodes; \
         2. inbound_msgs: routing inbound messages to respective handlers;",
        // metric labels (dimensions)
        &["node_addr", "name"],
        exponential_buckets(/*start=*/ 1e-3, /*factor=*/ 2.0, /*count=*/ 20).unwrap(),
    )
    .unwrap()
});
```

**File:** secure/net/src/grpc_network_service/mod.rs (L97-99)
```rust
        let _timer = NETWORK_HANDLER_TIMER
            .with_label_values(&[&self.self_addr.to_string(), "inbound_msgs"])
            .start_timer();
```

**File:** secure/net/src/network_controller/outbound_handler.rs (L120-122)
```rust
                _timer = NETWORK_HANDLER_TIMER
                    .with_label_values(&[&socket_addr.to_string(), "outbound_msgs"])
                    .start_timer();
```

**File:** crates/aptos-inspection-service/src/server/mod.rs (L142-146)
```rust
        METRICS_PATH => {
            // /metrics
            // Exposes text encoded metrics
            metrics::handle_metrics_request()
        },
```

**File:** config/src/config/inspection_service_config.rs (L26-37)
```rust
impl Default for InspectionServiceConfig {
    fn default() -> InspectionServiceConfig {
        InspectionServiceConfig {
            address: "0.0.0.0".to_string(),
            port: 9101,
            expose_configuration: false,
            expose_identity_information: true,
            expose_peer_information: true,
            expose_system_information: true,
        }
    }
}
```

**File:** consensus/safety-rules/src/remote_service.rs (L30-44)
```rust
pub fn execute(storage: PersistentSafetyStorage, listen_addr: SocketAddr, network_timeout_ms: u64) {
    let mut safety_rules = SafetyRules::new(storage, false);
    if let Err(e) = safety_rules.consensus_state() {
        warn!("Unable to print consensus state: {}", e);
    }

    let mut serializer_service = SerializerService::new(safety_rules);
    let mut network_server =
        NetworkServer::new("safety-rules".to_string(), listen_addr, network_timeout_ms);

    loop {
        if let Err(e) = process_one_message(&mut network_server, &mut serializer_service) {
            warn!("Failed to process message: {}", e);
        }
    }
```
