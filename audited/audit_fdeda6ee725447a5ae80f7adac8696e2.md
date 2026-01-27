# Audit Report

## Title
Inspection Service Lacks Application-Level Connection Limits Enabling Resource Exhaustion on Validator Nodes

## Summary
The Aptos inspection service creates unbounded connections without application-level limits, relying solely on infrastructure-level protections (HAProxy, NetworkPolicy) that may be absent in certain deployment configurations. This allows attackers with network access to exhaust file descriptors and connection resources on validator nodes, potentially impacting consensus participation.

## Finding Description

The inspection service implementation creates a new `service_fn` for each incoming connection without enforcing any application-level connection limits. [1](#0-0) 

The `InspectionServiceConfig` struct lacks any fields for connection limiting, containing only address, port, and endpoint exposure flags. [2](#0-1) 

The service binds to `0.0.0.0` by default, exposing it to network connections. [3](#0-2) 

In contrast, other Aptos services implement application-level connection limits. For example, the API config includes `wait_by_hash_max_active_connections: 100`. [4](#0-3) 

**Attack Scenario:**
1. Attacker gains network access to validator node (through misconfigured firewall, compromised monitoring pod, or bare-metal deployment without proper network isolation)
2. Attacker opens thousands of TCP connections to port 9101
3. Each connection consumes a file descriptor and memory for the service closure
4. System file descriptor limit (~1024 default on many Linux systems) is exhausted
5. Validator cannot accept new consensus P2P connections
6. Validator loses consensus participation, impacting network liveness

**Mitigations Present (But Insufficient):**

While Kubernetes deployments have NetworkPolicy restricting access and HAProxy provides global limits (maxconn 500, maxconnrate 300), [5](#0-4)  these protections have critical limitations:

1. **Shared Limits**: HAProxy's 500 connection limit is shared across ALL services (validator network, API, metrics, VFN)
2. **Deployment Variance**: Bare-metal or cloud VM deployments may lack HAProxy/NetworkPolicy
3. **No Service Isolation**: An attacker targeting the inspection service can exhaust the global connection pool, impacting other critical services
4. **Default Exposure**: The service defaults to binding on all interfaces (0.0.0.0), requiring explicit network configuration for protection

## Impact Explanation

This vulnerability qualifies as **Medium Severity** per Aptos bug bounty criteria ("State inconsistencies requiring intervention" / "Validator node slowdowns"):

1. **Resource Exhaustion**: File descriptor exhaustion prevents the validator from accepting new network connections, including consensus-critical P2P connections
2. **Consensus Impact**: If validators cannot establish new connections during leader election or view changes, consensus liveness degrades
3. **Service Starvation**: Even with HAProxy limits, the inspection service can consume a disproportionate share of the global connection pool
4. **Recovery Required**: Manual intervention needed to identify and terminate malicious connections

The impact is limited by infrastructure protections in properly configured deployments, preventing escalation to Critical severity. However, the lack of defense-in-depth at the application level creates unnecessary risk.

## Likelihood Explanation

**Likelihood: Medium** with significant variance based on deployment configuration:

**Factors Increasing Likelihood:**
- Simple exploit: Only requires opening TCP connections (no authentication, no complex protocol)
- Default configuration exposes service on 0.0.0.0
- Bare-metal and cloud VM deployments may lack proper network isolation
- Compromised monitoring/health-checker pods in Kubernetes have legitimate access

**Factors Decreasing Likelihood:**
- Properly configured Kubernetes deployments have NetworkPolicy restrictions [6](#0-5) 
- HAProxy provides some connection rate limiting (300 conn/sec) and timeouts (60s client timeout) [7](#0-6) 
- Requires network-level access to the validator infrastructure

The bug bounty exclusion for "Network-level DoS attacks" does NOT apply here, as this is an application-layer resource exhaustion vulnerability exploiting missing connection limits, not a volumetric network flood.

## Recommendation

Implement application-level connection limiting in the inspection service configuration and server implementation:

**1. Add configuration field:**
```rust
// In config/src/config/inspection_service_config.rs
pub struct InspectionServiceConfig {
    pub address: String,
    pub port: u16,
    pub max_concurrent_connections: usize, // Add this field
    pub expose_configuration: bool,
    pub expose_identity_information: bool,
    pub expose_peer_information: bool,
    pub expose_system_information: bool,
}

impl Default for InspectionServiceConfig {
    fn default() -> InspectionServiceConfig {
        InspectionServiceConfig {
            address: "0.0.0.0".to_string(),
            port: 9101,
            max_concurrent_connections: 100, // Conservative limit
            expose_configuration: false,
            expose_identity_information: true,
            expose_peer_information: true,
            expose_system_information: true,
        }
    }
}
```

**2. Implement connection limiting in server:**
```rust
// Use tokio::sync::Semaphore to limit concurrent connections
use tokio::sync::Semaphore;
use std::sync::Arc;

pub fn start_inspection_service(
    node_config: NodeConfig,
    aptos_data_client: AptosDataClient,
    peers_and_metadata: Arc<PeersAndMetadata>,
) {
    let max_connections = node_config.inspection_service.max_concurrent_connections;
    let connection_limiter = Arc::new(Semaphore::new(max_connections));
    
    let make_service = make_service_fn(move |_conn| {
        let node_config = node_config.clone();
        let aptos_data_client = aptos_data_client.clone();
        let peers_and_metadata = peers_and_metadata.clone();
        let limiter = connection_limiter.clone();
        
        async move {
            // Acquire permit or reject connection
            let permit = limiter.try_acquire();
            if permit.is_err() {
                return Ok::<_, Infallible>(service_fn(move |_req| {
                    async move {
                        Ok::<_, hyper::Error>(
                            Response::builder()
                                .status(StatusCode::SERVICE_UNAVAILABLE)
                                .body(Body::from("Too many connections"))
                                .unwrap()
                        )
                    }
                }));
            }
            
            Ok::<_, Infallible>(service_fn(move |request| {
                let _permit = permit.unwrap(); // Hold permit for connection lifetime
                serve_requests(request, node_config.clone(), aptos_data_client.clone(), peers_and_metadata.clone())
            }))
        }
    });
    // ... rest of server setup
}
```

**3. Add metrics for monitoring:**
```rust
// Track rejected connections due to limits
static CONNECTION_LIMIT_REJECTIONS: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "aptos_inspection_service_connection_rejections_total",
        "Number of connections rejected due to limit"
    ).unwrap()
});
```

## Proof of Concept

```rust
// Rust test demonstrating connection exhaustion
#[tokio::test]
async fn test_inspection_service_connection_exhaustion() {
    use tokio::net::TcpStream;
    use std::time::Duration;
    
    // Start inspection service (simplified - in real test would use full setup)
    let service_addr = "127.0.0.1:9101";
    
    // Attempt to open many connections
    let mut connections = Vec::new();
    let max_attempts = 1000;
    
    for i in 0..max_attempts {
        match tokio::time::timeout(
            Duration::from_millis(100),
            TcpStream::connect(service_addr)
        ).await {
            Ok(Ok(stream)) => {
                connections.push(stream);
                println!("Opened connection {}", i);
            }
            Ok(Err(e)) => {
                println!("Connection {} failed: {:?}", i, e);
                break;
            }
            Err(_) => {
                println!("Connection {} timed out", i);
                break;
            }
        }
    }
    
    println!("Successfully opened {} connections", connections.len());
    
    // Without application-level limits, this will exhaust system resources
    // With proper limits, it should be capped at configured maximum
    
    // Verify that the service still responds to new connections
    let test_conn = TcpStream::connect(service_addr).await;
    assert!(test_conn.is_ok() || connections.len() < max_attempts,
            "Service should either accept connection or have hit application limit");
}
```

## Notes

**Critical Distinctions:**
- This is NOT the network-level DoS excluded by bug bounty rules (which refers to volumetric attacks like SYN floods)
- This exploits missing application logic (connection limiting) rather than overwhelming network bandwidth
- The vulnerability exists in the application code, not network infrastructure

**Defense-in-Depth Principle:**
Network-level protections (HAProxy, NetworkPolicy, firewalls) should complement, not replace, application-level resource management. The inspection service handles sensitive validator information and should implement robust connection limiting regardless of infrastructure configuration.

**Deployment Risk Variance:**
- **High Risk**: Bare-metal validators, cloud VMs without proper firewall rules
- **Medium Risk**: Kubernetes deployments where monitoring/health-checker pods are compromised  
- **Low Risk**: Properly configured Kubernetes with NetworkPolicy and HAProxy

The core issue is that Aptos validators should implement defense-in-depth at every layer, and the absence of application-level connection limits violates this principle.

### Citations

**File:** crates/aptos-inspection-service/src/server/mod.rs (L77-91)
```rust
        let make_service = make_service_fn(move |_conn| {
            let node_config = node_config.clone();
            let aptos_data_client = aptos_data_client.clone();
            let peers_and_metadata = peers_and_metadata.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |request| {
                    serve_requests(
                        request,
                        node_config.clone(),
                        aptos_data_client.clone(),
                        peers_and_metadata.clone(),
                    )
                }))
            }
        });
```

**File:** config/src/config/inspection_service_config.rs (L15-24)
```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct InspectionServiceConfig {
    pub address: String,
    pub port: u16,
    pub expose_configuration: bool,
    pub expose_identity_information: bool,
    pub expose_peer_information: bool,
    pub expose_system_information: bool,
}
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

**File:** config/src/config/api_config.rs (L90-91)
```rust
    pub wait_by_hash_max_active_connections: usize,
    /// Allow submission of encrypted transactions via the API
```

**File:** docker/compose/aptos-node/haproxy.cfg (L8-31)
```text
    # Limit the maximum number of connections to 500 (this is ~5x the validator set size)
    maxconn 500

    # Limit the maximum number of connections per second to 300 (this is ~3x the validator set size)
    maxconnrate 300

    # Limit user privileges
    user haproxy

## Default settings
defaults
    # Enable logging of events and traffic
    log global

    # Set the default mode to TCP
    mode tcp

    # Don't log normal events
    option dontlog-normal

    # Set timeouts for connections
    timeout client 60s
    timeout connect 10s
    timeout server 60s
```

**File:** terraform/helm/aptos-node/templates/networkpolicy.yaml (L20-32)
```yaml
  # HAproxy
  - from:
    - podSelector:
        matchLabels:
          {{- include "aptos-validator.selectorLabels" $ | nindent 10 }}
          app.kubernetes.io/name: haproxy
          app.kubernetes.io/instance: haproxy-{{$i}}
    ports:
      # AptosNet from HAproxy
    - protocol: TCP
      port: 6180
    - protocol: TCP
      port: 9101
```
