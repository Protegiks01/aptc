# Audit Report

## Title
Lack of IP-Based Access Control in Aptos Inspection Service Exposes Sensitive Node Information

## Summary
The Aptos Inspection Service (`aptos-inspection-service`) lacks application-layer IP-based access control (both allowlisting and denylisting). While HAProxy configurations provide reactive IP denylisting, the service itself accepts connections from any IP address when deployed without proper network-level protections, exposing sensitive operational data that could aid attackers in reconnaissance and targeted attacks.

## Finding Description

The inspection service binds to `0.0.0.0:9101` by default and serves multiple endpoints exposing sensitive node information without any IP-based access control at the application layer. [1](#0-0) 

The service handler ignores the connection parameter (`_conn`) which would contain the remote IP address, making no attempt to validate or restrict access based on source IP: [2](#0-1) 

Sensitive endpoints exposed without IP restrictions include:
- `/peer_information` - Exposes detailed peer connection metadata, state sync data, internal client states
- `/identity_information` - Reveals peer IDs and network identities
- `/configuration` - Exposes full node configuration (when enabled)
- `/metrics`, `/json_metrics`, `/forge_metrics` - Internal performance metrics
- `/consensus_health_check` - Consensus execution state
- `/system_information` - System and build information [3](#0-2) 

While configuration flags exist to disable specific endpoints, these flags control WHAT is exposed, not WHO can access it: [4](#0-3) 

HAProxy configurations provide only reactive denylisting (blocking known malicious IPs), not proactive allowlisting (permitting only trusted monitoring systems): [5](#0-4) [6](#0-5) 

Notably, the codebase already contains infrastructure for IP allowlisting in the faucet service that could be adapted: [7](#0-6) [8](#0-7) 

## Impact Explanation

This issue falls under **Low to Medium Severity** per the Aptos bug bounty criteria. While it does not directly cause consensus violations, funds loss, or network outages, it represents a **defense-in-depth failure** and **information disclosure vulnerability** that could enable higher-severity attacks:

1. **Reconnaissance Enablement**: Attackers can gather detailed intelligence about validator/node topology, peer connections, and network configuration to plan targeted attacks
2. **Timing Attack Facilitation**: Consensus health check exposure reveals optimal attack windows
3. **Peer Targeting**: Connection metadata enables focused DoS attacks on specific network peers
4. **Configuration Leakage**: When misconfigured, full node configuration exposure (even with secrets filtered) reveals deployment patterns

However, this does not directly meet Critical or High severity criteria as defined:
- No direct funds loss or consensus violation
- No validator slowdowns or API crashes from the information disclosure itself
- Requires additional attack steps to convert reconnaissance into actual harm

The issue qualifies as **Medium Severity** due to the sensitive operational data exposure that significantly aids attackers, though it requires proper network-level mitigation failures to be exploitable.

## Likelihood Explanation

**Likelihood: Medium to High** in misconfigured deployments:

1. **Deployment-Dependent**: Nodes behind proper firewalls/security groups are protected at the network layer
2. **Default Configuration Risk**: Service binds to `0.0.0.0` by default, accepting all connections
3. **HAProxy Limitations**: Only reactive denylisting is configured, not proactive allowlisting
4. **Common Misconfiguration**: Many operators may rely solely on configuration flags rather than defense-in-depth
5. **No Application-Layer Enforcement**: Even with HAProxy, the application lacks its own access control layer

The service is started unconditionally on all nodes: [9](#0-8) 

## Recommendation

Implement application-layer IP allowlisting for the inspection service using the existing `IpRangeManager` pattern from the faucet service:

1. **Add IP allowlist configuration** to `InspectionServiceConfig`:
```rust
pub struct InspectionServiceConfig {
    pub address: String,
    pub port: u16,
    pub expose_configuration: bool,
    pub expose_identity_information: bool,
    pub expose_peer_information: bool,
    pub expose_system_information: bool,
    // NEW: IP allowlist configuration
    pub allowed_ips: Option<PathBuf>, // Path to file with allowed IP ranges
}
```

2. **Extract client IP from connection** in `start_inspection_service`:
```rust
let make_service = make_service_fn(move |conn: &AddrStream| {
    let remote_addr = conn.remote_addr().ip();
    let node_config = node_config.clone();
    // ... pass remote_addr to serve_requests
});
```

3. **Validate IP in `serve_requests`** before processing:
```rust
async fn serve_requests(
    req: Request<Body>,
    node_config: NodeConfig,
    remote_addr: IpAddr,
    // ... other params
) -> Result<Response<Body>, hyper::Error> {
    // Check IP allowlist if configured
    if let Some(allowed_ips) = &node_config.inspection_service.allowed_ips {
        let ip_manager = IpRangeManager::new(IpRangeManagerConfig { 
            file: allowed_ips.clone() 
        })?;
        if !ip_manager.contains_ip(&remote_addr) {
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from("IP not allowed"))
                .unwrap());
        }
    }
    // ... existing endpoint routing
}
```

4. **Document deployment best practices** requiring IP allowlisting for production validators.

## Proof of Concept

**Reconnaissance Attack Scenario:**

```bash
# Attacker discovers exposed inspection service on validator
# (assumes no network firewall or misconfigured HAProxy)

# Step 1: Enumerate available endpoints
curl http://validator-ip:9101/

# Step 2: Gather peer topology information
curl http://validator-ip:9101/peer_information
# Output reveals:
# - All connected peer IDs and network IDs
# - Connection states and metadata
# - Trusted validator set information
# - State sync peer priorities
# - Request/response statistics per peer

# Step 3: Monitor consensus health
curl http://validator-ip:9101/consensus_health_check
# Output reveals if validator is actively participating in consensus

# Step 4: Extract system information
curl http://validator-ip:9101/system_information
# Output reveals build version, OS, hardware specs

# Step 5: Attempt configuration exposure (if misconfigured)
curl http://validator-ip:9101/configuration
# May reveal deployment configuration details

# Attacker now has:
# - Complete network topology
# - Optimal attack timing (consensus health)
# - Target peer information for focused attacks
# - System fingerprinting for exploit targeting
```

**Test Setup (Rust):**
```rust
// In a test environment, demonstrate that any IP can access the service
#[tokio::test]
async fn test_no_ip_restrictions() {
    // Start inspection service with default config
    let node_config = NodeConfig::default();
    // Service binds to 0.0.0.0:9101
    
    // Make requests from any IP (simulated)
    let client = reqwest::Client::new();
    let resp = client.get("http://127.0.0.1:9101/peer_information")
        .send()
        .await
        .unwrap();
    
    // Succeeds regardless of source IP - no access control
    assert_eq!(resp.status(), 200);
    
    // Sensitive information is accessible
    let body = resp.text().await.unwrap();
    assert!(body.contains("Peer information"));
}
```

## Notes

This finding represents a **defense-in-depth violation** rather than a directly exploitable consensus or funds-loss vulnerability. While the information disclosure itself is Low-Medium severity, it significantly increases the attack surface by providing reconnaissance data that enables more sophisticated attacks.

The issue is particularly concerning for validators where operational security requires strict access control to monitoring interfaces. The absence of application-layer IP validation means operators must rely entirely on network-level controls, violating security best practices that recommend multiple layers of defense.

The codebase demonstrates awareness of IP-based access control through the faucet service implementation, making the absence in the inspection service a notable gap in the security architecture.

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

**File:** crates/aptos-inspection-service/src/server/mod.rs (L104-109)
```rust
async fn serve_requests(
    req: Request<Body>,
    node_config: NodeConfig,
    aptos_data_client: AptosDataClient,
    peers_and_metadata: Arc<PeersAndMetadata>,
) -> Result<Response<Body>, hyper::Error> {
```

**File:** crates/aptos-inspection-service/src/server/mod.rs (L111-169)
```rust
    let (status_code, body, content_type) = match req.uri().path() {
        CONFIGURATION_PATH => {
            // /configuration
            // Exposes the node configuration
            configuration::handle_configuration_request(&node_config)
        },
        CONSENSUS_HEALTH_CHECK_PATH => {
            // /consensus_health_check
            // Exposes the consensus health check
            metrics::handle_consensus_health_check(&node_config).await
        },
        FORGE_METRICS_PATH => {
            // /forge_metrics
            // Exposes forge encoded metrics
            metrics::handle_forge_metrics()
        },
        IDENTITY_INFORMATION_PATH => {
            // /identity_information
            // Exposes the identity information of the node
            identity_information::handle_identity_information_request(&node_config)
        },
        INDEX_PATH => {
            // /
            // Exposes the index and list of available endpoints
            index::handle_index_request()
        },
        JSON_METRICS_PATH => {
            // /json_metrics
            // Exposes JSON encoded metrics
            metrics::handle_json_metrics_request()
        },
        METRICS_PATH => {
            // /metrics
            // Exposes text encoded metrics
            metrics::handle_metrics_request()
        },
        PEER_INFORMATION_PATH => {
            // /peer_information
            // Exposes the peer information
            peer_information::handle_peer_information_request(
                &node_config,
                aptos_data_client,
                peers_and_metadata,
            )
        },
        SYSTEM_INFORMATION_PATH => {
            // /system_information
            // Exposes the system and build information
            system_information::handle_system_information_request(node_config)
        },
        _ => {
            // Handle the invalid path
            (
                StatusCode::NOT_FOUND,
                Body::from(INVALID_ENDPOINT_MESSAGE),
                CONTENT_TYPE_TEXT.into(),
            )
        },
    };
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

**File:** docker/compose/aptos-node/haproxy-fullnode.cfg (L87-88)
```text
    # Deny requests from blocked IPs
    tcp-request connection reject if { src -n -f /usr/local/etc/haproxy/blocked.ips }
```

**File:** terraform/helm/aptos-node/files/haproxy.cfg (L99-100)
```text
    # Deny requests from blocked IPs
    tcp-request connection reject if { src -n -f /usr/local/etc/haproxy/blocked.ips }
```

**File:** crates/aptos-faucet/core/src/common/ip_range_manager.rs (L23-53)
```rust
impl IpRangeManager {
    pub fn new(config: IpRangeManagerConfig) -> Result<Self> {
        let file = File::open(&config.file)
            .with_context(|| format!("Failed to open {}", config.file.to_string_lossy()))?;

        let mut ipv4_list = IpRange::<Ipv4Net>::new();
        let mut ipv6_list = IpRange::<Ipv6Net>::new();
        for line in std::io::BufReader::new(file).lines() {
            let line = line?;
            if line.starts_with('#') || line.starts_with("//") || line.is_empty() {
                continue;
            }
            match line.parse::<Ipv4Net>() {
                Ok(ipv4_net) => {
                    ipv4_list.add(ipv4_net);
                },
                Err(_) => match line.parse::<Ipv6Net>() {
                    Ok(ipv6_net) => {
                        ipv6_list.add(ipv6_net);
                    },
                    Err(_) => {
                        bail!("Failed to parse line as IPv4 or IPv6 range: {}", line);
                    },
                },
            }
        }
        Ok(Self {
            ipv4_list,
            ipv6_list,
        })
    }
```

**File:** crates/aptos-faucet/core/src/bypasser/ip_allowlist.rs (L12-29)
```rust
pub struct IpAllowlistBypasser {
    manager: IpRangeManager,
}

impl IpAllowlistBypasser {
    pub fn new(config: IpRangeManagerConfig) -> Result<Self> {
        Ok(Self {
            manager: IpRangeManager::new(config)?,
        })
    }
}

#[async_trait]
impl BypasserTrait for IpAllowlistBypasser {
    async fn request_can_bypass(&self, data: CheckerData) -> Result<bool> {
        Ok(self.manager.contains_ip(&data.source_ip))
    }
}
```

**File:** aptos-node/src/lib.rs (L771-776)
```rust
    // Start the node inspection service
    services::start_node_inspection_service(
        &node_config,
        aptos_data_client,
        peers_and_metadata.clone(),
    );
```
