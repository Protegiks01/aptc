# Audit Report

## Title
Inspection Service Binds to All Network Interfaces Without Security Warning, Enabling Unintended Public Exposure

## Summary
The Aptos inspection service defaults to binding on `0.0.0.0:9101` (all network interfaces) without any configuration validation, sanitizer checks, or explicit documentation warning operators about the security implications for production deployments. [1](#0-0)  Operators deploying nodes outside of the provided docker-compose or helm configurations can unknowingly expose sensitive debugging endpoints to the internet, enabling reconnaissance attacks and information disclosure.

## Finding Description
The `InspectionServiceConfig` struct defines the configuration for the node inspection service, which exposes multiple HTTP endpoints for debugging and monitoring. The default configuration binds to all network interfaces: [1](#0-0) 

The inspection service exposes multiple endpoints that reveal operational information:
- `/metrics` - Prometheus metrics (always accessible)
- `/peer_information` - Detailed peer connection metadata, internal client states, and network topology [2](#0-1) 
- `/identity_information` - Peer IDs and network identities [3](#0-2) 
- `/system_information` - System and build information [4](#0-3) 
- `/configuration` - Full node configuration (if enabled) [5](#0-4) 

The service starts by binding to the configured address and port: [6](#0-5) 

While the `ConfigSanitizer` implementation checks whether mainnet validators expose the configuration endpoint, it **does not validate the bind address**: [7](#0-6) 

Reference deployment configurations (docker-compose and helm) correctly restrict access by binding the exposed port to `127.0.0.1` at the orchestration layer, but this protection is **not enforced by the application code**: [8](#0-7) 

**Attack Path:**
1. Operator deploys an Aptos validator or fullnode using a manual deployment method (systemd, custom container orchestration, bare metal)
2. Operator uses the default configuration or doesn't explicitly set `inspection_service.address` to `"127.0.0.1"`
3. The inspection service binds to `0.0.0.0:9101` and listens on all network interfaces
4. If firewall rules are misconfigured or absent, the service becomes accessible from the internet
5. Attacker scans and discovers the exposed port 9101
6. Attacker accesses `/metrics`, `/peer_information`, `/identity_information`, `/system_information` endpoints
7. Attacker gains detailed intelligence about:
   - Node operational metrics for DoS timing optimization
   - Complete network topology and peer relationships
   - Peer IDs for targeted network attacks
   - System and build information for vulnerability research

## Impact Explanation
This is a **Medium severity** issue based on the Aptos bug bounty program criteria for "Minor information leaks" elevated by the operational intelligence value:

1. **Information Disclosure**: Exposes sensitive operational data including network topology, peer relationships, internal metrics, and system information
2. **Reconnaissance Enablement**: Provides attackers with detailed intelligence for planning targeted attacks against the validator network
3. **DoS Attack Facilitation**: Metrics exposure reveals operational patterns that can be exploited for timing-based DoS attacks
4. **Network Mapping**: Peer information enables complete mapping of validator network relationships

While this does not directly result in funds loss or consensus violations, it significantly reduces the security posture of the network by removing operational obscurity and enabling sophisticated attack planning.

## Likelihood Explanation
**Likelihood: Medium to High**

Factors increasing likelihood:
- The default configuration uses `0.0.0.0` binding
- No validation warning is present in the code
- No explicit documentation warns operators about this risk
- Operators using custom deployment methods (not docker-compose/helm) are vulnerable
- Cloud deployments without proper security groups are at risk
- The service runs by default on all nodes

Mitigating factors:
- Professional deployments typically use proper firewall rules
- Reference deployment configurations show the correct pattern
- Cloud providers often have default deny-all ingress policies

However, the lack of application-level validation means operators must rely entirely on infrastructure security, with no defense-in-depth from the application itself.

## Recommendation
Implement multiple layers of protection:

**1. Add ConfigSanitizer validation for production deployments:**

```rust
impl ConfigSanitizer for InspectionServiceConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let inspection_service_config = &node_config.inspection_service;

        // Verify that mainnet validators do not expose the configuration
        if let Some(chain_id) = chain_id {
            if node_type.is_validator()
                && chain_id.is_mainnet()
                && inspection_service_config.expose_configuration
            {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "Mainnet validators should not expose the node configuration!".to_string(),
                ));
            }
            
            // NEW: Warn about binding to all interfaces on mainnet
            if chain_id.is_mainnet() 
                && (inspection_service_config.address == "0.0.0.0" 
                    || inspection_service_config.address == "::") 
            {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "Mainnet nodes should not bind inspection service to all interfaces (0.0.0.0). \
                     Use 127.0.0.1 to restrict access to localhost only. \
                     Binding to 0.0.0.0 exposes debugging endpoints to the network.".to_string(),
                ));
            }
        }

        Ok(())
    }
}
```

**2. Add inline documentation warning:**

```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct InspectionServiceConfig {
    /// Network address to bind the inspection service to.
    /// 
    /// **SECURITY WARNING**: Using "0.0.0.0" binds to all network interfaces
    /// and may expose debugging endpoints to the internet if firewall rules
    /// are not properly configured. For production deployments, use "127.0.0.1"
    /// to restrict access to localhost only.
    pub address: String,
    pub port: u16,
    // ...
}
```

**3. Change default for mainnet to localhost:**

Consider changing the default to `"127.0.0.1"` for production environments while maintaining `"0.0.0.0"` for testnet/development environments in the ConfigOptimizer.

## Proof of Concept

**Setup vulnerable node:**
1. Deploy an Aptos node with default configuration (address: "0.0.0.0")
2. Ensure port 9101 is accessible from external network

**Exploitation steps:**
```bash
# Discover exposed inspection service
nmap -p 9101 <target-ip>

# Access metrics endpoint (always available)
curl http://<target-ip>:9101/metrics

# Access peer information (if enabled - default for non-mainnet)
curl http://<target-ip>:9101/peer_information

# Access identity information (if enabled - default)
curl http://<target-ip>:9101/identity_information

# Access system information (if enabled - default)  
curl http://<target-ip>:9101/system_information

# List available endpoints
curl http://<target-ip>:9101/
```

**Expected result:** All endpoints return detailed operational data including:
- Complete Prometheus metrics revealing consensus state, block heights, network latency
- Peer network topology with connection states and peer IDs
- Node identity information
- System build information and OS details

**Validation that fix works:**
```bash
# After applying the fix, attempting to start a mainnet node with 0.0.0.0 binding should fail:
./aptos-node -f config.yaml
# Expected error: "Config sanitizer failed: Mainnet nodes should not bind inspection service to all interfaces..."
```

This demonstrates that operators can unknowingly expose sensitive debugging endpoints to the internet due to the default `0.0.0.0` binding without any application-level validation or warning.

### Citations

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

**File:** config/src/config/inspection_service_config.rs (L45-69)
```rust
impl ConfigSanitizer for InspectionServiceConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let inspection_service_config = &node_config.inspection_service;

        // Verify that mainnet validators do not expose the configuration
        if let Some(chain_id) = chain_id {
            if node_type.is_validator()
                && chain_id.is_mainnet()
                && inspection_service_config.expose_configuration
            {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "Mainnet validators should not expose the node configuration!".to_string(),
                ));
            }
        }

        Ok(())
    }
}
```

**File:** crates/aptos-inspection-service/src/server/peer_information.rs (L20-38)
```rust
/// Handles a new peer information request
pub fn handle_peer_information_request(
    node_config: &NodeConfig,
    aptos_data_client: AptosDataClient,
    peers_and_metadata: Arc<PeersAndMetadata>,
) -> (StatusCode, Body, String) {
    // Only return peer information if the endpoint is enabled
    let (status_code, body) = if node_config.inspection_service.expose_peer_information {
        let peer_information = get_peer_information(aptos_data_client, peers_and_metadata);
        (StatusCode::OK, Body::from(peer_information))
    } else {
        (
            StatusCode::FORBIDDEN,
            Body::from(PEER_INFO_DISABLED_MESSAGE),
        )
    };

    (status_code, body, CONTENT_TYPE_TEXT.into())
}
```

**File:** crates/aptos-inspection-service/src/server/identity_information.rs (L12-26)
```rust
/// Handles a new identity information request
pub fn handle_identity_information_request(node_config: &NodeConfig) -> (StatusCode, Body, String) {
    // Only return identity information if the endpoint is enabled
    let (status_code, body) = if node_config.inspection_service.expose_identity_information {
        let identity_information = get_identity_information(node_config);
        (StatusCode::OK, Body::from(identity_information))
    } else {
        (
            StatusCode::FORBIDDEN,
            Body::from(IDENTITY_INFO_DISABLED_MESSAGE),
        )
    };

    (status_code, body, CONTENT_TYPE_TEXT.into())
}
```

**File:** crates/aptos-inspection-service/src/server/system_information.rs (L14-29)
```rust
pub fn handle_system_information_request(node_config: NodeConfig) -> (StatusCode, Body, String) {
    // Only return system information if the endpoint is enabled
    if node_config.inspection_service.expose_system_information {
        (
            StatusCode::OK,
            Body::from(get_system_information_json()),
            CONTENT_TYPE_JSON.into(),
        )
    } else {
        (
            StatusCode::FORBIDDEN,
            Body::from(SYS_INFO_DISABLED_MESSAGE),
            CONTENT_TYPE_TEXT.into(),
        )
    }
}
```

**File:** crates/aptos-inspection-service/src/server/configuration.rs (L12-29)
```rust
/// Handles a new configuration request
pub fn handle_configuration_request(node_config: &NodeConfig) -> (StatusCode, Body, String) {
    // Only return configuration if the endpoint is enabled
    let (status_code, body) = if node_config.inspection_service.expose_configuration {
        // We format the configuration using debug formatting. This is important to
        // prevent secret/private keys from being serialized and leaked (i.e.,
        // all secret keys are marked with SilentDisplay and SilentDebug).
        let encoded_configuration = format!("{:?}", node_config);
        (StatusCode::OK, Body::from(encoded_configuration))
    } else {
        (
            StatusCode::FORBIDDEN,
            Body::from(CONFIGURATION_DISABLED_MESSAGE),
        )
    };

    (status_code, body, CONTENT_TYPE_TEXT.into())
}
```

**File:** crates/aptos-inspection-service/src/server/mod.rs (L55-70)
```rust
    // Fetch the service port and address
    let service_port = node_config.inspection_service.port;
    let service_address = node_config.inspection_service.address.clone();

    // Create the inspection service socket address
    let address: SocketAddr = (service_address.as_str(), service_port)
        .to_socket_addrs()
        .unwrap_or_else(|_| {
            panic!(
                "Failed to parse {}:{} as address",
                service_address, service_port
            )
        })
        .next()
        .unwrap();

```

**File:** docker/compose/aptos-node/docker-compose.yaml (L31-33)
```yaml
      # Preface these with 127 to only expose them locally
      - "127.0.0.1:9101:9101"
      - "127.0.0.1:9102:9102"
```
