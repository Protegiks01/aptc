# Audit Report

## Title
Information Disclosure via HTTP Status Code Fingerprinting in Consensus Health Check Endpoint

## Summary
The `/consensus_health_check` endpoint in the Aptos Inspection Service returns different HTTP status codes based on whether a node is a validator or not (400 vs 500/200), allowing attackers to fingerprint validator nodes even when the configuration endpoint is disabled. This bypasses the intended security control that prevents mainnet validators from exposing node configuration information.

## Finding Description
The `handle_consensus_health_check()` function returns distinct HTTP status codes that reveal node type information: [1](#0-0) 

For non-validator nodes, the endpoint returns `400 BAD_REQUEST` with the message "This node is not a validator!". [2](#0-1) 

For validator nodes with consensus issues, it returns `500 INTERNAL_SERVER_ERROR`.

This endpoint has no disable flag in the configuration, unlike other sensitive endpoints: [3](#0-2) 

Notice there is no `expose_consensus_health_check` flag, meaning this endpoint is always enabled when the inspection service runs.

The inspection service sanitizer explicitly prevents mainnet validators from exposing configuration: [4](#0-3) 

However, the consensus health check endpoint bypasses this protection by leaking the same node role information through status code differences.

The inspection service binds to `0.0.0.0:9101` by default: [5](#0-4) 

Making it accessible from the network unless explicitly firewalled.

## Impact Explanation
This is a **Low Severity** vulnerability per Aptos bug bounty criteria (minor information leak). The security impact includes:

1. **Bypasses Security Controls**: Operators who disable `expose_configuration` to hide node information have that protection circumvented
2. **Validator Enumeration**: Attackers can systematically identify all validators in the network
3. **Targeted Attack Surface**: Once validators are identified, they become targets for:
   - Focused DDoS attacks on consensus-critical nodes
   - Social engineering targeting validator operators
   - Network-level reconnaissance for more sophisticated attacks

The information leaked (node type) is not directly exploitable for fund theft or consensus violations, but it enables reconnaissance that could facilitate more serious attacks.

## Likelihood Explanation
**Very High Likelihood**: This vulnerability is trivially exploitable:
- Requires only a simple HTTP GET request
- No authentication needed
- Works on default configuration
- Cannot be disabled without shutting down the entire inspection service
- Attackers can automate validator discovery across the network

Any adversary with network connectivity to port 9101 can exploit this immediately.

## Recommendation
Add a configuration flag to disable the consensus health check endpoint, similar to other sensitive endpoints. Return a uniform status code for both validators and non-validators when checks fail:

```rust
// In config/src/config/inspection_service_config.rs
pub struct InspectionServiceConfig {
    pub address: String,
    pub port: u16,
    pub expose_configuration: bool,
    pub expose_consensus_health_check: bool,  // ADD THIS
    pub expose_identity_information: bool,
    pub expose_peer_information: bool,
    pub expose_system_information: bool,
}

// In crates/aptos-inspection-service/src/server/metrics.rs
pub async fn handle_consensus_health_check(node_config: &NodeConfig) -> (StatusCode, Body, String) {
    // Check if endpoint is enabled
    if !node_config.inspection_service.expose_consensus_health_check {
        return (
            StatusCode::FORBIDDEN,
            Body::from("This endpoint is disabled!"),
            CONTENT_TYPE_TEXT.into(),
        );
    }
    
    // Return uniform status code for failures regardless of node type
    if !node_config.base.role.is_validator() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,  // Changed from BAD_REQUEST
            Body::from("Consensus health check not available"),
            CONTENT_TYPE_TEXT.into(),
        );
    }
    
    // ... rest of implementation
}
```

Default `expose_consensus_health_check` to `false` for mainnet validators in the sanitizer.

## Proof of Concept

```rust
#[tokio::test]
async fn test_consensus_health_check_fingerprinting() {
    // Create a validator node config
    let validator_config = NodeConfig::get_default_validator_config();
    
    // Create a fullnode config
    let mut fullnode_config = NodeConfig::get_default_pfn_config();
    
    // Disable configuration endpoint for both
    validator_config.inspection_service.expose_configuration = false;
    fullnode_config.inspection_service.expose_configuration = false;
    
    // Send health check requests
    let validator_response = send_get_request_to_path(
        &validator_config, 
        "/consensus_health_check"
    ).await;
    let fullnode_response = send_get_request_to_path(
        &fullnode_config, 
        "/consensus_health_check"
    ).await;
    
    // Demonstrate fingerprinting via status code difference
    assert_eq!(fullnode_response.status(), StatusCode::BAD_REQUEST);
    assert_ne!(validator_response.status(), StatusCode::BAD_REQUEST);
    
    // Attacker can now distinguish validators from fullnodes
    // even though configuration endpoint is disabled
}
```

## Notes
While this is a Low severity information disclosure issue, it represents a genuine security vulnerability because it explicitly bypasses the intended security control (disabled configuration endpoint) that Aptos has implemented for mainnet validators. The impact is limited but the exploitability is trivial.

### Citations

**File:** crates/aptos-inspection-service/src/server/metrics.rs (L20-28)
```rust
pub async fn handle_consensus_health_check(node_config: &NodeConfig) -> (StatusCode, Body, String) {
    // Verify the node is a validator. If not, return an error.
    if !node_config.base.role.is_validator() {
        return (
            StatusCode::BAD_REQUEST,
            Body::from("This node is not a validator!"),
            CONTENT_TYPE_TEXT.into(),
        );
    }
```

**File:** crates/aptos-inspection-service/src/server/metrics.rs (L42-47)
```rust
    // Otherwise, consensus is not executing
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Body::from("Consensus health check failed! Consensus is not executing!"),
        CONTENT_TYPE_TEXT.into(),
    )
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

**File:** config/src/config/inspection_service_config.rs (L26-36)
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
```

**File:** config/src/config/inspection_service_config.rs (L54-65)
```rust
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
```
