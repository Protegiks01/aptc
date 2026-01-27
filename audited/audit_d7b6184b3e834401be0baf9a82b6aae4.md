# Audit Report

## Title
Unauthenticated Metrics Endpoints Enable Validator Intelligence Gathering and Targeted Attacks

## Summary
The Aptos inspection service exposes sensitive validator and consensus metrics through unauthenticated HTTP endpoints (`/json_metrics`, `/metrics`, `/forge_metrics`) without any authentication mechanism or configuration-based access controls. This allows unauthorized actors to gather critical intelligence about validator operations, consensus state, voting power distribution, and network topology, enabling sophisticated targeted attacks against the validator network.

## Finding Description

The inspection service implements inconsistent access controls across its endpoints. While endpoints exposing configuration, identity information, peer information, and system information have configurable authorization flags that can return `StatusCode::FORBIDDEN` when disabled, the metrics endpoints completely lack such protections. [1](#0-0) 

These handlers directly return all metrics without any authentication checks. The configuration structure confirms this inconsistency: [2](#0-1) 

Notice the absence of `expose_metrics`, `expose_json_metrics`, or `expose_forge_metrics` flags, unlike the protected endpoints that have corresponding flags: [3](#0-2) 

The exposed metrics contain highly sensitive consensus and validator information: [4](#0-3) [5](#0-4) [6](#0-5) 

The service binds to all network interfaces by default: [7](#0-6) 

**Attack Path:**
1. Attacker discovers an Aptos validator node's IP address (publicly available for mainnet validators)
2. Attacker sends HTTP GET request to `http://validator-ip:9101/json_metrics` or `/metrics`
3. Server returns comprehensive metrics including:
   - Voting power for all validators by peer_id (`aptos_all_validators_voting_power`)
   - Current consensus round (`aptos_consensus_current_round`)
   - Last vote epoch/round per peer (`aptos_consensus_last_voted_epoch`, `aptos_consensus_last_voted_round`)
   - Participation status per peer (`aptos_consensus_participation_status`)
   - Timeout rates, failed proposals, and performance metrics
4. Attacker correlates this data across multiple validators to build intelligence:
   - Identify high-value targets (validators with highest voting power)
   - Map network topology (peer connections and relationships)
   - Identify timing windows (current consensus round progression)
   - Detect performance weaknesses (validators with high timeout rates or slow voting)
5. Attacker uses this intelligence to execute targeted attacks:
   - Timing-synchronized DoS attacks during critical consensus rounds
   - Focused attacks on high-voting-power validators to maximize disruption
   - Exploitation of validators showing performance degradation

## Impact Explanation

This vulnerability qualifies as **HIGH severity** under the Aptos Bug Bounty program criteria for the following reasons:

1. **Significant Protocol Violations**: The lack of authentication violates the access control invariant that sensitive operational data should only be accessible to authorized parties. The metrics expose real-time consensus state that could be exploited to disrupt network operations.

2. **Validator Node Slowdowns**: By enabling reconnaissance of the validator network, attackers can identify and target critical validators more effectively, leading to coordinated attacks that cause slowdowns or temporary unavailability.

3. **Intelligence Gathering for Attacks**: While the metrics themselves don't directly cause harm, they provide attackers with actionable intelligence that significantly increases the effectiveness of subsequent attacks, including:
   - Identifying which validators to target for maximum consensus disruption
   - Timing attacks to coincide with specific consensus rounds
   - Exploiting validators with degraded performance

The vulnerability affects all Aptos validators that expose the inspection service on port 9101, which is the default configuration.

## Likelihood Explanation

The likelihood is **HIGH** because:

1. **No Prerequisites**: Attackers need only network access to port 9101, which many validators expose for monitoring purposes. No credentials, exploits, or sophisticated tools are required.

2. **Default Configuration**: The inspection service is enabled by default and binds to `0.0.0.0:9101`, making it accessible unless explicitly firewalled.

3. **Deployment Reality**: While Kubernetes NetworkPolicy and HAProxy IP blocking exist in the reference deployment, many operators may:
   - Run validators without Kubernetes
   - Misconfigure or skip firewall rules
   - Expose metrics for their own monitoring without realizing the security implications
   - Use the Docker Compose setup which exposes to localhost but could be misconfigured

4. **Inconsistent Security Model**: The presence of `expose_*` flags for other endpoints creates a false sense that all sensitive endpoints have such controls, when in fact the metrics endpoints lack them entirely.

## Recommendation

Implement authentication and authorization controls for the metrics endpoints consistent with other sensitive endpoints:

1. **Add configuration flags** in `InspectionServiceConfig`:
```rust
pub struct InspectionServiceConfig {
    pub address: String,
    pub port: u16,
    pub expose_configuration: bool,
    pub expose_identity_information: bool,
    pub expose_peer_information: bool,
    pub expose_system_information: bool,
    pub expose_metrics: bool,  // ADD THIS
    pub expose_json_metrics: bool,  // ADD THIS
    pub expose_forge_metrics: bool,  // ADD THIS
}
```

2. **Update default values** to disable metrics on mainnet validators:
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
            expose_metrics: false,  // Secure by default
            expose_json_metrics: false,
            expose_forge_metrics: false,
        }
    }
}
```

3. **Implement authorization checks** in the handlers:
```rust
pub fn handle_json_metrics_request(node_config: &NodeConfig) -> (StatusCode, Body, String) {
    if !node_config.inspection_service.expose_json_metrics {
        return (
            StatusCode::FORBIDDEN,
            Body::from("This endpoint is disabled! Enable it in the node config at inspection_service.expose_json_metrics: true"),
            CONTENT_TYPE_TEXT.into(),
        );
    }
    let buffer = utils::get_encoded_metrics(JsonEncoder);
    (StatusCode::OK, Body::from(buffer), CONTENT_TYPE_JSON.into())
}
```

4. **Add config sanitizer** to prevent mainnet validators from exposing metrics: [8](#0-7) 

5. **Consider token-based authentication** for authorized monitoring systems, similar to the telemetry service approach.

## Proof of Concept

```bash
#!/bin/bash
# PoC: Unauthenticated Metrics Access

# Step 1: Identify a validator node (example IP)
VALIDATOR_IP="validator.aptos.network"
METRICS_PORT="9101"

# Step 2: Query metrics endpoint without authentication
echo "[*] Attempting to access metrics without authentication..."
curl -v "http://${VALIDATOR_IP}:${METRICS_PORT}/json_metrics" > metrics_output.json

# Step 3: Parse sensitive information
echo "[*] Extracting sensitive consensus metrics..."

# Extract validator voting power distribution
jq 'to_entries | 
    map(select(.key | contains("aptos_all_validators_voting_power"))) | 
    map({peer: .key, voting_power: .value})' metrics_output.json

# Extract current consensus round
jq 'to_entries | 
    map(select(.key == "aptos_consensus_current_round")) | 
    .[0].value' metrics_output.json

# Extract last vote information per validator
jq 'to_entries | 
    map(select(.key | contains("aptos_consensus_last_voted"))) | 
    map({peer: .key, last_activity: .value})' metrics_output.json

# Extract participation status
jq 'to_entries | 
    map(select(.key | contains("aptos_consensus_participation_status"))) | 
    map({peer: .key, participating: (.value == 1)})' metrics_output.json

echo "[*] Successfully extracted sensitive validator intelligence without authentication!"
echo "[*] This data can be used to:"
echo "    - Identify high-value validators to target"
echo "    - Map consensus round progression for timing attacks"
echo "    - Detect validators with degraded performance"
echo "    - Build network topology map from peer relationships"
```

**Expected Result**: The script successfully retrieves all metrics without providing any credentials, demonstrating the absence of authentication.

**Notes**

The vulnerability is particularly concerning because:

1. **Defense-in-depth failure**: The codebase implements access controls for configuration and identity endpoints but completely omits them for metrics, creating an inconsistent security posture.

2. **Mainnet exposure**: While the config sanitizer prevents exposing `/configuration` on mainnet validators, no equivalent protection exists for metrics endpoints.

3. **Real-time intelligence**: Unlike static configuration data, metrics provide real-time operational intelligence that is immediately actionable for attackers coordinating timing-sensitive attacks.

4. **Network-level mitigations are insufficient**: Relying solely on external firewalls or Kubernetes NetworkPolicy violates the principle of defense-in-depth and leaves many deployments vulnerable, especially those using Docker Compose or custom deployments.

### Citations

**File:** crates/aptos-inspection-service/src/server/metrics.rs (L67-76)
```rust
pub fn handle_json_metrics_request() -> (StatusCode, Body, String) {
    let buffer = utils::get_encoded_metrics(JsonEncoder);
    (StatusCode::OK, Body::from(buffer), CONTENT_TYPE_JSON.into())
}

/// Handles a new metrics request (with text encoding)
pub fn handle_metrics_request() -> (StatusCode, Body, String) {
    let buffer = utils::get_encoded_metrics(TextEncoder::new());
    (StatusCode::OK, Body::from(buffer), CONTENT_TYPE_TEXT.into())
}
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

**File:** config/src/config/inspection_service_config.rs (L54-68)
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

        Ok(())
    }
```

**File:** crates/aptos-inspection-service/src/server/configuration.rs (L13-29)
```rust
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

**File:** consensus/src/counters.rs (L519-545)
```rust
pub static CONSENSUS_PARTICIPATION_STATUS: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!(
        "aptos_consensus_participation_status",
        "Counter for consensus participation status, 0 means no participation and 1 otherwise",
        &["peer_id"]
    )
    .unwrap()
});

/// Voting power of the validator
pub static VALIDATOR_VOTING_POWER: Lazy<Gauge> = Lazy::new(|| {
    register_gauge!(
        "aptos_validator_voting_power",
        "Voting power of the validator"
    )
    .unwrap()
});

/// Emits voting power for all validators in the current epoch.
pub static ALL_VALIDATORS_VOTING_POWER: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!(
        "aptos_all_validators_voting_power",
        "Voting power for all validators in current epoch",
        &["peer_id"]
    )
    .unwrap()
});
```

**File:** consensus/src/counters.rs (L577-594)
```rust
pub static CONSENSUS_LAST_VOTE_EPOCH: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!(
        "aptos_consensus_last_voted_epoch",
        "for each peer_id, last epoch we've seen consensus vote",
        &["peer_id"]
    )
    .unwrap()
});

/// Last vote seen for each of the peers
pub static CONSENSUS_LAST_VOTE_ROUND: Lazy<IntGaugeVec> = Lazy::new(|| {
    register_int_gauge_vec!(
        "aptos_consensus_last_voted_round",
        "for each peer_id, last round we've seen consensus vote",
        &["peer_id"]
    )
    .unwrap()
});
```

**File:** consensus/src/counters.rs (L620-626)
```rust
pub static CURRENT_ROUND: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "aptos_consensus_current_round",
        "This counter is set to the last round reported by the local round_state."
    )
    .unwrap()
});
```
