# Audit Report

## Title
Unauthenticated Consensus Health Check Enables Byzantine Attack Timing Oracle

## Summary
The `/consensus_health_check` endpoint in the inspection service lacks access control and reveals real-time validator consensus participation status. This information leakage enables Byzantine validators to precisely time attacks during periods when multiple honest validators are syncing, temporarily reducing effective Byzantine fault tolerance and enabling coordinated liveness attacks.

## Finding Description

The consensus health check endpoint is implemented without any access control mechanism, unlike other sensitive inspection service endpoints: [1](#0-0) 

The endpoint reveals whether a validator is actively executing consensus by checking the `CONSENSUS_EXECUTING_GAUGE` metric. This gauge is set based on whether the validator is in "consensus executing" mode: [2](#0-1) 

Critically, when validators are NOT executing consensus (during synchronization), they explicitly stop voting: [3](#0-2) 

The Byzantine fault tolerance quorum is calculated based on the TOTAL validator voting power, not active participants: [4](#0-3) 

Unlike other inspection service endpoints that have configurable access control flags, the health check endpoint has no such protection: [5](#0-4) 

The inspection service metrics port is exposed through the validator load balancer when configured: [6](#0-5) 

**Attack Scenario:**
1. Attacker continuously polls `/consensus_health_check` on all known validators
2. Identifies validators returning 500 (syncing, not voting)
3. When sufficient honest validators are syncing (e.g., 15 out of 67 honest validators in a 100-validator set):
   - Remaining honest validators (52) cannot form quorum alone (need 67)
   - Byzantine validators (33) can block all progress by refusing to vote
   - Or selectively vote to censor transactions/manipulate block content
4. Attack maximizes impact by coordinating with periods of degraded honest validator participation

## Impact Explanation

This is a **HIGH severity** vulnerability per the Aptos bug bounty program for multiple reasons:

1. **Significant Protocol Violation**: Enables Byzantine validators to reduce effective Byzantine fault tolerance below the guaranteed 2f+1 threshold during sync windows

2. **Network Availability Impact**: Facilitates coordinated liveness attacks where Byzantine validators can halt block production by timing their vote refusal with periods of reduced honest participation

3. **Information Disclosure**: Leaks critical consensus state information that should not be publicly accessible without authentication

The vulnerability enables "validator node slowdowns" and "significant protocol violations" classified as High severity in the bug bounty program. While it doesn't directly break consensus safety, it provides an attack timing oracle that maximizes the impact of Byzantine behavior.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability is highly likely to be exploited because:

1. **Easy to exploit**: Simple HTTP polling, no authentication required
2. **Common trigger condition**: Validators regularly enter sync mode when catching up after temporary lag, network issues, or high load
3. **Low barrier**: Any network observer can monitor all validators
4. **High reward**: Byzantine validators can coordinate attacks with minimal risk of detection
5. **Public exposure**: Many deployments expose the inspection service for monitoring purposes

The attack requires Byzantine validators to exist (up to f = 33 in a 100-validator set), but this is within the threat model of Byzantine fault tolerance.

## Recommendation

Implement access control for the consensus health check endpoint using a configuration flag similar to other sensitive endpoints:

**1. Add configuration flag:**
```rust
// In config/src/config/inspection_service_config.rs
pub struct InspectionServiceConfig {
    pub address: String,
    pub port: u16,
    pub expose_configuration: bool,
    pub expose_identity_information: bool,
    pub expose_peer_information: bool,
    pub expose_system_information: bool,
    pub expose_consensus_health_check: bool,  // ADD THIS
}
```

**2. Update endpoint handler to check the flag:**
```rust
// In crates/aptos-inspection-service/src/server/metrics.rs
pub async fn handle_consensus_health_check(node_config: &NodeConfig) -> (StatusCode, Body, String) {
    // ADD THIS CHECK
    if !node_config.inspection_service.expose_consensus_health_check {
        return (
            StatusCode::FORBIDDEN,
            Body::from("Consensus health check endpoint is disabled"),
            CONTENT_TYPE_TEXT.into(),
        );
    }
    
    // Verify the node is a validator...
    // (rest of existing code)
}
```

**3. Set default to false for mainnet:**
Set `expose_consensus_health_check: false` by default and only enable for non-production environments or with explicit operator consent.

**4. Consider additional mitigations:**
- Rate limiting on the endpoint
- Authentication for sensitive monitoring endpoints
- Aggregate health metrics that don't reveal individual validator state
- Random noise/delays in health responses to prevent precise timing correlation

## Proof of Concept

```rust
// Rust proof of concept showing the attack monitoring

use reqwest;
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // List of validator inspection service endpoints
    let validators = vec![
        "http://validator-0:9101",
        "http://validator-1:9101",
        "http://validator-2:9101",
        // ... more validators
    ];
    
    let client = reqwest::Client::new();
    
    loop {
        let mut syncing_count = 0;
        let mut healthy_count = 0;
        
        for validator in &validators {
            let endpoint = format!("{}/consensus_health_check", validator);
            
            match client.get(&endpoint).send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        healthy_count += 1;
                        println!("[HEALTHY] {}", validator);
                    } else {
                        syncing_count += 1;
                        println!("[SYNCING] {}", validator);
                    }
                },
                Err(_) => println!("[OFFLINE] {}", validator),
            }
        }
        
        let total_validators = validators.len();
        let quorum_needed = (total_validators * 2 / 3) + 1;
        
        // Check if Byzantine attack window exists
        if healthy_count < quorum_needed {
            println!("\n!!! ATTACK WINDOW DETECTED !!!");
            println!("Healthy validators: {}", healthy_count);
            println!("Quorum needed: {}", quorum_needed);
            println!("Byzantine validators can block consensus by refusing to vote\n");
            
            // Byzantine validators would launch attack here
            // - Refuse to vote on proposals
            // - Selectively vote to censor transactions
            // - Time double-voting or equivocation attempts
        }
        
        sleep(Duration::from_secs(2)).await;
    }
}
```

This PoC demonstrates how an attacker can continuously monitor validator health and identify windows where Byzantine behavior would have maximum impact, enabling coordinated liveness attacks or transaction censorship.

## Notes

The vulnerability is exacerbated by the fact that the inspection service is intentionally exposed for monitoring purposes in many deployments, making the attack surface widely available. The comment in the code "we assume that this endpoint will only be used every few seconds" suggests awareness of external monitoring use cases but no security controls were implemented to restrict access to trusted monitoring systems only.

### Citations

**File:** crates/aptos-inspection-service/src/server/metrics.rs (L16-48)
```rust
/// Handles a consensus health check request. This method returns
/// 200 if the node is currently participating in consensus.
///
/// Note: we assume that this endpoint will only be used every few seconds.
pub async fn handle_consensus_health_check(node_config: &NodeConfig) -> (StatusCode, Body, String) {
    // Verify the node is a validator. If not, return an error.
    if !node_config.base.role.is_validator() {
        return (
            StatusCode::BAD_REQUEST,
            Body::from("This node is not a validator!"),
            CONTENT_TYPE_TEXT.into(),
        );
    }

    // Check the value of the consensus execution gauge
    let metrics = utils::get_all_metrics();
    if let Some(gauge_value) = metrics.get(CONSENSUS_EXECUTION_GAUGE) {
        if gauge_value == "1" {
            return (
                StatusCode::OK,
                Body::from("Consensus health check passed!"),
                CONTENT_TYPE_TEXT.into(),
            );
        }
    }

    // Otherwise, consensus is not executing
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Body::from("Consensus health check failed! Consensus is not executing!"),
        CONTENT_TYPE_TEXT.into(),
    )
}
```

**File:** state-sync/state-sync-driver/src/driver.rs (L743-748)
```rust
        // Set the consensus executing gauge
        if executing_component == ExecutingComponent::Consensus {
            metrics::CONSENSUS_EXECUTING_GAUGE.set(1);
        } else {
            metrics::CONSENSUS_EXECUTING_GAUGE.set(0);
        }
```

**File:** consensus/src/round_manager.rs (L1514-1517)
```rust
        ensure!(
            !self.sync_only(),
            "[RoundManager] sync_only flag is set, stop voting"
        );
```

**File:** types/src/validator_verifier.rs (L206-214)
```rust
    pub fn new(validator_infos: Vec<ValidatorConsensusInfo>) -> Self {
        let total_voting_power = sum_voting_power(&validator_infos);
        let quorum_voting_power = if validator_infos.is_empty() {
            0
        } else {
            total_voting_power * 2 / 3 + 1
        };
        Self::build_index(validator_infos, quorum_voting_power, total_voting_power)
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

**File:** terraform/helm/aptos-node/templates/haproxy.yaml (L39-43)
```yaml
  {{- if $.Values.service.validator.enableMetricsPort }}
  - name: metrics
    port: 9101
    targetPort: 9102
  {{- end }}
```
