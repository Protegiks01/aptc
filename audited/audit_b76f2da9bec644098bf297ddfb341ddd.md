# Audit Report

## Title
Remote Consensus Disruption via Unauthenticated Failpoint API Endpoint

## Summary

The `/v1/set_failpoint` API endpoint allows unauthenticated remote attackers to configure global failpoints that affect critical consensus operations, causing validator nodes to lose liveness and fall out of consensus. While failpoints are intended for testing, the lack of namespace isolation between API and consensus failpoints creates a severe attack vector on misconfigured nodes.

## Finding Description

The vulnerability exists in the failpoint configuration mechanism exposed through the REST API. At line 250 in `attach_poem_to_runtime()`, the `/set_failpoint` endpoint is registered without authentication: [1](#0-0) 

This endpoint delegates to `set_failpoint_poem()` which uses the `fail::cfg()` function to configure global failpoints: [2](#0-1) 

The critical flaw is that the `fail` crate's failpoint mechanism is **global and unnamespaced**. While API endpoints use failpoints prefixed with `"api::"`: [3](#0-2) 

The consensus layer uses failpoints with the `"consensus::"` prefix in critical code paths: [4](#0-3) [5](#0-4) [6](#0-5) 

An attacker who can access the API endpoint can configure **any** failpoint in the entire codebase, including those in the consensus layer. For example, setting `consensus::send::any` causes all consensus network operations to fail, or setting `consensus::process_proposal_msg` prevents proposal processing.

**Attack Path:**
1. Attacker identifies a testnet/devnet node with `api.failpoints_enabled = true`
2. Attacker sends: `GET /v1/set_failpoint?name=consensus::send::any&actions=return`
3. The global failpoint is configured via `fail::cfg()`
4. All subsequent consensus RPC operations fail due to the triggered failpoint
5. The validator loses consensus liveness and cannot participate in block production

The only protection is the `failpoints_enabled` configuration check: [7](#0-6) 

Which is validated to prevent mainnet usage: [8](#0-7) 

However, testnet and devnet nodes commonly enable failpoints for debugging, making them vulnerable.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program:

- **Validator node slowdowns**: Setting consensus failpoints causes complete validator liveness failure
- **Significant protocol violations**: Breaking consensus message handling violates the AptosBFT liveness guarantee

The attack causes:
- **Complete consensus liveness failure** for the affected validator node
- **Network degradation** if multiple validators are compromised
- **Validator rewards loss** due to inability to participate in consensus
- **Difficult-to-debug failures** that may be mistaken for network or software bugs

This does NOT reach Critical severity because:
- It does not break consensus **safety** (only liveness)
- It does not enable theft of funds or state corruption
- It requires misconfiguration (`failpoints_enabled = true`)
- It is explicitly prevented on mainnet

## Likelihood Explanation

**Likelihood: Medium**

- **Moderate** in test environments where `failpoints_enabled = true` is common for debugging
- **Low** in production due to default-disabled configuration and mainnet sanitization
- **High** exploitability once a misconfigured node is identified (single HTTP GET request)

The vulnerability is **easily exploitable** with no authentication required beyond network access to the API endpoint. The attack complexity is minimal - a single curl command can disable consensus on a validator.

## Recommendation

**Immediate Fix**: Implement namespace isolation for failpoints to prevent API endpoint from configuring non-API failpoints:

```rust
// In api/src/set_failpoints.rs
#[cfg(feature = "failpoints")]
#[handler]
pub fn set_failpoint_poem(
    context: Data<&std::sync::Arc<Context>>,
    Query(failpoint_conf): Query<FailpointConf>,
) -> poem::Result<String> {
    if context.failpoints_enabled() {
        // SECURITY: Only allow configuring API failpoints
        if !failpoint_conf.name.starts_with("api::") {
            return Err(poem::Error::from(anyhow::anyhow!(
                "Failpoint name must start with 'api::' prefix. Attempted: {}",
                failpoint_conf.name
            )));
        }
        
        fail::cfg(&failpoint_conf.name, &failpoint_conf.actions)
            .map_err(|e| poem::Error::from(anyhow::anyhow!(e)))?;
        // ... rest of function
    }
    // ...
}
```

**Additional Recommendations:**
1. Add authentication/authorization to the `/set_failpoint` endpoint
2. Rate-limit failpoint configuration requests
3. Log all failpoint configuration attempts for security monitoring
4. Consider removing the endpoint entirely from production builds
5. Add warnings in documentation about the security implications of enabling failpoints

## Proof of Concept

**Setup**: Start an Aptos node with `api.failpoints_enabled = true` and the `failpoints` feature compiled.

**Attack**:
```bash
# Disable all consensus network operations
curl -X GET "http://localhost:8080/v1/set_failpoint?name=consensus::send::any&actions=return"

# Disable proposal processing
curl -X GET "http://localhost:8080/v1/set_failpoint?name=consensus::process_proposal_msg&actions=return"

# Disable state synchronization
curl -X GET "http://localhost:8080/v1/set_failpoint?name=consensus::sync_to_target&actions=return"
```

**Expected Result**: 
- Validator immediately loses ability to participate in consensus
- Consensus metrics show network operation failures
- Node falls behind in block production
- Operator sees consensus errors without obvious cause

**Verification**:
Monitor consensus logs showing failpoint-induced errors and validator falling out of sync with the network.

---

## Notes

This vulnerability demonstrates a classic **privilege escalation through feature interaction** - a debugging feature (failpoints) intended for testing creates an attack vector when exposed through an unauthenticated API. The root cause is the global, unscoped nature of the `fail` crate's failpoint mechanism combined with the lack of access control on the configuration endpoint.

While the mainnet protection is effective, the vulnerability poses a real threat to testnet/devnet infrastructure and any production nodes that are accidentally misconfigured.

### Citations

**File:** api/src/runtime.rs (L248-251)
```rust
                    .at(
                        "/set_failpoint",
                        poem::get(set_failpoints::set_failpoint_poem).data(context.clone()),
                    ),
```

**File:** api/src/set_failpoints.rs (L27-29)
```rust
    if context.failpoints_enabled() {
        fail::cfg(&failpoint_conf.name, &failpoint_conf.actions)
            .map_err(|e| poem::Error::from(anyhow::anyhow!(e)))?;
```

**File:** api/src/failpoint.rs (L14-20)
```rust
pub fn fail_point_poem<E: InternalError>(name: &str) -> Result<(), E> {
    fail::fail_point!(format!("api::{}", name).as_str(), |_| {
        Err(E::internal_with_code_no_info(
            format!("Failpoint unexpected internal error for {}", name),
            AptosErrorCode::InternalError,
        ))
    });
```

**File:** consensus/src/network.rs (L283-288)
```rust
        fail_point!("consensus::send::any", |_| {
            Err(anyhow::anyhow!("Injected error in request_block"))
        });
        fail_point!("consensus::send::block_retrieval", |_| {
            Err(anyhow::anyhow!("Injected error in request_block"))
        });
```

**File:** consensus/src/round_manager.rs (L727-729)
```rust
        fail_point!("consensus::process_proposal_msg", |_| {
            Err(anyhow::anyhow!("Injected error in process_proposal_msg"))
        });
```

**File:** consensus/src/state_computer.rs (L144-146)
```rust
        fail_point!("consensus::sync_for_duration", |_| {
            Err(anyhow::anyhow!("Injected error in sync_for_duration").into())
        });
```

**File:** api/src/context.rs (L209-211)
```rust
    pub fn failpoints_enabled(&self) -> bool {
        self.node_config.api.failpoints_enabled
    }
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
