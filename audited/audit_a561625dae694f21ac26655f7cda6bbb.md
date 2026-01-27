# Audit Report

## Title
Time-of-Check Time-of-Use Vulnerability in Failpoint Sanitizer Allows Mainnet Deployment with Failpoints Enabled

## Summary
The failpoint configuration sanitizer uses `chain_id` extracted from the genesis file during config validation, but the node runtime uses `chain_id` from the database. When genesis is missing/corrupted, the sanitizer receives `None` and skips mainnet validation, allowing a failpoints-enabled node to start and connect to mainnet using the database's chain_id.

## Finding Description
The vulnerability exists in a time-of-check vs time-of-use (TOCTTOU) discrepancy between config sanitization and runtime execution.

**Phase 1: Config Sanitization (check)** [1](#0-0) 

When `get_chain_id()` fails due to missing/corrupted genesis, `chain_id` is set to `None`: [2](#0-1) 

The mainnet check is skipped when `chain_id` is `None`, allowing failpoints to pass validation.

Similarly in API config: [3](#0-2) 

**Phase 2: Node Runtime (use)** [4](#0-3) 

The runtime fetches `chain_id` from the database, not from genesis: [5](#0-4) 

**Attack Scenario:**
1. Existing mainnet node has populated database with `ChainId::mainnet()`
2. Operator deploys failpoints-enabled binary (debug build on production)
3. Genesis file missing/corrupted in deployment
4. Config sanitizer: `chain_id = None` → mainnet check skipped → passes
5. Node startup: `fetch_chain_id(db)` → `ChainId::mainnet()` from existing database
6. Network handshake uses mainnet chain_id → connects to mainnet peers
7. Failpoints active on mainnet node via API endpoints [6](#0-5) 

## Impact Explanation
**High Severity** per Aptos bug bounty criteria:
- Enables failpoint injection on mainnet nodes leading to:
  - Validator node crashes/slowdowns (panic injection)
  - API crashes (targeted failure injection)
  - State sync corruption (data path failures)
  - Consensus disruption (protocol-level failures)

While failpoints require compile-time enablement, the sanitizer's purpose is to provide defense-in-depth against operator mistakes. This bypass defeats that protection layer, allowing production misconfigurations that should be impossible.

The explicit test confirms this behavior is documented: [7](#0-6) 

## Likelihood Explanation
**Medium-High likelihood** in practice:
- Requires operator error (deploying debug build) or compromised build pipeline
- Missing genesis is realistic in automated deployments with misconfigured paths
- Existing production databases make sanitizer bypass viable
- No secondary validation after database chain_id is discovered

## Recommendation
Add a runtime validation that re-checks failpoint configuration after `chain_id` is fetched from the database:

```rust
// In aptos-node/src/lib.rs, after line 713:
pub fn setup_environment_and_start_node(...) -> anyhow::Result<AptosHandle> {
    // ... existing code ...
    let chain_id = utils::fetch_chain_id(&db_rw)?;
    
    // Re-validate failpoint configuration with actual chain_id
    if chain_id.is_mainnet() {
        if are_failpoints_enabled() {
            return Err(anyhow!(
                "Failpoints are compiled in but this is a mainnet node! \
                This should have been caught during config sanitization."
            ));
        }
        if node_config.api.failpoints_enabled {
            return Err(anyhow!(
                "API failpoints are enabled but this is a mainnet node! \
                This should have been caught during config sanitization."
            ));
        }
    }
    
    // ... rest of startup ...
}
```

Additionally, require genesis during config sanitization or fail loudly:
```rust
// In config/src/config/node_config_loader.rs
fn extract_node_type_and_chain_id(node_config: &NodeConfig) -> (NodeType, Option<ChainId>) {
    let node_type = NodeType::extract_from_config(node_config);
    match get_chain_id(node_config) {
        Ok(chain_id) => (node_type, Some(chain_id)),
        Err(error) => {
            // For production roles, require genesis
            if node_type.is_validator() {
                panic!("Validator nodes MUST have valid genesis! Error: {:?}", error);
            }
            eprintln!("WARNING: Failed to extract chain ID: {:?}", error);
            (node_type, None)
        },
    }
}
```

## Proof of Concept
```rust
// Test demonstrating the bypass
#[test]
#[cfg(feature = "failpoints")]
fn test_sanitizer_bypass_with_existing_mainnet_db() {
    use aptos_config::config::{NodeConfig, ApiConfig};
    use aptos_types::chain_id::ChainId;
    
    // Simulate config with failpoints but no genesis (chain_id = None)
    let mut node_config = NodeConfig {
        api: ApiConfig {
            enabled: true,
            failpoints_enabled: true,
            ..Default::default()
        },
        ..Default::default()
    };
    node_config.execution.genesis = None; // No genesis
    
    // Config sanitizer with chain_id = None should pass (BUG!)
    let result = ApiConfig::sanitize(&node_config, NodeType::Validator, None);
    assert!(result.is_ok(), "Sanitizer should pass with None chain_id");
    
    // But if we had called it with mainnet chain_id, it would fail
    let result = ApiConfig::sanitize(&node_config, NodeType::Validator, Some(ChainId::mainnet()));
    assert!(result.is_err(), "Sanitizer should fail with mainnet chain_id");
    
    // This demonstrates the TOCTTOU: sanitizer sees None, runtime uses mainnet
}
```

**Notes**
- The vulnerability requires operator-level access to deploy custom binaries and modify configurations
- This represents a failure of defense-in-depth rather than a direct protocol vulnerability
- The sanitizer's documented behavior (test at line 286-287) confirms `None` chain_id bypasses mainnet checks
- Network handshake validation prevents connecting to wrong chains, but doesn't prevent failpoints on the correct chain
- Impact is amplified on validators where failpoint injection can disrupt consensus

### Citations

**File:** config/src/config/node_config_loader.rs (L109-124)
```rust
/// Extracts the node type and chain ID from the given node config
/// and genesis transaction. If the chain ID cannot be extracted,
/// None is returned.
fn extract_node_type_and_chain_id(node_config: &NodeConfig) -> (NodeType, Option<ChainId>) {
    // Get the node type from the node config
    let node_type = NodeType::extract_from_config(node_config);

    // Get the chain ID from the genesis transaction
    match get_chain_id(node_config) {
        Ok(chain_id) => (node_type, Some(chain_id)),
        Err(error) => {
            println!("Failed to extract the chain ID from the genesis transaction: {:?}! Continuing with None.", error);
            (node_type, None)
        },
    }
}
```

**File:** config/src/config/config_sanitizer.rs (L74-91)
```rust
fn sanitize_failpoints_config(
    node_config: &NodeConfig,
    _node_type: NodeType,
    chain_id: Option<ChainId>,
) -> Result<(), Error> {
    let sanitizer_name = FAILPOINTS_SANITIZER_NAME.to_string();
    let failpoints = &node_config.failpoints;

    // Verify that failpoints are not enabled in mainnet
    let failpoints_enabled = are_failpoints_enabled();
    if let Some(chain_id) = chain_id {
        if chain_id.is_mainnet() && failpoints_enabled {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "Failpoints are not supported on mainnet nodes!".into(),
            ));
        }
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

**File:** config/src/config/api_config.rs (L286-287)
```rust
        // Sanitize the config for an unknown network and verify that it succeeds
        ApiConfig::sanitize(&node_config, NodeType::Validator, None).unwrap();
```

**File:** aptos-node/src/lib.rs (L712-713)
```rust
    // Obtain the chain_id from the DB
    let chain_id = utils::fetch_chain_id(&db_rw)?;
```

**File:** aptos-node/src/utils.rs (L42-49)
```rust
pub fn fetch_chain_id(db: &DbReaderWriter) -> anyhow::Result<ChainId> {
    let db_state_view = db
        .reader
        .latest_state_checkpoint_view()
        .map_err(|err| anyhow!("[aptos-node] failed to create db state view {}", err))?;
    Ok(ChainIdResource::fetch_config(&db_state_view)
        .expect("[aptos-node] missing chain ID resource")
        .chain_id())
```

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
