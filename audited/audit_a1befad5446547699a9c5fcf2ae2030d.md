# Audit Report

## Title
TOCTOU Vulnerability in Config Sanitizer Allows Mainnet Validators to Bypass Configuration Exposure Protection

## Summary
A Time-of-Check to Time-of-Use (TOCTOU) vulnerability exists in the node configuration sanitization process. When the chain ID cannot be extracted from the genesis transaction during config loading, the sanitizer skips critical security checks, allowing mainnet validators to boot with `expose_configuration = true` and expose sensitive node configuration via the inspection service endpoint.

## Finding Description

The vulnerability arises from a mismatch between when the chain ID is checked (during config sanitization) and when it's actually used (during node runtime).

**The Check (Time-of-Check):**
During config loading, the sanitizer attempts to extract the chain ID from the genesis transaction: [1](#0-0) 

When `get_genesis_txn()` returns `None` (no genesis transaction configured), the function prints a warning but continues with `chain_id = None`: [2](#0-1) 

The sanitizer is then invoked with this `None` chain_id: [3](#0-2) 

**The Bypass:**
In `InspectionServiceConfig::sanitize()`, when `chain_id` is `None`, the entire security check is skipped: [4](#0-3) 

**The Use (Time-of-Use):**
After config sanitization completes, the node fetches the actual chain ID from the database during startup: [5](#0-4) [6](#0-5) 

**Why the Node Boots Without Genesis:**
The node explicitly allows booting without a genesis transaction if the database is already bootstrapped: [7](#0-6) 

**Attack Scenario:**
1. Operator configures a mainnet validator with `expose_configuration = true`
2. They remove or misconfigure the genesis transaction in their config
3. Database is already bootstrapped (from state sync or previous run)
4. During config loading, `chain_id = None` causes sanitizer to skip the mainnet check
5. Node boots successfully, fetches `chain_id` from database (discovers it's mainnet)
6. Inspection service starts with `expose_configuration = true`
7. Configuration is exposed via `/configuration` endpoint, violating security policy [8](#0-7) 

## Impact Explanation

**High Severity** - This qualifies as a "Significant protocol violation" per the Aptos bug bounty criteria.

The vulnerability allows mainnet validators to violate an explicit security policy. The inspection service configuration exposure check exists specifically to prevent mainnet validators from exposing sensitive operational data. By bypassing this check, the following information is exposed:

- Network topology (seed peers, validator network addresses, listen addresses)
- Storage configuration (database paths, pruning settings)
- Consensus configuration (round timeouts, voting thresholds)
- Mempool settings
- State sync configuration
- All other `NodeConfig` fields

This information disclosure could enable reconnaissance for more sophisticated attacks against the validator, such as:
- Identifying network infrastructure for targeted attacks
- Understanding consensus timing for potential manipulation
- Mapping validator connections for network-level attacks

The vulnerability directly violates the security invariant that mainnet validators must not expose configuration details to untrusted parties.

## Likelihood Explanation

**Medium-High Likelihood:**

The vulnerability is easily triggered in legitimate scenarios:

1. **State Sync Bootstrapping**: New validators often bootstrap via state sync without providing a genesis transaction, relying on the database to establish chain state. This is a documented deployment pattern.

2. **Node Restarts**: Validators that restart after initial bootstrapping no longer need the genesis transaction in their config, as the database already contains chain state.

3. **Configuration Errors**: Operators may accidentally omit or misconfigure the genesis transaction path, especially when migrating configurations or using configuration templates.

The attack requires no special privileges beyond node operator access (which is expected). An operator could intentionally or accidentally trigger this by:
- Setting `expose_configuration = true` for debugging
- Removing the genesis configuration
- Restarting the node

The sanitizer fails silently with only a console warning, making it easy to overlook.

## Recommendation

**Fix the TOCTOU vulnerability by deferring the inspection service sanitization check until the chain ID is definitively known:**

**Option 1: Runtime Validation** (Recommended)
Add a runtime check in the inspection service initialization that verifies mainnet validators don't have configuration exposure enabled:

```rust
// In crates/aptos-inspection-service/src/server/mod.rs or similar
pub fn start_inspection_service(
    node_config: &NodeConfig,
    chain_id: ChainId,
) -> Result<(), Error> {
    // Enforce mainnet validator policy at runtime
    if node_config.base.role.is_validator() 
        && chain_id.is_mainnet() 
        && node_config.inspection_service.expose_configuration 
    {
        return Err(Error::ConfigurationError(
            "Mainnet validators cannot expose configuration!".to_string()
        ));
    }
    // ... start service
}
```

**Option 2: Require Genesis Transaction**
Modify the sanitizer to fail when chain ID cannot be determined:

```rust
// In config/src/config/node_config_loader.rs
fn extract_node_type_and_chain_id(node_config: &NodeConfig) -> Result<(NodeType, ChainId), Error> {
    let node_type = NodeType::extract_from_config(node_config);
    let chain_id = get_chain_id(node_config)?; // Propagate error instead of defaulting to None
    Ok((node_type, chain_id))
}
```

**Option 3: Database Chain ID for Sanitization**
Extract chain ID from the database during config loading if genesis is unavailable:

```rust
fn extract_node_type_and_chain_id(
    node_config: &NodeConfig,
    db_rw: Option<&DbReaderWriter>
) -> (NodeType, Option<ChainId>) {
    let node_type = NodeType::extract_from_config(node_config);
    let chain_id = get_chain_id(node_config)
        .or_else(|_| db_rw.and_then(|db| utils::fetch_chain_id(db).ok()))
        .ok();
    (node_type, chain_id)
}
```

**Recommended Approach**: Option 1 is the safest as it enforces the policy at the point where it matters most (service initialization) and doesn't disrupt existing node bootstrap workflows.

## Proof of Concept

```rust
// Integration test demonstrating the vulnerability
// Add to config/src/config/inspection_service_config.rs tests

#[test]
fn test_sanitize_bypass_via_missing_chain_id() {
    use crate::config::{NodeConfig, RoleType, BaseConfig, InspectionServiceConfig};
    use super::*;

    // Create a validator config with configuration exposure enabled (violates policy)
    let mut node_config = NodeConfig {
        base: BaseConfig {
            role: RoleType::Validator,
            ..Default::default()
        },
        inspection_service: InspectionServiceConfig {
            expose_configuration: true,  // This should FAIL for mainnet validators
            ..Default::default()
        },
        ..Default::default()
    };

    // Deliberately provide chain_id = None (simulating missing genesis transaction)
    let result = InspectionServiceConfig::sanitize(
        &node_config,
        NodeType::Validator,
        None,  // chain_id is None - the vulnerability condition
    );

    // The sanitizer INCORRECTLY returns Ok(())
    assert!(result.is_ok(), "Sanitizer should have rejected this config but passed!");

    // Compare with the correct behavior when chain_id is provided
    let result_with_chain = InspectionServiceConfig::sanitize(
        &node_config,
        NodeType::Validator,
        Some(ChainId::mainnet()),
    );

    // This correctly fails
    assert!(result_with_chain.is_err(), "Sanitizer correctly rejects mainnet validator with exposed config");
    
    println!("VULNERABILITY CONFIRMED: Sanitizer bypass when chain_id is None");
}

// Reproduction steps for manual testing:
// 1. Set up a mainnet validator with bootstrapped database
// 2. Edit node config:
//    - Set inspection_service.expose_configuration = true
//    - Remove execution.genesis or set to invalid path
// 3. Restart node
// 4. Observe: Node starts successfully despite violating security policy
// 5. Query: curl http://<inspection_service_address>:<port>/configuration
// 6. Result: Full node configuration is exposed
```

**Notes:**

This vulnerability demonstrates a fundamental flaw in the sanitization architecture where security-critical checks depend on optional configuration data (genesis transaction) rather than guaranteed runtime state (database chain ID). The TOCTOU gap allows policy violations that persist throughout the node's lifetime.

The issue is particularly concerning because the warning message at configuration load time (`"Failed to extract the chain ID... Continuing with None"`) suggests this is expected behavior, but the security implications are not adequately handled.

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

**File:** config/src/config/node_config_loader.rs (L143-144)
```rust
    // Sanitize the node config
    NodeConfig::sanitize(node_config, node_type, chain_id)
```

**File:** config/src/utils.rs (L220-222)
```rust
pub fn get_genesis_txn(config: &NodeConfig) -> Option<&Transaction> {
    config.execution.genesis.as_ref()
}
```

**File:** config/src/config/inspection_service_config.rs (L45-68)
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
```

**File:** aptos-node/src/lib.rs (L712-716)
```rust
    // Obtain the chain_id from the DB
    let chain_id = utils::fetch_chain_id(&db_rw)?;

    // Set the chain_id in global AptosNodeIdentity
    aptos_node_identity::set_chain_id(chain_id)?;
```

**File:** aptos-node/src/utils.rs (L42-50)
```rust
pub fn fetch_chain_id(db: &DbReaderWriter) -> anyhow::Result<ChainId> {
    let db_state_view = db
        .reader
        .latest_state_checkpoint_view()
        .map_err(|err| anyhow!("[aptos-node] failed to create db state view {}", err))?;
    Ok(ChainIdResource::fetch_config(&db_state_view)
        .expect("[aptos-node] missing chain ID resource")
        .chain_id())
}
```

**File:** aptos-node/src/storage.rs (L34-42)
```rust
    if let Some(genesis) = get_genesis_txn(node_config) {
        let ledger_info_opt =
            maybe_bootstrap::<AptosVMBlockExecutor>(db_rw, genesis, genesis_waypoint)
                .map_err(|err| anyhow!("DB failed to bootstrap {}", err))?;
        Ok(ledger_info_opt)
    } else {
        info ! ("Genesis txn not provided! This is fine only if you don't expect to apply it. Otherwise, the config is incorrect!");
        Ok(None)
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
