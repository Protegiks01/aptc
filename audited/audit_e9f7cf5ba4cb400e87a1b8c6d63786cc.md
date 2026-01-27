# Audit Report

## Title
Genesis Waypoint Validation Bypass Through Explicit Configuration Override

## Summary
The Aptos node configuration system allows explicit setting of `execution.genesis_waypoint`, which bypasses the hardcoded mainnet/testnet genesis waypoint protection without validation. This enables distribution of malicious node configurations that accept arbitrary genesis states while claiming to be mainnet/testnet nodes.

## Finding Description

The genesis waypoint validation mechanism has a critical bypass when `execution.genesis_waypoint` is explicitly set in configuration files.

**Normal Protection Flow (when it works):** [1](#0-0) 

The optimizer automatically injects hardcoded genesis waypoints (MAINNET_GENESIS_WAYPOINT or TESTNET_GENESIS_WAYPOINT) when three conditions are met: base waypoint is non-genesis, execution.genesis_waypoint is None, and it's not explicitly set in the local config YAML. [2](#0-1) 

**The Bypass:**

When a user explicitly sets `execution.genesis_waypoint` in their configuration file, the condition at line 204 fails (`local_execution_config_yaml["genesis_waypoint"].is_null()` returns false), preventing the hardcoded waypoint injection. [3](#0-2) 

The genesis application logic uses the explicitly-set waypoint without validation against expected mainnet/testnet values.

**Missing Validation:** [4](#0-3) 

The ExecutionConfig sanitizer only validates paranoid verification flags for mainnet nodes but performs no validation on the `genesis_waypoint` field itself, even when chain_id indicates mainnet/testnet.

**Attack Propagation:**

1. Attacker creates malicious genesis transaction with `chain_id = ChainId::mainnet()`
2. Attacker calculates matching waypoint: `Waypoint::new_epoch_boundary(malicious_genesis_ledger_info)`
3. Attacker distributes config package containing:
   - `genesis.blob` (malicious genesis)
   - `node.yaml` with `execution.genesis_waypoint: "0:malicious_hash"`
4. Victim loads config via NodeConfigLoader
5. Chain ID extraction succeeds, identifying as mainnet: [5](#0-4) 

6. Optimizer sees explicit genesis_waypoint, skips hardcoded injection
7. Genesis bootstrap proceeds with malicious waypoint: [6](#0-5) 

8. Malicious genesis matches attacker's waypoint, gets committed

**Network Isolation Consequence:**

While the compromised node cannot directly harm the real mainnet (network handshake chain_id checks pass, but state sync fails due to mismatched genesis), victims believe they're on mainnet: [7](#0-6) 

## Impact Explanation

**Severity Assessment: Medium**

This vulnerability enables **supply chain attacks** where malicious node distribution packages compromise victim nodes through configuration manipulation. While it doesn't directly steal funds from mainnet or break consensus, it creates:

1. **Phishing Vector**: Victims believe they're on mainnet but interact with attacker-controlled network
2. **Credential Theft**: Users may expose private keys thinking they're securing mainnet assets
3. **Fund Loss**: Transactions sent to "mainnet" addresses actually go to attacker's isolated network
4. **Reputation Damage**: Undermines trust in official node deployment processes

This falls under **"State inconsistencies requiring intervention"** (Medium severity) as victims must be alerted and migrated to correctly configured nodes. The limited impact (requires social engineering, doesn't affect real mainnet) prevents Critical/High classification.

## Likelihood Explanation

**Likelihood: Medium**

This requires:
- Attacker distributes malicious config package (feasible via compromised mirrors, typosquatting, DNS hijacking)
- Victim downloads and uses malicious config instead of generating their own
- Victim doesn't notice their node fails to sync with real network

Mitigating factors:
- Official documentation recommends specific setup procedures
- Experienced operators generate their own configs
- Network isolation becomes apparent quickly

Increasing factors:
- Many users trust "one-click setup" packages
- Config files appear legitimate (valid YAML, proper structure)
- Error messages about sync failure may be ignored as "network issues"

## Recommendation

**Add genesis waypoint validation to the config sanitizer:**

```rust
impl ConfigSanitizer for ExecutionConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let execution_config = &node_config.execution;

        // EXISTING CHECKS...
        
        // NEW: Validate genesis_waypoint for mainnet/testnet
        if let Some(chain_id) = chain_id {
            if let Some(genesis_waypoint_config) = &execution_config.genesis_waypoint {
                let genesis_waypoint = genesis_waypoint_config.waypoint();
                
                // Check if explicitly-set waypoint matches expected value
                if chain_id.is_mainnet() {
                    let expected = Waypoint::from_str(MAINNET_GENESIS_WAYPOINT)
                        .expect("Invalid hardcoded mainnet genesis waypoint");
                    if genesis_waypoint.version() == GENESIS_VERSION && genesis_waypoint != expected {
                        return Err(Error::ConfigSanitizerFailed(
                            sanitizer_name,
                            format!(
                                "Genesis waypoint mismatch for mainnet! Expected: {}, Got: {}",
                                expected, genesis_waypoint
                            ),
                        ));
                    }
                } else if chain_id.is_testnet() {
                    let expected = Waypoint::from_str(TESTNET_GENESIS_WAYPOINT)
                        .expect("Invalid hardcoded testnet genesis waypoint");
                    if genesis_waypoint.version() == GENESIS_VERSION && genesis_waypoint != expected {
                        return Err(Error::ConfigSanitizerFailed(
                            sanitizer_name,
                            format!(
                                "Genesis waypoint mismatch for testnet! Expected: {}, Got: {}",
                                expected, genesis_waypoint
                            ),
                        ));
                    }
                }
            }
        }

        Ok(())
    }
}
```

**Additional Hardening:**
- Log warnings when explicitly-set genesis_waypoint differs from hardcoded values
- Document that custom genesis_waypoint is for private networks only
- Add checksum verification for genesis.blob files in setup scripts

## Proof of Concept

```rust
// File: config/src/config/execution_config_test.rs
#[test]
fn test_explicit_genesis_waypoint_bypass() {
    use std::str::FromStr;
    
    // Create malicious genesis waypoint (wrong hash for mainnet)
    let malicious_waypoint = Waypoint::from_str(
        "0:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    ).unwrap();
    
    // Create config with explicitly-set malicious waypoint
    let mut node_config = NodeConfig {
        execution: ExecutionConfig {
            genesis_waypoint: Some(WaypointConfig::FromConfig(malicious_waypoint)),
            ..Default::default()
        },
        ..Default::default()
    };
    
    // Create local config YAML with explicit setting
    let local_config_yaml = serde_yaml::from_str(
        r#"
        execution:
            genesis_waypoint: "0:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        "#
    ).unwrap();
    
    // Run optimizer - should NOT inject hardcoded waypoint
    let modified = ExecutionConfig::optimize(
        &mut node_config,
        &local_config_yaml,
        NodeType::Validator,
        Some(ChainId::mainnet()),
    ).unwrap();
    
    assert!(!modified, "Optimizer should not modify explicitly-set waypoint");
    
    // Verify malicious waypoint is still present
    let genesis_waypoint = node_config.execution.genesis_waypoint
        .as_ref()
        .unwrap()
        .waypoint();
    assert_eq!(genesis_waypoint, malicious_waypoint);
    assert_ne!(genesis_waypoint, Waypoint::from_str(MAINNET_GENESIS_WAYPOINT).unwrap());
    
    // Current sanitizer FAILS to detect this
    let sanitize_result = ExecutionConfig::sanitize(
        &node_config,
        NodeType::Validator,
        Some(ChainId::mainnet()),
    );
    
    // This should fail but currently passes
    assert!(sanitize_result.is_ok(), "Current code allows malicious waypoint!");
    
    println!("VULNERABILITY: Malicious genesis waypoint bypassed validation!");
}
```

**Notes**

This vulnerability represents a **configuration validation gap** rather than a direct protocol exploit. The attack requires distributing malicious configuration files (social engineering element), which places it at the boundary of the Aptos bug bounty scope. However, the technical mechanism—bypassing hardcoded genesis waypoint protection through explicit configuration without validation—constitutes a genuine security weakness in the node bootstrapping process.

The recommended fix is straightforward: extend the config sanitizer to validate that explicitly-set genesis waypoints for mainnet/testnet match expected hardcoded values, preventing configuration-based genesis substitution attacks while preserving the ability to run private networks with custom genesis configurations.

### Citations

**File:** config/src/config/execution_config.rs (L25-28)
```rust
const MAINNET_GENESIS_WAYPOINT: &str =
    "0:6072b68a942aace147e0655c5704beaa255c84a7829baa4e72a500f1516584c4";
const TESTNET_GENESIS_WAYPOINT: &str =
    "0:4b56f15c1dcef7f9f3eb4b4798c0cba0f1caacc0d35f1c80ad9b7a21f1f8b454";
```

**File:** config/src/config/execution_config.rs (L157-186)
```rust
impl ConfigSanitizer for ExecutionConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let execution_config = &node_config.execution;

        // If this is a mainnet node, ensure that additional verifiers are enabled
        if let Some(chain_id) = chain_id {
            if chain_id.is_mainnet() {
                if !execution_config.paranoid_hot_potato_verification {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        "paranoid_hot_potato_verification must be enabled for mainnet nodes!"
                            .into(),
                    ));
                }
                if !execution_config.paranoid_type_verification {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        "paranoid_type_verification must be enabled for mainnet nodes!".into(),
                    ));
                }
            }
        }

        Ok(())
    }
```

**File:** config/src/config/execution_config.rs (L202-205)
```rust
        if node_config.base.waypoint.waypoint().version() != GENESIS_VERSION
            && execution_config.genesis_waypoint.is_none()
            && local_execution_config_yaml["genesis_waypoint"].is_null()
        {
```

**File:** aptos-node/src/storage.rs (L28-33)
```rust
    let genesis_waypoint = node_config
        .execution
        .genesis_waypoint
        .as_ref()
        .unwrap_or(&node_config.base.waypoint)
        .genesis_waypoint();
```

**File:** config/src/config/node_config_loader.rs (L158-191)
```rust
fn get_chain_id(node_config: &NodeConfig) -> Result<ChainId, Error> {
    // TODO: can we make this less hacky?

    // Load the genesis transaction from disk
    let genesis_txn = get_genesis_txn(node_config).ok_or_else(|| {
        Error::InvariantViolation("The genesis transaction was not found!".to_string())
    })?;

    // Extract the chain ID from the genesis transaction
    match genesis_txn {
        Transaction::GenesisTransaction(WriteSetPayload::Direct(change_set)) => {
            let chain_id_state_key = StateKey::on_chain_config::<ChainId>()?;

            // Get the write op from the write set
            let write_set_mut = change_set.clone().write_set().clone().into_mut();
            let write_op = write_set_mut.get(&chain_id_state_key).ok_or_else(|| {
                Error::InvariantViolation(
                    "The genesis transaction does not contain the write op for the chain id!"
                        .into(),
                )
            })?;

            // Extract the chain ID from the write op
            let write_op_bytes = write_op.bytes().ok_or_else(|| Error::InvariantViolation(
                "The genesis transaction does not contain the correct write op for the chain ID!".into(),
            ))?;
            let chain_id = ChainId::deserialize_into_config(write_op_bytes).map_err(|error| {
                Error::InvariantViolation(format!(
                    "Failed to deserialize the chain ID: {:?}",
                    error
                ))
            })?;

            Ok(chain_id)
```

**File:** execution/executor/src/db_bootstrapper/mod.rs (L61-67)
```rust
    let committer = calculate_genesis::<V>(db, ledger_summary, genesis_txn)?;
    ensure!(
        waypoint == committer.waypoint(),
        "Waypoint verification failed. Expected {:?}, got {:?}.",
        waypoint,
        committer.waypoint(),
    );
```

**File:** network/framework/src/protocols/wire/handshake/v1/mod.rs (L435-441)
```rust
        // verify that both peers are on the same chain
        if self.chain_id != other.chain_id {
            return Err(HandshakeError::InvalidChainId(
                other.chain_id,
                self.chain_id,
            ));
        }
```
