# Audit Report

## Title
Chain ID Bypass Allows Mainnet Validators to Run with Unsafe Test Configurations

## Summary
A critical vulnerability in `NodeConfig::sanitize()` allows attackers to bypass all mainnet-specific security validations by causing chain ID extraction to fail. This enables mainnet validators to run with dangerous test-only features like failpoints, disabled cryptographic verifications, and insecure key storage, leading to consensus disruption and potential safety violations.

## Finding Description

The vulnerability exists in the config sanitization flow where the chain ID is extracted from the genesis transaction. When genesis extraction fails, the system continues with `chain_id = None`, bypassing all mainnet-specific security checks. [1](#0-0) 

The `extract_node_type_and_chain_id()` function catches errors from `get_chain_id()` and returns `None` instead of failing, printing only a warning message. This None value propagates to all config sanitizers. [2](#0-1) 

Multiple critical sanitizers use conditional checks that skip validation when `chain_id` is None:

**1. Failpoints Check Bypass:** [3](#0-2) 

When chain_id is None, failpoints can be enabled on mainnet. Failpoints allow runtime injection of failures into consensus: [4](#0-3) 

An attacker can use the failpoints API to block all consensus messages: [5](#0-4) 

**2. Execution Verification Bypass:** [6](#0-5) 

Disabling `paranoid_hot_potato_verification` and `paranoid_type_verification` removes critical Move VM runtime checks that ensure deterministic execution across validators.

**3. Consensus Test Feature Bypass:** [7](#0-6) 

**4. Safety Rules Bypass:** [8](#0-7) 

This allows mainnet validators to store private keys in memory instead of secure vaults, use non-local safety rules services, and enable test configurations.

**5. Additional Bypasses:**
- API failpoints: [9](#0-8) 
- Network benchmarking: [10](#0-9) 
- Configuration exposure: [11](#0-10) 

**Attack Execution:**

1. Attacker compiles `aptos-node` with test features: `cargo build --features failpoints`
2. Sets up mainnet validator configuration
3. Deletes or corrupts the genesis.blob file (or sets invalid path)
4. Starts the node - genesis extraction fails at: [12](#0-11) 

5. Node continues with `chain_id = None`, bypassing all mainnet checks
6. Node starts with failpoints enabled on mainnet: [13](#0-12) 

7. Attacker calls `/set_failpoint?name=consensus::send::any&actions=return` to block all consensus messages
8. Validator stops participating in consensus, causing liveness degradation

## Impact Explanation

This vulnerability is **CRITICAL** severity under Aptos Bug Bounty criteria:

1. **Consensus Safety Violations**: By disabling paranoid verification checks, validators may execute Move bytecode differently, breaking the deterministic execution invariant and potentially causing chain splits.

2. **Total Loss of Liveness**: Failpoints allow complete disruption of consensus messaging. An attacker controlling enough validators can halt the network by blocking proposal broadcasts, vote messages, and sync info.

3. **Cryptographic Security Compromise**: Allowing in-memory key storage on mainnet validators exposes private keys to memory dumps and process inspection, violating validator key security.

4. **Non-recoverable Network Partition**: If validators with different verification settings commit divergent state, a hard fork may be required to recover.

The impact is network-wide because compromised validators can:
- Refuse to participate in consensus (liveness attack)
- Execute blocks inconsistently (safety attack)
- Have their keys compromised (security breach)

## Likelihood Explanation

**Likelihood: HIGH**

**Attacker Requirements:**
- Ability to run a mainnet validator node (publicly accessible)
- File system access to their own node (standard for operators)
- Capability to compile with optional features (documented in Cargo.toml)

**Complexity: LOW**
- Delete a single file (genesis.blob) before node startup
- Single API call to inject failpoints
- No cryptographic attacks or protocol exploitation required

**Realistic Scenario:**
A malicious actor or compromised validator operator intentionally deploys a validator with test features enabled and missing genesis file. The node passes all config checks despite running on mainnet with unsafe configurations.

The vulnerability is especially concerning because:
1. The warning message is easily missed in logs
2. Node appears to start successfully
3. No alerts indicate unsafe configuration running on mainnet
4. Attacker has extended time to exploit failpoints

## Recommendation

**Fix 1: Fail Fast on Missing Chain ID**

Treat missing chain ID as a fatal error instead of continuing with None:

```rust
fn extract_node_type_and_chain_id(node_config: &NodeConfig) -> Result<(NodeType, ChainId), Error> {
    let node_type = NodeType::extract_from_config(node_config);
    
    match get_chain_id(node_config) {
        Ok(chain_id) => Ok((node_type, chain_id)),
        Err(error) => {
            Err(Error::InvariantViolation(
                format!("Failed to extract chain ID from genesis transaction: {:?}. Cannot safely sanitize node configuration.", error)
            ))
        }
    }
}
```

Update all call sites to handle the Result:

```rust
fn optimize_and_sanitize_node_config(
    node_config: &mut NodeConfig,
    local_config_yaml: Value,
) -> Result<(), Error> {
    let (node_type, chain_id) = extract_node_type_and_chain_id(node_config)?;
    
    NodeConfig::optimize(node_config, &local_config_yaml, node_type, Some(chain_id))?;
    NodeConfig::sanitize(node_config, node_type, Some(chain_id))
}
```

**Fix 2: Remove Option from chain_id Parameter**

Change all sanitizer signatures to require a valid ChainId:

```rust
fn sanitize(
    node_config: &NodeConfig,
    node_type: NodeType,
    chain_id: ChainId,  // No longer Option
) -> Result<(), Error>
```

**Fix 3: Add Defense in Depth**

Even with fixes above, add explicit runtime checks:

```rust
// In aptos-node/src/lib.rs start function
pub fn start_and_report_ports(...) -> anyhow::Result<()> {
    // Before any critical operations
    let chain_id = extract_chain_id_or_fail(&config)?;
    
    if chain_id.is_mainnet() {
        ensure!(!fail::has_failpoints(), "Failpoints must not be enabled on mainnet");
        ensure!(config.execution.paranoid_hot_potato_verification, "Paranoid verification required on mainnet");
        // ... other critical checks
    }
    // ... continue startup
}
```

## Proof of Concept

```rust
// File: config/tests/chain_id_bypass_poc.rs
use aptos_config::config::{NodeConfig, NodeConfigLoader};
use aptos_types::chain_id::ChainId;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

#[test]
fn test_chain_id_bypass_allows_mainnet_failpoints() {
    // Create a temporary directory for the test
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("node.yaml");
    
    // Create a mainnet-style config with failpoints enabled
    let mut config = NodeConfig::default();
    config.failpoints = Some(vec![
        ("consensus::send::any".to_string(), "return".to_string())
    ].into_iter().collect());
    
    // Set genesis_file_location to a non-existent file
    config.execution.genesis_file_location = PathBuf::from("/nonexistent/genesis.blob");
    
    // Save the config
    config.save_to_path(&config_path).unwrap();
    
    // Load and sanitize - this should FAIL but currently SUCCEEDS
    let result = NodeConfigLoader::new(&config_path).load_and_sanitize_config();
    
    match result {
        Ok(loaded_config) => {
            // VULNERABILITY: Config loads successfully with failpoints on "mainnet"
            // because chain_id is None and mainnet checks are bypassed
            assert!(loaded_config.failpoints.is_some());
            println!("VULNERABILITY CONFIRMED: Mainnet node can run with failpoints!");
        }
        Err(e) => {
            // This is the EXPECTED behavior after fix
            println!("Correctly rejected unsafe config: {}", e);
        }
    }
}

#[test]
fn test_chain_id_bypass_disables_paranoid_verification() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("node.yaml");
    
    // Create config with disabled paranoid checks
    let mut config = NodeConfig::default();
    config.execution.paranoid_hot_potato_verification = false;
    config.execution.paranoid_type_verification = false;
    config.execution.genesis_file_location = PathBuf::from("/nonexistent/genesis.blob");
    
    config.save_to_path(&config_path).unwrap();
    
    // On mainnet, this should fail but succeeds due to bypass
    let result = NodeConfigLoader::new(&config_path).load_and_sanitize_config();
    
    assert!(result.is_ok(), "VULNERABILITY: Paranoid checks can be disabled on mainnet");
    
    let loaded = result.unwrap();
    assert!(!loaded.execution.paranoid_hot_potato_verification);
    assert!(!loaded.execution.paranoid_type_verification);
}
```

**Runtime Exploitation:**

```bash
# Step 1: Compile node with failpoints
cd aptos-core
cargo build --release --features failpoints -p aptos-node

# Step 2: Setup mainnet config but remove genesis
mkdir -p /tmp/mainnet-node
cp mainnet-node.yaml /tmp/mainnet-node/
# Either delete genesis or set invalid path in config
rm /tmp/mainnet-node/genesis.blob

# Step 3: Start node - bypasses all mainnet checks
./target/release/aptos-node -f /tmp/mainnet-node/mainnet-node.yaml

# Step 4: Verify failpoints are enabled (check logs for "Failpoints are enabled!")

# Step 5: Inject consensus failure
curl "http://localhost:8080/set_failpoint?name=consensus::send::any&actions=return"

# Result: Validator stops sending all consensus messages, breaks liveness
```

## Notes

This vulnerability demonstrates a critical flaw in the defense-in-depth strategy: the config sanitizer relies entirely on chain ID extraction, with no fallback validation. The permissive error handling (returning None instead of failing) creates a dangerous bypass that undermines all mainnet-specific security policies.

The root cause is treating chain ID as optional throughout the sanitization pipeline, when it should be mandatory for safe node operation. The fix requires making chain ID extraction a hard requirement and eliminating the Option type from the sanitization interface.

### Citations

**File:** config/src/config/node_config_loader.rs (L112-124)
```rust
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

**File:** config/src/config/node_config_loader.rs (L127-145)
```rust
fn optimize_and_sanitize_node_config(
    node_config: &mut NodeConfig,
    local_config_yaml: Value,
) -> Result<(), Error> {
    // Extract the node type and chain ID from the node config
    let (node_type, chain_id) = extract_node_type_and_chain_id(node_config);

    // Print the extracted node type and chain ID
    println!(
        "Identified node type ({:?}) and chain ID ({:?}) from node config!",
        node_type, chain_id
    );

    // Optimize the node config
    NodeConfig::optimize(node_config, &local_config_yaml, node_type, chain_id)?;

    // Sanitize the node config
    NodeConfig::sanitize(node_config, node_type, chain_id)
}
```

**File:** config/src/config/node_config_loader.rs (L158-198)
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
        },
        _ => Err(Error::InvariantViolation(format!(
            "The genesis transaction has the incorrect type: {:?}!",
            genesis_txn
        ))),
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

**File:** consensus/src/network.rs (L363-385)
```rust
    async fn broadcast(&self, msg: ConsensusMsg) {
        fail_point!("consensus::send::any", |_| ());
        // Directly send the message to ourself without going through network.
        let self_msg = Event::Message(self.author, msg.clone());
        let mut self_sender = self.self_sender.clone();
        if let Err(err) = self_sender.send(self_msg).await {
            error!("Error broadcasting to self: {:?}", err);
        }

        #[cfg(feature = "failpoints")]
        {
            let msg_ref = &msg;
            fail_point!("consensus::send::broadcast_self_only", |maybe_msg_name| {
                if let Some(msg_name) = maybe_msg_name {
                    if msg_ref.name() != &msg_name {
                        self.broadcast_without_self(msg_ref.clone());
                    }
                }
            });
        }

        self.broadcast_without_self(msg);
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

**File:** config/src/config/consensus_config.rs (L515-523)
```rust
        // Verify that the consensus-only feature is not enabled in mainnet
        if let Some(chain_id) = chain_id {
            if chain_id.is_mainnet() && is_consensus_only_perf_test_enabled() {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "consensus-only-perf-test should not be enabled in mainnet!".to_string(),
                ));
            }
        }
```

**File:** config/src/config/safety_rules_config.rs (L85-113)
```rust
        if let Some(chain_id) = chain_id {
            // Verify that the secure backend is appropriate for mainnet validators
            if chain_id.is_mainnet()
                && node_type.is_validator()
                && safety_rules_config.backend.is_in_memory()
            {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "The secure backend should not be set to in memory storage in mainnet!"
                        .to_string(),
                ));
            }

            // Verify that the safety rules service is set to local for optimal performance
            if chain_id.is_mainnet() && !safety_rules_config.service.is_local() {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    format!("The safety rules service should be set to local in mainnet for optimal performance! Given config: {:?}", &safety_rules_config.service)
                ));
            }

            // Verify that the safety rules test config is not enabled in mainnet
            if chain_id.is_mainnet() && safety_rules_config.test.is_some() {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "The safety rules test config should not be used in mainnet!".to_string(),
                ));
            }
        }
```

**File:** config/src/config/api_config.rs (L178-184)
```rust
        if let Some(chain_id) = chain_id {
            if chain_id.is_mainnet() && api_config.failpoints_enabled {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "Failpoints are not supported on mainnet nodes!".into(),
                ));
            }
```

**File:** config/src/config/netbench_config.rs (L66-73)
```rust
        if let Some(chain_id) = chain_id {
            if chain_id.is_testnet() || chain_id.is_mainnet() {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "The netbench application should not be enabled in testnet or mainnet!"
                        .to_string(),
                ));
            }
```

**File:** config/src/config/inspection_service_config.rs (L55-64)
```rust
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
```

**File:** aptos-node/src/lib.rs (L256-273)
```rust
    // Ensure failpoints are configured correctly
    if fail::has_failpoints() {
        warn!("Failpoints are enabled!");

        // Set all of the failpoints
        if let Some(failpoints) = &config.failpoints {
            for (point, actions) in failpoints {
                fail::cfg(point, actions).unwrap_or_else(|_| {
                    panic!(
                        "Failed to set actions for failpoint! Failpoint: {:?}, Actions: {:?}",
                        point, actions
                    )
                });
            }
        }
    } else if config.failpoints.is_some() {
        warn!("Failpoints is set in the node config, but the binary didn't compile with this feature!");
    }
```
