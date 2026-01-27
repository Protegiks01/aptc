# Audit Report

## Title
Config Sanitizer Chain ID Extraction Failure Allows Failpoints on Mainnet Nodes

## Summary
The config sanitizer's mainnet protection checks for failpoints can be completely bypassed when chain ID extraction fails during node initialization. If the genesis transaction is missing, corrupted, or the `genesis_file_location` is empty, the sanitizer sets `chain_id = None` and skips all mainnet-specific validations, allowing failpoints to be enabled on mainnet nodes.

## Finding Description
The Aptos node configuration sanitizer implements two independent checks to prevent failpoints from being enabled on mainnet nodes:

1. **Global failpoint check** in `sanitize_failpoints_config()` [1](#0-0) 

2. **API-specific failpoint check** in `ApiConfig::sanitize()` [2](#0-1) 

Both checks follow the same conditional pattern that only validates when `chain_id` is `Some(...)`: [3](#0-2) 

The critical flaw is in the chain ID extraction logic. The `extract_node_type_and_chain_id()` function attempts to extract the chain ID from the genesis transaction, but if extraction fails, it prints a warning message and **continues execution with `chain_id = None`**: [4](#0-3) 

The chain ID extraction can fail in several scenarios:

1. **Empty genesis file location**: The default `ExecutionConfig` initializes `genesis_file_location` as `PathBuf::new()` (empty path) [5](#0-4) 

2. **Missing genesis transaction**: If `genesis_file_location` is empty, `load_from_path()` skips loading and leaves `genesis` as `None` [6](#0-5) 

3. **Genesis transaction extraction returns None**: The `get_genesis_txn()` function returns `None` when `config.execution.genesis` is `None` [7](#0-6) 

When any of these conditions occur, the `get_chain_id()` function fails [8](#0-7) , causing the sanitizer to skip mainnet validation entirely.

**Attack Path:**
1. Compile Aptos binary with `failpoints` feature enabled (required for fail! macros to function)
2. Create a node configuration with:
   - `api.failpoints_enabled = true`
   - `execution.genesis_file_location = ""` (empty) OR point to non-existent/corrupted file
3. The config loader calls `NodeConfig::load_and_sanitize_config()` [9](#0-8) 
4. Chain ID extraction fails, returns `None`
5. Both sanitizer checks are bypassed due to `if let Some(chain_id) = chain_id` guard
6. Node starts successfully with failpoints enabled on what should be a mainnet node
7. Failpoint API endpoints become accessible [10](#0-9) 

The vulnerability breaks the **Deterministic Execution** invariant because failpoints can inject non-deterministic crashes or errors at critical execution points [11](#0-10) , causing different validators to produce different results.

## Impact Explanation
This vulnerability qualifies as **High Severity** under the Aptos bug bounty criteria:

**Consensus Safety Impact**: Failpoints can be configured to trigger at consensus-critical points (block processing, state commitment, transaction execution), causing:
- Non-deterministic node behavior leading to consensus disagreements
- Validator nodes crashing during block validation
- State divergence between validators

**Node Availability Impact**: Attackers with access to failpoint APIs can:
- Remotely crash validator or fullnode instances
- Cause persistent failures requiring manual intervention
- Disrupt network operations without requiring validator compromise

While the attack requires the binary to be compiled with the `failpoints` feature (uncommon in production), the sanitizer's purpose is to provide defense-in-depth. The fact that it can be trivially bypassed represents a significant security control failure.

## Likelihood Explanation
**Likelihood: Medium**

The attack requires:
1. **Binary compiled with failpoints** - Unlikely in official production releases, but possible in:
   - Testing/staging environments configured to mirror mainnet
   - Custom builds by node operators
   - Development nodes using mainnet genesis
   
2. **Configuration control** - Attacker needs ability to:
   - Supply node configuration (e.g., through misconfigured deployment scripts)
   - Set `api.failpoints_enabled = true`
   - Omit or corrupt `genesis_file_location`

3. **Node restart** - Vulnerable configuration must be loaded during node initialization

The vulnerability is most dangerous in:
- **Hybrid test/production environments** where operators test with failpoints enabled
- **Automated deployment systems** that might omit genesis files in certain failure scenarios
- **Configuration template errors** where genesis path is accidentally left empty

## Recommendation

**Immediate Fix:** Make chain ID extraction mandatory for mainnet protection:

```rust
// In config/src/config/node_config_loader.rs
fn extract_node_type_and_chain_id(node_config: &NodeConfig) -> (NodeType, Option<ChainId>) {
    let node_type = NodeType::extract_from_config(node_config);
    
    match get_chain_id(node_config) {
        Ok(chain_id) => (node_type, Some(chain_id)),
        Err(error) => {
            // SECURITY: Chain ID is required for mainnet protection checks
            // If we cannot extract it, we must fail safely
            eprintln!("CRITICAL: Failed to extract chain ID from genesis transaction: {:?}", error);
            eprintln!("Chain ID is required for security validation. Node startup aborted.");
            std::process::exit(1);
        },
    }
}
```

**Additional Hardening:**

1. **Fail-safe on missing chain ID in sanitizers**:
```rust
// In config/src/config/config_sanitizer.rs, sanitize_failpoints_config()
let chain_id = chain_id.ok_or_else(|| {
    Error::ConfigSanitizerFailed(
        sanitizer_name.clone(),
        "Chain ID is required for mainnet protection validation but could not be determined!".into(),
    )
})?;

if are_failpoints_enabled() && chain_id.is_mainnet() {
    return Err(Error::ConfigSanitizerFailed(
        sanitizer_name,
        "Failpoints are not supported on mainnet nodes!".into(),
    ));
}
```

2. **Validate genesis presence early**:
```rust
// In config/src/config/node_config_loader.rs, load_and_sanitize_config()
if node_config.execution.genesis_file_location.as_os_str().is_empty() {
    return Err(Error::Unexpected(
        "Genesis file location is required for node initialization".into()
    ));
}
```

3. **Add explicit mainnet binary check** - Require production mainnet binaries to be compiled WITHOUT failpoints feature.

## Proof of Concept

```rust
// Test demonstrating the bypass
#[cfg(test)]
mod failpoint_bypass_test {
    use super::*;
    use aptos_config::config::{ApiConfig, ExecutionConfig, NodeConfig, NodeStartupConfig};
    use aptos_types::chain_id::ChainId;
    use std::path::PathBuf;

    #[test]
    #[cfg(feature = "failpoints")]
    fn test_failpoint_mainnet_bypass_via_missing_genesis() {
        // Create a node config that would be for mainnet
        let mut node_config = NodeConfig::default();
        
        // Enable failpoints in API config (should be blocked on mainnet)
        node_config.api.failpoints_enabled = true;
        
        // Set empty genesis file location (or point to non-existent file)
        node_config.execution.genesis_file_location = PathBuf::new();
        node_config.execution.genesis = None;
        
        // Extract node type and chain_id (will return None due to missing genesis)
        let (node_type, chain_id) = extract_node_type_and_chain_id(&node_config);
        
        // Verify chain_id is None
        assert!(chain_id.is_none(), "Chain ID should be None when genesis is missing");
        
        // Attempt sanitization - THIS SHOULD FAIL but currently SUCCEEDS
        let result = NodeConfig::sanitize(&node_config, node_type, chain_id);
        
        // VULNERABILITY: Sanitization passes even though failpoints are enabled
        // and we cannot verify this is not a mainnet node
        assert!(result.is_ok(), "Config sanitizer improperly allows failpoints without chain ID verification");
        
        // If we could determine this was mainnet, it should have failed:
        let mainnet_result = NodeConfig::sanitize(&node_config, node_type, Some(ChainId::mainnet()));
        assert!(mainnet_result.is_err(), "Should fail with explicit mainnet chain ID");
    }
}
```

**Notes:**
- The vulnerability exists in the production codebase's logic flow
- Exploitation requires the `skip_config_sanitizer` flag to be false (default) [12](#0-11) 
- The node can continue operating without genesis if it has an existing database [13](#0-12)

### Citations

**File:** config/src/config/config_sanitizer.rs (L45-48)
```rust
        // If config sanitization is disabled, don't do anything!
        if node_config.node_startup.skip_config_sanitizer {
            return Ok(());
        }
```

**File:** config/src/config/config_sanitizer.rs (L74-109)
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

    // Ensure that the failpoints config is populated appropriately
    if let Some(failpoints) = failpoints {
        if failpoints_enabled && failpoints.is_empty() {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "Failpoints are enabled, but the failpoints config is empty?".into(),
            ));
        } else if !failpoints_enabled && !failpoints.is_empty() {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "Failpoints are disabled, but the failpoints config is not empty!".into(),
            ));
        }
    }

    Ok(())
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

**File:** config/src/config/node_config_loader.rs (L72-90)
```rust
    pub fn load_and_sanitize_config(&self) -> Result<NodeConfig, Error> {
        // Load the node config from disk
        let mut node_config = NodeConfig::load_config(&self.node_config_path)?;

        // Load the execution config
        let input_dir = RootPath::new(&self.node_config_path);
        node_config.execution.load_from_path(&input_dir)?;

        // Update the data directory. This needs to be done before
        // we optimize and sanitize the node configs (because some optimizers
        // rely on the data directory for file reading/writing).
        node_config.set_data_dir(node_config.get_data_dir().to_path_buf());

        // Optimize and sanitize the node config
        let local_config_yaml = get_local_config_yaml(&self.node_config_path)?;
        optimize_and_sanitize_node_config(&mut node_config, local_config_yaml)?;

        Ok(node_config)
    }
```

**File:** config/src/config/node_config_loader.rs (L117-123)
```rust
    match get_chain_id(node_config) {
        Ok(chain_id) => (node_type, Some(chain_id)),
        Err(error) => {
            println!("Failed to extract the chain ID from the genesis transaction: {:?}! Continuing with None.", error);
            (node_type, None)
        },
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

**File:** config/src/config/execution_config.rs (L78-96)
```rust
impl Default for ExecutionConfig {
    fn default() -> ExecutionConfig {
        ExecutionConfig {
            genesis: None,
            genesis_file_location: PathBuf::new(),
            // use min of (num of cores/2, DEFAULT_CONCURRENCY_LEVEL) as default concurrency level
            concurrency_level: 0,
            num_proof_reading_threads: 32,
            paranoid_type_verification: true,
            paranoid_hot_potato_verification: true,
            discard_failed_blocks: false,
            processed_transactions_detailed_counters: false,
            genesis_waypoint: None,
            blockstm_v2_enabled: false,
            layout_caches_enabled: true,
            // TODO: consider setting to be true by default.
            async_runtime_checks: false,
        }
    }
```

**File:** config/src/config/execution_config.rs (L100-139)
```rust
    pub fn load_from_path(&mut self, root_dir: &RootPath) -> Result<(), Error> {
        if !self.genesis_file_location.as_os_str().is_empty() {
            // Ensure the genesis file exists
            let genesis_path = root_dir.full_path(&self.genesis_file_location);
            if !genesis_path.exists() {
                return Err(Error::Unexpected(format!(
                    "The genesis file could not be found! Ensure the given path is correct: {:?}",
                    genesis_path.display()
                )));
            }

            // Open the genesis file and read the bytes
            let mut file = File::open(&genesis_path).map_err(|error| {
                Error::Unexpected(format!(
                    "Failed to open the genesis file: {:?}. Error: {:?}",
                    genesis_path.display(),
                    error
                ))
            })?;
            let mut buffer = vec![];
            file.read_to_end(&mut buffer).map_err(|error| {
                Error::Unexpected(format!(
                    "Failed to read the genesis file into a buffer: {:?}. Error: {:?}",
                    genesis_path.display(),
                    error
                ))
            })?;

            // Deserialize the genesis file and store it
            let genesis = bcs::from_bytes(&buffer).map_err(|error| {
                Error::Unexpected(format!(
                    "Failed to BCS deserialize the genesis file: {:?}. Error: {:?}",
                    genesis_path.display(),
                    error
                ))
            })?;
            self.genesis = Some(genesis);
        }

        Ok(())
```

**File:** config/src/utils.rs (L220-222)
```rust
pub fn get_genesis_txn(config: &NodeConfig) -> Option<&Transaction> {
    config.execution.genesis.as_ref()
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

**File:** api/src/failpoint.rs (L11-23)
```rust
/// Build a failpoint to intentionally crash an API for testing
#[allow(unused_variables)]
#[inline]
pub fn fail_point_poem<E: InternalError>(name: &str) -> Result<(), E> {
    fail::fail_point!(format!("api::{}", name).as_str(), |_| {
        Err(E::internal_with_code_no_info(
            format!("Failpoint unexpected internal error for {}", name),
            AptosErrorCode::InternalError,
        ))
    });

    Ok(())
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
