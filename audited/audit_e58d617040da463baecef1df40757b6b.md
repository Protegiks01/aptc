# Audit Report

## Title
AdminService Sanitizer Bypass Allows Unauthenticated Mainnet Access via ChainId Extraction Failure

## Summary
The `AdminServiceConfig::sanitize()` function can be bypassed when the chain ID extraction fails, allowing a mainnet node to start with an unauthenticated AdminService that exposes sensitive debugging endpoints. This violates the explicit security requirement that authentication must be enabled for AdminService on mainnet.

## Finding Description

The vulnerability exists in the `sanitize()` function's authentication enforcement logic: [1](#0-0) 

The sanitizer only checks for mainnet authentication when `chain_id` is `Some(chain_id)`. If `chain_id` is `None`, the check at line 68 fails pattern matching and the entire mainnet authentication validation is skipped, allowing the function to return `Ok(())`.

The `chain_id` parameter can legitimately be `None` when the `extract_node_type_and_chain_id()` function fails to extract the chain ID from the genesis transaction: [2](#0-1) 

The `get_chain_id()` function can fail in several scenarios: [3](#0-2) 

Critically, when `genesis_file_location` is empty (which is the default), the genesis transaction is never loaded: [4](#0-3) 

With an empty `genesis_file_location` (default value): [5](#0-4) 

The node can still start without genesis: [6](#0-5) 

**Attack Path:**
1. Operator configures mainnet node with `admin_service.enabled: true` and `authentication_configs: []`
2. The `genesis_file_location` is not set (empty PathBuf) or points to invalid/corrupted file
3. During config loading, `get_chain_id()` fails and returns an error
4. `extract_node_type_and_chain_id()` catches the error and returns `(node_type, None)`
5. `AdminServiceConfig::sanitize()` receives `chain_id = None`
6. The pattern match `if let Some(chain_id) = chain_id` fails, skipping the mainnet authentication check
7. Node starts with unauthenticated AdminService exposing sensitive endpoints

The AdminService exposes critical debugging endpoints without authentication: [7](#0-6) 

Including consensus database dumps, block inspection, mempool data, CPU profiling, thread dumps, and memory statistics.

## Impact Explanation

**Severity: High**

This vulnerability breaks the explicit security requirement stated in the code comments: [8](#0-7) 

An attacker who discovers a misconfigured mainnet node could access sensitive debugging endpoints including:
- Consensus database dumps (`/debug/consensus/consensusdb`)
- Quorum store database dumps (`/debug/consensus/quorumstoredb`)
- Block inspection data (`/debug/consensus/block`)
- Mempool parking lot addresses (`/debug/mempool/parking-lot/addresses`)
- CPU profiling data (`/profilez`)
- Thread dumps (`/threadz`)
- Memory allocation statistics (`/malloc/stats`)

This information disclosure could:
- Reveal consensus internals and validator behavior patterns
- Expose mempool transaction details before block inclusion
- Provide reconnaissance data for planning further attacks
- Leak performance characteristics useful for DoS attacks

While this doesn't directly cause consensus violations or fund loss, it constitutes a **significant protocol violation** and **information disclosure vulnerability** that qualifies as High Severity under the Aptos bug bounty program.

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability requires operator misconfiguration but is realistic:
1. **New operators** may follow incomplete documentation and omit `genesis_file_location`
2. **Path errors** during deployment could cause genesis file loading to fail
3. **File corruption** could cause genesis deserialization to fail
4. **Explicit misconfiguration** where operators enable admin service but forget authentication

The sanitizer exists specifically to catch such misconfigurations, but its logic flaw allows the bypass. The fact that the error is only logged with `println!` rather than causing hard failure increases likelihood: [9](#0-8) 

## Recommendation

The sanitizer should fail-safe when chain_id cannot be determined. Modify the `sanitize()` function to reject any configuration where AdminService is enabled without authentication when chain_id is unknown:

```rust
fn sanitize(
    node_config: &NodeConfig,
    _node_type: NodeType,
    chain_id: Option<ChainId>,
) -> Result<(), Error> {
    let sanitizer_name = Self::get_sanitizer_name();

    if node_config.admin_service.enabled == Some(true) {
        // If we cannot determine the chain ID, treat it as potentially mainnet
        // and require authentication (fail-safe approach)
        let is_mainnet_or_unknown = match chain_id {
            Some(chain_id) => chain_id.is_mainnet(),
            None => true, // Fail-safe: require authentication when chain_id is unknown
        };

        if is_mainnet_or_unknown
            && node_config.admin_service.authentication_configs.is_empty()
        {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "Must enable authentication for AdminService on mainnet or when chain ID cannot be determined.".into(),
            ));
        }
    }

    Ok(())
}
```

Additionally, consider making chain_id extraction failure a hard error rather than continuing with `None`, or at minimum upgrade the `println!` to a warning-level log.

## Proof of Concept

```rust
#[cfg(test)]
mod test_sanitizer_bypass {
    use super::*;
    use crate::config::{AdminServiceConfig, NodeConfig};
    use aptos_config::config::config_sanitizer::ConfigSanitizer;
    use aptos_config::config::node_config_loader::NodeType;

    #[test]
    fn test_sanitizer_bypassed_with_none_chain_id() {
        // Create a node config with admin service enabled and no authentication
        let mut node_config = NodeConfig::default();
        node_config.admin_service.enabled = Some(true);
        node_config.admin_service.authentication_configs = vec![];

        // Pass None as chain_id (simulating failed genesis extraction)
        let result = AdminServiceConfig::sanitize(
            &node_config,
            NodeType::Validator,
            None, // Chain ID is None - this bypasses the check
        );

        // The sanitizer incorrectly allows this insecure configuration
        assert!(result.is_ok(), "Sanitizer should reject this but doesn't!");
        
        // For comparison, with mainnet chain_id it correctly fails:
        let result_mainnet = AdminServiceConfig::sanitize(
            &node_config,
            NodeType::Validator,
            Some(aptos_types::chain_id::ChainId::mainnet()),
        );
        assert!(result_mainnet.is_err(), "Sanitizer correctly rejects mainnet without auth");
    }

    #[test]
    fn test_node_starts_without_genesis() {
        // Create a node config with empty genesis_file_location
        let mut node_config = NodeConfig::default();
        node_config.admin_service.enabled = Some(true);
        node_config.admin_service.authentication_configs = vec![];
        // genesis_file_location defaults to empty PathBuf
        
        // Simulate the config loading process
        let (node_type, chain_id) = extract_node_type_and_chain_id(&node_config);
        
        // Chain ID will be None due to missing genesis
        assert_eq!(chain_id, None);
        
        // Sanitizer will pass despite insecure configuration
        let result = AdminServiceConfig::sanitize(&node_config, node_type, chain_id);
        assert!(result.is_ok());
    }
}
```

## Notes

The vulnerability demonstrates a fail-unsafe design pattern where the absence of information (chain_id) leads to weaker security checks rather than stronger ones. The sanitizer should adopt a fail-safe approach: when uncertain about the chain type, assume it could be mainnet and enforce the strictest security requirements.

### Citations

**File:** config/src/config/admin_service_config.rs (L21-22)
```rust
    // If empty, will allow all requests without authentication. (Not allowed on mainnet.)
    pub authentication_configs: Vec<AuthenticationConfig>,
```

**File:** config/src/config/admin_service_config.rs (L59-82)
```rust
impl ConfigSanitizer for AdminServiceConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();

        if node_config.admin_service.enabled == Some(true) {
            if let Some(chain_id) = chain_id {
                if chain_id.is_mainnet()
                    && node_config.admin_service.authentication_configs.is_empty()
                {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        "Must enable authentication for AdminService on mainnet.".into(),
                    ));
                }
            }
        }

        Ok(())
    }
}
```

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

**File:** config/src/config/execution_config.rs (L100-140)
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

**File:** crates/aptos-admin-service/src/server/mod.rs (L154-181)
```rust
        let mut authenticated = false;
        if context.config.authentication_configs.is_empty() {
            authenticated = true;
        } else {
            for authentication_config in &context.config.authentication_configs {
                match authentication_config {
                    AuthenticationConfig::PasscodeSha256(passcode_sha256) => {
                        let query = req.uri().query().unwrap_or("");
                        let query_pairs: HashMap<_, _> =
                            url::form_urlencoded::parse(query.as_bytes()).collect();
                        let passcode: Option<String> =
                            query_pairs.get("passcode").map(|p| p.to_string());
                        if let Some(passcode) = passcode {
                            if sha256::digest(passcode) == *passcode_sha256 {
                                authenticated = true;
                            }
                        }
                    },
                }
            }
        };

        if !authenticated {
            return Ok(reply_with_status(
                StatusCode::NETWORK_AUTHENTICATION_REQUIRED,
                format!("{} endpoint requires authentication.", req.uri().path()),
            ));
        }
```
