# Audit Report

## Title
Chain ID Validation Bypass Allows Unauthenticated Admin Service Access on Mainnet Nodes

## Summary
The `AdminServiceConfig::sanitize()` function fails to enforce authentication requirements on mainnet when the chain ID cannot be extracted from the genesis transaction. A malicious node operator can bypass mainnet authentication checks by omitting or providing an invalid genesis file, enabling unauthenticated access to sensitive admin endpoints that expose consensus databases, mempool state, and profiling information.

## Finding Description

The vulnerability exists in the chain ID validation logic used during node configuration sanitization. The security guarantee being broken is: **mainnet nodes must always require authentication for admin service access**. [1](#0-0) 

The `sanitize()` function only enforces authentication when `chain_id` is `Some(chain_id)`. If `chain_id` is `None`, the check is completely bypassed and returns `Ok(())` without error.

The chain ID is extracted during config loading: [2](#0-1) 

When `get_chain_id()` fails, the system prints a warning but continues with `chain_id = None`: [3](#0-2) 

The `get_chain_id()` function fails when: [4](#0-3) 

This returns `None` if `config.execution.genesis` is not set.

The genesis loading logic allows empty genesis file locations: [5](#0-4) 

When no genesis is provided, the node continues without error: [6](#0-5) 

The AdminService exposes sensitive endpoints without authentication when `authentication_configs` is empty: [7](#0-6) 

**Attack Path:**

1. A malicious mainnet node operator modifies their config file:
   - Set `admin_service.enabled = true`
   - Set `admin_service.authentication_configs = []` (empty)
   - Set `execution.genesis_file_location = ""` OR point to non-existent file

2. The operator restarts their node (which already has a bootstrapped database)

3. During startup:
   - `ExecutionConfig::load_from_path()` skips genesis loading (empty path) or fails (invalid path)
   - `get_chain_id()` returns error because `genesis` is `None`
   - `extract_node_type_and_chain_id()` continues with `chain_id = None`
   - `AdminServiceConfig::sanitize()` bypasses mainnet check (no error raised)

4. The node starts successfully with an unauthenticated admin service on port 9102

5. The attacker now has unauthenticated access to:
   - `/debug/consensus/consensusdb` - dump consensus database
   - `/debug/consensus/quorumstoredb` - dump quorum store database
   - `/debug/consensus/block` - dump specific blocks
   - `/debug/mempool/parking-lot/addresses` - mempool state
   - `/profilez` - CPU profiling (Linux only)
   - `/threadz` - thread dumps (Linux only)
   - `/malloc/stats` and `/malloc/dump_profile` - memory profiling (Unix only)

## Impact Explanation

This is **HIGH SEVERITY** based on the Aptos bug bounty criteria. The vulnerability enables:

1. **Information Disclosure**: Unauthorized access to consensus databases reveals sensitive validator operations, voting patterns, and block proposal information that should be restricted.

2. **Operational Security Breach**: Profiling and debugging endpoints expose internal node state, memory layouts, and execution profiles that could be used to identify additional vulnerabilities or optimize DoS attacks.

3. **Network-Wide Risk**: If multiple mainnet validators are compromised this way, attackers gain comprehensive visibility into the consensus layer's operation, potentially enabling more sophisticated attacks.

While this doesn't directly cause loss of funds or consensus violations, it represents a significant protocol violation and access control failure that weakens the security posture of the entire network.

## Likelihood Explanation

**Likelihood: MEDIUM**

The vulnerability is easily exploitable by any node operator with the following characteristics:

- **Low Complexity**: Requires only config file modification (single line changes)
- **No Special Privileges**: Any node operator can exploit this on their own node
- **Works on Existing Nodes**: Doesn't require fresh setup, works on nodes with existing databases
- **Stealthy**: The warning message is easy to ignore among normal startup logs

However, the impact is limited to:
- Only affects the specific node where the config is modified (not network-wide propagation)
- Requires network access to the admin service port (default 9102)
- Legitimate operators unlikely to accidentally trigger this (requires intentional config manipulation)

## Recommendation

Fix the `sanitize()` function to fail when chain ID cannot be determined for nodes with admin service enabled:

```rust
impl ConfigSanitizer for AdminServiceConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();

        if node_config.admin_service.enabled == Some(true) {
            // FIXED: Require chain_id to be present when admin service is enabled
            let chain_id = chain_id.ok_or_else(|| {
                Error::ConfigSanitizerFailed(
                    sanitizer_name.clone(),
                    "Admin service is enabled but chain ID cannot be determined. Ensure genesis file is configured correctly.".into(),
                )
            })?;
            
            if chain_id.is_mainnet()
                && node_config.admin_service.authentication_configs.is_empty()
            {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "Must enable authentication for AdminService on mainnet.".into(),
                ));
            }
        }

        Ok(())
    }
}
```

Additionally, consider requiring genesis file presence for mainnet nodes in `ExecutionConfig::sanitize()`.

## Proof of Concept

```rust
#[cfg(test)]
mod exploit_test {
    use super::*;
    use crate::config::{NodeConfig, AdminServiceConfig};
    
    #[test]
    fn test_chain_id_bypass_vulnerability() {
        // Create a mainnet-style node config with admin service enabled
        // but NO authentication configured
        let node_config = NodeConfig {
            admin_service: AdminServiceConfig {
                enabled: Some(true),
                authentication_configs: vec![], // EMPTY - no auth!
                ..Default::default()
            },
            execution: ExecutionConfig {
                genesis_file_location: PathBuf::new(), // EMPTY - no genesis!
                ..Default::default()
            },
            ..Default::default()
        };
        
        // Sanitize with chain_id = None (simulating failed genesis loading)
        // This SHOULD fail for a mainnet node, but it doesn't!
        let result = AdminServiceConfig::sanitize(
            &node_config, 
            NodeType::Validator, 
            None  // ← Chain ID is None because genesis couldn't be loaded
        );
        
        // VULNERABILITY: Sanitizer passes when it should fail!
        assert!(result.is_ok()); // ← This assertion passes, proving the bypass
        
        // In reality, this node would be running mainnet (chain_id=1)
        // but the sanitizer couldn't detect it, allowing unauthenticated admin access
    }
    
    #[test]
    fn test_proper_mainnet_detection_blocks_unauthenticated_admin() {
        // Same config as above
        let node_config = NodeConfig {
            admin_service: AdminServiceConfig {
                enabled: Some(true),
                authentication_configs: vec![],
                ..Default::default()
            },
            ..Default::default()
        };
        
        // With proper chain_id detection (Some(mainnet)), sanitizer correctly fails
        let result = AdminServiceConfig::sanitize(
            &node_config,
            NodeType::Validator,
            Some(ChainId::mainnet())  // ← Proper chain ID provided
        );
        
        // This correctly fails with authentication error
        assert!(result.is_err());
    }
}
```

**Notes**

The vulnerability specifically exploits the `Option<ChainId>` pattern where `None` is treated as "unknown/skip validation" rather than "error condition." This is a classic mistake in optional validation where the absence of information is incorrectly treated as permissive rather than restrictive. The fix ensures that security-critical validations fail-closed (deny by default) when required information is unavailable.

### Citations

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

**File:** config/src/utils.rs (L220-222)
```rust
pub fn get_genesis_txn(config: &NodeConfig) -> Option<&Transaction> {
    config.execution.genesis.as_ref()
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

**File:** aptos-node/src/storage.rs (L23-43)
```rust
pub(crate) fn maybe_apply_genesis(
    db_rw: &DbReaderWriter,
    node_config: &NodeConfig,
) -> Result<Option<LedgerInfoWithSignatures>> {
    // We read from the storage genesis waypoint and fallback to the node config one if it is none
    let genesis_waypoint = node_config
        .execution
        .genesis_waypoint
        .as_ref()
        .unwrap_or(&node_config.base.waypoint)
        .genesis_waypoint();
    if let Some(genesis) = get_genesis_txn(node_config) {
        let ledger_info_opt =
            maybe_bootstrap::<AptosVMBlockExecutor>(db_rw, genesis, genesis_waypoint)
                .map_err(|err| anyhow!("DB failed to bootstrap {}", err))?;
        Ok(ledger_info_opt)
    } else {
        info ! ("Genesis txn not provided! This is fine only if you don't expect to apply it. Otherwise, the config is incorrect!");
        Ok(None)
    }
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
