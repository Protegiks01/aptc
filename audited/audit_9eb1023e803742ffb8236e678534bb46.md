# Audit Report

## Title
Genesis Cache Poisoning Enables Security Bypass via Chain ID Mismatch Between Config Optimization and Runtime

## Summary
The chain ID extracted from the genesis file during config optimization can differ from the chain ID stored in the database at runtime, allowing an attacker who replaces the genesis file to bypass mainnet security controls. Config optimizers automatically enable security-sensitive endpoints (inspection service, admin service) based on the poisoned chain ID, while the node continues to operate on the actual mainnet network.

## Finding Description

The vulnerability exists in the node startup sequence where chain ID is extracted at two different stages using two different sources:

**Stage 1 - Config Optimization (uses genesis file):** [1](#0-0) 

The `get_chain_id()` function reads the genesis transaction from disk and extracts the chain ID. This chain ID is then used by config sanitizers and optimizers: [2](#0-1) 

**Stage 2 - Runtime Execution (uses database):** [3](#0-2) 

After the database is opened, the actual chain ID is fetched from the on-chain state: [4](#0-3) 

**The Attack Vector:**

Config optimizers make security-critical decisions based on the genesis file chain ID. For example, the `InspectionServiceConfig` optimizer automatically enables all debugging endpoints for non-mainnet nodes: [5](#0-4) 

Similarly, the `AdminServiceConfig` optimizer enables the admin service for non-mainnet nodes: [6](#0-5) 

**Exploitation Path:**

1. A mainnet validator is running with genesis.blob (chain_id=1, mainnet) and a database containing mainnet state
2. The validator's config file uses the default configuration without explicitly setting inspection_service or admin_service fields (typical for validators using base configs): [7](#0-6) 

3. Attacker replaces `/opt/aptos/genesis/genesis.blob` with testnet genesis (chain_id=2)
4. On node restart:
   - Config loader extracts chain_id=2 from poisoned genesis file
   - Optimizer sees testnet chain ID and enables `expose_configuration=true`, `expose_identity_information=true`, etc.
   - Optimizer enables `admin_service.enabled=true`
   - Database opens with mainnet state (chain_id=1)
   - Node runs on mainnet but with testnet security settings

5. Result: Mainnet validator exposes sensitive endpoints that should be disabled

## Impact Explanation

**Medium Severity** - This vulnerability qualifies as "Limited funds loss or manipulation" and "State inconsistencies requiring intervention" per the Aptos bug bounty criteria:

1. **Information Disclosure:** The inspection service `/configuration` endpoint exposes the full node configuration when enabled: [8](#0-7) 

2. **Admin Service Exposure:** The admin service provides privileged access to node operations without authentication requirements on non-mainnet networks

3. **Attack Surface Expansion:** Exposed endpoints can be leveraged for reconnaissance or further exploitation

4. **Validator-Specific Impact:** The sanitizer explicitly prevents mainnet validators from exposing configuration: [9](#0-8) 

This protection is bypassed by the chain ID mismatch.

## Likelihood Explanation

**Medium Likelihood:**

**Attack Requirements:**
- File system write access to replace `/opt/aptos/genesis/genesis.blob`
- Ability to trigger node restart
- Target node must use default config (no explicit inspection_service settings)

**Realistic Attack Scenarios:**
1. Compromised validator infrastructure (e.g., through supply chain attack, insider threat, or server compromise)
2. Misconfigured deployment pipelines that could be exploited to replace genesis files
3. Kubernetes/container environments where genesis files are mounted from external sources

**Mitigating Factors:**
- Requires elevated file system access
- Most security-conscious operators may explicitly set inspection_service config
- Database bootstrap skip mechanism prevents complete genesis replacement: [10](#0-9) 

## Recommendation

Implement chain ID validation at runtime to ensure the genesis file matches the database state:

```rust
// In config/src/config/node_config_loader.rs, after line 145:
pub fn validate_chain_id_consistency(
    node_config: &NodeConfig,
    db_rw: &DbReaderWriter,
) -> Result<(), Error> {
    // Extract chain ID from genesis file
    let genesis_chain_id = get_chain_id(node_config)?;
    
    // Fetch chain ID from database if it exists
    if let Ok(db_chain_id) = utils::fetch_chain_id(db_rw) {
        if genesis_chain_id != db_chain_id {
            return Err(Error::InvariantViolation(format!(
                "Chain ID mismatch detected! Genesis file has chain_id={}, but database has chain_id={}. This may indicate genesis file poisoning.",
                genesis_chain_id.id(),
                db_chain_id.id()
            )));
        }
    }
    
    Ok(())
}
```

Then call this validation in `aptos-node/src/lib.rs` after opening the database:

```rust
// After line 713 in aptos-node/src/lib.rs:
let chain_id = utils::fetch_chain_id(&db_rw)?;

// Add validation:
if let Err(e) = node_config_loader::validate_chain_id_consistency(&node_config, &db_rw) {
    panic!("Critical security error: {}", e);
}
```

**Additional Hardening:**
1. Consider making inspection_service and admin_service settings mandatory for mainnet validators
2. Add integrity checks (checksums/signatures) for genesis.blob files
3. Log chain ID extraction prominently to aid in detecting anomalies

## Proof of Concept

```rust
#[cfg(test)]
mod genesis_poisoning_test {
    use super::*;
    use aptos_types::chain_id::ChainId;
    
    #[test]
    fn test_chain_id_mismatch_enables_inspection_endpoints() {
        // Create a mainnet-style config without explicit inspection_service settings
        let mut node_config = NodeConfig::default();
        
        // Simulate config optimization with TESTNET chain ID (poisoned genesis)
        let local_config_yaml = serde_yaml::from_str("{}").unwrap();
        let modified = InspectionServiceConfig::optimize(
            &mut node_config,
            &local_config_yaml,
            NodeType::Validator,
            Some(ChainId::testnet()), // Genesis file says testnet
        ).unwrap();
        
        assert!(modified, "Config should be modified");
        assert!(node_config.inspection_service.expose_configuration,
            "Configuration endpoint should be exposed for testnet");
        
        // In reality, the node would run with mainnet chain ID from database
        // This demonstrates the security bypass: mainnet node with testnet security settings
    }
    
    #[test]
    fn test_admin_service_enabled_for_non_mainnet() {
        let mut node_config = NodeConfig::default();
        
        let local_config_yaml = serde_yaml::from_str("{}").unwrap();
        AdminServiceConfig::optimize(
            &mut node_config,
            &local_config_yaml,
            NodeType::Validator,
            Some(ChainId::testnet()), // Poisoned genesis
        ).unwrap();
        
        assert_eq!(node_config.admin_service.enabled, Some(true),
            "Admin service should be enabled for non-mainnet");
        
        // This would fail mainnet sanitization if chain ID was correct:
        // AdminServiceConfig::sanitize(&node_config, NodeType::Validator, 
        //     Some(ChainId::mainnet())).unwrap_err();
    }
}
```

**Notes:**

The vulnerability stems from the temporal separation between config optimization (which uses the genesis file) and runtime chain ID fetching (which uses the database). The genesis transaction is loaded early during config processing but the database is not yet open, preventing any validation of consistency. This creates a window for chain ID poisoning that bypasses network-specific security controls designed to protect mainnet validators.

### Citations

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

**File:** aptos-node/src/lib.rs (L703-716)
```rust
    // Set up the storage database and any RocksDB checkpoints
    let (db_rw, backup_service, genesis_waypoint, indexer_db_opt, update_receiver) =
        storage::initialize_database_and_checkpoints(&mut node_config)?;

    admin_service.set_aptos_db(db_rw.clone().into());

    // Set the Aptos VM configurations
    utils::set_aptos_vm_configurations(&node_config);

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

**File:** config/src/config/inspection_service_config.rs (L71-109)
```rust
impl ConfigOptimizer for InspectionServiceConfig {
    fn optimize(
        node_config: &mut NodeConfig,
        local_config_yaml: &Value,
        _node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<bool, Error> {
        let inspection_service_config = &mut node_config.inspection_service;
        let local_inspection_config_yaml = &local_config_yaml["inspection_service"];

        // Enable all endpoints for non-mainnet nodes (to aid debugging)
        let mut modified_config = false;
        if let Some(chain_id) = chain_id {
            if !chain_id.is_mainnet() {
                if local_inspection_config_yaml["expose_configuration"].is_null() {
                    inspection_service_config.expose_configuration = true;
                    modified_config = true;
                }

                if local_inspection_config_yaml["expose_identity_information"].is_null() {
                    inspection_service_config.expose_identity_information = true;
                    modified_config = true;
                }

                if local_inspection_config_yaml["expose_peer_information"].is_null() {
                    inspection_service_config.expose_peer_information = true;
                    modified_config = true;
                }

                if local_inspection_config_yaml["expose_system_information"].is_null() {
                    inspection_service_config.expose_system_information = true;
                    modified_config = true;
                }
            }
        }

        Ok(modified_config)
    }
}
```

**File:** config/src/config/admin_service_config.rs (L84-100)
```rust
impl ConfigOptimizer for AdminServiceConfig {
    fn optimize(
        node_config: &mut NodeConfig,
        _local_config_yaml: &Value,
        _node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<bool, Error> {
        let mut modified_config = false;

        if node_config.admin_service.enabled.is_none() {
            // Only enable the admin service if the chain is not mainnet
            let admin_service_enabled = if let Some(chain_id) = chain_id {
                !chain_id.is_mainnet()
            } else {
                false // We cannot determine the chain ID, so we disable the admin service
            };
            node_config.admin_service.enabled = Some(admin_service_enabled);
```

**File:** terraform/helm/aptos-node/files/configs/validator-base.yaml (L1-48)
```yaml
###
### This is the base validator NodeConfig to work with this helm chart
### Additional overrides to the NodeConfig can be specified via .Values.validator.config or .Values.overrideNodeConfig
###
base:
  role: validator
  waypoint:
    from_file: /opt/aptos/genesis/waypoint.txt

consensus:
  safety_rules:
    service:
      type: "local"
    backend:
      type: "on_disk_storage"
      path: secure-data.json
      namespace: ~
    initial_safety_rules_config:
      from_file:
        waypoint:
          from_file: /opt/aptos/genesis/waypoint.txt
        identity_blob_path: /opt/aptos/genesis/validator-identity.yaml

execution:
  genesis_file_location: /opt/aptos/genesis/genesis.blob

full_node_networks:
  - network_id:
      private: "vfn"
    listen_address: "/ip4/0.0.0.0/tcp/6181"
    identity:
      type: "from_config"
      key: "b0f405a3e75516763c43a2ae1d70423699f34cd68fa9f8c6bb2d67aa87d0af69"
      peer_id: "00000000000000000000000000000000d58bc7bb154b38039bc9096ce04e1237"

storage:
  rocksdb_configs:
    enable_storage_sharding: true

api:
  enabled: true
  address: "0.0.0.0:8080"

validator_network:
  discovery_method: "onchain"
  identity:
    type: "from_file"
    path: /opt/aptos/genesis/validator-identity.yaml
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

**File:** execution/executor/src/db_bootstrapper/mod.rs (L48-71)
```rust
pub fn maybe_bootstrap<V: VMBlockExecutor>(
    db: &DbReaderWriter,
    genesis_txn: &Transaction,
    waypoint: Waypoint,
) -> Result<Option<LedgerInfoWithSignatures>> {
    let ledger_summary = db.reader.get_pre_committed_ledger_summary()?;
    // if the waypoint is not targeted with the genesis txn, it may be either already bootstrapped, or
    // aiming for state sync to catch up.
    if ledger_summary.version().map_or(0, |v| v + 1) != waypoint.version() {
        info!(waypoint = %waypoint, "Skip genesis txn.");
        return Ok(None);
    }

    let committer = calculate_genesis::<V>(db, ledger_summary, genesis_txn)?;
    ensure!(
        waypoint == committer.waypoint(),
        "Waypoint verification failed. Expected {:?}, got {:?}.",
        waypoint,
        committer.waypoint(),
    );
    let ledger_info = committer.output.ledger_info_opt.clone();
    committer.commit()?;
    Ok(ledger_info)
}
```
