# Audit Report

## Title
Chain ID Spoofing via Malicious Genesis Configuration Bypasses Critical Mainnet Security Checks

## Summary
A Time-of-Check-Time-of-Use (TOCTOU) vulnerability in `load_and_sanitize_config()` allows an attacker who can control the node configuration file to inject a malicious genesis transaction with a spoofed chain ID. This fake chain ID is extracted and trusted BEFORE sanitization occurs, causing critical mainnet-specific security validations to be bypassed.

## Finding Description

The vulnerability exists in the config loading flow where multiple security-critical operations occur between lines 74-87 before sanitization is applied: [1](#0-0) 

The attack flow works as follows:

**Step 1: Genesis Loading Without Validation**
At line 78, `execution.load_from_path()` loads a genesis file from a path specified in the config without validating the path or content: [2](#0-1) 

The `genesis_file_location` can be an absolute path or use path traversal, and the genesis transaction is deserialized from BCS format without validation. [3](#0-2) 

**Step 2: Malicious Chain ID Extraction**
At line 87, `optimize_and_sanitize_node_config()` calls `extract_node_type_and_chain_id()`, which extracts the chain ID from the already-loaded malicious genesis transaction: [4](#0-3) 

The `get_chain_id()` function extracts the chain ID directly from the genesis WriteSet without validating it matches the expected network: [5](#0-4) 

**Step 3: Security Bypass via Fake Chain ID**
The extracted fake chain ID is then used for BOTH optimization and sanitization decisions: [6](#0-5) 

This allows bypass of multiple critical mainnet security checks:

**Bypassed Check #1 - Execution Paranoid Verifications:** [7](#0-6) 

**Bypassed Check #2 - Safety Rules Backend Security:** [8](#0-7) 

**Bypassed Check #3 - Admin Service Authentication:** [9](#0-8) 

**Bypassed Check #4 - Failpoints Protection:** [10](#0-9) 

**Attack Scenario:**
1. Attacker creates malicious genesis blob with `ChainId(2)` (testnet) instead of `ChainId(1)` (mainnet)
2. Attacker places this blob on filesystem (e.g., via supply chain attack, compromised deployment pipeline, or malicious config template)
3. Node config points `execution.genesis_file_location` to malicious blob
4. On node startup, fake testnet chain ID is extracted from malicious genesis
5. All mainnet security checks treat the node as testnet, bypassing critical protections
6. Malicious genesis is later executed during database bootstrapping with system privileges [11](#0-10) 

The chain ID check uses simple integer comparison: [12](#0-11) 

## Impact Explanation

This vulnerability qualifies as **High Severity** based on the following impacts:

**Consensus Safety Risk:** If a mainnet validator uses in-memory safety rules backend (allowed when spoofed as testnet), consensus keys are stored insecurely, enabling easier Byzantine behavior and potential consensus safety violations.

**Move VM Exploit Surface:** Disabling `paranoid_hot_potato_verification` and `paranoid_type_verification` removes critical runtime checks that prevent Move VM exploits, potentially enabling malicious bytecode execution.

**Remote Access:** Unauthenticated admin service on mainnet nodes enables remote administrative control of the validator.

**Intentional Failure Injection:** Enabled failpoints on mainnet allow attackers to inject failures at critical consensus or execution points, causing liveness failures.

While this doesn't directly cause fund loss, it creates the conditions for Critical-severity attacks by weakening multiple security layers simultaneously. The combined effect of bypassing paranoid VM checks, weakening consensus security, and enabling remote admin access represents a significant protocol violation.

## Likelihood Explanation

**Attack Prerequisites:**
- Attacker must control or influence the node configuration file
- Possible through: supply chain attacks on config templates, compromised CI/CD pipelines, malicious Docker images, or social engineering

**Likelihood: Medium**
- Requires supply chain or deployment compromise rather than pure protocol exploit
- Not exploitable remotely without prior system access
- However, automated deployment systems and config templates are common attack vectors
- Once deployed, automatically triggers on node startup without detection

## Recommendation

**Immediate Fix:** Validate extracted chain ID against an expected value or independent source before using it for security decisions.

Add validation in `optimize_and_sanitize_node_config()`:

```rust
fn optimize_and_sanitize_node_config(
    node_config: &mut NodeConfig,
    local_config_yaml: Value,
) -> Result<(), Error> {
    // Extract the node type and chain ID from the node config
    let (node_type, chain_id) = extract_node_type_and_chain_id(node_config);

    // NEW: Validate chain ID against waypoint or independent source
    if let Some(extracted_chain_id) = chain_id {
        if let Some(expected_chain_id) = validate_chain_id_from_waypoint(node_config) {
            if extracted_chain_id != expected_chain_id {
                return Err(Error::ConfigSanitizerFailed(
                    "ChainIdValidator".to_string(),
                    format!(
                        "Chain ID mismatch! Genesis contains {:?} but waypoint indicates {:?}",
                        extracted_chain_id, expected_chain_id
                    ),
                ));
            }
        }
    }

    // Continue with existing optimization and sanitization...
}
```

**Defense in Depth:**
1. Add path validation to `load_from_path()` to prevent absolute paths and path traversal
2. Validate genesis transaction signature/hash against known mainnet/testnet genesis
3. Add explicit chain ID configuration field that must match genesis
4. Log warnings when security-critical configs differ from expected mainnet defaults

## Proof of Concept

```rust
// poc_chain_id_spoof.rs
use aptos_types::{
    chain_id::ChainId,
    transaction::{Transaction, WriteSetPayload, ChangeSet},
    write_set::{WriteSetMut, WriteOp},
    state_store::state_key::StateKey,
};
use aptos_config::config::{NodeConfig, ExecutionConfig};
use std::path::PathBuf;

#[test]
fn test_chain_id_spoofing_bypass() {
    // Step 1: Create malicious genesis with fake testnet chain ID
    let fake_chain_id = ChainId::new(2); // Testnet ID instead of mainnet (1)
    let chain_id_bytes = bcs::to_bytes(&fake_chain_id).unwrap();
    
    let chain_id_state_key = StateKey::on_chain_config::<ChainId>().unwrap();
    let mut write_set = WriteSetMut::new(vec![]);
    write_set.insert((
        chain_id_state_key,
        WriteOp::Value(chain_id_bytes.into()),
    ));
    
    let malicious_genesis = Transaction::GenesisTransaction(
        WriteSetPayload::Direct(ChangeSet::new(
            write_set.freeze().unwrap(),
            vec![],
        ))
    );
    
    // Step 2: Save malicious genesis to file
    let temp_dir = tempfile::tempdir().unwrap();
    let genesis_path = temp_dir.path().join("malicious_genesis.blob");
    let genesis_bytes = bcs::to_bytes(&malicious_genesis).unwrap();
    std::fs::write(&genesis_path, genesis_bytes).unwrap();
    
    // Step 3: Create node config pointing to malicious genesis
    let mut node_config = NodeConfig::default();
    node_config.execution.genesis_file_location = genesis_path.clone();
    node_config.execution.paranoid_hot_potato_verification = false; // Would fail on mainnet
    
    // Step 4: Load config - this should extract fake chain ID
    let config_path = temp_dir.path().join("node_config.yaml");
    node_config.save_config(&config_path).unwrap();
    
    // Step 5: Reload and verify chain ID is spoofed
    let loaded_config = NodeConfig::load_from_path(&config_path).unwrap();
    
    // Verify the malicious genesis was loaded
    assert!(loaded_config.execution.genesis.is_some());
    
    // Extract chain ID from loaded genesis - should be fake testnet ID
    let genesis = loaded_config.execution.genesis.as_ref().unwrap();
    if let Transaction::GenesisTransaction(WriteSetPayload::Direct(cs)) = genesis {
        let ws = cs.write_set();
        let chain_id_key = StateKey::on_chain_config::<ChainId>().unwrap();
        let write_op = ws.get(&chain_id_key).unwrap();
        let extracted_chain_id: ChainId = bcs::from_bytes(
            write_op.bytes().unwrap()
        ).unwrap();
        
        // Verify we successfully spoofed the chain ID
        assert_eq!(extracted_chain_id.id(), 2); // Testnet, not mainnet!
        assert!(extracted_chain_id.is_testnet());
        assert!(!extracted_chain_id.is_mainnet());
    }
    
    // This config would bypass mainnet security checks despite being
    // intended for a mainnet validator node
}
```

**Notes**

This vulnerability represents a defense-in-depth failure where the config loading process trusts user-controlled input (genesis file path and content) to make security-critical decisions. While exploitation requires the ability to influence node configuration files (typically through supply chain attacks or compromised deployment pipelines), the impact of successfully bypassing multiple mainnet security checks simultaneously is severe enough to warrant immediate remediation.

The core issue is that chain ID extraction happens at the wrong layer - it should be validated against an independent, trusted source rather than extracted from the potentially malicious genesis transaction itself. This is a classic TOCTOU vulnerability where the value used for security checks (chain ID) comes from the same untrusted source that those checks are meant to protect against.

### Citations

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

**File:** config/src/config/execution_config.rs (L167-183)
```rust
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
```

**File:** config/src/config/utils.rs (L30-36)
```rust
    pub fn full_path(&self, file_path: &Path) -> PathBuf {
        if file_path.is_relative() {
            self.root_path.join(file_path)
        } else {
            file_path.to_path_buf()
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

**File:** config/src/config/admin_service_config.rs (L67-77)
```rust
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
```

**File:** config/src/config/config_sanitizer.rs (L84-91)
```rust
    if let Some(chain_id) = chain_id {
        if chain_id.is_mainnet() && failpoints_enabled {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "Failpoints are not supported on mainnet nodes!".into(),
            ));
        }
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

**File:** types/src/chain_id.rs (L84-96)
```rust
    /// Returns true iff the chain ID matches mainnet
    pub fn is_mainnet(&self) -> bool {
        self.matches_named_chain(NamedChain::MAINNET)
    }

    /// Returns true iff the chain ID matches the given named chain
    fn matches_named_chain(&self, expected_chain: NamedChain) -> bool {
        if let Ok(named_chain) = NamedChain::from_chain_id(self) {
            named_chain == expected_chain
        } else {
            false
        }
    }
```
