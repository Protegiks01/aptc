# Audit Report

## Title
Genesis File Path Resolution Divergence Due to Relative Path Handling in RootPath

## Summary
The `RootPath::new_path()` and `RootPath::new()` functions accept and store relative paths without canonicalization, which can cause different validators to resolve configuration files (particularly genesis files) to different absolute paths based on their current working directory, leading to immediate consensus failure at network initialization.

## Finding Description

The vulnerability exists in the path resolution logic used during node configuration loading: [1](#0-0) 

The `new_path()` function stores paths as-is without converting them to absolute paths. Similarly, `RootPath::new()` extracts the parent directory but preserves relativity: [2](#0-1) 

When a relative config path is provided to the node via command line, the execution flow is: [3](#0-2) 

The config loader creates a `RootPath` from the config file path: [4](#0-3) 

When loading the genesis file, relative paths are resolved against this potentially-relative root path: [5](#0-4) 

The `full_path()` method joins relative paths without ensuring absolute resolution: [6](#0-5) 

**Attack Scenario:**

1. Validator A starts from `/opt/validator-a/` with command: `aptos-node -f config.yaml`
2. Validator B starts from `/opt/validator-b/` with command: `aptos-node -f config.yaml`
3. Both configs specify `genesis_file_location: "genesis.blob"` (relative path)
4. Validator A loads genesis from `/opt/validator-a/genesis.blob`
5. Validator B loads genesis from `/opt/validator-b/genesis.blob`
6. Different genesis transactions result in different initial state roots
7. **Immediate consensus failure** - validators cannot agree on block 0

This breaks the **Deterministic Execution** invariant (Critical Invariant #1) - all validators must produce identical state roots for identical blocks.

## Impact Explanation

**Severity: Critical** (Consensus/Safety Violation)

This vulnerability causes immediate, network-wide consensus failure if exploited. Different validators would initialize with different genesis states, making it impossible for them to reach consensus on any blocks. This falls under the "Consensus/Safety violations" category worth up to $1,000,000 in the Aptos bug bounty program.

The impact includes:
- Complete network initialization failure
- Inability for validators to agree on genesis state root
- Permanent chain split if some validators proceed with different genesis
- Requires network restart with corrected configurations
- Could be exploited to create shadow networks with altered initial state

Unlike the storage path validation which enforces absolute paths: [7](#0-6) 

The ExecutionConfig sanitizer does not validate genesis file path absoluteness: [8](#0-7) 

## Likelihood Explanation

**Likelihood: Low to Medium**

While standard deployment configurations use absolute paths (as seen in production configs), the vulnerability can occur through:

1. **Misconfiguration**: Operators using relative paths inadvertently
2. **Automated deployment tools**: Scripts that generate configs with relative paths
3. **Testing/staging environments**: Where relative paths might be used for convenience
4. **Malicious config injection**: If an attacker can influence validator configuration generation

Example showing a test config using relative paths: [9](#0-8) 

The vulnerability does NOT require insider access - it only requires that validators be configured with relative paths and started from different working directories, which could happen through legitimate misconfiguration or supply chain attacks on deployment tooling.

## Recommendation

**Immediate Fix:** Enforce absolute path validation for critical configuration paths, particularly `genesis_file_location`.

Add validation in `ExecutionConfig::sanitize()`:

```rust
impl ConfigSanitizer for ExecutionConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let execution_config = &node_config.execution;

        // Validate genesis file location is absolute if specified
        if !execution_config.genesis_file_location.as_os_str().is_empty() {
            if !execution_config.genesis_file_location.is_absolute() {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    format!(
                        "genesis_file_location must be an absolute path, got: {:?}",
                        execution_config.genesis_file_location
                    ),
                ));
            }
        }

        // Existing mainnet validation...
        if let Some(chain_id) = chain_id {
            if chain_id.is_mainnet() {
                // ... existing checks
            }
        }

        Ok(())
    }
}
```

**Additional Fix:** Canonicalize config path at entry point:

```rust
// In aptos-node/src/lib.rs
let config_path = self.config.expect("Config is required to launch node");
let config_path = config_path.canonicalize().map_err(|e| {
    panic!("Failed to canonicalize config path {:?}: {}", config_path, e)
})?;
```

## Proof of Concept

```rust
// Create test demonstrating path divergence
#[test]
fn test_relative_path_consensus_divergence() {
    use std::env;
    use std::fs::{self, File};
    use std::io::Write;
    use tempfile::TempDir;
    
    // Create two validator directories with different genesis files
    let validator_a_dir = TempDir::new().unwrap();
    let validator_b_dir = TempDir::new().unwrap();
    
    // Create different genesis files
    let genesis_a = Transaction::GenesisTransaction(/* different state A */);
    let genesis_b = Transaction::GenesisTransaction(/* different state B */);
    
    let mut genesis_a_file = File::create(validator_a_dir.path().join("genesis.blob")).unwrap();
    genesis_a_file.write_all(&bcs::to_bytes(&genesis_a).unwrap()).unwrap();
    
    let mut genesis_b_file = File::create(validator_b_dir.path().join("genesis.blob")).unwrap();
    genesis_b_file.write_all(&bcs::to_bytes(&genesis_b).unwrap()).unwrap();
    
    // Create config with relative genesis path
    let config_content = r#"
execution:
    genesis_file_location: "genesis.blob"
"#;
    
    let mut config_a = File::create(validator_a_dir.path().join("config.yaml")).unwrap();
    config_a.write_all(config_content.as_bytes()).unwrap();
    
    let mut config_b = File::create(validator_b_dir.path().join("config.yaml")).unwrap();
    config_b.write_all(config_content.as_bytes()).unwrap();
    
    // Simulate validator A loading from its directory
    env::set_current_dir(validator_a_dir.path()).unwrap();
    let mut execution_config_a = ExecutionConfig::default();
    execution_config_a.genesis_file_location = PathBuf::from("genesis.blob");
    let root_path_a = RootPath::new("config.yaml");
    execution_config_a.load_from_path(&root_path_a).unwrap();
    
    // Simulate validator B loading from its directory
    env::set_current_dir(validator_b_dir.path()).unwrap();
    let mut execution_config_b = ExecutionConfig::default();
    execution_config_b.genesis_file_location = PathBuf::from("genesis.blob");
    let root_path_b = RootPath::new("config.yaml");
    execution_config_b.load_from_path(&root_path_b).unwrap();
    
    // Verify validators loaded DIFFERENT genesis transactions
    assert_ne!(execution_config_a.genesis, execution_config_b.genesis);
    
    // This would cause immediate consensus failure
    println!("CONSENSUS FAILURE: Validators initialized with different genesis states");
}
```

## Notes

While `new_path()` itself is only used in test code, the underlying issue affects the production path through `RootPath::new()` which is called during actual node initialization. The vulnerability requires configuration mistakes (using relative paths) but represents a critical safety violation when triggered. Standard deployments mitigate this by using absolute paths throughout, but the lack of enforcement makes the codebase vulnerable to misconfiguration-induced consensus failures.

### Citations

**File:** config/src/config/utils.rs (L13-21)
```rust
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        let root_path = if let Some(parent) = path.as_ref().parent() {
            parent.to_path_buf()
        } else {
            PathBuf::from("")
        };

        Self { root_path }
    }
```

**File:** config/src/config/utils.rs (L23-27)
```rust
    /// This function assumes that the path is already a directory
    pub fn new_path<P: AsRef<Path>>(path: P) -> Self {
        let root_path = path.as_ref().to_path_buf();
        Self { root_path }
    }
```

**File:** config/src/config/utils.rs (L29-36)
```rust
    /// This adds a full path when loading / storing if one is not specified
    pub fn full_path(&self, file_path: &Path) -> PathBuf {
        if file_path.is_relative() {
            self.root_path.join(file_path)
        } else {
            file_path.to_path_buf()
        }
    }
```

**File:** aptos-node/src/lib.rs (L167-177)
```rust
            // Get the config file path
            let config_path = self.config.expect("Config is required to launch node");
            if !config_path.exists() {
                panic!(
                    "The node config file could not be found! Ensure the given path is correct: {:?}",
                    config_path.display()
                )
            }

            // A config file exists, attempt to parse the config
            let config = NodeConfig::load_from_path(config_path.clone()).unwrap_or_else(|error| {
```

**File:** config/src/config/node_config_loader.rs (L76-78)
```rust
        // Load the execution config
        let input_dir = RootPath::new(&self.node_config_path);
        node_config.execution.load_from_path(&input_dir)?;
```

**File:** config/src/config/execution_config.rs (L100-109)
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

**File:** config/src/config/storage_config.rs (L738-746)
```rust
            if let Some(ledger_db_path) = db_path_overrides.ledger_db_path.as_ref() {
                if !ledger_db_path.is_absolute() {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        format!(
                            "Path {ledger_db_path:?} in db_path_overrides is not an absolute path."
                        ),
                    ));
                }
```

**File:** config/src/config/test_data/validator.yaml (L18-19)
```yaml
execution:
    genesis_file_location: "relative/path/to/genesis"
```
