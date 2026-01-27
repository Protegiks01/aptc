# Audit Report

## Title
Missing Path Validation on Base Data Directory Allows Potential System Directory Contamination

## Summary
The `base.data_dir` configuration field lacks validation to prevent it from being set to sensitive system directories like `/etc`, `/root`, or other critical paths. While RocksDB database initialization will fail with permission errors in properly configured deployments, this represents a missing defense-in-depth control that could lead to system instability in misconfigured environments.

## Finding Description

The `data_dir` field in `BaseConfig` is directly deserializable from YAML configuration files without any path validation. [1](#0-0) 

The `BaseConfig::sanitize()` method only validates the waypoint configuration and completely omits validation of the `data_dir` path. [2](#0-1) 

This path propagates through the system via `NodeConfig::set_data_dir()` which sets both the base directory and storage directory. [3](#0-2) 

The path is ultimately used by storage initialization without additional validation. [4](#0-3) 

When RocksDB attempts to open databases, it directly uses the configured path without validation. [5](#0-4) 

Interestingly, the codebase DOES validate paths in `db_path_overrides` to ensure they are absolute paths, showing awareness of path security but inconsistent application. [6](#0-5) 

## Impact Explanation

This issue is rated as **HIGH severity** based on the following scenarios:

1. **Misconfigured Production Deployments**: If a validator node runs with elevated privileges (root or with write access to system directories), attempting to initialize databases in `/etc` or `/root` could corrupt system configuration files or cause system instability.

2. **Disk Space Exhaustion**: An attacker who can provide a malicious config could set `data_dir` to a small partition, causing disk exhaustion and node failure (DoS).

3. **Development/Testing Environments**: Testing environments may run nodes with elevated privileges where this vulnerability could cause unintended system damage.

While the Docker deployment creates a non-root `aptos` user [7](#0-6) , the Dockerfile does not set a `USER` directive, potentially allowing containers to run as root by default unless overridden by orchestration configurations.

## Likelihood Explanation

**Likelihood: MEDIUM to HIGH**

For this vulnerability to be exploited, an attacker must:
1. Provide a malicious node configuration file that gets loaded by the validator
2. The node must have sufficient permissions to write to the targeted directory

Scenarios where this is likely:
- Node operators downloading configs from untrusted sources
- Automated deployment systems with insufficient config validation
- Compromised CI/CD pipelines that inject malicious configs
- Development/testing environments with relaxed security

The attack does NOT require:
- Network access
- Transaction submission capabilities
- Validator collusion
- Stake or governance participation

## Recommendation

Implement path validation in `BaseConfig::sanitize()` to restrict `data_dir` to safe locations:

```rust
impl ConfigSanitizer for BaseConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        _chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let base_config = &node_config.base;

        // Verify the waypoint is not None
        if let WaypointConfig::None = base_config.waypoint {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "The waypoint config must be set in the base config!".into(),
            ));
        }

        // Validate data_dir path
        let data_dir = &base_config.data_dir;
        
        // Reject sensitive system directories
        let dangerous_prefixes = ["/etc", "/root", "/sys", "/proc", "/dev", "/boot"];
        let canonical_path = data_dir.canonicalize().unwrap_or(data_dir.clone());
        let path_str = canonical_path.to_string_lossy();
        
        for prefix in &dangerous_prefixes {
            if path_str.starts_with(prefix) {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    format!("data_dir cannot be set to system directory: {}", path_str),
                ));
            }
        }

        Ok(())
    }
}
```

Additionally, ensure the Docker container explicitly sets `USER aptos` before the entrypoint to enforce non-root execution.

## Proof of Concept

**Test Configuration (malicious.yaml):**
```yaml
base:
  data_dir: "/etc/aptos-malicious"
  role: validator
  waypoint:
    from_config: "0:0000000000000000000000000000000000000000000000000000000000000000"

storage:
  dir: "db"
  backup_service_address: "127.0.0.1:6186"
```

**Exploitation Steps:**
1. Deploy Aptos node with the malicious configuration
2. If running as root or with write permissions to `/etc`, the node will attempt to create `/etc/aptos-malicious/db/` 
3. RocksDB will create database files in this sensitive directory
4. Potential outcomes:
   - System instability from filesystem corruption
   - Disk space exhaustion on the root partition
   - Interference with system services reading from `/etc`

**Rust Test to Demonstrate Lack of Validation:**
```rust
#[test]
fn test_dangerous_data_dir_not_rejected() {
    let mut node_config = NodeConfig::default();
    node_config.base.data_dir = PathBuf::from("/etc/aptos");
    node_config.base.waypoint = WaypointConfig::FromConfig(Waypoint::default());
    
    // This should fail but currently passes
    let result = BaseConfig::sanitize(&node_config, NodeType::Validator, Some(ChainId::mainnet()));
    
    // Assertion would fail - showing the vulnerability exists
    assert!(result.is_err(), "Dangerous data_dir should be rejected");
}
```

## Notes

This vulnerability represents a **defense-in-depth failure** rather than a direct protocol exploit. While standard deployments with proper permission boundaries would prevent the most severe impacts, the lack of validation violates security best practices and creates unnecessary risk in edge cases.

The inconsistency between validating `db_path_overrides` but not validating `base.data_dir` suggests this was an oversight rather than an intentional design decision.

### Citations

**File:** config/src/config/base_config.rs (L15-22)
```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct BaseConfig {
    pub data_dir: PathBuf,
    pub working_dir: Option<PathBuf>,
    pub role: RoleType,
    pub waypoint: WaypointConfig,
}
```

**File:** config/src/config/base_config.rs (L35-54)
```rust
impl ConfigSanitizer for BaseConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        _chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let base_config = &node_config.base;

        // Verify the waypoint is not None
        if let WaypointConfig::None = base_config.waypoint {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "The waypoint config must be set in the base config!".into(),
            ));
        }

        Ok(())
    }
}
```

**File:** config/src/config/node_config.rs (L127-135)
```rust
    /// Sets the data directory for this config
    pub fn set_data_dir(&mut self, data_dir: PathBuf) {
        // Set the base directory
        self.base.data_dir.clone_from(&data_dir);

        // Set the data directory for each sub-module
        self.consensus.set_data_dir(data_dir.clone());
        self.storage.set_data_dir(data_dir);
    }
```

**File:** aptos-node/src/storage.rs (L63-67)
```rust
    let (aptos_db_reader, db_rw, backup_service) = match FastSyncStorageWrapper::initialize_dbs(
        node_config,
        internal_indexer_db.clone(),
        update_sender,
    )? {
```

**File:** storage/aptosdb/src/ledger_db/mod.rs (L457-484)
```rust
    fn open_rocksdb(
        path: PathBuf,
        name: &str,
        db_config: &RocksdbConfig,
        env: Option<&Env>,
        block_cache: Option<&Cache>,
        readonly: bool,
    ) -> Result<DB> {
        let db = if readonly {
            DB::open_cf_readonly(
                &gen_rocksdb_options(db_config, env, true),
                path.clone(),
                name,
                Self::gen_cfds_by_name(db_config, block_cache, name),
            )?
        } else {
            DB::open_cf(
                &gen_rocksdb_options(db_config, env, false),
                path.clone(),
                name,
                Self::gen_cfds_by_name(db_config, block_cache, name),
            )?
        };

        info!("Opened {name} at {path:?}!");

        Ok(db)
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

**File:** docker/builder/validator.Dockerfile (L22-22)
```dockerfile
RUN addgroup --system --gid 6180 aptos && adduser --system --ingroup aptos --no-create-home --uid 6180 aptos
```
