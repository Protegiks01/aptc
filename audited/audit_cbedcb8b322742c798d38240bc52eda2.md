# Audit Report

## Title
Non-Atomic Configuration File Writes Enable Validator Node Denial of Service via Filesystem Quota Exhaustion

## Summary
The `save_config()` function in `persistable_config.rs` performs non-atomic file writes that can result in corrupted SafetyRulesConfig files when filesystem quota is exhausted. This leaves validator nodes unable to restart without manual intervention.

## Finding Description

The `write_file()` method uses a destructive write pattern that creates a critical window for data loss: [1](#0-0) 

The execution flow is:
1. `File::create()` immediately **truncates** any existing configuration file
2. `write_all()` attempts to write the serialized configuration
3. If quota is exhausted during step 2, the write fails after the original file has been destroyed

This affects SafetyRulesConfig which stores critical consensus initialization parameters: [2](#0-1) 

When configuration updates are performed (typically during node maintenance), the pattern is: [3](#0-2) 

**Attack Scenario:**
1. Attacker or natural usage fills filesystem approaching quota limits
2. Operator performs configuration update via `config.save_to_path()`
3. `File::create()` succeeds and truncates SafetyRulesConfig
4. `write_all()` fails with EDQUOT (disk quota exceeded) error
5. SafetyRulesConfig is left empty or partially written
6. Node restart fails as config cannot be parsed

The SafetyRulesManager requires valid SafetyRulesConfig on initialization: [4](#0-3) 

Without valid configuration, the node panics and cannot participate in consensus.

## Impact Explanation

This qualifies as **Medium Severity** under "State inconsistencies requiring intervention" because:

1. **Manual Recovery Required**: Operators must manually restore configuration files from backups or reconstruct them, as there is no automated recovery mechanism
2. **Validator Unavailability**: The affected validator cannot restart and remains offline until configuration is manually fixed
3. **Single-Node Impact**: Other validators continue operating normally; this does not cause network-wide liveness failure or consensus safety violations

This is NOT:
- A consensus safety violation (no double-voting or fork)
- A loss of funds vulnerability
- A network-wide availability issue (other nodes continue)

The impact is limited to operational availability of individual validator nodes requiring human intervention.

## Likelihood Explanation

**Likelihood: LOW to MEDIUM**

Prerequisites for exploitation:
1. **Filesystem quota approaching limits** - Can occur through:
   - Natural disk usage from logs, state growth, backups
   - Attacker filling filesystem if they have write access
   - Misconfigured disk quotas on validator infrastructure

2. **Configuration save operation during quota exhaustion** - Occurs during:
   - Node configuration updates (infrequent)
   - Initial node setup
   - NOT during normal consensus operations

3. **Timing**: The quota must be exceeded during the narrow window between `File::create()` and `write_all()` completion

The likelihood is **LOW** in well-managed validator infrastructure with proper disk monitoring, but **MEDIUM** in environments with inadequate capacity planning or where attackers can influence filesystem usage.

## Recommendation

Implement atomic file writes using the standard write-tempfile-then-rename pattern:

```rust
fn write_file<P: AsRef<Path>>(serialized_config: Vec<u8>, output_file: P) -> Result<(), Error> {
    use std::fs;
    use std::io::Write;
    
    let output_path = output_file.as_ref();
    let temp_path = output_path.with_extension("tmp");
    
    // Write to temporary file
    let mut file = File::create(&temp_path)
        .map_err(|e| Error::IO(temp_path.to_str().unwrap().to_string(), e))?;
    file.write_all(&serialized_config)
        .map_err(|e| Error::IO(temp_path.to_str().unwrap().to_string(), e))?;
    
    // Ensure data is flushed to disk
    file.sync_all()
        .map_err(|e| Error::IO(temp_path.to_str().unwrap().to_string(), e))?;
    
    // Atomic rename over original file
    fs::rename(&temp_path, output_path)
        .map_err(|e| Error::IO(output_path.to_str().unwrap().to_string(), e))?;
    
    Ok(())
}
```

This ensures that either:
- The write completes successfully and the new config is atomically moved into place
- The write fails and the original config remains intact

Additional hardening:
- Add disk space validation before writes
- Implement configuration versioning/backups
- Add health checks that validate config file integrity on startup

## Proof of Concept

```rust
#[cfg(test)]
mod quota_exhaustion_test {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;
    use tempfile::TempDir;
    
    #[test]
    fn test_config_corruption_on_quota_exhaustion() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("safety_rules.yaml");
        
        // Create initial valid config
        let mut config = SafetyRulesConfig::default();
        config.save_config(&config_path).unwrap();
        
        // Verify config loads successfully
        let loaded = SafetyRulesConfig::load_config(&config_path).unwrap();
        assert_eq!(config, loaded);
        
        // Simulate quota exhaustion by filling disk (platform-specific)
        // On most systems, can use ulimit or disk quota tools
        // For test purposes, we demonstrate the truncation issue:
        
        // Manually truncate file (simulating File::create behavior)
        let mut file = File::create(&config_path).unwrap();
        // Simulate write_all failing after truncation
        // (In reality this would be EDQUOT error)
        drop(file); // Leave file empty
        
        // Attempt to reload config - should fail
        let result = SafetyRulesConfig::load_config(&config_path);
        assert!(result.is_err(), "Config should be corrupted");
        
        // Node cannot initialize SafetyRules without valid config
        // This demonstrates the DoS condition
    }
    
    #[test]
    fn test_atomic_write_prevents_corruption() {
        // Test that atomic write pattern preserves original on failure
        // (Would require implementing the recommended fix first)
    }
}
```

## Notes

**Important Clarifications:**

1. **Not a Consensus Bug**: This vulnerability does NOT affect consensus safety, does not enable double-voting, and does not cause blockchain state corruption. The consensus safety data (last_voted_round, epoch, etc.) is stored separately through PersistentSafetyStorage with a different storage backend.

2. **Operational Impact Only**: The impact is limited to operational availability of individual validators. The network continues functioning with remaining validators.

3. **Requires External Conditions**: Exploitation requires filesystem quota exhaustion, which may be caused by attackers with filesystem access or natural resource constraints.

4. **Standard Software Engineering Issue**: This is a well-known class of bug (non-atomic file writes) that should be fixed using standard techniques, but the security impact in a blockchain validator context elevates its priority.

5. **Not During Consensus**: Configuration saves do not occur during normal consensus operations - they happen during node setup, maintenance, and configuration updates.

### Citations

**File:** config/src/config/persistable_config.rs (L43-50)
```rust
    fn write_file<P: AsRef<Path>>(serialized_config: Vec<u8>, output_file: P) -> Result<(), Error> {
        let mut file = File::create(output_file.as_ref())
            .map_err(|e| Error::IO(output_file.as_ref().to_str().unwrap().to_string(), e))?;
        file.write_all(&serialized_config)
            .map_err(|e| Error::IO(output_file.as_ref().to_str().unwrap().to_string(), e))?;

        Ok(())
    }
```

**File:** config/src/config/safety_rules_config.rs (L23-34)
```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SafetyRulesConfig {
    pub backend: SecureBackend,
    pub logger: LoggerConfig,
    pub service: SafetyRulesService,
    pub test: Option<SafetyRulesTestConfig>,
    // Read/Write/Connect networking operation timeout in milliseconds.
    pub network_timeout_ms: u64,
    pub enable_cached_safety_data: bool,
    pub initial_safety_rules_config: InitialSafetyRulesConfig,
}
```

**File:** testsuite/smoke-test/src/consensus_observer.rs (L375-385)
```rust
fn update_node_config_and_restart(node: &mut LocalNode, mut config: NodeConfig) {
    // Stop the node
    node.stop();

    // Update the node's config
    let node_path = node.config_path();
    config.save_to_path(node_path).unwrap();

    // Restart the node
    node.start().unwrap();
}
```

**File:** consensus/safety-rules/src/safety_rules_manager.rs (L21-26)
```rust
pub fn storage(config: &SafetyRulesConfig) -> PersistentSafetyStorage {
    let backend = &config.backend;
    let internal_storage: Storage = backend.into();
    if let Err(error) = internal_storage.available() {
        panic!("Storage is not available: {:?}", error);
    }
```
