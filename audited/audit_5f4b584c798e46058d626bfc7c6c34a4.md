# Audit Report

## Title
Non-Atomic SafetyRulesConfig Write Leaves Validator in Unrecoverable State on Partial Write Failure

## Summary
The `write_file()` function in `persistable_config.rs` uses a non-atomic write pattern that truncates the existing configuration file before writing the new content. If the write operation fails partway through, the SafetyRulesConfig file is left corrupted, preventing validator restart and requiring manual intervention.

## Finding Description

The `write_file()` function implements a fundamentally unsafe write pattern for critical validator configuration data: [1](#0-0) 

The vulnerability occurs through the following sequence:

1. `File::create()` is called, which **immediately truncates** any existing configuration file to zero bytes
2. `write_all()` attempts to write the serialized configuration data
3. If `write_all()` fails partway through (due to disk full, I/O error, system crash, or process termination), the file is left in a partially-written, corrupted state
4. The original configuration is already lost due to the truncation in step 1
5. No rollback mechanism or atomic write pattern exists

SafetyRulesConfig is critical for validator startup because it contains: [2](#0-1) 

When a validator attempts to restart with a corrupted config file, the YAML parsing fails: [3](#0-2) 

This causes the entire validator initialization to fail: [4](#0-3) 

The codebase **already implements the correct atomic write pattern** in `OnDiskStorage` for secure storage: [5](#0-4) 

This pattern writes to a temporary file first, then atomically renames it to the target location, ensuring that either the old file remains intact OR the new file is completely written.

**Failure Scenarios:**
- **Disk Full**: Validator writes config during reconfiguration, disk fills partway through write
- **I/O Errors**: Storage system errors during write operation
- **Process Termination**: Validator process killed (OOM, SIGKILL) during config write
- **System Crash**: Power loss or kernel panic during write operation
- **File System Issues**: NFS timeouts, disk failures, quota exceeded

## Impact Explanation

This vulnerability falls under **High Severity** per the Aptos bug bounty criteria: "Validator node slowdowns" and operational unavailability.

**Validator Impact:**
- Validator cannot restart after config corruption
- Requires manual intervention: operator must restore config from backup or recreate it
- No automatic recovery mechanism exists
- Validator offline until manual fix is applied

**Network Impact:**
- Single validator: Temporary reduction in validator set participation
- Multiple validators (if same operational issue affects many): Could impact consensus liveness if >1/3 validators affected simultaneously
- Coordinated attack scenario: If attacker can trigger disk full conditions on multiple validators simultaneously, could cause widespread outage

**Recovery Requirements:**
- Manual operator intervention required
- Need backup of valid configuration or ability to regenerate
- Potential for extended downtime if operator is unavailable or backups don't exist

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH in production environments**

This vulnerability can manifest through:

1. **Operational Failures (High Probability)**:
   - Disk space exhaustion is common in production systems
   - Log files, state database growth can fill disks
   - Monitoring gaps may not catch disk space issues in time
   - Config regeneration during operations can trigger writes

2. **System Failures (Medium Probability)**:
   - Hardware failures, power issues
   - OOM killer terminating processes
   - Container/pod evictions in Kubernetes environments
   - Network filesystem (NFS) timeouts

3. **Attack Scenarios (Low-Medium Probability)**:
   - Attacker causing disk pressure through state bloat
   - DoS attacks filling disk space
   - Requires attacker to time attack during config write (small window)

**When Config Writes Occur:** [6](#0-5) 

Genesis and initial setup are the primary times configs are written, reducing attack window but not eliminating operational risk.

## Recommendation

Implement atomic file writes using the temporary-file-and-rename pattern already used in `OnDiskStorage`:

```rust
fn write_file<P: AsRef<Path>>(serialized_config: Vec<u8>, output_file: P) -> Result<(), Error> {
    use aptos_temppath::TempPath;
    
    // Get the directory of the output file for creating temp file in same filesystem
    let file_dir = output_file.as_ref()
        .parent()
        .map_or_else(std::path::PathBuf::new, |p| p.to_path_buf());
    
    // Create a temporary file in the same directory (ensures atomic rename)
    let temp_path = TempPath::new_with_temp_dir(file_dir);
    
    // Write to temporary file
    let mut file = File::create(temp_path.path())
        .map_err(|e| Error::IO(output_file.as_ref().to_str().unwrap().to_string(), e))?;
    file.write_all(&serialized_config)
        .map_err(|e| Error::IO(output_file.as_ref().to_str().unwrap().to_string(), e))?;
    
    // Ensure data is flushed to disk before rename
    file.sync_all()
        .map_err(|e| Error::IO(output_file.as_ref().to_str().unwrap().to_string(), e))?;
    
    // Atomic rename: either old file remains or new file is completely written
    std::fs::rename(&temp_path, output_file.as_ref())
        .map_err(|e| Error::IO(output_file.as_ref().to_str().unwrap().to_string(), e))?;
    
    Ok(())
}
```

**Additional Recommendations:**
1. Add config file validation on startup with clear error messages
2. Implement automatic backup of config files before overwriting
3. Add health checks that verify config file integrity
4. Document recovery procedures for corrupted config files

## Proof of Concept

```rust
#[cfg(test)]
mod test_config_corruption {
    use super::*;
    use std::io::{self, Write};
    use tempfile::tempdir;
    
    /// Custom Write implementation that fails after writing partial data
    struct FailingWriter {
        data: Vec<u8>,
        fail_after: usize,
    }
    
    impl Write for FailingWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let to_write = buf.len().min(self.fail_after - self.data.len());
            if to_write == 0 {
                return Err(io::Error::new(io::ErrorKind::Other, "Disk full"));
            }
            self.data.extend_from_slice(&buf[..to_write]);
            Ok(to_write)
        }
        
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    
    #[test]
    fn test_partial_write_corruption() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("safety_rules.yaml");
        
        // Create initial valid config
        let initial_config = SafetyRulesConfig::default();
        initial_config.save_config(&config_path).unwrap();
        
        // Verify it can be loaded
        let loaded = SafetyRulesConfig::load_config(&config_path).unwrap();
        assert_eq!(initial_config, loaded);
        
        // Simulate partial write by truncating file and writing incomplete data
        let mut new_config = SafetyRulesConfig::default();
        new_config.network_timeout_ms = 60000; // Change something
        
        let serialized = serde_yaml::to_vec(&new_config).unwrap();
        
        // Write only partial data (simulating write_all failure)
        {
            let mut file = File::create(&config_path).unwrap(); // Truncates!
            file.write_all(&serialized[..serialized.len()/2]).unwrap(); // Partial write
            // Simulate crash - file is left in corrupted state
        }
        
        // Attempt to load corrupted config - should fail
        let result = SafetyRulesConfig::load_config(&config_path);
        assert!(result.is_err(), "Should fail to load corrupted config");
        
        // Original config is lost - no recovery possible
        // Validator cannot restart without manual intervention
    }
    
    #[test]
    fn test_atomic_write_resilience() {
        // This demonstrates how atomic writes would prevent corruption
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("safety_rules.yaml");
        
        // Create initial config
        let initial_config = SafetyRulesConfig::default();
        initial_config.save_config(&config_path).unwrap();
        
        // Simulate failed atomic write (using temp file + rename pattern)
        // Even if write to temp file fails, original file remains intact
        let temp_path = temp_dir.path().join(".safety_rules.yaml.tmp");
        let new_config = SafetyRulesConfig::default();
        
        // Write to temp file fails partway
        {
            let serialized = serde_yaml::to_vec(&new_config).unwrap();
            let mut file = File::create(&temp_path).unwrap();
            let _ = file.write_all(&serialized[..serialized.len()/2]); // Partial write
            // Don't rename - simulating failure
        }
        
        // Original config still intact and loadable
        let loaded = SafetyRulesConfig::load_config(&config_path).unwrap();
        assert_eq!(initial_config, loaded);
        // Validator can still restart successfully
    }
}
```

## Notes

While this vulnerability represents a real implementation flaw that violates atomicity guarantees for critical configuration data, its exploitability is limited by requiring local system-level conditions (disk full, crashes, I/O errors) that are not directly triggerable by a remote unprivileged attacker. The issue is more of an operational reliability concern than a directly exploitable security vulnerability, though it does have security implications for validator availability and could potentially be exploited opportunistically during DoS attacks or operational incidents.

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

**File:** config/src/config/persistable_config.rs (L53-55)
```rust
    fn parse_serialized_config(serialized_config: &str) -> Result<Self, Error> {
        serde_yaml::from_str(serialized_config).map_err(|e| Error::Yaml("config".to_string(), e))
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

**File:** aptos-node/src/lib.rs (L310-312)
```rust
    let config = if validator_config_path.exists() {
        NodeConfig::load_from_path(&validator_config_path)
            .map_err(|error| anyhow!("Unable to load config: {:?}", error))?
```

**File:** secure/storage/src/on_disk.rs (L64-70)
```rust
    fn write(&self, data: &HashMap<String, Value>) -> Result<(), Error> {
        let contents = serde_json::to_vec(data)?;
        let mut file = File::create(self.temp_path.path())?;
        file.write_all(&contents)?;
        fs::rename(&self.temp_path, &self.file_path)?;
        Ok(())
    }
```

**File:** crates/aptos-genesis/src/builder.rs (L179-189)
```rust
    fn save_config(&mut self) -> anyhow::Result<()> {
        // Save the execution config to disk along with the full config.
        self.config
            .override_config_mut()
            .save_to_path(self.dir.join(CONFIG_FILE))?;

        // Overwrite the full config with the override config
        self.config
            .save_config(self.dir.join(CONFIG_FILE))
            .map_err(Into::into)
    }
```
