# Audit Report

## Title
Non-Atomic Genesis File Writes in ExecutionConfig::save_to_path() Lead to Node Startup Failures

## Summary
The `save_to_path()` function in `ExecutionConfig` performs non-atomic file writes to genesis.blob, using `File::create()` which immediately truncates the file before writing. If the process crashes, disk becomes full, or the function is called multiple times concurrently, the genesis file can become corrupted, preventing validator nodes from starting.

## Finding Description

The vulnerability exists in the `save_to_path()` method which writes the genesis transaction to disk without atomic guarantees. [1](#0-0) 

The problematic sequence is:
1. **Line 148**: `File::create(path)` immediately truncates any existing genesis.blob to zero bytes
2. **Line 149**: Genesis transaction is serialized to bytes
3. **Lines 150-151**: Serialized data is written to the already-truncated file

If any failure occurs between step 1 and step 3 completing (process crash, SIGKILL, disk full, serialization error), the genesis.blob file is left in a corrupted or empty state.

When a node starts, it loads the genesis via `load_from_path()`: [2](#0-1) 

If the genesis file is corrupted, BCS deserialization fails at line 129, returning an error and preventing the node from starting.

The node startup process requires a valid genesis transaction: [3](#0-2) 

**Contrast with Correct Implementation:**

The codebase already has the proper atomic write pattern in `OnDiskStorage`: [4](#0-3) 

This implementation writes to a temporary file first, then atomically renames it to the final location, ensuring readers never see a partially written file.

**Failure Scenarios:**

1. **Process Crash**: Node setup process is killed between truncate and write completion → empty genesis.blob
2. **Disk Full**: Disk space exhausted after truncation but before write completes → partial/corrupted genesis.blob  
3. **Multiple Calls**: Operator error or retry logic calls `save_to_path()` multiple times → file truncated mid-write
4. **Signal Interruption**: SIGTERM/SIGKILL between operations → corrupted genesis.blob

## Impact Explanation

**Severity: Medium** per Aptos bug bounty criteria - "State inconsistencies requiring intervention"

**Impact:**
- **Validator Unavailability**: A corrupted genesis file prevents the validator node from starting. During bootstrap, `maybe_apply_genesis()` is called, which retrieves the genesis transaction via `get_genesis_txn()`. If the genesis cannot be deserialized, node initialization fails completely.
- **Manual Intervention Required**: Recovery requires manually restoring or regenerating the genesis.blob file - an automated restart cannot fix this.
- **Batch Deployment Risk**: In scenarios where multiple validators are initialized from shared configuration or deployment automation, a systemic failure (e.g., disk full, deployment script error) could corrupt genesis files for multiple validators simultaneously.
- **Persistent Downtime**: Unlike transient errors, a corrupted genesis file causes permanent unavailability until manual intervention occurs.

This does NOT directly cause:
- Loss of funds
- Consensus safety violations (node cannot participate in consensus if it cannot start)
- Network-wide partition (only affects individual node(s))

The impact fits "Medium" severity as it causes state inconsistencies (corrupted configuration) requiring manual intervention and affects validator availability.

## Likelihood Explanation

**Likelihood: LOW to MEDIUM**

**Factors Increasing Likelihood:**
- Process crashes during node setup/configuration are not uncommon in production deployments
- Disk full conditions during writes are realistic in containerized environments with storage limits
- Operator errors (running setup commands multiple times) are common during manual deployments
- Automated deployment scripts may retry failed operations, potentially calling `save_to_path()` multiple times

**Factors Decreasing Likelihood:**
- `save_to_path()` is primarily called during initial setup, not runtime operations
- Each validator typically writes to its own directory, reducing concurrent write risks
- Genesis files are relatively small, making disk full less likely (though not impossible)
- Not directly exploitable by external attackers - requires operational/deployment context

**Realistic Occurrence Scenarios:**
1. Containerized deployment with pod crash during genesis setup
2. Kubernetes deployment with storage quota exhausted during config generation
3. Manual operator error running genesis setup command multiple times
4. Deployment automation with retry logic on failure [5](#0-4) 

## Recommendation

Implement atomic file writes using the temporary-file-then-rename pattern already established in the codebase. The fix should follow the pattern from `OnDiskStorage::write()`:

**Recommended Fix:**

```rust
pub fn save_to_path(&mut self, root_dir: &RootPath) -> Result<(), Error> {
    if let Some(genesis) = &self.genesis {
        if self.genesis_file_location.as_os_str().is_empty() {
            self.genesis_file_location = PathBuf::from(GENESIS_BLOB_FILENAME);
        }
        
        let final_path = root_dir.full_path(&self.genesis_file_location);
        
        // Write to temporary file first
        let temp_path = final_path.with_extension("tmp");
        let mut file = File::create(&temp_path)
            .map_err(|e| Error::IO("genesis".into(), e))?;
        
        let data = bcs::to_bytes(&genesis)
            .map_err(|e| Error::BCS("genesis", e))?;
        
        file.write_all(&data)
            .map_err(|e| Error::IO("genesis".into(), e))?;
        
        // Ensure data is flushed to disk
        file.sync_all()
            .map_err(|e| Error::IO("genesis".into(), e))?;
        
        // Atomic rename
        std::fs::rename(&temp_path, &final_path)
            .map_err(|e| Error::IO("genesis".into(), e))?;
    }
    Ok(())
}
```

This ensures:
1. New data is fully written to a temporary file
2. Data is flushed to disk before rename
3. The rename operation is atomic at the filesystem level
4. Readers never see partially written genesis files

## Proof of Concept

```rust
use aptos_config::config::{ExecutionConfig, RootPath};
use aptos_temppath::TempPath;
use aptos_types::transaction::{ChangeSet, Transaction, WriteSetPayload};
use aptos_types::write_set::WriteSetMut;
use std::fs;
use std::path::PathBuf;

#[test]
fn test_non_atomic_write_corruption() {
    // Create test genesis transaction
    let genesis = Transaction::GenesisTransaction(
        WriteSetPayload::Direct(
            ChangeSet::new(
                WriteSetMut::new(vec![]).freeze().unwrap(), 
                vec![]
            )
        )
    );
    
    // Setup temp directory
    let temp_dir = TempPath::new();
    temp_dir.create_as_dir().unwrap();
    let root_dir = RootPath::new_path(temp_dir.path());
    
    // Create config and save first time
    let mut config = ExecutionConfig::default();
    config.genesis = Some(genesis.clone());
    config.genesis_file_location = PathBuf::from("genesis.blob");
    
    // First save succeeds
    config.save_to_path(&root_dir).unwrap();
    
    let genesis_path = root_dir.full_path(&config.genesis_file_location);
    assert!(genesis_path.exists());
    
    // Simulate corruption scenario: 
    // File::create() truncates immediately, so if we check size
    // between create and write_all, it would be 0
    
    // Save again - each call truncates then writes
    // In a crash scenario, file would be left at 0 bytes
    config.save_to_path(&root_dir).unwrap();
    
    // Simulate crash after truncate: manually truncate file
    fs::write(&genesis_path, b"").unwrap();
    
    // Now try to load - should fail with BCS deserialization error
    let mut load_config = ExecutionConfig::default();
    load_config.genesis_file_location = PathBuf::from("genesis.blob");
    
    let result = load_config.load_from_path(&root_dir);
    
    // This demonstrates that corrupted genesis prevents node startup
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("BCS deserialize"));
}

#[test]
fn test_atomic_write_prevents_corruption() {
    // This test would pass with the recommended fix
    // Using temp file + rename pattern ensures readers never see
    // partially written files, even if process crashes mid-write
}
```

**Notes:**
- The vulnerability is a violation of the atomic write principle for critical configuration files
- Genesis files are foundational to node initialization and must be handled with care
- The fix is straightforward and follows established patterns already in the codebase
- This is classified as Medium severity due to availability impact requiring manual intervention, not Critical/High as it doesn't directly affect consensus or fund security

### Citations

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

**File:** config/src/config/execution_config.rs (L142-154)
```rust
    pub fn save_to_path(&mut self, root_dir: &RootPath) -> Result<(), Error> {
        if let Some(genesis) = &self.genesis {
            if self.genesis_file_location.as_os_str().is_empty() {
                self.genesis_file_location = PathBuf::from(GENESIS_BLOB_FILENAME);
            }
            let path = root_dir.full_path(&self.genesis_file_location);
            let mut file = File::create(path).map_err(|e| Error::IO("genesis".into(), e))?;
            let data = bcs::to_bytes(&genesis).map_err(|e| Error::BCS("genesis", e))?;
            file.write_all(&data)
                .map_err(|e| Error::IO("genesis".into(), e))?;
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
