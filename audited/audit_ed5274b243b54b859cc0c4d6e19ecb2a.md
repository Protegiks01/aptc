# Audit Report

## Title
Genesis Transaction Memory Exhaustion via Unbounded BCS Deserialization

## Summary
Genesis transactions can be arbitrarily large with no size limits enforced during file loading or BCS deserialization, allowing attackers to cause memory exhaustion and crash nodes during startup through maliciously crafted genesis files.

## Finding Description

The `load_from_path()` function in `ExecutionConfig` loads genesis transactions without any size validation, violating the "Resource Limits" invariant that requires all operations to respect memory constraints.

**Vulnerable Code Flow:**

1. **Unrestricted File Reading**: The genesis file is read entirely into memory without size checks: [1](#0-0) 

2. **Unbounded BCS Deserialization**: The loaded buffer is deserialized without size limits: [2](#0-1) 

3. **Comparison with Protected Endpoints**: Other parts of the codebase use `bcs::from_bytes_with_limit()` with explicit limits: [3](#0-2) 

4. **Regular Transaction Size Limits**: User transactions are restricted to 64KB (governance: 1MB): [4](#0-3) 

5. **Genesis Bypasses Validation**: Genesis transactions bypass `check_gas()` validation entirely: [5](#0-4) 

6. **Bootstrap Tool Vulnerable Too**: Same pattern exists in the database bootstrap tool: [6](#0-5) 

**Attack Vectors:**

1. **MITM During Node Setup**: Fullnodes download genesis files from remote URLs without size limits: [7](#0-6) 

2. **Genesis Download Without Validation**: The download script uses curl without `--max-filesize`: [8](#0-7) 

3. **Config Loading Order**: Genesis is loaded during config initialization, before waypoint verification: [9](#0-8) 

**Exploitation Scenario:**

An attacker performing a MITM attack during initial node setup can serve a multi-gigabyte genesis.blob file. When the node attempts to start:
1. `NodeConfigLoader::load_and_sanitize_config()` calls `ExecutionConfig::load_from_path()`
2. `file.read_to_end(&mut buffer)` allocates unbounded memory for the malicious genesis
3. Node crashes with OOM before waypoint verification can detect the attack
4. Network bootstrapping fails, causing denial of service

## Impact Explanation

**High Severity** per Aptos Bug Bounty criteria: "Validator node slowdowns / API crashes / Significant protocol violations"

- **Availability Impact**: Prevents nodes from starting up, causing network unavailability
- **Scope**: Affects all nodes attempting to join a network (validators, fullnodes)
- **Recovery**: Requires manual intervention to identify and replace malicious genesis file
- **Private Networks**: Particularly severe for private deployments where genesis distribution is less controlled

This breaks the "Resource Limits" critical invariant, which requires all operations to respect memory constraints.

## Likelihood Explanation

**Medium-to-High Likelihood:**

- **During Initial Setup**: Nodes are most vulnerable during first-time configuration when downloading genesis from remote sources
- **Private Networks**: Higher risk in enterprise/private deployments where genesis file distribution may be less secure
- **MITM Feasibility**: Attackers controlling network infrastructure (ISP, malicious proxy) can intercept genesis downloads
- **Misconfiguration**: Node operators could be tricked into using malicious genesis URLs via social engineering

**Mitigating Factors:**
- Mainnet/testnet genesis files are served from official Aptos repositories
- Waypoint verification provides post-loading validation (though too late to prevent OOM)

## Recommendation

Implement size limits at multiple defense layers:

1. **Add Maximum Genesis Size Constant:**
```rust
// Reasonable limit for genesis transaction (e.g., 10 MB)
const MAX_GENESIS_FILE_SIZE: u64 = 10 * 1024 * 1024;
```

2. **Validate File Size Before Reading:**
```rust
pub fn load_from_path(&mut self, root_dir: &RootPath) -> Result<(), Error> {
    if !self.genesis_file_location.as_os_str().is_empty() {
        let genesis_path = root_dir.full_path(&self.genesis_file_location);
        
        // Check file size before reading
        let metadata = std::fs::metadata(&genesis_path).map_err(|error| {
            Error::Unexpected(format!("Failed to get genesis file metadata: {:?}", error))
        })?;
        
        if metadata.len() > MAX_GENESIS_FILE_SIZE {
            return Err(Error::Unexpected(format!(
                "Genesis file exceeds maximum size of {} bytes: {} bytes",
                MAX_GENESIS_FILE_SIZE,
                metadata.len()
            )));
        }
        
        // Existing file reading logic...
    }
    Ok(())
}
```

3. **Use Bounded BCS Deserialization:**
Replace `bcs::from_bytes(&buffer)` with `bcs::from_bytes_with_limit(&buffer, MAX_BCS_RECURSION_DEPTH)` to prevent deeply nested structures.

4. **Add curl Size Limit:** Update Helm templates to include `--max-filesize` in genesis downloads:
```bash
curl --max-filesize 10485760 -o /opt/aptos/genesis/genesis.blob {{ genesis_blob_url }}
```

## Proof of Concept

**Rust Test to Demonstrate Vulnerability:**

```rust
#[test]
fn test_genesis_size_vulnerability() {
    use aptos_temppath::TempPath;
    use std::io::Write;
    
    // Create a temporary directory
    let temp_dir = TempPath::new();
    temp_dir.create_as_dir().expect("Failed to create temp dir");
    
    // Create a maliciously large "genesis" file (100MB of zeros)
    let genesis_path = temp_dir.path().join("genesis.blob");
    let mut file = std::fs::File::create(&genesis_path).unwrap();
    let large_data = vec![0u8; 100 * 1024 * 1024];
    file.write_all(&large_data).unwrap();
    
    // Configure ExecutionConfig to load this file
    let mut config = ExecutionConfig::default();
    config.genesis_file_location = PathBuf::from("genesis.blob");
    
    let root_dir = RootPath::new_path(temp_dir.path());
    
    // This will attempt to load entire 100MB into memory
    // On systems with limited memory, this causes OOM
    let result = config.load_from_path(&root_dir);
    
    // Currently this succeeds (vulnerability)
    // After fix, should fail with size limit error
    assert!(result.is_ok()); // Will crash with OOM on constrained systems
}
```

**Attack Simulation:**

```bash
# Create 2GB malicious genesis file
dd if=/dev/zero of=malicious_genesis.blob bs=1M count=2048

# Start node with this genesis (via modified config)
# Node will crash with OOM during load_from_path()
```

## Notes

This vulnerability represents a defense-in-depth failure. While genesis files are typically trusted and validated via waypoints, the lack of size limits creates an unnecessary attack surface. The same pattern appears in multiple locations (`execution_config.rs`, `bootstrap.rs`), suggesting systematic oversight rather than isolated bug.

The fix should be applied consistently across all genesis loading code paths and coordinated with infrastructure changes to add download size limits.

### Citations

**File:** config/src/config/execution_config.rs (L119-126)
```rust
            let mut buffer = vec![];
            file.read_to_end(&mut buffer).map_err(|error| {
                Error::Unexpected(format!(
                    "Failed to read the genesis file into a buffer: {:?}. Error: {:?}",
                    genesis_path.display(),
                    error
                ))
            })?;
```

**File:** config/src/config/execution_config.rs (L129-136)
```rust
            let genesis = bcs::from_bytes(&buffer).map_err(|error| {
                Error::Unexpected(format!(
                    "Failed to BCS deserialize the genesis file: {:?}. Error: {:?}",
                    genesis_path.display(),
                    error
                ))
            })?;
            self.genesis = Some(genesis);
```

**File:** api/src/transactions.rs (L1224-1224)
```rust
                    bcs::from_bytes_with_limit(&data.0, Self::MAX_SIGNED_TRANSACTION_DEPTH)
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L73-80)
```rust
            max_transaction_size_in_bytes: NumBytes,
            "max_transaction_size_in_bytes",
            64 * 1024
        ],
        [
            max_transaction_size_in_bytes_gov: NumBytes,
            { RELEASE_V1_13.. => "max_transaction_size_in_bytes.gov" },
            1024 * 1024
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L2908-2916)
```rust
            Transaction::GenesisTransaction(write_set_payload) => {
                let (vm_status, output) = self.process_waypoint_change_set(
                    resolver,
                    code_storage,
                    write_set_payload.clone(),
                    log_context,
                )?;
                (vm_status, output)
            },
```

**File:** storage/db-tool/src/bootstrap.rs (L108-114)
```rust
fn load_genesis_txn(path: &Path) -> Result<Transaction> {
    let mut file = File::open(path)?;
    let mut buffer = vec![];
    file.read_to_end(&mut buffer)?;

    Ok(bcs::from_bytes(&buffer)?)
}
```

**File:** terraform/helm/fullnode/templates/fullnode.yaml (L127-128)
```yaml
          curl -o /opt/aptos/genesis/waypoint.txt {{ (get .Values.aptos_chains .Values.chain.name).waypoint_txt_url }}
          curl -o /opt/aptos/genesis/genesis.blob {{ (get .Values.aptos_chains .Values.chain.name).genesis_blob_url }}
```

**File:** .github/actions/fullnode-sync/fullnode_sync.py (L364-367)
```python
  genesis_blob_path = GENESIS_BLOB_PATH.format(network=network)
  waypoint_file_path = WAYPOINT_FILE_PATH.format(network=network)
  subprocess.run(["curl", "-s", "-O", genesis_blob_path])
  subprocess.run(["curl", "-s", "-O", waypoint_file_path])
```

**File:** config/src/config/node_config_loader.rs (L76-78)
```rust
        // Load the execution config
        let input_dir = RootPath::new(&self.node_config_path);
        node_config.execution.load_from_path(&input_dir)?;
```
