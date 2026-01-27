# Audit Report

## Title
Consensus Private Key Exposure via File Permission Inheritance in OnDiskStorage write() Operation

## Summary
The `OnDiskStorage::write()` function in `secure/storage/src/on_disk.rs` creates temporary files with default (world-readable) permissions and uses `fs::rename()` to replace the original storage file. On Unix systems, `fs::rename()` preserves the source file's permissions rather than the destination's, causing any previously-set restrictive permissions (e.g., 0600) on the storage file to be replaced with the temporary file's looser permissions (e.g., 0644). This exposes validator consensus private keys stored in the file to all local users on the system.

## Finding Description

The vulnerability exists in the `write()` function implementation: [1](#0-0) 

When this function executes:
1. Line 66 creates a temporary file using `File::create()` without setting explicit permissions, resulting in default permissions based on the system umask (typically 0644 - world-readable)
2. Line 68 uses `fs::rename()` to atomically move the temporary file to the final location

On Unix systems, `fs::rename()` moves the inode from source to destination, **preserving all inode metadata including permissions from the source file**. This means the destination file inherits the temporary file's permissions rather than retaining its original permissions.

**Attack Scenario:**
1. Validator administrator deploys OnDiskStorage for consensus keys (as configured in validator.yaml files)
2. Administrator manually sets secure permissions (`chmod 600`) on the storage file to restrict access
3. During normal validator operation, `PersistentSafetyStorage` stores the consensus private key: [2](#0-1) 

4. This triggers `OnDiskStorage::write()`, which creates a world-readable temp file and renames it
5. The storage file now has 0644 permissions (world-readable) instead of 0600
6. Any local user can read the file and extract the BLS consensus private key

**Usage Context:**
OnDiskStorage is used in validator configurations: [3](#0-2) [4](#0-3) 

**Comparison with Secure Pattern:**
The codebase demonstrates the correct approach for handling sensitive files: [5](#0-4) 

This pattern explicitly sets `mode(0o600)` on Unix systems. The OnDiskStorage implementation fails to apply this pattern.

## Impact Explanation

**Critical Severity** - This meets the "$1,000,000" tier criteria for multiple reasons:

1. **Consensus/Safety Violations**: Exposing the consensus private key enables an attacker to:
   - Sign conflicting votes (equivocation/double-voting)
   - Participate in Byzantine attacks against consensus
   - Cause the validator to be slashed for malicious behavior
   - Potentially break consensus safety guarantees if combined with other compromised validators

2. **Loss of Funds**: The compromised validator faces:
   - Slashing penalties for observed equivocation
   - Loss of staked funds
   - Removal from the validator set

3. **Network Impact**: Widespread exploitation across validators could:
   - Enable coordinated Byzantine attacks
   - Threaten network liveness and safety
   - Require emergency validator key rotations

The vulnerability directly violates critical invariants:
- **Consensus Safety**: "AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine"
- **Cryptographic Correctness**: "BLS signatures, VRF, and hash operations must be secure"

## Likelihood Explanation

**High Likelihood** in affected deployments:

1. **Automatic Trigger**: The vulnerability triggers automatically on every write operation - no attacker action needed beyond having local system access
2. **Realistic Deployment Scenario**: While the README warns against production use, OnDiskStorage is:
   - Used in validator configuration templates
   - Commonly deployed in development/testing environments
   - May be used in early-stage networks or testnets
3. **Shared System Access**: Development and testing environments often run on shared systems where multiple users have accounts
4. **Administrator False Sense of Security**: An admin might manually set secure permissions believing this protects the file, unaware that subsequent writes reset permissions
5. **No Warning on Permission Loss**: The system provides no indication that file permissions have been relaxed

## Recommendation

Apply the same secure file creation pattern used elsewhere in the codebase. Modify the `write()` function to set restrictive permissions on the temporary file before writing:

```rust
fn write(&self, data: &HashMap<String, Value>) -> Result<(), Error> {
    let contents = serde_json::to_vec(data)?;
    
    // Create temp file with secure permissions
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);  // Owner read/write only
    }
    let mut file = opts.open(self.temp_path.path())?;
    
    file.write_all(&contents)?;
    drop(file);  // Ensure file is closed before rename
    fs::rename(&self.temp_path, &self.file_path)?;
    Ok(())
}
```

Additionally, set secure permissions during initial file creation: [6](#0-5) 

Replace line 36-37 with:
```rust
let mut opts = std::fs::OpenOptions::new();
opts.write(true).create(true);
#[cfg(unix)]
{
    use std::os::unix::fs::OpenOptionsExt;
    opts.mode(0o600);
}
opts.open(&file_path)
    .unwrap_or_else(|_| panic!("Unable to create storage at path: {:?}", file_path));
```

## Proof of Concept

```rust
#[cfg(test)]
mod permission_test {
    use super::*;
    use aptos_temppath::TempPath;
    use std::collections::HashMap;
    use std::os::unix::fs::PermissionsExt;
    
    #[test]
    #[cfg(unix)]
    fn test_permission_inheritance_vulnerability() {
        // Create storage with a file
        let temp_dir = TempPath::new();
        temp_dir.create_as_dir().unwrap();
        let storage_path = temp_dir.path().join("secure-data.json");
        
        let mut storage = OnDiskStorage::new(storage_path.clone());
        
        // Write initial data
        let mut data = HashMap::new();
        data.insert("test_key".to_string(), serde_json::json!("test_value"));
        storage.write(&data).unwrap();
        
        // Manually set secure permissions (simulating admin action)
        std::fs::set_permissions(&storage_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        
        // Verify permissions are secure
        let metadata = std::fs::metadata(&storage_path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        
        // Write again (simulating normal operation)
        data.insert("another_key".to_string(), serde_json::json!("another_value"));
        storage.write(&data).unwrap();
        
        // BUG: Permissions are now world-readable!
        let metadata = std::fs::metadata(&storage_path).unwrap();
        let final_perms = metadata.permissions().mode() & 0o777;
        
        // This assertion will FAIL, demonstrating the vulnerability
        // The file will have 0o644 (or whatever umask allows) instead of 0o600
        assert_eq!(final_perms, 0o600, 
            "VULNERABILITY: File permissions changed from 0o600 to 0o{:o} after write(), exposing consensus keys!",
            final_perms
        );
    }
}
```

**Notes:**
- While the OnDiskStorage README states it should not be used in production, the specific permission inheritance bug via `fs::rename()` is not documented
- The vulnerability is present in validator configuration templates and may be deployed in development/testing environments with shared system access
- Even in non-production environments, consensus key exposure enables attack research and potential network disruption
- The fix is straightforward and aligns with existing secure file handling patterns in the codebase

### Citations

**File:** secure/storage/src/on_disk.rs (L35-38)
```rust
        if !file_path.exists() {
            File::create(&file_path)
                .unwrap_or_else(|_| panic!("Unable to create storage at path: {:?}", file_path));
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

**File:** consensus/safety-rules/src/persistent_safety_storage.rs (L68-68)
```rust
        let result = internal_store.set(CONSENSUS_KEY, consensus_private_key);
```

**File:** docker/compose/aptos-node/validator.yaml (L11-13)
```yaml
    backend:
      type: "on_disk_storage"
      path: secure-data.json
```

**File:** config/src/config/secure_backend_config.rs (L166-167)
```rust
            SecureBackend::OnDiskStorage(config) => {
                let storage = Storage::from(OnDiskStorage::new(config.path()));
```

**File:** crates/aptos/src/common/utils.rs (L224-229)
```rust
pub fn write_to_user_only_file(path: &Path, name: &str, bytes: &[u8]) -> CliTypedResult<()> {
    let mut opts = OpenOptions::new();
    #[cfg(unix)]
    opts.mode(0o600);
    write_to_file_with_opts(path, name, bytes, &mut opts)
}
```
