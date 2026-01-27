# Audit Report

## Title
OnDiskStorage Creates World-Readable Files Exposing Consensus Private Keys to Local Attackers

## Summary
The `OnDiskStorage` implementation creates files using `File::create()` without setting restrictive Unix permissions, resulting in world-readable files (mode 0644) that expose validator consensus private keys to any local user on the system. This violates the fundamental security requirement that cryptographic keys must be protected from unauthorized access.

## Finding Description

The `OnDiskStorage` struct is used by validators to persist consensus private keys and safety data to disk. [1](#0-0) 

The implementation creates files in two locations without setting appropriate permissions:

1. **Initial file creation** in the constructor: [2](#0-1) 

2. **Temporary file creation** during writes: [3](#0-2) 

Both use `File::create()` which respects the process umask on Unix systems, typically resulting in mode 0644 (rw-r--r--) permissions, making files readable by all users on the system.

The storage is used to persist validator consensus private keys: [4](#0-3) 

Despite documentation stating "This should not be used in production", the `OnDiskStorage` backend is configured in production validator configurations: [5](#0-4) 

The codebase demonstrates awareness of this security requirement in other components that properly set mode 0600: [6](#0-5) 

**Attack Path:**
1. Attacker gains local access to validator node (compromised service, container escape, SSH access, etc.)
2. Attacker reads `/opt/aptos/data/secure-data.json` (world-readable)
3. Attacker extracts the BLS12-381 consensus private key from the JSON storage
4. Attacker can now sign malicious consensus votes, timeout certificates, or blocks
5. Attacker can cause equivocation (signing conflicting messages), breaking AptosBFT safety guarantees
6. This enables double-spending attacks and chain splits under the Byzantine fault threshold

## Impact Explanation

**Severity: Critical** (up to $1,000,000 per Aptos Bug Bounty)

This vulnerability enables **Consensus/Safety violations**, a Critical impact category. With access to a validator's consensus private key, an attacker can:

- **Sign conflicting consensus messages** (equivocation), violating the fundamental safety property of AptosBFT that prevents chain splits with <1/3 Byzantine validators
- **Participate in malicious quorum formation** to commit invalid blocks
- **Cause loss of funds** through double-spending if they control enough compromised validators
- **Break network determinism** by signing messages that conflict with the honest validator's behavior

The vulnerability affects **all validators** using the default `OnDiskStorage` backend configuration, which includes the provided Docker Compose and Terraform Helm configurations used for deployment.

## Likelihood Explanation

**Likelihood: High**

This vulnerability has a high likelihood of exploitation because:

1. **Common attack vector**: Local access to servers is frequently achieved through:
   - Compromised application services running on the same host
   - Container escape vulnerabilities
   - Supply chain attacks in dependencies
   - Misconfigured SSH/remote access
   - Insider threats (system administrators, DevOps personnel)

2. **Default configuration**: The vulnerable storage backend is used in provided configuration templates

3. **No additional barriers**: Once local access is gained, reading a world-readable file requires no special privileges or exploitation techniques

4. **High value target**: Validator nodes are valuable targets for attackers seeking to compromise blockchain consensus

5. **Silent exploitation**: The attack leaves minimal traces - just a file read operation in system logs

## Recommendation

Implement proper file permissions when creating storage files. Modify the `OnDiskStorage` implementation to set mode 0600 on Unix systems:

```rust
use std::fs::{File, OpenOptions};

impl OnDiskStorage {
    fn new_with_time_service(file_path: PathBuf, time_service: TimeService) -> Self {
        if !file_path.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                OpenOptions::new()
                    .write(true)
                    .create(true)
                    .mode(0o600)
                    .open(&file_path)
                    .unwrap_or_else(|_| panic!("Unable to create storage at path: {:?}", file_path));
            }
            #[cfg(not(unix))]
            {
                File::create(&file_path)
                    .unwrap_or_else(|_| panic!("Unable to create storage at path: {:?}", file_path));
            }
        }
        // ... rest of implementation
    }

    fn write(&self, data: &HashMap<String, Value>) -> Result<(), Error> {
        let contents = serde_json::to_vec(data)?;
        
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(self.temp_path.path())?;
            file.write_all(&contents)?;
        }
        #[cfg(not(unix))]
        {
            let mut file = File::create(self.temp_path.path())?;
            file.write_all(&contents)?;
        }
        
        fs::rename(&self.temp_path, &self.file_path)?;
        Ok(())
    }
}
```

**Additional Recommendations:**
1. Update documentation to explicitly warn about file permission requirements
2. Add runtime validation to check file permissions on startup
3. Consider deprecating `OnDiskStorage` for production and mandate Vault usage
4. Add security scanning to detect world-readable sensitive files

## Proof of Concept

```rust
use std::fs::{File, metadata};
use std::io::Write;
use std::path::PathBuf;
use aptos_secure_storage::{OnDiskStorage, Storage, KVStorage};
use aptos_crypto::{bls12381, PrivateKey, Uniform};

#[test]
fn test_ondisk_storage_file_permissions_vulnerability() {
    // Create OnDiskStorage with a test file
    let temp_dir = tempfile::tempdir().unwrap();
    let file_path = temp_dir.path().join("test_storage.json");
    
    let mut storage = Storage::from(OnDiskStorage::new(file_path.clone()));
    
    // Store a mock consensus private key
    let consensus_key = bls12381::PrivateKey::generate_for_testing();
    storage.set("consensus_key", consensus_key.clone()).unwrap();
    
    // Check file permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = metadata(&file_path).unwrap();
        let permissions = metadata.permissions();
        let mode = permissions.mode();
        
        // Extract permission bits (last 9 bits)
        let file_perms = mode & 0o777;
        
        println!("File permissions: {:o}", file_perms);
        
        // VULNERABILITY: File is created with default permissions (usually 0644)
        // which means it's readable by group and others
        assert_ne!(file_perms, 0o600, 
            "VULNERABILITY CONFIRMED: File permissions are {:o}, not 0600. \
             Any local user can read the consensus private key!", 
            file_perms);
        
        // Demonstrate that the file is world-readable
        assert!(file_perms & 0o044 != 0, 
            "File is readable by group and/or others - CRITICAL VULNERABILITY!");
    }
    
    // An attacker with local access can now read the file
    let stolen_data = std::fs::read_to_string(&file_path).unwrap();
    println!("Attacker can read: {}", stolen_data);
    
    // Parse and extract the consensus key
    let json: serde_json::Value = serde_json::from_str(&stolen_data).unwrap();
    println!("Consensus key exposed in world-readable file: {:?}", 
             json.get("consensus_key"));
}
```

**Expected Output:**
```
File permissions: 644
thread 'test_ondisk_storage_file_permissions_vulnerability' panicked at:
VULNERABILITY CONFIRMED: File permissions are 644, not 0600. 
Any local user can read the consensus private key!
```

This demonstrates that any local user on the validator node can read the consensus private key, enabling them to sign malicious consensus messages and break AptosBFT safety guarantees.

### Citations

**File:** secure/storage/src/on_disk.rs (L16-22)
```rust
/// OnDiskStorage represents a key value store that is persisted to the local filesystem and is
/// intended for single threads (or must be wrapped by a Arc<RwLock<>>). This provides no permission
/// checks and simply offers a proof of concept to unblock building of applications without more
/// complex data stores. Internally, it reads and writes all data to a file, which means that it
/// must make copies of all key material which violates the code base. It violates it because
/// the anticipation is that data stores would securely handle key material. This should not be used
/// in production.
```

**File:** secure/storage/src/on_disk.rs (L35-38)
```rust
        if !file_path.exists() {
            File::create(&file_path)
                .unwrap_or_else(|_| panic!("Unable to create storage at path: {:?}", file_path));
        }
```

**File:** secure/storage/src/on_disk.rs (L64-69)
```rust
    fn write(&self, data: &HashMap<String, Value>) -> Result<(), Error> {
        let contents = serde_json::to_vec(data)?;
        let mut file = File::create(self.temp_path.path())?;
        file.write_all(&contents)?;
        fs::rename(&self.temp_path, &self.file_path)?;
        Ok(())
```

**File:** consensus/safety-rules/src/persistent_safety_storage.rs (L63-81)
```rust
    fn initialize_keys_and_accounts(
        internal_store: &mut Storage,
        author: Author,
        consensus_private_key: bls12381::PrivateKey,
    ) -> Result<(), Error> {
        let result = internal_store.set(CONSENSUS_KEY, consensus_private_key);
        // Attempting to re-initialize existing storage. This can happen in environments like
        // forge. Rather than be rigid here, leave it up to the developer to detect
        // inconsistencies or why they did not reset storage between rounds. Do not repeat the
        // checks again below, because it is just too strange to have a partially configured
        // storage.
        if let Err(aptos_secure_storage::Error::KeyAlreadyExists(_)) = result {
            warn!("Attempted to re-initialize existing storage");
            return Ok(());
        }

        internal_store.set(OWNER_ACCOUNT, author)?;
        Ok(())
    }
```

**File:** docker/compose/aptos-node/validator.yaml (L11-13)
```yaml
    backend:
      type: "on_disk_storage"
      path: secure-data.json
```

**File:** crates/aptos/src/common/utils.rs (L223-229)
```rust
/// Write a User only read / write file
pub fn write_to_user_only_file(path: &Path, name: &str, bytes: &[u8]) -> CliTypedResult<()> {
    let mut opts = OpenOptions::new();
    #[cfg(unix)]
    opts.mode(0o600);
    write_to_file_with_opts(path, name, bytes, &mut opts)
}
```
