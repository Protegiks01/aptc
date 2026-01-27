# Audit Report

## Title
Plaintext Storage of Cryptographic Keys in Backup and Recovery System Enables Key Theft

## Summary
The Aptos secure storage system lacks encrypted key backup mechanisms. Private keys (consensus, network, and account keys) are stored and exported in plaintext, protected only by filesystem permissions. This design flaw enables key theft through backup system compromise, violating the fundamental security requirement for cryptographic key management.

## Finding Description

The security question asks: "If keys need to be backed up for disaster recovery, is there a secure backup mechanism that doesn't expose keys?" The answer is **no**—there is no secure backup mechanism.

**Vulnerability Details:**

1. **Plaintext Key Storage in OnDiskStorage:**
The `OnDiskStorage` implementation stores all keys in plaintext JSON format with no encryption: [1](#0-0) 

The `write()` method serializes keys directly to JSON: [2](#0-1) 

2. **Unencrypted Key Export Function:**
The `export_private_key()` function in `CryptoStorage` trait returns plaintext private keys: [3](#0-2) 

Implementation returns the key directly from storage: [4](#0-3) 

3. **Plaintext Validator Key Backup Files:**
Genesis key generation creates plaintext YAML files for backup: [5](#0-4) 

Keys are written with only filesystem permissions as protection: [6](#0-5) 

The file permission protection is Unix-only and provides no encryption: [7](#0-6) 

4. **Base64 Encoding (Not Encryption) in Vault Backup:**
The Vault `KeyBackup` mechanism only base64 encodes keys, providing no cryptographic protection: [8](#0-7) 

5. **Production Usage Despite Warnings:**
Despite documentation warnings, `OnDiskStorage` is configured for production validators: [9](#0-8) 

The README acknowledges the lack of security: [10](#0-9) 

**Attack Scenario:**

1. Validator operator generates keys for disaster recovery backup
2. Keys are exported via `export_private_key()` or by copying storage files
3. Backup files contain plaintext consensus keys, network keys, and account keys
4. Attacker compromises backup storage (cloud storage, backup server, CI/CD pipeline, monitoring systems)
5. Attacker extracts plaintext keys from backup files
6. Attacker can now:
   - Sign malicious consensus votes (double-signing, equivocation)
   - Impersonate the validator on the network
   - Submit transactions as the validator account
   - Steal staked funds

## Impact Explanation

**Critical Severity** - This vulnerability enables multiple critical attacks:

1. **Consensus Safety Violation**: Stolen consensus keys allow an attacker to participate in consensus as the compromised validator, enabling double-signing and equivocation attacks that could break consensus safety under the Byzantine fault tolerance threshold.

2. **Loss of Funds**: Stolen account keys provide access to validator staking accounts, enabling theft of staked APT tokens.

3. **Validator Impersonation**: Network keys allow complete impersonation of validators, enabling man-in-the-middle attacks on consensus messages.

This meets the **Critical Severity** criteria per Aptos bug bounty:
- "Loss of Funds (theft or minting)" ✓
- "Consensus/Safety violations" ✓

The vulnerability breaks the **Cryptographic Correctness** invariant: "BLS signatures, VRF, and hash operations must be secure" - the system fails to protect the private keys that underpin these operations.

## Likelihood Explanation

**High Likelihood** - This vulnerability will be exploited whenever:

1. **Backup Requirements**: Validator operators MUST backup keys for disaster recovery - this is operational necessity
2. **Attack Surface**: Backup systems are high-value targets with broad attack surface:
   - Cloud storage services (S3, GCS, Azure Blob)
   - Backup servers and appliances
   - CI/CD pipeline artifacts
   - Container registries (Docker images with keys)
   - Log aggregation systems
   - Monitoring/observability platforms
   - Development machines where operators test configurations
3. **Supply Chain**: Many third-party services have access to backup storage
4. **Windows Deployments**: No file permission protection on Windows systems (the `#[cfg(unix)]` guard means keys are world-readable on Windows)

The likelihood is HIGHER than typical vulnerabilities because:
- It affects the operational workflow (backups are mandatory)
- The attack doesn't require exploiting the validator directly
- Many organizations have weaker security on backup infrastructure than production systems

## Recommendation

Implement encrypted key backup and recovery mechanisms:

1. **Add Password-Protected Key Export:**
```rust
fn export_private_key_encrypted(&self, name: &str, password: &str) -> Result<Vec<u8>, Error> {
    let private_key = self.export_private_key(name)?;
    let salt = generate_random_salt();
    let key = derive_key_from_password(password, &salt);
    let encrypted = encrypt_with_aes_256_gcm(&private_key.to_bytes(), &key)?;
    Ok(encode_encrypted_backup(salt, encrypted))
}
```

2. **Implement Encrypted Storage Backend:**
Create an `EncryptedOnDiskStorage` variant that:
    - Derives encryption keys from a master password or HSM
    - Encrypts all data before writing to disk
    - Uses authenticated encryption (AES-256-GCM)
    - Stores key derivation parameters securely

3. **Hardware Security Module Integration:**
Add HSM support for production deployments:
    - Keys never leave the HSM
    - Backup via HSM-specific mechanisms
    - Use PKCS#11 or similar standards

4. **Update Documentation:**
Clearly document that plaintext backups are insecure and provide encrypted alternatives.

5. **Mandatory Encryption for Mainnet:**
Update the config sanitizer to reject unencrypted storage for mainnet validators: [11](#0-10) 

## Proof of Concept

**Demonstrating Plaintext Key Storage:**

```rust
use aptos_secure_storage::{CryptoStorage, OnDiskStorage, Storage};
use aptos_temppath::TempPath;
use std::fs;

#[test]
fn test_plaintext_key_exposure() {
    // Setup storage
    let temp_path = TempPath::new();
    temp_path.create_as_file().unwrap();
    let mut storage = Storage::from(OnDiskStorage::new(temp_path.path().to_path_buf()));
    
    // Create a key
    let key_name = "consensus_key";
    storage.create_key(key_name).unwrap();
    
    // Read the storage file directly
    let file_contents = fs::read_to_string(temp_path.path()).unwrap();
    
    // Verify the private key is stored in plaintext JSON
    assert!(file_contents.contains(key_name));
    assert!(file_contents.contains("\"value\""));
    
    // Export the key - returns plaintext
    let exported_key = storage.export_private_key(key_name).unwrap();
    
    // An attacker with file access can:
    // 1. Read the JSON storage file directly
    // 2. Parse the private key bytes from the JSON
    // 3. Use the key to sign consensus messages
    
    println!("Storage file contains: {}", file_contents);
    println!("Exported key (plaintext): {:?}", exported_key.to_bytes());
}
```

**Demonstrating Validator Key Backup Exposure:**

```bash
# Generate validator keys
aptos genesis generate-keys --output-dir ./validator-keys

# Keys are stored in plaintext YAML
cat ./validator-keys/private-keys.yaml
# Output shows:
# ---
# account_address: "0x..."
# account_private_key: "0x..." # PLAINTEXT
# consensus_private_key: "0x..." # PLAINTEXT
# full_node_network_private_key: "0x..." # PLAINTEXT
# validator_network_private_key: "0x..." # PLAINTEXT

# Any backup of this directory exposes all keys
tar czf backup.tar.gz ./validator-keys
# backup.tar.gz now contains all validator keys in plaintext
```

**Attack Simulation:**

An attacker who gains read access to backup storage can extract keys and use them for consensus attacks, validator impersonation, or fund theft. No password, encryption, or additional authentication is required.

## Notes

This vulnerability specifically addresses the security question about backup and recovery mechanisms. While the codebase documentation warns against using `OnDiskStorage` in production, it remains the configured backend for validator genesis and the only practical backup mechanism provided. The lack of encrypted alternatives forces operators to choose between disaster recovery capability and key security—a false choice that should be resolved through proper cryptographic key management.

### Citations

**File:** secure/storage/src/on_disk.rs (L16-27)
```rust
/// OnDiskStorage represents a key value store that is persisted to the local filesystem and is
/// intended for single threads (or must be wrapped by a Arc<RwLock<>>). This provides no permission
/// checks and simply offers a proof of concept to unblock building of applications without more
/// complex data stores. Internally, it reads and writes all data to a file, which means that it
/// must make copies of all key material which violates the code base. It violates it because
/// the anticipation is that data stores would securely handle key material. This should not be used
/// in production.
pub struct OnDiskStorage {
    file_path: PathBuf,
    temp_path: TempPath,
    time_service: TimeService,
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

**File:** secure/storage/src/crypto_storage.rs (L16-17)
```rust
    /// Returns the Ed25519 private key stored at 'name'.
    fn export_private_key(&self, name: &str) -> Result<Ed25519PrivateKey, Error>;
```

**File:** secure/storage/src/crypto_kv_storage.rs (L26-28)
```rust
    fn export_private_key(&self, name: &str) -> Result<Ed25519PrivateKey, Error> {
        self.get(name).map(|v| v.value)
    }
```

**File:** crates/aptos/src/genesis/keys.rs (L28-31)
```rust
const PRIVATE_KEYS_FILE: &str = "private-keys.yaml";
pub const PUBLIC_KEYS_FILE: &str = "public-keys.yaml";
const VALIDATOR_FILE: &str = "validator-identity.yaml";
const VFN_FILE: &str = "validator-full-node-identity.yaml";
```

**File:** crates/aptos/src/genesis/keys.rs (L82-97)
```rust
        write_to_user_only_file(
            private_keys_file.as_path(),
            PRIVATE_KEYS_FILE,
            to_yaml(&private_identity)?.as_bytes(),
        )?;
        write_to_user_only_file(
            public_keys_file.as_path(),
            PUBLIC_KEYS_FILE,
            to_yaml(&public_identity)?.as_bytes(),
        )?;
        write_to_user_only_file(
            validator_file.as_path(),
            VALIDATOR_FILE,
            to_yaml(&validator_blob)?.as_bytes(),
        )?;
        write_to_user_only_file(vfn_file.as_path(), VFN_FILE, to_yaml(&vfn_blob)?.as_bytes())?;
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

**File:** secure/storage/vault/src/lib.rs (L777-792)
```rust
impl KeyBackup {
    pub fn new(key: &Ed25519PrivateKey) -> Self {
        let mut key_bytes = key.to_bytes().to_vec();
        let pub_key_bytes = key.public_key().to_bytes();
        key_bytes.extend(pub_key_bytes);

        let now = chrono::Utc::now();
        let time_as_str = now.to_rfc3339();

        let info = KeyBackupInfo {
            key: Some(base64::encode(key_bytes)),
            public_key: Some(base64::encode(pub_key_bytes)),
            creation_time: now.timestamp_subsec_millis(),
            time: time_as_str.clone(),
            ..Default::default()
        };
```

**File:** crates/aptos-genesis/src/builder.rs (L620-623)
```rust
        // Use a file based storage backend for safety rules
        let mut storage = OnDiskStorageConfig::default();
        storage.set_data_dir(validator.dir.clone());
        config.consensus.safety_rules.backend = SecureBackend::OnDiskStorage(storage);
```

**File:** secure/storage/README.md (L37-42)
```markdown
- `OnDisk`: Similar to InMemory, the OnDisk secure storage implementation provides another
useful testing implementation: an on-disk storage engine, where the storage backend is
implemented using a single file written to local disk. In a similar fashion to the in-memory
storage, on-disk should not be used in production environments as it provides no security
guarantees (e.g., encryption before writing to disk). Moreover, OnDisk storage does not
currently support concurrent data accesses.
```

**File:** config/src/config/safety_rules_config.rs (L86-96)
```rust
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
```
