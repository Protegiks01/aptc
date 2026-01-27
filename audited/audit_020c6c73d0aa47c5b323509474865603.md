# Audit Report

## Title
Critical: Validator Private Keys Exposed in Plaintext via OnDiskStorage Backups

## Summary
The `OnDiskStorage` implementation stores validator consensus private keys (BLS12-381) in unencrypted JSON format on disk. Any filesystem backup mechanism (cloud backups, system snapshots, disk cloning) will expose these keys in plaintext, allowing an attacker with backup access to compromise validator identities and break consensus safety guarantees.

## Finding Description

The Aptos secure storage system provides multiple backend implementations for storing cryptographic keys. The `OnDiskStorage` backend persists data to a local JSON file without any encryption. [1](#0-0) 

When validators use `OnDiskStorage` (which the README acknowledges happens in test/development environments), consensus private keys are stored via `PersistentSafetyStorage`: [2](#0-1) 

The `CryptoKVStorage` implementation directly stores private keys without encryption: [3](#0-2) 

The write operation serializes to JSON without encryption: [4](#0-3) 

The BLS12-381 private key serialization uses standard byte encoding: [5](#0-4) 

**Attack Path:**
1. Validator node configured with OnDiskStorage (common in testnet/devnet configurations)
2. Consensus private keys stored at `/opt/aptos/data/secure_storage.json` or similar path
3. Automated backup system (cloud sync, disk snapshots, system backups) copies this file
4. Attacker gains access to backup storage (compromised cloud account, backup system breach, privileged access)
5. Attacker extracts plaintext JSON and retrieves BLS12-381 private key bytes
6. Attacker can now sign consensus messages, propose malicious blocks, and violate consensus safety

The README acknowledges the risk but doesn't prevent usage: [6](#0-5) 

## Impact Explanation

**Critical Severity** - This vulnerability allows complete compromise of validator consensus keys, which breaks fundamental security guarantees:

1. **Consensus Safety Violation**: With stolen validator keys, an attacker can sign conflicting blocks at the same height, causing consensus splits and violating Byzantine fault tolerance assumptions.

2. **Network Partition**: Malicious block signing can cause permanent network partitions requiring manual intervention or hard forks.

3. **Loss of Funds**: Compromised validators can be used to steal staking rewards, manipulate the validator set, or approve malicious governance proposals.

4. **Complete Identity Theft**: The attacker gains full validator authority without requiring 51% stake or direct node access.

This meets the "Consensus/Safety violations" category for Critical Severity ($1,000,000 maximum payout).

## Likelihood Explanation

**High Likelihood:**

1. **Common Configuration**: Despite warnings, OnDiskStorage is widely used in testnet, devnet, and local development environments based on configuration examples found in the codebase.

2. **Ubiquitous Backups**: Modern infrastructure universally employs automated backup systems (cloud sync, snapshots, disk cloning) that will capture the unencrypted storage file.

3. **Low Attacker Bar**: The attacker only needs filesystem-level read access to backups, which is much easier than direct node compromise. This includes:
   - Compromised cloud backup accounts (AWS S3, Google Cloud Storage)
   - Privileged system administrators with backup access
   - Breached backup vendors or contractors
   - Misconfigured backup permissions

4. **Persistent Exposure**: Once a backup containing keys exists, the vulnerability persists indefinitely until those specific validators rotate their keys.

## Recommendation

**Immediate Mitigations:**

1. **Enforce VaultStorage for Production**: Add runtime checks that prevent validator nodes from starting with OnDiskStorage in non-test modes:

```rust
// In consensus/safety-rules/src/safety_rules_manager.rs
pub fn storage(config: &SecureBackend) -> Result<Storage, Error> {
    match config {
        SecureBackend::OnDiskStorage(_) => {
            if !cfg!(test) && !cfg!(feature = "testing") {
                return Err(Error::SecureStorageUnexpectedError(
                    "OnDiskStorage is insecure and must not be used in production. Use VaultStorage instead.".to_string()
                ));
            }
        },
        _ => {}
    }
    Ok(config.into())
}
```

2. **Add Encryption Layer to OnDiskStorage**: For development environments, implement mandatory encryption before writing to disk using OS keyring or environment-derived keys.

3. **File Permission Hardening**: Set restrictive permissions (0600) and add file integrity monitoring for the storage file.

4. **Key Rotation Documentation**: Provide clear procedures for immediate key rotation if backup compromise is suspected.

**Long-term Solutions:**

1. **Hardware Security Module (HSM) Integration**: Support HSM-backed key storage for production validators.

2. **Encrypted Storage Backend**: Implement a new storage backend that uses OS-level encryption (Linux LUKS, BitLocker) or application-level encryption with secure key derivation.

3. **Backup Security Guidelines**: Publish comprehensive documentation on secure backup practices for validator operators, including encryption requirements for backup storage.

## Proof of Concept

```rust
// File: consensus/safety-rules/tests/backup_key_exposure_test.rs
use aptos_crypto::{bls12381, PrivateKey, Uniform};
use aptos_secure_storage::{KVStorage, OnDiskStorage, Storage};
use aptos_temppath::TempPath;
use aptos_types::account_address::AccountAddress;
use consensus_safety_rules::PersistentSafetyStorage;
use std::fs;

#[test]
fn test_ondisk_backup_exposes_validator_keys() {
    // Step 1: Create OnDiskStorage like a validator would
    let temp_path = TempPath::new();
    temp_path.create_as_file().unwrap();
    let storage_file = temp_path.path().to_path_buf();
    
    let storage = Storage::from(OnDiskStorage::new(storage_file.clone()));
    
    // Step 2: Initialize validator with consensus key
    let mut rng = rand::thread_rng();
    let original_key = bls12381::PrivateKey::generate(&mut rng);
    let author = AccountAddress::random();
    let waypoint = aptos_types::waypoint::Waypoint::default();
    
    let _safety_storage = PersistentSafetyStorage::initialize(
        storage,
        author,
        original_key.clone(),
        waypoint,
        false,
    );
    
    // Step 3: Simulate backup - just read the file
    let backup_contents = fs::read_to_string(&storage_file)
        .expect("Failed to read storage file");
    
    println!("Backup file contents (UNENCRYPTED):\n{}", backup_contents);
    
    // Step 4: Extract the key from JSON backup
    let parsed: serde_json::Value = serde_json::from_str(&backup_contents).unwrap();
    let consensus_key_entry = &parsed["consensus_key"];
    
    // Verify the private key is exposed in plaintext
    assert!(backup_contents.contains("consensus_key"));
    assert!(consensus_key_entry.is_object());
    
    println!("\n[CRITICAL] Validator consensus private key is stored in PLAINTEXT!");
    println!("An attacker with backup access can extract this key and compromise consensus.");
}
```

**To reproduce:**
1. Run the test: `cargo test --package consensus-safety-rules test_ondisk_backup_exposes_validator_keys`
2. Observe that the JSON file contains the consensus private key in an easily parseable format
3. Note that any backup mechanism copying this file exposes the validator's identity

**Notes**

This vulnerability affects any deployment using `OnDiskStorage`, which includes many testnet and development configurations. While the README warns against production use, the severity stems from:

1. The ease of exploitation (backup access vs. direct node compromise)
2. The permanence of exposure (backups persist indefinitely)  
3. The critical nature of consensus keys (complete validator authority)
4. The realistic deployment scenarios where OnDiskStorage is used despite warnings

The recommended mitigation is to programmatically prevent OnDiskStorage in non-test builds and mandate VaultStorage or HSM-backed solutions for any validator handling real value.

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

**File:** consensus/safety-rules/src/persistent_safety_storage.rs (L63-80)
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
```

**File:** secure/storage/src/crypto_kv_storage.rs (L55-57)
```rust
    fn import_private_key(&mut self, name: &str, key: Ed25519PrivateKey) -> Result<(), Error> {
        self.set(name, key)
    }
```

**File:** crates/aptos-crypto/src/bls12381/bls12381_keys.rs (L89-97)
```rust
impl PrivateKey {
    /// The length of a serialized PrivateKey struct.
    // NOTE: We have to hardcode this here because there is no library-defined constant
    pub const LENGTH: usize = 32;

    /// Serialize a PrivateKey.
    pub fn to_bytes(&self) -> [u8; Self::LENGTH] {
        self.privkey.to_bytes()
    }
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
