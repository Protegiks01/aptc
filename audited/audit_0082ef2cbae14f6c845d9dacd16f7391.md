# Audit Report

## Title
Consensus Private Keys Stored in Plaintext on Filesystem via OnDiskStorage Backend

## Summary
The `PersistentSafetyStorage` implementation accepts any `Storage` backend without enforcing encryption requirements. The default production configuration uses `OnDiskStorage`, which stores all data—including BLS12381 consensus private keys—as plaintext JSON on the filesystem. Any attacker with filesystem read access can steal validator consensus keys, enabling equivocation attacks and consensus safety violations.

## Finding Description

The vulnerability stems from three critical design flaws:

**1. OnDiskStorage stores data as plaintext JSON** [1](#0-0) [2](#0-1) 

The `OnDiskStorage` implementation explicitly states it "should not be used in production," yet it reads and writes all data as unencrypted JSON files. When consensus private keys are stored, they are serialized as hex-encoded strings.

**2. BLS12381 PrivateKey serializes as plaintext hex in JSON** [3](#0-2) 

When serialized to human-readable formats like JSON, cryptographic keys use `to_encoded_string()` which returns the raw key bytes as a hex string prefixed with "0x". This means the consensus private key appears in the JSON file as a readable hex string.

**3. PersistentSafetyStorage does not enforce encrypted storage** [4](#0-3) 

The `initialize()` function accepts any `Storage` backend and directly stores the consensus private key without validating that the backend uses encryption: [5](#0-4) 

**4. OnDiskStorage is the default production configuration** [6](#0-5) [7](#0-6) 

Both the Docker Compose and Terraform/Helm production configurations explicitly use `type: "on_disk_storage"` as the safety rules backend.

**5. Configuration sanitizer does not prevent OnDiskStorage on mainnet** [8](#0-7) 

The sanitizer only checks for `InMemoryStorage` on mainnet, but allows `OnDiskStorage`: [9](#0-8) 

**Attack Path:**
1. Attacker gains filesystem read access to validator node (via vulnerability, misconfiguration, backup compromise, or insider access)
2. Attacker reads `/opt/aptos/data/secure-data.json`
3. File contains plaintext JSON with `CONSENSUS_KEY` field storing the BLS12381 private key as hex string (e.g., `"0x1234abcd..."`)
4. Attacker imports the stolen private key and can now sign blocks on behalf of the validator
5. Attacker can cause equivocation (double-signing), sign invalid blocks, or participate in Byzantine attacks

## Impact Explanation

**Critical Severity - Consensus Safety Violation**

This vulnerability enables complete compromise of validator consensus keys, which breaks the fundamental security invariant: **"Consensus Safety: AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine"**

With a stolen consensus key, an attacker can:
- Sign conflicting blocks at the same round (equivocation), violating BFT safety
- Participate in Byzantine behavior without controlling validator stake
- If multiple validators are compromised through this vector, could potentially fork the chain
- Sign malicious blocks that could be accepted by honest validators

This qualifies as **Critical Severity** per the Aptos bug bounty program's definition: "Consensus/Safety violations" with potential for "Non-recoverable network partition (requires hardfork)".

The impact extends to all validators using the default configuration, which includes production deployments using the official Docker Compose and Terraform/Helm configurations.

## Likelihood Explanation

**HIGH Likelihood**

The likelihood is high because:

1. **OnDiskStorage is the default**: All validators using the official deployment configurations (Docker Compose, Terraform/Helm) are vulnerable
2. **Common attack vectors**: Filesystem access can be gained through:
   - Container escape vulnerabilities
   - Host privilege escalation
   - Compromised backup systems accessing `/opt/aptos/data`
   - Misconfigured file permissions
   - Compromised monitoring/logging agents with file read access
   - Insider threats (system administrators, SRE teams)
3. **No encryption defense**: Unlike VaultStorage (which uses HashiCorp Vault's encryption), OnDiskStorage provides zero protection against filesystem reads
4. **Long-term exposure**: Keys persist on disk indefinitely, expanding the attack window
5. **No runtime detection**: There's no mechanism to detect when the file has been read by unauthorized processes

## Recommendation

**Immediate Actions:**

1. **Add storage backend validation in PersistentSafetyStorage:**

```rust
// In persistent_safety_storage.rs
pub fn initialize(
    internal_store: Storage,
    author: Author,
    consensus_private_key: bls12381::PrivateKey,
    waypoint: Waypoint,
    enable_cached_safety_data: bool,
) -> Result<Self, Error> {
    // Validate that the storage backend is secure
    if !is_secure_backend(&internal_store) {
        return Err(Error::SecureStorageUnexpectedError(
            "Consensus keys require encrypted storage backend (Vault). OnDiskStorage is not secure.".to_string()
        ));
    }
    // ... rest of implementation
}

fn is_secure_backend(storage: &Storage) -> bool {
    match storage {
        Storage::VaultStorage(_) => true,
        Storage::NamespacedStorage(ns) => is_secure_backend(ns.inner()),
        _ => false,
    }
}
```

2. **Update configuration sanitizer to block OnDiskStorage on mainnet:**

```rust
// In safety_rules_config.rs, add to sanitize() function:
if chain_id.is_mainnet() 
    && node_type.is_validator() 
    && matches!(safety_rules_config.backend, SecureBackend::OnDiskStorage(_)) 
{
    return Err(Error::ConfigSanitizerFailed(
        sanitizer_name,
        "OnDiskStorage backend is not secure for mainnet validators. Use Vault storage for encrypted key management.".to_string(),
    ));
}
```

3. **Update default configurations to use VaultStorage**

4. **Add documentation warning** about OnDiskStorage security risks

**Long-term Solution:**

Implement encrypted on-disk storage using platform-specific secure enclaves (TPM, SGX) or at minimum, encrypt the JSON file using a key derived from hardware or a separate key management service.

## Proof of Concept

**Demonstration of key extraction:**

```bash
#!/bin/bash
# Assume validator node running with default config
# Attacker with filesystem access runs:

# Read the unencrypted storage file
cat /opt/aptos/data/secure-data.json

# Output will contain (example):
# {
#   "CONSENSUS_KEY": {
#     "value": "0x1a2b3c4d5e6f...",  <-- BLS12381 private key in hex
#     "last_update": 1234567890
#   },
#   "OWNER_ACCOUNT": { ... },
#   "SAFETY_DATA": { ... }
# }

# Extract the consensus key
CONSENSUS_KEY=$(jq -r '.CONSENSUS_KEY.value' /opt/aptos/data/secure-data.json)

# The attacker now has the private key and can use it with standard
# BLS12381 libraries to sign arbitrary consensus messages
echo "Stolen consensus key: $CONSENSUS_KEY"
```

**Rust validation test:**

```rust
#[test]
fn test_ondisk_storage_exposes_keys_in_plaintext() {
    use aptos_secure_storage::{OnDiskStorage, KVStorage, Storage};
    use aptos_crypto::{bls12381, Uniform};
    use std::fs;
    use tempfile::TempDir;
    
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test-storage.json");
    
    let mut storage = Storage::from(OnDiskStorage::new(file_path.clone()));
    
    // Store a consensus key
    let mut rng = rand::thread_rng();
    let private_key = bls12381::PrivateKey::generate(&mut rng);
    storage.set("CONSENSUS_KEY", private_key.clone()).unwrap();
    
    // Read the file as plaintext
    let file_contents = fs::read_to_string(&file_path).unwrap();
    
    // Verify the key is visible in plaintext JSON
    assert!(file_contents.contains("CONSENSUS_KEY"));
    assert!(file_contents.contains("0x")); // Hex prefix
    
    // Verify we can extract the key bytes from the JSON
    let json: serde_json::Value = serde_json::from_str(&file_contents).unwrap();
    let key_hex = json["CONSENSUS_KEY"]["value"].as_str().unwrap();
    
    // Verify the extracted key can be parsed back
    let stolen_key = bls12381::PrivateKey::from_encoded_string(key_hex).unwrap();
    assert_eq!(stolen_key.public_key(), private_key.public_key());
    
    println!("VULNERABILITY CONFIRMED: Consensus key readable in plaintext from {}", file_path.display());
}
```

## Notes

This vulnerability demonstrates a critical gap between the implementation's security warning (OnDiskStorage "should not be used in production") and the actual default production configurations. The fact that official deployment templates use OnDiskStorage suggests this may be a widely deployed vulnerability affecting real mainnet validators.

The proper solution requires migrating all production validators to VaultStorage or implementing encrypted on-disk storage, which may require significant operational coordination.

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

**File:** secure/storage/src/on_disk.rs (L53-70)
```rust
    fn read(&self) -> Result<HashMap<String, Value>, Error> {
        let mut file = File::open(&self.file_path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        if contents.is_empty() {
            return Ok(HashMap::new());
        }
        let data = serde_json::from_str(&contents)?;
        Ok(data)
    }

    fn write(&self, data: &HashMap<String, Value>) -> Result<(), Error> {
        let contents = serde_json::to_vec(data)?;
        let mut file = File::create(self.temp_path.path())?;
        file.write_all(&contents)?;
        fs::rename(&self.temp_path, &self.file_path)?;
        Ok(())
    }
```

**File:** crates/aptos-crypto-derive/src/lib.rs (L191-209)
```rust
        impl ::serde::Serialize for #name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: ::serde::Serializer,
            {
                if serializer.is_human_readable() {
                    self.to_encoded_string()
                        .map_err(<S::Error as ::serde::ser::Error>::custom)
                        .and_then(|str| serializer.serialize_str(&str[..]))
                } else {
                    // See comment in deserialize_key.
                    serializer.serialize_newtype_struct(
                        #name_string,
                        serde_bytes::Bytes::new(&ValidCryptoMaterial::to_bytes(self).as_slice()),
                    )
                }
            }
        }
    }
```

**File:** consensus/safety-rules/src/persistent_safety_storage.rs (L30-61)
```rust
impl PersistentSafetyStorage {
    /// Use this to instantiate a PersistentStorage for a new data store, one that has no
    /// SafetyRules values set.
    pub fn initialize(
        mut internal_store: Storage,
        author: Author,
        consensus_private_key: bls12381::PrivateKey,
        waypoint: Waypoint,
        enable_cached_safety_data: bool,
    ) -> Self {
        // Initialize the keys and accounts
        Self::initialize_keys_and_accounts(&mut internal_store, author, consensus_private_key)
            .expect("Unable to initialize keys and accounts in storage");

        // Create the new persistent safety storage
        let safety_data = SafetyData::new(1, 0, 0, 0, None, 0);
        let mut persisent_safety_storage = Self {
            enable_cached_safety_data,
            cached_safety_data: Some(safety_data.clone()),
            internal_store,
        };

        // Initialize the safety data and waypoint
        persisent_safety_storage
            .set_safety_data(safety_data)
            .expect("Unable to initialize safety data");
        persisent_safety_storage
            .set_waypoint(&waypoint)
            .expect("Unable to initialize waypoint");

        persisent_safety_storage
    }
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

**File:** docker/compose/aptos-node/validator.yaml (L7-19)
```yaml
consensus:
  safety_rules:
    service:
      type: "local"
    backend:
      type: "on_disk_storage"
      path: secure-data.json
      namespace: ~
    initial_safety_rules_config:
      from_file:
        waypoint:
          from_file: /opt/aptos/genesis/waypoint.txt
        identity_blob_path: /opt/aptos/genesis/validator-identity.yaml
```

**File:** terraform/helm/aptos-node/files/configs/validator-base.yaml (L10-22)
```yaml
consensus:
  safety_rules:
    service:
      type: "local"
    backend:
      type: "on_disk_storage"
      path: secure-data.json
      namespace: ~
    initial_safety_rules_config:
      from_file:
        waypoint:
          from_file: /opt/aptos/genesis/waypoint.txt
        identity_blob_path: /opt/aptos/genesis/validator-identity.yaml
```

**File:** config/src/config/safety_rules_config.rs (L71-117)
```rust
impl ConfigSanitizer for SafetyRulesConfig {
    fn sanitize(
        node_config: &NodeConfig,
        node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let safety_rules_config = &node_config.consensus.safety_rules;

        // If the node is not a validator, there's nothing to be done
        if !node_type.is_validator() {
            return Ok(());
        }

        if let Some(chain_id) = chain_id {
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

            // Verify that the safety rules service is set to local for optimal performance
            if chain_id.is_mainnet() && !safety_rules_config.service.is_local() {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    format!("The safety rules service should be set to local in mainnet for optimal performance! Given config: {:?}", &safety_rules_config.service)
                ));
            }

            // Verify that the safety rules test config is not enabled in mainnet
            if chain_id.is_mainnet() && safety_rules_config.test.is_some() {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "The safety rules test config should not be used in mainnet!".to_string(),
                ));
            }
        }

        Ok(())
    }
}
```

**File:** config/src/config/secure_backend_config.rs (L45-48)
```rust
    /// Returns true iff the backend is in memory
    pub fn is_in_memory(&self) -> bool {
        matches!(self, SecureBackend::InMemoryStorage)
    }
```
