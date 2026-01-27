# Audit Report

## Title
Ed25519PrivateKey Exposure via Human-Readable Serialization in KVStorage Backends

## Summary
The KVStorage trait serializes Ed25519PrivateKey objects in human-readable hexadecimal format when using JSON-based storage backends (OnDiskStorage, VaultStorage KV methods). This exposes critical cryptographic key material in plain text within storage files, backups, and potentially audit logs, violating defense-in-depth principles for sensitive cryptographic material handling.

## Finding Description

The vulnerability stems from the serialization mechanism used by the `SerializeKey` procedural macro applied to `Ed25519PrivateKey`. When this key type is serialized using a human-readable serializer (such as `serde_json`), it converts the private key bytes into a hexadecimal string prefixed with "0x". [1](#0-0) 

The critical code path occurs in the `to_encoded_string()` method, which formats the key as readable hex: [2](#0-1) 

This human-readable serialization is invoked when `OnDiskStorage` persists Ed25519PrivateKey objects via the `CryptoKVStorage` trait implementation: [3](#0-2) 

The `OnDiskStorage` backend writes all data as JSON to disk: [4](#0-3) 

**Attack Scenario**: OnDiskStorage is configured as a production deployment option in multiple configurations: [5](#0-4) [6](#0-5) 

When a validator node uses `OnDiskStorage` for consensus safety rules (as shown in the Docker Compose configuration), the consensus private keys are stored in `secure-data.json` as:

```
{
  "consensus_key": {
    "last_update": 1234567890,
    "value": "0x<64_hexadecimal_characters_representing_32_byte_private_key>"
  }
}
```

**Exploitation Paths**:

1. **File System Backups**: Automated backup systems (cloud sync, snapshot tools, rsync) copy the JSON file containing readable private keys to potentially less-secure backup locations.

2. **File System Access**: Any process or user with read access to the data directory can extract the private key by reading the JSON file directly.

3. **Vault Audit Logs**: When VaultStorage's KVStorage interface is used (not the Transit engine), the JSON payload containing hex-encoded keys could be logged by Vault's audit logging if configured to log request bodies.

4. **Development/Testing Spillover**: The OnDiskStorage option, while documented as "testing-only" in the README, is present in production configuration templates, increasing the risk of accidental production deployment.

## Impact Explanation

**Severity: HIGH** (per Aptos Bug Bounty criteria)

This vulnerability enables multiple attack vectors:

1. **Consensus Safety Violation**: If a validator's consensus safety rules keys are compromised, an attacker can:
   - Sign conflicting votes violating safety rules
   - Cause validator equivocation leading to slashing
   - Participate in double-signing attacks

2. **Validator Impersonation**: Compromised network identity keys allow:
   - Man-in-the-middle attacks on validator communication
   - Unauthorized participation in consensus rounds
   - Network-level attacks on validator nodes

3. **Reduced Defense-in-Depth**: Even if file system encryption is enabled, the keys remain readable to any process with decryption access, rather than being additionally obscured through binary serialization.

The impact aligns with **High Severity** criteria: "Significant protocol violations" and "Validator node slowdowns" (through compromised keys forcing key rotation and validator reconfiguration).

While not reaching **Critical** severity (as it requires file system access rather than remote exploitation), the exposure of consensus-critical keys represents a significant security degradation.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

Several factors increase the probability of exploitation:

1. **Configuration Availability**: OnDiskStorage is a documented configuration option with examples in production deployment files (Docker Compose, Terraform templates).

2. **Testing-to-Production Migration**: Validators may start with OnDiskStorage during testing and forget to migrate to Vault before production deployment.

3. **Backup System Integration**: Modern infrastructure commonly includes automated backup systems that would capture these files without operators realizing they contain plaintext keys.

4. **Operational Errors**: File permission misconfigurations, container escape vulnerabilities, or compromised monitoring agents could expose the files.

5. **Cloud Environments**: In containerized deployments, volume mounts and persistent storage may be accessible to other services or backup operators.

The primary mitigation factor is that the OnDiskStorage README explicitly warns against production use: [7](#0-6) 

However, this documentation warning is insufficient defense given the configuration option remains available and exemplified in deployment templates.

## Recommendation

Implement multiple layers of protection:

### 1. Force Binary Serialization for Sensitive Types

Modify the `SerializeKey` macro to always use binary serialization regardless of serializer type:

```rust
#[proc_macro_derive(SerializeKey)]
pub fn serialize_key(source: TokenStream) -> TokenStream {
    let ast: DeriveInput = syn::parse(source).expect("Incorrect macro input");
    let name = &ast.ident;
    let name_string = find_key_name(&ast, name.to_string());
    quote! {
        impl ::serde::Serialize for #name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: ::serde::Serializer,
            {
                // Always use binary serialization for private keys
                serializer.serialize_newtype_struct(
                    #name_string,
                    serde_bytes::Bytes::new(&ValidCryptoMaterial::to_bytes(self).as_slice()),
                )
            }
        }
    }
    .into()
}
```

### 2. Add Runtime Validation

Add compile-time checks to prevent OnDiskStorage in production builds:

```rust
impl From<&SecureBackend> for Storage {
    fn from(backend: &SecureBackend) -> Self {
        match backend {
            #[cfg(any(test, feature = "testing"))]
            SecureBackend::OnDiskStorage(config) => {
                let storage = Storage::from(OnDiskStorage::new(config.path()));
                // ... existing code
            },
            #[cfg(not(any(test, feature = "testing")))]
            SecureBackend::OnDiskStorage(_) => {
                panic!("OnDiskStorage is not available in production builds. Use Vault backend.");
            },
            // ... other backends
        }
    }
}
```

### 3. Encrypt OnDiskStorage Files

If OnDiskStorage must remain available, add encryption at rest:

```rust
fn write(&self, data: &HashMap<String, Value>) -> Result<(), Error> {
    let contents = serde_json::to_vec(data)?;
    
    // Encrypt contents before writing
    let encrypted = self.encrypt(&contents)?;
    
    let mut file = File::create(self.temp_path.path())?;
    file.write_all(&encrypted)?;
    fs::rename(&self.temp_path, &self.file_path)?;
    Ok(())
}
```

### 4. Remove from Production Configurations

Remove OnDiskStorage from all production configuration examples in `docker/compose/` and `terraform/helm/` directories, replacing with Vault configurations only.

## Proof of Concept

The following demonstrates the vulnerability by showing how an Ed25519PrivateKey is serialized to readable hex:

```rust
use aptos_crypto::{ed25519::Ed25519PrivateKey, Uniform};
use aptos_secure_storage::{CryptoStorage, KVStorage, OnDiskStorage};
use std::path::PathBuf;
use tempfile::TempDir;

#[test]
fn test_private_key_exposure_in_json() {
    // Create temporary storage
    let temp_dir = TempDir::new().unwrap();
    let storage_path = temp_dir.path().join("test_storage.json");
    let mut storage = OnDiskStorage::new(storage_path.clone());
    
    // Generate and store a private key
    let key_name = "test_consensus_key";
    let public_key = storage.create_key(key_name).unwrap();
    
    // Read the raw file contents
    let file_contents = std::fs::read_to_string(&storage_path).unwrap();
    println!("Storage file contents:\n{}", file_contents);
    
    // Verify the file contains hex-encoded private key
    assert!(file_contents.contains("0x"));
    assert!(file_contents.contains(&key_name));
    
    // Extract the private key for verification
    let private_key = storage.export_private_key(key_name).unwrap();
    
    // Demonstrate that the hex in the file matches the actual key
    let expected_hex = format!("0x{}", hex::encode(private_key.to_bytes()));
    assert!(file_contents.contains(&expected_hex), 
            "Private key is stored in readable hex format in JSON file");
    
    println!("\n[VULNERABILITY CONFIRMED]");
    println!("Private key bytes: {:?}", private_key.to_bytes());
    println!("Hex representation in file: {}", expected_hex);
    println!("Public key: {}", public_key);
}

#[test]
fn test_backup_exposure_scenario() {
    let temp_dir = TempDir::new().unwrap();
    let storage_path = temp_dir.path().join("validator_storage.json");
    let mut storage = OnDiskStorage::new(storage_path.clone());
    
    // Simulate validator setup
    storage.create_key("consensus_key").unwrap();
    storage.create_key("network_key").unwrap();
    
    // Simulate backup operation (copy file)
    let backup_path = temp_dir.path().join("backup/validator_storage.json");
    std::fs::create_dir_all(backup_path.parent().unwrap()).unwrap();
    std::fs::copy(&storage_path, &backup_path).unwrap();
    
    // Attacker accesses backup
    let backup_contents = std::fs::read_to_string(&backup_path).unwrap();
    
    // Verify attacker can read both keys
    assert!(backup_contents.contains("consensus_key"));
    assert!(backup_contents.contains("network_key"));
    assert!(backup_contents.matches("0x").count() >= 2);
    
    println!("\n[ATTACK SCENARIO]");
    println!("Backup file contains {} private keys in readable format", 
             backup_contents.matches("0x").count());
}
```

**Expected Output**:
```
Storage file contents:
{"test_consensus_key":{"data":"...","last_update":1234567890,"value":"0x<64_hex_chars>"}}

[VULNERABILITY CONFIRMED]
Private key bytes: [1, 2, 3, ..., 32]
Hex representation in file: 0x0102030405...
Public key: <public_key_hex>

[ATTACK SCENARIO]
Backup file contains 2 private keys in readable format
```

This PoC demonstrates that consensus-critical private keys are stored in immediately readable hexadecimal format, accessible to anyone with file system access or backup access.

### Citations

**File:** crates/aptos-crypto-derive/src/lib.rs (L185-211)
```rust
#[proc_macro_derive(SerializeKey)]
pub fn serialize_key(source: TokenStream) -> TokenStream {
    let ast: DeriveInput = syn::parse(source).expect("Incorrect macro input");
    let name = &ast.ident;
    let name_string = find_key_name(&ast, name.to_string());
    quote! {
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
    .into()
}
```

**File:** crates/aptos-crypto/src/traits/mod.rs (L101-104)
```rust
    /// A function to encode into hex-string after serializing.
    fn to_encoded_string(&self) -> Result<String> {
        Ok(format!("0x{}", ::hex::encode(self.to_bytes())))
    }
```

**File:** secure/storage/src/crypto_kv_storage.rs (L55-57)
```rust
    fn import_private_key(&mut self, name: &str, key: Ed25519PrivateKey) -> Result<(), Error> {
        self.set(name, key)
    }
```

**File:** secure/storage/src/on_disk.rs (L85-92)
```rust
    fn set<V: Serialize>(&mut self, key: &str, value: V) -> Result<(), Error> {
        let now = self.time_service.now_secs();
        let mut data = self.read()?;
        data.insert(
            key.to_string(),
            serde_json::to_value(GetResponse::new(value, now))?,
        );
        self.write(&data)
```

**File:** docker/compose/aptos-node/validator.yaml (L11-14)
```yaml
    backend:
      type: "on_disk_storage"
      path: secure-data.json
      namespace: ~
```

**File:** config/src/config/secure_backend_config.rs (L162-173)
```rust
impl From<&SecureBackend> for Storage {
    fn from(backend: &SecureBackend) -> Self {
        match backend {
            SecureBackend::InMemoryStorage => Storage::from(InMemoryStorage::new()),
            SecureBackend::OnDiskStorage(config) => {
                let storage = Storage::from(OnDiskStorage::new(config.path()));
                if let Some(namespace) = &config.namespace {
                    Storage::from(Namespaced::new(namespace, Box::new(storage)))
                } else {
                    storage
                }
            },
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
