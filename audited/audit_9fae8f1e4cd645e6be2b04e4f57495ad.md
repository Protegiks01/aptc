# Audit Report

## Title
Lack of Privilege Separation in CryptoStorage Trait Enables Unrestricted Access to All Cryptographic Operations

## Summary
The `CryptoStorage` trait provides no method-level access control, allowing any component with a storage reference to access all cryptographic operations including private key export, signing, and key rotation. This violates the principle of least privilege and creates security risks when combined with other vulnerabilities.

## Finding Description

The `CryptoStorage` trait defines a unified interface for all cryptographic operations without any privilege separation mechanism. [1](#0-0) 

Any code holding a reference to an object implementing `CryptoStorage` (such as `Storage`, `InMemoryStorage`, `OnDiskStorage`, or `VaultStorage`) can invoke ALL methods including:
- `get_public_key()` - read-only operation returning public keys
- `export_private_key()` - sensitive operation exporting private key material
- `sign()` - uses private key to sign messages
- `rotate_key()`, `create_key()`, `import_private_key()` - key management operations

For `InMemoryStorage` and `OnDiskStorage`, there is explicitly no permission checking: [2](#0-1) [3](#0-2) 

Both implementations provide blanket `CryptoStorage` access through the `CryptoKVStorage` trait: [4](#0-3) 

While `VaultPolicy` exists to enforce capability-based access control (Export, Read, Rotate, Sign), it is NOT exported from the library and only used in tests: [5](#0-4) 

Critically, `OnDiskStorage` is permitted in production (only `InMemoryStorage` is blocked for mainnet validators): [6](#0-5) 

The `PersistentSafetyStorage` used by consensus safety rules exposes the internal storage object: [7](#0-6) 

## Impact Explanation

This architectural weakness creates **High** severity risk as defined in the Aptos bug bounty program for "Significant protocol violations". However, the actual exploitability depends on the existence of other vulnerabilities.

**Theoretical Attack Scenarios:**

1. **Compromised Component**: If an attacker gains code execution within any component holding a `Storage` reference (e.g., through memory corruption, logic bug, or supply chain attack), they can immediately export consensus private keys without any additional authorization checks.

2. **Confused Deputy**: A component that should only read public keys might be tricked into calling `export_private_key()` through a logic bug, with no runtime enforcement preventing this misuse.

3. **Defense-in-Depth Failure**: When using `OnDiskStorage` in production, there are zero access control layers between a component and private key export operations.

**Impact on Consensus Safety Invariant:**
If consensus private keys are exported by a compromised component, an attacker could:
- Sign malicious blocks/votes to violate consensus safety
- Cause chain splits or equivocation
- Impersonate validators

## Likelihood Explanation

**Likelihood: Low-to-Medium**

The vulnerability requires a prerequisite condition: an attacker must first compromise a component that has `Storage` access. This could occur through:
- Memory corruption bugs (buffer overflow, use-after-free)
- Logic vulnerabilities in components handling `Storage`
- Supply chain compromise of dependencies

Once such access is obtained, the lack of privilege separation makes exploitation trivial - a single method call to `export_private_key()` suffices.

The likelihood increases when `OnDiskStorage` is used in production environments, as there's absolutely no runtime access control layer.

## Recommendation

Implement fine-grained privilege separation through one of these approaches:

**Approach 1: Split CryptoStorage into Read-Only and Privileged Traits**

```rust
// Read-only trait for public key operations
pub trait CryptoReader {
    fn get_public_key(&self, name: &str) -> Result<PublicKeyResponse, Error>;
    fn get_public_key_previous_version(&self, name: &str) -> Result<Ed25519PublicKey, Error>;
}

// Privileged trait for sensitive operations (requires explicit authorization)
pub trait CryptoPrivileged: CryptoReader {
    fn export_private_key(&self, name: &str) -> Result<Ed25519PrivateKey, Error>;
    fn sign<T: CryptoHash + Serialize>(&self, name: &str, message: &T) -> Result<Ed25519Signature, Error>;
}

// Key management operations
pub trait CryptoManager: CryptoPrivileged {
    fn create_key(&mut self, name: &str) -> Result<Ed25519PublicKey, Error>;
    fn rotate_key(&mut self, name: &str) -> Result<Ed25519PublicKey, Error>;
    fn import_private_key(&mut self, name: &str, key: Ed25519PrivateKey) -> Result<(), Error>;
}
```

**Approach 2: Make VaultPolicy Public and Mandatory**

Export `VaultPolicy` from `lib.rs` and enforce its use for all production storage backends:

```rust
// In lib.rs
pub use crate::vault::VaultPolicy;

// Update SafetyRulesConfig sanitizer to enforce policy-wrapped storage
impl ConfigSanitizer for SafetyRulesConfig {
    fn sanitize(...) -> Result<(), Error> {
        // Existing checks...
        
        // Require that OnDiskStorage is wrapped with capability restrictions
        if chain_id.is_mainnet() && !backend.has_access_control() {
            return Err(Error::ConfigSanitizerFailed(
                sanitizer_name,
                "Production validators must use storage with access control policies".to_string()
            ));
        }
    }
}
```

**Approach 3: Runtime Capability Checking**

Implement a wrapper that enforces capability checks at runtime for all storage backends:

```rust
pub struct RestrictedStorage {
    inner: Storage,
    allowed_capabilities: HashSet<Capability>,
}

impl CryptoStorage for RestrictedStorage {
    fn export_private_key(&self, name: &str) -> Result<Ed25519PrivateKey, Error> {
        if !self.allowed_capabilities.contains(&Capability::Export) {
            return Err(Error::PermissionDenied);
        }
        self.inner.export_private_key(name)
    }
    // ... implement other methods with capability checks
}
```

## Proof of Concept

```rust
// This PoC demonstrates the lack of privilege separation
// It shows that any code with Storage access can export private keys

#[cfg(test)]
mod privilege_separation_test {
    use aptos_crypto::{ed25519::Ed25519PrivateKey, Uniform};
    use aptos_secure_storage::{CryptoStorage, OnDiskStorage, Storage};
    use rand::rngs::OsRng;
    
    #[test]
    fn test_no_privilege_separation() {
        let temp_path = tempfile::NamedTempFile::new().unwrap();
        let mut storage = Storage::from(OnDiskStorage::new(temp_path.path().to_path_buf()));
        
        // Component A: Creates a key (legitimate operation)
        let key_name = "consensus_key";
        let public_key = storage.create_key(key_name).unwrap();
        println!("Created key with public key: {:?}", public_key);
        
        // Component B: Should only READ public keys, but can also EXPORT private keys
        // This demonstrates the lack of privilege separation
        
        // Legitimate read operation (should be allowed)
        let pub_key_response = storage.get_public_key(key_name).unwrap();
        println!("Read public key: {:?}", pub_key_response.public_key);
        
        // PROBLEMATIC: Component B can also export the private key
        // There is NO runtime check preventing this!
        let private_key = storage.export_private_key(key_name).unwrap();
        println!("Exported private key: {:?}", private_key);
        
        // Verify the exported key is valid
        assert_eq!(private_key.public_key(), public_key);
        
        // Component B can also sign messages (another privileged operation)
        let message = b"test message";
        let signature = storage.sign(key_name, &message).unwrap();
        println!("Signed message: {:?}", signature);
    }
}
```

## Notes

While this report identifies a genuine architectural weakness in the secure storage design, it's important to note that **direct exploitation requires an attacker to first gain code execution within a component that has Storage access**. This is not trivially achievable by an external unprivileged attacker.

The issue represents a **defense-in-depth failure** rather than a directly exploitable vulnerability. It would become critical when combined with:
- Memory corruption vulnerabilities in components using Storage
- Logic bugs that allow unintended method invocation
- Supply chain compromises

The fact that `VaultPolicy` exists but is not exported or enforced suggests this was a known concern during development, but the mitigation was never completed or made mandatory for production use.

### Citations

**File:** secure/storage/src/crypto_storage.rs (L9-65)
```rust
/// CryptoStorage provides an abstraction for secure generation and handling of cryptographic keys.
#[enum_dispatch]
pub trait CryptoStorage {
    /// Securely generates a new named Ed25519 private key. The behavior for calling this interface
    /// multiple times with the same name is implementation specific.
    fn create_key(&mut self, name: &str) -> Result<Ed25519PublicKey, Error>;

    /// Returns the Ed25519 private key stored at 'name'.
    fn export_private_key(&self, name: &str) -> Result<Ed25519PrivateKey, Error>;

    /// An optional API that allows importing private keys and storing them at the provided name.
    /// This is not intended to be used in production and the API may throw unimplemented if
    /// not used correctly. As this is purely a testing API, there is no defined behavior for
    /// importing a key for a given name if that name already exists.  It only exists to allow
    /// running in test environments where a set of deterministic keys must be generated.
    fn import_private_key(&mut self, name: &str, key: Ed25519PrivateKey) -> Result<(), Error>;

    /// Returns the Ed25519 private key stored at 'name' and identified by 'version', which is the
    /// corresponding public key. This may fail even if the 'named' key exists but the version is
    /// not present.
    fn export_private_key_for_version(
        &self,
        name: &str,
        version: Ed25519PublicKey,
    ) -> Result<Ed25519PrivateKey, Error>;

    /// Returns the Ed25519 public key stored at 'name'.
    fn get_public_key(&self, name: &str) -> Result<PublicKeyResponse, Error>;

    /// Returns the previous version of the Ed25519 public key stored at 'name'. For the most recent
    /// version, see 'get_public_key(..)' above.
    fn get_public_key_previous_version(&self, name: &str) -> Result<Ed25519PublicKey, Error>;

    /// Rotates an Ed25519 private key. Future calls without version to this 'named' key will
    /// return the rotated key instance. The previous key is retained and can be accessed via
    /// the version. At most two versions are expected to be retained.
    fn rotate_key(&mut self, name: &str) -> Result<Ed25519PublicKey, Error>;

    /// Signs the provided securely-hashable struct, using the 'named' private
    /// key.
    // The FQDNs on the next line help macros don't remove them
    fn sign<T: aptos_crypto::hash::CryptoHash + serde::Serialize>(
        &self,
        name: &str,
        message: &T,
    ) -> Result<Ed25519Signature, Error>;

    /// Signs the provided securely-hashable struct, using the 'named' and 'versioned' private key. This may fail
    /// even if the 'named' key exists but the version is not present.
    // The FQDNs on the next line help macros, don't remove them
    fn sign_using_version<T: aptos_crypto::hash::CryptoHash + serde::Serialize>(
        &self,
        name: &str,
        version: Ed25519PublicKey,
        message: &T,
    ) -> Result<Ed25519Signature, Error>;
}
```

**File:** secure/storage/src/in_memory.rs (L9-14)
```rust
/// InMemoryStorage represents a key value store that is purely in memory and intended for single
/// threads (or must be wrapped by a Arc<RwLock<>>). This provides no permission checks and simply
/// is a proof of concept to unblock building of applications without more complex data stores.
/// Internally, it retains all data, which means that it must make copies of all key material which
/// violates the code base. It violates it because the anticipation is that data stores would
/// securely handle key material. This should not be used in production.
```

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

**File:** secure/storage/src/crypto_kv_storage.rs (L18-28)
```rust
impl<T: CryptoKVStorage> CryptoStorage for T {
    fn create_key(&mut self, name: &str) -> Result<Ed25519PublicKey, Error> {
        // Generate and store the new named key pair
        let (private_key, public_key) = new_ed25519_key_pair();
        self.import_private_key(name, private_key)?;
        Ok(public_key)
    }

    fn export_private_key(&self, name: &str) -> Result<Ed25519PrivateKey, Error> {
        self.get(name).map(|v| v.value)
    }
```

**File:** secure/storage/src/lib.rs (L17-28)
```rust
pub use crate::{
    crypto_kv_storage::CryptoKVStorage,
    crypto_storage::{CryptoStorage, PublicKeyResponse},
    error::Error,
    in_memory::InMemoryStorage,
    kv_storage::{GetResponse, KVStorage},
    namespaced::Namespaced,
    on_disk::OnDiskStorage,
    policy::{Capability, Identity, Permission, Policy},
    storage::Storage,
    vault::VaultStorage,
};
```

**File:** config/src/config/safety_rules_config.rs (L85-96)
```rust
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
```

**File:** consensus/safety-rules/src/persistent_safety_storage.rs (L187-189)
```rust
    pub fn internal_store(&mut self) -> &mut Storage {
        &mut self.internal_store
    }
```
