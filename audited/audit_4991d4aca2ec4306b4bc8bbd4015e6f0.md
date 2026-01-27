# Audit Report

## Title
Non-Atomic Key Rotation in Secure Storage Leading to Inconsistent State on Partial Failure

## Summary
The `rotate_key()` function in the secure storage system lacks atomicity guarantees. In both `CryptoKVStorage` and `VaultStorage` implementations, key rotation consists of multiple non-transactional operations that can fail partway through, leaving the storage in an inconsistent state with no rollback mechanism. This requires manual intervention to recover.

## Finding Description

The secure storage system provides cryptographic key management for Aptos validators. The `rotate_key()` function is designed to rotate Ed25519 private keys while maintaining access to the previous version.

**CryptoKVStorage Implementation Vulnerability:**

The implementation performs two separate, non-atomic `set()` operations: [1](#0-0) 

**Step-by-step failure scenario:**

1. `get(name)` retrieves the current private key
2. `new_ed25519_key_pair()` generates a new key pair (in-memory only)
3. `set(&get_previous_version_name(name), private_key)` stores old key as `{name}_previous` - **SUCCESS**
4. `set(name, new_private_key)` stores new key at `{name}` - **FAILS** (disk full, I/O error, process crash)

After step 4 failure:
- Storage contains: `{name}_previous` = old key
- Storage contains: `{name}` = old key (unchanged)
- Both "current" and "previous" contain identical keys
- System expects new key at `{name}` but it was never written

**OnDiskStorage atomicity analysis:**

Each individual `set()` operation uses atomic file rename: [2](#0-1) 

However, the two `set()` calls in `rotate_key()` are NOT atomic together. There's no transaction wrapping both operations.

**VaultStorage Implementation Vulnerability:** [3](#0-2) 

This performs multiple HTTP requests without transaction support: [4](#0-3) 

Followed by: [5](#0-4) 

The `trim_key_versions()` makes additional HTTP calls that can fail independently:
- `read_ed25519_key()` 
- `set_minimum_encrypt_decrypt_version()`
- `set_minimum_available_version()`

If any call fails after `rotate_key()` succeeds, the Vault contains rotated keys but with untrimmed old versions, violating the documented "at most two versions" invariant.

**Invariant Violated:**
The **State Consistency** invariant is broken: "State transitions must be atomic and verifiable." The key rotation is not atomic across storage backends.

## Impact Explanation

**Severity: Medium** - "State inconsistencies requiring intervention"

According to Aptos bug bounty criteria, this qualifies as Medium severity because:

1. **State Inconsistency**: Storage left in corrupted state where previous and current keys are identical
2. **Manual Recovery Required**: Operators must manually inspect and repair storage state
3. **Operational Impact**: If this occurs on validator nodes using secure storage for signing operations, it could cause:
   - Inability to access the "new" key that was supposed to be rotated to
   - Confusion about which key version is actually current
   - Potential validator downtime during recovery

The trait documentation explicitly states the rotation contract: [6](#0-5) 

This contract is violated when partial failures occur.

## Likelihood Explanation

**Likelihood: Medium to High** in production environments

This can occur during normal operational failures:

1. **Disk space exhaustion** - OnDiskStorage write failures when disk is full
2. **I/O errors** - Hardware failures, filesystem corruption
3. **Process crashes** - Node restarts, OOM kills during rotation
4. **Network failures** - VaultStorage HTTP timeouts, connection failures
5. **Permission changes** - File permissions modified during operation

The storage backends provide no transaction log or rollback mechanism: [7](#0-6) [8](#0-7) 

## Recommendation

Implement atomic key rotation using one of these approaches:

**Option 1: Single-write atomic rotation (preferred for OnDiskStorage)**
```rust
fn rotate_key(&mut self, name: &str) -> Result<Ed25519PublicKey, Error> {
    let private_key: Ed25519PrivateKey = self.get(name)?.value;
    let (new_private_key, new_public_key) = new_ed25519_key_pair();
    
    // Single atomic operation that writes both keys
    let rotation_data = KeyRotationData {
        current: new_private_key,
        previous: Some(private_key),
    };
    self.set(name, rotation_data)?;
    
    Ok(new_public_key)
}
```

**Option 2: Write-ahead log with rollback**
```rust
fn rotate_key(&mut self, name: &str) -> Result<Ed25519PublicKey, Error> {
    // Write intention log
    let rotation_id = self.begin_rotation(name)?;
    
    match self.execute_rotation(name, rotation_id) {
        Ok(pub_key) => {
            self.commit_rotation(rotation_id)?;
            Ok(pub_key)
        }
        Err(e) => {
            self.rollback_rotation(rotation_id)?;
            Err(e)
        }
    }
}
```

**Option 3: Vault transaction support**
For VaultStorage, use Vault's transaction capabilities or implement idempotent retry logic with state validation.

## Proof of Concept

```rust
#[cfg(test)]
mod test_rotation_atomicity {
    use super::*;
    use aptos_secure_storage::{OnDiskStorage, CryptoStorage};
    use std::sync::{Arc, Mutex};
    use std::sync::atomic::{AtomicBool, Ordering};
    
    // Mock storage that fails on second set() call
    struct FailingStorage {
        inner: OnDiskStorage,
        call_count: Arc<Mutex<usize>>,
        fail_on_second: AtomicBool,
    }
    
    impl KVStorage for FailingStorage {
        fn set<V: Serialize>(&mut self, key: &str, value: V) -> Result<(), Error> {
            let mut count = self.call_count.lock().unwrap();
            *count += 1;
            
            // Fail on second set() call (the actual rotation write)
            if *count == 2 && self.fail_on_second.load(Ordering::SeqCst) {
                return Err(Error::InternalError("Simulated I/O failure".into()));
            }
            
            self.inner.set(key, value)
        }
        
        fn get<V: DeserializeOwned>(&self, key: &str) -> Result<GetResponse<V>, Error> {
            self.inner.get(key)
        }
        
        fn available(&self) -> Result<(), Error> {
            self.inner.available()
        }
    }
    
    impl CryptoKVStorage for FailingStorage {}
    
    #[test]
    fn test_partial_rotation_leaves_inconsistent_state() {
        let temp_path = aptos_temppath::TempPath::new();
        temp_path.create_as_file().unwrap();
        
        let mut storage = FailingStorage {
            inner: OnDiskStorage::new(temp_path.path().to_path_buf()),
            call_count: Arc::new(Mutex::new(0)),
            fail_on_second: AtomicBool::new(false),
        };
        
        // Create initial key
        let original_pub_key = storage.create_key("test_key").unwrap();
        let original_priv_key = storage.export_private_key("test_key").unwrap();
        
        // Enable failure on second set() call
        storage.fail_on_second.store(true, Ordering::SeqCst);
        
        // Attempt rotation - should fail
        let rotation_result = storage.rotate_key("test_key");
        assert!(rotation_result.is_err());
        
        // Verify inconsistent state
        // Previous version was written successfully
        let prev_key = storage.export_private_key("test_key_previous");
        assert!(prev_key.is_ok());
        assert_eq!(prev_key.unwrap(), original_priv_key);
        
        // Current key is still the old key (rotation failed)
        let current_key = storage.export_private_key("test_key").unwrap();
        assert_eq!(current_key, original_priv_key);
        
        // INCONSISTENT STATE DETECTED:
        // Both "current" and "previous" contain the same key!
        // No new key was created, but previous version exists.
        // This violates the rotation invariant and requires manual recovery.
    }
}
```

## Notes

This vulnerability affects all three storage backends (`OnDiskStorage`, `InMemoryStorage`, `VaultStorage`) but manifests differently:

- **OnDiskStorage**: Most critical due to persistent state corruption requiring manual file editing
- **InMemoryStorage**: Affects in-memory state until process restart
- **VaultStorage**: Affects remote Vault state, may leave dangling key versions

The trait definition provides no atomicity guarantees: [9](#0-8) 

While this secure storage system is used by SafetyRules for consensus operations, the actual usage pattern in production determines real-world impact. Current code does not show active `rotate_key()` usage in critical consensus paths, but the API is public and could be used by operators or future features.

### Citations

**File:** secure/storage/src/crypto_kv_storage.rs (L80-86)
```rust
    fn rotate_key(&mut self, name: &str) -> Result<Ed25519PublicKey, Error> {
        let private_key: Ed25519PrivateKey = self.get(name)?.value;
        let (new_private_key, new_public_key) = new_ed25519_key_pair();
        self.set(&get_previous_version_name(name), private_key)?;
        self.set(name, new_private_key)?;
        Ok(new_public_key)
    }
```

**File:** secure/storage/src/on_disk.rs (L23-27)
```rust
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

**File:** secure/storage/src/vault.rs (L268-272)
```rust
    fn rotate_key(&mut self, name: &str) -> Result<Ed25519PublicKey, Error> {
        let ns_name = self.crypto_name(name);
        self.client().rotate_key(&ns_name)?;
        Ok(self.client().trim_key_versions(&ns_name)?)
    }
```

**File:** secure/storage/vault/src/lib.rs (L340-347)
```rust
    pub fn rotate_key(&self, name: &str) -> Result<(), Error> {
        let request = self
            .agent
            .post(&format!("{}/v1/transit/keys/{}/rotate", self.host, name));
        let resp = self.upgrade_request(request).call();

        process_generic_response(resp)
    }
```

**File:** secure/storage/vault/src/lib.rs (L356-390)
```rust
    pub fn trim_key_versions(&self, name: &str) -> Result<Ed25519PublicKey, Error> {
        // Read all keys and versions
        let all_pub_keys = self.read_ed25519_key(name)?;

        // Find the maximum and minimum versions
        let max_version = all_pub_keys
            .iter()
            .map(|resp| resp.version)
            .max()
            .ok_or_else(|| Error::NotFound("transit/".into(), name.into()))?;
        let min_version = all_pub_keys
            .iter()
            .map(|resp| resp.version)
            .min()
            .ok_or_else(|| Error::NotFound("transit/".into(), name.into()))?;

        // Trim keys if too many versions exist
        if (max_version - min_version) >= MAX_NUM_KEY_VERSIONS {
            // let min_available_version = max_version - MAX_NUM_KEY_VERSIONS + 1;
            let min_available_version = max_version
                .checked_sub(MAX_NUM_KEY_VERSIONS)
                .and_then(|n| n.checked_add(1))
                .ok_or_else(|| {
                    Error::OverflowError("trim_key_versions::min_available_version".into())
                })?;
            self.set_minimum_encrypt_decrypt_version(name, min_available_version)?;
            self.set_minimum_available_version(name, min_available_version)?;
        };

        let newest_pub_key = all_pub_keys
            .iter()
            .find(|pub_key| pub_key.version == max_version)
            .ok_or_else(|| Error::NotFound("transit/".into(), name.into()))?;
        Ok(newest_pub_key.value.clone())
    }
```

**File:** secure/storage/src/crypto_storage.rs (L9-11)
```rust
/// CryptoStorage provides an abstraction for secure generation and handling of cryptographic keys.
#[enum_dispatch]
pub trait CryptoStorage {
```

**File:** secure/storage/src/crypto_storage.rs (L42-45)
```rust
    /// Rotates an Ed25519 private key. Future calls without version to this 'named' key will
    /// return the rotated key instance. The previous key is retained and can be accessed via
    /// the version. At most two versions are expected to be retained.
    fn rotate_key(&mut self, name: &str) -> Result<Ed25519PublicKey, Error>;
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
