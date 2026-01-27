# Audit Report

## Title
Key Version Accumulation Due to Non-Atomic Rotation in VaultStorage

## Summary
The `rotate_key()` function in VaultStorage performs key rotation and version trimming as two separate HTTP operations to Vault. If a validator crashes between these operations, old key versions accumulate indefinitely, violating the documented maximum version limit and increasing the attack surface for key compromise.

## Finding Description

The `rotate_key()` function in VaultStorage executes two non-atomic operations: [1](#0-0) 

These operations call separate HTTP endpoints to the Vault service: [2](#0-1) [3](#0-2) 

The vulnerability occurs when a validator crashes after `rotate_key()` succeeds but before `trim_key_versions()` executes. In this scenario:

1. A new key version is created in Vault Transit storage
2. Old key versions are NOT trimmed
3. No recovery mechanism exists on restart to complete the trimming operation
4. Repeated crashes during rotations cause unbounded accumulation of key versions

This violates the documented security contract: [4](#0-3) 

The implementation uses `MAX_NUM_KEY_VERSIONS = 4`: [5](#0-4) 

However, crashes can cause unlimited accumulation beyond this limit.

## Impact Explanation

This qualifies as **Medium severity** under Aptos bug bounty criteria: "State inconsistencies requiring intervention."

**Security Impact:**
- Old key versions remain accessible and usable for signing operations via `sign_using_version()` and `export_private_key_for_version()`
- Violates key rotation security principles where old keys should be retired after rotation
- An attacker who compromises an old key version (through memory dump, storage leak, or side-channel attack) can continue using it indefinitely
- The attack surface grows unbounded with repeated crashes, as each incomplete rotation leaves another old version accessible
- Requires manual intervention to detect and remediate the inconsistent state

**Scope:** Affects Ed25519 keys managed through VaultStorage's CryptoStorage interface, which may include validator network keys, operator keys, or other cryptographic material used for signing operations.

## Likelihood Explanation

**Likelihood: Medium**

Validator crashes during key rotation are realistic due to:
- Process termination (OOM kills, segfaults, panics)
- Infrastructure failures (power loss, network partitions, hardware failures)  
- Deployment issues (forced restarts during upgrades, container orchestration issues)
- Software bugs causing crashes

Key rotations are infrequent but do occur during:
- Security incident response (compromised keys)
- Planned key rotation policies
- Validator operational procedures
- Testing and development environments

The exploitation window is small (milliseconds between HTTP calls) but deterministic - every crash during rotation leaves the state inconsistent with no recovery path.

## Recommendation

**Solution 1: Implement atomic rotation with transaction support**

Modify the Vault client to use Vault's transaction capabilities or implement compensation logic:

```rust
fn rotate_key(&mut self, name: &str) -> Result<Ed25519PublicKey, Error> {
    let ns_name = self.crypto_name(name);
    
    // Perform rotation
    self.client().rotate_key(&ns_name)?;
    
    // Immediately trim in same operation - if this fails, log error but don't fail rotation
    match self.client().trim_key_versions(&ns_name) {
        Ok(pubkey) => Ok(pubkey),
        Err(e) => {
            aptos_logger::error!("Failed to trim key versions for {}: {}. Old versions may persist.", ns_name, e);
            // Return the latest key even if trimming failed
            self.get_public_key(name).map(|r| r.public_key)
        }
    }
}
```

**Solution 2: Add startup recovery mechanism**

Implement a reconciliation function that runs on validator startup to detect and fix inconsistent key version states:

```rust
pub fn reconcile_key_versions(&mut self) -> Result<(), Error> {
    let keys = self.client().list_keys()?;
    for key_name in keys {
        // Check if key has too many versions and trim if needed
        let versions = self.client().read_ed25519_key(&key_name)?;
        if versions.len() > MAX_NUM_KEY_VERSIONS as usize {
            aptos_logger::warn!("Key {} has {} versions, trimming to {}", 
                key_name, versions.len(), MAX_NUM_KEY_VERSIONS);
            self.client().trim_key_versions(&key_name)?;
        }
    }
    Ok(())
}
```

**Solution 3: Document and monitor**

If immediate fixes are not feasible:
- Add metrics to track key version counts
- Implement alerting when versions exceed thresholds  
- Document the recovery procedure for operators
- Add periodic audit jobs to detect inconsistent states

## Proof of Concept

```rust
#[test]
fn test_key_rotation_crash_scenario() {
    use aptos_vault_client::dev::{self, ROOT_TOKEN};
    use secure_storage::{VaultStorage, CryptoStorage};
    
    if dev::test_host_safe().is_none() {
        return; // Skip if vault not available
    }
    
    let mut storage = VaultStorage::new(
        dev::test_host(),
        ROOT_TOKEN.into(),
        None,
        None,
        true,
        None,
        None,
    );
    
    storage.reset_and_clear().unwrap();
    
    // Create initial key
    let key_name = "test_crash_key";
    storage.create_key(key_name).unwrap();
    
    // Simulate multiple rotations with crashes
    for i in 1..10 {
        // Call rotate_key on vault client directly (simulating first part succeeding)
        storage.client().rotate_key(&key_name).unwrap();
        // Simulate crash - DO NOT call trim_key_versions
        
        println!("After rotation {}: ", i);
        let versions = storage.get_all_key_versions(key_name).unwrap();
        println!("  Version count: {}", versions.len());
        
        // After 4 rotations, we should have 5 versions (initial + 4 rotations)
        // This exceeds MAX_NUM_KEY_VERSIONS (4)
        if i >= 4 {
            assert!(versions.len() > 4, 
                "Expected version accumulation beyond MAX_NUM_KEY_VERSIONS, got {}", 
                versions.len());
        }
    }
    
    // Verify all old versions are still accessible
    let all_versions = storage.get_all_key_versions(key_name).unwrap();
    println!("Final version count: {} (should be capped at 4)", all_versions.len());
    assert!(all_versions.len() > 4, "Vulnerability confirmed: {} versions exist", all_versions.len());
    
    // Verify old versions can still be used for signing
    for version in &all_versions[..all_versions.len()-1] {
        let old_key = storage.export_private_key_for_version(key_name, version.value).unwrap();
        assert_eq!(old_key.public_key(), version.value, "Old key version still accessible");
    }
}
```

## Notes

This vulnerability requires validator crashes to trigger but has no recovery mechanism, leading to unbounded accumulation of cryptographic key versions that should have been retired. The state inconsistency persists across restarts and requires manual intervention to detect and remediate. While the exploitation requires a separate compromise vector to access the old keys, the persistence of these keys beyond their intended lifetime violates defense-in-depth principles and documented version limits.

### Citations

**File:** secure/storage/src/vault.rs (L268-272)
```rust
    fn rotate_key(&mut self, name: &str) -> Result<Ed25519PublicKey, Error> {
        let ns_name = self.crypto_name(name);
        self.client().rotate_key(&ns_name)?;
        Ok(self.client().trim_key_versions(&ns_name)?)
    }
```

**File:** secure/storage/vault/src/lib.rs (L26-28)
```rust
/// The max number of key versions held in vault at any one time.
/// Keys are trimmed in FIFO order.
const MAX_NUM_KEY_VERSIONS: u32 = 4;
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

**File:** secure/storage/src/crypto_storage.rs (L42-45)
```rust
    /// Rotates an Ed25519 private key. Future calls without version to this 'named' key will
    /// return the rotated key instance. The previous key is retained and can be accessed via
    /// the version. At most two versions are expected to be retained.
    fn rotate_key(&mut self, name: &str) -> Result<Ed25519PublicKey, Error>;
```
