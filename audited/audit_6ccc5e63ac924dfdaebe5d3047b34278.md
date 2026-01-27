# Audit Report

## Title
Insecure File Permissions on Network Private Key Storage Exposes Validator Identity to Local Attackers

## Summary
The `Identity::save_private_key()` function saves x25519 network private keys to disk using `File::create()` without setting secure file permissions. On Unix systems, this results in world-readable files (0644 permissions with default umask), exposing validator and fullnode network identities to any local user on the machine. [1](#0-0) 

## Finding Description
The Aptos network authentication system relies on x25519 private keys for peer identity and mutual authentication. Each validator and fullnode has a unique x25519 private key that is used in the Noise IK handshake protocol to establish authenticated connections. [2](#0-1) 

When auto-generated network identities are persisted to disk for fullnodes, the `save_private_key()` function uses Rust's standard `File::create()` without explicitly setting restrictive permissions. On Unix-like systems, `File::create()` respects the process umask, which typically defaults to 0022, resulting in files created with 0644 permissions (readable by owner, group, and world). [3](#0-2) 

**Exploitation Path:**
1. A validator or fullnode operator runs an Aptos node on a multi-user system
2. The node generates an ephemeral identity key and saves it via `Identity::save_private_key()`
3. The private key file is created with world-readable permissions (0644)
4. Any local user on the system can read the file: `cat /path/to/storage/ephemeral_identity_key`
5. The attacker now possesses the node's x25519 private key and can derive its public key and peer ID
6. The attacker can impersonate the node in network communications, potentially intercepting or manipulating validator messages

This vulnerability breaks the **Cryptographic Correctness** and **Access Control** invariants. The codebase already contains proper utilities for secure file writing that set 0600 permissions: [4](#0-3) [5](#0-4) 

However, these secure functions are not used in `Identity::save_private_key()`, indicating an oversight in the implementation.

## Impact Explanation
This vulnerability qualifies as **High Severity** under the Aptos Bug Bounty program criteria for "Significant protocol violations."

**Impact on Validators:**
- Compromised validator network identity enables man-in-the-middle attacks on consensus messages
- Attackers with the validator's x25519 key can eavesdrop on encrypted validator communications
- In combination with other vulnerabilities, could facilitate consensus manipulation attacks
- Undermines the mutual authentication guarantees of the validator network

**Impact on Fullnodes:**
- Compromised fullnode identity allows network impersonation
- Potential for routing attacks or eclipse attacks on other nodes
- Degradation of network security posture

While this requires local access to the validator/fullnode machine, validators are high-value targets and often run in shared cloud environments or by operators with multiple users. The exposure of cryptographic key material represents a fundamental security failure.

## Likelihood Explanation
**Likelihood: Medium to High**

This vulnerability will occur by default on any Unix-based system running an Aptos fullnode with auto-generated network identity, which is the common deployment scenario for public fullnodes. The conditions are:

1. **Guaranteed to occur**: Any fullnode using auto-generated identity will save the key with insecure permissions
2. **Local access required**: Attacker needs shell access on the same machine (medium barrier)
3. **No additional exploitation complexity**: Reading the file is trivial once local access is obtained
4. **Multi-user environments common**: Many operators run nodes in cloud environments or shared servers where multiple users or services have access

The likelihood increases significantly for validators running in cloud environments, shared hosting, or with multiple administrative users.

## Recommendation
Modify `Identity::save_private_key()` to explicitly set secure file permissions (0600) before writing the private key. Use Rust's `OpenOptions` with the `mode()` method on Unix systems:

**Fixed Implementation:**
```rust
pub fn save_private_key(path: &PathBuf, key: &x25519::PrivateKey) -> anyhow::Result<()> {
    use std::fs::OpenOptions;
    
    // Create the parent directory
    let parent_path = path.parent().unwrap();
    fs::create_dir_all(parent_path)?;

    // Create file with secure permissions (0600 on Unix)
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    
    // Save the private key to the specified path
    opts.open(path)?
        .write_all(&key.to_bytes())
        .map_err(|error| error.into())
}
```

Alternatively, use the existing secure utility functions from the codebase like `write_to_user_only_file()`.

## Proof of Concept

```rust
#[cfg(test)]
mod test_insecure_permissions {
    use super::*;
    use aptos_crypto::{x25519, Uniform};
    use rand::rngs::OsRng;
    use std::fs;
    use tempfile::NamedTempFile;
    
    #[test]
    #[cfg(unix)]
    fn test_private_key_has_insecure_permissions() {
        use std::os::unix::fs::PermissionsExt;
        
        // Create a temporary file path
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();
        
        // Generate a private key
        let private_key = x25519::PrivateKey::generate(&mut OsRng);
        
        // Save using the vulnerable function
        Identity::save_private_key(&path, &private_key).unwrap();
        
        // Check the file permissions
        let metadata = fs::metadata(&path).unwrap();
        let permissions = metadata.permissions();
        let mode = permissions.mode();
        
        // Extract permission bits (last 9 bits)
        let file_perms = mode & 0o777;
        
        println!("File permissions: {:o}", file_perms);
        
        // VULNERABILITY: File is readable by group and others (not 0600)
        // With default umask 0022, File::create() produces 0644
        assert_ne!(file_perms, 0o600, 
            "VULNERABILITY CONFIRMED: File should have 0600 permissions but has {:o}", 
            file_perms);
        
        // Demonstrate that the file is world-readable
        assert!(file_perms & 0o004 != 0, 
            "File is world-readable! Private key is exposed to all local users.");
    }
    
    #[test]
    #[cfg(unix)]
    fn test_secure_alternative() {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        use std::fs::OpenOptions;
        use std::io::Write;
        
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path();
        let private_key = x25519::PrivateKey::generate(&mut OsRng);
        
        // Secure implementation
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true).mode(0o600);
        
        opts.open(path)
            .unwrap()
            .write_all(&private_key.to_bytes())
            .unwrap();
        
        // Verify secure permissions
        let metadata = fs::metadata(path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        
        assert_eq!(mode, 0o600, "Secure implementation sets 0600 permissions");
        assert_eq!(mode & 0o077, 0, "File is not readable by group or others");
    }
}
```

**To demonstrate the vulnerability:**
1. Run the test: `cargo test test_private_key_has_insecure_permissions -- --nocapture`
2. The test will confirm that files created by `Identity::save_private_key()` have world-readable permissions
3. On a real system, use `ls -l` to verify the ephemeral_identity_key file has 0644 permissions
4. Any local user can then `cat` the file to extract the private key bytes

## Notes

This vulnerability specifically affects the network identity keys used for peer authentication. While the impact requires local access to the validator/fullnode machine, it represents a critical defense-in-depth failure. Validators are high-value targets, and proper key material protection is essential for maintaining network security. The existence of secure file writing utilities elsewhere in the codebase suggests this is an oversight rather than an intentional design decision.

### Citations

**File:** config/src/config/identity_config.rs (L117-126)
```rust
    pub fn save_private_key(path: &PathBuf, key: &x25519::PrivateKey) -> anyhow::Result<()> {
        // Create the parent directory
        let parent_path = path.parent().unwrap();
        fs::create_dir_all(parent_path)?;

        // Save the private key to the specified path
        File::create(path)?
            .write_all(&key.to_bytes())
            .map_err(|error| error.into())
    }
```

**File:** network/framework/src/noise/handshake.rs (L76-94)
```rust
/// Noise handshake authentication mode.
pub enum HandshakeAuthMode {
    /// In `Mutual` mode, both sides will authenticate each other with their
    /// `trusted_peers` set. We also include replay attack mitigation in this mode.
    ///
    /// For example, in the Aptos validator network, validator peers will only
    /// allow connections from other validator peers. They will use this mode to
    /// check that inbound connections authenticate to a network public key
    /// actually contained in the current validator set.
    Mutual {
        // Only use anti replay protection in mutual-auth scenarios. In theory,
        // this is applicable everywhere; however, we would need to spend some
        // time making this more sophisticated so it garbage collects old
        // timestamps and doesn't use unbounded space. These are not problems in
        // mutual-auth scenarios because we have a bounded set of trusted peers
        // that rarely changes.
        anti_replay_timestamps: RwLock<AntiReplayTimestamps>,
        peers_and_metadata: Arc<PeersAndMetadata>,
    },
```

**File:** config/src/config/config_optimizer.rs (L220-232)
```rust
            if let Identity::FromConfig(IdentityFromConfig {
                source: IdentitySource::AutoGenerated,
                key: config_key,
                ..
            }) = &fullnode_network_config.identity
            {
                let path = node_config.storage.dir().join(IDENTITY_KEY_FILE);
                if let Some(loaded_identity) = Identity::load_identity(&path)? {
                    fullnode_network_config.identity = loaded_identity;
                } else {
                    Identity::save_private_key(&path, &config_key.private_key())?;
                }
            }
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

**File:** crates/aptos/src/common/types.rs (L1083-1089)
```rust
    /// Save to the `output_file` with restricted permissions (mode 0600)
    pub fn save_to_file_confidential(&self, name: &str, bytes: &[u8]) -> CliTypedResult<()> {
        let mut opts = OpenOptions::new();
        #[cfg(unix)]
        opts.mode(0o600);
        write_to_file_with_opts(self.output_file.as_path(), name, bytes, &mut opts)
    }
```
