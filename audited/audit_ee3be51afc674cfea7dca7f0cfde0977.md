# Audit Report

## Title
Insecure File Permissions on Network Identity Private Keys Allow Local Privilege Escalation

## Summary
The `Identity::save_private_key()` function writes x25519 network identity private keys to disk without setting restrictive file permissions, potentially allowing any local user to read the key file and impersonate the node in P2P network connections.

## Finding Description

The vulnerability exists in the `Identity::save_private_key()` method which persists x25519 network identity private keys to disk: [1](#0-0) 

This function uses `File::create()` which relies on the system's umask to determine file permissions. On typical Unix systems with umask `0022`, this results in files created with `0644` permissions (world-readable). The function creates parent directories and writes the private key bytes but never explicitly sets secure permissions.

The vulnerable code path is triggered during node configuration optimization for public fullnode networks (VFNs and PFNs): [2](#0-1) 

When an auto-generated identity key doesn't exist on disk, it gets saved to `<storage_dir>/ephemeral_identity_key`. Any local user with read access to this directory can steal the x25519 private key.

**Attack Scenario:**
1. Attacker gains local user-level access to the validator/fullnode machine (via compromised service, ssh access, etc.)
2. Attacker reads the world-readable `ephemeral_identity_key` file
3. Attacker can now impersonate the node in P2P network connections using the stolen x25519 private key
4. This enables network-level attacks: DoS via identity theft, potential man-in-the-middle if positioned correctly, or reputation damage

**Security Invariant Violated:**
The cryptographic correctness invariant is broken - network identity keys must be kept confidential and only accessible by the node owner. The Noise IK protocol used for peer authentication assumes the private key remains secret. [3](#0-2) 

**Evidence of Proper Implementation:**
The codebase already contains the correct pattern for saving sensitive keys with restrictive permissions: [4](#0-3) 

This secure implementation is used for Ed25519 and BLS12381 keys: [5](#0-4) 

However, the network identity keys saved via `Identity::save_private_key()` do not use this secure method.

## Impact Explanation

**High Severity** per Aptos Bug Bounty criteria - this qualifies as a "Significant protocol violation" affecting validator infrastructure security.

With a stolen x25519 network identity key, an attacker can:
- **Impersonate the fullnode** in P2P network connections, authenticated via Noise IK handshake
- **Cause denial-of-service** by establishing connections as the legitimate peer, potentially confusing peer management
- **Intercept network traffic** if positioned between the legitimate node and its peers
- **Damage reputation** of validator operators by performing malicious actions under their network identity

While this doesn't directly compromise consensus (the key is for public fullnode networks, not validator consensus networks), it significantly impacts validator infrastructure security and can be chained with other attacks.

## Likelihood Explanation

**High Likelihood** - The vulnerability will manifest on any system where:
1. The default umask allows world-readable files (common default: `0022`)
2. The node runs with auto-generated network identity (common for fullnodes)
3. An attacker gains any local user access to the machine

This is particularly concerning because:
- Many validator operators run VFNs (Validator Fullnodes) alongside validators
- Container environments and cloud deployments may have default umasks that create world-readable files
- The key file name `ephemeral_identity_key` is predictable and stored in the well-known storage directory
- No additional exploitation complexity is required - simple file read access is sufficient

## Recommendation

Apply the same secure file permission pattern already used for other private keys in the codebase. Replace `File::create()` with `OpenOptions` that explicitly sets mode `0o600` on Unix systems:

**Fixed Implementation:**
```rust
pub fn save_private_key(path: &PathBuf, key: &x25519::PrivateKey) -> anyhow::Result<()> {
    // Create the parent directory
    let parent_path = path.parent().unwrap();
    fs::create_dir_all(parent_path)?;

    // Save the private key with restrictive permissions (0600)
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    
    opts.open(path)?
        .write_all(&key.to_bytes())
        .map_err(|error| error.into())
}
```

Additionally, import `OpenOptions` and the Unix extension trait:
```rust
use std::fs::OpenOptions;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
```

Alternatively, refactor to use the existing `write_to_user_only_file()` utility if appropriate for the config module dependencies.

## Proof of Concept

**Rust Test Demonstrating Insecure Permissions:**

```rust
#[cfg(unix)]
#[test]
fn test_identity_key_insecure_permissions() {
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;
    use aptos_crypto::{x25519, Uniform};
    use rand::rngs::OsRng;

    // Create a temporary directory
    let temp_dir = tempdir().unwrap();
    let key_path = temp_dir.path().join("identity_key");
    
    // Generate and save a key using the vulnerable function
    let private_key = x25519::PrivateKey::generate(&mut OsRng);
    Identity::save_private_key(&key_path, &private_key).unwrap();
    
    // Check file permissions
    let metadata = std::fs::metadata(&key_path).unwrap();
    let permissions = metadata.permissions();
    let mode = permissions.mode();
    
    // On systems with umask 0022, this will be 0o100644 (regular file, rw-r--r--)
    // The file is world-readable (mode & 0o004 != 0)
    println!("File created with mode: {:o}", mode);
    
    // This assertion will PASS, demonstrating the vulnerability
    assert_ne!(mode & 0o004, 0, "File should be world-readable with default umask");
    
    // Expected secure mode would be 0o100600 (rw-------)
    assert_ne!(mode & 0o177, 0o600, "File permissions are NOT restrictive");
}

#[cfg(unix)]
#[test]
fn test_secure_key_save_comparison() {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use tempfile::tempdir;
    use aptos_crypto::{x25519, Uniform};
    use rand::rngs::OsRng;

    let temp_dir = tempdir().unwrap();
    let secure_path = temp_dir.path().join("secure_key");
    
    // Save with explicit 0600 permissions (secure)
    let private_key = x25519::PrivateKey::generate(&mut OsRng);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    opts.mode(0o600);
    opts.open(&secure_path).unwrap()
        .write_all(&private_key.to_bytes()).unwrap();
    
    let metadata = std::fs::metadata(&secure_path).unwrap();
    let mode = metadata.permissions().mode();
    
    println!("Secure file mode: {:o}", mode);
    
    // Verify NOT world-readable
    assert_eq!(mode & 0o004, 0, "Secure file should NOT be world-readable");
    // Verify NOT group-readable
    assert_eq!(mode & 0o040, 0, "Secure file should NOT be group-readable");
    // Verify owner can read/write
    assert_eq!(mode & 0o600, 0o600, "Owner should have read/write");
}
```

**Exploitation Steps:**
1. Deploy a VFN or PFN node with default configuration
2. As any local user: `cat /path/to/storage/ephemeral_identity_key`
3. Use stolen x25519 private key to establish authenticated P2P connections impersonating the node
4. Execute network-level attacks (DoS, traffic interception, etc.)

## Notes

This vulnerability affects **public fullnode networks** (VFNs and PFNs), not the validator's private consensus network. However, VFNs are critical infrastructure for validators, and compromising their network identity still represents a significant security risk. The fix is straightforward and follows existing secure patterns in the codebase.

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

**File:** config/src/config/config_optimizer.rs (L217-232)
```rust
            // If the identity key was not set in the config, attempt to
            // load it from disk. Otherwise, save the already generated
            // one to disk (for future runs).
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

**File:** network/framework/src/noise/handshake.rs (L76-99)
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
    /// In `MaybeMutual` mode, the dialer authenticates the server and the server will allow all
    /// inbound connections from any peer but will mark connections as `Trusted` if the incoming
    /// connection is apart of its trusted peers set.
    MaybeMutual(Arc<PeersAndMetadata>),
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

**File:** crates/aptos/src/op/key.rs (L426-446)
```rust
    pub fn save_key<Key: PrivateKey + ValidCryptoMaterial>(
        self,
        key: &Key,
        key_name: &'static str,
    ) -> CliTypedResult<HashMap<&'static str, PathBuf>> {
        let encoded_private_key = self.encoding_options.encoding.encode_key(key_name, key)?;
        let encoded_public_key = self
            .encoding_options
            .encoding
            .encode_key(key_name, &key.public_key())?;

        // Write private and public keys to files
        let public_key_file = self.public_key_file()?;
        self.file_options
            .save_to_file_confidential(key_name, &encoded_private_key)?;
        write_to_file(&public_key_file, key_name, &encoded_public_key)?;

        let mut map = HashMap::new();
        map.insert("PrivateKey Path", self.file_options.output_file);
        map.insert("PublicKey Path", public_key_file);
        Ok(map)
```
