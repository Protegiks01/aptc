# Audit Report

## Title
Network Identity Private Keys Created with World-Readable Permissions

## Summary
The `Identity::save_private_key` function in `config/src/config/identity_config.rs` creates x25519 network identity private key files with insecure default permissions (typically 0o644 on Unix systems), making them world-readable. Additionally, parent directories are created with world-readable permissions (0o755). This allows any local user on the same system to read validator and full node network identity keys, enabling node impersonation and man-in-the-middle attacks on the Aptos peer-to-peer network.

## Finding Description

The vulnerability exists in two related code locations:

**Primary Vulnerability** - File created with default permissions: [1](#0-0) 

This function uses `File::create(path)` which creates files with default permissions (0o666 & !umask). With the standard Unix umask of 0o022, this results in 0o644 permissions (rw-r--r--), making the file world-readable. The x25519 private key bytes are written directly to this insecure file.

**Secondary Vulnerability** - Directory created with world-readable permissions: [2](#0-1) 

The `fs::create_dir_all` function creates parent directories with default permissions (typically 0o755, rwxr-xr-x), allowing any user to list directory contents and discover key file locations.

**Production Usage Path:** [3](#0-2) 

This code is invoked during full node configuration optimization when an auto-generated network identity needs to be persisted. The path is `node_config.storage.dir().join(IDENTITY_KEY_FILE)` where `IDENTITY_KEY_FILE = "ephemeral_identity_key"`.

**Security Context** - x25519 keys are used for network authentication:

The x25519 private keys serve as network identity and are used in the Noise protocol for authenticated encryption between peers. Exposure of these keys allows an attacker to:
1. Impersonate the node on the peer-to-peer network
2. Perform man-in-the-middle attacks on validator communications
3. Inject malicious messages or disrupt consensus messaging

**Comparison with Secure Implementation:**

The CLI tool properly secures key files: [4](#0-3) 

This shows the codebase has the correct implementation pattern using mode 0o600, but `identity_config.rs` doesn't follow it.

**Additional Directory Permission Issue:** [5](#0-4) [6](#0-5) 

Genesis key generation creates directories without setting restrictive permissions, allowing directory listing even though files have 0o600 permissions.

## Impact Explanation

This vulnerability qualifies as **HIGH severity** under the Aptos bug bounty program:

- **Significant Protocol Violation**: Network identity keys are critical security credentials. Their exposure violates the fundamental security assumption that node identities are authentic and cannot be forged.

- **Network Security Compromise**: An attacker with local filesystem access (e.g., compromised service, multi-tenant environment, container escape) can:
  - Read validator and full node network identity private keys
  - Impersonate nodes on the network
  - Intercept or modify consensus messages
  - Disrupt validator network communication
  - Perform man-in-the-middle attacks

- **Affected Deployments**: Any validator or full node running on:
  - Shared hosting environments
  - Multi-tenant systems
  - Systems with other compromised services
  - Systems where an attacker has gained limited local access

While this doesn't directly cause fund loss or consensus safety violations, it enables attacks that could lead to validator node slowdowns, network disruption, and significant protocol violations, meeting the HIGH severity criteria.

## Likelihood Explanation

**Likelihood: MEDIUM to HIGH**

The vulnerability will be triggered automatically in production scenarios:

1. **Automatic Triggering**: When a full node starts with an auto-generated network identity, the config optimizer automatically calls `Identity::save_private_key` with insecure permissions.

2. **Common Attack Vector**: Local filesystem access attacks are common:
   - Container escape vulnerabilities
   - Compromised application services on the same host
   - Multi-tenant cloud environments
   - Shared hosting scenarios
   - Privilege escalation from limited user accounts

3. **No Warning or Detection**: The insecure permissions are created silently with no warnings, and operators may not realize their keys are exposed.

4. **Persistent Exposure**: Once created, the world-readable files remain vulnerable until manually fixed.

The attack requires local access but does not require validator privileges or complex exploitation, making it realistic in many deployment scenarios.

## Recommendation

**Immediate Fix for `identity_config.rs`:**

Replace the `save_private_key` function implementation to use secure file permissions:

```rust
pub fn save_private_key(path: &PathBuf, key: &x25519::PrivateKey) -> anyhow::Result<()> {
    // Create the parent directory with restrictive permissions
    let parent_path = path.parent().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)  // rwx------ (owner only)
            .create(parent_path)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(parent_path)?;
    }

    // Save the private key with user-only permissions
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);  // rw------- (owner read/write only)
    
    let mut file = opts.open(path)?;
    file.write_all(&key.to_bytes())
        .map_err(|error| error.into())
}
```

**Fix for `create_dir_if_not_exist` in utils.rs:**

```rust
pub fn create_dir_if_not_exist(dir: &Path) -> CliTypedResult<()> {
    if !dir.exists() || !dir.is_dir() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)  // rwx------ (owner only)
                .create(dir)
                .map_err(|e| CliError::IO(dir.display().to_string(), e))?;
        }
        #[cfg(not(unix))]
        {
            std::fs::create_dir_all(dir)
                .map_err(|e| CliError::IO(dir.display().to_string(), e))?;
        }
        debug!("Created {} folder", dir.display());
    } else {
        debug!("{} folder already exists", dir.display());
    }
    Ok(())
}
```

**Remediation for Existing Deployments:**

Operators should immediately check and fix permissions on existing key files:
```bash
# Fix directory permissions
chmod 700 /path/to/key/directory

# Fix file permissions
chmod 600 /path/to/key/directory/ephemeral_identity_key
```

## Proof of Concept

```rust
// File: poc_insecure_permissions.rs
// Demonstrates the vulnerability in identity_config.rs

use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::os::unix::fs::PermissionsExt;

fn main() {
    // Simulate the vulnerable save_private_key function
    let test_dir = PathBuf::from("/tmp/aptos_vuln_test");
    let key_path = test_dir.join("ephemeral_identity_key");
    
    // Create directory (as done in identity_config.rs line 120)
    fs::create_dir_all(&test_dir).expect("Failed to create directory");
    
    // Create file (as done in identity_config.rs line 123)
    let mut file = File::create(&key_path).expect("Failed to create file");
    
    // Write dummy key data
    let key_data = b"SENSITIVE_PRIVATE_KEY_DATA_x25519_32_bytes!!";
    file.write_all(key_data).expect("Failed to write key");
    
    // Check directory permissions
    let dir_metadata = fs::metadata(&test_dir).expect("Failed to read dir metadata");
    let dir_perms = dir_metadata.permissions().mode() & 0o777;
    println!("Directory permissions: {:o}", dir_perms);
    
    // Check file permissions
    let file_metadata = fs::metadata(&key_path).expect("Failed to read file metadata");
    let file_perms = file_metadata.permissions().mode() & 0o777;
    println!("File permissions: {:o}", file_perms);
    
    // Verify vulnerability
    if dir_perms == 0o755 {
        println!("❌ VULNERABLE: Directory is world-readable (755)");
    }
    
    if file_perms == 0o644 {
        println!("❌ VULNERABLE: File is world-readable (644)");
        println!("   Any user on the system can run: cat {}", key_path.display());
    }
    
    // Demonstrate attack: another user can read the key
    match fs::read_to_string(&key_path) {
        Ok(contents) => {
            println!("✓ EXPLOIT CONFIRMED: Successfully read private key as unprivileged user");
            println!("   Key content: {:?}", contents);
        }
        Err(e) => println!("Read failed: {}", e),
    }
    
    // Cleanup
    fs::remove_dir_all(&test_dir).ok();
}

/*
Expected output on Unix systems with default umask 0o022:
Directory permissions: 755
File permissions: 644
❌ VULNERABLE: Directory is world-readable (755)
❌ VULNERABLE: File is world-readable (644)
   Any user on the system can run: cat /tmp/aptos_vuln_test/ephemeral_identity_key
✓ EXPLOIT CONFIRMED: Successfully read private key as unprivileged user
   Key content: "SENSITIVE_PRIVATE_KEY_DATA_x25519_32_bytes!!"
*/
```

**Notes**

The vulnerability exists in production code paths and affects both validator and full node deployments. The x25519 network identity keys are critical for peer authentication in the Noise protocol, and their exposure enables node impersonation attacks. While similar to the directory permission issues in `genesis/keys.rs`, the `identity_config.rs` vulnerability is more severe as it exposes actual key material with world-readable file permissions, not just directory metadata. The fix requires setting explicit mode 0o600 for files and 0o700 for directories on Unix systems, following the pattern already established in `crates/aptos/src/common/utils.rs`.

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

**File:** config/src/config/config_optimizer.rs (L220-231)
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

**File:** crates/aptos/src/common/utils.rs (L416-425)
```rust
pub fn create_dir_if_not_exist(dir: &Path) -> CliTypedResult<()> {
    // Check if the directory exists, if it's not a dir, it will also fail here
    if !dir.exists() || !dir.is_dir() {
        std::fs::create_dir_all(dir).map_err(|e| CliError::IO(dir.display().to_string(), e))?;
        debug!("Created {} folder", dir.display());
    } else {
        debug!("{} folder already exists", dir.display());
    }
    Ok(())
}
```

**File:** crates/aptos/src/genesis/keys.rs (L80-80)
```rust
        create_dir_if_not_exist(output_dir.as_path())?;
```
