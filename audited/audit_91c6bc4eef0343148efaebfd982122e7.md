# Audit Report

## Title
Insecure Directory Permissions Expose Validator Key Material to Local Attackers

## Summary
The `create_dir_if_not_exist()` function uses `std::fs::create_dir_all()` without explicitly setting secure permissions, resulting in world-readable directories (typically 0o755) that contain sensitive validator configuration and key material. This allows any local user to discover validator directory structures and potentially exploit race conditions during key generation.

## Finding Description
The vulnerability exists in the directory creation logic used throughout the Aptos CLI and configuration system: [1](#0-0) 

This function uses Rust's standard `std::fs::create_dir_all()` which creates directories with default permissions of 0o777 masked by the process umask. On most Linux systems with a default umask of 0o022, this results in directories with 0o755 permissions (rwxr-xr-x), making them world-readable and world-executable.

**Critical Usage Points:**

1. **Validator Key Generation**: When generating validator keys, the output directory is created with world-readable permissions before private keys are written: [2](#0-1) 

While the key files themselves receive proper 0o600 permissions via `write_to_user_only_file()`: [3](#0-2) 

The parent directory remains world-readable, allowing any local user to:
- List all files in the directory (revealing key file names like `private-keys.yaml`, `validator-identity.yaml`)
- Identify validator nodes by their directory structure
- Monitor when keys are generated or updated

2. **Identity Key Storage**: Similar issue when saving network identity keys: [4](#0-3) 

3. **Validator Data Directories**: Validator configuration directories are also created without secure permissions: [5](#0-4) 

**Attack Scenario:**
1. Validator operator runs `aptos genesis generate-keys --output-dir /path/to/keys`
2. Directory `/path/to/keys` is created with 0o755 permissions
3. Local attacker (different user on same machine) can:
   - Run `ls -la /path/to/keys` to see all key files
   - Use `inotify` to monitor when files are created/modified
   - Potentially exploit TOCTOU race conditions between directory creation and file creation
4. If the system has a misconfigured umask (e.g., 0o000), directories could even be world-writable, allowing attackers to replace key files

This violates the principle of least privilege for sensitive cryptographic material and creates an unnecessary attack surface on validator nodes.

## Impact Explanation
This vulnerability is classified as **Medium Severity** per the Aptos Bug Bounty criteria:

- **Information Disclosure**: Local attackers can discover validator directory structures, key file names, and timing information about key operations
- **Increased Attack Surface**: World-readable directories enable monitoring and potential race condition exploits
- **Configuration Exposure**: Validator configuration metadata becomes accessible to unprivileged local users

While this doesn't directly leak private key contents (the files themselves have proper permissions), it significantly weakens defense-in-depth for validator security. On multi-tenant systems or shared infrastructure, this could enable privilege escalation attacks or targeted exploitation.

The issue doesn't reach High or Critical severity because:
- Requires local access (not remotely exploitable)
- Doesn't directly compromise keys (files have 0o600 permissions)
- No direct consensus or funds impact

However, it's more severe than Low because it affects core validator security posture and could facilitate more complex attacks.

## Likelihood Explanation
**Likelihood: High**

This vulnerability occurs **automatically** whenever:
- Validators run `aptos genesis generate-keys`
- Nodes create identity key directories
- Any validator configuration is initialized

No special conditions or misconfigurations are required—it's the default behavior. Every validator operator on a multi-user system is potentially affected.

**Attack Requirements:**
- Local user account on the validator node's host machine
- Basic Unix command-line tools (`ls`, `inotify-tools`)
- No elevated privileges needed

Most production deployments should use dedicated machines for validators, reducing exposure. However:
- Development/testing environments often use shared machines
- Container orchestration platforms may have unexpected user access
- Compromised non-root accounts on validator machines can exploit this

## Recommendation
Implement explicit secure directory creation with 0o700 permissions (user-only read/write/execute). Create a new secure directory creation function:

```rust
#[cfg(unix)]
use std::os::unix::fs::DirBuilderExt;
use std::fs::DirBuilder;

pub fn create_dir_if_not_exist_secure(dir: &Path) -> CliTypedResult<()> {
    if !dir.exists() || !dir.is_dir() {
        let mut builder = DirBuilder::new();
        builder.recursive(true);
        
        #[cfg(unix)]
        builder.mode(0o700); // User-only permissions
        
        builder.create(dir)
            .map_err(|e| CliError::IO(dir.display().to_string(), e))?;
        debug!("Created {} folder with secure permissions", dir.display());
    } else {
        debug!("{} folder already exists", dir.display());
    }
    Ok(())
}
```

**Apply this fix to:**
1. Replace `create_dir_if_not_exist()` usage in `genesis/keys.rs` when creating key directories
2. Replace `fs::create_dir_all()` in `identity_config.rs` when creating identity key parent directories
3. Replace `std::fs::create_dir_all()` in `builder.rs` when creating validator data directories
4. Add a security comment explaining why 0o700 is required for these sensitive directories

Additionally, consider auditing existing deployed validators and documenting proper file system permissions in operational security guidelines.

## Proof of Concept

**Step 1: Demonstrate the vulnerability**

```bash
#!/bin/bash
# Run this as a regular user on a system where aptos CLI is installed

# Create a test directory and generate keys
TEST_DIR="/tmp/validator-test-$$"
aptos genesis generate-keys --output-dir "$TEST_DIR" --assume-yes

# Check directory permissions
echo "=== Directory Permissions ==="
ls -ld "$TEST_DIR"
# Expected output: drwxr-xr-x (0755) - VULNERABLE

echo -e "\n=== File Permissions ==="
ls -la "$TEST_DIR"
# Expected output: Files have -rw------- (0600) but directory is readable

# Now switch to a different user and demonstrate information leak
echo -e "\n=== Information Accessible to Other Users ==="
echo "Another user can run: ls -la $TEST_DIR"
echo "They will see:"
echo "  - private-keys.yaml (presence of validator keys)"
echo "  - validator-identity.yaml"
echo "  - Directory structure revealing this is a validator"

# Cleanup
rm -rf "$TEST_DIR"
```

**Step 2: Rust reproduction showing the issue**

```rust
use std::fs;
use std::path::Path;

fn main() {
    // Simulate what create_dir_if_not_exist() does
    let test_dir = Path::new("/tmp/aptos-permission-test");
    
    // This is what the current code does
    fs::create_dir_all(test_dir).unwrap();
    
    // Check resulting permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(test_dir).unwrap();
        let permissions = metadata.permissions();
        let mode = permissions.mode();
        
        println!("Created directory with permissions: {:o}", mode & 0o777);
        println!("Expected: 0700 (user-only)");
        println!("Actual: {:o} (world-readable!)", mode & 0o777);
        
        assert_eq!(mode & 0o777, 0o755, "Directory is world-readable - VULNERABLE");
    }
    
    // Cleanup
    fs::remove_dir_all(test_dir).ok();
}
```

This proof of concept demonstrates that directories created by the current implementation have 0o755 permissions, making them world-readable and exposing validator configuration to local attackers.

## Notes

While individual key files are properly protected with 0o600 permissions through `write_to_user_only_file()`, the containing directories remain world-readable. This creates an asymmetric security posture where file contents are protected but file metadata (names, existence, timestamps) is exposed.

The codebase already demonstrates awareness of secure file permissions (0o600 for key files), but this security control wasn't extended to directory creation—a common oversight in file permission handling. The fix is straightforward and should be applied consistently across all sensitive directory creation paths.

### Citations

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

**File:** crates/aptos-genesis/src/builder.rs (L80-83)
```rust
        // Create the data dir and set it appropriately
        let dir = base_dir.join(&name);
        std::fs::create_dir_all(dir.as_path())?;
        config.override_config_mut().set_data_dir(dir.clone());
```
