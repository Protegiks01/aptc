# Audit Report

## Title
Symlink Following Vulnerability in Genesis Pool Address Generation Tool

## Summary
The `write_to_file()` function used by the genesis pool address generation tool follows symbolic links without validation, potentially allowing local attackers to redirect file writes to arbitrary locations. This could enable privilege escalation if the tool is run by a privileged user (e.g., validator operator) in an environment where an attacker can create symlinks. [1](#0-0) 

## Finding Description
The `PoolAddresses::execute()` function in the genesis tools module writes two YAML files containing stake pool addresses to a user-specified (or current) directory. The underlying `write_to_file()` implementation uses Rust's standard `OpenOptions::open()` which follows symbolic links by default. [2](#0-1) 

The core implementation in `write_to_file_with_opts()` opens files with `.write(true).create(true).truncate(true)` flags, which will follow any symbolic links present at the target path: [3](#0-2) 

**Attack Scenario:**
1. An attacker with local system access creates a directory containing symbolic links named `pool-addresses.yaml` and `employee-pool-addresses.yaml` pointing to sensitive files (e.g., validator keys, system configuration files, SSH authorized_keys)
2. The attacker tricks or waits for a privileged user (validator operator, system administrator) to run: `aptos genesis get-pool-addresses --output-dir /path/to/malicious/directory`
3. The tool follows the symlinks and overwrites the target files with YAML-formatted pool address data, potentially corrupting critical validator infrastructure

The output directory defaults to the current working directory if not specified: [4](#0-3) 

Notably, the codebase has utilities for canonicalizing paths (resolving symlinks), but these are not used in the file writing functions, confirming the vulnerability exists as a design gap rather than an implementation oversight.

## Impact Explanation
This vulnerability qualifies as **High Severity** under the Aptos Bug Bounty program criteria because successful exploitation could lead to:

1. **Validator Node Compromise**: Overwriting validator configuration files, private keys, or consensus parameters could disable or compromise validator nodes
2. **Local Privilege Escalation**: Lower-privileged users could overwrite files owned by privileged users running the genesis tool
3. **Infrastructure Corruption**: Overwriting system files (if run as root) could lead to denial of service or system compromise

While this does not directly violate blockchain consensus invariants, it targets critical validator infrastructure used during genesis and validator setup processes, which are essential for network security.

## Likelihood Explanation
**Medium Likelihood** - Exploitation requires specific conditions:

1. **Local System Access**: Attacker must have write access to create symlinks in the target directory
2. **Privileged Execution**: The tool must be run by a user with higher privileges than the attacker
3. **Exploitation Window**: The attacker must create symlinks before the tool runs, requiring knowledge of when and where it will be executed

The likelihood increases in:
- Shared validator setup environments
- Automated deployment pipelines where output directories may be predictable
- Scenarios where validator operators run genesis commands from shared or untrusted directories

The likelihood decreases with:
- Single-user validator setups with proper file permissions
- SELinux/AppArmor protections preventing symlink attacks
- Validators following security best practices (running tools from secure, dedicated directories)

## Recommendation
Implement symlink detection and prevention before writing files. Multiple approaches can mitigate this vulnerability:

**Option 1: Canonicalize paths before writing (Recommended)**
```rust
pub fn write_to_file(path: &Path, name: &str, bytes: &[u8]) -> CliTypedResult<()> {
    // Resolve symlinks and convert to absolute path
    let canonical_path = path.canonicalize()
        .map_err(|e| CliError::IO(name.to_string(), e))?;
    
    // Verify the canonical path is still within expected directory
    // (prevents directory traversal via symlinks)
    
    write_to_file_with_opts(&canonical_path, name, bytes, &mut OpenOptions::new())
}
```

**Option 2: Use O_NOFOLLOW flag on Unix systems**
```rust
pub fn write_to_file(path: &Path, name: &str, bytes: &[u8]) -> CliTypedResult<()> {
    let mut opts = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    write_to_file_with_opts(path, name, bytes, &mut opts)
}
```

**Option 3: Use create_new instead of create**
```rust
// This prevents overwriting existing files/symlinks but doesn't fully prevent symlink attacks
opts.write(true).create_new(true).truncate(true)
```

Additionally, add validation to `PoolAddresses::execute()` to check file types before writing and prompt users when writing to potentially dangerous locations.

## Proof of Concept
```rust
#[test]
fn test_symlink_following_vulnerability() {
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;
    
    // Create temporary directories
    let temp_dir = TempDir::new().unwrap();
    let target_dir = TempDir::new().unwrap();
    
    // Create a target file we want to protect
    let target_file = target_dir.path().join("sensitive.txt");
    std::fs::write(&target_file, b"SENSITIVE DATA").unwrap();
    
    // Create symlink in output directory pointing to target file
    let symlink_path = temp_dir.path().join("pool-addresses.yaml");
    symlink(&target_file, &symlink_path).unwrap();
    
    // Write using the vulnerable function
    write_to_file(
        &symlink_path,
        "pool-addresses.yaml",
        b"pools:\n  - 0x1\n  - 0x2\n"
    ).unwrap();
    
    // Verify the symlink was followed and target file was overwritten
    let contents = std::fs::read_to_string(&target_file).unwrap();
    assert!(contents.contains("pools"), "Symlink was followed and target overwritten!");
    assert!(!contents.contains("SENSITIVE DATA"), "Original data was destroyed!");
}
```

**Notes:**
- This vulnerability is a **local privilege escalation** issue, not a remote network exploit
- Exploitation requires the attacker to have local system access and write permissions in the output directory
- While the technical vulnerability exists and is valid, its practical exploitability depends heavily on deployment context and security practices
- The genesis tool is not a continuously running service but a utility command used during validator setup, which limits the attack surface
- Modern operating systems with security modules (SELinux, AppArmor) may provide additional protections against symlink attacks

### Citations

**File:** crates/aptos/src/genesis/tools.rs (L87-96)
```rust
        write_to_file(
            pool_addresses_file.as_path(),
            POOL_ADDRESSES,
            serde_yaml::to_string(&address_to_pool)?.as_bytes(),
        )?;
        write_to_file(
            employee_pool_addresses_file.as_path(),
            EMPLOYEE_POOL_ADDRESSES,
            serde_yaml::to_string(&employee_address_to_pool)?.as_bytes(),
        )?;
```

**File:** crates/aptos/src/common/utils.rs (L219-221)
```rust
pub fn write_to_file(path: &Path, name: &str, bytes: &[u8]) -> CliTypedResult<()> {
    write_to_file_with_opts(path, name, bytes, &mut OpenOptions::new())
}
```

**File:** crates/aptos/src/common/utils.rs (L232-246)
```rust
pub fn write_to_file_with_opts(
    path: &Path,
    name: &str,
    bytes: &[u8],
    opts: &mut OpenOptions,
) -> CliTypedResult<()> {
    let mut file = opts
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|e| CliError::IO(name.to_string(), e))?;
    file.write_all(bytes)
        .map_err(|e| CliError::IO(name.to_string(), e))
}
```

**File:** crates/aptos/src/common/utils.rs (L408-414)
```rust
pub fn dir_default_to_current(maybe_dir: Option<PathBuf>) -> CliTypedResult<PathBuf> {
    if let Some(dir) = maybe_dir {
        Ok(dir)
    } else {
        current_dir()
    }
}
```
