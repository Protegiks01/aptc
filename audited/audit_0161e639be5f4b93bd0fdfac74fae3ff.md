# Audit Report

## Title
Validator Private Keys Exposed via Insecure File Permissions During Genesis Key Generation

## Summary
The `validator_blob` containing all validator private keys (account, consensus, and network keys) is written to disk with insecure file permissions during genesis key generation, allowing unauthorized filesystem access to steal all validator secrets and compromise consensus safety.

## Finding Description

The `generate_key_objects()` function creates a `validator_blob` containing all critical validator private keys. [1](#0-0) 

This blob is serialized to YAML format where private keys are exposed as plaintext hex strings. [2](#0-1) 

The critical vulnerability occurs in `builder.rs` where the `write_yaml()` helper function writes these sensitive files using `File::create()` without setting restrictive permissions. [3](#0-2) 

The validator identity blob is written using this insecure function. [4](#0-3) 

**Contrast with Secure Implementation**: The codebase contains a secure alternative `write_to_user_only_file()` that properly sets `0o600` permissions on Unix systems. [5](#0-4) 

However, this secure function is NOT used in the builder path, creating an inconsistency where some key files are protected while others are not.

**Attack Vector**: 
1. Validator operator runs genesis key generation via `ValidatorNodeConfig::get_key_objects()`
2. Files `validator-identity.yaml` and `private-identity.yaml` are created with default OS permissions (potentially world-readable)
3. Attacker with filesystem read access (malware, another user, backup system, cloud sync) reads the files
4. Attacker obtains all validator private keys in plaintext hex format
5. Attacker can impersonate validator in consensus, sign malicious blocks, and compromise validator account

## Impact Explanation

**CRITICAL Severity** - This vulnerability enables complete validator compromise:

1. **Consensus Safety Violation**: Stolen `consensus_private_key` allows attacker to participate in BFT consensus as the legitimate validator, potentially causing equivocation or voting for malicious blocks
2. **Validator Account Compromise**: Stolen `account_private_key` grants full control over validator's on-chain account, including stake manipulation
3. **Network Impersonation**: Stolen `network_private_key` allows network-level impersonation
4. **Multi-Validator Risk**: If multiple validators generate keys on shared infrastructure, a single compromise could steal keys from all validators, enabling >1/3 Byzantine attacks

This meets the **Critical Severity** criteria: "Consensus/Safety violations" and potential "Loss of Funds" through validator account control.

## Likelihood Explanation

**HIGH Likelihood**:

1. **Common Deployment Scenarios**: Validators often use shared infrastructure, CI/CD systems, or cloud environments where multiple processes/users have filesystem access
2. **Backup and Monitoring**: Automated backup systems, log aggregators, and monitoring tools routinely scan filesystems and could inadvertently expose these keys
3. **Default OS Permissions**: Without explicit restriction, Unix systems typically create files with umask-dependent permissions (often 0o644 readable by all users)
4. **Windows Systems**: On Windows, the secure permission setting is completely omitted, leaving files with default permissions
5. **Long Exposure Window**: Files persist on disk until manually removed, providing extended opportunity for compromise

## Recommendation

Replace all `write_yaml()` calls for sensitive key material with `write_to_user_only_file()` or implement platform-specific secure file creation:

**Fix for builder.rs**:
```rust
fn write_yaml<T: Serialize>(path: &Path, object: &T) -> anyhow::Result<()> {
    let yaml_bytes = serde_yaml::to_string(object)?.as_bytes().to_vec();
    
    // Set restrictive permissions (0o600 on Unix)
    let mut opts = std::fs::OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    #[cfg(windows)]
    {
        // On Windows, use platform-specific ACLs to restrict access
        // This requires additional implementation
    }
    
    let mut file = opts
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    
    file.write_all(&yaml_bytes)?;
    Ok(())
}
```

Additionally, consider encrypting the validator identity files at rest with a passphrase or HSM-based encryption.

## Proof of Concept

**Reproduction Steps**:

1. Create a test validator configuration directory
2. Run the genesis key generation flow via `ValidatorNodeConfig::get_key_objects()`
3. Check file permissions on the created `validator-identity.yaml`

```rust
// PoC test demonstrating insecure permissions
#[test]
fn test_validator_identity_file_permissions() {
    use std::fs;
    use std::path::PathBuf;
    use tempfile::tempdir;
    
    // Create temporary directory for test
    let temp_dir = tempdir().unwrap();
    let validator_dir = temp_dir.path().join("validator-0");
    fs::create_dir_all(&validator_dir).unwrap();
    
    // Simulate validator config creation
    let mut validator_config = ValidatorNodeConfig::new(
        "validator-0".to_string(),
        0,
        temp_dir.path(),
        // ... config parameters
    ).unwrap();
    
    // Generate keys (triggers write_yaml)
    let _ = validator_config.get_key_objects(None).unwrap();
    
    // Check file permissions
    let identity_file = validator_dir.join("validator-identity.yaml");
    let metadata = fs::metadata(&identity_file).unwrap();
    
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        let perms = mode & 0o777;
        
        // VULNERABLE: File may have world-readable permissions (e.g., 0o644)
        // EXPECTED: Should be 0o600 (user read/write only)
        assert_eq!(perms, 0o600, 
            "Validator identity file has insecure permissions: {:o}", perms);
    }
}
```

**Expected Result**: Test fails, demonstrating that files are created with insecure permissions, allowing unauthorized access to validator private keys.

### Citations

**File:** crates/aptos-genesis/src/keys.rs (L47-52)
```rust
    let validator_blob = IdentityBlob {
        account_address: Some(account_address),
        account_private_key: Some(account_key.private_key()),
        consensus_private_key: Some(consensus_key.private_key()),
        network_private_key: validator_network_key.private_key(),
    };
```

**File:** crates/aptos-crypto/src/traits/mod.rs (L102-104)
```rust
    fn to_encoded_string(&self) -> Result<String> {
        Ok(format!("0x{}", ::hex::encode(self.to_bytes())))
    }
```

**File:** crates/aptos-genesis/src/builder.rs (L145-145)
```rust
            write_yaml(val_identity_file.as_path(), &validator_identity)?;
```

**File:** crates/aptos-genesis/src/builder.rs (L418-420)
```rust
fn write_yaml<T: Serialize>(path: &Path, object: &T) -> anyhow::Result<()> {
    File::create(path)?.write_all(serde_yaml::to_string(object)?.as_bytes())?;
    Ok(())
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
