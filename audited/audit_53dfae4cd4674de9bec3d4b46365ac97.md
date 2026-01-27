# Audit Report

## Title
Private Key File Path Disclosure in CLI Error Messages

## Summary
The Aptos CLI exposes full file system paths of private key files in error messages when file read operations fail due to permission issues, missing files, or I/O errors. This information disclosure vulnerability affects multiple CLI commands that load cryptographic keys from files.

## Finding Description

When the Aptos CLI attempts to load a private key from a file and encounters an error (wrong permissions, file not found, or any I/O failure), the error message includes the complete file system path to the private key file.

The vulnerability exists in the `EncodingType::load_key()` function which calls `read_from_file()`. When file reading fails, the error is constructed with the full path: [1](#0-0) 

This error is then converted to a CLI error that preserves the path information: [2](#0-1) 

The error message format explicitly includes the file path: [3](#0-2) 

This vulnerability affects multiple locations where private keys are loaded:

1. **Network key loading** in `NetworkKeyInputOptions::extract_public_network_key()`: [4](#0-3) 

2. **Private key loading** in `ParseEd25519PrivateKey::parse_private_key()`: [5](#0-4) 

3. **Authentication key loading**: [6](#0-5) 

**Attack Scenario:**
1. User runs: `aptos key extract-peer --host 127.0.0.1:6180 --private-network-key-file /home/alice/.aptos/validator-network-key --output-file peer.yaml`
2. If the file has incorrect permissions (e.g., chmod 000) or doesn't exist, the error displays: `"Unable to read file '/home/alice/.aptos/validator-network-key', error: Permission denied"`
3. This exposes the complete directory structure where validator keys are stored

In containerized/orchestrated environments (Kubernetes, Docker) or multi-tenant systems, these error messages may be logged to centralized logging systems, exposing key storage locations to unauthorized parties who have log access.

## Impact Explanation

This qualifies as **Medium Severity** under the Aptos bug bounty program. While it doesn't directly compromise cryptographic key material, it constitutes more than a "minor information leak" (Low severity) because:

1. **Reconnaissance Aid**: Attackers gain knowledge of exact file system paths where private keys are stored, facilitating targeted attacks
2. **Multi-tenant Risk**: In shared validator infrastructure or container orchestration platforms, error logs could expose key locations to other tenants
3. **Social Engineering**: Exposed paths can be used in social engineering attacks or to identify high-value targets
4. **Defense-in-Depth Violation**: Security best practice dictates minimizing information disclosure; exposing key storage locations weakens defense-in-depth

The vulnerability doesn't cause "limited funds loss" but represents a significant operational security weakness in key management infrastructure.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability triggers in common operational scenarios:
- File permission misconfiguration during validator setup
- Typos in file paths during CLI operations
- File system issues (disk full, unmounted volumes)
- Incorrect file ownership in containerized deployments
- Standard troubleshooting where users share error messages

Any operator configuring Aptos validators or using the CLI for key management operations will likely encounter this at least once. In automated deployment pipelines with centralized logging, every failed key loading operation creates a permanent record of key file locations.

## Recommendation

Sanitize file paths in error messages for cryptographic key operations. Replace the full path with a generic message or only the filename (not the full path):

**Recommended Fix:**

Modify `read_from_file()` in `crates/aptos-crypto/src/encoding_type.rs`:

```rust
pub fn read_from_file(path: &Path) -> Result<Vec<u8>, EncodingError> {
    std::fs::read(path).map_err(|e| {
        // Only expose filename, not full path, for security-sensitive operations
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("<unknown>");
        EncodingError::UnableToReadFile(
            format!("<redacted path>/{}", file_name),
            e.to_string(),
        )
    })
}
```

Alternatively, create a separate function for loading sensitive key material that never includes paths in error messages:

```rust
pub fn read_key_from_file(path: &Path) -> Result<Vec<u8>, EncodingError> {
    std::fs::read(path).map_err(|e| {
        EncodingError::UnableToReadFile(
            String::from("private key file"),
            e.to_string(),
        )
    })
}
```

## Proof of Concept

**Rust Reproduction Steps:**

```rust
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use tempfile::TempDir;
use aptos_crypto::encoding_type::{EncodingType, EncodingError};

#[test]
fn test_private_key_path_disclosure() {
    // Create a temporary directory with a private key file
    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("secret-validator-key");
    
    // Create file and set restrictive permissions to trigger read error
    File::create(&key_path).unwrap();
    let mut perms = fs::metadata(&key_path).unwrap().permissions();
    perms.set_mode(0o000); // No read permissions
    fs::set_permissions(&key_path, perms).unwrap();
    
    // Attempt to load key - this will fail and expose the path
    let encoding = EncodingType::Hex;
    let result = encoding.load_key::<aptos_crypto::x25519::PrivateKey>(
        "--private-network-key-file",
        &key_path
    );
    
    // Verify the error contains the full path
    match result {
        Err(EncodingError::UnableToReadFile(path, _)) => {
            println!("❌ VULNERABILITY CONFIRMED: Full path exposed in error: {}", path);
            assert!(path.contains(key_path.to_str().unwrap()));
            // In production, this path would be visible in error logs/output
        }
        _ => panic!("Expected UnableToReadFile error"),
    }
}
```

**CLI Reproduction:**

```bash
# Create a test key file with no read permissions
touch /tmp/test-validator-key
chmod 000 /tmp/test-validator-key

# Run CLI command that loads the key
aptos key extract-peer \
  --host 127.0.0.1:6180 \
  --private-network-key-file /tmp/test-validator-key \
  --output-file peer.yaml

# Expected output exposes full path:
# Error: Unable to read file '/tmp/test-validator-key', error: Permission denied

# Clean up
rm /tmp/test-validator-key
```

The vulnerability is confirmed when the error message includes the complete file system path to the private key file.

## Notes

This vulnerability affects all CLI commands that load private keys, network keys, or authentication keys from files. The issue is systemic in the `EncodingType::load_key()` function, making it affect multiple attack surfaces across the Aptos CLI tooling. While the immediate security impact is information disclosure rather than key compromise, it represents a violation of the principle of least privilege in error reporting and could facilitate more sophisticated attacks against validator infrastructure.

### Citations

**File:** crates/aptos-crypto/src/encoding_type.rs (L103-106)
```rust
pub fn read_from_file(path: &Path) -> Result<Vec<u8>, EncodingError> {
    std::fs::read(path)
        .map_err(|e| EncodingError::UnableToReadFile(format!("{}", path.display()), e.to_string()))
}
```

**File:** crates/aptos/src/common/types.rs (L147-148)
```rust
    #[error("Unable to read file '{0}', error: {1}")]
    UnableToReadFile(String, String),
```

**File:** crates/aptos/src/common/types.rs (L246-254)
```rust
impl From<EncodingError> for CliError {
    fn from(e: EncodingError) -> Self {
        match e {
            EncodingError::BCS(s, e) => CliError::BCS(s, e),
            EncodingError::UnableToParse(s, e) => CliError::UnableToParse(s, e),
            EncodingError::UnableToReadFile(s, e) => CliError::UnableToReadFile(s, e),
            EncodingError::UTF8(s) => CliError::UnexpectedError(s),
        }
    }
```

**File:** crates/aptos/src/common/types.rs (L658-660)
```rust
        if let Some(ref file) = self.auth_key_file {
            Ok(Some(encoding.load_key("--auth-key-file", file.as_path())?))
        } else if let Some(ref key) = self.auth_key {
```

**File:** crates/aptos/src/common/types.rs (L734-737)
```rust
        if let Some(ref file) = private_key_file {
            Ok(Some(
                encoding.load_key("--private-key-file", file.as_path())?,
            ))
```

**File:** crates/aptos/src/op/key.rs (L160-162)
```rust
            (None, None, None, Some(private_network_key_file)) => {
                let private_network_key: x25519::PrivateKey = encoding.load_key("--private-network-key-file", private_network_key_file.as_path())?;
                Ok(private_network_key.public_key())
```
