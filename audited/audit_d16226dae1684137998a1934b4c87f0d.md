# Audit Report

## Title
Insecure File Permissions on Extracted Validator Public Keys Allow Local Information Disclosure

## Summary
The `ExtractPublicKey::execute()` function saves public key files with default system umask permissions (typically 0644), making them world-readable on multi-user systems. This exposes validator public keys to local attackers who can use this information for reconnaissance.

## Finding Description
When extracting public keys from private keys, the CLI tool creates output files without restricting permissions. [1](#0-0) 

The `save_material()` function calls `write_to_file()`, which uses default `OpenOptions` without setting Unix file permissions. [2](#0-1) 

The underlying `write_to_file_with_opts()` creates files with `.write(true).create(true).truncate(true)` but no mode specification. [3](#0-2) 

This contrasts with private key handling, which uses `save_to_file_confidential()` that explicitly sets mode 0600 (user-only access). [4](#0-3) 

**Exploitation Path:**
1. Validator operator runs `aptos key extract-public-key --private-key-file validator.key --output-file validator.pub` on a shared server
2. Public key file created with default umask (0644 = `-rw-r--r--`)
3. Local attacker (non-privileged user) runs `cat /home/validator/validator.pub.pub`
4. Attacker learns validator's public key and identity
5. Attacker uses this for targeted reconnaissance, social engineering, or identifying high-value targets

The same vulnerability exists in `save_key()` and `save_bls_key()` functions. [5](#0-4) 

## Impact Explanation
This is a **Low Severity** issue per Aptos bug bounty criteria (Minor information leak). While public keys are cryptographically meant to be public, exposing validator identities to local attackers on multi-user systems violates defense-in-depth principles. This does not directly compromise:
- Cryptographic security (cannot forge signatures)
- Consensus safety (no protocol violation)
- Funds (no financial loss)

However, it aids attacker reconnaissance by revealing which validators operate on specific infrastructure.

## Likelihood Explanation
**Moderate likelihood** in production environments:
- Validator operators often use shared infrastructure (cloud instances, bastion hosts)
- CLI key management is a common operational task
- Default umask is typically 0022, creating world-readable files
- No technical skill required to exploit (simple file read)

## Recommendation
Use restrictive file permissions (0600) for all key material, including public keys, to minimize information disclosure.

**Fix for `save_material()`:**
Replace `write_to_file()` with `write_to_user_only_file()` which sets mode 0600:

```rust
pub fn save_material<Key: ValidCryptoMaterial>(
    self,
    material: &Key,
    name: &'static str,
    extension: &'static str,
) -> CliTypedResult<(&'static str, PathBuf)> {
    let encoded_material = self.encoding_options.encoding.encode_key(name, material)?;
    let file = append_file_extension(self.file_options.output_file.as_path(), extension)?;
    write_to_user_only_file(&file, name, &encoded_material)?;  // Changed from write_to_file
    Ok((name, file))
}
```

Apply the same fix to `save_key()` (line 441) and `save_bls_key()` (lines 483, 484-488).

## Proof of Concept
```bash
# Setup: Create a test key extraction scenario
cd /tmp
mkdir -p test_permissions
cd test_permissions

# Generate a private key
aptos key generate --key-type ed25519 --output-file test.key --assume-yes

# Extract public key
aptos key extract-public-key --private-key-file test.key --output-file extracted --assume-yes

# Check permissions
ls -la extracted.pub
# Expected output with vulnerability: -rw-r--r-- (0644 - world readable)
# Expected output after fix: -rw------- (0600 - user only)

# Demonstrate local user can read (as different user)
su - otheruser -c "cat /tmp/test_permissions/extracted.pub"
# This succeeds with current code, should fail with proper permissions
```

**Notes:**
While this is a valid low-severity security issue, it represents a defense-in-depth weakness rather than a direct exploit. The codebase has a secure function (`write_to_user_only_file`) available but doesn't use it consistently for all cryptographic material.

### Citations

**File:** crates/aptos/src/op/key.rs (L438-447)
```rust
        let public_key_file = self.public_key_file()?;
        self.file_options
            .save_to_file_confidential(key_name, &encoded_private_key)?;
        write_to_file(&public_key_file, key_name, &encoded_public_key)?;

        let mut map = HashMap::new();
        map.insert("PrivateKey Path", self.file_options.output_file);
        map.insert("PublicKey Path", public_key_file);
        Ok(map)
    }
```

**File:** crates/aptos/src/op/key.rs (L449-460)
```rust
    /// Saves material to an enocded file
    pub fn save_material<Key: ValidCryptoMaterial>(
        self,
        material: &Key,
        name: &'static str,
        extension: &'static str,
    ) -> CliTypedResult<(&'static str, PathBuf)> {
        let encoded_material = self.encoding_options.encoding.encode_key(name, material)?;
        let file = append_file_extension(self.file_options.output_file.as_path(), extension)?;
        write_to_file(&file, name, &encoded_material)?;
        Ok((name, file))
    }
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
