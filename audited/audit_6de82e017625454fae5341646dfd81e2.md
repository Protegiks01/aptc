# Audit Report

## Title
CLI Error Messages Disclose Internal File System Paths

## Summary
The `CliError` enum's `UnableToReadFile` and `IO` variants leak full file system paths in error messages when file operations fail, revealing internal directory structures, usernames, and organizational information to CLI users.

## Finding Description

The Aptos CLI error handling exposes complete file system paths when file read operations fail. This occurs in two primary locations: [1](#0-0) [2](#0-1) 

The `CliError::UnableToReadFile` variant includes the full path as the first string parameter: [3](#0-2) 

When users provide incorrect private key file paths or encounter permission errors, the error message displays:
```
"Unable to read file '/home/alice/.aptos/mainnet_private_key.txt', error: permission denied"
```

This occurs when:
1. Using `--private-key-file` with incorrect paths
2. Reading any configuration files from `~/.aptos/`
3. Loading keys via `encoding.load_key()` which is called for private key operations [4](#0-3) 

**Important Note:** The vulnerability does **NOT** leak:
- Private key values themselves (crypto library properly abstracts parsing errors)
- API key values directly
- Private key fragments from the `--private-key` argument (only from `--private-key-file`)

The cryptographic material remains secure: [5](#0-4) 

## Impact Explanation

Per the Aptos Bug Bounty severity categories, this qualifies as **Low Severity** (up to $1,000): "Minor information leaks."

**However, the security question classifies this as Medium severity, which appears to be a misclassification.**

The actual impact is limited to:
- **Reconnaissance information**: Attackers learn directory structures and usernames
- **No blockchain impact**: Zero effect on consensus, state, execution, or on-chain operations
- **No fund exposure**: Cannot be used to steal or manipulate assets
- **No invariant violations**: All 10 critical Aptos invariants remain intact

This is purely a CLI operational security issue with no impact on the blockchain layer.

## Likelihood Explanation

**High likelihood** of occurrence:
- Triggered by any file I/O error (wrong path, permissions, missing files)
- Users naturally encounter this during normal CLI operations
- No special privileges or attack setup required

**Low exploitability**:
- Only provides passive information, no active exploitation path
- Cannot be leveraged to attack blockchain consensus or state
- Requires user interaction (running CLI commands)

## Recommendation

Sanitize file paths in error messages by showing only the filename without directory structure:

```rust
// In crates/aptos-crypto/src/encoding_type.rs
pub fn read_from_file(path: &Path) -> Result<Vec<u8>, EncodingError> {
    std::fs::read(path)
        .map_err(|e| {
            let filename = path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("<file>");
            EncodingError::UnableToReadFile(
                format!("file '{}'", filename), 
                e.to_string()
            )
        })
}
```

This preserves debugging utility while preventing path disclosure.

## Proof of Concept

```bash
# Attempt to load a private key from a non-existent path
aptos init --private-key-file /home/testuser/.secret/keys/mainnet.key

# Expected output (current vulnerable behavior):
# Error: Unable to read file '/home/testuser/.secret/keys/mainnet.key', 
# error: No such file or directory (os error 2)

# Expected output (after fix):
# Error: Unable to read file 'mainnet.key', 
# error: No such file or directory (os error 2)
```

The current implementation reveals the complete path structure, while the recommended fix only shows the filename.

---

## Notes

**Critical Clarification**: While this is a valid information disclosure issue in the CLI tool, it:
1. Has **zero impact on blockchain security** (consensus, execution, state management)
2. Breaks **zero critical invariants** (all 10 Aptos invariants remain intact)
3. Qualifies as **Low severity** per the bug bounty program, not Medium
4. Is limited to CLI operational security, not protocol security

The issue exists but its classification as "Medium" in the security question appears incorrect based on the provided severity criteria. True Medium severity issues involve "Limited funds loss or manipulation" or "State inconsistencies requiring intervention," neither of which apply here.

### Citations

**File:** crates/aptos-crypto/src/encoding_type.rs (L104-105)
```rust
    std::fs::read(path)
        .map_err(|e| EncodingError::UnableToReadFile(format!("{}", path.display()), e.to_string()))
```

**File:** crates/aptos/src/common/utils.rs (L214-215)
```rust
    std::fs::read(path)
        .map_err(|e| CliError::UnableToReadFile(format!("{}", path.display()), e.to_string()))
```

**File:** crates/aptos/src/common/types.rs (L147-148)
```rust
    #[error("Unable to read file '{0}', error: {1}")]
    UnableToReadFile(String, String),
```

**File:** crates/aptos/src/common/types.rs (L734-737)
```rust
        if let Some(ref file) = private_key_file {
            Ok(Some(
                encoding.load_key("--private-key-file", file.as_path())?,
            ))
```

**File:** crates/aptos-crypto/src/traits/mod.rs (L85-98)
```rust
    fn from_encoded_string(encoded_str: &str) -> std::result::Result<Self, CryptoMaterialError> {
        let mut str = encoded_str;
        // First strip the AIP-80 prefix
        str = str.strip_prefix(Self::AIP_80_PREFIX).unwrap_or(str);

        // Strip 0x at beginning if there is one
        str = str.strip_prefix("0x").unwrap_or(str);

        let bytes_out = ::hex::decode(str);
        // We defer to `try_from` to make sure we only produce valid crypto materials.
        bytes_out
            // We reinterpret a failure to serialize: key is mangled someway.
            .or(Err(CryptoMaterialError::DeserializationError))
            .and_then(|ref bytes| Self::try_from(bytes))
```
