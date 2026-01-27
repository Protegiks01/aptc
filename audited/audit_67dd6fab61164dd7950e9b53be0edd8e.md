# Audit Report

## Title
Information Disclosure via Unsanitized Error Messages in Rosetta CLI ErrorWrapper

## Summary
The `ErrorWrapper` struct in the Aptos Rosetta CLI does not sanitize error messages before serialization, leading to exposure of sensitive information including file paths, configuration details, and internal system structure through error outputs.

## Finding Description

The vulnerability exists in how the Aptos Rosetta CLI handles and displays errors to users. When an error occurs during CLI execution, the error is converted to a string and wrapped in an `ErrorWrapper` struct without any sanitization. [1](#0-0) 

The `ErrorWrapper` struct itself is a simple wrapper that directly serializes the error string: [2](#0-1) 

When users attempt operations that involve file system access (such as loading private keys), any errors that occur will include the full file paths in the error messages. This happens because the underlying error handling includes file paths: [3](#0-2) 

The `CliError::UnableToReadFile` variant explicitly includes the file path in its error message: [4](#0-3) 

Similarly, the crypto encoding layer also leaks file paths: [5](#0-4) 

**Attack Scenario:**
1. Attacker runs a Rosetta CLI command with an invalid `--private-key-file` path
2. The CLI attempts to read the file and fails
3. The error propagates up with the full file path embedded
4. The error is serialized to JSON via `ErrorWrapper` and printed to stdout
5. If the CLI output is logged or displayed, the file path is exposed
6. Attacker learns internal directory structure, configuration paths, and file naming conventions

## Impact Explanation

While the security question is marked as "(Medium)", according to the Aptos Bug Bounty severity criteria provided, this vulnerability falls under **Low Severity** (up to $1,000): "Minor information leaks."

This is an information disclosure vulnerability that does not directly lead to:
- Loss of funds
- Consensus violations
- Node availability issues
- State inconsistencies

However, it can aid attackers in reconnaissance by revealing:
- Internal file system structure
- Configuration file locations
- Private key storage paths
- System architecture details

The exposed information could facilitate further attacks or social engineering attempts.

## Likelihood Explanation

The likelihood is **HIGH** because:
- Any CLI user can trigger this by providing invalid file paths
- No special privileges or insider access is required
- The vulnerability affects all error paths involving file operations
- CLI tools are commonly used in scripted environments where errors may be logged

The vulnerability will manifest whenever:
- A user provides an invalid `--private-key-file` path
- File permissions prevent reading configuration files
- Network requests fail with URL details in error messages
- Any I/O operation encounters an error

## Recommendation

Implement error sanitization before wrapping errors in `ErrorWrapper`. Create a sanitization function that:

1. Strips file paths to show only relative paths or generic descriptions
2. Removes URL query parameters and credentials
3. Redacts any potential API keys or tokens
4. Provides user-friendly error messages without internal details

**Suggested Fix:**

```rust
// In crates/aptos-rosetta-cli/src/common.rs
impl ErrorWrapper {
    pub fn from_error(error: anyhow::Error) -> Self {
        ErrorWrapper {
            error: Self::sanitize_error_message(error.to_string()),
        }
    }
    
    fn sanitize_error_message(msg: String) -> String {
        // Redact file paths - show only filename
        let msg = Self::redact_file_paths(msg);
        // Redact URLs - remove query parameters and credentials
        let msg = Self::redact_urls(msg);
        msg
    }
    
    fn redact_file_paths(msg: String) -> String {
        // Replace full paths with just filenames
        // Pattern: /path/to/file.ext -> <file.ext>
        // Implementation needed based on path format
        msg
    }
    
    fn redact_urls(msg: String) -> String {
        // Remove credentials and sensitive query parameters from URLs
        msg
    }
}

// In crates/aptos-rosetta-cli/src/main.rs
Err(error) => {
    let error = ErrorWrapper::from_error(error);
    println!("{}", serde_json::to_string_pretty(&error).unwrap());
    exit(-1)
}
```

## Proof of Concept

```bash
# Run the Rosetta CLI with a non-existent private key file
# This will leak the full file path in the error output

aptos-rosetta-cli construction transfer \
  --rosetta-api-url http://localhost:8082 \
  --chain-id TESTNET \
  --private-key-file /home/user/.aptos/config/sensitive-keys/validator-private.key \
  --receiver 0x123 \
  --amount 1000 \
  --currency '{"symbol":"APT","decimals":8}'

# Expected output (vulnerable version):
# {
#   "error": "Unable to read file '/home/user/.aptos/config/sensitive-keys/validator-private.key', error: No such file or directory (os error 2)"
# }

# This reveals:
# 1. Full directory structure
# 2. Key file naming conventions
# 3. User home directory path
# 4. Configuration directory layout
```

The attacker can now use this information to:
- Target specific file paths in further attacks
- Understand the system's configuration structure
- Craft more sophisticated social engineering attacks
- Know where sensitive files are expected to be located

---

## Notes

This is a **Low Severity** information disclosure issue in the Rosetta CLI tool (not the core blockchain node). While file paths should be sanitized for security best practices, this does not impact consensus, validator operations, or on-chain state. The vulnerability is limited to CLI users and would primarily assist in reconnaissance for more sophisticated attacks.

### Citations

**File:** crates/aptos-rosetta-cli/src/main.rs (L43-46)
```rust
        Err(error) => {
            let error = ErrorWrapper {
                error: error.to_string(),
            };
```

**File:** crates/aptos-rosetta-cli/src/common.rs (L80-83)
```rust
#[derive(Serialize)]
pub struct ErrorWrapper {
    pub error: String,
}
```

**File:** crates/aptos/src/common/utils.rs (L213-216)
```rust
pub fn read_from_file(path: &Path) -> CliTypedResult<Vec<u8>> {
    std::fs::read(path)
        .map_err(|e| CliError::UnableToReadFile(format!("{}", path.display()), e.to_string()))
}
```

**File:** crates/aptos/src/common/types.rs (L147-148)
```rust
    #[error("Unable to read file '{0}', error: {1}")]
    UnableToReadFile(String, String),
```

**File:** crates/aptos-crypto/src/encoding_type.rs (L103-106)
```rust
pub fn read_from_file(path: &Path) -> Result<Vec<u8>, EncodingError> {
    std::fs::read(path)
        .map_err(|e| EncodingError::UnableToReadFile(format!("{}", path.display()), e.to_string()))
}
```
