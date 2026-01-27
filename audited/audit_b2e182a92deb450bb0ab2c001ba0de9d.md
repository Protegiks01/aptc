# Audit Report

## Title
Resource Exhaustion via Unbounded File Read in CLI Utilities Causes OOM Crash During Validator Operations

## Summary
The `read_from_file()` function in the Aptos CLI lacks file size validation before reading files into memory. An operator can trigger an Out-of-Memory (OOM) crash by providing a path to infinite-size special files (e.g., `/dev/zero`, `/dev/random`) during critical validator setup operations, causing denial of service.

## Finding Description

The vulnerability exists in two locations where files are read without size checks: [1](#0-0) [2](#0-1) 

Both functions directly call `std::fs::read(path)`, which attempts to read the entire file into memory without any size validation. This breaks the **Resource Limits** invariant (#9), which states "All operations must respect gas, storage, and computational limits."

**Attack Flow:**

1. The `read_from_file()` function is called from multiple validator operation commands that accept user-provided file paths via CLI arguments: [3](#0-2) [4](#0-3) 

2. During validator initialization, the operator configuration file is loaded: [5](#0-4) 

3. If an attacker (or misconfigured automation) provides a path like `/dev/zero`, the `std::fs::read()` call attempts to allocate unbounded memory until the process crashes with OOM.

4. Similar vulnerabilities exist in:
   - Genesis key loading operations [6](#0-5) 
   - Configuration file loading [7](#0-6) 
   - Cryptographic key loading [8](#0-7) 

**Contrast with Other File Operations:**

The codebase demonstrates awareness of size validation in other contexts. For example, the compression module validates sizes before operations, and the binary deserializer uses maximum size constraints. However, the CLI utility functions lack these protections.

## Impact Explanation

**Severity: Medium** (up to $10,000 per Aptos Bug Bounty)

This vulnerability causes **availability disruption** of validator operations:

- **Crashes the Aptos CLI** during critical validator setup operations (`aptos node initialize-validator`)
- **Disrupts automation scripts** that use the CLI for validator management
- **Prevents completion** of genesis operations and key management tasks
- **Does NOT directly affect** the running validator node itself (only the CLI tool)
- **Does NOT compromise** consensus, funds, or network security directly

The impact is limited because it affects the CLI tool rather than core validator node operations. However, it can prevent validators from joining the network or updating their configuration, which indirectly affects network participation.

## Likelihood Explanation

**Likelihood: Medium to High**

The vulnerability can be triggered through:

1. **Accidental triggers**: 
   - Typos in file paths (e.g., `/dev/config.yaml` instead of `./dev/config.yaml`)
   - Symlinks inadvertently pointing to special files
   - Misconfigured automation scripts

2. **Intentional exploitation**:
   - Malicious insider with CLI access
   - Compromised validator operator machine
   - Social engineering attacks targeting operators

**Attacker Requirements:**
- Local access to run Aptos CLI commands
- Ability to specify file paths (via command-line arguments)
- No special privileges beyond normal CLI usage

The attack is trivial to execute once CLI access is obtained, requiring only a single malformed file path argument.

## Recommendation

Implement file size validation before reading files into memory. Add a configurable maximum file size with a reasonable default (e.g., 10-50 MB for config files, 1 MB for key files).

**Recommended Fix:**

```rust
// In crates/aptos/src/common/utils.rs
pub fn read_from_file(path: &Path) -> CliTypedResult<Vec<u8>> {
    const MAX_FILE_SIZE: u64 = 50 * 1024 * 1024; // 50 MB
    
    let metadata = std::fs::metadata(path)
        .map_err(|e| CliError::UnableToReadFile(format!("{}", path.display()), e.to_string()))?;
    
    // Check if it's a regular file and validate size
    if !metadata.is_file() {
        return Err(CliError::UnableToReadFile(
            format!("{}", path.display()),
            "Not a regular file".to_string()
        ));
    }
    
    if metadata.len() > MAX_FILE_SIZE {
        return Err(CliError::UnableToReadFile(
            format!("{}", path.display()),
            format!("File too large: {} bytes (max: {} bytes)", metadata.len(), MAX_FILE_SIZE)
        ));
    }
    
    std::fs::read(path)
        .map_err(|e| CliError::UnableToReadFile(format!("{}", path.display()), e.to_string()))
}
```

Apply the same fix to `crates/aptos-crypto/src/encoding_type.rs`.

## Proof of Concept

**Bash Reproduction:**

```bash
#!/bin/bash
# PoC: Trigger OOM crash in Aptos CLI via infinite file read

# Create a test validator configuration
# This will crash when trying to read /dev/zero
aptos node initialize-validator \
  --operator-config-file /dev/zero \
  --assume-yes

# Expected result: Process crashes with OOM error
# Actual behavior: CLI attempts to allocate unlimited memory until kernel kills it

# Alternative PoC with /dev/urandom (also infinite)
aptos node initialize-validator \
  --operator-config-file /dev/urandom \
  --assume-yes

# Also affects key loading operations
aptos key generate \
  --output-file /tmp/test.key

# Symlink attack
ln -s /dev/zero /tmp/malicious-config.yaml
aptos node initialize-validator \
  --operator-config-file /tmp/malicious-config.yaml \
  --assume-yes
```

**Expected Outcome:**
The CLI process will allocate memory indefinitely until the operating system kills it with an OOM error, preventing the command from completing.

**Note**: The codebase shows proper size validation patterns in other modules (compression, binary deserialization, network framing), indicating this is an oversight rather than a design decision.

### Citations

**File:** crates/aptos/src/common/utils.rs (L213-216)
```rust
pub fn read_from_file(path: &Path) -> CliTypedResult<Vec<u8>> {
    std::fs::read(path)
        .map_err(|e| CliError::UnableToReadFile(format!("{}", path.display()), e.to_string()))
}
```

**File:** crates/aptos-crypto/src/encoding_type.rs (L70-70)
```rust
        self.decode_key(name, read_from_file(path)?)
```

**File:** crates/aptos-crypto/src/encoding_type.rs (L103-106)
```rust
pub fn read_from_file(path: &Path) -> Result<Vec<u8>, EncodingError> {
    std::fs::read(path)
        .map_err(|e| EncodingError::UnableToReadFile(format!("{}", path.display()), e.to_string()))
}
```

**File:** crates/aptos/src/node/mod.rs (L119-120)
```rust
    #[clap(long, value_parser)]
    pub(crate) operator_config_file: Option<PathBuf>,
```

**File:** crates/aptos/src/node/mod.rs (L124-128)
```rust
    fn load(&self) -> CliTypedResult<Option<OperatorConfiguration>> {
        if let Some(ref file) = self.operator_config_file {
            Ok(from_yaml(
                &String::from_utf8(read_from_file(file)?).map_err(CliError::from)?,
            )?)
```

**File:** crates/aptos/src/node/mod.rs (L612-612)
```rust
        let operator_config = self.operator_config_file_args.load()?;
```

**File:** crates/aptos/src/genesis/keys.rs (L265-265)
```rust
    let bytes = read_from_file(public_identity_file)?;
```

**File:** crates/aptos/src/config/mod.rs (L338-338)
```rust
            from_yaml(&String::from_utf8(read_from_file(path.as_path())?)?)
```
