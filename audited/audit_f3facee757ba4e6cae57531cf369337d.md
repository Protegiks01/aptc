# Audit Report

## Title
Resource Exhaustion via Unbounded File Reading in CLI Validator Operations

## Summary
The `read_from_file()` function in `aptos-core/crates/aptos/src/common/utils.rs` lacks file size validation before reading files into memory. This allows an operator to cause Out-of-Memory (OOM) crashes by providing paths to infinite special files (e.g., `/dev/zero`) or extremely large files during validator initialization and configuration operations.

## Finding Description

The vulnerable function directly calls `std::fs::read(path)` without any file size checks: [1](#0-0) 

This function is used in critical validator setup operations where file paths are user-controlled CLI arguments:

**1. Validator Initialization:** [2](#0-1) 

The `operator_config_file` is a user-provided `PathBuf` that gets passed directly to `read_from_file()` during the `InitializeValidator` command execution: [3](#0-2) 

**2. Genesis Configuration:** [4](#0-3) 

These identity file paths are also passed to `read_public_identity_file()` which uses `read_from_file()`: [5](#0-4) 

**3. Global Configuration Loading:** [6](#0-5) 

**Exploitation Path:**

When Rust's `std::fs::read()` encounters special files like `/dev/zero` or `/dev/urandom`, it uses `read_to_end()` which continuously reads until EOF. For character devices like `/dev/zero`, there is no EOF—they provide infinite streams of data. The implementation will:

1. Allocate an initial buffer
2. Continuously read and reallocate memory
3. Keep growing the buffer until the process exhausts available memory
4. Crash with OOM error

**Attack Scenario:**
```bash
# Attacker runs validator initialization with malicious file path
aptos node initialize-validator \
  --operator-config-file /dev/zero \
  --consensus-public-key <KEY> \
  --validator-host 0.0.0.0:6180
```

This causes the CLI process to consume all available memory and crash, disrupting validator setup operations.

## Impact Explanation

This vulnerability falls under **Medium Severity** per the Aptos bug bounty program for the following reasons:

1. **CLI Crash**: While classified as "API crashes" (High severity in the bounty program), this specifically affects the CLI tool rather than the validator node runtime or API endpoints. The CLI is a critical operational tool for validator setup.

2. **Operational Disruption**: Validator operators rely on the CLI for initialization, configuration updates, and key management. A crash during these operations could delay validator onboarding or prevent configuration updates during critical maintenance windows.

3. **Limited Scope**: The vulnerability does not:
   - Affect consensus or blockchain state
   - Impact running validator nodes  
   - Allow theft or manipulation of funds
   - Cause network-wide availability issues

4. **No Remote Exploitation**: This requires local execution of the CLI with attacker-controlled arguments, limiting the attack surface to scenarios where an operator is already compromised or makes a configuration error.

The impact aligns with Medium severity: operational tooling disruption requiring manual intervention to restart and reconfigure.

## Likelihood Explanation

**Likelihood: Low to Medium**

**Factors increasing likelihood:**
- Common CLI pattern where operators provide file paths as arguments
- Easy to accidentally reference wrong files (e.g., typos in paths)
- No validation or warning before attempting to read
- Special files like `/dev/zero` exist on all Linux systems used for validators

**Factors decreasing likelihood:**
- Requires local CLI access (not remotely exploitable)
- Operators typically use generated configuration files with known paths
- Most operational scenarios involve reading small YAML/JSON config files
- Experienced operators would notice unusual behavior before completing setup

**Realistic scenarios:**
1. **Accidental misconfiguration**: Operator typos a path or references the wrong device file
2. **Compromised operator environment**: If an attacker gains access to an operator's machine, they could intentionally crash the CLI as part of a broader attack
3. **Automated deployment bugs**: Scripts that generate file paths could produce incorrect special file paths

## Recommendation

**Add file size validation before reading files into memory:**

```rust
use std::fs;

pub fn read_from_file(path: &Path) -> CliTypedResult<Vec<u8>> {
    // Maximum file size: 10 MB for configuration files
    const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;
    
    // Get file metadata first
    let metadata = fs::metadata(path)
        .map_err(|e| CliError::UnableToReadFile(
            format!("{}", path.display()), 
            e.to_string()
        ))?;
    
    // Check if it's a regular file (not a device or special file)
    if !metadata.is_file() {
        return Err(CliError::UnableToReadFile(
            format!("{}", path.display()),
            "Path must point to a regular file, not a device or special file".to_string()
        ));
    }
    
    // Check file size
    let file_size = metadata.len();
    if file_size > MAX_FILE_SIZE {
        return Err(CliError::UnableToReadFile(
            format!("{}", path.display()),
            format!("File size ({} bytes) exceeds maximum allowed size ({} bytes)", 
                    file_size, MAX_FILE_SIZE)
        ));
    }
    
    // Safe to read now
    std::fs::read(path)
        .map_err(|e| CliError::UnableToReadFile(
            format!("{}", path.display()), 
            e.to_string()
        ))
}
```

**Additional recommendations:**
1. Document expected file size limits for each configuration file type
2. Add similar validation to other file-reading utilities in the codebase
3. Consider using streaming readers for larger files if needed in future
4. Add integration tests that verify rejection of special files

## Proof of Concept

**Shell reproduction steps:**

```bash
#!/bin/bash
# PoC: Demonstrate OOM crash via /dev/zero

# This will crash the CLI with OOM error
# WARNING: This will consume all available memory on the test system
# Run in a memory-limited container or VM

aptos node initialize-validator \
  --operator-config-file /dev/zero \
  --consensus-public-key 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef \
  --proof-of-possession 0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890 \
  --validator-network-public-key 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef \
  --validator-host 127.0.0.1:6180

# Expected result: Process killed due to OOM
# Actual result without fix: CLI crashes with memory allocation error
```

**Alternative PoC with large file:**

```bash
#!/bin/bash
# Create a 5GB file to trigger OOM on systems with less memory
dd if=/dev/zero of=/tmp/large_config.yaml bs=1M count=5120

aptos node initialize-validator \
  --operator-config-file /tmp/large_config.yaml \
  --consensus-public-key 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef \
  --proof-of-possession 0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890 \
  --validator-network-public-key 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef \
  --validator-host 127.0.0.1:6180

# Clean up
rm /tmp/large_config.yaml
```

## Notes

While this is a valid resource exhaustion vulnerability in the CLI tooling, its security impact is limited because:

1. It requires local execution access (not remotely exploitable)
2. It only affects the CLI process, not running validator nodes
3. Validator operators are considered trusted parties in the Aptos threat model

The vulnerability is best classified as a **robustness issue** that should be fixed to improve operational reliability, but it does not directly threaten consensus, funds, or network availability. The recommended fix adds defense-in-depth against both accidental misconfiguration and potential exploitation in compromised environments.

### Citations

**File:** crates/aptos/src/common/utils.rs (L213-216)
```rust
pub fn read_from_file(path: &Path) -> CliTypedResult<Vec<u8>> {
    std::fs::read(path)
        .map_err(|e| CliError::UnableToReadFile(format!("{}", path.display()), e.to_string()))
}
```

**File:** crates/aptos/src/node/mod.rs (L114-133)
```rust
#[derive(Parser)]
pub struct OperatorConfigFileArgs {
    /// Operator Configuration file
    ///
    /// Config file created from the `genesis set-validator-configuration` command
    #[clap(long, value_parser)]
    pub(crate) operator_config_file: Option<PathBuf>,
}

impl OperatorConfigFileArgs {
    fn load(&self) -> CliTypedResult<Option<OperatorConfiguration>> {
        if let Some(ref file) = self.operator_config_file {
            Ok(from_yaml(
                &String::from_utf8(read_from_file(file)?).map_err(CliError::from)?,
            )?)
        } else {
            Ok(None)
        }
    }
}
```

**File:** crates/aptos/src/node/mod.rs (L594-612)
```rust
pub struct InitializeValidator {
    #[clap(flatten)]
    pub(crate) txn_options: TransactionOptions,
    #[clap(flatten)]
    pub(crate) operator_config_file_args: OperatorConfigFileArgs,
    #[clap(flatten)]
    pub(crate) validator_consensus_key_args: ValidatorConsensusKeyArgs,
    #[clap(flatten)]
    pub(crate) validator_network_addresses_args: ValidatorNetworkAddressesArgs,
}

#[async_trait]
impl CliCommand<TransactionSummary> for InitializeValidator {
    fn command_name(&self) -> &'static str {
        "InitializeValidator"
    }

    async fn execute(mut self) -> CliTypedResult<TransactionSummary> {
        let operator_config = self.operator_config_file_args.load()?;
```

**File:** crates/aptos/src/genesis/keys.rs (L141-151)
```rust
    /// Path to private identity generated from GenerateKeys
    #[clap(long, value_parser)]
    pub(crate) owner_public_identity_file: Option<PathBuf>,

    /// Path to operator public identity, defaults to owner identity
    #[clap(long, value_parser)]
    pub(crate) operator_public_identity_file: Option<PathBuf>,

    /// Path to voter public identity, defaults to owner identity
    #[clap(long, value_parser)]
    pub(crate) voter_public_identity_file: Option<PathBuf>,
```

**File:** crates/aptos/src/genesis/keys.rs (L264-267)
```rust
pub fn read_public_identity_file(public_identity_file: &Path) -> CliTypedResult<PublicIdentity> {
    let bytes = read_from_file(public_identity_file)?;
    from_yaml(&String::from_utf8(bytes).map_err(CliError::from)?)
}
```

**File:** crates/aptos/src/config/mod.rs (L335-346)
```rust
    pub fn load() -> CliTypedResult<Self> {
        let path = global_folder()?.join(GLOBAL_CONFIG_FILE);
        if path.exists() {
            from_yaml(&String::from_utf8(read_from_file(path.as_path())?)?)
        } else {
            // If we don't have a config, let's load the default
            // Let's create the file if it doesn't exist
            let config = GlobalConfig::default();
            config.save()?;
            Ok(config)
        }
    }
```
