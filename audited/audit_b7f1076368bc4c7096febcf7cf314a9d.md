# Audit Report

## Title
Path Traversal Vulnerability in Genesis Validator Configuration via Unsanitized Username Field

## Summary
The `SetValidatorConfiguration` command in the genesis setup process does not sanitize the `username` field before using it to construct file paths, allowing path traversal attacks that can write validator configuration files to arbitrary locations on the file system.

## Finding Description

The `username` field in `SetValidatorConfiguration` is used directly to construct file paths without any sanitization for path traversal sequences (`../`), absolute paths, control characters, or null bytes. [1](#0-0) 

The username is converted to a PathBuf and joined with operator/owner filenames, then written to disk via the git client. An attacker who can influence the username parameter (e.g., through compromised input files, social engineering of operators, or automated systems) can write files outside the intended genesis directory structure. [2](#0-1) 

For local repositories, the path joining operation does not prevent directory traversal, allowing writes to arbitrary file system locations.

The same vulnerability exists in the genesis reading path where usernames from the layout file are used to construct paths: [3](#0-2) 

Regarding `validator_host` and `full_node_host`: These fields use the `HostAndPort` type containing `DnsName`. The DnsName validation only checks for ASCII validity but does NOT reject control characters (including null bytes): [4](#0-3) 

The `is_ascii()` check at line 674 allows all ASCII characters including control characters (0x00-0x1F, 0x7F). However, these fields are not directly used in file path construction, limiting their exploitability to other contexts (DNS resolution, logging, network operations).

## Impact Explanation

This issue represents a **High Severity** vulnerability per Aptos bug bounty criteria as it can lead to:

1. **Arbitrary file write** on validator operator systems during genesis setup
2. **Configuration file corruption** by overwriting critical system files
3. **Potential code execution** if attackers overwrite executables or scripts
4. **Genesis process compromise** affecting the entire validator set initialization

While this occurs during genesis setup rather than normal validator operation, compromise at this stage could affect the entire blockchain's security foundation.

## Likelihood Explanation

**Medium Likelihood** - While this requires genesis operator access (trusted role), the attack surface includes:

1. **Automated genesis tools** that might process untrusted input files
2. **Social engineering** of operators to use malicious usernames
3. **Compromised configuration sources** (YAML files, databases, APIs)
4. **Supply chain attacks** on genesis automation scripts
5. **Insider threats** from disgruntled or compromised operators

Defense-in-depth principles require input sanitization even for trusted inputs, as operators can make mistakes or be compromised.

## Recommendation

Implement strict username validation before using it in file paths:

```rust
fn validate_username(username: &str) -> CliTypedResult<()> {
    // Reject empty usernames
    if username.is_empty() {
        return Err(CliError::CommandArgumentError("Username cannot be empty".to_string()));
    }
    
    // Reject path traversal sequences
    if username.contains("..") || username.contains('/') || username.contains('\\') {
        return Err(CliError::CommandArgumentError(
            "Username cannot contain path separators or traversal sequences".to_string()
        ));
    }
    
    // Reject absolute paths (Unix and Windows)
    if username.starts_with('/') || username.contains(':') {
        return Err(CliError::CommandArgumentError(
            "Username cannot be an absolute path".to_string()
        ));
    }
    
    // Reject control characters and null bytes
    if username.chars().any(|c| c.is_control() || c == '\0') {
        return Err(CliError::CommandArgumentError(
            "Username cannot contain control characters or null bytes".to_string()
        ));
    }
    
    // Restrict to alphanumeric, dash, and underscore
    if !username.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        return Err(CliError::CommandArgumentError(
            "Username must contain only alphanumeric characters, dashes, and underscores".to_string()
        ));
    }
    
    Ok(())
}
```

Apply this validation in `SetValidatorConfiguration::execute()` before line 254.

For DnsName control characters, enhance validation:

```rust
fn validate(s: &str) -> Result<(), ParseError> {
    if s.is_empty() {
        Err(ParseError::EmptyDnsNameString)
    } else if s.len() > MAX_DNS_NAME_SIZE {
        Err(ParseError::DnsNameTooLong(s.len()))
    } else if s.contains('/') {
        Err(ParseError::InvalidDnsNameCharacter)
    } else if !s.is_ascii() {
        Err(ParseError::DnsNameNonASCII(s.into()))
    } else if s.chars().any(|c| c.is_control()) {
        Err(ParseError::DnsNameContainsControlCharacters)
    } else {
        Ok(())
    }
}
```

## Proof of Concept

```rust
// Test demonstrating path traversal via username
#[tokio::test]
async fn test_path_traversal_in_username() {
    use std::fs;
    use tempfile::TempDir;
    
    // Create temporary directories
    let temp_genesis = TempDir::new().unwrap();
    let temp_target = TempDir::new().unwrap();
    
    // Calculate relative path from genesis dir to target dir
    let traversal_username = format!("../../../{}/malicious", 
        temp_target.path().file_name().unwrap().to_str().unwrap());
    
    // Generate keys
    let keys_dir = temp_genesis.path().join("keys");
    fs::create_dir_all(&keys_dir).unwrap();
    
    let generate_keys = GenerateKeys {
        output_dir: Some(keys_dir.clone()),
        pool_address_args: OptionalPoolAddressArgs { pool_address: None },
        prompt_options: PromptOptions::yes(),
        rng_args: RngArgs::from_string_seed("test"),
    };
    generate_keys.execute().await.unwrap();
    
    // Attempt SetValidatorConfiguration with malicious username
    let git_options = GitOptions {
        local_repository_dir: Some(temp_genesis.path().to_path_buf()),
        github_repository: None,
        github_branch: "main".to_string(),
        github_token_file: None,
    };
    
    let cmd = SetValidatorConfiguration {
        username: traversal_username.clone(),
        git_options,
        owner_public_identity_file: Some(keys_dir.join("public-keys.yaml")),
        operator_public_identity_file: None,
        voter_public_identity_file: None,
        validator_host: HostAndPort::from_str("localhost:6180").unwrap(),
        full_node_host: None,
        stake_amount: 100_000_000_000_000,
        commission_percentage: 0,
        join_during_genesis: true,
    };
    
    // Execute - this should write files outside genesis directory
    cmd.execute().await.unwrap();
    
    // Verify files were written outside the intended directory
    let malicious_path = temp_genesis.path()
        .join(&traversal_username)
        .join("operator.yaml");
    
    assert!(malicious_path.exists(), 
        "Path traversal successful - file written outside genesis directory");
}
```

**Notes:**
- The primary vulnerability is the unsanitized `username` field allowing path traversal during genesis validator configuration setup
- The `validator_host` and `full_node_host` fields accept control characters through DnsName but are not used in file paths, limiting their direct exploitability
- This vulnerability affects the integrity of the genesis setup process, which is foundational to the entire blockchain's security
- While genesis operators are considered trusted, defense-in-depth requires input sanitization to protect against mistakes, social engineering, or compromised input sources

### Citations

**File:** crates/aptos/src/genesis/keys.rs (L254-260)
```rust
        let directory = PathBuf::from(&self.username);
        let operator_file = directory.join(OPERATOR_FILE);
        let owner_file = directory.join(OWNER_FILE);

        let git_client = self.git_options.get_client()?;
        git_client.put(operator_file.as_path(), &operator_config)?;
        git_client.put(owner_file.as_path(), &owner_config)
```

**File:** crates/aptos/src/genesis/git.rs (L187-213)
```rust
    pub fn put<T: Serialize + ?Sized>(&self, name: &Path, input: &T) -> CliTypedResult<()> {
        match self {
            Client::Local(local_repository_path) => {
                let path = local_repository_path.join(name);

                // Create repository path and any sub-directories
                if let Some(dir) = path.parent() {
                    self.create_dir(dir)?;
                } else {
                    return Err(CliError::UnexpectedError(format!(
                        "Path should always have a parent {}",
                        path.display()
                    )));
                }
                write_to_file(
                    path.as_path(),
                    &path.display().to_string(),
                    to_yaml(input)?.as_bytes(),
                )?;
            },
            Client::Github(client) => {
                client.put(&name.display().to_string(), &to_base64_encoded_yaml(input)?)?;
            },
        }

        Ok(())
    }
```

**File:** crates/aptos/src/genesis/mod.rs (L352-361)
```rust
fn get_config(
    client: &Client,
    user: &str,
    is_mainnet: bool,
) -> CliTypedResult<ValidatorConfiguration> {
    // Load a user's configuration files
    let dir = PathBuf::from(user);
    let owner_file = dir.join(OWNER_FILE);
    let owner_file = owner_file.as_path();
    let owner_config = client.get::<StringOwnerConfiguration>(owner_file)?;
```

**File:** types/src/network_address/mod.rs (L667-679)
```rust
    fn validate(s: &str) -> Result<(), ParseError> {
        if s.is_empty() {
            Err(ParseError::EmptyDnsNameString)
        } else if s.len() > MAX_DNS_NAME_SIZE {
            Err(ParseError::DnsNameTooLong(s.len()))
        } else if s.contains('/') {
            Err(ParseError::InvalidDnsNameCharacter)
        } else if !s.is_ascii() {
            Err(ParseError::DnsNameNonASCII(s.into()))
        } else {
            Ok(())
        }
    }
```
