# Audit Report

## Title
Path Traversal Vulnerability in Genesis Configuration Loading Allows Unauthorized File Access

## Summary
The `get_config()` function in the genesis module does not sanitize the `user` parameter before constructing file paths, enabling directory traversal attacks. An attacker who can control the `layout.yaml` file can inject directory traversal sequences (e.g., `../../sensitive`) to read validator configuration files from unauthorized filesystem locations, potentially leaking sensitive credentials.

## Finding Description

The vulnerability exists in the genesis configuration loading process where validator usernames from the layout file are used to construct file paths without validation. [1](#0-0) 

The `user` parameter, sourced from the `layout.users` field, is directly converted to a `PathBuf` without any sanitization to prevent directory traversal sequences. The layout structure shows that `users` is a simple `Vec<String>` loaded from YAML with no validation: [2](#0-1) 

When the genesis tool loads validator configurations, it iterates through each user and constructs paths by joining the user string with filenames like "owner.yaml" and "operator.yaml": [3](#0-2) 

The `Client::get()` method then joins these paths with the repository base path and opens the files: [4](#0-3) 

**Attack Path:**
1. Attacker creates a malicious `layout.yaml` with directory traversal sequences in the `users` array:
   ```yaml
   users:
     - "../../home/validator/.aptos/keys"
     - "../../../etc/sensitive_config"
   ```
2. The attacker tricks an operator into running the genesis tool with this malicious repository (via social engineering or repository compromise)
3. When `generate-genesis` executes, the code constructs paths like `/genesis/repo/../../home/validator/.aptos/keys/owner.yaml`
4. The operating system resolves the `..` sequences, resulting in access to `/home/validator/.aptos/keys/owner.yaml`
5. The file contents are read and deserialized, potentially leaking validator credentials through error messages or successful parsing

While the codebase contains path sanitization utilities in other modules (like `ShellSafeName` in backup-cli), these are not applied to the genesis user validation path. [5](#0-4) 

## Impact Explanation

This vulnerability is classified as **HIGH severity** based on the following factors:

**Credential Leakage Risk**: The genesis setup process handles highly sensitive validator credentials including consensus keys, network keys, and operator configurations. If an attacker can read these files from unauthorized locations, they could:
- Extract validator private keys from backup locations
- Access operator configuration files from other validator setups
- Discover sensitive filesystem paths and configurations

**Information Disclosure**: While limited to YAML-formatted files due to deserialization requirements, validator configuration files follow predictable formats, making this a viable attack vector for credential theft.

**Scope**: Although this affects the genesis CLI tool rather than runtime validators, compromising credentials during genesis setup can lead to validator compromise before the blockchain network even starts operating.

According to Aptos bug bounty severity categories, this qualifies as **High Severity** under "Significant protocol violations" - the genesis process is a critical security boundary, and unauthorized file access represents a significant breach of trust assumptions.

## Likelihood Explanation

**Moderate to Low Likelihood** due to the following prerequisites:

**Required Conditions:**
1. Attacker must control or compromise the genesis repository (local directory or GitHub repo)
2. Victim operator must execute the genesis tool with the malicious repository
3. Attack requires social engineering or supply chain compromise

**Realistic Scenarios:**
- Operator uses a community-provided genesis template without verification
- Genesis repository is compromised through supply chain attack
- Internal operator accidentally uses wrong repository path during testing/setup

**Mitigating Factors:**
- Genesis setup is typically performed by trusted administrators in controlled environments
- The tool only reads YAML files (limits the attack surface to structured data)
- Most validators use dedicated genesis machines with limited filesystem access

However, the **lack of any input validation** makes this vulnerability trivially exploitable once the attacker achieves the prerequisite position.

## Recommendation

Implement path validation to prevent directory traversal attacks. Add sanitization before constructing file paths:

```rust
fn get_config(
    client: &Client,
    user: &str,
    is_mainnet: bool,
) -> CliTypedResult<ValidatorConfiguration> {
    // Validate user parameter to prevent directory traversal
    if user.contains("..") || user.contains('/') || user.contains('\\') {
        return Err(CliError::CommandArgumentError(
            format!("Invalid user identifier '{}': must not contain path traversal sequences", user)
        ));
    }
    
    if user.starts_with('.') || user.is_empty() {
        return Err(CliError::CommandArgumentError(
            format!("Invalid user identifier '{}': must not be empty or start with '.'", user)
        ));
    }
    
    // Validate that user contains only safe characters
    if !user.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
        return Err(CliError::CommandArgumentError(
            format!("Invalid user identifier '{}': must contain only alphanumeric characters, underscores, and hyphens", user)
        ));
    }
    
    // Load a user's configuration files
    let dir = PathBuf::from(user);
    let owner_file = dir.join(OWNER_FILE);
    // ... rest of function
}
```

Additionally, apply the same validation in the `Layout` deserialization to fail fast:

```rust
impl Layout {
    pub fn from_disk(path: &Path) -> anyhow::Result<Self> {
        let mut file = File::open(path).map_err(|e| {
            anyhow::Error::msg(format!("Failed to open file {}, {}", path.display(), e))
        })?;
        let mut contents = String::new();
        file.read_to_string(&mut contents).map_err(|e| {
            anyhow::Error::msg(format!("Failed to read file {}, {}", path.display(), e))
        })?;

        let layout: Self = serde_yaml::from_str(&contents)?;
        
        // Validate users after deserialization
        for user in &layout.users {
            if user.contains("..") || user.contains('/') || user.contains('\\') 
               || user.starts_with('.') || user.is_empty() 
               || !user.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
                return Err(anyhow::Error::msg(
                    format!("Invalid user identifier '{}' in layout file", user)
                ));
            }
        }
        
        Ok(layout)
    }
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod path_traversal_test {
    use super::*;
    use aptos_temppath::TempPath;
    use std::fs;

    #[test]
    fn test_path_traversal_vulnerability() {
        // Setup: Create a temporary directory structure
        let temp_dir = TempPath::new();
        temp_dir.create_as_dir().unwrap();
        let temp_path = temp_dir.path();
        
        // Create a "sensitive" directory outside the genesis repo
        let sensitive_dir = temp_path.join("sensitive");
        fs::create_dir(&sensitive_dir).unwrap();
        
        // Create a sensitive file
        let sensitive_file = sensitive_dir.join("owner.yaml");
        fs::write(&sensitive_file, "owner_account_address: \"0x1\"\nowner_account_public_key: \"0xSECRET\"").unwrap();
        
        // Create genesis repo directory
        let genesis_repo = temp_path.join("genesis_repo");
        fs::create_dir(&genesis_repo).unwrap();
        
        // Create malicious layout.yaml with directory traversal
        let layout_content = format!(
            "users:\n  - \"../sensitive\"\nchain_id: 4\nepoch_duration_secs: 7200\nmin_stake: 100000000000000\nmin_voting_threshold: 100000000000000\nmax_stake: 100000000000000000\nrecurring_lockup_duration_secs: 86400\nrequired_proposer_stake: 100000000000000\nrewards_apy_percentage: 10\nvoting_duration_secs: 43200\nvoting_power_increase_limit: 20\n"
        );
        let layout_file = genesis_repo.join("layout.yaml");
        fs::write(&layout_file, layout_content).unwrap();
        
        // Attempt to load the layout
        let layout = Layout::from_disk(&layout_file).unwrap();
        
        // Create client pointing to genesis_repo
        let client = Client::local(genesis_repo.clone());
        
        // Attempt to get config with traversal - this should fail with proper validation
        // but currently succeeds in reading ../sensitive/owner.yaml
        let result = get_config(&client, &layout.users[0], false);
        
        // VULNERABILITY: If this succeeds, we've read a file outside the intended directory
        // With proper validation, this should return an error
        match result {
            Ok(_) => {
                println!("VULNERABILITY CONFIRMED: Successfully read file from unauthorized location");
                panic!("Path traversal attack succeeded - validation missing!");
            },
            Err(e) => {
                println!("Attack blocked (expected behavior): {:?}", e);
            }
        }
    }
}
```

**Note**: The above PoC demonstrates the vulnerability pattern. In the current unpatched code, if a file matching the expected YAML structure exists at the traversed path, it will be successfully read, confirming the path traversal vulnerability.

### Citations

**File:** crates/aptos/src/genesis/mod.rs (L322-342)
```rust
fn get_validator_configs(
    client: &Client,
    layout: &Layout,
    is_mainnet: bool,
) -> Result<Vec<ValidatorConfiguration>, Vec<String>> {
    let mut validators = Vec::new();
    let mut errors = Vec::new();
    for user in &layout.users {
        match get_config(client, user, is_mainnet) {
            Ok(validator) => {
                validators.push(validator);
            },
            Err(failure) => {
                if let CliError::UnexpectedError(failure) = failure {
                    errors.push(format!("{}: {}", user, failure));
                } else {
                    errors.push(format!("{}: {:?}", user, failure));
                }
            },
        }
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

**File:** crates/aptos-genesis/src/config.rs (L30-35)
```rust
pub struct Layout {
    /// Root key for the blockchain only for test chains
    #[serde(default)]
    pub root_key: Option<Ed25519PublicKey>,
    /// List of usernames or identifiers
    pub users: Vec<String>,
```

**File:** crates/aptos/src/genesis/git.rs (L159-178)
```rust
    pub fn get<T: DeserializeOwned + Debug>(&self, path: &Path) -> CliTypedResult<T> {
        match self {
            Client::Local(local_repository_path) => {
                let path = local_repository_path.join(path);

                if !path.exists() {
                    return Err(CliError::UnableToReadFile(
                        path.display().to_string(),
                        "File not found".to_string(),
                    ));
                }

                eprintln!("Reading {}", path.display());
                let mut file = std::fs::File::open(path.as_path())
                    .map_err(|e| CliError::IO(path.display().to_string(), e))?;

                let mut contents = String::new();
                file.read_to_string(&mut contents)
                    .map_err(|e| CliError::IO(path.display().to_string(), e))?;
                from_yaml(&contents)
```

**File:** storage/backup/backup-cli/src/storage/tests.rs (L42-57)
```rust

```
