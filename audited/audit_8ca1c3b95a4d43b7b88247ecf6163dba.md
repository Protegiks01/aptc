# Audit Report

## Title
Path Traversal Vulnerability in Genesis Configuration Reader Allows Arbitrary File Read

## Summary
The `Client::get()` function in the genesis git client does not validate or canonicalize file paths, allowing path traversal sequences in the `layout.yaml` configuration to read arbitrary files on the operator's filesystem during genesis setup.

## Finding Description

The vulnerability exists in the genesis configuration loading mechanism. The code flow is:

1. Genesis setup reads `layout.yaml` containing a list of validator usernames in the `users` field [1](#0-0) 

2. For each user, the code constructs a path by joining the username with configuration file names [2](#0-1) 

3. This path is passed to `Client::get()` which performs an unsanitized join with the local repository path [3](#0-2) 

4. The resulting path is opened directly without canonicalization or validation [4](#0-3) 

**Attack Vector**: An attacker who can influence the `layout.yaml` file (through compromised GitHub repository, malicious testnet template, or social engineering) can inject path traversal sequences like `"../../etc"` into the `users` array. When genesis generation runs, the code will:
- Construct path: `PathBuf::from("../../etc").join("owner.yaml")` → `"../../etc/owner.yaml"`
- Join with repository: `/tmp/genesis/../../etc/owner.yaml` → `/etc/owner.yaml`
- Read the file if it exists and is valid YAML

Since `StringOwnerConfiguration` has all `Option<String>` fields, even an empty YAML file `{}` satisfies the deserialization constraint [5](#0-4) 

Rust's `PathBuf::join()` does NOT canonicalize paths or prevent `..` sequences - these are resolved by the OS during file operations, enabling directory traversal.

## Impact Explanation

**Severity: Low** (per Aptos Bug Bounty criteria)

This vulnerability allows **information disclosure** through arbitrary file read on the genesis operator's machine. While this could potentially leak sensitive files (private keys, configuration files), the impact is classified as Low severity because:

1. **Out of Protocol Scope**: This affects the genesis setup CLI tool, not the running blockchain protocol or validator nodes
2. **Requires Trusted Input Compromise**: The attacker must control or influence the `layout.yaml` file, which is typically a trusted configuration managed by the genesis operator
3. **No Direct Chain Impact**: Does not cause consensus violations, fund loss, network partition, or other Critical/High severity impacts on the blockchain itself
4. **Listed Exclusion**: Key theft and social engineering are explicitly out of scope per the bug bounty rules

Per Aptos bug bounty: "Minor information leaks" are categorized as Low Severity (up to $1,000).

## Likelihood Explanation

**Likelihood: Low**

The attack requires:
1. Attacker gaining control over genesis configuration files (GitHub repository compromise, malicious template distribution, or insider threat)
2. Genesis operator using the compromised configuration without verification
3. Target files being readable by the genesis process and valid YAML format

Since genesis operators are considered trusted actors in the threat model, and the configuration source is typically controlled, the likelihood is low under normal operational security.

## Recommendation

Implement path validation and canonicalization in the `Client::get()` function:

```rust
pub fn get<T: DeserializeOwned + Debug>(&self, path: &Path) -> CliTypedResult<T> {
    match self {
        Client::Local(local_repository_path) => {
            // Validate path doesn't contain traversal sequences
            if path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
                return Err(CliError::CommandArgumentError(
                    format!("Path traversal not allowed: {}", path.display())
                ));
            }
            
            let full_path = local_repository_path.join(path);
            
            // Canonicalize and verify it's within the repository
            let canonical_path = full_path.canonicalize()
                .map_err(|e| CliError::IO(full_path.display().to_string(), e))?;
            let canonical_repo = local_repository_path.canonicalize()
                .map_err(|e| CliError::IO(local_repository_path.display().to_string(), e))?;
            
            if !canonical_path.starts_with(&canonical_repo) {
                return Err(CliError::CommandArgumentError(
                    format!("Path outside repository: {}", path.display())
                ));
            }
            
            // Continue with existing logic...
```

Apply similar validation to `Client::put()` and `create_dir()` functions.

## Proof of Concept

```bash
# 1. Create a malicious layout.yaml
cat > /tmp/genesis/layout.yaml << EOF
root_key: "D04470F43AB6AEAA4EB616B72128881EEF77346F2075FFE68E14BA7DEBD8095E"
users: 
  - "../../etc"
chain_id: 4
allow_new_validators: false
epoch_duration_secs: 7200
is_test: true
min_stake: 100000000000000
min_voting_threshold: 100000000000000
max_stake: 100000000000000000
recurring_lockup_duration_secs: 86400
required_proposer_stake: 1000000
rewards_apy_percentage: 10
voting_duration_secs: 43200
voting_power_increase_limit: 20
EOF

# 2. Create a readable YAML file in /etc (for demonstration)
# In practice, the attacker would target existing readable files like /etc/passwd
echo "{}" | sudo tee /etc/owner.yaml

# 3. Run genesis generation
aptos genesis generate-genesis \
    --local-repository-dir /tmp/genesis \
    --output-dir /tmp/output

# Expected: The tool reads /etc/owner.yaml instead of /tmp/genesis/../../etc/owner.yaml
# Actual: Path traversal occurs, file outside intended directory is read
```

**Note**: This vulnerability does not meet the Critical, High, or Medium severity thresholds required for bug bounty submission per the validation checklist, as it constitutes a "minor information leak" (Low severity) affecting only the genesis setup process, not the blockchain protocol itself.

### Citations

**File:** crates/aptos-genesis/src/config.rs (L34-35)
```rust
    /// List of usernames or identifiers
    pub users: Vec<String>,
```

**File:** crates/aptos-genesis/src/config.rs (L374-384)
```rust
pub struct StringOwnerConfiguration {
    pub owner_account_address: Option<String>,
    pub owner_account_public_key: Option<String>,
    pub voter_account_address: Option<String>,
    pub voter_account_public_key: Option<String>,
    pub operator_account_address: Option<String>,
    pub operator_account_public_key: Option<String>,
    pub stake_amount: Option<String>,
    pub commission_percentage: Option<String>,
    pub join_during_genesis: Option<String>,
}
```

**File:** crates/aptos/src/genesis/mod.rs (L358-361)
```rust
    let dir = PathBuf::from(user);
    let owner_file = dir.join(OWNER_FILE);
    let owner_file = owner_file.as_path();
    let owner_config = client.get::<StringOwnerConfiguration>(owner_file)?;
```

**File:** crates/aptos/src/genesis/git.rs (L161-162)
```rust
            Client::Local(local_repository_path) => {
                let path = local_repository_path.join(path);
```

**File:** crates/aptos/src/genesis/git.rs (L172-173)
```rust
                let mut file = std::fs::File::open(path.as_path())
                    .map_err(|e| CliError::IO(path.display().to_string(), e))?;
```
