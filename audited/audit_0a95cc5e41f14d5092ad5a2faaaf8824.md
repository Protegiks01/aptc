# Audit Report

## Title
Path Traversal Vulnerability in Genesis CLI Allows Arbitrary File System Writes

## Summary
The `Client::create_dir()` and `Client::put()` functions in the genesis CLI tool do not validate or sanitize user-provided path components, allowing path traversal sequences (e.g., `../`) to escape the intended `local_repository_path` directory. This enables arbitrary directory creation and file writes on the host filesystem where the CLI user has permissions.

## Finding Description

The vulnerability exists in the genesis configuration setup workflow. When a user executes `aptos genesis set-validator-configuration` with a malicious `--username` parameter containing path traversal sequences, the system fails to validate or normalize the path before using it for filesystem operations.

**Attack Flow:**

1. The `SetValidatorConfiguration` command accepts a user-controlled `username` parameter [1](#0-0) 

2. This username is directly used to construct directory paths [2](#0-1) 

3. The constructed paths are passed to `Client::put()` which joins them with `local_repository_path` without validation [3](#0-2) 

4. The `create_dir()` function is called with the parent directory, again without path validation [4](#0-3) 

5. In `create_dir()`, the path is joined and passed directly to `create_dir_if_not_exist()` [5](#0-4) 

6. The underlying `std::fs::create_dir_all()` resolves the `..` components, creating directories outside the intended path [6](#0-5) 

7. Files containing validator configuration are then written to the traversed path [7](#0-6) 

**Example Attack:**
```bash
aptos genesis set-validator-configuration \
  --username "../../tmp/malicious" \
  --local-repository-dir /home/user/genesis \
  --validator-host 127.0.0.1:6180 \
  --stake-amount 1000000
```

This would create directories and write files to `/tmp/malicious/` instead of `/home/user/genesis/../../tmp/malicious/`.

## Impact Explanation

This vulnerability allows an attacker to:
- Create arbitrary directories on the filesystem where the CLI user has write permissions
- Write validator configuration files (operator.yaml, owner.yaml) to arbitrary locations
- Potentially overwrite existing configuration files or inject malicious configurations

**Severity: Medium** - This assessment aligns with the classification in the security question. While this is a serious local filesystem security issue, it:
- Does NOT directly affect blockchain consensus, state management, or runtime validator operations
- Requires local access to execute the genesis CLI tool
- Is limited to the permissions of the user running the command
- Affects the genesis setup phase, not the operational blockchain network
- Does not lead to loss of funds or consensus violations

The impact fits the Medium severity category: "State inconsistencies requiring intervention" - in this case, filesystem state inconsistencies that could disrupt genesis setup processes.

## Likelihood Explanation

**Likelihood: Medium to High**

This vulnerability is highly likely to occur in scenarios where:
- Network operators follow compromised tutorials or scripts during genesis setup
- Social engineering attacks trick operators into using malicious usernames
- Automated genesis setup tools accept external input without validation
- Multiple parties coordinate genesis setup with untrusted inputs

The genesis CLI is a critical tool used during network initialization, making it a valuable target for attackers seeking to compromise validator setups.

## Recommendation

**Implement path validation and normalization before filesystem operations:**

1. **Validate username input** - Reject usernames containing path traversal sequences:
```rust
// In crates/aptos/src/genesis/keys.rs
fn validate_username(username: &str) -> CliTypedResult<()> {
    if username.contains("..") || username.contains('/') || username.contains('\\') {
        return Err(CliError::CommandArgumentError(
            "Username cannot contain path traversal sequences or path separators".to_string()
        ));
    }
    Ok(())
}
```

2. **Canonicalize paths in Client::put() and Client::create_dir()**:
```rust
// In crates/aptos/src/genesis/git.rs
pub fn create_dir(&self, dir: &Path) -> CliTypedResult<()> {
    match self {
        Client::Local(local_repository_path) => {
            let path = local_repository_path.join(dir);
            
            // Canonicalize and validate path is within repository
            let canonical_path = path.canonicalize()
                .or_else(|_| {
                    // Path doesn't exist yet, canonicalize parent and append last component
                    path.parent()
                        .ok_or_else(|| CliError::UnexpectedError("Invalid path".to_string()))?
                        .canonicalize()
                        .map(|p| p.join(path.file_name().unwrap()))
                })?;
            
            let canonical_repo = local_repository_path.canonicalize()?;
            if !canonical_path.starts_with(&canonical_repo) {
                return Err(CliError::UnexpectedError(format!(
                    "Path traversal detected: {} is outside repository {}",
                    canonical_path.display(),
                    canonical_repo.display()
                )));
            }
            
            create_dir_if_not_exist(canonical_path.as_path())?;
        },
        Client::Github(_) => {},
    }
    Ok(())
}
```

3. **Apply similar validation in put() method** before writing files.

## Proof of Concept

```bash
#!/bin/bash
# Proof of Concept: Path Traversal in Genesis CLI

# Setup: Create a test repository directory
TEST_REPO="/tmp/test_genesis_repo"
mkdir -p "$TEST_REPO"

# Create dummy key files (required for the command to run)
cat > /tmp/public-keys.yaml <<EOF
account_address: "0x1"
account_public_key: "0x1234"
EOF

# Attack: Use path traversal in username
aptos genesis set-validator-configuration \
  --username "../../tmp/pwned" \
  --local-repository-dir "$TEST_REPO" \
  --validator-host 127.0.0.1:6180 \
  --full-node-host 127.0.0.1:6181 \
  --stake-amount 1000000 \
  --owner-public-identity-file /tmp/public-keys.yaml

# Verify: Check if files were created outside the repository
if [ -d "/tmp/pwned" ]; then
    echo "VULNERABILITY CONFIRMED: Directories created at /tmp/pwned/"
    ls -la /tmp/pwned/
    
    if [ -f "/tmp/pwned/operator.yaml" ]; then
        echo "CRITICAL: operator.yaml written outside repository"
        cat /tmp/pwned/operator.yaml
    fi
else
    echo "Vulnerability not exploitable or paths resolved differently"
fi

# Cleanup
rm -rf "$TEST_REPO" /tmp/pwned /tmp/public-keys.yaml
```

**Expected Result:** The script will create directories and write configuration files to `/tmp/pwned/` instead of within `$TEST_REPO`, demonstrating the path traversal vulnerability.

## Notes

**Important Context:**
- This vulnerability affects the **genesis CLI tool**, not the runtime blockchain validators
- It is a **local filesystem security issue**, not a consensus or state management vulnerability
- The impact is limited to the machine running the CLI command and the permissions of that user
- This does **not** compromise the blockchain network, consensus protocol, or Move VM
- The vulnerability could be exploited through social engineering during network setup phases

**Scope Clarification:**
While this is a valid security vulnerability as identified in the security question, it should be understood as a CLI tool security issue rather than a core blockchain protocol vulnerability. It does not affect the 10 critical invariants listed (Deterministic Execution, Consensus Safety, Move VM Safety, etc.) as those apply to the runtime blockchain operations, not the genesis setup tooling.

### Citations

**File:** crates/aptos/src/genesis/keys.rs (L114-115)
```rust
    #[clap(long)]
    pub(crate) username: String,
```

**File:** crates/aptos/src/genesis/keys.rs (L254-256)
```rust
        let directory = PathBuf::from(&self.username);
        let operator_file = directory.join(OPERATOR_FILE);
        let owner_file = directory.join(OWNER_FILE);
```

**File:** crates/aptos/src/genesis/git.rs (L190-190)
```rust
                let path = local_repository_path.join(name);
```

**File:** crates/aptos/src/genesis/git.rs (L193-194)
```rust
                if let Some(dir) = path.parent() {
                    self.create_dir(dir)?;
```

**File:** crates/aptos/src/genesis/git.rs (L201-205)
```rust
                write_to_file(
                    path.as_path(),
                    &path.display().to_string(),
                    to_yaml(input)?.as_bytes(),
                )?;
```

**File:** crates/aptos/src/genesis/git.rs (L218-219)
```rust
                let path = local_repository_path.join(dir);
                create_dir_if_not_exist(path.as_path())?;
```

**File:** crates/aptos/src/common/utils.rs (L418-419)
```rust
    if !dir.exists() || !dir.is_dir() {
        std::fs::create_dir_all(dir).map_err(|e| CliError::IO(dir.display().to_string(), e))?;
```
