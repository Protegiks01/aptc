# Audit Report

## Title
URL Injection Vulnerability in GitHub Client Allows Genesis Repository Manipulation

## Summary
The `aptos-github-client` library constructs GitHub API URLs by directly concatenating user-controlled path strings without URL encoding, allowing attackers to inject special characters that manipulate API requests during genesis setup. This can lead to unauthorized repository access, writing to unintended paths, and potential corruption of the genesis configuration.

## Finding Description

The vulnerability exists in the URL construction methods of the GitHub client implementation. The `post_url()` and `get_url()` functions directly concatenate the `path` parameter into API URLs without any URL encoding or sanitization. [1](#0-0) 

When the `SetValidatorConfiguration` command is executed during genesis setup, it accepts a user-controlled `--username` parameter that is used to construct file paths: [2](#0-1) 

The username field has no validation or sanitization: [3](#0-2) 

This creates an attack chain where:
1. Attacker provides malicious username like `malicious?ref=evil-branch` or `../../.github/workflows/backdoor`
2. PathBuf converts this to a path string via `display().to_string()`
3. The GitHub client inserts this unsanitized string directly into the API URL
4. Special characters (`?`, `#`, `/`) are not URL-encoded, allowing URL structure manipulation

**Attack Scenarios:**

**Scenario 1 - Query Parameter Injection:**
- Username: `validator?ref=attacker-branch#`
- Resulting URL: `https://api.github.com/repos/owner/repo/contents/validator?ref=attacker-branch#/operator.yaml`
- Impact: The `?` character terminates the path and starts query parameters, potentially redirecting the API call to read/write from different branches

**Scenario 2 - Path Manipulation:**
- Username: `../../.github/workflows/malicious-action`
- Resulting URL: `https://api.github.com/repos/owner/repo/contents/../../.github/workflows/malicious-action/operator.yaml`
- Impact: Attempts to write to GitHub Actions workflows directory, potentially injecting malicious CI/CD pipelines

**Scenario 3 - Fragment Injection:**
- Username: `validator#ignore-rest`
- Resulting URL: `https://api.github.com/repos/owner/repo/contents/validator#ignore-rest/operator.yaml`
- Impact: The `#` character creates a fragment identifier, potentially truncating or altering the intended API request

The `aptos-github-client` crate has no URL encoding dependencies: [4](#0-3) 

## Impact Explanation

This vulnerability qualifies as **HIGH SEVERITY** under the Aptos bug bounty program criteria for the following reasons:

1. **API Manipulation**: Malformed URLs can cause API crashes or unexpected behavior during critical genesis setup operations
2. **Significant Protocol Violations**: The genesis setup process is fundamental to network bootstrapping - any compromise here violates the integrity of the initial validator set
3. **Repository Access Control Bypass**: Attackers could potentially write validator configuration to unintended repository locations, including sensitive directories like `.github/workflows`
4. **Data Exfiltration Risk**: Query parameter injection could allow reading from branches other than the intended genesis branch

While this doesn't directly break consensus (since genesis happens before the chain starts), it compromises the **Access Control** invariant by allowing writes to arbitrary repository paths, and could lead to malicious genesis configurations that affect validator operations post-launch.

## Likelihood Explanation

The likelihood is **MODERATE to HIGH** because:

**Attack Requirements:**
- Attacker needs to run the `aptos genesis set-validator-configuration` command
- This is a publicly available CLI tool used during network setup
- No special privileges are required to provide the `--username` parameter
- The command is documented and used in genesis setup scripts

**Feasibility:**
- The attack is trivial to execute (just provide special characters in username)
- No complex timing or race conditions required
- Works against any genesis setup using the GitHub storage backend

**Real-World Scenario:**
During a testnet or mainnet genesis ceremony, if validators are instructed to run setup commands, a malicious participant could inject special characters in their username to manipulate the shared genesis repository. [5](#0-4) 

## Recommendation

Implement proper URL encoding for path segments before inserting them into GitHub API URLs. Add input validation to reject suspicious usernames at the CLI layer.

**Fix for `aptos-github-client/src/lib.rs`:**

Add the `percent-encoding` crate to dependencies and modify URL construction:

```rust
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};

fn post_url(&self, path: &str) -> String {
    let encoded_path = utf8_percent_encode(path, NON_ALPHANUMERIC).to_string();
    format!(
        "{}/repos/{}/{}/contents/{}",
        URL, self.owner, self.repository, encoded_path
    )
}

fn get_url(&self, path: &str) -> String {
    let encoded_path = utf8_percent_encode(path, NON_ALPHANUMERIC).to_string();
    format!(
        "{}/repos/{}/{}/contents/{}?ref={}",
        URL, self.owner, self.repository, encoded_path, self.branch
    )
}
```

**Fix for `crates/aptos/src/genesis/keys.rs`:**

Add validation for the username field:

```rust
fn validate_username(username: &str) -> CliTypedResult<()> {
    if username.is_empty() || username.len() > 127 {
        return Err(CliError::CommandArgumentError(
            "Username must be between 1 and 127 characters".to_string()
        ));
    }
    
    // Only allow alphanumeric, hyphens, and underscores
    if !username.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        return Err(CliError::CommandArgumentError(
            "Username can only contain alphanumeric characters, hyphens, and underscores".to_string()
        ));
    }
    
    // Reject path traversal attempts
    if username.contains("..") || username.contains("/") || username.contains("\\") {
        return Err(CliError::CommandArgumentError(
            "Username cannot contain path separators or traversal sequences".to_string()
        ));
    }
    
    Ok(())
}
```

Then call this validation in `SetValidatorConfiguration::execute()` before using the username.

## Proof of Concept

**Rust Test Demonstrating URL Construction Vulnerability:**

```rust
#[cfg(test)]
mod url_injection_poc {
    use super::*;
    
    #[test]
    fn test_url_injection_query_parameter() {
        let client = Client::new(
            "aptos-labs".to_string(),
            "genesis-repo".to_string(),
            "main".to_string(),
            "fake-token".to_string(),
        );
        
        // Malicious path with query parameter injection
        let malicious_path = "validator?ref=evil-branch&foo=bar";
        let url = client.post_url(malicious_path);
        
        // The URL should NOT contain unencoded special characters
        // Expected (with proper encoding): .../contents/validator%3Fref%3Devil-branch%26foo%3Dbar
        // Actual (vulnerable): .../contents/validator?ref=evil-branch&foo=bar
        assert!(url.contains("?"), "URL contains unencoded query parameter delimiter");
        assert!(url.contains("&"), "URL contains unencoded parameter separator");
        
        println!("Generated URL: {}", url);
        println!("VULNERABLE: Special characters not URL-encoded!");
    }
    
    #[test]
    fn test_url_injection_path_traversal() {
        let client = Client::new(
            "aptos-labs".to_string(),
            "genesis-repo".to_string(),
            "main".to_string(),
            "fake-token".to_string(),
        );
        
        // Malicious path with directory traversal
        let malicious_path = "../../.github/workflows/malicious";
        let url = client.post_url(malicious_path);
        
        // The URL should have encoded the slashes and dots
        assert!(url.contains("../"), "URL contains unencoded path traversal sequence");
        
        println!("Generated URL: {}", url);
        println!("VULNERABLE: Path traversal sequences not encoded!");
    }
    
    #[test]
    fn test_url_injection_fragment() {
        let client = Client::new(
            "aptos-labs".to_string(),
            "genesis-repo".to_string(),
            "main".to_string(),
            "fake-token".to_string(),
        );
        
        // Malicious path with fragment identifier
        let malicious_path = "validator#fragment/ignored";
        let url = client.get_url(malicious_path);
        
        // The URL should have encoded the # character
        assert!(url.contains("#"), "URL contains unencoded fragment identifier");
        
        println!("Generated URL: {}", url);
        println!("VULNERABLE: Fragment identifier not URL-encoded!");
    }
}
```

**CLI Exploitation Steps:**

```bash
# Step 1: Attempt to inject query parameters via username
aptos genesis set-validator-configuration \
  --username "attacker?ref=malicious-branch" \
  --validator-host "validator.example.com:6180" \
  --stake-amount 100000000 \
  --github-repository "aptos-labs/genesis-repo" \
  --github-branch "main" \
  --github-token-file ./token.txt

# Step 2: Attempt path traversal to write to workflows directory
aptos genesis set-validator-configuration \
  --username "../../.github/workflows/backdoor" \
  --validator-host "validator.example.com:6180" \
  --stake-amount 100000000 \
  --github-repository "aptos-labs/genesis-repo" \
  --github-branch "main" \
  --github-token-file ./token.txt

# Expected Result: The GitHub API receives malformed URLs with unencoded
# special characters, allowing manipulation of the API request structure
```

## Notes

This vulnerability affects the genesis setup workflow, which is a critical phase before the blockchain network launches. While it doesn't directly impact consensus or the running blockchain, compromising the genesis configuration could:

1. Allow injection of malicious validator configurations
2. Enable writing to sensitive repository paths like GitHub Actions workflows
3. Permit reading genesis data from unintended branches through query injection
4. Cause API errors that disrupt the genesis ceremony

The fix requires both **defensive input validation** at the CLI layer and **proper URL encoding** at the GitHub client layer to follow defense-in-depth principles.

### Citations

**File:** crates/aptos-github-client/src/lib.rs (L246-258)
```rust
    fn post_url(&self, path: &str) -> String {
        format!(
            "{}/repos/{}/{}/contents/{}",
            URL, self.owner, self.repository, path
        )
    }

    fn get_url(&self, path: &str) -> String {
        format!(
            "{}/repos/{}/{}/contents/{}?ref={}",
            URL, self.owner, self.repository, path, self.branch
        )
    }
```

**File:** crates/aptos/src/genesis/keys.rs (L113-115)
```rust
    /// Name of the validator
    #[clap(long)]
    pub(crate) username: String,
```

**File:** crates/aptos/src/genesis/keys.rs (L254-260)
```rust
        let directory = PathBuf::from(&self.username);
        let operator_file = directory.join(OPERATOR_FILE);
        let owner_file = directory.join(OWNER_FILE);

        let git_client = self.git_options.get_client()?;
        git_client.put(operator_file.as_path(), &operator_config)?;
        git_client.put(owner_file.as_path(), &owner_config)
```

**File:** crates/aptos-github-client/Cargo.toml (L15-20)
```text
[dependencies]
aptos-proxy = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
thiserror = { workspace = true }
ureq = { workspace = true }
```

**File:** terraform/helm/genesis/files/genesis.sh (L1-10)
```shellscript
#!/bin/bash

#
# Runs an automated genesis ceremony for validators spun up by the aptos-node helm chart
#
# Expect the following environment variables to be set before execution:
# NUM_VALIDATORS
# ERA
# WORKSPACE: default /tmp
# USERNAME_PREFIX: default aptos-node
```
