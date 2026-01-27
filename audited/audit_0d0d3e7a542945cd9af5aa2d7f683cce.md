# Audit Report

## Title
Auth Token File Permission Vulnerability Allows Unauthorized Faucet Access

## Summary
The `ListManager::new()` function in the Aptos Faucet does not verify file permissions when loading authentication tokens, potentially allowing any local user on the system to read world-readable token files and bypass all faucet security controls.

## Finding Description

The `AuthTokenChecker` in the Aptos Faucet service loads authentication tokens from a file via `ListManager::new()`: [1](#0-0) 

This delegates to `ListManager::new()` which opens the file without checking permissions: [2](#0-1) 

The function uses `File::open()` which reads the file regardless of its permissions. If an operator creates the token file with default permissions (commonly 0o644 on Unix systems), any local user on the system can read the file contents.

**Attack Scenario:**

1. Faucet operator creates auth token file: `/etc/aptos-faucet/auth_tokens.txt`
2. File has default permissions (0o644 - world-readable)
3. Unprivileged local user reads file: `cat /etc/aptos-faucet/auth_tokens.txt`
4. Attacker extracts token and uses it in HTTP requests: `Authorization: Bearer <stolen_token>`
5. With valid token, attacker can bypass ALL security checkers via `AuthTokenBypasser`: [3](#0-2) 

This breaks the access control invariant by allowing unauthorized users to bypass captcha verification, IP blocklists, rate limiting, and access higher funding limits (`maximum_amount_with_bypass`).

## Impact Explanation

This vulnerability falls under **Low Severity** per Aptos bug bounty criteria, specifically "Minor information leaks" and impacts to auxiliary services. 

While the security question labels this as Medium, the actual impact is limited because:

1. **Scope**: Affects only the faucet auxiliary service, not core blockchain components (consensus, Move VM, state management, governance, or staking)
2. **Funds**: Only testnet/devnet tokens are at risk, which have no real monetary value
3. **Access Requirement**: Requires local file system access on the faucet server machine
4. **Impact Boundary**: Cannot affect validator operations, blockchain state, or mainnet assets

The practical harm is faucet fund depletion requiring more frequent refills, and availability degradation for legitimate developers requesting test tokens.

## Likelihood Explanation

**Medium likelihood** in multi-user or shared hosting environments:

1. Default file creation with `File::create()` often results in 0o644 permissions (world-readable)
2. Test code demonstrates this pattern without explicit permission hardening: [4](#0-3) 

3. Operators may not be aware of the security requirement to restrict permissions
4. No validation warning at startup to alert operators of insecure configurations
5. However, exploitation requires local shell access to the faucet server

## Recommendation

Add file permission validation in `ListManager::new()` to ensure auth token files are not world-readable:

```rust
pub fn new(config: ListManagerConfig) -> Result<Self> {
    let file = File::open(&config.file)
        .with_context(|| format!("Failed to open {}", config.file.to_string_lossy()))?;
    
    // Verify file permissions on Unix systems
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = file.metadata()?;
        let mode = metadata.permissions().mode();
        
        // Check if file is readable by group or others (anything beyond 0o600)
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "Auth token file {} has insecure permissions {:o}. \
                File must not be readable by group or others (recommend 0o600)",
                config.file.to_string_lossy(),
                mode & 0o777
            );
        }
    }
    
    let mut items = HashSet::new();
    for line in std::io::BufReader::new(file).lines() {
        let line = line?;
        if line.starts_with('#') || line.starts_with("//") || line.is_empty() {
            continue;
        }
        items.insert(line);
    }
    Ok(Self { items })
}
```

Additionally, update documentation to instruct operators to create token files with restrictive permissions: `chmod 600 /path/to/auth_tokens.txt`

## Proof of Concept

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{File, Permissions};
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::NamedTempFile;

    #[test]
    fn test_world_readable_file_rejected() {
        // Create a world-readable token file
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "secret_token_123").unwrap();
        
        // Set world-readable permissions (0o644)
        let permissions = Permissions::from_mode(0o644);
        file.as_file().set_permissions(permissions).unwrap();
        
        let config = ListManagerConfig {
            file: file.path().to_path_buf(),
        };
        
        // Should fail due to insecure permissions
        let result = ListManager::new(config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("insecure permissions"));
    }

    #[test]
    fn test_secure_file_accepted() {
        // Create a user-only readable token file
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "secret_token_123").unwrap();
        
        // Set user-only permissions (0o600)
        let permissions = Permissions::from_mode(0o600);
        file.as_file().set_permissions(permissions).unwrap();
        
        let config = ListManagerConfig {
            file: file.path().to_path_buf(),
        };
        
        // Should succeed with secure permissions
        let result = ListManager::new(config);
        assert!(result.is_ok());
        assert!(result.unwrap().contains("secret_token_123"));
    }
}
```

## Notes

While this is a legitimate access control vulnerability in the faucet component, it's important to contextualize the severity:

- **Not a blockchain protocol vulnerability**: Does not affect Aptos consensus, Move VM, state management, governance, or staking systems
- **Limited scope**: Only impacts the auxiliary faucet service used for distributing testnet tokens
- **No mainnet impact**: Testnet tokens have no monetary value
- **Requires local access**: Attacker needs shell access to the faucet server machine

The Aptos core blockchain remains secure even if this faucet vulnerability is exploited. This finding is relevant for production faucet deployments but does not represent a critical security risk to the Aptos blockchain protocol itself.

### Citations

**File:** crates/aptos-faucet/core/src/checkers/auth_token.rs (L20-27)
```rust
    pub fn new(config: ListManagerConfig) -> Result<Self> {
        let manager = ListManager::new(config)?;
        info!(
            "Loaded {} auth tokens into AuthTokenChecker",
            manager.num_items()
        );
        Ok(Self { manager })
    }
```

**File:** crates/aptos-faucet/core/src/common/list_manager.rs (L21-32)
```rust
    pub fn new(config: ListManagerConfig) -> Result<Self> {
        let file = File::open(&config.file)
            .with_context(|| format!("Failed to open {}", config.file.to_string_lossy()))?;
        let mut items = HashSet::new();
        for line in std::io::BufReader::new(file).lines() {
            let line = line?;
            if line.starts_with('#') || line.starts_with("//") || line.is_empty() {
                continue;
            }
            items.insert(line);
        }
        Ok(Self { items })
```

**File:** crates/aptos-faucet/core/src/bypasser/auth_token.rs (L32-49)
```rust
    async fn request_can_bypass(&self, data: CheckerData) -> Result<bool> {
        // Don't check if the request has X_IS_JWT_HEADER set.
        if data.headers.contains_key(X_IS_JWT_HEADER) {
            return Ok(false);
        }

        let auth_token = match data
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split_whitespace().nth(1))
        {
            Some(auth_token) => auth_token,
            None => return Ok(false),
        };

        Ok(self.manager.contains(auth_token))
    }
```

**File:** crates/aptos-faucet/core/src/server/run.rs (L494-504)
```rust
    fn make_list_file(filename: &str, items: &[&str]) -> Result<()> {
        let mut file = File::create(filename)?;
        for item in items {
            writeln!(file, "{}", item)?;
        }
        Ok(())
    }

    fn make_auth_tokens_file(auth_tokens: &[&str]) -> Result<()> {
        make_list_file("/tmp/auth_tokens.txt", auth_tokens)
    }
```
