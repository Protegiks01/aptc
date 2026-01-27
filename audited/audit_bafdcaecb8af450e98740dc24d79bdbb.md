# Audit Report

## Title
Insecure File Permissions in Transaction Simulation Config File Allows API Key Disclosure

## Summary
The `save_to_file()` function in the transaction simulation session configuration module writes configuration files containing sensitive API keys with default file permissions (0644 on Unix systems), allowing any local user to read the API key from the stored config file.

## Finding Description
The `Config::save_to_file()` function uses `std::fs::write()` to persist session configuration to disk without setting restrictive file permissions. [1](#0-0) 

When users initialize a simulation session with remote state, they provide an API key that gets stored in the configuration: [2](#0-1) 

This API key is saved to `config.json` in the session directory. On Unix-like systems, `std::fs::write()` creates files with default permissions (typically 0644), making them readable by the owner, group, and all other users on the system.

The vulnerability is triggered when a user initializes a session with remote state: [3](#0-2) 

The API key is used as a Bearer token for authentication with node APIs: [4](#0-3) 

**Attack Scenario:**
1. Developer runs: `aptos move sim init --path ./my-session --network mainnet --api-key sk_live_abc123xyz`
2. Config file is created at `./my-session/config.json` with permissions 0644
3. Any other user on the system can read: `cat ./my-session/config.json` and extract the API key
4. Attacker uses the stolen API key to make authenticated requests to the fullnode, consuming the victim's API quota or accessing paid services

**Security Guarantee Violation:** This violates the principle of least privilege and credential protection. The Aptos codebase already demonstrates awareness of this issue by providing secure file writing utilities: [5](#0-4) 

However, the simulation session config module does not use these secure utilities.

## Impact Explanation
Per the Aptos Bug Bounty severity categories, this qualifies as **Low Severity** (up to $1,000) - "Minor information leaks." 

The disclosed API key:
- Allows unauthorized consumption of the victim's node API quota
- May enable access to paid API services if the victim uses a premium key
- Could be used for impersonation in API request logging

However, this does NOT lead to:
- Direct loss of blockchain funds
- Consensus violations or network attacks  
- Validator compromise or staking vulnerabilities
- Smart contract or Move VM exploitation

The impact is limited to operational security of a CLI development tool, not the core blockchain protocol.

## Likelihood Explanation
Likelihood: **Medium**

This vulnerability will occur whenever:
- A user initializes a simulation session with remote state and an API key
- The session directory is on a multi-user system or shared filesystem
- The user doesn't manually restrict file permissions after creation

The vulnerability is easy to exploit (simple file read) but requires:
- Local system access on the same machine as the victim
- Victim using the simulation feature with an API key
- Timing the attack while the config file exists

## Recommendation
Use the existing secure file writing utilities or implement similar permission restrictions. Modify the `save_to_file()` function to set mode 0600 (owner read/write only):

```rust
pub fn save_to_file(&self, path: &std::path::Path) -> Result<()> {
    let json = serde_json::to_string_pretty(self)?;
    
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(json.as_bytes())?;
    }
    
    #[cfg(not(unix))]
    {
        std::fs::write(path, json)?;
    }
    
    Ok(())
}
```

Alternatively, use the existing `write_to_user_only_file()` utility from `crates/aptos/src/common/utils.rs` if refactoring dependencies is acceptable.

## Proof of Concept

```rust
use std::fs;
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;
use url::Url;

#[test]
fn test_config_file_permissions_vulnerability() {
    let temp_dir = TempDir::new().unwrap();
    let session_path = temp_dir.path();
    
    // Initialize session with API key
    use aptos_transaction_simulation_session::Session;
    Session::init_with_remote_state(
        session_path,
        Url::parse("https://fullnode.mainnet.aptoslabs.com").unwrap(),
        1,
        Some("secret_api_key_12345".to_string()),
    ).unwrap();
    
    // Check config file permissions
    let config_path = session_path.join("config.json");
    let metadata = fs::metadata(&config_path).unwrap();
    let permissions = metadata.permissions();
    let mode = permissions.mode();
    
    // On Unix, mode & 0o777 gives the permission bits
    let perm_bits = mode & 0o777;
    
    println!("Config file permissions: {:o}", perm_bits);
    
    // Verify the file is world-readable (VULNERABILITY)
    assert_ne!(perm_bits & 0o044, 0, "File should be world-readable (INSECURE)");
    
    // Demonstrate API key extraction
    let config_content = fs::read_to_string(&config_path).unwrap();
    assert!(config_content.contains("secret_api_key_12345"), 
            "API key is readable in plaintext");
    
    // This test PASSES, demonstrating the vulnerability
    // It SHOULD FAIL if permissions were set correctly to 0600
}
```

**Notes:**

This vulnerability exists in production code but affects only the CLI simulation tool (`aptos move sim`), not core blockchain consensus or validation logic. The severity is **Low** per Aptos Bug Bounty criteria as it's a minor information leak that doesn't impact blockchain security directly. The fix is straightforward and the codebase already has the necessary utilities to implement secure file writing.

### Citations

**File:** aptos-move/aptos-transaction-simulation-session/src/config.rs (L16-21)
```rust
    Remote {
        node_url: Url,
        network_version: u64,
        api_key: Option<String>,
    },
}
```

**File:** aptos-move/aptos-transaction-simulation-session/src/config.rs (L56-60)
```rust
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
```

**File:** aptos-move/aptos-transaction-simulation-session/src/session.rs (L173-175)
```rust
        let config = Config::with_remote(node_url.clone(), network_version, api_key.clone());
        let config_path = session_path.join("config.json");
        config.save_to_file(&config_path)?;
```

**File:** crates/aptos/src/common/types.rs (L1105-1109)
```rust
    /// Key to use for ratelimiting purposes with the node API. This value will be used
    /// as `Authorization: Bearer <key>`. You may also set this with the NODE_API_KEY
    /// environment variable.
    #[clap(long, env)]
    pub node_api_key: Option<String>,
```

**File:** crates/aptos/src/common/utils.rs (L223-229)
```rust
/// Write a User only read / write file
pub fn write_to_user_only_file(path: &Path, name: &str, bytes: &[u8]) -> CliTypedResult<()> {
    let mut opts = OpenOptions::new();
    #[cfg(unix)]
    opts.mode(0o600);
    write_to_file_with_opts(path, name, bytes, &mut opts)
}
```
