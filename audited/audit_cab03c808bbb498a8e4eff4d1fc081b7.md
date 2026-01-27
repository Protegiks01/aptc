# Audit Report

## Title
CLI Configuration File Race Condition in Concurrent Tool Execution

## Summary
The Aptos CLI's `Tool::execute()` method and its sub-tools perform unsynchronized read-modify-write operations on shared configuration files (`.aptos/config.yaml` and `~/.aptos/global_config.yaml`). When multiple CLI commands execute concurrently, race conditions can corrupt configuration state, leading to lost profile data and inconsistent CLI behavior.

## Finding Description

The `Tool::execute()` method in [1](#0-0)  dispatches to various sub-tools that manipulate shared configuration files. These operations follow a load-modify-save pattern without any file locking mechanism.

**Critical Code Paths:**

1. **CliConfig Load Operation** - [2](#0-1)  reads the configuration file without acquiring any locks.

2. **CliConfig Save Operation** - [3](#0-2)  writes the entire configuration using truncate mode without locks.

3. **Commands That Modify Config** include:
   - Profile deletion: [4](#0-3) 
   - Profile renaming: [5](#0-4) 
   - Key rotation: [6](#0-5) 
   - Initialization: [7](#0-6) 

4. **GlobalConfig has identical issues**: [8](#0-7)  and [9](#0-8) 

**The codebase already implements proper file locking** for other operations via [10](#0-9)  using `fs2::FileExt::lock_exclusive()`, but this is not used for CLI config files.

**Race Condition Scenario:**

Terminal A: `aptos config rename-profile --profile default --new-profile-name prod`  
Terminal B: `aptos init --profile backup`

1. Both commands load config with profiles: `{default, staging}`
2. Command A modifies: `{prod, staging}` (rename default→prod)
3. Command B modifies: `{default, staging, backup}` (add backup)
4. Command A saves: `{prod, staging}`
5. Command B saves: `{default, staging, backup}` ← **Overwrites A's changes**

Result: The rename operation is lost entirely.

## Impact Explanation

This qualifies as **Medium Severity** under the Aptos bug bounty program's criteria: "State inconsistencies requiring intervention."

However, upon critical examination, this vulnerability has **LIMITED REAL-WORLD IMPACT** because:

1. **Not blockchain-affecting**: This bug only affects local CLI configuration files, not consensus, state management, or on-chain operations.
2. **No fund loss**: Private keys stored in profiles remain intact (only profile metadata is affected).
3. **User-local**: Each user's config is independent; one user cannot corrupt another's config.
4. **Recoverable**: Users can manually recreate profiles using `aptos init`.

**This fails the core validation criteria**: The documented invariants (Deterministic Execution, Consensus Safety, Move VM Safety, State Consistency, Governance Integrity, etc.) all pertain to **blockchain-level security**, not CLI tool convenience features.

## Likelihood Explanation

**Low to Medium Likelihood** for typical usage:
- Requires user to run multiple CLI commands simultaneously
- Most users run commands sequentially
- Automation scripts might hit this if poorly designed

**Not applicable for validator operations**: Validators use direct APIs and consensus protocols, not CLI configuration files for critical operations.

## Recommendation

Implement file-based locking for configuration operations:

```rust
use fs2::FileExt;
use std::fs::File;

impl CliConfig {
    pub fn save(&self) -> CliTypedResult<()> {
        let aptos_folder = Self::aptos_folder(ConfigSearchMode::CurrentDir)?;
        let lock_file = File::create(aptos_folder.join(".lock"))?;
        lock_file.lock_exclusive()?; // Acquire exclusive lock
        
        // ... existing save logic ...
        
        Ok(()) // Lock released on drop
    }
}
```

Apply the same pattern to `CliConfig::load()` and `GlobalConfig` operations.

## Proof of Concept

```bash
#!/bin/bash
# Race condition demonstration

# Setup initial profile
aptos init --assume-yes --profile default 2>&1 >/dev/null

# Run two concurrent operations that modify config
aptos config rename-profile --profile default --new-profile-name prod &
PID1=$!

aptos init --assume-yes --profile backup &
PID2=$!

wait $PID1
wait $PID2

# Check result - one operation's changes will be lost
aptos config show-profiles
```

Expected: Profiles should be `{prod, backup}`  
Actual: Profiles will be `{default, backup}` OR `{prod}` (depending on timing)

---

## Notes

**CRITICAL ASSESSMENT**: While this is a **valid race condition bug**, it does **NOT** qualify as an Aptos blockchain security vulnerability under the audit scope defined in the prompt. 

The prompt explicitly states the focus is on "consensus vulnerabilities, Move VM implementation bugs, state management attacks, and on-chain governance security" with invariants like "Consensus Safety," "State Consistency," and "Governance Integrity."

This CLI config file race condition:
- ❌ Does not affect blockchain consensus
- ❌ Does not affect validator operations  
- ❌ Does not affect on-chain state or governance
- ❌ Does not cause loss of funds
- ❌ Does not affect network availability

It's a **local CLI tool usability bug**, not a blockchain protocol vulnerability. The impact is limited to user convenience (corrupted local profiles), which is recoverable and doesn't affect blockchain security guarantees.

**Per the validation checklist requirement**: "Issue breaks at least one documented invariant" — This bug does NOT break any of the 10 documented blockchain invariants (Deterministic Execution, Consensus Safety, Move VM Safety, etc.).

Given the extremely high bar set by the validation checklist and the explicit blockchain-security focus of the audit, this issue should be classified as **out of scope** for the Aptos blockchain security audit, despite being a legitimate software bug.

### Citations

**File:** crates/aptos/src/lib.rs (L60-78)
```rust
    pub async fn execute(self) -> CliResult {
        use Tool::*;
        match self {
            Account(tool) => tool.execute().await,
            Config(tool) => tool.execute().await,
            Genesis(tool) => tool.execute().await,
            Governance(tool) => tool.execute().await,
            Info(tool) => tool.execute_serialized().await,
            // TODO: Replace entirely with config init
            Init(tool) => tool.execute_serialized_success().await,
            Key(tool) => tool.execute().await,
            Move(tool) => tool.execute().await,
            Multisig(tool) => tool.execute().await,
            Node(tool) => tool.execute().await,
            Stake(tool) => tool.execute().await,
            Update(tool) => tool.execute().await,
            Workspace(workspace) => workspace.execute_serialized_without_logger().await,
        }
    }
```

**File:** crates/aptos/src/common/types.rs (L370-391)
```rust
    pub fn load(mode: ConfigSearchMode) -> CliTypedResult<Self> {
        let folder = Self::aptos_folder(mode)?;

        let config_file = folder.join(CONFIG_FILE);
        let old_config_file = folder.join(LEGACY_CONFIG_FILE);
        if config_file.exists() {
            from_yaml(
                &String::from_utf8(read_from_file(config_file.as_path())?)
                    .map_err(CliError::from)?,
            )
        } else if old_config_file.exists() {
            from_yaml(
                &String::from_utf8(read_from_file(old_config_file.as_path())?)
                    .map_err(CliError::from)?,
            )
        } else {
            Err(CliError::ConfigNotFoundError(format!(
                "{}",
                config_file.display()
            )))
        }
    }
```

**File:** crates/aptos/src/common/types.rs (L423-453)
```rust
    pub fn save(&self) -> CliTypedResult<()> {
        let aptos_folder = Self::aptos_folder(ConfigSearchMode::CurrentDir)?;

        // Create if it doesn't exist
        let no_dir = !aptos_folder.exists();
        create_dir_if_not_exist(aptos_folder.as_path())?;

        // If the `.aptos/` doesn't exist, we'll add a .gitignore in it to ignore the config file
        // so people don't save their credentials...
        if no_dir {
            write_to_user_only_file(
                aptos_folder.join(GIT_IGNORE).as_path(),
                GIT_IGNORE,
                APTOS_FOLDER_GIT_IGNORE.as_bytes(),
            )?;
        }

        // Save over previous config file
        let config_file = aptos_folder.join(CONFIG_FILE);
        let config_bytes = serde_yaml::to_string(&self).map_err(|err| {
            CliError::UnexpectedError(format!("Failed to serialize config {}", err))
        })?;
        write_to_user_only_file(&config_file, CONFIG_FILE, config_bytes.as_bytes())?;

        // As a cleanup, delete the old if it exists
        let legacy_config_file = aptos_folder.join(LEGACY_CONFIG_FILE);
        if legacy_config_file.exists() {
            eprintln!("Removing legacy config file {}", LEGACY_CONFIG_FILE);
            let _ = std::fs::remove_file(legacy_config_file);
        }
        Ok(())
```

**File:** crates/aptos/src/config/mod.rs (L215-238)
```rust
    async fn execute(self) -> CliTypedResult<String> {
        let mut config = CliConfig::load(ConfigSearchMode::CurrentDir)?;

        if let Some(profiles) = &mut config.profiles {
            if profiles.remove(&self.profile).is_none() {
                Err(CliError::CommandArgumentError(format!(
                    "Profile {} does not exist",
                    self.profile
                )))
            } else {
                config.save().map_err(|err| {
                    CliError::UnexpectedError(format!(
                        "Unable to save config after deleting profile: {}",
                        err,
                    ))
                })?;
                Ok(format!("Deleted profile {}", self.profile))
            }
        } else {
            Err(CliError::CommandArgumentError(
                "Config has no profiles".to_string(),
            ))
        }
    }
```

**File:** crates/aptos/src/config/mod.rs (L259-291)
```rust
    async fn execute(self) -> CliTypedResult<String> {
        let mut config = CliConfig::load(ConfigSearchMode::CurrentDir)?;

        if let Some(profiles) = &mut config.profiles {
            if profiles.contains_key(&self.new_profile_name.clone()) {
                Err(CliError::CommandArgumentError(format!(
                    "Profile {} already exists",
                    self.new_profile_name
                )))
            } else if let Some(profile_config) = profiles.remove(&self.profile) {
                profiles.insert(self.new_profile_name.clone(), profile_config);
                config.save().map_err(|err| {
                    CliError::UnexpectedError(format!(
                        "Unable to save config after renaming profile: {}",
                        err,
                    ))
                })?;
                Ok(format!(
                    "Renamed profile {} to {}",
                    self.profile, self.new_profile_name
                ))
            } else {
                Err(CliError::CommandArgumentError(format!(
                    "Profile {} does not exist",
                    self.profile
                )))
            }
        } else {
            Err(CliError::CommandArgumentError(
                "Config has no profiles".to_string(),
            ))
        }
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

**File:** crates/aptos/src/config/mod.rs (L365-380)
```rust
    fn save(&self) -> CliTypedResult<()> {
        let global_folder = global_folder()?;
        create_dir_if_not_exist(global_folder.as_path())?;

        write_to_user_only_file(
            global_folder.join(GLOBAL_CONFIG_FILE).as_path(),
            "Global Config",
            &to_yaml(&self)?.into_bytes(),
        )?;
        // Let's also write a .gitignore that ignores this folder
        write_to_user_only_file(
            global_folder.join(GIT_IGNORE).as_path(),
            ".gitignore",
            APTOS_FOLDER_GIT_IGNORE.as_bytes(),
        )
    }
```

**File:** crates/aptos/src/account/key_rotation.rs (L314-325)
```rust
        config
            .profiles
            .as_mut()
            .unwrap()
            .insert(new_profile_name.clone(), new_profile_config);
        config.save()?;

        Ok(RotateSummary {
            transaction: txn_summary,
            message: Some(format!("Saved new profile {}", new_profile_name)),
        })
    }
```

**File:** crates/aptos/src/common/init.rs (L324-333)
```rust
        // Ensure the loaded config has profiles setup for a possible empty file
        if config.profiles.is_none() {
            config.profiles = Some(BTreeMap::new());
        }
        config
            .profiles
            .as_mut()
            .expect("Must have profiles, as created above")
            .insert(profile_name.to_string(), profile_config);
        config.save()?;
```

**File:** third_party/move/tools/move-package-cache/src/file_lock.rs (L15-66)
```rust
/// A file-based lock to ensure exclusive access to certain resources.
///
/// This is used by the package cache to ensure only one process can mutate a cached repo, checkout,
/// or on-chain package at a time.
pub struct FileLock {
    file: Option<File>,
    path: PathBuf,
}

impl FileLock {
    /// Attempts to acquire an exclusive `FileLock`, with an optional alert callback.
    ///
    /// If the lock cannot be acquired within `alert_timeout`, the `alert_on_wait` callback
    /// is executed to notify the caller.
    pub async fn lock_with_alert_on_wait<P, F>(
        lock_path: P,
        alert_timeout: Duration,
        alert_on_wait: F,
    ) -> Result<Self>
    where
        P: AsRef<Path>,
        F: FnOnce(),
    {
        let lock_path = lock_path.as_ref().to_owned();

        let lock_fut = {
            let lock_path = lock_path.clone();

            task::spawn_blocking(move || -> Result<File> {
                let lock_file = File::create(&lock_path)?;
                lock_file.lock_exclusive()?;
                Ok(lock_file)
            })
        };

        let timeout = tokio::time::sleep(alert_timeout).fuse();

        pin!(lock_fut, timeout);

        let lock_file = select! {
            _ = &mut timeout => {
                alert_on_wait();
                lock_fut.await??
            },
            res = &mut lock_fut => res??,
        };

        Ok(Self {
            file: Some(lock_file),
            path: lock_path,
        })
    }
```
