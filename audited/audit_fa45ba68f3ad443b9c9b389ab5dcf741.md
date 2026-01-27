# Audit Report

## Title
Cross-Platform Path Separator Inconsistency Causing Validator Startup Failures and Network Liveness Risk

## Summary
The `RootPath::full_path()` function in `config/src/config/utils.rs` does not normalize path separators before processing configuration file paths. Due to platform-specific path separator handling in Rust's `PathBuf`, validators on different operating systems can resolve different files from identical configuration values containing backslashes, leading to selective validator failures and potential network liveness compromise.

## Finding Description

The vulnerability stems from the interaction between YAML-based configuration parsing and Rust's platform-specific path handling semantics. When a configuration file specifies `genesis_file_location` with Windows-style backslash separators (e.g., `"genesis\\genesis.blob"`), the behavior diverges across platforms: [1](#0-0) 

The `full_path()` method uses `PathBuf::join()` without any path normalization. In Rust:
- **Windows**: Both `/` and `\` are treated as path separators
- **Unix/Linux/macOS**: Only `/` is a path separator; `\` is a valid filename character

When `ExecutionConfig::load_from_path()` processes the genesis file location, it resolves paths using the `RootPath` utility: [2](#0-1) 

**Attack Scenario:**

1. A configuration template or documentation uses backslashes: `genesis_file_location: "genesis\\genesis.blob"`
2. **Windows validators**: PathBuf interprets `\\` as a separator → resolves to `<config_dir>/genesis/genesis.blob`
3. **Unix validators**: PathBuf treats `\\` as literal characters → attempts to load `<config_dir>/genesis\\genesis.blob` (a filename containing backslashes)
4. Unix validators encounter file-not-found errors and fail to start: [3](#0-2) 

5. During bootstrap, the waypoint verification detects the mismatch (if different genesis loaded) and fails: [4](#0-3) 

This breaks the **Deterministic Execution** invariant: identical configurations must produce identical behavior across all validator platforms.

The `ExecutionConfig` sanitizer only validates paranoid verification flags for mainnet, with no path validation: [5](#0-4) 

## Impact Explanation

**Severity: HIGH** (up to $50,000 per Aptos Bug Bounty)

This vulnerability causes **validator node failures** and **significant protocol violations**:

1. **Selective Validator DoS**: Validators on Unix-based systems fail to start when configs contain backslash separators, while Windows validators continue normally
2. **Quorum Loss Risk**: If >1/3 of validators run Unix systems and fail simultaneously, the network loses BFT safety threshold and halts completely
3. **Network Liveness Impact**: Even without quorum loss, reduced validator participation degrades network performance and increases centralization risk
4. **Non-Deterministic Configuration**: Violates the fundamental distributed systems principle that identical inputs produce identical outputs across platforms

While waypoint validation prevents consensus divergence (validators load different genesis → fail waypoint check → don't start), the DoS impact remains severe.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

This vulnerability has significant probability of occurrence:

1. **Natural User Behavior**: Windows users naturally use backslashes in paths; validators running on Windows might create configs with `\` separators
2. **Shared Configuration Templates**: If deployment scripts or documentation examples use backslashes, all validators following those instructions would inherit the issue
3. **No Validation Defense**: The codebase has no sanitization or normalization preventing this misconfiguration
4. **Silent Failure on Unix**: Operators might not detect the issue until deploying to Unix systems, especially if initial testing occurred on Windows

The git repository checks prevent backslashes in filenames in the source tree: [6](#0-5) 

However, this protection does NOT extend to configuration file **contents** (YAML string values), leaving the vulnerability exposed.

## Recommendation

Implement path normalization in the configuration loading pipeline to ensure cross-platform consistency:

**Solution 1: Normalize paths in `RootPath::full_path()`**

```rust
pub fn full_path(&self, file_path: &Path) -> PathBuf {
    let normalized_path = if file_path.is_relative() {
        // Normalize by converting to string and replacing backslashes
        let path_str = file_path.to_string_lossy();
        let normalized_str = path_str.replace('\\', "/");
        PathBuf::from(normalized_str)
    } else {
        file_path.to_path_buf()
    };
    
    if normalized_path.is_relative() {
        self.root_path.join(normalized_path)
    } else {
        normalized_path
    }
}
```

**Solution 2: Validate paths in `ExecutionConfig::sanitize()`**

Add validation to reject configurations with backslashes on Unix systems:

```rust
impl ConfigSanitizer for ExecutionConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let execution_config = &node_config.execution;

        // Validate path separators for cross-platform consistency
        if !execution_config.genesis_file_location.as_os_str().is_empty() {
            let path_str = execution_config.genesis_file_location.to_string_lossy();
            if path_str.contains('\\') {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    format!(
                        "genesis_file_location contains backslashes which are not cross-platform compatible: {:?}. Use forward slashes (/) instead.",
                        path_str
                    ),
                ));
            }
        }
        
        // ... existing mainnet validation ...
    }
}
```

**Recommended Approach**: Implement both solutions - normalize in `full_path()` for defense-in-depth, and validate in sanitizer to provide clear error messages to operators.

## Proof of Concept

```rust
#[cfg(test)]
mod path_separator_test {
    use super::*;
    use std::path::PathBuf;
    use aptos_temppath::TempPath;
    use std::fs;

    #[test]
    fn test_cross_platform_path_inconsistency() {
        // Create a temporary directory structure
        let temp_dir = TempPath::new();
        temp_dir.create_as_dir().unwrap();
        
        // Create subdirectory with forward slash (standard)
        let genesis_dir = temp_dir.path().join("genesis");
        fs::create_dir(&genesis_dir).unwrap();
        let genesis_file = genesis_dir.join("genesis.blob");
        fs::write(&genesis_file, b"test genesis data").unwrap();
        
        // Test path with backslashes
        let path_with_backslashes = PathBuf::from("genesis\\\\genesis.blob");
        
        let root_path = RootPath::new_path(temp_dir.path());
        let resolved_path = root_path.full_path(&path_with_backslashes);
        
        // On Windows: resolves to genesis/genesis.blob (exists)
        // On Unix: resolves to literal "genesis\\genesis.blob" (doesn't exist)
        #[cfg(unix)]
        {
            // Unix interprets backslashes as filename characters
            assert!(!resolved_path.exists(), 
                "Unix should fail to find file with backslash in name");
            assert!(resolved_path.to_string_lossy().contains("\\\\"),
                "Unix path should contain literal backslashes");
        }
        
        #[cfg(windows)]
        {
            // Windows interprets backslashes as separators
            assert!(resolved_path.exists(), 
                "Windows should successfully resolve path");
        }
    }
}
```

**Notes**

The vulnerability demonstrates a critical oversight in distributed systems design: **platform-specific behavior in configuration processing**. While the Aptos codebase correctly uses platform-specific path construction in compile-time contexts [7](#0-6) , it fails to normalize runtime configuration paths that validators on different operating systems must process identically.

The waypoint verification mechanism provides defense-in-depth by preventing consensus divergence, but does not address the liveness vulnerability. Validators with mismatched paths fail during bootstrap [8](#0-7) , creating an operational DoS vector that could be triggered accidentally through seemingly innocent configuration practices.

This finding emphasizes the importance of explicit path normalization in any distributed system where configuration consistency across heterogeneous deployment environments is a security requirement.

### Citations

**File:** config/src/config/utils.rs (L30-36)
```rust
    pub fn full_path(&self, file_path: &Path) -> PathBuf {
        if file_path.is_relative() {
            self.root_path.join(file_path)
        } else {
            file_path.to_path_buf()
        }
    }
```

**File:** config/src/config/execution_config.rs (L100-109)
```rust
    pub fn load_from_path(&mut self, root_dir: &RootPath) -> Result<(), Error> {
        if !self.genesis_file_location.as_os_str().is_empty() {
            // Ensure the genesis file exists
            let genesis_path = root_dir.full_path(&self.genesis_file_location);
            if !genesis_path.exists() {
                return Err(Error::Unexpected(format!(
                    "The genesis file could not be found! Ensure the given path is correct: {:?}",
                    genesis_path.display()
                )));
            }
```

**File:** config/src/config/execution_config.rs (L112-118)
```rust
            let mut file = File::open(&genesis_path).map_err(|error| {
                Error::Unexpected(format!(
                    "Failed to open the genesis file: {:?}. Error: {:?}",
                    genesis_path.display(),
                    error
                ))
            })?;
```

**File:** config/src/config/execution_config.rs (L157-186)
```rust
impl ConfigSanitizer for ExecutionConfig {
    fn sanitize(
        node_config: &NodeConfig,
        _node_type: NodeType,
        chain_id: Option<ChainId>,
    ) -> Result<(), Error> {
        let sanitizer_name = Self::get_sanitizer_name();
        let execution_config = &node_config.execution;

        // If this is a mainnet node, ensure that additional verifiers are enabled
        if let Some(chain_id) = chain_id {
            if chain_id.is_mainnet() {
                if !execution_config.paranoid_hot_potato_verification {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        "paranoid_hot_potato_verification must be enabled for mainnet nodes!"
                            .into(),
                    ));
                }
                if !execution_config.paranoid_type_verification {
                    return Err(Error::ConfigSanitizerFailed(
                        sanitizer_name,
                        "paranoid_type_verification must be enabled for mainnet nodes!".into(),
                    ));
                }
            }
        }

        Ok(())
    }
```

**File:** execution/executor/src/db_bootstrapper/mod.rs (L62-67)
```rust
    ensure!(
        waypoint == committer.waypoint(),
        "Waypoint verification failed. Expected {:?}, got {:?}.",
        waypoint,
        committer.waypoint(),
    );
```

**File:** scripts/git-checks.sh (L60-64)
```shellscript
	badnames=$(grep '\\\|[`{}|~:]' <<< "$names") || true
	#                ^^ find anything with a backslash in the name
	#                  ^^ or...
	#                    ^^^^^^^ any of these funky chars

```

**File:** aptos-move/framework/cached-packages/src/lib.rs (L12-15)
```rust
#[cfg(unix)]
const HEAD_RELEASE_BUNDLE_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/head.mrb"));
#[cfg(windows)]
const HEAD_RELEASE_BUNDLE_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "\\head.mrb"));
```

**File:** aptos-node/src/storage.rs (L34-37)
```rust
    if let Some(genesis) = get_genesis_txn(node_config) {
        let ledger_info_opt =
            maybe_bootstrap::<AptosVMBlockExecutor>(db_rw, genesis, genesis_waypoint)
                .map_err(|err| anyhow!("DB failed to bootstrap {}", err))?;
```
