# Audit Report

## Title
Insufficient Cache Directory Permission Validation in Move Package Dependency Resolution

## Summary
The `maybe_download_package()` function in `package_hooks.rs` does not validate or enforce restrictive permissions on the `download_to` cache directory, creating a potential supply chain attack vector if directory permissions are misconfigured.

## Finding Description

The Move package system caches downloaded Aptos dependencies to a local directory under `MOVE_HOME` (defaulting to `~/.move`). The caching implementation has two security weaknesses:

**1. No Permission Validation or Enforcement:**

The cache directory is created with default OS permissions, without explicit permission restrictions. [1](#0-0) 

**2. No Integrity Verification on Cache Reuse:**

When a cached package exists, it is reused without any integrity checks (hash verification, timestamp validation, or content verification). [2](#0-1) 

**3. Cache Path Predictability:**

The cache location is deterministically constructed, making it predictable to potential attackers. [3](#0-2) 

**4. Optional Digest Verification:**

Integrity checks via `digest` field are optional in dependency declarations and not enforced for cached packages. [4](#0-3) 

**Attack Scenario:**
1. Developer compiles a Move package with custom Aptos dependencies
2. Package is cached to `~/.move/{node_url}_{address}_{package}/`
3. If the cache directory has insecure permissions (e.g., on shared/multi-user systems, improperly configured development environments, or compromised containers), an attacker with local access could modify cached source files
4. Developer recompiles their package → malicious code from poisoned cache is compiled
5. Malicious code could be deployed to Aptos blockchain

## Impact Explanation

This represents a **supply chain attack vector** that could lead to:
- Malicious Move code being compiled into deployed packages
- Potential theft of funds if the injected code manipulates on-chain assets
- Compromise of smart contract logic in deployed modules

However, **exploitation requires pre-existing conditions**:
- Misconfigured directory permissions (non-default configuration)
- Local access to the victim's system
- Victim rebuilding packages after cache poisoning

While the codebase has proper permission-setting utilities available (`write_to_user_only_file` with mode 0o600), they are not used for package caching. [5](#0-4) 

**Severity Assessment:** This qualifies as **Medium severity** rather than High because:
1. Requires local system access and permission misconfiguration
2. Does not directly compromise Aptos network consensus, validator nodes, or core protocol
3. Attack surface is limited to developer environments with insecure configurations
4. Standard Unix umask provides default protection (directories typically created as 755 or 700)

## Likelihood Explanation

**Likelihood: Low to Medium**

Exploitation requires:
1. **Local access** - Attacker must have access to the victim's development machine
2. **Permission misconfiguration** - Directory must be world-writable or group-writable (not default)
3. **Timing** - Attack must occur between package download and next compilation
4. **No digest verification** - Victim must not use optional `digest` field in Move.toml

More likely in:
- Shared development servers
- Container environments with improper volume permissions
- CI/CD pipelines with weak isolation
- Development machines with compromised user accounts

Less likely in:
- Single-user properly-configured workstations
- Environments using mandatory access control (SELinux, AppArmor)
- Systems where developers use digest verification

## Recommendation

**Immediate Fix:**
1. Set restrictive permissions (0o700) on cache directories upon creation
2. Implement integrity verification for cached packages
3. Add cache validation before reuse

**Proposed Implementation:**

```rust
// In stored_package.rs, save_package_to_disk():
pub fn save_package_to_disk(&self, path: &Path) -> anyhow::Result<()> {
    // Create directory with restrictive permissions
    fs::create_dir_all(path)?;
    
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o700); // Owner read/write/execute only
        fs::set_permissions(path, perms)?;
    }
    
    // Write manifest
    let manifest_content = unzip_metadata_str(&self.metadata.manifest)?;
    fs::write(path.join("Move.toml"), &manifest_content)?;
    
    // Store hash for integrity verification
    let hash = format!("{:x}", md5::compute(&manifest_content));
    fs::write(path.join(".cache_integrity"), hash)?;
    
    // Continue with sources...
}

// In package_hooks.rs, maybe_download_package():
async fn maybe_download_package(info: &CustomDepInfo) -> anyhow::Result<()> {
    let build_info_path = info.download_to.join(CompiledPackageLayout::BuildInfo.path());
    
    if build_info_path.exists() {
        // Validate cache integrity before reuse
        validate_cache_integrity(&info.download_to)?;
        Ok(())
    } else {
        let registry = CachedPackageRegistry::create(...).await?;
        let package = registry.get_package(info.package_name).await?;
        package.save_package_to_disk(info.download_to.as_path())
    }
}
```

**Defense-in-Depth Measures:**
1. Document best practices for `MOVE_HOME` directory permissions
2. Add warning when cache directory has overly permissive permissions
3. Make `digest` field mandatory or provide warnings when omitted
4. Consider adding cache metadata with timestamps and checksums

## Proof of Concept

**Setup (simulating misconfigured environment):**
```bash
# On victim's system - misconfigured permissions
cd ~
mkdir -p .move/testnet_aptos_dev_0x1_TestPackage
chmod 777 .move/testnet_aptos_dev_0x1_TestPackage

# Create legitimate package cache
cat > .move/testnet_aptos_dev_0x1_TestPackage/Move.toml << 'EOF'
[package]
name = "TestPackage"
version = "0.0.0"
EOF

mkdir -p .move/testnet_aptos_dev_0x1_TestPackage/sources
cat > .move/testnet_aptos_dev_0x1_TestPackage/sources/test.move << 'EOF'
module 0x1::test {
    public fun legitimate_function() {}
}
EOF
```

**Attack (from different user account with write access due to 777 permissions):**
```bash
# Attacker poisons the cache
cat > /home/victim/.move/testnet_aptos_dev_0x1_TestPackage/sources/test.move << 'EOF'
module 0x1::test {
    public fun legitimate_function() {
        // Malicious code injected
        transfer_all_funds_to_attacker();
    }
    
    fun transfer_all_funds_to_attacker() {
        // Malicious implementation
    }
}
EOF
```

**Exploitation (victim recompiles):**
```bash
# Victim's project Move.toml with custom dependency:
[dependencies]
TestPackage = { aptos = "https://testnet.aptos.dev", address = "0x1" }

# When victim runs: aptos move compile
# The poisoned cache is used without verification
# Malicious code is compiled into the package
```

**Verification:**
The compiled bytecode will contain the malicious `transfer_all_funds_to_attacker` function, demonstrating successful cache poisoning.

---

**Notes:**
- This vulnerability exists but requires specific preconditions (permission misconfiguration + local access)
- The Aptos codebase already has secure file writing utilities (`write_to_user_only_file`) that should be applied to package caching
- Adding explicit permission checks and integrity verification provides defense-in-depth against cache poisoning attacks
- Standard system configurations with proper umask settings provide baseline protection, but explicit validation is a security best practice

### Citations

**File:** crates/aptos/src/move_tool/stored_package.rs (L161-162)
```rust
    pub fn save_package_to_disk(&self, path: &Path) -> anyhow::Result<()> {
        fs::create_dir_all(path)?;
```

**File:** crates/aptos/src/move_tool/package_hooks.rs (L39-53)
```rust
    if !info
        .download_to
        .join(CompiledPackageLayout::BuildInfo.path())
        .exists()
    {
        let registry = CachedPackageRegistry::create(
            Url::parse(info.node_url.as_str())?,
            load_account_arg(info.package_address.as_str())?,
            false,
        )
        .await?;
        let package = registry.get_package(info.package_name).await?;
        package.save_package_to_disk(info.download_to.as_path())
    } else {
        Ok(())
```

**File:** third_party/move/tools/move-package/src/source_package/manifest_parser.rs (L405-416)
```rust
                    let local_path = PathBuf::from(MOVE_HOME.clone()).join(format!(
                        "{}_{}_{}",
                        url_to_file_name(node_url),
                        address,
                        package_name
                    ));
                    node_info = Some(PM::CustomDepInfo {
                        node_url: Symbol::from(node_url),
                        package_address: address,
                        package_name,
                        download_to: local_path.clone(),
                    });
```

**File:** third_party/move/tools/move-package/src/resolution/resolution_graph.rs (L456-472)
```rust
        match dep.digest {
            None => (),
            Some(fixed_digest) => {
                let resolved_pkg = self
                    .package_table
                    .get(&dep_name_in_pkg)
                    .context("Unable to find resolved package by name")?;
                if fixed_digest != resolved_pkg.source_digest {
                    bail!(
                        "Source digest mismatch in dependency '{}'. Expected '{}' but got '{}'.",
                        dep_name_in_pkg,
                        fixed_digest,
                        resolved_pkg.source_digest
                    )
                }
            },
        }
```

**File:** crates/aptos/src/common/utils.rs (L224-229)
```rust
pub fn write_to_user_only_file(path: &Path, name: &str, bytes: &[u8]) -> CliTypedResult<()> {
    let mut opts = OpenOptions::new();
    #[cfg(unix)]
    opts.mode(0o600);
    write_to_file_with_opts(path, name, bytes, &mut opts)
}
```
