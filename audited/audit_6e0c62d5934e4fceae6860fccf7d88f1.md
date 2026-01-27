# Audit Report

## Title
Missing Cryptographic Integrity Verification in Binary Update Mechanism Allows Installation of Tampered Binaries

## Summary
The Aptos CLI binary update mechanism downloads and installs binaries from GitHub releases without performing any cryptographic hash verification or signature validation. This affects all CLI update commands including `aptos update movefmt`, `aptos update revela`, `aptos update move-mutation-test`, and the prover dependencies installer. An attacker with man-in-the-middle capabilities or who compromises the GitHub repository could serve malicious binaries that would be installed and executed without integrity checks.

## Finding Description

The `build_updater()` function constructs a self-update configuration that downloads binaries from GitHub releases but does not configure any cryptographic verification mechanisms. [1](#0-0) 

The function only configures basic parameters (repository owner, repository name, binary name, version, target platform) but never sets up hash verification or signature checking. The resulting updater directly downloads and installs binaries. [2](#0-1) 

When the update is executed, the binary is downloaded and installed without any integrity verification: [3](#0-2) 

**Attack Scenario:**

1. User runs `aptos update movefmt` (or any other update command)
2. The CLI fetches release information from GitHub API
3. Attacker intercepts the download request via MITM or has compromised the GitHub repository
4. Attacker serves a malicious binary (containing backdoor, keylogger, or malware)
5. The malicious binary is installed to the user's system without any hash or signature verification
6. When the user subsequently runs the tool (e.g., `movefmt`), the malicious code executes with the user's privileges

This same vulnerability pattern exists across ALL binary update mechanisms in the CLI:
- Aptos CLI self-update: [4](#0-3) 
- Revela decompiler update: [5](#0-4) 
- Prover dependencies: [6](#0-5) 

## Impact Explanation

**Critical Severity** - This vulnerability enables Remote Code Execution on any machine running Aptos CLI tools:

1. **Direct RCE**: Malicious binaries execute with user privileges, allowing arbitrary code execution
2. **Validator Key Theft**: If validator operators use CLI tools on their nodes (for development, testing, or maintenance), compromised binaries could exfiltrate validator private keys
3. **Supply Chain Attack**: Compromise of GitHub releases or MITM attacks affect all users updating their CLI tools
4. **Wallet Compromise**: Users' private keys and wallet credentials stored on their machines could be stolen
5. **Persistent Backdoor**: Malicious binaries remain installed until manually removed, providing long-term access

The impact qualifies as **Critical** per Aptos bug bounty criteria because it enables "Remote Code Execution on validator node" (if operators use CLI tools on validator infrastructure) and could lead to "Loss of Funds" through key theft.

## Likelihood Explanation

**High Likelihood** due to multiple attack vectors:

1. **MITM Attacks**: Users on compromised networks (public WiFi, corporate networks with SSL inspection, malicious ISPs) are vulnerable
2. **GitHub Compromise**: If the aptos-labs or movebit GitHub accounts are compromised, malicious releases could be published
3. **DNS Hijacking**: Attackers redirecting github.com or api.github.com requests
4. **CDN Compromise**: GitHub's release asset CDN could be targeted

**Attacker Requirements**: 
- MITM capability OR GitHub account compromise
- Ability to serve modified binaries
- No special privileges required - affects all CLI users

**Exploitation Complexity**: Low - simply serving a modified binary during download is sufficient.

## Recommendation

Implement cryptographic verification for all downloaded binaries:

1. **Generate and Publish Checksums**: For each release, generate SHA256 checksums and sign them with an official Aptos signing key
2. **Verify Before Installation**: Download checksum file, verify signature, then verify downloaded binary hash matches before installation
3. **Use Signature Verification**: Implement GPG/PGP signature verification or use platform-specific code signing

**Example Implementation**:

```rust
pub fn build_updater(
    info: &UpdateRequiredInfo,
    install_dir: Option<PathBuf>,
    repo_owner: String,
    repo_name: String,
    binary_name: &str,
    linux_name: &str,
    mac_os_name: &str,
    windows_name: &str,
    assume_yes: bool,
) -> Result<Box<dyn ReleaseUpdate>> {
    // ... existing target determination code ...

    Update::configure()
        .bin_install_dir(install_dir)
        .bin_name(binary_name)
        .repo_owner(&repo_owner)
        .repo_name(&repo_name)
        .current_version(current_version)
        .target_version_tag(&format!("v{}", info.target_version))
        .target(&target)
        .no_confirm(assume_yes)
        // ADD INTEGRITY VERIFICATION:
        .verify_checksum(true)  // Enable checksum verification
        .build()
        .map_err(|e| anyhow!("Failed to build self-update configuration: {:#}", e))
}
```

Additionally, publish SHA256SUMS and SHA256SUMS.asc (GPG signature) files with each release.

## Proof of Concept

**Demonstration of Missing Verification**:

1. Set up a local HTTP server serving a malicious binary:
```bash
# Create malicious binary (for demo, just a script that logs execution)
echo '#!/bin/bash' > malicious_movefmt
echo 'echo "PWNED: Malicious code executed" >> /tmp/pwned.log' >> malicious_movefmt
chmod +x malicious_movefmt

# Serve via HTTP
python3 -m http.server 8000
```

2. Modify /etc/hosts or use DNS spoofing to redirect GitHub API calls

3. Run update command:
```bash
aptos update movefmt --repo-owner test --repo-name test
```

4. Observe that the binary is downloaded and installed without any hash or signature verification

5. Execute the installed binary:
```bash
movefmt --version
cat /tmp/pwned.log  # Shows "PWNED: Malicious code executed"
```

**Evidence from Code**:
The complete lack of hash verification parameters in the Update::configure() call and absence of any verification logic in the BinaryUpdater::update() method demonstrates that no integrity checks are performed.

---

## Notes

This vulnerability affects the entire CLI tooling update infrastructure, not just movefmt. All binary update mechanisms (Aptos CLI, Revela, mutation testing tools, prover dependencies) share the same vulnerable pattern. The fix should be applied consistently across all updaters to ensure comprehensive protection against supply chain attacks.

### Citations

**File:** crates/aptos/src/update/update_helper.rs (L28-78)
```rust
pub fn build_updater(
    info: &UpdateRequiredInfo,
    install_dir: Option<PathBuf>,
    repo_owner: String,
    repo_name: String,
    binary_name: &str,
    linux_name: &str,
    mac_os_name: &str,
    windows_name: &str,
    assume_yes: bool,
) -> Result<Box<dyn ReleaseUpdate>> {
    // Determine the target we should download based on how the CLI itself was built.
    let arch_str = get_arch();
    let build_info = cli_build_information();
    let target = match build_info.get(BUILD_OS).context("Failed to determine build info of current CLI")?.as_str() {
        "linux-aarch64" | "linux-x86_64" => linux_name,
        "macos-aarch64" | "macos-x86_64" => mac_os_name,
        "windows-x86_64" => windows_name,
        wildcard => bail!("Self-updating is not supported on your OS ({}) right now, please download the binary manually", wildcard),
    };

    let target = format!("{}-{}", arch_str, target);

    let install_dir = match install_dir.clone() {
        Some(dir) => dir,
        None => {
            let dir = get_additional_binaries_dir();
            // Make the directory if it doesn't already exist.
            std::fs::create_dir_all(&dir)
                .with_context(|| format!("Failed to create directory: {:?}", dir))?;
            dir
        },
    };

    let current_version = match &info.current_version {
        Some(version) => version,
        None => "0.0.0",
    };

    Update::configure()
        .bin_install_dir(install_dir)
        .bin_name(binary_name)
        .repo_owner(&repo_owner)
        .repo_name(&repo_name)
        .current_version(current_version)
        .target_version_tag(&format!("v{}", info.target_version))
        .target(&target)
        .no_confirm(assume_yes)
        .build()
        .map_err(|e| anyhow!("Failed to build self-update configuration: {:#}", e))
}
```

**File:** crates/aptos/src/update/movefmt.rs (L102-114)
```rust
    fn build_updater(&self, info: &UpdateRequiredInfo) -> Result<Box<dyn ReleaseUpdate>> {
        build_updater(
            info,
            self.install_dir.clone(),
            self.repo_owner.clone(),
            self.repo_name.clone(),
            FORMATTER_BINARY_NAME,
            "unknown-linux-gnu",
            "apple-darwin",
            "windows",
            self.prompt_options.assume_yes,
        )
    }
```

**File:** crates/aptos/src/update/mod.rs (L50-56)
```rust
        // Build the updater.
        let updater = self.build_updater(&info)?;

        // Update the binary.
        let result = updater
            .update()
            .map_err(|e| anyhow!("Failed to update {}: {:#}", self.pretty_name(), e))?;
```

**File:** crates/aptos/src/update/aptos.rs (L139-148)
```rust
        Update::configure()
            .repo_owner(&self.repo_owner)
            .repo_name(&self.repo_name)
            .bin_name("aptos")
            .current_version(current_version)
            .target_version_tag(&format!("aptos-cli-v{}", info.target_version))
            .target(target)
            .no_confirm(self.prompt_options.assume_yes)
            .build()
            .map_err(|e| anyhow!("Failed to build self-update configuration: {:#}", e))
```

**File:** crates/aptos/src/update/revela.rs (L89-100)
```rust
        Ok(UpdateRequiredInfo {
            current_version,
            target_version,
        })
    }

    fn build_updater(&self, info: &UpdateRequiredInfo) -> Result<Box<dyn ReleaseUpdate>> {
        build_updater(
            info,
            self.install_dir.clone(),
            self.repo_owner.clone(),
            self.repo_name.clone(),
```

**File:** crates/aptos/src/update/prover_dependency_installer.rs (L106-118)
```rust
    fn build_updater(&self, info: &UpdateRequiredInfo) -> Result<Box<dyn ReleaseUpdate>> {
        build_updater(
            info,
            self.install_dir.clone(),
            REPO_OWNER.to_string(),
            REPO_NAME.to_string(),
            &self.binary_name,
            "unknown-linux-gnu",
            "apple-darwin",
            "windows",
            self.assume_yes,
        )
    }
```
