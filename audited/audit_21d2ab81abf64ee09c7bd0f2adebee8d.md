# Audit Report

## Title
Path Traversal Vulnerability in CLI Binary Installation via Empty Environment Variables

## Summary
The `get_additional_binaries_dir()` function in the Aptos CLI returns a relative path when the `HOME` (Unix) or `USERPROFILE` (Windows) environment variables are empty, allowing an attacker who controls the working directory to redirect binary installation to an attacker-controlled location, potentially leading to arbitrary code execution.

## Finding Description

The vulnerability exists in the `get_additional_binaries_dir()` function: [1](#0-0) 

When the `HOME` or `USERPROFILE` environment variable is empty, the function constructs a path starting with an empty string, resulting in relative paths:
- Unix: `.local/bin` (relative path)
- Windows: `.aptoscli/bin` (relative path)

This relative path is used when installing prover dependencies (boogie, z3, cvc5): [2](#0-1) 

The binaries are then installed to this relative directory: [3](#0-2) 

Environment variables are set to point to these installed binaries: [4](#0-3) 

These binaries are later executed when running the Move prover: [5](#0-4) [6](#0-5) 

**Attack Scenario:**
1. Attacker tricks a user/operator into running the Aptos CLI in an attacker-controlled directory
2. The user's environment has an empty `HOME`/`USERPROFILE` variable (uncommon but possible in containers, CI/CD, or misconfigured systems)
3. User runs `aptos update install-prover-deps`
4. Binaries are installed to `.local/bin` or `.aptoscli/bin` relative to the attacker-controlled directory
5. Attacker places malicious binaries in these relative paths
6. When the user later runs Move prover commands, the malicious binaries are executed

## Impact Explanation

**This is a CLI tool vulnerability, NOT a blockchain security vulnerability.**

While this vulnerability could theoretically lead to code execution on a user's or validator operator's machine, it does NOT meet the Aptos bug bounty severity criteria because:

- **Does NOT affect blockchain consensus, state, or funds**
- **Does NOT cause validator node compromise** (requires operator negligence)
- **Does NOT impact network availability or liveness**
- **Does NOT violate any blockchain invariants**

This would only qualify as **High Severity** if it could lead to validator node compromise through realistic attack paths. However, the attack requires:
- Empty environment variables (extremely rare in production)
- Operator running CLI in attacker-controlled directory (severe negligence)
- Installing and running prover (specific workflow)

This does not meet the "Remote Code Execution on validator node" criteria for Critical severity, as it requires multiple layers of operator error rather than being a direct vulnerability exploitable against validators.

## Likelihood Explanation

**Low Likelihood** - Requires multiple uncommon preconditions:
1. `HOME`/`USERPROFILE` environment variable must be empty (very rare in normal systems)
2. Attacker must control the working directory when CLI is executed
3. User must install prover dependencies in this compromised environment
4. User must subsequently run the Move prover

Normal production validator environments have properly configured environment variables, making this scenario highly unlikely.

## Recommendation

Add validation to ensure paths are absolute before using them for binary installation:

```rust
pub fn get_additional_binaries_dir() -> Result<PathBuf> {
    #[cfg(windows)]
    let home_dir = std::env::var("USERPROFILE")
        .context("USERPROFILE environment variable not set")?;
    
    #[cfg(not(windows))]
    let home_dir = std::env::var("HOME")
        .context("HOME environment variable not set")?;
    
    if home_dir.is_empty() {
        anyhow::bail!("Home directory environment variable is empty");
    }
    
    let path = PathBuf::from(home_dir);
    if !path.is_absolute() {
        anyhow::bail!("Home directory path must be absolute, got: {}", path.display());
    }
    
    #[cfg(windows)]
    return Ok(path.join(".aptoscli/bin"));
    
    #[cfg(not(windows))]
    return Ok(path.join(".local/bin"));
}
```

## Proof of Concept

```bash
# Demonstrate the vulnerability
unset HOME  # Or unset USERPROFILE on Windows
mkdir attacker_controlled_dir
cd attacker_controlled_dir

# Run the CLI - binaries would be installed to ./local/bin
# instead of ~/.local/bin
aptos update install-prover-deps

# The binaries are now installed relative to current directory
ls .local/bin  # Shows installed binaries in attacker's directory
```

---

**CONCLUSION:** While this is a legitimate code quality and CLI security issue that should be fixed, it does **NOT** qualify as a valid Aptos blockchain security vulnerability per the bug bounty program criteria. It does not affect consensus, state integrity, funds on-chain, or network availability. The impact is limited to individual CLI users/operators who run the tool in highly unusual and negligent configurations.

**Notes:**
- This is a **client-side** vulnerability, not a **blockchain** vulnerability
- Does not meet the strict criteria for Aptos bug bounty submission
- Should still be fixed as a security hardening measure for the CLI tool
- The fix is straightforward: validate environment variables are set and paths are absolute

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

**File:** crates/aptos/src/update/prover_dependencies.rs (L105-114)
```rust
        let install_dir = match self.install_dir.clone() {
            Some(dir) => dir,
            None => {
                let dir = get_additional_binaries_dir();
                // Make the directory if it doesn't already exist.
                std::fs::create_dir_all(&dir)
                    .with_context(|| format!("Failed to create directory: {:?}", dir))?;
                dir
            },
        };
```

**File:** crates/aptos/src/update/prover_dependencies.rs (L202-206)
```rust
        let install_dir = install_dir.join(exe_name);
        if let Err(err) = self.add_env_var(env_name, &install_dir) {
            eprintln!("{:#}. Please set it manually", err);
        }
        Ok(result)
```

**File:** crates/aptos/src/update/update_helper.rs (L51-59)
```rust
    let install_dir = match install_dir.clone() {
        Some(dir) => dir,
        None => {
            let dir = get_additional_binaries_dir();
            // Make the directory if it doesn't already exist.
            std::fs::create_dir_all(&dir)
                .with_context(|| format!("Failed to create directory: {:?}", dir))?;
            dir
        },
```

**File:** third_party/move/move-prover/boogie-backend/src/prover_task_runner.rs (L189-198)
```rust
        let args = self
            .get_boogie_command(task_id)
            .map_err(std::io::Error::other)?;
        debug!("running Boogie command with seed {}", task_id);
        Command::new(&args[0])
            .args(&args[1..])
            .kill_on_drop(true)
            .output()
            .await
    }
```

**File:** third_party/move/move-prover/boogie-backend/src/options.rs (L243-254)
```rust
    pub fn get_boogie_command(&self, boogie_file: &str) -> anyhow::Result<Vec<String>> {
        let mut result = if self.use_exp_boogie {
            // This should have a better ux...
            vec![read_env_var("EXP_BOOGIE_EXE")]
        } else {
            vec![self.boogie_exe.clone()]
        };

        // If we don't have a boogie executable, nothing will work
        if result.iter().all(|path| path.is_empty()) {
            anyhow::bail!("No boogie executable set.  Please set BOOGIE_EXE");
        }
```
