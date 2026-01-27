# Audit Report

## Title
Absence of Privilege Dropping After Initialization in Aptos Node Binary

## Summary
The `aptos-node` binary lacks privilege dropping functionality after completing initialization tasks. If the node is started with elevated privileges (e.g., root), it continues to run with those privileges throughout its lifetime, violating the principle of least privilege and expanding the attack surface.

## Finding Description

The Aptos node entry point begins at `main()` [1](#0-0)  which calls `AptosNodeArgs::parse().run()`. The execution flow proceeds through `run()` [2](#0-1)  to `start_and_report_ports()` [3](#0-2) , which performs initialization including setting resource limits via `ensure_max_open_files_limit()` [4](#0-3) .

During initialization, the node attempts to increase `RLIMIT_NOFILE` hard limits, which may require root privileges [5](#0-4) . After this initialization phase completes and the node begins normal operation, there is no code path that drops privileges (e.g., via `setuid`/`setgid` system calls).

While the Kubernetes deployment configuration includes security contexts that run the node as a non-root user (UID 6180) by default [6](#0-5) , the binary itself contains no privilege separation logic. In scenarios where `enablePrivilegedMode: true` is set [7](#0-6) , or when the node is run outside Kubernetes (e.g., bare metal, Docker without user specification), it may execute with elevated privileges indefinitely.

## Impact Explanation

This is a **defense-in-depth** security issue rather than a direct exploitable vulnerability. The impact manifests only in conjunction with other vulnerabilities:

- If a Remote Code Execution (RCE) vulnerability exists elsewhere in the codebase (consensus, API, mempool, state sync, etc.), an attacker exploiting it would gain root privileges instead of limited user privileges
- The node processes untrusted network input from multiple sources (P2P messages, API requests, transactions), increasing exposure
- All node components (consensus, execution, storage, networking) run with the same elevated privilege level

However, this does **not** directly cause any of the Aptos bug bounty impact categories by itself:
- No loss of funds or consensus violations
- No state inconsistencies or protocol violations  
- No liveness or availability issues

The issue only amplifies the impact of hypothetical future vulnerabilities.

## Likelihood Explanation

**Moderate likelihood** in non-Kubernetes deployments:
- Operators running nodes on bare metal may start as root to bypass system limits
- Docker deployments without explicit user specification run as root by default [8](#0-7) 
- The `enablePrivilegedMode` flag exists for profiling scenarios [7](#0-6) 

**Low likelihood** in production Kubernetes deployments where security contexts enforce non-root execution [9](#0-8) .

## Recommendation

Implement privilege dropping in the node initialization sequence:

1. **Add privilege dropping logic** after initialization tasks complete in `start_and_report_ports()` or `setup_environment_and_start_node()`
2. **Use platform-specific APIs**: On Unix systems, call `setuid()/setgid()` to drop to a non-privileged user after binding sockets and setting resource limits
3. **Configuration support**: Add command-line flags (e.g., `--drop-privileges-user`, `--drop-privileges-group`) to specify the target user/group
4. **Fail-safe**: If started as root without explicit privilege dropping configuration, log a warning or fail to start

Example implementation location: After line 249 in `aptos-node/src/lib.rs` [10](#0-9) , add privilege dropping using the `nix` crate's `setuid`/`setgid` functions.

## Proof of Concept

```bash
# Start node as root
sudo ./target/release/aptos-node -f config.yaml

# In another terminal, check the process owner
ps aux | grep aptos-node
# Shows: root ... aptos-node -f config.yaml

# Verify no privilege dropping occurred throughout runtime
# Process continues running as root indefinitely
```

---

## Notes

**Important Context**: This finding represents a **security hardening opportunity** rather than a directly exploitable vulnerability under the Aptos bug bounty criteria. It does not meet the strict validation requirements because:

1. **No direct exploit path**: The issue requires another vulnerability (RCE, memory corruption, etc.) to be exploited first
2. **No immediate impact**: Running as root alone doesn't cause loss of funds, consensus violations, or protocol failures
3. **Deployment mitigation exists**: Kubernetes security contexts already enforce non-root execution in production deployments

This is analogous to missing AppArmor profiles, seccomp filters, or other defense-in-depth measures—important for security posture but not qualifying as standalone vulnerabilities per the defined impact categories.

The question asks whether privilege dropping occurs, and the factual answer is **no**—but this constitutes a best practice violation rather than an exploitable security flaw under the program's criteria.

### Citations

**File:** aptos-node/src/main.rs (L21-27)
```rust
fn main() {
    // Check that we are not including any Move test natives
    aptos_vm::natives::assert_no_test_natives(ERROR_MSG_BAD_FEATURE_FLAGS);

    // Start the node
    AptosNodeArgs::parse().run()
}
```

**File:** aptos-node/src/lib.rs (L115-188)
```rust
    pub fn run(self) {
        #[cfg(target_os = "linux")]
        // https://sfackler.github.io/rstack/doc/rstack_self/index.html
        //
        // TODO(grao): I don't like this way, but I didn't find other existing solution in Rust.
        // Maybe try to use libc directly?
        if self.stacktrace {
            let _ = rstack_self::child();
            return;
        }

        if self.info {
            let build_information = build_information!();
            println!(
                "{}",
                serde_json::to_string_pretty(&build_information)
                    .expect("Failed to print build information")
            );
            return;
        }

        if self.test {
            println!("WARNING: Entering test mode! This should never be used in production!");
            if self.performance {
                println!("WARNING: Entering performance mode! System utilization may be high!");
            }

            // Set the genesis framework
            let genesis_framework = if let Some(path) = self.genesis_framework {
                ReleaseBundle::read(path).unwrap()
            } else {
                aptos_cached_packages::head_release_bundle().clone()
            };

            // Create a seeded RNG, setup the test environment and start the node
            let rng = self
                .seed
                .map(StdRng::from_seed)
                .unwrap_or_else(StdRng::from_entropy);
            setup_test_environment_and_start_node(
                &self.config,
                &self.test_config_override,
                None,
                self.test_dir,
                self.random_ports,
                self.lazy,
                self.performance,
                &genesis_framework,
                rng,
            )
            .expect("Test node should start correctly!");
        } else {
            // Get the config file path
            let config_path = self.config.expect("Config is required to launch node");
            if !config_path.exists() {
                panic!(
                    "The node config file could not be found! Ensure the given path is correct: {:?}",
                    config_path.display()
                )
            }

            // A config file exists, attempt to parse the config
            let config = NodeConfig::load_from_path(config_path.clone()).unwrap_or_else(|error| {
                panic!(
                    "Failed to load the node config file! Given file path: {:?}. Error: {:?}",
                    config_path.display(),
                    error
                )
            });

            // Start the node
            start(config, None, true).expect("Node should start correctly");
        };
    }
```

**File:** aptos-node/src/lib.rs (L226-289)
```rust
pub fn start_and_report_ports(
    config: NodeConfig,
    log_file: Option<PathBuf>,
    create_global_rayon_pool: bool,
    api_port_tx: Option<oneshot::Sender<u16>>,
    indexer_grpc_port_tx: Option<oneshot::Sender<u16>>,
) -> anyhow::Result<()> {
    // Setup panic handler
    aptos_crash_handler::setup_panic_handler();

    // Create global rayon thread pool
    utils::create_global_rayon_pool(create_global_rayon_pool);

    // Initialize the global aptos-node-identity
    aptos_node_identity::init(config.get_peer_id())?;

    // Instantiate the global logger
    let (remote_log_receiver, logger_filter_update) = logger::create_logger(&config, log_file);

    // Ensure `ulimit -n`.
    ensure_max_open_files_limit(
        config.storage.ensure_rlimit_nofile,
        config.storage.assert_rlimit_nofile,
    );

    assert!(
        !cfg!(feature = "testing") && !cfg!(feature = "fuzzing"),
        "Testing features shouldn't be compiled"
    );

    // Ensure failpoints are configured correctly
    if fail::has_failpoints() {
        warn!("Failpoints are enabled!");

        // Set all of the failpoints
        if let Some(failpoints) = &config.failpoints {
            for (point, actions) in failpoints {
                fail::cfg(point, actions).unwrap_or_else(|_| {
                    panic!(
                        "Failed to set actions for failpoint! Failpoint: {:?}, Actions: {:?}",
                        point, actions
                    )
                });
            }
        }
    } else if config.failpoints.is_some() {
        warn!("Failpoints is set in the node config, but the binary didn't compile with this feature!");
    }

    // Set up the node environment and start it
    let _node_handle = setup_environment_and_start_node(
        config,
        remote_log_receiver,
        Some(logger_filter_update),
        api_port_tx,
        indexer_grpc_port_tx,
    )?;
    let term = Arc::new(AtomicBool::new(false));
    while !term.load(Ordering::Acquire) {
        thread::park();
    }

    Ok(())
}
```

**File:** aptos-node/src/utils.rs (L81-136)
```rust
pub fn ensure_max_open_files_limit(required: u64, assert_success: bool) {
    if required == 0 {
        return;
    }

    // Only works on Unix environments
    #[cfg(unix)]
    {
        if !rlimit::Resource::NOFILE.is_supported() {
            warn!(
                required = required,
                "rlimit setting not supported on this platform. Won't ensure."
            );
            return;
        }

        let (soft, mut hard) = match rlimit::Resource::NOFILE.get() {
            Ok((soft, hard)) => (soft, hard),
            Err(err) => {
                warn!(
                    error = ?err,
                    required = required,
                    "Failed getting RLIMIT_NOFILE. Won't ensure."
                );
                return;
            },
        };

        if soft >= required {
            return;
        }

        if required > hard {
            warn!(
                hard_limit = hard,
                required = required,
                "System RLIMIT_NOFILE hard limit too small."
            );
            // Not panicking right away -- user can be root
            hard = required;
        }

        rlimit::Resource::NOFILE
            .set(required, hard)
            .unwrap_or_else(|err| {
                let msg = format!("RLIMIT_NOFILE soft limit is {soft}, configured requirement is {required}, and \
                    failed to raise to it. Please make sure that `limit -n` shows a number larger than \
                    {required} before starting the node. Error: {err}.");
                if assert_success {
                    panic!("{}", msg)
                } else {
                    error!("{}", msg)
                }
            });
    }
}
```

**File:** terraform/helm/aptos-node/templates/validator.yaml (L217-227)
```yaml
      securityContext:
        {{- if $.Values.enablePrivilegedMode }}
        runAsUser: 0
        runAsGroup: 0
        fsGroup: 0
        {{- else }}
        runAsNonRoot: true
        runAsUser: 6180
        runAsGroup: 6180
        fsGroup: 6180
        {{- end }}
```

**File:** terraform/helm/aptos-node/values.yaml (L193-194)
```yaml
# -- TEST ONLY: Enable running as root for profiling
enablePrivilegedMode: false
```

**File:** docker/builder/validator.Dockerfile (L22-22)
```dockerfile
RUN addgroup --system --gid 6180 aptos && adduser --system --ingroup aptos --no-create-home --uid 6180 aptos
```
