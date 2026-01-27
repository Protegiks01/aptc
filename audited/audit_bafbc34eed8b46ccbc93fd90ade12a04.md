# Audit Report

## Title
Tokio-Console Debug Feature Exposes Unauthenticated Network-Accessible Validator Runtime Telemetry Enabling Consensus Timing Attacks

## Summary
When the `tokio-console` debug feature is accidentally enabled in production builds, the tokio runtime telemetry server binds to all network interfaces (0.0.0.0) without authentication, exposing sensitive real-time task scheduling data, consensus operation timing, and internal validator state that attackers can use to profile validator behavior, identify performance bottlenecks, and time attacks for maximum impact.

## Finding Description

The tokio-console debugging feature, when enabled, creates a gRPC telemetry server that exposes detailed runtime information about all async tasks in the validator node. The vulnerability has three critical components:

**1. Network Binding to All Interfaces** [1](#0-0) 

The console subscriber binds to `[0, 0, 0, 0]` (0.0.0.0), making it accessible from any network interface rather than restricting it to localhost (127.0.0.1). This means any network attacker who can reach the validator's IP address can connect to the telemetry server.

**2. No Authentication Mechanism**

The console-subscriber library provides no authentication mechanism. Any client that can connect to the port can read all telemetry data. The codebase shows other gRPC services implement TLS and authentication, but tokio-console has no such protections.

**3. Default Port Configuration** [2](#0-1) 

The default port 6669 is predictable and documented in the configuration, making it easy for attackers to discover exposed instances.

**What Information is Exposed:**

The tokio-console protocol (via console-subscriber) exposes:
- Task names, spawn locations, and source file locations
- Task state transitions (idle, busy, polling)
- Poll times, idle times, and total task duration
- Resource contention (Mutex, RwLock, Semaphore, Channel operations)
- Waker events and task scheduling patterns
- Call stacks and execution traces

**Critical Consensus Operations Exposed:**

The consensus subsystem spawns numerous async tasks that would be visible: [3](#0-2) 

Tasks like RoundManager, block retrieval, and recovery manager operations reveal:
- When new consensus rounds start
- When votes are being processed
- When proposals are being created
- Lock contention during critical consensus operations
- Channel message flow patterns indicating network activity
- Task spawn patterns during epoch transitions

**Attack Scenarios:**

1. **Consensus Timing Attacks**: Monitor RoundManager task activity to identify when validators are busy processing votes. Time network attacks or malicious proposals to coincide with peak load periods.

2. **Performance Profiling**: Identify which operations are slow (high poll times) and target those specific code paths with crafted inputs to amplify performance degradation.

3. **Consensus State Inference**: By observing task spawning patterns and activity, infer the current consensus round, epoch state, and voting progress without being a validator.

4. **Lock Contention Exploitation**: Identify mutex/channel contention points and craft transactions or messages that intentionally trigger those contention points to cause validator slowdowns.

5. **Network Pattern Analysis**: Monitor channel activity patterns to infer when the validator is receiving votes from specific peers, potentially enabling targeted network partitioning attacks.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty criteria:

- **"Validator node slowdowns"**: The exposed information directly enables attackers to identify and exploit performance bottlenecks, craft inputs that trigger slow paths, and time attacks for maximum impact on validator performance.

- **"Significant protocol violations"**: While not directly causing protocol violations, the information disclosure materially aids attackers in conducting timing-based attacks that could lead to consensus liveness issues or targeted validator disruption.

The information disclosed goes beyond "minor information leaks" because it provides real-time operational visibility into consensus operations, which are the most security-critical components of the blockchain. This is comparable to exposing internal metrics of a financial system's transaction processing engine.

## Likelihood Explanation

**Likelihood: Medium-High**

The feature requires explicit compilation with `--features tokio-console`, but the scenario is realistic: [4](#0-3) 

**Realistic Scenarios:**

1. **Debug Builds in Production**: Operators compile with debug features during troubleshooting and forget to remove them before redeployment.

2. **Persistent Configuration**: The feature flag is added to a build script or CI/CD configuration and persists across deployments.

3. **Documentation Misunderstanding**: The feature is mentioned in operational documentation without clear warnings about production use.

4. **Default Logging Configuration**: When the feature is enabled, the config sanitizer ensures the port is set: [5](#0-4) 

This means enabling the feature automatically activates the telemetry server with no additional warnings.

**Aggravating Factors:**

- No runtime warning when the feature is active
- Feature is logged but not highlighted as security-sensitive: [6](#0-5) 

- Port binding to 0.0.0.0 cannot be configured to localhost
- No authentication requirement makes exploitation trivial once the port is found

## Recommendation

**Immediate Mitigations:**

1. **Change Default Binding to Localhost**:
   Modify the server binding from `[0, 0, 0, 0]` to `[127, 0, 0, 1]` to restrict access to local debugging only.

2. **Add Configuration Option**:
   Allow operators to specify the binding address in `LoggerConfig`:
   - Add `tokio_console_bind_address` field
   - Default to localhost
   - Validate and warn if binding to public interfaces

3. **Add Runtime Warning**:
   Log a clear security warning when tokio-console is enabled, especially if binding to non-localhost addresses.

4. **Documentation**:
   Add prominent security warnings in configuration documentation about the risks of enabling tokio-console in production.

**Recommended Code Fix:**

```rust
// In config/src/config/logger_config.rs
pub struct LoggerConfig {
    // ... existing fields ...
    pub tokio_console_port: Option<u16>,
    pub tokio_console_bind_address: Option<String>, // New field
}

impl Default for LoggerConfig {
    fn default() -> LoggerConfig {
        LoggerConfig {
            // ... existing defaults ...
            tokio_console_port: None,
            tokio_console_bind_address: Some("127.0.0.1".to_string()), // Localhost only
        }
    }
}

// In crates/aptos-logger/src/logger.rs
#[cfg(feature = "tokio-console")]
{
    if let Some(tokio_console_port) = tokio_console_port {
        // Parse bind address from config or default to localhost
        let bind_addr = parse_bind_address(config_bind_address)
            .unwrap_or([127, 0, 0, 1]);
        
        // Warn if binding to non-localhost
        if bind_addr != [127, 0, 0, 1] {
            error!(
                "SECURITY WARNING: tokio-console is binding to {:?}:{} (non-localhost). \
                This exposes runtime telemetry data on the network without authentication!",
                bind_addr, tokio_console_port
            );
        }
        
        let console_layer = console_subscriber::ConsoleLayer::builder()
            .server_addr((bind_addr, tokio_console_port))
            .spawn();
        
        tracing_subscriber::registry().with(console_layer).init();
        return;
    }
}
```

## Proof of Concept

**Prerequisites:**
- Aptos validator node compiled with `--features tokio-console`
- Node deployed and running
- Network access to validator's IP address

**Exploitation Steps:**

1. **Build and Deploy Vulnerable Configuration**:
```bash
cargo build --release --features tokio-console
# Deploy binary to validator node
# Configure tokio_console_port: 6669 in node config
```

2. **Scan for Exposed Instances**:
```bash
# From attacker machine with network access to validator
nmap -p 6669 <validator-ip>
# Should show port 6669/tcp open
```

3. **Connect with Tokio-Console Client**:
```bash
# Install tokio-console client
cargo install tokio-console

# Connect to exposed validator
tokio-console http://<validator-ip>:6669
```

4. **Observe Sensitive Telemetry**:
The attacker can now see:
    - All active async tasks with names like "round_manager", "block_retrieval", etc.
    - Real-time poll times showing when consensus operations are busy
    - Resource wait times showing lock contention
    - Task spawn patterns indicating epoch transitions
    - Channel activity showing vote/proposal message flow

5. **Profile Consensus Behavior**:
```bash
# Monitor specific tasks
tokio-console http://<validator-ip>:6669 --task-filter "round_manager"

# Record timing patterns over multiple rounds
# Identify peak load periods
# Time subsequent attacks to coincide with busy periods
```

**Expected Result**:
Attacker gains real-time visibility into validator's internal state, consensus round progression, and performance characteristics without authentication, enabling sophisticated timing attacks and performance exploitation.

**Notes**

This vulnerability represents a defense-in-depth failure where a debugging feature designed for local development exposes sensitive operational data when accidentally enabled in production. While it requires the feature to be explicitly compiled in, the lack of security warnings, binding to all interfaces by default, and absence of authentication create a significant attack surface. The exposed telemetry data about consensus operations provides attackers with actionable intelligence for timing sophisticated attacks against validator availability and performance.

### Citations

**File:** crates/aptos-logger/src/logger.rs (L54-63)
```rust
    #[cfg(feature = "tokio-console")]
    {
        if let Some(tokio_console_port) = tokio_console_port {
            let console_layer = console_subscriber::ConsoleLayer::builder()
                .server_addr(([0, 0, 0, 0], tokio_console_port))
                .spawn();

            tracing_subscriber::registry().with(console_layer).init();
            return;
        }
```

**File:** config/src/config/logger_config.rs (L17-37)
```rust
const DEFAULT_TOKIO_CONSOLE_PORT: u16 = 6669;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggerConfig {
    /// Channel size for asynchronous node logging
    pub chan_size: usize,
    /// Enables backtraces on error logs
    pub enable_backtrace: bool,
    /// Use asynchronous logging
    pub is_async: bool,
    /// The default logging level for the logger.
    pub level: Level,
    /// Whether to enable remote telemetry logging
    pub enable_telemetry_remote_log: bool,
    /// Whether to enable remote telemetry logging flushing
    pub enable_telemetry_flush: bool,
    /// Level for telemetry logging
    pub telemetry_level: Level,
    /// Tokio console port for local debugging
    pub tokio_console_port: Option<u16>,
```

**File:** config/src/config/logger_config.rs (L107-118)
```rust
        // Set the tokio console port
        let mut modified_config = false;
        if local_logger_config_yaml["tokio_console_port"].is_null() {
            // If the tokio-console feature is enabled, set the default port.
            // Otherwise, disable the tokio console port.
            if is_tokio_console_enabled() {
                logger_config.tokio_console_port = Some(DEFAULT_TOKIO_CONSOLE_PORT);
            } else {
                logger_config.tokio_console_port = None;
            }
            modified_config = true;
        }
```

**File:** consensus/src/epoch_manager.rs (L993-1000)
```rust
        let (close_tx, close_rx) = oneshot::channel();
        self.round_manager_close_tx = Some(close_tx);
        tokio::spawn(round_manager.start(
            round_manager_rx,
            buffered_proposal_rx,
            opt_proposal_loopback_rx,
            close_rx,
        ));
```

**File:** aptos-node/Cargo.toml (L90-98)
```text
[features]
assert-private-keys-not-cloneable = ["aptos-crypto/assert-private-keys-not-cloneable"]
check-vm-features = []
consensus-only-perf-test = ["aptos-executor/consensus-only-perf-test", "aptos-mempool/consensus-only-perf-test", "aptos-db/consensus-only-perf-test"]
default = []
failpoints = ["fail/failpoints", "aptos-consensus/failpoints", "aptos-executor/failpoints", "aptos-mempool/failpoints", "aptos-api/failpoints", "aptos-config/failpoints"]
indexer = ["aptos-indexer"]
tokio-console = ["aptos-logger/tokio-console", "aptos-config/tokio-console"]
smoke-test = ["aptos-jwk-consensus/smoke-test", "aptos-dkg-runtime/smoke-test"]
```

**File:** aptos-node/src/logger.rs (L75-86)
```rust
    // Log the feature information. Note: this should be kept up-to-date
    // with the features defined in the aptos-node Cargo.toml file.
    info!("Feature information:");
    log_feature_info!(
        "assert-private-keys-not-cloneable",
        "check-vm-features",
        "consensus-only-perf-test",
        "default",
        "failpoints",
        "indexer",
        "tokio-console"
    );
```
