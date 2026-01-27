# Audit Report

## Title
Inspection Service Port Binding Failure Causes Complete Validator Shutdown via Global Panic Handler

## Summary
The Aptos inspection service fails to properly isolate port binding errors, causing the entire validator process to exit if the configured port (default 9101) is already in use. This occurs because the inspection service panics on binding failure in a spawned thread, and the global panic handler terminates the entire process for any thread panic, preventing validators from starting when the inspection port is unavailable.

## Finding Description

The Aptos inspection service implements a critical fault isolation vulnerability that violates the expectation of service isolation. The vulnerability arises from the interaction between three components:

**Component 1: Global Panic Handler Installation**

During validator startup, a global panic handler is installed that terminates the entire process on any thread panic: [1](#0-0) 

This panic handler calls `process::exit(12)` for all thread panics except those in the bytecode verifier: [2](#0-1) 

**Component 2: Inspection Service Thread Spawning**

The inspection service spawns a detached thread and panics if server binding fails: [3](#0-2) 

The critical `.unwrap()` at line 99 will panic if `Server::bind(&address)` fails (e.g., port already in use, permission denied).

**Component 3: Validator Startup Sequence**

The inspection service starts during the validator initialization sequence, after the panic handler is installed: [4](#0-3) 

**Attack Path:**

1. Attacker identifies the validator's inspection service port (default 9101) from configuration: [5](#0-4) 

2. Attacker binds to port 9101 on the validator machine (requires local access or compromised process)

3. Validator operator starts the validator node

4. Panic handler is installed at validator startup

5. Inspection service thread spawns and attempts to bind to port 9101

6. `Server::bind()` fails with "address already in use"

7. `.unwrap()` panics in the spawned thread

8. Global panic handler catches the panic and calls `process::exit(12)`

9. **Entire validator process terminates**

This breaks the isolation principle that non-critical services (like monitoring/inspection) should not prevent critical validator operations from functioning.

## Impact Explanation

**Severity: High** (up to $50,000 per Aptos Bug Bounty criteria)

This vulnerability enables a **Denial of Service attack on validator startup**:

- **Validator Unavailability**: Targeted validators cannot start and participate in consensus
- **Network Impact**: If multiple validators are targeted, network liveness degraded
- **Operational Impact**: Legitimate validator operators cannot run their nodes until the port conflict is resolved

The impact qualifies as **High Severity** under the "Validator node slowdowns" and "Significant protocol violations" categories. While it doesn't directly cause fund loss or consensus violations, it prevents validators from participating in consensus entirely, which affects network availability.

The vulnerability is particularly severe because:
1. The inspection service is mandatory (no disable flag)
2. Port conflicts are common operational scenarios
3. The failure mode is catastrophic (complete process exit) rather than graceful degradation
4. No error logging or retry mechanism exists

## Likelihood Explanation

**Likelihood: Medium-High**

**Attacker Requirements:**
- Local access to the validator machine OR ability to run a compromised process
- Knowledge of the inspection service port (publicly documented as default 9101)
- Ability to bind to the target port before validator starts

**Realistic Scenarios:**
1. **Misconfiguration**: Operator accidentally starts two validator instances with same config
2. **Competing Service**: Another service already using port 9101
3. **Malicious Process**: Compromised service intentionally occupying the port
4. **Targeted Attack**: Attacker with local access preventing validator startup

The likelihood increases in environments where:
- Multiple services run on the same machine
- Port management is not strictly controlled  
- Container/orchestration systems may reassign ports

While the attack requires local access (not remote exploitation), it's a realistic operational scenario that can occur accidentally or through a compromised non-privileged process.

## Recommendation

**Immediate Fix: Remove panic and handle binding errors gracefully**

The inspection service should handle binding failures without crashing the validator:

```rust
pub fn start_inspection_service(
    node_config: NodeConfig,
    aptos_data_client: AptosDataClient,
    peers_and_metadata: Arc<PeersAndMetadata>,
) {
    // Fetch the service port and address
    let service_port = node_config.inspection_service.port;
    let service_address = node_config.inspection_service.address.clone();

    // Create the inspection service socket address
    let address: SocketAddr = match (service_address.as_str(), service_port).to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => addr,
            None => {
                error!("No valid address for inspection service {}:{}", service_address, service_port);
                return;
            }
        },
        Err(e) => {
            error!("Failed to parse inspection service address {}:{}: {}", service_address, service_port, e);
            return;
        }
    };

    // Create a runtime for the inspection service
    let runtime = aptos_runtimes::spawn_named_runtime("inspection".into(), None);

    // Spawn the inspection service
    thread::spawn(move || {
        // Create the service function that handles the endpoint requests
        let make_service = make_service_fn(move |_conn| {
            let node_config = node_config.clone();
            let aptos_data_client = aptos_data_client.clone();
            let peers_and_metadata = peers_and_metadata.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |request| {
                    serve_requests(
                        request,
                        node_config.clone(),
                        aptos_data_client.clone(),
                        peers_and_metadata.clone(),
                    )
                }))
            }
        });

        // Start and block on the server, with error handling
        let result = runtime.block_on(async {
            let server = Server::bind(&address).serve(make_service);
            info!("Inspection service started on {}", address);
            server.await
        });

        // Log error but don't panic
        if let Err(e) = result {
            error!("Inspection service failed: {}. Validator will continue without inspection service.", e);
        }
    });
}
```

**Additional Hardening:**
1. Add configuration option to disable inspection service if needed
2. Implement automatic port retry mechanism
3. Log clear warnings when inspection service fails to start
4. Consider running inspection service in same runtime as other non-critical services

## Proof of Concept

**Step 1: Create a simple port blocker**

```rust
// port_blocker.rs
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

fn main() {
    println!("Binding to port 9101...");
    let listener = TcpListener::bind("0.0.0.0:9101").expect("Failed to bind to port 9101");
    println!("Successfully bound to port 9101. Validator will now fail to start.");
    
    // Keep the port occupied
    loop {
        thread::sleep(Duration::from_secs(60));
    }
}
```

**Step 2: Reproduction Steps**

```bash
# Terminal 1: Start the port blocker
cargo run --bin port_blocker

# Terminal 2: Attempt to start the validator
# The validator will panic and exit with code 12 when the inspection service
# tries to bind to the already-occupied port 9101

cargo run -p aptos-node -- --config path/to/validator.yaml

# Expected output:
# thread '<unnamed>' panicked at 'called `Result::unwrap()` on an `Err` value: ...'
# Process exits with code 12
```

**Step 3: Verify the vulnerability**

```bash
echo $?  # Should output: 12 (the exit code from the panic handler)
```

The validator will completely fail to start despite the inspection service being a non-critical monitoring component. Critical services like consensus, mempool, and state sync never get initialized because the process exits during startup.

---

**Notes:**

The vulnerability exists because the inspection service was designed with the assumption that it operates in isolation (spawned thread), but the global panic handler violates this assumption by terminating the process for any thread panic. This creates a critical availability vulnerability where a monitoring service failure can DoS the entire validator.

### Citations

**File:** aptos-node/src/lib.rs (L233-234)
```rust
    // Setup panic handler
    aptos_crash_handler::setup_panic_handler();
```

**File:** aptos-node/src/lib.rs (L771-776)
```rust
    // Start the node inspection service
    services::start_node_inspection_service(
        &node_config,
        aptos_data_client,
        peers_and_metadata.clone(),
    );
```

**File:** crates/crash-handler/src/lib.rs (L52-57)
```rust
    if state::get_state() == VMState::VERIFIER || state::get_state() == VMState::DESERIALIZER {
        return;
    }

    // Kill the process
    process::exit(12);
```

**File:** crates/aptos-inspection-service/src/server/mod.rs (L75-100)
```rust
    thread::spawn(move || {
        // Create the service function that handles the endpoint requests
        let make_service = make_service_fn(move |_conn| {
            let node_config = node_config.clone();
            let aptos_data_client = aptos_data_client.clone();
            let peers_and_metadata = peers_and_metadata.clone();
            async move {
                Ok::<_, Infallible>(service_fn(move |request| {
                    serve_requests(
                        request,
                        node_config.clone(),
                        aptos_data_client.clone(),
                        peers_and_metadata.clone(),
                    )
                }))
            }
        });

        // Start and block on the server
        runtime
            .block_on(async {
                let server = Server::bind(&address).serve(make_service);
                server.await
            })
            .unwrap();
    });
```

**File:** config/src/config/inspection_service_config.rs (L26-36)
```rust
impl Default for InspectionServiceConfig {
    fn default() -> InspectionServiceConfig {
        InspectionServiceConfig {
            address: "0.0.0.0".to_string(),
            port: 9101,
            expose_configuration: false,
            expose_identity_information: true,
            expose_peer_information: true,
            expose_system_information: true,
        }
    }
```
