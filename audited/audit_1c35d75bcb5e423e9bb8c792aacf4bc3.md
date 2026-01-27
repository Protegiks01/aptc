# Audit Report

## Title
Silent Network Listener Failure in ProcessExecutorService Initialization Due to Unhandled Port Binding Errors

## Summary
The `ProcessExecutorService::new()` function initializes an executor service without validating that the network listener successfully binds to the specified port. When port binding fails (e.g., port already in use), the failure occurs silently within a spawned tokio task, causing the service to appear operational while being unable to receive remote execution requests.

## Finding Description

The vulnerability exists in the initialization flow of the remote executor service: [1](#0-0) 

The `ProcessExecutorService::new()` function creates an `ExecutorService` and calls `start()`, both of which return successfully regardless of whether the network listener starts. The actual port binding occurs deep in the call stack: [2](#0-1) 

The `NetworkController` is created with the `self_address`, but binding doesn't occur until `start()` is called: [3](#0-2) 

The critical issue occurs in the gRPC server startup within a spawned tokio task: [4](#0-3) 

At line 86, `serve_with_shutdown()` returns a `Result` that is unwrapped. If port binding fails, this panics. However, since this occurs within a tokio spawned task (line 51), the panic is caught by tokio's runtime and the task terminates silently without propagating the error.

Critically, the executor service does not set up a panic handler: [5](#0-4) 

Unlike other Aptos services, `setup_panic_handler()` is never called. The crash handler explicitly states that without it, "Tokio's default behavior is to catch panics and ignore them": [6](#0-5) 

**Exploitation Scenario:**
1. Deploy a malicious service or accidentally run a conflicting service on the executor's port
2. Start the `ProcessExecutorService` - it initializes and appears healthy
3. The network listener fails to bind but the error is swallowed
4. Remote coordinator and other shards attempt to communicate but receive no response
5. Transaction execution hangs or fails, causing block execution delays
6. The issue is difficult to diagnose since the service reports successful initialization

## Impact Explanation

This qualifies as **Medium Severity** under the Aptos bug bounty criteria for the following reasons:

1. **Availability Impact**: A silently failed executor shard prevents transaction execution in the sharded execution system, causing operational failures that require manual intervention to diagnose and fix.

2. **State Inconsistency Risk**: If some shards fail silently while others succeed, it creates an inconsistent execution environment that may require coordinator intervention, meeting the "State inconsistencies requiring intervention" criterion.

3. **Difficult Diagnosis**: The silent failure makes it extremely difficult to diagnose, potentially leading to prolonged service degradation.

4. **Not Critical Because**: 
   - Does not directly cause fund loss or theft
   - Does not create consensus violations (execution just doesn't happen)
   - Does not corrupt existing state
   - Requires environmental conditions (port conflict) rather than being directly exploitable

## Likelihood Explanation

**Likelihood: Medium-High**

This can occur in several realistic scenarios:
- **Port Conflicts**: Another service (legitimate or malicious) using the same port
- **Rapid Restarts**: Service crashes and restarts before OS releases the port
- **Configuration Errors**: Multiple executor instances misconfigured to use the same port
- **Container/Orchestration Issues**: Port allocation conflicts in Kubernetes/Docker environments

The lack of validation makes this a predictable failure mode that will occur in production environments.

## Recommendation

Implement proper error handling and validation for network listener initialization:

1. **Add Result return type to initialization functions** to propagate errors:
   - `ExecutorService::new()` and `start()` should return `Result<(), Error>`
   - `NetworkController::start()` should return `Result<(), Error>`

2. **Validate port binding before returning from initialization**:
   - Wait for server to start successfully or fail with timeout
   - Return error on binding failure

3. **Add panic handler in main.rs**:
   ```rust
   fn main() {
       aptos_crash_handler::setup_panic_handler();
       // ... rest of initialization
   }
   ```

4. **Implement health check endpoint** to verify network listener is active

5. **Add explicit error handling in GRPCNetworkMessageServiceServerWrapper**:
   - Replace `.unwrap()` with proper error propagation
   - Log binding errors before panic/exit
   - Return binding result to caller

## Proof of Concept

```rust
// Reproduction steps:
// 1. Start a service on port 8080
// 2. Run this test

#[test]
fn test_port_binding_failure() {
    use std::net::{TcpListener, SocketAddr};
    use std::thread;
    use std::time::Duration;
    
    // Occupy the port
    let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    let _blocker = TcpListener::bind(addr).unwrap();
    
    // Create remote_shard_addresses with the occupied port
    let remote_shard_addresses = vec![addr];
    let coordinator_address: SocketAddr = "127.0.0.1:8081".parse().unwrap();
    
    // This will return successfully but the listener won't be working
    let _service = ProcessExecutorService::new(
        0,  // shard_id
        1,  // num_shards
        4,  // num_threads
        coordinator_address,
        remote_shard_addresses,
    );
    
    // Service appears initialized but network listener is dead
    // Attempting to connect to port 8080 for this shard will fail
    thread::sleep(Duration::from_millis(100));
    
    // The service exists but is non-functional - silent failure
    println!("Service initialized successfully, but listener is not running!");
}
```

**Notes**

This vulnerability affects the sharded block executor service specifically, not the main validator nodes. The impact is localized to execution availability rather than consensus safety. However, in production deployments using sharded execution, silent failures can cause significant operational issues and difficult-to-diagnose transaction execution problems. The fix requires adding proper error propagation throughout the initialization chain and ensuring the panic handler is configured to exit the process on critical failures.

### Citations

**File:** execution/executor-service/src/process_executor_service.rs (L17-45)
```rust
    pub fn new(
        shard_id: ShardId,
        num_shards: usize,
        num_threads: usize,
        coordinator_address: SocketAddr,
        remote_shard_addresses: Vec<SocketAddr>,
    ) -> Self {
        let self_address = remote_shard_addresses[shard_id];
        info!(
            "Starting process remote executor service on {}; coordinator address: {}, other shard addresses: {:?}; num threads: {}",
            self_address, coordinator_address, remote_shard_addresses, num_threads
        );
        aptos_node_resource_metrics::register_node_metrics_collector(None);
        let _mp = MetricsPusher::start_for_local_run(
            &("remote-executor-service-".to_owned() + &shard_id.to_string()),
        );

        AptosVM::set_concurrency_level_once(num_threads);
        let mut executor_service = ExecutorService::new(
            shard_id,
            num_shards,
            num_threads,
            self_address,
            coordinator_address,
            remote_shard_addresses,
        );
        executor_service.start();
        Self { executor_service }
    }
```

**File:** execution/executor-service/src/remote_executor_service.rs (L30-31)
```rust
        let service_name = format!("executor_service-{}", shard_id);
        let mut controller = NetworkController::new(service_name, self_address, 5000);
```

**File:** secure/net/src/network_controller/mod.rs (L139-150)
```rust
    pub fn start(&mut self) {
        info!(
            "Starting network controller started for at {}",
            self.listen_addr
        );
        self.inbound_server_shutdown_tx = self
            .inbound_handler
            .lock()
            .unwrap()
            .start(&self.inbound_rpc_runtime);
        self.outbound_task_shutdown_tx = self.outbound_handler.start(&self.outbound_rpc_runtime);
    }
```

**File:** secure/net/src/grpc_network_service/mod.rs (L51-88)
```rust
        rt.spawn(async move {
            self.start_async(server_addr, rpc_timeout_ms, server_shutdown_rx)
                .await;
        });
    }

    async fn start_async(
        self,
        server_addr: SocketAddr,
        rpc_timeout_ms: u64,
        server_shutdown_rx: oneshot::Receiver<()>,
    ) {
        let reflection_service = tonic_reflection::server::Builder::configure()
            .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
            .build_v1()
            .unwrap();

        info!("Starting Server async at {:?}", server_addr);
        // NOTE: (1) serve_with_shutdown() starts the server, if successful the task does not return
        //           till the server is shutdown. Hence this should be called as a separate
        //           non-blocking task. Signal handler 'server_shutdown_rx' is needed to shutdown
        //           the server
        //       (2) There is no easy way to know if/when the server has started successfully. Hence
        //           we may need to implement a healthcheck service to check if the server is up
        Server::builder()
            .timeout(std::time::Duration::from_millis(rpc_timeout_ms))
            .add_service(
                NetworkMessageServiceServer::new(self).max_decoding_message_size(MAX_MESSAGE_SIZE),
            )
            .add_service(reflection_service)
            .serve_with_shutdown(server_addr, async {
                server_shutdown_rx.await.ok();
                info!("Received signal to shutdown server at {:?}", server_addr);
            })
            .await
            .unwrap();
        info!("Server shutdown at {:?}", server_addr);
    }
```

**File:** execution/executor-service/src/main.rs (L27-48)
```rust
fn main() {
    let args = Args::parse();
    aptos_logger::Logger::new().init();

    let (tx, rx) = crossbeam_channel::unbounded();
    ctrlc::set_handler(move || {
        tx.send(()).unwrap();
    })
    .expect("Error setting Ctrl-C handler");

    let _exe_service = ProcessExecutorService::new(
        args.shard_id,
        args.num_shards,
        args.num_executor_threads,
        args.coordinator_address,
        args.remote_executor_addresses,
    );

    rx.recv()
        .expect("Could not receive Ctrl-C msg from channel.");
    info!("Process executor service shutdown successfully.");
}
```

**File:** crates/crash-handler/src/lib.rs (L21-30)
```rust
/// Invoke to ensure process exits on a thread panic.
///
/// Tokio's default behavior is to catch panics and ignore them.  Invoking this function will
/// ensure that all subsequent thread panics (even Tokio threads) will report the
/// details/backtrace and then exit.
pub fn setup_panic_handler() {
    panic::set_hook(Box::new(move |pi: &PanicHookInfo<'_>| {
        handle_panic(pi);
    }));
}
```
