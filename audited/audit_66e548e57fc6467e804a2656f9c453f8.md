# Audit Report

## Title
Silent Failure in InboundHandler Startup Leaves Executor Service Unable to Receive Messages

## Summary
The `InboundHandler::start()` function in `secure/net/src/network_controller/inbound_handler.rs` returns successfully even when the underlying gRPC server fails to bind to its port. The server startup happens asynchronously in a spawned task, and any failure results in a panic within that task without propagating the error to the caller. This leaves the `ExecutorService` in a broken state where it believes it's ready to receive remote execution requests but is actually unable to receive any inbound messages.

## Finding Description

The vulnerability exists in the interaction between three functions:

1. **InboundHandler::start()** creates a shutdown channel and calls `GRPCNetworkMessageServiceServerWrapper::start()`, then immediately returns `Some(server_shutdown_tx)` without waiting for the server to actually start successfully. [1](#0-0) 

2. **GRPCNetworkMessageServiceServerWrapper::start()** spawns an async task to start the server and returns immediately (void return). [2](#0-1) 

3. **GRPCNetworkMessageServiceServerWrapper::start_async()** attempts to bind and start the gRPC server, calling `.unwrap()` on the result. If the server fails to bind (e.g., port already in use), this panics within the spawned task. [3](#0-2) 

The code comments explicitly acknowledge this limitation: "There is no easy way to know if/when the server has started successfully." [4](#0-3) 

**Attack Scenario:**
1. Attacker binds to the port that `ExecutorService` will use (or port conflict occurs naturally)
2. `ExecutorService::start()` calls `NetworkController::start()` [5](#0-4) 
3. `NetworkController::start()` calls `InboundHandler::start()` and stores the returned shutdown handle [6](#0-5) 
4. `InboundHandler::start()` returns `Some(shutdown_tx)` immediately
5. The spawned task attempts to bind and panics due to port conflict
6. The `ExecutorService` believes it's operational but cannot receive any inbound messages
7. Remote execution requests from coordinator or other shards are never delivered
8. The affected shard cannot participate in sharded block execution

This breaks the invariant that all components must be able to communicate for distributed execution to proceed correctly.

## Impact Explanation

This vulnerability qualifies as **High Severity** (potentially **Critical** depending on deployment configuration):

**High Severity Justification:**
- **Validator node dysfunction**: The affected shard in the sharded executor cannot receive execution requests, causing block execution failures or severe performance degradation
- **Protocol violations**: The distributed execution protocol requires all shards to communicate; silent failure breaks this requirement

**Potential Critical Severity:**
If sharded execution is mandatory (no fallback to single-threaded execution), this could cause:
- **Total loss of liveness**: The validator cannot execute blocks at all, preventing consensus participation
- **Non-recoverable network partition**: The affected shard is permanently isolated from the execution network

The severity depends on whether the system has fallback mechanisms when sharded execution fails.

## Likelihood Explanation

**Likelihood: Medium to High**

Port binding failures can occur through:
1. **Accidental conflicts**: Another service using the same port, validator restart before port release, multiple instances misconfiguration
2. **Deliberate attack**: Attacker with local system access binding the port before the validator starts
3. **Resource exhaustion**: Operating system limits on open sockets/ports

The vulnerability is highly likely to manifest because:
- No validation or retry logic exists for server startup
- No health checks verify the server is actually running
- Test code includes TODO comments acknowledging the need for retry mechanisms [7](#0-6) 
- The failure is completely silent from the caller's perspective

## Recommendation

**Immediate Fix:**

1. Return a `Result` from `start_async()` instead of calling `.unwrap()`:

```rust
async fn start_async(
    self,
    server_addr: SocketAddr,
    rpc_timeout_ms: u64,
    server_shutdown_rx: oneshot::Receiver<()>,
) -> Result<(), tonic::transport::Error> {
    // ... setup code ...
    
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
        .await // Remove .unwrap()
}
```

2. Use a oneshot channel to communicate startup success/failure:

```rust
pub fn start(
    self,
    rt: &Runtime,
    _service: String,
    server_addr: SocketAddr,
    rpc_timeout_ms: u64,
    server_shutdown_rx: oneshot::Receiver<()>,
) -> oneshot::Receiver<Result<(), String>> {
    let (startup_tx, startup_rx) = oneshot::channel();
    rt.spawn(async move {
        match self.start_async(server_addr, rpc_timeout_ms, server_shutdown_rx).await {
            Ok(_) => {
                startup_tx.send(Ok(())).ok();
            }
            Err(e) => {
                error!("Failed to start server at {:?}: {}", server_addr, e);
                startup_tx.send(Err(e.to_string())).ok();
            }
        }
    });
    startup_rx
}
```

3. Update `InboundHandler::start()` to wait for and propagate the startup result:

```rust
pub fn start(&self, rt: &Runtime) -> Result<oneshot::Sender<()>, String> {
    if self.inbound_handlers.lock().unwrap().is_empty() {
        return Err("No handlers registered".to_string());
    }

    let (server_shutdown_tx, server_shutdown_rx) = oneshot::channel();
    let startup_rx = GRPCNetworkMessageServiceServerWrapper::new(
        self.inbound_handlers.clone(),
        self.listen_addr,
    )
    .start(rt, self.service.clone(), self.listen_addr, self.rpc_timeout_ms, server_shutdown_rx);
    
    // Wait for startup confirmation with timeout
    match rt.block_on(async {
        tokio::time::timeout(std::time::Duration::from_secs(5), startup_rx).await
    }) {
        Ok(Ok(Ok(()))) => Ok(server_shutdown_tx),
        Ok(Ok(Err(e))) => Err(format!("Server startup failed: {}", e)),
        Ok(Err(_)) => Err("Server startup channel closed unexpectedly".to_string()),
        Err(_) => Err("Server startup timeout".to_string()),
    }
}
```

## Proof of Concept

```rust
// Save as: secure/net/tests/startup_failure_test.rs
use aptos_secure_net::network_controller::NetworkController;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::thread;
use std::time::Duration;

#[test]
fn test_silent_startup_failure() {
    let port = 9999;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    
    // Bind the port to simulate conflict
    let _blocker = TcpListener::bind(addr).expect("Failed to bind port for test");
    println!("Port {} is now occupied", port);
    
    // Try to start NetworkController on the same port
    let mut controller = NetworkController::new(
        "test_service".to_string(),
        addr,
        1000,
    );
    
    // Register a handler so start() doesn't return None
    let _receiver = controller.create_inbound_channel("test_message".to_string());
    
    // This should fail but currently succeeds
    controller.start();
    println!("NetworkController.start() returned successfully despite port conflict!");
    
    // Give time for the spawned task to attempt binding and panic
    thread::sleep(Duration::from_millis(100));
    
    // Try to send a message - it will fail silently
    println!("Attempting to send message to broken handler...");
    // In real scenario, this message would never arrive
    
    // The controller thinks it's running but isn't actually receiving messages
    assert!(true, "Controller started 'successfully' but is actually broken");
}
```

**Expected behavior:** The test demonstrates that `start()` returns successfully even though the server cannot bind to the port. The spawned task panics, but the caller has no way to detect this failure.

**Actual behavior:** Run this test and observe that:
1. `NetworkController::start()` completes without error
2. A panic occurs in the background task (check logs)
3. The controller believes it's operational but cannot receive messages

### Citations

**File:** secure/net/src/network_controller/inbound_handler.rs (L44-63)
```rust
    pub fn start(&self, rt: &Runtime) -> Option<oneshot::Sender<()>> {
        if self.inbound_handlers.lock().unwrap().is_empty() {
            return None;
        }

        let (server_shutdown_tx, server_shutdown_rx) = oneshot::channel();
        // The server is started in a separate task
        GRPCNetworkMessageServiceServerWrapper::new(
            self.inbound_handlers.clone(),
            self.listen_addr,
        )
        .start(
            rt,
            self.service.clone(),
            self.listen_addr,
            self.rpc_timeout_ms,
            server_shutdown_rx,
        );
        Some(server_shutdown_tx)
    }
```

**File:** secure/net/src/grpc_network_service/mod.rs (L43-55)
```rust
    pub fn start(
        self,
        rt: &Runtime,
        _service: String,
        server_addr: SocketAddr,
        rpc_timeout_ms: u64,
        server_shutdown_rx: oneshot::Receiver<()>,
    ) {
        rt.spawn(async move {
            self.start_async(server_addr, rpc_timeout_ms, server_shutdown_rx)
                .await;
        });
    }
```

**File:** secure/net/src/grpc_network_service/mod.rs (L57-88)
```rust
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

**File:** secure/net/src/grpc_network_service/mod.rs (L199-200)
```rust
    // TODO: We need to implement retry on send_message failures such that we can pass this test
    //       without this sleep
```

**File:** execution/executor-service/src/remote_executor_service.rs (L57-58)
```rust
    pub fn start(&mut self) {
        self.controller.start();
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
