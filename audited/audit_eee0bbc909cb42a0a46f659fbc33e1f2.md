# Audit Report

## Title
Race Condition in NetworkController Async Task Initialization Causes Execution Failures in Sharded Block Executor

## Summary
The `NetworkController::start()` function spawns async tasks for gRPC server initialization but returns immediately without waiting for the server to be ready to accept connections. This creates a race condition where the remote executor client may attempt to send execution commands before the server is listening, causing block execution failures and validator slowdowns.

## Finding Description

The vulnerability exists in the network controller's initialization sequence used by the remote executor service. When `NetworkController::start()` is called, it spawns async tasks to start the gRPC server but returns control immediately: [1](#0-0) 

The `InboundHandler::start()` method spawns the gRPC server asynchronously without blocking: [2](#0-1) 

The actual server initialization happens in a spawned task that may not complete before the caller continues execution: [3](#0-2) 

The code explicitly acknowledges this limitation with a critical comment: [4](#0-3) 

**Production Impact**: The `RemoteExecutorClient` uses this NetworkController for sharded block execution. It calls `start()` and immediately begins using the network channels: [5](#0-4) 

If execution commands are sent before the server binds to its socket, connection attempts will fail, causing block execution to fail. This breaks the **Deterministic Execution** invariant (#1) as different validators may experience different execution outcomes based on timing.

**Test Evidence**: The codebase's own tests confirm this race condition with explicit sleep statements: [6](#0-5) [7](#0-6) 

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty criteria:

1. **Validator Node Slowdowns**: When the race condition triggers, execution commands fail and must be retried, causing significant delays in block execution
2. **Execution Failures**: Critical sharded execution operations can fail entirely during startup or restart scenarios
3. **Protocol Violations**: Non-deterministic execution failures violate the requirement that all validators process blocks identically

The impact is amplified because:
- The remote executor service is used for parallel block execution across shards
- Multiple validators restarting simultaneously (e.g., after an upgrade) will all hit this race window
- Failed execution attempts can cascade, causing cumulative delays

While this doesn't directly cause fund loss or consensus breaks, it significantly degrades validator performance and can cause temporary execution unavailability, meeting the High severity threshold.

## Likelihood Explanation

**Likelihood: HIGH**

This race condition will occur with high probability under the following conditions:

1. **Every Startup**: The race window exists during every NetworkController initialization
2. **High System Load**: Under CPU or I/O pressure, async task scheduling delays increase the race window
3. **Coordinated Restarts**: Network upgrades causing simultaneous validator restarts amplify the impact
4. **Resource Contention**: Multiple services competing for tokio runtime threads extend the race window

The test code requiring explicit `sleep()` calls demonstrates this happens reliably without synchronization. The race window may be small on idle systems but becomes significant under production load.

## Recommendation

Implement a synchronization mechanism to ensure the gRPC server is ready before `start()` returns. Use a oneshot channel to signal server readiness:

**Modified `GRPCNetworkMessageServiceServerWrapper::start_async()`:**
```rust
async fn start_async(
    self,
    server_addr: SocketAddr,
    rpc_timeout_ms: u64,
    server_shutdown_rx: oneshot::Receiver<()>,
    ready_tx: oneshot::Sender<()>, // NEW: readiness signal
) {
    let reflection_service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
        .build_v1()
        .unwrap();

    info!("Starting Server async at {:?}", server_addr);
    
    let server = Server::builder()
        .timeout(std::time::Duration::from_millis(rpc_timeout_ms))
        .add_service(
            NetworkMessageServiceServer::new(self).max_decoding_message_size(MAX_MESSAGE_SIZE),
        )
        .add_service(reflection_service);
    
    // Bind to address to start listening
    let incoming = match server.into_service().bind(server_addr).await {
        Ok(bound) => {
            // Signal readiness AFTER successful bind
            ready_tx.send(()).ok();
            bound
        },
        Err(e) => {
            error!("Failed to bind server to {:?}: {}", server_addr, e);
            return;
        }
    };
    
    // Now serve with shutdown signal
    incoming.serve_with_shutdown(async {
        server_shutdown_rx.await.ok();
        info!("Received signal to shutdown server at {:?}", server_addr);
    }).await.unwrap();
    
    info!("Server shutdown at {:?}", server_addr);
}
```

**Modified `InboundHandler::start()`:**
```rust
pub fn start(&self, rt: &Runtime) -> Option<oneshot::Sender<()>> {
    if self.inbound_handlers.lock().unwrap().is_empty() {
        return None;
    }

    let (server_shutdown_tx, server_shutdown_rx) = oneshot::channel();
    let (ready_tx, ready_rx) = oneshot::channel(); // NEW: readiness channel
    
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
        ready_tx, // NEW: pass readiness sender
    );
    
    // Block until server is ready
    rt.block_on(async {
        ready_rx.await.expect("Server failed to start")
    });
    
    Some(server_shutdown_tx)
}
```

This ensures `start()` only returns after the server has successfully bound to its socket and is ready to accept connections.

## Proof of Concept

The existing test code demonstrates the vulnerability. Remove the sleep to reproduce the race condition:

```rust
#[test]
fn test_race_condition() {
    let server_port1 = utils::get_available_port();
    let server_addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port1);
    
    let server_port2 = utils::get_available_port();
    let server_addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), server_port2);
    
    let mut network_controller1 =
        NetworkController::new("test1".to_string(), server_addr1, 1000);
    let mut network_controller2 =
        NetworkController::new("test2".to_string(), server_addr2, 1000);
    
    let test1_sender =
        network_controller2.create_outbound_channel(server_addr1, "test1".to_string());
    let test1_receiver = network_controller1.create_inbound_channel("test1".to_string());
    
    network_controller1.start();
    network_controller2.start();
    
    // REMOVED: thread::sleep() - this will now fail intermittently
    
    let test1_message = "test1".as_bytes().to_vec();
    test1_sender
        .send(Message::new(test1_message.clone()))
        .unwrap();
    
    // This will panic/timeout due to connection failure if race occurs
    let received = test1_receiver.recv_timeout(Duration::from_millis(100));
    assert!(received.is_ok(), "Race condition: server not ready");
}
```

Run this test multiple times under load to observe intermittent failures when the gRPC server hasn't finished binding before messages are sent.

## Notes

The vulnerability is documented in the codebase itself through TODO comments and explicit sleep statements in tests, indicating the developers were aware of the issue but have not implemented a proper fix. The impact extends to critical execution infrastructure (RemoteExecutorClient) used in sharded block execution, making this a priority fix for production validator reliability.

### Citations

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

**File:** secure/net/src/network_controller/mod.rs (L199-204)
```rust
        network_controller1.start();
        network_controller2.start();

        // wait for the server to be ready to serve
        // TODO: We need to pass this test without this sleep
        thread::sleep(std::time::Duration::from_millis(100));
```

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

**File:** secure/net/src/grpc_network_service/mod.rs (L69-74)
```rust
        // NOTE: (1) serve_with_shutdown() starts the server, if successful the task does not return
        //           till the server is shutdown. Hence this should be called as a separate
        //           non-blocking task. Signal handler 'server_shutdown_rx' is needed to shutdown
        //           the server
        //       (2) There is no easy way to know if/when the server has started successfully. Hence
        //           we may need to implement a healthcheck service to check if the server is up
```

**File:** secure/net/src/grpc_network_service/mod.rs (L198-201)
```rust
    // wait for the server to be ready before sending messages
    // TODO: We need to implement retry on send_message failures such that we can pass this test
    //       without this sleep
    thread::sleep(std::time::Duration::from_millis(10));
```

**File:** execution/executor-service/src/remote_executor_client.rs (L134-134)
```rust
        controller.start();
```
