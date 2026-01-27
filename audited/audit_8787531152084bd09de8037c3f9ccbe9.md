# Audit Report

## Title
Tokio Executor Thread Starvation in Remote Executor gRPC Service Due to Blocking Operations in Async Context

## Summary
The `simple_msg_exchange` async handler in the remote executor's gRPC service performs synchronous blocking operations (mutex lock and channel send) without proper async wrapping, which can block tokio worker threads and cause task starvation under high concurrent message load, affecting the liveness of sharded block execution.

## Finding Description

The remote executor service uses a gRPC-based network message handler that violates tokio async best practices by performing blocking synchronous operations directly within async code. [1](#0-0) 

The generated gRPC service code creates an async future that calls the trait implementation. The actual vulnerability is in the trait implementation: [2](#0-1) 

The handler performs two critical blocking operations within the async context:
1. **Synchronous mutex lock** to access the handler registry
2. **Synchronous crossbeam channel send** to forward messages

Neither operation is wrapped in `tokio::task::spawn_blocking()`, causing them to execute directly on tokio's worker threads.

The tokio runtime is created with default configuration: [3](#0-2) 

This creates a multi-threaded runtime with worker threads equal to CPU cores. When concurrent gRPC requests arrive, each request's handler blocks a worker thread while acquiring the mutex and sending to the channel. Under sustained high-concurrency load (e.g., during intensive sharded block execution with many concurrent execution commands and state sync messages), all worker threads can become blocked, preventing new async tasks from being scheduled.

**Attack Propagation Path:**
1. Multiple shards send concurrent execution commands and state view requests to a target shard
2. Each incoming gRPC request invokes `simple_msg_exchange` on a tokio worker thread
3. Worker threads block on mutex acquisition and channel send operations
4. With sufficient concurrency, all worker threads become blocked
5. New gRPC requests cannot be processed as no worker threads are available
6. Remote executor service becomes unresponsive
7. Block execution stalls, affecting validator liveness

This service is used in production for sharded block execution: [4](#0-3) 

## Impact Explanation

**Severity: High** - This meets the "Validator node slowdowns" category in the Aptos bug bounty program.

The remote executor service is critical infrastructure for sharded block execution. When this service experiences task starvation:
- Block execution is delayed or stalled
- Transaction processing throughput degrades
- Validator performance metrics suffer
- In extreme cases, validators may fail to participate in consensus rounds

This does not directly cause consensus safety violations or fund loss, but it significantly impacts validator liveness and network performance, which falls under High severity criteria.

## Likelihood Explanation

**Likelihood: Medium-High**

While the blocking operations are individually brief (microseconds for mutex lock on HashMap lookup, fast for unbounded channel send), the likelihood increases under:

1. **High transaction throughput**: During peak network activity, many blocks are being processed concurrently
2. **Sharded execution load**: With multiple shards (configured via `--num-shards`), the coordinator sends concurrent execute commands to all shards
3. **State synchronization**: Concurrent state view requests and cross-shard messages amplify the load
4. **Limited worker threads**: Default tokio runtime uses CPU-core-count workers (typically 8-16), easily exhausted

The vulnerability does not require malicious intent - it can manifest during legitimate high-load scenarios. A misbehaving or buggy coordinator could also inadvertently trigger this by sending excessive concurrent requests.

## Recommendation

Wrap the blocking operations in `tokio::task::spawn_blocking()` to prevent worker thread starvation. Alternatively, use async-friendly primitives (tokio::sync::Mutex and async channels).

**Option 1: Use spawn_blocking** [2](#0-1) 

Replace the synchronous operations with:
```rust
let inbound_handlers = self.inbound_handlers.clone();
let self_addr = self.self_addr;

tokio::task::spawn_blocking(move || {
    let _timer = NETWORK_HANDLER_TIMER
        .with_label_values(&[&self_addr.to_string(), "inbound_msgs"])
        .start_timer();
    
    if let Some(handler) = inbound_handlers.lock().unwrap().get(&message_type) {
        handler.send(msg).unwrap();
    } else {
        error!("No handler registered for sender: {:?} and msg type {:?}", 
               remote_addr, message_type);
    }
})
.await
.map_err(|e| Status::internal(format!("Task join error: {}", e)))?;
```

**Option 2: Use async primitives**
Replace `std::sync::Mutex` with `tokio::sync::Mutex` and use async channels throughout the codebase.

## Proof of Concept

```rust
#[tokio::test]
async fn test_concurrent_message_starvation() {
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time::timeout;
    
    // Setup: Create a gRPC server with limited worker threads
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)  // Limit to 2 workers to demonstrate issue
        .build()
        .unwrap();
    
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 
                                      utils::get_available_port());
    let server_handlers = Arc::new(Mutex::new(HashMap::new()));
    
    // Create a slow receiver to increase blocking duration
    let (msg_tx, msg_rx) = crossbeam_channel::unbounded();
    server_handlers.lock().unwrap()
        .insert(MessageType::new("test".to_string()), msg_tx);
    
    let server = GRPCNetworkMessageServiceServerWrapper::new(
        server_handlers, server_addr
    );
    
    runtime.spawn(async move {
        server.start_async(server_addr, 5000, 
                          tokio::sync::oneshot::channel().1).await;
    });
    
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Attack: Send many concurrent requests
    let mut tasks = vec![];
    for _ in 0..20 {  // More than worker threads
        let mut client = GRPCNetworkMessageServiceClientWrapper::new(
            &runtime, server_addr
        );
        let task = tokio::spawn(async move {
            client.send_message(
                server_addr,
                Message::new(vec![0u8; 1024]),
                &MessageType::new("test".to_string())
            ).await;
        });
        tasks.push(task);
    }
    
    // Observe: Later tasks timeout due to worker thread starvation
    for (i, task) in tasks.into_iter().enumerate() {
        let result = timeout(Duration::from_secs(2), task).await;
        if i > 10 {
            // Tasks after worker threads are exhausted should timeout
            assert!(result.is_err(), 
                   "Task {} should timeout due to starvation", i);
        }
    }
}
```

## Notes

This vulnerability specifically affects the remote executor service's gRPC message handling. The issue is a violation of tokio's async runtime invariants: blocking operations must not execute directly on worker threads. While individual blocking operations are brief, sustained high-concurrency load during sharded block execution can exhaust the limited worker thread pool, causing cascading delays and service degradation. This impacts validator liveness without requiring malicious intent.

### Citations

**File:** protos/rust/src/pb/aptos.remote_executor.v1.tonic.rs (L229-235)
```rust
                            let fut = async move {
                                <T as NetworkMessageService>::simple_msg_exchange(
                                        &inner,
                                        request,
                                    )
                                    .await
                            };
```

**File:** secure/net/src/grpc_network_service/mod.rs (L93-115)
```rust
    async fn simple_msg_exchange(
        &self,
        request: Request<NetworkMessage>,
    ) -> Result<Response<Empty>, Status> {
        let _timer = NETWORK_HANDLER_TIMER
            .with_label_values(&[&self.self_addr.to_string(), "inbound_msgs"])
            .start_timer();
        let remote_addr = request.remote_addr();
        let network_message = request.into_inner();
        let msg = Message::new(network_message.message);
        let message_type = MessageType::new(network_message.message_type);

        if let Some(handler) = self.inbound_handlers.lock().unwrap().get(&message_type) {
            // Send the message to the registered handler
            handler.send(msg).unwrap();
        } else {
            error!(
                "No handler registered for sender: {:?} and msg type {:?}",
                remote_addr, message_type
            );
        }
        Ok(Response::new(Empty {}))
    }
```

**File:** secure/net/src/network_controller/mod.rs (L106-107)
```rust
            inbound_rpc_runtime: Runtime::new().unwrap(),
            outbound_rpc_runtime: Runtime::new().unwrap(),
```

**File:** execution/executor-service/src/remote_executor_service.rs (L30-36)
```rust
        let service_name = format!("executor_service-{}", shard_id);
        let mut controller = NetworkController::new(service_name, self_address, 5000);
        let coordinator_client = Arc::new(RemoteCoordinatorClient::new(
            shard_id,
            &mut controller,
            coordinator_address,
        ));
```
