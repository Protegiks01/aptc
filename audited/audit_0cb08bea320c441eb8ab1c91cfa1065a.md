# Audit Report

## Title
Unbounded Channel Memory Exhaustion in Remote Executor Service

## Summary
The `simple_msg_exchange` gRPC endpoint uses unbounded channels without authentication or rate limiting, allowing an attacker to exhaust memory by sending messages faster than the receiver can process them, ultimately causing node crashes and message loss.

## Finding Description

The `NetworkController` creates inbound message handlers using unbounded crossbeam channels [1](#0-0) , which are then registered to handle incoming gRPC messages [2](#0-1) .

When a message arrives via the `simple_msg_exchange` gRPC endpoint, it is immediately sent to the registered handler's channel with `.unwrap()` [3](#0-2) . Since the channel is unbounded, messages accumulate in memory indefinitely if they arrive faster than the receiver processes them.

The gRPC server has **no authentication or authorization** mechanism [4](#0-3) , allowing any network peer to send messages. While individual messages are limited to 80 MB [5](#0-4) , there is no rate limiting on the number of messages.

This service is deployed as a standalone process for sharded block execution [6](#0-5) , handling critical execution commands from coordinators and cross-shard messages [7](#0-6) .

**Attack Path:**
1. Attacker identifies exposed executor shard gRPC endpoint
2. Attacker floods endpoint with valid messages (up to 80 MB each) to any registered message type
3. Messages accumulate in unbounded channel faster than receiver processes them
4. Process memory grows until system OOM killer terminates the executor shard
5. All queued messages are lost; execution halts

To the specific question: While unbounded channels don't cause **deadlocks** (they never block on send), they do cause **message drops** indirectly through memory exhaustion and subsequent process termination.

## Impact Explanation

**Severity: HIGH**

This vulnerability meets the "High Severity" criteria from the Aptos bug bounty program:
- **Validator node slowdowns**: Memory pressure causes degraded performance before OOM
- **Significant protocol violations**: Executor shard crashes disrupt sharded block execution

The impact includes:
- **Denial of Service**: Executor shards can be crashed repeatedly
- **Execution Disruption**: Blocks cannot be executed if shards are unavailable
- **Resource Exhaustion**: System resources consumed by unbounded memory growth
- **Message Loss**: All in-flight messages lost when process crashes

While this doesn't directly affect consensus safety (consensus uses a separate network layer), it can impact block execution throughput and validator operational stability.

## Likelihood Explanation

**Likelihood: HIGH**

The attack is highly feasible because:
- No authentication required on gRPC endpoint
- No rate limiting implemented
- Service is designed to be network-accessible for distributed execution
- Attack requires only gRPC client capabilities
- Messages can be up to 80 MB, amplifying memory consumption
- Receiver processing may be slow due to heavy computation (block execution)

The only barriers are:
- Attacker must identify exposed executor shard endpoints
- Service must be deployed (currently appears experimental but has production infrastructure)

## Recommendation

**Immediate Fix**: Replace unbounded channels with bounded channels and implement backpressure:

```rust
// In network_controller/mod.rs, line 129:
pub fn create_inbound_channel(&mut self, message_type: String) -> Receiver<Message> {
    const CHANNEL_CAPACITY: usize = 1000; // Adjust based on expected throughput
    let (inbound_sender, inbound_receiver) = bounded(CHANNEL_CAPACITY);
    
    self.inbound_handler
        .lock()
        .unwrap()
        .register_handler(message_type, inbound_sender);
    
    inbound_receiver
}
```

**In grpc_network_service/mod.rs, line 107, add error handling:**

```rust
// Instead of: handler.send(msg).unwrap();
match handler.try_send(msg) {
    Ok(()) => {},
    Err(TrySendError::Full(_)) => {
        error!("Channel full for message type {:?}, rejecting message", message_type);
        return Err(Status::resource_exhausted("Handler channel full"));
    },
    Err(TrySendError::Disconnected(_)) => {
        error!("Handler disconnected for message type {:?}", message_type);
        return Err(Status::internal("Handler disconnected"));
    }
}
```

**Additional Protections**:
1. **Implement authentication**: Add mTLS or token-based authentication to gRPC endpoint
2. **Add rate limiting**: Apply per-peer message rate limits
3. **Monitor channel depth**: Add metrics and alerts for channel queue sizes
4. **Graceful degradation**: Return backpressure signals to senders when channel is near capacity

## Proof of Concept

```rust
// Test demonstrating unbounded channel memory growth
// Add to secure/net/src/grpc_network_service/mod.rs tests

#[test]
fn test_unbounded_channel_memory_exhaustion() {
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;
    
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 
                                      utils::get_available_port());
    let message_type = "test_flood".to_string();
    let server_handlers: Arc<Mutex<HashMap<MessageType, Sender<Message>>>> = 
        Arc::new(Mutex::new(HashMap::new()));
    
    let (msg_tx, msg_rx) = crossbeam_channel::unbounded();
    server_handlers
        .lock()
        .unwrap()
        .insert(MessageType::new(message_type.clone()), msg_tx);
    
    let server = GRPCNetworkMessageServiceServerWrapper::new(
        server_handlers, 
        server_addr
    );
    
    let rt = Runtime::new().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    server.start(&rt, "flood_test".to_string(), server_addr, 1000, shutdown_rx);
    
    thread::sleep(Duration::from_millis(100));
    
    let mut grpc_client = GRPCNetworkMessageServiceClientWrapper::new(&rt, server_addr);
    let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 
                                      utils::get_available_port());
    
    // Send large messages rapidly without receiver consuming
    let large_message = vec![0u8; 10_000_000]; // 10 MB message
    
    // Flood with 100 messages (1 GB total) - receiver not consuming
    for _ in 0..100 {
        rt.block_on(async {
            grpc_client.send_message(
                client_addr,
                Message::new(large_message.clone()),
                &MessageType::new(message_type.clone()),
            ).await;
        });
    }
    
    // Verify messages queued but not received
    // In production, this would exhaust memory
    assert_eq!(msg_rx.len(), 100);
    
    shutdown_tx.send(()).unwrap();
}
```

**Notes**

The vulnerability is confirmed in the remote executor service implementation but does not affect the main Aptos consensus network layer, which uses a different networking stack (`aptos-network` with proper flow control). The issue is specific to the sharded execution service's use of `NetworkController` with unbounded channels and unauthenticated gRPC endpoints.

### Citations

**File:** secure/net/src/network_controller/mod.rs (L128-136)
```rust
    pub fn create_inbound_channel(&mut self, message_type: String) -> Receiver<Message> {
        let (inbound_sender, inbound_receiver) = unbounded();

        self.inbound_handler
            .lock()
            .unwrap()
            .register_handler(message_type, inbound_sender);

        inbound_receiver
```

**File:** secure/net/src/grpc_network_service/mod.rs (L23-23)
```rust
const MAX_MESSAGE_SIZE: usize = 1024 * 1024 * 80;
```

**File:** secure/net/src/grpc_network_service/mod.rs (L75-86)
```rust
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

**File:** execution/executor-service/src/main.rs (L1-48)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

use aptos_executor_service::process_executor_service::ProcessExecutorService;
use aptos_logger::info;
use clap::Parser;
use std::net::SocketAddr;

#[derive(Debug, Parser)]
struct Args {
    #[clap(long, default_value_t = 8)]
    pub num_executor_threads: usize,

    #[clap(long)]
    pub shard_id: usize,

    #[clap(long)]
    pub num_shards: usize,

    #[clap(long, num_args = 1..)]
    pub remote_executor_addresses: Vec<SocketAddr>,

    #[clap(long)]
    pub coordinator_address: SocketAddr,
}

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

**File:** execution/executor-service/src/remote_executor_service.rs (L13-72)
```rust
/// A service that provides support for remote execution. Essentially, it reads a request from
/// the remote executor client and executes the block locally and returns the result.
pub struct ExecutorService {
    shard_id: ShardId,
    controller: NetworkController,
    executor_service: Arc<ShardedExecutorService<RemoteStateViewClient>>,
}

impl ExecutorService {
    pub fn new(
        shard_id: ShardId,
        num_shards: usize,
        num_threads: usize,
        self_address: SocketAddr,
        coordinator_address: SocketAddr,
        remote_shard_addresses: Vec<SocketAddr>,
    ) -> Self {
        let service_name = format!("executor_service-{}", shard_id);
        let mut controller = NetworkController::new(service_name, self_address, 5000);
        let coordinator_client = Arc::new(RemoteCoordinatorClient::new(
            shard_id,
            &mut controller,
            coordinator_address,
        ));
        let cross_shard_client = Arc::new(RemoteCrossShardClient::new(
            &mut controller,
            remote_shard_addresses,
        ));

        let executor_service = Arc::new(ShardedExecutorService::new(
            shard_id,
            num_shards,
            num_threads,
            coordinator_client,
            cross_shard_client,
        ));

        Self {
            shard_id,
            controller,
            executor_service,
        }
    }

    pub fn start(&mut self) {
        self.controller.start();
        let thread_name = format!("ExecutorService-{}", self.shard_id);
        let builder = thread::Builder::new().name(thread_name);
        let executor_service_clone = self.executor_service.clone();
        builder
            .spawn(move || {
                executor_service_clone.start();
            })
            .expect("Failed to spawn thread");
    }

    pub fn shutdown(&mut self) {
        self.controller.shutdown();
    }
}
```
