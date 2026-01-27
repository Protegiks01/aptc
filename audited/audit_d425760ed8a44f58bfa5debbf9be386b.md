# Audit Report

## Title
Missing Rate Limiting in Remote Executor Service Allows Byzantine Coordinator to Cause Resource Exhaustion

## Summary
The remote executor service lacks rate limiting on incoming execution requests, allowing a Byzantine coordinator or shard to flood an executor with unbounded ExecuteBlock commands. This can cause memory exhaustion and denial of service on the executor shard, violating the Resource Limits invariant and potentially stalling blockchain execution.

## Finding Description

The executor service architecture uses a `NetworkController` to receive execution commands from a coordinator. The vulnerability exists at multiple levels:

**1. Unbounded Channel Creation** [1](#0-0) 

The `create_inbound_channel()` method creates an unbounded crossbeam channel with no capacity limits. When the coordinator sends `ExecuteBlock` commands, they are queued in this unbounded channel.

**2. No Rate Limiting in NetworkController** [2](#0-1) 

The `NetworkController::new()` constructor only accepts a `timeout_ms` parameter but no rate limiting configuration. A grep search of the entire `secure/net/` directory confirms zero rate limiting code exists in this component.

**3. Immediate Message Forwarding Without Checks** [3](#0-2) 

The gRPC service's `simple_msg_exchange()` method immediately forwards all incoming messages to registered handlers without any rate limiting, validation, or backpressure mechanism. Every message received is unconditionally sent to the unbounded channel.

**4. Sequential Processing Creates Backlog** [4](#0-3) 

The `ShardedExecutorService` processes commands sequentially in a loop, blocking on `receive_execute_command()`. While one block executes, additional commands queue up in memory.

**Attack Path:**

1. Byzantine coordinator establishes gRPC connection to executor shard
2. Coordinator rapidly sends thousands of `ExecuteBlock` commands via `simple_msg_exchange()`
3. Each command is serialized and queued in the unbounded channel
4. Executor processes blocks sequentially (taking seconds each with transaction execution)
5. Queue grows unbounded in memory as commands arrive faster than processing
6. Eventually causes OOM kill or system resource exhaustion
7. Executor shard becomes unavailable, stalling block execution

**Invariant Violated:**
- **Resource Limits**: "All operations must respect gas, storage, and computational limits" - the unbounded queue violates memory resource limits
- **Availability**: Executor availability is compromised by resource exhaustion

**Contrast with Existing Infrastructure:**

The codebase already has a rate limiting infrastructure: [5](#0-4) 

However, the `NetworkController` in the executor service does not integrate with this token bucket rate limiter, leaving it vulnerable.

## Impact Explanation

**Medium Severity** per Aptos bug bounty criteria:

- **State inconsistencies requiring intervention**: If an executor shard crashes mid-execution, it may require manual intervention to restore and could leave partial state updates
- **Validator node slowdowns**: Executor resource exhaustion impacts block processing performance
- **Limited availability impact**: Affects specific executor shards rather than entire network, but can cascade if multiple shards are targeted

This does not reach High severity because:
- It doesn't directly cause consensus violations (blocks simply aren't processed)
- No funds are directly lost or stolen
- Recovery is possible by restarting the executor service

This exceeds Low severity because:
- It causes measurable operational impact requiring intervention
- It can stall critical blockchain functions (block execution)
- Exploitation is straightforward for a Byzantine actor in the distributed system

## Likelihood Explanation

**High Likelihood:**

1. **Low Attack Complexity**: The coordinator already has legitimate network access to send ExecuteBlock commands - it simply sends them at an excessive rate with no additional privileges required
2. **No Authentication Barriers**: The gRPC service processes all incoming messages without rate checks
3. **Distributed System Threat Model**: The executor service is explicitly designed to operate in a Byzantine environment where coordinators/shards may be malicious
4. **Realistic Scenario**: In sharded execution, a compromised coordinator or shard is a realistic threat vector
5. **No Existing Mitigations**: Complete absence of rate limiting means any burst of requests triggers the vulnerability

The only requirement is network access to the executor's gRPC endpoint, which is inherently granted to coordinators in the distributed execution architecture.

## Recommendation

Integrate rate limiting into the `NetworkController` and `GRPCNetworkMessageServiceServerWrapper`:

**Solution 1: Add Rate Limiting Configuration to NetworkController**

```rust
// In secure/net/src/network_controller/mod.rs
use aptos_rate_limiter::rate_limit::{TokenBucketRateLimiter, SharedBucket};

pub struct NetworkController {
    inbound_handler: Arc<Mutex<InboundHandler>>,
    outbound_handler: OutboundHandler,
    inbound_rpc_runtime: Runtime,
    outbound_rpc_runtime: Runtime,
    inbound_server_shutdown_tx: Option<oneshot::Sender<()>>,
    outbound_task_shutdown_tx: Option<Sender<Message>>,
    listen_addr: SocketAddr,
    rate_limiter: Option<Arc<TokenBucketRateLimiter<SocketAddr>>>, // NEW
}

impl NetworkController {
    pub fn new(
        service: String, 
        listen_addr: SocketAddr, 
        timeout_ms: u64,
        max_requests_per_sec: Option<usize>, // NEW
    ) -> Self {
        let rate_limiter = max_requests_per_sec.map(|rate| {
            Arc::new(TokenBucketRateLimiter::new(
                "executor_service",
                format!("Rate limiter for {}", service),
                100, // start at 100%
                rate * 10, // bucket size (10 seconds of burst)
                rate, // refill rate
                None,
            ))
        });
        // ... rest of initialization
    }
}
```

**Solution 2: Add Rate Check in GRPC Handler**

```rust
// In secure/net/src/grpc_network_service/mod.rs
#[tonic::async_trait]
impl NetworkMessageService for GRPCNetworkMessageServiceServerWrapper {
    async fn simple_msg_exchange(
        &self,
        request: Request<NetworkMessage>,
    ) -> Result<Response<Empty>, Status> {
        let remote_addr = request.remote_addr()
            .ok_or_else(|| Status::internal("No remote address"))?;
        
        // NEW: Rate limit check
        if let Some(limiter) = &self.rate_limiter {
            if !limiter.try_acquire(&remote_addr, 1) {
                return Err(Status::resource_exhausted(
                    "Rate limit exceeded for sender"
                ));
            }
        }
        
        // ... rest of processing
    }
}
```

**Solution 3: Use Bounded Channels**

```rust
// In secure/net/src/network_controller/mod.rs
pub fn create_inbound_channel(&mut self, message_type: String) -> Receiver<Message> {
    let (inbound_sender, inbound_receiver) = bounded(1000); // NEW: bounded
    
    self.inbound_handler
        .lock()
        .unwrap()
        .register_handler(message_type, inbound_sender);
    
    inbound_receiver
}
```

**Recommended Configuration**: 
- Rate limit: 100 requests/second per remote address
- Bucket size: 1000 (allows 10-second burst)
- Bounded channel capacity: 1000 messages

## Proof of Concept

```rust
// File: execution/executor-service/src/tests.rs
#[test]
fn test_executor_flood_attack() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};
    use aptos_config::utils;
    
    // Setup executor service
    let executor_addr = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST), 
        utils::get_available_port()
    );
    
    let mut executor_service = ProcessExecutorService::new(
        0, // shard_id
        1, // num_shards
        8, // num_threads
        executor_addr, // coordinator address (self for test)
        vec![executor_addr], // shard addresses
    );
    
    // Wait for service to start
    thread::sleep(Duration::from_millis(100));
    
    // Create malicious coordinator client
    let rt = Runtime::new().unwrap();
    let mut malicious_client = GRPCNetworkMessageServiceClientWrapper::new(
        &rt, 
        executor_addr
    );
    
    // Track memory usage
    let memory_usage = Arc::new(AtomicUsize::new(0));
    let memory_clone = memory_usage.clone();
    
    thread::spawn(move || {
        loop {
            if let Ok(usage) = sys_info::mem_info() {
                memory_clone.store(usage.avail as usize, Ordering::Relaxed);
            }
            thread::sleep(Duration::from_secs(1));
        }
    });
    
    // Flood attack: send 10,000 execute commands rapidly
    let start_mem = memory_usage.load(Ordering::Relaxed);
    let start_time = Instant::now();
    
    for i in 0..10000 {
        let command = RemoteExecutionRequest::ExecuteBlock(ExecuteBlockCommand {
            sub_blocks: create_dummy_sub_blocks(), // helper function
            concurrency_level: 8,
            onchain_config: BlockExecutorConfigFromOnchain::default(),
        });
        
        let message = Message::new(bcs::to_bytes(&command).unwrap());
        
        rt.block_on(async {
            malicious_client.send_message(
                executor_addr,
                message,
                &MessageType::new(format!("execute_command_0"))
            ).await;
        });
        
        if i % 1000 == 0 {
            let elapsed = start_time.elapsed();
            let current_mem = memory_usage.load(Ordering::Relaxed);
            let mem_delta = start_mem.saturating_sub(current_mem);
            
            println!(
                "Sent {} requests in {:?}, memory consumed: {} MB",
                i,
                elapsed,
                mem_delta / 1024 / 1024
            );
            
            // Vulnerability demonstrated if memory grows unbounded
            assert!(
                mem_delta < 1024 * 1024 * 1024, // 1GB
                "Memory exhaustion detected: consumed {} MB",
                mem_delta / 1024 / 1024
            );
        }
    }
    
    executor_service.shutdown();
}

fn create_dummy_sub_blocks() -> SubBlocksForShard<AnalyzedTransaction> {
    // Create minimal valid sub-blocks for testing
    // Implementation details omitted for brevity
}
```

**Expected Behavior Without Fix**: Memory usage grows to several GB and executor becomes unresponsive or crashes.

**Expected Behavior With Fix**: Rate limiter rejects requests after threshold, executor remains stable.

## Notes

This vulnerability is particularly concerning in the sharded execution architecture where:
1. Multiple shards communicate over the network
2. Byzantine fault tolerance assumptions require handling malicious actors
3. Resource exhaustion of one shard can impact overall block execution throughput
4. The distributed nature makes detection and recovery more complex

The fix should balance security (preventing DoS) with performance (allowing legitimate high-throughput execution). The recommended rate limits should be tuned based on expected workload characteristics.

### Citations

**File:** secure/net/src/network_controller/mod.rs (L95-113)
```rust
    pub fn new(service: String, listen_addr: SocketAddr, timeout_ms: u64) -> Self {
        let inbound_handler = Arc::new(Mutex::new(InboundHandler::new(
            service.clone(),
            listen_addr,
            timeout_ms,
        )));
        let outbound_handler = OutboundHandler::new(service, listen_addr, inbound_handler.clone());
        info!("Network controller created for node {}", listen_addr);
        Self {
            inbound_handler,
            outbound_handler,
            inbound_rpc_runtime: Runtime::new().unwrap(),
            outbound_rpc_runtime: Runtime::new().unwrap(),
            // we initialize the shutdown handles when we start the network controller
            inbound_server_shutdown_tx: None,
            outbound_task_shutdown_tx: None,
            listen_addr,
        }
    }
```

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

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_executor_service.rs (L215-260)
```rust
    pub fn start(&self) {
        trace!(
            "Shard starting, shard_id={}, num_shards={}.",
            self.shard_id,
            self.num_shards
        );
        let mut num_txns = 0;
        loop {
            let command = self.coordinator_client.receive_execute_command();
            match command {
                ExecutorShardCommand::ExecuteSubBlocks(
                    state_view,
                    transactions,
                    concurrency_level_per_shard,
                    onchain_config,
                ) => {
                    num_txns += transactions.num_txns();
                    trace!(
                        "Shard {} received ExecuteBlock command of block size {} ",
                        self.shard_id,
                        num_txns
                    );
                    let exe_timer = SHARDED_EXECUTOR_SERVICE_SECONDS
                        .timer_with(&[&self.shard_id.to_string(), "execute_block"]);
                    let ret = self.execute_block(
                        transactions,
                        state_view.as_ref(),
                        BlockExecutorConfig {
                            local: BlockExecutorLocalConfig::default_with_concurrency_level(
                                concurrency_level_per_shard,
                            ),
                            onchain: onchain_config,
                        },
                    );
                    drop(state_view);
                    drop(exe_timer);

                    let _result_tx_timer = SHARDED_EXECUTOR_SERVICE_SECONDS
                        .timer_with(&[&self.shard_id.to_string(), "result_tx"]);
                    self.coordinator_client.send_execution_result(ret);
                },
                ExecutorShardCommand::Stop => {
                    break;
                },
            }
        }
```

**File:** crates/aptos-rate-limiter/src/rate_limit.rs (L54-89)
```rust
pub struct TokenBucketRateLimiter<Key: Eq + Hash + Clone + Debug> {
    label: &'static str,
    log_info: String,
    buckets: RwLock<HashMap<Key, SharedBucket>>,
    new_bucket_start_percentage: u8,
    default_bucket_size: usize,
    default_fill_rate: usize,
    enabled: bool,
    metrics: Option<HistogramVec>,
}

impl<Key: Eq + Hash + Clone + Debug> TokenBucketRateLimiter<Key> {
    pub fn new(
        label: &'static str,
        log_info: String,
        new_bucket_start_percentage: u8,
        default_bucket_size: usize,
        default_fill_rate: usize,
        metrics: Option<HistogramVec>,
    ) -> Self {
        // Ensure that we can actually use the rate limiter
        assert!(new_bucket_start_percentage <= 100);
        assert!(default_bucket_size > 0);
        assert!(default_fill_rate > 0);

        Self {
            label,
            log_info,
            buckets: RwLock::new(HashMap::new()),
            new_bucket_start_percentage,
            default_bucket_size,
            default_fill_rate,
            enabled: true,
            metrics,
        }
    }
```
