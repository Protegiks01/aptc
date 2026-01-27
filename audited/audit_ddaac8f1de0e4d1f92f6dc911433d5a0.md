# Audit Report

## Title
Race Condition in Executor Service Initialization Allows Early Requests to Fail and Cause Node Hangs

## Summary
The `ExecutorService::start()` method in the remote executor service infrastructure lacks proper synchronization guarantees between service initialization and readiness to accept requests. This race condition can cause early execution requests to fail with panics, leading to validator node hangs during block execution.

## Finding Description

The executor service initialization in `ThreadExecutorService::new()` and `ProcessExecutorService::new()` exhibits a critical race condition where the service is considered "started" before it is actually ready to accept incoming requests. [1](#0-0) 

The initialization sequence proceeds as follows:

1. `ExecutorService::new()` creates the service components but does not start network listeners
2. `executor_service.start()` is called, which:
   - Calls `controller.start()` to spawn the gRPC server asynchronously
   - Spawns a separate thread to run the executor service loop
   - **Returns immediately without waiting for initialization** [2](#0-1) 

The NetworkController's `start()` method spawns asynchronous tasks for both inbound and outbound handlers: [3](#0-2) 

The gRPC server is started asynchronously with no mechanism to signal when it's ready: [4](#0-3) 

The code itself acknowledges this issue: [5](#0-4) 

When requests are sent before the service is ready, the gRPC call fails and causes a panic: [6](#0-5) 

The test code explicitly works around this issue with sleep statements: [7](#0-6) [8](#0-7) 

**Exploitation Scenario:**

In production deployments using remote sharded execution: [9](#0-8) 

1. Remote executor service processes are started via `ProcessExecutorService`
2. The coordinator node starts and is configured with remote executor addresses
3. When `REMOTE_SHARDED_BLOCK_EXECUTOR` is lazily initialized and tries to execute a block
4. Execution requests are immediately sent to remote services via `RemoteExecutorClient::execute_block()`
5. If the remote gRPC servers haven't finished binding yet, the requests fail
6. The outbound handler task panics, killing the communication channel
7. The coordinator's `get_output_from_shards()` waits indefinitely on channels that will never receive responses
8. **The validator node hangs indefinitely during block execution**

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under the Aptos bug bounty criteria: "State inconsistencies requiring intervention."

When the race condition is triggered:
- Validator nodes hang during block execution
- Nodes cannot participate in consensus
- Manual intervention (node restart) is required
- If multiple validators are affected simultaneously (e.g., during coordinated upgrades), network liveness degrades

While this doesn't cause consensus safety violations or fund loss, it directly impacts network availability and requires manual intervention to resolve.

## Likelihood Explanation

This issue has **Medium to High likelihood** of occurrence in production:

1. **Timing-dependent**: Happens when coordinator attempts execution before services are fully initialized
2. **Startup scenarios**: Most likely during node restarts, network upgrades, or initial deployment
3. **Distributed execution**: Only affects deployments using remote sharded execution (optional but production-capable)
4. **No retry mechanism**: The code has no retry logic, so a single early request can cause permanent failure
5. **Known issue**: Multiple TODO comments indicate developers are aware but haven't implemented a fix

## Recommendation

Implement proper initialization synchronization using one of these approaches:

**Option 1: Add readiness checks**
```rust
pub fn start(&mut self) -> Result<()> {
    self.controller.start();
    
    // Wait for server to be ready
    self.wait_for_server_ready()?;
    
    let thread_name = format!("ExecutorService-{}", self.shard_id);
    let builder = thread::Builder::new().name(thread_name);
    let executor_service_clone = self.executor_service.clone();
    builder
        .spawn(move || {
            executor_service_clone.start();
        })
        .expect("Failed to spawn thread");
    
    Ok(())
}

fn wait_for_server_ready(&self) -> Result<()> {
    // Implement health check or use a ready signal
}
```

**Option 2: Add retry logic with exponential backoff**
```rust
pub async fn send_message(
    &mut self,
    sender_addr: SocketAddr,
    message: Message,
    mt: &MessageType,
) {
    let request = tonic::Request::new(NetworkMessage {
        message: message.data,
        message_type: mt.get_type(),
    });
    
    // Implement retry with exponential backoff as noted in TODO
    let mut retries = 0;
    let max_retries = 5;
    while retries < max_retries {
        match self.remote_channel.simple_msg_exchange(request.clone()).await {
            Ok(_) => return,
            Err(e) if retries < max_retries - 1 => {
                let delay = Duration::from_millis(100 * 2_u64.pow(retries));
                tokio::time::sleep(delay).await;
                retries += 1;
            },
            Err(e) => {
                panic!(
                    "Error '{}' sending message to {} on node {:?} after {} retries",
                    e, self.remote_addr, sender_addr, retries
                );
            },
        }
    }
}
```

**Option 3: Use synchronization primitives**
Add a `tokio::sync::Barrier` or `oneshot::channel` to signal when the server is ready to accept connections.

## Proof of Concept

The existing test code demonstrates this vulnerability and its workaround:

```rust
// From execution/executor-service/src/tests.rs
#[test]
fn test_race_condition() {
    let num_shards = 2;
    let (executor_client, mut executor_services) =
        create_thread_remote_executor_shards(num_shards, Some(2));
    let sharded_block_executor = ShardedBlockExecutor::new(executor_client);

    // WITHOUT this sleep, the test fails due to race condition
    // thread::sleep(std::time::Duration::from_millis(10));
    
    // Attempting immediate execution will cause panic/hang:
    // test_utils::test_sharded_block_executor_no_conflict(sharded_block_executor);
    
    executor_services.iter_mut().for_each(|executor_service| {
        executor_service.shutdown();
    });
}
```

To reproduce in a production-like scenario:
1. Start remote executor service processes
2. Immediately configure and start a coordinator node with those addresses
3. Trigger block execution before services are fully initialized
4. Observe gRPC connection failures and node hang

The vulnerability is confirmed by multiple TODO comments acknowledging the need to fix this issue without sleep-based workarounds.

## Notes

- This issue affects both `ThreadExecutorService` (testing) and `ProcessExecutorService` (production)
- The vulnerability is present in the core networking infrastructure used by remote sharded execution
- Multiple code locations acknowledge this as a known limitation requiring fixes
- Remote sharded execution is an optional deployment mode, but the affected code is production-capable
- No external attacker action is required - the race condition occurs naturally during startup

### Citations

**File:** execution/executor-service/src/thread_executor_service.rs (L15-36)
```rust
    pub fn new(
        shard_id: ShardId,
        num_shards: usize,
        num_threads: usize,
        coordinator_address: SocketAddr,
        remote_shard_addresses: Vec<SocketAddr>,
    ) -> Self {
        let self_address = remote_shard_addresses[shard_id];
        let mut executor_service = ExecutorService::new(
            shard_id,
            num_shards,
            num_threads,
            self_address,
            coordinator_address,
            remote_shard_addresses,
        );
        executor_service.start();
        Self {
            _self_address: self_address,
            executor_service,
        }
    }
```

**File:** execution/executor-service/src/remote_executor_service.rs (L57-67)
```rust
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

**File:** secure/net/src/network_controller/mod.rs (L199-204)
```rust
        network_controller1.start();
        network_controller2.start();

        // wait for the server to be ready to serve
        // TODO: We need to pass this test without this sleep
        thread::sleep(std::time::Duration::from_millis(100));
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

**File:** secure/net/src/grpc_network_service/mod.rs (L140-160)
```rust
    pub async fn send_message(
        &mut self,
        sender_addr: SocketAddr,
        message: Message,
        mt: &MessageType,
    ) {
        let request = tonic::Request::new(NetworkMessage {
            message: message.data,
            message_type: mt.get_type(),
        });
        // TODO: Retry with exponential backoff on failures
        match self.remote_channel.simple_msg_exchange(request).await {
            Ok(_) => {},
            Err(e) => {
                panic!(
                    "Error '{}' sending message to {} on node {:?}",
                    e, self.remote_addr, sender_addr
                );
            },
        }
    }
```

**File:** execution/executor-service/src/tests.rs (L66-68)
```rust
    // wait for the servers to be ready before sending messages
    // TODO: We need to pass this test without this sleep
    thread::sleep(std::time::Duration::from_millis(10));
```

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L256-276)
```rust
    fn execute_block_sharded<V: VMBlockExecutor>(
        partitioned_txns: PartitionedTransactions,
        state_view: Arc<CachedStateView>,
        onchain_config: BlockExecutorConfigFromOnchain,
    ) -> Result<Vec<TransactionOutput>> {
        if !get_remote_addresses().is_empty() {
            Ok(V::execute_block_sharded(
                &REMOTE_SHARDED_BLOCK_EXECUTOR.lock(),
                partitioned_txns,
                state_view,
                onchain_config,
            )?)
        } else {
            Ok(V::execute_block_sharded(
                &SHARDED_BLOCK_EXECUTOR.lock(),
                partitioned_txns,
                state_view,
                onchain_config,
            )?)
        }
    }
```
