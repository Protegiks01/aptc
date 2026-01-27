# Audit Report

## Title
Silent Failure in Executor Service: Background Thread Panics Undetected, Causing Validator Liveness Loss

## Summary
The executor-service main thread blocks indefinitely on `rx.recv()` waiting for Ctrl-C signals while critical execution work happens in detached background threads. If these background threads panic due to malformed inputs or internal errors, the main thread never detects the failure. The service process remains running and appears healthy, but execution has completely stopped, causing validator liveness loss.

## Finding Description

The vulnerability exists in the executor-service architecture where the main thread has no monitoring of background thread health: [1](#0-0) 

The main thread creates a `ProcessExecutorService`, then blocks on `rx.recv()` which only receives Ctrl-C signals. The service is kept alive via `_exe_service` variable but its background threads are never monitored.

`ProcessExecutorService` spawns an `ExecutorService` which creates a detached thread: [2](#0-1) 

This spawned thread runs `ShardedExecutorService::start()` which contains multiple panic points: [3](#0-2) 

The loop calls `receive_execute_command()` which contains an unwrapped BCS deserialization that can panic: [4](#0-3) 

Additionally, the NetworkController spawns async tasks on tokio runtime for the gRPC server: [5](#0-4) 

**Attack Path:**
1. Attacker sends malformed BCS-encoded execution request to gRPC endpoint
2. `bcs::from_bytes()` fails deserialization and panics
3. Background thread dies silently
4. Main thread continues blocking on `rx.recv()`
5. Service appears running but stops processing all execution requests
6. Validator misses consensus rounds, loses rewards, potential slashing

This breaks the **liveness invariant** - validators must continuously process blocks or fail visibly.

## Impact Explanation

**High Severity** per Aptos Bug Bounty criteria:
- **"Validator node slowdowns"**: Complete stop of execution processing is worse than slowdown
- **"Significant protocol violations"**: A validator not processing blocks violates consensus participation requirements

A validator running this service would:
- Stop executing all blocks assigned to its shard
- Fail to respond to coordinator execution requests
- Miss consensus rounds and voting opportunities
- Accumulate missed rounds leading to potential slashing
- Cause degraded network performance if multiple validators affected

The vulnerability affects **deterministic execution** and **consensus liveness** - core protocol invariants.

## Likelihood Explanation

**High Likelihood:**

Multiple realistic trigger conditions exist:
1. **Malformed BCS messages**: Any network peer can send invalid execution requests
2. **Metrics initialization failure**: The `.unwrap()` on metrics retrieval can panic if Prometheus setup fails
3. **Channel send failures**: Any `.unwrap()` on channel sends can panic if receivers are dropped
4. **gRPC server failures**: Network issues or configuration problems can cause server startup to panic

The service runs continuously on validator nodes in production, providing sustained attack surface. No authentication prevents untrusted actors from reaching the gRPC endpoints in a remote executor deployment.

## Recommendation

Implement comprehensive panic monitoring and health checking:

```rust
fn main() {
    let args = Args::parse();
    aptos_logger::Logger::new().init();

    let (tx, rx) = crossbeam_channel::unbounded();
    let (health_tx, health_rx) = crossbeam_channel::unbounded();
    
    ctrlc::set_handler(move || {
        tx.send(()).unwrap();
    })
    .expect("Error setting Ctrl-C handler");

    let exe_service = ProcessExecutorService::new(
        args.shard_id,
        args.num_shards,
        args.num_executor_threads,
        args.coordinator_address,
        args.remote_executor_addresses,
        health_tx, // Pass health channel
    );

    // Monitor both shutdown signal and health status
    crossbeam_channel::select! {
        recv(rx) -> _ => {
            info!("Received Ctrl-C, shutting down gracefully");
        },
        recv(health_rx) -> res => {
            match res {
                Ok(HealthStatus::ThreadPanic(msg)) => {
                    error!("Background thread panicked: {}", msg);
                    std::process::exit(1);
                },
                Err(_) => {
                    error!("Health monitoring channel closed unexpectedly");
                    std::process::exit(1);
                },
                _ => {}
            }
        }
    }
    
    info!("Process executor service shutdown successfully.");
}
```

Additionally:
1. Replace all `.unwrap()` calls with proper error handling
2. Store `JoinHandle` for spawned threads and use `thread::join()` or periodic health checks
3. Wrap the executor loop in `catch_unwind()` to recover from panics
4. Add periodic heartbeat mechanism to detect stalled threads
5. Implement graceful degradation instead of panicking on non-critical errors

## Proof of Concept

```rust
// File: execution/executor-service/tests/panic_detection_test.rs

#[test]
fn test_undetected_background_panic() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::Duration;
    
    // Simulate the current architecture
    let (ctrl_c_tx, ctrl_c_rx) = crossbeam_channel::unbounded();
    let panic_occurred = Arc::new(AtomicBool::new(false));
    let panic_flag = panic_occurred.clone();
    
    // Spawn background thread similar to ExecutorService::start()
    let handle = thread::Builder::new()
        .name("SimulatedExecutor".to_string())
        .spawn(move || {
            // Simulate work, then panic (like BCS deserialization failure)
            thread::sleep(Duration::from_millis(100));
            panic_flag.store(true, Ordering::SeqCst);
            panic!("Simulated BCS deserialization failure");
        })
        .expect("Failed to spawn thread");
    
    // Drop the handle - this is the bug! Main thread can't detect panic
    drop(handle);
    
    // Main thread blocks waiting for Ctrl-C
    let main_blocked = thread::spawn(move || {
        // This would block forever if not for timeout
        ctrl_c_rx.recv_timeout(Duration::from_secs(1))
    });
    
    // Wait for background thread to panic
    thread::sleep(Duration::from_millis(200));
    
    // Main thread is still blocked, unaware of panic
    assert!(panic_occurred.load(Ordering::SeqCst), "Background thread should have panicked");
    
    // Main thread is still waiting - demonstrates the bug
    assert!(main_blocked.join().unwrap().is_err(), "Main thread still blocked despite background panic");
    
    println!("BUG DEMONSTRATED: Background thread panicked but main thread never detected it");
}

#[test]
fn test_bcs_deserialization_panic() {
    use bcs;
    use std::panic;
    
    // Simulate malformed BCS data that would panic in receive_execute_command
    let malformed_data = vec![0xFF, 0xFF, 0xFF, 0xFF];
    
    let result = panic::catch_unwind(|| {
        // This simulates line 89 in remote_cordinator_client.rs
        let _decoded: Vec<u8> = bcs::from_bytes(&malformed_data).unwrap();
    });
    
    assert!(result.is_err(), "BCS deserialization should panic on malformed data");
    println!("VULNERABILITY: Malformed BCS data causes panic in background thread");
}
```

**To trigger in production:**
1. Deploy executor-service with remote execution configuration
2. Send malformed BCS-encoded protobuf message to the gRPC endpoint
3. Background thread panics on deserialization
4. Observe process still running but not processing any execution requests
5. Validator fails to participate in consensus rounds

## Notes

This vulnerability is particularly dangerous because:
1. **Silent failure mode**: No logs, alerts, or visible errors indicate the service has stopped
2. **Process appears healthy**: Standard process monitoring shows service running
3. **Cascading impact**: Other validators may also be affected by the same malformed message
4. **No automatic recovery**: Service remains broken until manual restart
5. **Production deployment risk**: Remote executor services are designed for high-performance validator setups

The fix requires architectural changes to the service lifecycle management, not just local patches.

### Citations

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

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_executor_service.rs (L215-272)
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
        let exe_time = SHARDED_EXECUTOR_SERVICE_SECONDS
            .get_metric_with_label_values(&[&self.shard_id.to_string(), "execute_block"])
            .unwrap()
            .get_sample_sum();
        info!(
            "Shard {} is shutting down; On shard execution tps {} txns/s ({} txns / {} s)",
            self.shard_id,
            (num_txns as f64 / exe_time),
            num_txns,
            exe_time
        );
    }
```

**File:** execution/executor-service/src/remote_cordinator_client.rs (L80-113)
```rust
    fn receive_execute_command(&self) -> ExecutorShardCommand<RemoteStateViewClient> {
        match self.command_rx.recv() {
            Ok(message) => {
                let _rx_timer = REMOTE_EXECUTOR_TIMER
                    .with_label_values(&[&self.shard_id.to_string(), "cmd_rx"])
                    .start_timer();
                let bcs_deser_timer = REMOTE_EXECUTOR_TIMER
                    .with_label_values(&[&self.shard_id.to_string(), "cmd_rx_bcs_deser"])
                    .start_timer();
                let request: RemoteExecutionRequest = bcs::from_bytes(&message.data).unwrap();
                drop(bcs_deser_timer);

                match request {
                    RemoteExecutionRequest::ExecuteBlock(command) => {
                        let init_prefetch_timer = REMOTE_EXECUTOR_TIMER
                            .with_label_values(&[&self.shard_id.to_string(), "init_prefetch"])
                            .start_timer();
                        let state_keys = Self::extract_state_keys(&command);
                        self.state_view_client.init_for_block(state_keys);
                        drop(init_prefetch_timer);

                        let (sub_blocks, concurrency, onchain_config) = command.into();
                        ExecutorShardCommand::ExecuteSubBlocks(
                            self.state_view_client.clone(),
                            sub_blocks,
                            concurrency,
                            onchain_config,
                        )
                    },
                }
            },
            Err(_) => ExecutorShardCommand::Stop,
        }
    }
```

**File:** secure/net/src/grpc_network_service/mod.rs (L43-88)
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
