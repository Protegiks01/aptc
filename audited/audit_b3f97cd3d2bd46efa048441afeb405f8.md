# Audit Report

## Title
Indefinite Blocking on Cross-Shard Dependencies Due to Missing Timeout Handling When Remote Shard is Offline

## Summary
The sharded execution system lacks timeout and error handling for cross-shard message reception, causing indefinite blocking when a required remote shard becomes unavailable. Transactions with cross-shard dependencies hang forever instead of properly failing, violating liveness guarantees and causing denial of service.

## Finding Description

When the `ProcessExecutorService` is initialized, it creates a `RemoteCrossShardClient` that handles cross-shard communication for transactions with dependencies across shards. [1](#0-0) 

The critical vulnerability lies in how cross-shard messages are received. The `RemoteCrossShardClient::receive_cross_shard_msg()` function uses a blocking `recv()` call without any timeout mechanism: [2](#0-1) 

When a transaction has cross-shard dependencies, the execution flow creates a `CrossShardStateView` where each remote state key is initialized with a `RemoteStateValue` in "waiting" state. [3](#0-2) 

A `CrossShardCommitReceiver` thread is spawned that loops indefinitely calling `receive_cross_shard_msg()`: [4](#0-3) 

When a transaction attempts to read a cross-shard state value, it blocks on a condition variable until the value is set: [5](#0-4) 

**The Attack Scenario:**

1. Shard A receives a block with a transaction that depends on data from Shard B
2. The execution system creates cross-shard state values in "waiting" state and spawns the receiver thread
3. Shard B becomes unavailable (crashes, network partition, or DoS attack)
4. The `CrossShardCommitReceiver` on Shard A calls `receive_cross_shard_msg()`, which blocks indefinitely on `rx.recv()`
5. The transaction execution tries to read the cross-shard value, which blocks on the condition variable in `RemoteStateValue::get_value()`
6. Neither thread can make progress - the receiver waits for a message that will never arrive, and the execution waits for a value that will never be set
7. The execution never completes, so the `StopMsg` is never sent: [6](#0-5) 
8. Shard A becomes completely unresponsive and cannot process any subsequent blocks with cross-shard dependencies

The NetworkController does have a timeout parameter, but it only applies to the GRPC layer, not to the crossbeam channel `recv()` operations: [7](#0-6) 

## Impact Explanation

This vulnerability meets **HIGH severity** criteria per the Aptos bug bounty program:

- **"Validator node slowdowns"**: Affected shards become completely unresponsive, unable to process blocks with cross-shard dependencies
- **"Significant protocol violations"**: Violates the liveness guarantee that transactions should eventually complete or fail

The impact can escalate depending on the dependency graph:
- If multiple shards depend on the offline shard, multiple shards become blocked
- Block execution halts across affected shards, preventing state progression
- The only recovery is manual intervention (restart the stuck shards)

This also violates critical invariants:
- **Liveness**: The system should make progress or fail gracefully, not hang indefinitely
- **Deterministic Execution**: Different nodes may timeout at different times if timeouts were eventually added at the OS level, causing non-determinism

## Likelihood Explanation

**HIGH likelihood** - This vulnerability is triggered by common operational scenarios:

1. **Natural failures**: Any shard crash, restart, or maintenance operation can trigger this
2. **Network partitions**: Temporary network issues between shards cause indefinite blocking
3. **Cascading failures**: One shard failure can block multiple dependent shards
4. **Malicious exploitation**: An attacker can deliberately crash or DoS a single shard to block others

The vulnerability requires no special privileges or complex attack setup. Any condition that makes a shard temporarily or permanently unavailable will trigger the indefinite blocking.

## Recommendation

Implement timeout-based error handling for cross-shard message reception:

1. **Add timeout to `receive_cross_shard_msg()`**: Use `recv_timeout()` instead of `recv()` in `RemoteCrossShardClient`:

```rust
fn receive_cross_shard_msg(&self, current_round: RoundId) -> Result<CrossShardMsg, CrossShardError> {
    let rx = self.message_rxs[current_round].lock().unwrap();
    match rx.recv_timeout(Duration::from_secs(30)) {
        Ok(message) => {
            let msg: CrossShardMsg = bcs::from_bytes(&message.to_bytes())?;
            Ok(msg)
        }
        Err(RecvTimeoutError::Timeout) => {
            Err(CrossShardError::Timeout(format!("Timeout waiting for cross-shard message in round {}", current_round)))
        }
        Err(RecvTimeoutError::Disconnected) => {
            Err(CrossShardError::ShardDisconnected)
        }
    }
}
```

2. **Update `CrossShardCommitReceiver::start()` to handle errors**: Propagate timeout errors and terminate gracefully

3. **Add timeout to `RemoteStateValue::get_value()`**: Use `wait_timeout()` instead of `wait()` to prevent indefinite blocking on condition variable

4. **Implement pre-execution shard availability checks**: Validate that all required shards are reachable before starting execution

5. **Add shard health monitoring**: Implement periodic heartbeats to detect offline shards early

## Proof of Concept

```rust
#[test]
#[ignore] // Requires multi-shard setup
fn test_cross_shard_dependency_offline_shard_hangs() {
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    // Setup: Create 2 shards
    let shard_0_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8000);
    let shard_1_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8001);
    
    let mut shard_0_service = ProcessExecutorService::new(
        0, // shard_id
        2, // num_shards
        4, // num_threads
        coordinator_addr,
        vec![shard_0_addr, shard_1_addr],
    );
    
    let mut shard_1_service = ProcessExecutorService::new(
        1, // shard_id
        2, // num_shards
        4, // num_threads
        coordinator_addr,
        vec![shard_0_addr, shard_1_addr],
    );
    
    let barrier = Arc::new(Barrier::new(2));
    let barrier_clone = barrier.clone();
    
    // Thread 1: Simulate shard 1 going offline after starting
    let handle = thread::spawn(move || {
        barrier_clone.wait();
        thread::sleep(Duration::from_millis(100));
        // Shard 1 crashes/goes offline
        drop(shard_1_service);
    });
    
    // Thread 2: Shard 0 tries to execute transaction with dependency on shard 1
    barrier.wait();
    
    // Create a transaction that depends on state from shard 1
    let txn_with_cross_shard_dep = create_transaction_with_dependency(
        /* shard_id: */ 0,
        /* depends_on_shard: */ 1,
        /* state_key: */ "some_cross_shard_key",
    );
    
    // This should fail with timeout error, but instead HANGS INDEFINITELY
    let start = Instant::now();
    let result = execute_on_shard_0_with_timeout(txn_with_cross_shard_dep, Duration::from_secs(5));
    
    // Expected: Should return error within 5 seconds
    // Actual: Hangs forever, test never completes
    assert!(start.elapsed() < Duration::from_secs(10), "Execution should timeout, not hang indefinitely");
    assert!(result.is_err(), "Should return error when dependency shard is offline");
    
    handle.join().unwrap();
}
```

**Notes:**

The vulnerability is triggered by any scenario where a remote shard becomes unavailable - crashes, network issues, maintenance, or malicious DoS. The issue is the **missing error handling in the code**, not a network-level attack. The system should gracefully fail or timeout when dependencies cannot be satisfied, rather than hanging indefinitely and requiring manual intervention.

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

**File:** execution/executor-service/src/remote_cross_shard_client.rs (L61-66)
```rust
    fn receive_cross_shard_msg(&self, current_round: RoundId) -> CrossShardMsg {
        let rx = self.message_rxs[current_round].lock().unwrap();
        let message = rx.recv().unwrap();
        let msg: CrossShardMsg = bcs::from_bytes(&message.to_bytes()).unwrap();
        msg
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_state_view.rs (L26-39)
```rust
    pub fn new(cross_shard_keys: HashSet<StateKey>, base_view: &'a S) -> Self {
        let mut cross_shard_data = HashMap::new();
        trace!(
            "Initializing cross shard state view with {} keys",
            cross_shard_keys.len(),
        );
        for key in cross_shard_keys {
            cross_shard_data.insert(key, RemoteStateValue::waiting());
        }
        Self {
            cross_shard_data,
            base_view,
        }
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_client.rs (L26-45)
```rust
    pub fn start<S: StateView + Sync + Send>(
        cross_shard_state_view: Arc<CrossShardStateView<S>>,
        cross_shard_client: Arc<dyn CrossShardClient>,
        round: RoundId,
    ) {
        loop {
            let msg = cross_shard_client.receive_cross_shard_msg(round);
            match msg {
                RemoteTxnWriteMsg(txn_commit_msg) => {
                    let (state_key, write_op) = txn_commit_msg.take();
                    cross_shard_state_view
                        .set_value(&state_key, write_op.and_then(|w| w.as_state_value()));
                },
                CrossShardMsg::StopMsg => {
                    trace!("Cross shard commit receiver stopped for round {}", round);
                    break;
                },
            }
        }
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/remote_state_value.rs (L29-39)
```rust
    pub fn get_value(&self) -> Option<StateValue> {
        let (lock, cvar) = &*self.value_condition;
        let mut status = lock.lock().unwrap();
        while let RemoteValueStatus::Waiting = *status {
            status = cvar.wait(status).unwrap();
        }
        match &*status {
            RemoteValueStatus::Ready(value) => value.clone(),
            RemoteValueStatus::Waiting => unreachable!(),
        }
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_executor_service.rs (L163-168)
```rust
                    // Send a self message to stop the cross-shard commit receiver.
                    cross_shard_client_clone.send_cross_shard_msg(
                        shard_id,
                        round,
                        CrossShardMsg::StopMsg,
                    );
```

**File:** execution/executor-service/src/remote_executor_service.rs (L31-31)
```rust
        let mut controller = NetworkController::new(service_name, self_address, 5000);
```
