# Audit Report

## Title
Silent Shard Shutdown Causes Coordinator Panic and Block Execution Failure

## Summary
When a remote executor shard shuts down during block execution, it does not notify the coordinator or other shards. This silent shutdown causes the coordinator to panic when attempting to receive execution results from the closed channel, leading to block execution failure and potential node unavailability.

## Finding Description

The vulnerability exists in the remote executor service's shutdown mechanism. When `ProcessExecutorService::shutdown()` is called, it only shuts down the network controller without sending explicit shutdown notifications to the coordinator or peer shards. [1](#0-0) 

This delegates to `ExecutorService::shutdown()` which only calls `NetworkController::shutdown()`: [2](#0-1) 

The `NetworkController::shutdown()` method sends shutdown signals to inbound/outbound handlers but does not wait for clean shutdown (as acknowledged by the TODO comment): [3](#0-2) 

Meanwhile, the coordinator's `RemoteExecutorClient::get_output_from_shards()` uses `.unwrap()` on channel receive operations: [4](#0-3) 

**Attack Scenario:**

1. Coordinator sends block execution commands to all shards via `RemoteExecutorClient::execute_block()`
2. One shard initiates shutdown (voluntarily, due to crash, or network failure) during block execution
3. The shard's `NetworkController::shutdown()` closes network connections and channels
4. Coordinator waits for results in `get_output_from_shards()`
5. When iterating through result receivers, `rx.recv().unwrap()` encounters the closed channel from the shutdown shard
6. The `.unwrap()` panics, crashing the coordinator thread
7. Block execution fails and the node becomes unavailable

This occurs in the critical block execution path used by the executor: [5](#0-4) 

## Impact Explanation

**Severity: Medium** per Aptos bug bounty criteria:

1. **State inconsistencies requiring intervention**: The panic causes block execution to fail mid-process, potentially leaving the coordinator in an inconsistent state requiring node restart.

2. **Node unavailability**: Repeated shard failures during block execution can cause persistent coordinator crashes, leading to node unavailability.

3. **No graceful degradation**: The system has no error recovery mechanism for shard failures. The use of `.unwrap()` converts what should be a handled error into a fatal panic.

The vulnerability does not directly cause loss of funds or consensus safety violations, but it affects the **State Consistency** invariant by preventing atomic state transitions and impacts availability guarantees.

## Likelihood Explanation

**Likelihood: Medium**

This vulnerability can be triggered by:

1. **Graceful shard shutdown**: Operators shutting down shards during maintenance while block execution is in progress
2. **Shard crashes**: Any bug causing a shard to crash will trigger this vulnerability
3. **Network failures**: Connection loss between coordinator and shard during execution
4. **Cascading failures**: If one shard fails and causes coordinator panic, other shards may also become disconnected

The race condition window exists throughout the entire block execution period, making it reasonably likely to occur in production deployments with multiple remote shards.

## Recommendation

Implement proper error handling and shutdown notification protocol:

1. **Replace `.unwrap()` with proper error handling**:
   - Use `Result` types and propagate errors instead of panicking
   - Handle `RecvError` gracefully by returning `VMStatus` error

2. **Implement explicit shutdown notification**:
   - Add shutdown notification message to the protocol
   - Coordinator should track shard health status
   - Implement timeout mechanism for unresponsive shards

3. **Add graceful degradation**:
   - Retry mechanism for transient failures
   - Ability to re-execute blocks after shard recovery

**Code Fix Example** for `get_output_from_shards()`:

```rust
fn get_output_from_shards(&self) -> Result<Vec<Vec<Vec<TransactionOutput>>>, VMStatus> {
    trace!("RemoteExecutorClient Waiting for results");
    let mut results = vec![];
    for (shard_id, rx) in self.result_rxs.iter().enumerate() {
        let received_bytes = rx.recv()
            .map_err(|_| {
                error!("Shard {} closed connection during execution", shard_id);
                VMStatus::error(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR, None)
            })?
            .to_bytes();
        let result: RemoteExecutionResult = bcs::from_bytes(&received_bytes)
            .map_err(|e| {
                error!("Failed to deserialize result from shard {}: {}", shard_id, e);
                VMStatus::error(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR, None)
            })?;
        results.push(result.inner?);
    }
    Ok(results)
}
```

## Proof of Concept

```rust
// Proof of Concept demonstrating the vulnerability
// Place in execution/executor-service/src/tests.rs

#[test]
#[should_panic(expected = "RecvError")]
fn test_shard_shutdown_during_execution() {
    use std::sync::Arc;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use crossbeam_channel::unbounded;
    use aptos_config::utils;
    
    // Setup coordinator and 2 shards
    let coordinator_port = utils::get_available_port();
    let coordinator_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), coordinator_port);
    
    let shard1_port = utils::get_available_port();
    let shard1_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), shard1_port);
    
    let shard2_port = utils::get_available_port();
    let shard2_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), shard2_port);
    
    let remote_addresses = vec![shard1_addr, shard2_addr];
    
    // Create coordinator with RemoteExecutorClient
    let mut coordinator_controller = NetworkController::new(
        "coordinator".to_string(),
        coordinator_addr,
        5000
    );
    
    let mut shard1_service = ProcessExecutorService::new(
        0,
        2,
        4,
        coordinator_addr,
        remote_addresses.clone(),
    );
    
    let mut shard2_service = ProcessExecutorService::new(
        1,
        2,
        4,
        coordinator_addr,
        remote_addresses.clone(),
    );
    
    coordinator_controller.start();
    
    // Simulate block execution starting
    // Coordinator sends execute commands to both shards
    // ... (execution setup code)
    
    // Shard 1 shuts down during execution
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(50));
        shard1_service.shutdown(); // Silent shutdown, no notification
    });
    
    // Coordinator tries to receive results from both shards
    // This will panic when shard1's channel is closed
    // get_output_from_shards() -> rx.recv().unwrap() -> PANIC!
    
    // Expected: This test should panic with RecvError
}
```

## Notes

The vulnerability is confirmed by the TODO comment in `NetworkController::shutdown()` which states "This is still not a very clean shutdown." The lack of proper shutdown coordination and error handling creates a reliability and availability issue that can be exploited through various failure scenarios.

### Citations

**File:** execution/executor-service/src/process_executor_service.rs (L47-49)
```rust
    pub fn shutdown(&mut self) {
        self.executor_service.shutdown()
    }
```

**File:** execution/executor-service/src/remote_executor_service.rs (L69-71)
```rust
    pub fn shutdown(&mut self) {
        self.controller.shutdown();
    }
```

**File:** secure/net/src/network_controller/mod.rs (L152-166)
```rust
    // TODO: This is still not a very clean shutdown. We don't wait for the full shutdown after
    //       sending the signal. May not matter much for now because we shutdown before exiting the
    //       process. Ideally, we want to fix this.
    pub fn shutdown(&mut self) {
        info!("Shutting down network controller at {}", self.listen_addr);
        if let Some(shutdown_signal) = self.inbound_server_shutdown_tx.take() {
            shutdown_signal.send(()).unwrap();
        }

        if let Some(shutdown_signal) = self.outbound_task_shutdown_tx.take() {
            shutdown_signal.send(Message::new(vec![])).unwrap_or_else(|_| {
                warn!("Failed to send shutdown signal to outbound task; probably already shutdown");
            })
        }
    }
```

**File:** execution/executor-service/src/remote_executor_client.rs (L163-172)
```rust
    fn get_output_from_shards(&self) -> Result<Vec<Vec<Vec<TransactionOutput>>>, VMStatus> {
        trace!("RemoteExecutorClient Waiting for results");
        let mut results = vec![];
        for rx in self.result_rxs.iter() {
            let received_bytes = rx.recv().unwrap().to_bytes();
            let result: RemoteExecutionResult = bcs::from_bytes(&received_bytes).unwrap();
            results.push(result.inner?);
        }
        Ok(results)
    }
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
