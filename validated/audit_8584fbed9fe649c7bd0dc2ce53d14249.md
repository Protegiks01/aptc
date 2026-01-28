# Audit Report

## Title
Silent Message Drop in Remote Executor Causes Permanent Consensus Deadlock

## Summary
The remote executor system's message routing silently drops messages when handlers are not yet registered, returning success to the sender. When this occurs during consensus block execution, the coordinator blocks indefinitely waiting for execution results that never arrive, causing permanent validator deadlock for nodes using distributed execution.

## Finding Description

The vulnerability exists in the message routing logic for the remote executor system used in sharded block execution.

When messages arrive at the network layer before handlers are registered, they are silently dropped with only log warnings. In `InboundHandler::send_incoming_message_to_handler`, unregistered messages are dropped with a warning log: [1](#0-0) 

Similarly, the gRPC service drops messages for unregistered handlers but critically returns `Ok(Response::new(Empty {}))`, providing no error indication to the sender: [2](#0-1) 

This becomes critical in the consensus execution path where `RemoteExecutorClient` coordinates distributed block execution. The coordinator sends execution commands to remote shards: [3](#0-2) 

And then blocks indefinitely waiting for results with no timeout mechanism: [4](#0-3) 

The `rx.recv().unwrap()` call uses crossbeam channels which cannot be interrupted by async abort mechanisms and has no timeout. If a shard's handler is not yet registered when the message arrives (due to initialization timing races or shard restarts), the message is silently dropped and the coordinator deadlocks permanently.

This system is used in production consensus when remote executors are configured: [5](#0-4) 

The test infrastructure itself acknowledges this timing vulnerability with explicit sleeps and TODO comments: [6](#0-5) 

## Impact Explanation

This vulnerability causes permanent validator deadlock for nodes configured with remote executor shards, meeting **High to Critical** severity criteria depending on deployment prevalence.

**For Affected Validators:** Complete loss of liveness - the validator cannot execute blocks and requires manual process restart. The deadlock is non-recoverable due to the infinite blocking `recv()` with no timeout mechanism.

**For Network:** If multiple validators using remote executors are affected simultaneously (during synchronized upgrades, coordinated restarts, or targeted attacks causing shard crashes), and if these represent >1/3 of voting power, the network loses consensus and stops producing blocks.

The vulnerability breaks the **Consensus Liveness** invariant for affected validators. While remote executors are not the default configuration, they are documented as a production feature for "higher throughput" deployments and have dedicated standalone binaries and infrastructure.

## Likelihood Explanation

**High likelihood** for production validators that have remote executor shards configured:

1. **Timing races are inherent to distributed systems:** During initialization, rolling upgrades, or network delays, shards may register handlers slower than the coordinator sends commands.

2. **Attacker amplification possible:** An attacker can force shard restarts by sending resource-intensive transactions to trigger OOM conditions, creating windows where handlers are unregistered during the restart cycle.

3. **No defensive mechanisms:** The code has no retry logic, timeout handling, error propagation, or message acknowledgment. Once a message is dropped, there is no recovery path.

**Note:** This only affects validators that have explicitly configured remote executors via `set_remote_addresses()`. The default configuration uses local in-process execution and is not vulnerable.

## Recommendation

Implement timeout and error handling in the remote executor communication:

1. **Add timeout to recv():** Replace `rx.recv().unwrap()` with `rx.recv_timeout(Duration::from_secs(30))` and handle timeout errors with retry logic or error propagation.

2. **Fix message drop acknowledgment:** The gRPC service should return an error status when no handler is registered, not `Ok(Empty {})`.

3. **Add retry mechanism:** If execution commands fail to deliver, implement exponential backoff retry before failing the block execution.

4. **Handler registration verification:** Before starting execution, verify all shard handlers are registered and ready.

## Proof of Concept

The existing test code demonstrates the vulnerability by requiring explicit sleep to avoid the race condition: [7](#0-6) 

To reproduce the deadlock, remove the sleep at line 68 and run the test - the coordinator will hang indefinitely waiting for results from shards whose handlers haven't registered yet.

A malicious actor can trigger this in production by:
1. Sending transactions that consume excessive memory
2. Causing target shard processes to OOM and restart
3. During restart window, coordinator sends execution commands
4. Messages are dropped, coordinator deadlocks

---

**Notes:**
- This vulnerability specifically affects the **non-default remote executor configuration**
- Validators using default local execution are not vulnerable
- Severity depends on deployment prevalence of remote executors in the validator set
- The technical vulnerability is real and exploitable in affected deployments

### Citations

**File:** secure/net/src/network_controller/inbound_handler.rs (L66-74)
```rust
    pub fn send_incoming_message_to_handler(&self, message_type: &MessageType, message: Message) {
        // Check if there is a registered handler for the sender
        if let Some(handler) = self.inbound_handlers.lock().unwrap().get(message_type) {
            // Send the message to the registered handler
            handler.send(message).unwrap();
        } else {
            warn!("No handler registered for message type: {:?}", message_type);
        }
    }
```

**File:** secure/net/src/grpc_network_service/mod.rs (L105-114)
```rust
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

**File:** execution/executor-service/src/remote_executor_client.rs (L180-206)
```rust
    fn execute_block(
        &self,
        state_view: Arc<S>,
        transactions: PartitionedTransactions,
        concurrency_level_per_shard: usize,
        onchain_config: BlockExecutorConfigFromOnchain,
    ) -> Result<ShardedExecutionOutput, VMStatus> {
        trace!("RemoteExecutorClient Sending block to shards");
        self.state_view_service.set_state_view(state_view);
        let (sub_blocks, global_txns) = transactions.into();
        if !global_txns.is_empty() {
            panic!("Global transactions are not supported yet");
        }
        for (shard_id, sub_blocks) in sub_blocks.into_iter().enumerate() {
            let senders = self.command_txs.clone();
            let execution_request = RemoteExecutionRequest::ExecuteBlock(ExecuteBlockCommand {
                sub_blocks,
                concurrency_level: concurrency_level_per_shard,
                onchain_config: onchain_config.clone(),
            });

            senders[shard_id]
                .lock()
                .unwrap()
                .send(Message::new(bcs::to_bytes(&execution_request).unwrap()))
                .unwrap();
        }
```

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L261-267)
```rust
        if !get_remote_addresses().is_empty() {
            Ok(V::execute_block_sharded(
                &REMOTE_SHARDED_BLOCK_EXECUTOR.lock(),
                partitioned_txns,
                state_view,
                onchain_config,
            )?)
```

**File:** execution/executor-service/src/tests.rs (L56-75)
```rust
#[test]
#[ignore]
fn test_sharded_block_executor_no_conflict() {
    use std::thread;

    let num_shards = 8;
    let (executor_client, mut executor_services) =
        create_thread_remote_executor_shards(num_shards, Some(2));
    let sharded_block_executor = ShardedBlockExecutor::new(executor_client);

    // wait for the servers to be ready before sending messages
    // TODO: We need to pass this test without this sleep
    thread::sleep(std::time::Duration::from_millis(10));

    test_utils::test_sharded_block_executor_no_conflict(sharded_block_executor);

    executor_services.iter_mut().for_each(|executor_service| {
        executor_service.shutdown();
    });
}
```
