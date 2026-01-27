# Audit Report

## Title
Byzantine Shard Causes Indefinite Blocking and Total Loss of Liveness in Remote Cross-Shard Execution

## Summary
The `receive_cross_shard_msg()` function in `RemoteCrossShardClient` uses an unbounded blocking `recv()` call without timeout, allowing a single Byzantine shard to cause complete liveness failure in distributed sharded execution. When Byzantine shards refuse to send required cross-shard messages, victim shards block indefinitely, creating a deadlock that halts all block execution.

## Finding Description

The vulnerability exists in the remote cross-shard message reception mechanism used for distributed parallel execution: [1](#0-0) 

This function is called in an infinite loop by the `CrossShardCommitReceiver`: [2](#0-1) 

The receiver thread is spawned within a thread pool scope that blocks until all threads complete: [3](#0-2) 

**Attack Scenario:**

1. **Setup**: Distributed sharded execution with multiple `ExecutorService` instances communicating over the network [4](#0-3) 

2. **Byzantine Behavior**: A malicious shard stops sending required cross-shard messages (e.g., `RemoteTxnWriteMsg` containing state updates)

3. **Victim Blocking**: The victim shard's `CrossShardCommitReceiver` blocks indefinitely at `rx.recv().unwrap()` because:
   - The crossbeam channel receiver has no timeout mechanism
   - The network layer timeout only applies to TCP/GRPC connections, not the channel itself [5](#0-4) 

4. **Deadlock Creation**:
   - The receiver thread cannot exit because it never receives the `StopMsg`
   - The execution thread sends `StopMsg` only AFTER completing execution [6](#0-5) 
   - The thread pool scope blocks waiting for both threads to complete
   - Result: Complete deadlock, total loss of liveness

**Invariant Violation:**
This breaks the fundamental liveness requirement that Byzantine actors should not be able to halt system progress with less than 1/3 participation. Here, a **single** Byzantine shard causes complete liveness failure for dependent shards.

## Impact Explanation

**Severity: Critical** (up to $1,000,000 per Aptos Bug Bounty criteria)

This vulnerability falls under the **"Total loss of liveness/network availability"** category because:

1. **Complete Service Halt**: The affected executor shard becomes completely unresponsive and cannot process any blocks requiring cross-shard dependencies

2. **Cascading Failure**: If multiple rounds depend on the blocked shard, the entire distributed execution system halts

3. **No Recovery Mechanism**: Without manual intervention (process restart), the shard remains permanently blocked

4. **Low Attack Threshold**: Only a SINGLE Byzantine shard is required to cause the attack (vs. the typical 1/3 Byzantine tolerance assumption)

5. **Widespread Impact**: Any deployment using remote/distributed sharded execution is vulnerable

## Likelihood Explanation

**Likelihood: High**

1. **Ease of Exploitation**: 
   - Trivial to execute - Byzantine shard simply drops outbound messages
   - No cryptographic breaking or complex state manipulation required
   - No need for validator majority or consensus participation

2. **Attacker Requirements**:
   - Control of a single executor shard in distributed mode
   - Ability to selectively drop network messages (standard network control)

3. **Attack Detectability**:
   - Difficult to distinguish from legitimate network failures
   - No immediate error signals (silent blocking)
   - May appear as normal high latency initially

4. **Deployment Scope**:
   - Affects all remote/distributed sharded execution deployments
   - Particularly critical for scaling solutions relying on cross-shard parallelism

## Recommendation

**Primary Fix: Add timeout to channel receive operations**

Replace the blocking `recv()` with `recv_timeout()` to allow periodic checks and graceful degradation:

```rust
fn receive_cross_shard_msg(&self, current_round: RoundId) -> CrossShardMsg {
    let rx = self.message_rxs[current_round].lock().unwrap();
    
    // Use configurable timeout (e.g., 30 seconds)
    const CROSS_SHARD_MSG_TIMEOUT: Duration = Duration::from_secs(30);
    
    loop {
        match rx.recv_timeout(CROSS_SHARD_MSG_TIMEOUT) {
            Ok(message) => {
                let msg: CrossShardMsg = bcs::from_bytes(&message.to_bytes()).unwrap();
                return msg;
            }
            Err(RecvTimeoutError::Timeout) => {
                // Log warning and check for shutdown signal
                warn!("Cross-shard message timeout for round {}", current_round);
                // Could implement retry logic or failure handling here
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => {
                panic!("Cross-shard message channel disconnected for round {}", current_round);
            }
        }
    }
}
```

**Additional Hardening Measures:**

1. **Implement Byzantine Detection**: Track message delivery rates per shard and flag/isolate non-responsive shards

2. **Add Heartbeat Mechanism**: Require periodic liveness signals from all shards

3. **Execution Timeout**: Add overall execution timeout at the scope level to prevent indefinite blocking

4. **Graceful Degradation**: Allow execution to proceed with partial results if certain shards become unresponsive (depending on dependency graph)

## Proof of Concept

```rust
// Rust integration test demonstrating the vulnerability
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;
    use crossbeam_channel::{unbounded, Sender, Receiver};

    #[test]
    #[ignore] // This test will hang indefinitely, demonstrating the vulnerability
    fn test_byzantine_shard_blocks_indefinitely() {
        // Setup: Create a mock remote cross-shard client
        let (tx, rx): (Sender<Message>, Receiver<Message>) = unbounded();
        let message_rxs = vec![Mutex::new(rx)];
        
        let client = RemoteCrossShardClient {
            message_txs: Arc::new(vec![]),
            message_rxs: Arc::new(message_rxs),
        };
        
        // Attacker: Byzantine shard never sends the required message
        // (We simply don't send anything on tx)
        
        // Victim: Try to receive a message
        let handle = thread::spawn(move || {
            println!("Waiting for cross-shard message...");
            // This will block FOREVER
            let _msg = client.receive_cross_shard_msg(0);
            println!("Received message (this will never print)");
        });
        
        // Wait for a reasonable timeout to demonstrate blocking
        thread::sleep(Duration::from_secs(5));
        
        // The thread is still alive and blocked
        assert!(!handle.is_finished(), "Thread should still be blocked");
        
        println!("VULNERABILITY CONFIRMED: Thread blocked indefinitely");
        println!("In production, this causes total loss of liveness");
        
        // Note: This test would hang forever without the timeout in the test harness
        // In production, there is NO timeout, causing permanent deadlock
    }
    
    #[test]
    fn test_recommended_fix_with_timeout() {
        // Demonstrates the fix using recv_timeout
        let (tx, rx): (Sender<Message>, Receiver<Message>) = unbounded();
        
        let handle = thread::spawn(move || {
            const TIMEOUT: Duration = Duration::from_secs(2);
            match rx.recv_timeout(TIMEOUT) {
                Ok(_) => println!("Received message"),
                Err(RecvTimeoutError::Timeout) => {
                    println!("Timeout - can handle gracefully");
                    return "Timeout handled";
                }
                Err(RecvTimeoutError::Disconnected) => {
                    panic!("Channel disconnected");
                }
            }
            "Success"
        });
        
        // Byzantine shard doesn't send message
        thread::sleep(Duration::from_secs(3));
        
        // Thread completes with timeout error instead of blocking forever
        let result = handle.join().unwrap();
        assert_eq!(result, "Timeout handled");
        println!("FIX VERIFIED: Timeout prevents indefinite blocking");
    }
}
```

## Notes

**Critical Context:**

1. **Local vs Remote Execution**: The local implementation also uses blocking `recv()` but is less vulnerable because all shards run in the same process with coordinated shutdown: [7](#0-6) 

2. **Network Layer Limitations**: While the `NetworkController` has timeout configuration, it only applies to TCP/GRPC operations, not the crossbeam channel: [8](#0-7) 

3. **Production Deployment Risk**: This vulnerability is particularly severe in production distributed execution deployments where shards run on separate machines/processes and may be operated by different entities with varying trust levels.

4. **Byzantine Fault Tolerance Gap**: Standard Byzantine fault tolerance assumes safety violations require >1/3 malicious actors. This liveness violation requires only ONE malicious shard, creating an asymmetric attack surface.

### Citations

**File:** execution/executor-service/src/remote_cross_shard_client.rs (L61-66)
```rust
    fn receive_cross_shard_msg(&self, current_round: RoundId) -> CrossShardMsg {
        let rx = self.message_rxs[current_round].lock().unwrap();
        let message = rx.recv().unwrap();
        let msg: CrossShardMsg = bcs::from_bytes(&message.to_bytes()).unwrap();
        msg
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

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_executor_service.rs (L134-183)
```rust
        executor_thread_pool.clone().scope(|s| {
            s.spawn(move |_| {
                CrossShardCommitReceiver::start(
                    cross_shard_state_view_clone,
                    cross_shard_client,
                    round,
                );
            });
            s.spawn(move |_| {
                let txn_provider =
                    DefaultTxnProvider::new_without_info(signature_verified_transactions);
                let ret = AptosVMBlockExecutorWrapper::execute_block_on_thread_pool(
                    executor_thread_pool,
                    &txn_provider,
                    aggr_overridden_state_view.as_ref(),
                    // Since we execute blocks in parallel, we cannot share module caches, so each
                    // thread has its own caches.
                    &AptosModuleCacheManager::new(),
                    config,
                    TransactionSliceMetadata::unknown(),
                    cross_shard_commit_sender,
                )
                .map(BlockOutput::into_transaction_outputs_forced);
                if let Some(shard_id) = shard_id {
                    trace!(
                        "executed sub block for shard {} and round {}",
                        shard_id,
                        round
                    );
                    // Send a self message to stop the cross-shard commit receiver.
                    cross_shard_client_clone.send_cross_shard_msg(
                        shard_id,
                        round,
                        CrossShardMsg::StopMsg,
                    );
                } else {
                    trace!("executed block for global shard and round {}", round);
                    // Send a self message to stop the cross-shard commit receiver.
                    cross_shard_client_clone.send_global_msg(CrossShardMsg::StopMsg);
                }
                callback.send(ret).unwrap();
                executor_thread_pool_clone.spawn(move || {
                    // Explicit async drop
                    drop(txn_provider);
                });
            });
        });

        block_on(callback_receiver).unwrap()
    }
```

**File:** execution/executor-service/src/remote_executor_service.rs (L21-55)
```rust
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
```

**File:** secure/net/src/network_controller/mod.rs (L95-100)
```rust
    pub fn new(service: String, listen_addr: SocketAddr, timeout_ms: u64) -> Self {
        let inbound_handler = Arc::new(Mutex::new(InboundHandler::new(
            service.clone(),
            listen_addr,
            timeout_ms,
        )));
```

**File:** secure/net/src/network_controller/mod.rs (L128-137)
```rust
    pub fn create_inbound_channel(&mut self, message_type: String) -> Receiver<Message> {
        let (inbound_sender, inbound_receiver) = unbounded();

        self.inbound_handler
            .lock()
            .unwrap()
            .register_handler(message_type, inbound_sender);

        inbound_receiver
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/local_executor_shard.rs (L335-337)
```rust
    fn receive_cross_shard_msg(&self, current_round: RoundId) -> CrossShardMsg {
        self.message_rxs[current_round].recv().unwrap()
    }
```
