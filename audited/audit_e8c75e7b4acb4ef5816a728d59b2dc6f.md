# Audit Report

## Title
Cascading Panic in Sharded Block Executor Due to Unwrapped Channel Operations

## Summary
The `LocalCoordinatorClient` implementation contains multiple `unwrap()` calls on channel receive/send operations that will panic if the coordinator disconnects unexpectedly, causing cascading failures across all executor shards and crashing the entire validator node process.

## Finding Description

The sharded block executor uses crossbeam channels for inter-thread communication between the coordinator (`LocalExecutorClient`) and executor shards (`LocalCoordinatorClient`). Multiple locations use `.unwrap()` on channel operations without proper error handling:

**Primary vulnerability location:** [1](#0-0) 

When an executor shard calls `receive_execute_command()`, it blocks on `recv().unwrap()`. If the coordinator thread panics or is dropped unexpectedly (due to memory exhaustion, assertion failures, or other bugs), the channel sender will be disconnected, causing `recv()` to return an `Err` variant, which `unwrap()` converts to a panic.

**Additional vulnerable locations:** [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

**Cascading failure mechanism:**

When any panic occurs in the execution path, the global panic handler is invoked: [6](#0-5) 

Since executor shard code runs outside the VERIFIER/DESERIALIZER context, panics trigger `process::exit(12)`, terminating the entire validator node.

**Attack scenario:**
1. Sharded execution is enabled (num_shards > 1)
2. A bug or resource exhaustion causes the coordinator thread to panic during block execution
3. The coordinator's channel senders are dropped without sending Stop commands
4. Executor shards blocked on `recv().unwrap()` receive disconnect errors
5. Each shard panics on unwrap(), triggering the global panic handler
6. The entire validator node process exits with code 12

This breaks the **Resource Limits** invariant (#9) - the system should handle resource exhaustion gracefully without crashing, and it impacts **Node Availability** by causing complete validator crashes.

## Impact Explanation

**Severity: Medium** (per Aptos bug bounty criteria)

This qualifies as Medium severity based on:
- **"State inconsistencies requiring intervention"**: A crashed validator requires manual restart
- **"API crashes"**: The node becomes completely unavailable

While the issue could be classified as High severity under "Validator node slowdowns" / "API crashes", it has mitigating factors:
- Sharded execution defaults to 1 shard (effectively disabled): [7](#0-6) 
- Requires a triggering condition (coordinator panic from another bug or OOM)
- Not directly exploitable without causing the initial coordinator failure

However, the impact is **amplified** because:
- Any single coordinator bug becomes a multi-thread cascading failure
- Recovery requires process restart rather than graceful degradation
- Multiple executor shards crash simultaneously

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability will trigger when:
1. **Sharded execution is enabled**: Operators must configure num_shards > 1 via: [8](#0-7) 

2. **Coordinator experiences an error**: This could occur through:
   - Memory exhaustion during block execution
   - Assertion failures in execution logic
   - Bugs in the coordinator's execution path
   - Race conditions during node shutdown

3. **Executor is actively processing blocks**: The shards must be blocked waiting for commands: [9](#0-8) 

While not immediately exploitable, the likelihood increases as:
- Sharded execution becomes production-ready and enabled by default
- Transaction complexity increases (higher OOM risk)
- More validators enable sharding for performance

## Recommendation

Replace all `unwrap()` calls on channel operations with proper error handling that treats disconnection as a shutdown signal:

**For `receive_execute_command()`:**
```rust
fn receive_execute_command(&self) -> ExecutorShardCommand<S> {
    match self.command_rx.recv() {
        Ok(cmd) => cmd,
        Err(_) => {
            // Coordinator disconnected, treat as shutdown
            ExecutorShardCommand::Stop
        }
    }
}
```

**For `send_execution_result()`:**
```rust
fn send_execution_result(&self, result: Result<Vec<Vec<TransactionOutput>>, VMStatus>) {
    // Ignore send errors - coordinator may have already exited
    let _ = self.result_tx.send(result);
}
```

**For coordinator's `get_output_from_shards()`:**
```rust
fn get_output_from_shards(&self) -> Result<Vec<Vec<Vec<TransactionOutput>>>, VMStatus> {
    let _timer = WAIT_FOR_SHARDED_OUTPUT_SECONDS.start_timer();
    trace!("LocalExecutorClient Waiting for results");
    let mut results = vec![];
    for (i, rx) in self.result_rxs.iter().enumerate() {
        match rx.recv() {
            Ok(result) => results.push(result?),
            Err(_) => {
                return Err(VMStatus::error(
                    StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR,
                    Some(format!("Shard {} disconnected unexpectedly", i))
                ));
            }
        }
    }
    Ok(results)
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod panic_reproduction_test {
    use super::*;
    use crossbeam_channel::unbounded;
    use std::panic;
    
    #[test]
    fn test_coordinator_panic_causes_shard_panic() {
        // Simulate the channel setup
        let (command_tx, command_rx) = unbounded::<ExecutorShardCommand<MockStateView>>();
        let (result_tx, result_rx) = unbounded::<Result<Vec<Vec<TransactionOutput>>, VMStatus>>();
        
        let coordinator_client = LocalCoordinatorClient::new(command_rx, result_tx);
        
        // Spawn a shard thread that will wait for commands
        let shard_handle = std::thread::spawn(move || {
            // This will panic when command_tx is dropped
            let cmd = coordinator_client.receive_execute_command();
            cmd
        });
        
        // Simulate coordinator panic by dropping the sender without sending Stop
        drop(command_tx);
        
        // The shard thread should panic with "called `Result::unwrap()` on an `Err` value"
        let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            shard_handle.join().expect("Shard thread panicked")
        }));
        
        assert!(result.is_err(), "Shard should panic when coordinator disconnects");
    }
}
```

This test demonstrates that when the coordinator's channel sender is dropped unexpectedly, the shard thread panics on `recv().unwrap()` rather than gracefully handling the disconnection. In production, this panic would propagate to the global panic handler and crash the validator node process.

### Citations

**File:** aptos-move/aptos-vm/src/sharded_block_executor/local_executor_shard.rs (L169-172)
```rust
            results.push(
                rx.recv()
                    .unwrap_or_else(|_| panic!("Did not receive output from shard {}", i))?,
            );
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/local_executor_shard.rs (L260-262)
```rust
    fn receive_execute_command(&self) -> ExecutorShardCommand<S> {
        self.command_rx.recv().unwrap()
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/local_executor_shard.rs (L264-266)
```rust
    fn send_execution_result(&self, result: Result<Vec<Vec<TransactionOutput>>, VMStatus>) {
        self.result_tx.send(result).unwrap()
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/local_executor_shard.rs (L300-300)
```rust
        self.global_message_rx.recv().unwrap()
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/local_executor_shard.rs (L336-336)
```rust
        self.message_rxs[current_round].recv().unwrap()
```

**File:** crates/crash-handler/src/lib.rs (L52-57)
```rust
    if state::get_state() == VMState::VERIFIER || state::get_state() == VMState::DESERIALIZER {
        return;
    }

    // Kill the process
    process::exit(12);
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L457-460)
```rust
    pub fn set_num_shards_once(mut num_shards: usize) {
        num_shards = max(num_shards, 1);
        // Only the first call succeeds, due to OnceCell semantics.
        NUM_EXECUTION_SHARD.set(num_shards).ok();
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L463-467)
```rust
    pub fn get_num_shards() -> usize {
        match NUM_EXECUTION_SHARD.get() {
            Some(num_shards) => *num_shards,
            None => 1,
        }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_executor_service.rs (L222-224)
```rust
        loop {
            let command = self.coordinator_client.receive_execute_command();
            match command {
```
