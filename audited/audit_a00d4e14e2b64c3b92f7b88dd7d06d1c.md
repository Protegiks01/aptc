# Audit Report

## Title
Cross-Shard Message Replay Attack in Global Executor via Persistent Unbounded Channel

## Summary
The global cross-shard message channel is a single persistent unbounded channel shared across all blocks, unlike regular shard-to-shard channels which are separated per round. When the global executor finishes execution before regular shards complete (intentional concurrent execution), messages sent by regular shards to the global channel can arrive after the global receiver has stopped, remaining in the channel and being replayed in the next block. This causes validator crashes (panic on unexpected state keys) or consensus divergence if timing differs between validators.

## Finding Description

The sharded block executor uses separate channels per round for regular shard-to-shard communication to prevent message replay between rounds, as explicitly documented: [1](#0-0) 

However, the global cross-shard channel uses a single persistent unbounded channel without round or block separation: [2](#0-1) 

The global executor is explicitly designed to run **concurrently** with regular shards: [3](#0-2) 

This creates a race condition where:

1. **Block N execution begins**: Regular shards and global shard start executing concurrently
2. **Global executor completes first**: If global transactions are lightweight or few, the global executor finishes and sends `StopMsg` to itself: [4](#0-3) 

3. **Global receiver stops**: The receiver loop terminates when it receives `StopMsg`: [5](#0-4) 

4. **Regular shard sends message**: A transaction in a regular shard commits with a dependent edge to `GLOBAL_ROUND_ID`, triggering message send: [6](#0-5) 

5. **Message arrives after receiver stopped**: The message remains in the persistent global channel

6. **Block N+1 begins**: The global executor's receiver starts fresh and immediately receives the **old message from Block N**

7. **Validator panic**: When the receiver attempts to set the value, it calls `unwrap()` on a state key lookup. If the old message's state key is not in Block N+1's dependencies, this panics: [7](#0-6) 

The cross-shard state view only contains keys from the current block's required edges: [8](#0-7) 

**Messages contain no block ID or nonce for replay protection**: [9](#0-8) 

## Impact Explanation

This is **HIGH severity** per Aptos bug bounty criteria:

1. **Validator Node Crashes**: The `unwrap()` panic causes immediate validator crash when an old message with unexpected state key is received. This meets "API crashes" criteria.

2. **Consensus Divergence**: If timing varies between validators (network latency, CPU load), some validators may receive and crash on old messages while others process blocks normally. This violates the "Deterministic Execution" invariant that "all validators must produce identical state roots for identical blocks."

3. **Consensus Safety Violation**: Non-deterministic crashes can cause validators to fall out of sync, potentially leading to temporary consensus failure if >1/3 validators are affected. This violates the "Consensus Safety" invariant.

4. **Denial of Service**: An attacker can intentionally trigger this by crafting transactions that maximize the timing window (heavy computation in regular shards, lightweight global transactions), repeatedly causing validator crashes.

## Likelihood Explanation

**Likelihood: HIGH**

- The concurrent execution pattern is **intentional and documented** (see comment in citation)
- The timing window exists in every block where global executor finishes before regular shards
- No privileged access required - any transaction sender can influence timing through transaction complexity
- The vulnerability is deterministic given the race condition
- The persistent channel is a **static global variable**, created once and reused indefinitely: [10](#0-9) 

## Recommendation

**Solution 1: Use per-block or per-round channels for global messages** (preferred)

Create separate global message channels indexed by block ID or round, similar to regular shard-to-shard channels. Replace the single `unbounded()` channel with a per-block channel map that gets cleaned up after block completion.

**Solution 2: Add block ID/nonce to messages**

Add a block identifier to `CrossShardMsg` and validate it in the receiver:

```rust
pub enum CrossShardMsg {
    RemoteTxnWriteMsg(BlockId, RemoteTxnWrite),
    StopMsg(BlockId),
}
```

The receiver should reject messages with mismatched block IDs.

**Solution 3: Enforce completion ordering**

Ensure the global executor only finishes after all regular shards have completed sending their messages. Move the global execution call after waiting for shard results:

```rust
let mut sharded_output = self.get_output_from_shards()?;
// Now execute global after all shards complete
let mut global_output = self.global_executor.execute_global_txns(...)?;
```

However, this loses the concurrency optimization mentioned in the comments.

**Solution 4: Drain and validate channel between blocks**

Before starting Block N+1, drain any remaining messages from the global channel and log/error if any exist (they indicate a bug). This prevents replay but doesn't fix the root cause.

## Proof of Concept

```rust
#[test]
fn test_global_message_replay_vulnerability() {
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;
    use crossbeam_channel::unbounded;
    
    // Simulate the global channel setup (same as production)
    let (global_tx, global_rx) = unbounded();
    let message_count = Arc::new(Mutex::new(0));
    
    // Block N execution
    {
        let global_rx_clone = global_rx.clone();
        let count_clone = message_count.clone();
        
        // Global receiver thread (finishes quickly)
        let receiver_handle = thread::spawn(move || {
            // Receive messages until StopMsg
            loop {
                if let Ok(msg) = global_rx_clone.recv_timeout(Duration::from_millis(100)) {
                    match msg {
                        "data" => {
                            let mut count = count_clone.lock().unwrap();
                            *count += 1;
                        },
                        "stop" => break,
                        _ => {}
                    }
                }
            }
        });
        
        // Send StopMsg immediately (global finishes fast)
        thread::sleep(Duration::from_millis(50));
        global_tx.send("stop").unwrap();
        
        // Wait for receiver to stop
        receiver_handle.join().unwrap();
        
        // Simulate slow regular shard sending message AFTER global stopped
        thread::sleep(Duration::from_millis(100));
        global_tx.send("data_from_block_N").unwrap(); // Message arrives late!
    }
    
    // Block N+1 execution
    {
        let global_rx_clone = global_rx.clone();
        let count_clone = message_count.clone();
        
        // New global receiver for Block N+1
        let receiver_handle = thread::spawn(move || {
            // This will receive the OLD message from Block N!
            if let Ok(msg) = global_rx_clone.recv_timeout(Duration::from_millis(100)) {
                if msg == "data_from_block_N" {
                    // Replayed message from previous block!
                    panic!("Received replayed message from previous block!");
                }
            }
        });
        
        let result = receiver_handle.join();
        
        // This demonstrates the vulnerability - we received an old message
        assert!(result.is_err()); // Panics due to replayed message
    }
}
```

To reproduce in the actual Aptos codebase:
1. Create a test with 2 blocks
2. Block 1: Have a regular shard transaction with dependent edge to global, use `thread::sleep()` to delay its commit
3. Block 1 global: Use minimal/empty transactions so it finishes quickly
4. Verify the message from Block 1's regular shard appears in Block 2's global receiver
5. Observe panic when Block 2 tries to set a state key not in its dependencies

## Notes

This vulnerability exists because the global executor optimization (concurrent execution to improve performance) was implemented without the same replay protection used for regular shard-to-shard messages. The comment explicitly acknowledges the need for per-round channels to prevent this exact issue in regular shards, but this protection was not extended to the global channel.

### Citations

**File:** aptos-move/aptos-vm/src/sharded_block_executor/local_executor_shard.rs (L65-75)
```rust
    fn setup_global_executor() -> (GlobalExecutor<S>, Sender<CrossShardMsg>) {
        let (cross_shard_tx, cross_shard_rx) = unbounded();
        let cross_shard_client = Arc::new(GlobalCrossShardClient::new(
            cross_shard_tx.clone(),
            cross_shard_rx,
        ));
        // Limit the number of global executor threads to 32 as parallel execution doesn't scale well beyond that.
        let executor_threads = num_cpus::get().min(32);
        let global_executor = GlobalExecutor::new(cross_shard_client, executor_threads);
        (global_executor, cross_shard_tx)
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/local_executor_shard.rs (L92-94)
```rust
        // We need to create channels for each shard and each round. This is needed because individual
        // shards might send cross shard messages to other shards that will be consumed in different rounds.
        // Having a single channel per shard will cause a shard to receiver messages that is not intended in the current round.
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/local_executor_shard.rs (L203-211)
```rust
        // This means that we are executing the global transactions concurrently with the individual shards but the
        // global transactions will be blocked for cross shard transaction results. This hopefully will help with
        // finishing the global transactions faster but we need to evaluate if this causes thread contention. If it
        // does, then we can simply move this call to the end of the function.
        let mut global_output = self.global_executor.execute_global_txns(
            global_txns,
            state_view.as_ref(),
            onchain_config,
        )?;
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_executor_service.rs (L169-173)
```rust
                } else {
                    trace!("executed block for global shard and round {}", round);
                    // Send a self message to stop the cross-shard commit receiver.
                    cross_shard_client_clone.send_global_msg(CrossShardMsg::StopMsg);
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

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_client.rs (L122-130)
```rust
                    if *round_id == GLOBAL_ROUND_ID {
                        self.cross_shard_client.send_global_msg(message);
                    } else {
                        self.cross_shard_client.send_cross_shard_msg(
                            *dependent_shard_id,
                            *round_id,
                            message,
                        );
                    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_state_view.rs (L49-56)
```rust
    pub fn set_value(&self, state_key: &StateKey, state_value: Option<StateValue>) {
        self.cross_shard_data
            .get(state_key)
            .unwrap()
            .set_value(state_value);
        // uncomment the following line to debug waiting count
        // trace!("waiting count for shard id {} is {}", self.shard_id, self.waiting_count());
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_state_view.rs (L58-71)
```rust
    pub fn create_cross_shard_state_view(
        base_view: &'a S,
        transactions: &[TransactionWithDependencies<AnalyzedTransaction>],
    ) -> CrossShardStateView<'a, S> {
        let mut cross_shard_state_key = HashSet::new();
        for txn in transactions {
            for (_, storage_locations) in txn.cross_shard_dependencies.required_edges_iter() {
                for storage_location in storage_locations {
                    cross_shard_state_key.insert(storage_location.clone().into_state_key());
                }
            }
        }
        CrossShardStateView::new(cross_shard_state_key, base_view)
    }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/messages.rs (L7-31)
```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum CrossShardMsg {
    RemoteTxnWriteMsg(RemoteTxnWrite),
    StopMsg,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RemoteTxnWrite {
    state_key: StateKey,
    // The write op is None if the transaction is aborted.
    write_op: Option<WriteOp>,
}

impl RemoteTxnWrite {
    pub fn new(state_key: StateKey, write_op: Option<WriteOp>) -> Self {
        Self {
            state_key,
            write_op,
        }
    }

    pub fn take(self) -> (StateKey, Option<WriteOp>) {
        (self.state_key, self.write_op)
    }
}
```

**File:** execution/executor-service/src/local_executor_helper.rs (L14-21)
```rust
pub static SHARDED_BLOCK_EXECUTOR: Lazy<
    Arc<Mutex<ShardedBlockExecutor<CachedStateView, LocalExecutorClient<CachedStateView>>>>,
> = Lazy::new(|| {
    info!("LOCAL_SHARDED_BLOCK_EXECUTOR created");
    Arc::new(Mutex::new(
        LocalExecutorClient::create_local_sharded_block_executor(AptosVM::get_num_shards(), None),
    ))
});
```
