# Audit Report

## Title
Cross-Shard Message Replay Attack in Global Executor via Persistent Unbounded Channel

## Summary
The global cross-shard message channel is a single persistent unbounded channel shared across all blocks, unlike regular shard-to-shard channels which are separated per round. When the global executor finishes execution before regular shards complete (intentional concurrent execution), messages sent by regular shards to the global channel can arrive after the global receiver has stopped, remaining in the channel and being replayed in the next block. This causes validator crashes via panic on unexpected state keys.

## Finding Description

The sharded block executor implements two different channel architectures for cross-shard communication:

**Regular Shard-to-Shard Channels (Protected)**: Separate channels are created per round to prevent message replay between rounds: [1](#0-0) 

**Global Cross-Shard Channel (Vulnerable)**: A single persistent unbounded channel is created once and reused across all blocks: [2](#0-1) 

This global channel is part of a static global variable that persists indefinitely: [3](#0-2) 

The global executor is explicitly designed to run concurrently with regular shards: [4](#0-3) 

**Race Condition Scenario:**

1. **Block N Execution**: The global executor starts concurrently with regular shards. If global transactions are lightweight, the global executor finishes first and sends StopMsg to itself: [5](#0-4) 

2. **Receiver Termination**: The receiver loop exits upon receiving StopMsg: [6](#0-5) 

3. **Late Message Arrival**: A regular shard transaction with cross-shard dependency to GLOBAL_ROUND_ID commits after the receiver stopped, sending a message to the persistent global channel: [7](#0-6) 

4. **Message Replay in Block N+1**: When Block N+1 executes, a new CrossShardStateView is created containing only Block N+1's state keys: [8](#0-7) 

The state view only contains keys from the current block's required edges: [9](#0-8) 

5. **Panic on Invalid Key**: The receiver immediately receives the old message from Block N. When attempting to set the value, it calls unwrap() on a state key that doesn't exist in Block N+1's state view: [10](#0-9) 

**No Replay Protection**: Messages contain only state_key and write_op, with no block ID or nonce: [11](#0-10) 

## Impact Explanation

This vulnerability meets **HIGH severity** per Aptos bug bounty criteria:

**Validator Node Crashes**: The unwrap() panic at line 52 of cross_shard_state_view.rs causes immediate validator process crash when an old message with an unexpected state key is received. This directly qualifies as "API crashes" under HIGH severity criteria.

**Potential Denial of Service**: An attacker can intentionally maximize the race condition window by:
- Submitting heavy computation transactions to regular shards (delaying completion)
- Ensuring minimal global transactions (allowing early completion)
- Repeatedly triggering validator crashes across the network

If this affects >1/3 of validators simultaneously due to timing variations, it could lead to temporary consensus unavailability, approaching CRITICAL severity.

**Non-Deterministic Behavior**: While all validators execute the same block, timing differences in when the global executor finishes relative to regular shards can cause some validators to receive replayed messages and crash while others process normally. This creates operational instability in the validator network.

## Likelihood Explanation

**Likelihood: HIGH**

- The concurrent execution pattern is intentional and documented in the codebase
- The timing window exists in every block where the global executor completes before all regular shards finish
- No privileged access required - any transaction sender can influence timing through transaction complexity
- The persistent channel is created once as a static global variable and reused across all blocks indefinitely
- No cleanup mechanism exists to drain messages between blocks
- Current tests only execute single blocks per test, which would not reveal this cross-block issue

## Recommendation

Implement one of the following solutions:

**Option 1: Add Block/Round Identifier to Messages**
Extend CrossShardMsg to include a block_id or round_id field. The receiver should validate that incoming messages match the current execution context and drop messages from previous blocks.

**Option 2: Channel Cleanup Between Blocks**
Drain the global channel before starting each new block execution by calling try_recv() in a loop until the channel is empty, similar to the reset pattern used in the consensus buffer manager.

**Option 3: Per-Block Global Channel**
Create a new global channel for each block execution instead of reusing a persistent static channel, matching the pattern used for regular shard-to-shard channels.

**Option 4: Synchronization Barrier**
Ensure the global executor only sends StopMsg after all regular shards have confirmed completion, eliminating the race condition window.

## Proof of Concept

A concrete PoC would require:
1. Setting up a sharded block executor with multiple shards
2. Creating Block N with:
   - Lightweight global transactions (finish quickly)
   - Heavy regular shard transactions with GLOBAL_ROUND_ID dependencies
3. Ensuring the global executor completes before regular shards send their messages
4. Executing Block N+1 with different transaction dependencies
5. Observing the panic in Block N+1's receiver

The vulnerability can be reproduced by executing multiple consecutive blocks with the same ShardedBlockExecutor instance under conditions where global execution consistently completes before regular shard cross-shard message transmission.

## Notes

The vulnerability is fundamentally caused by architectural mismatch: regular shard-to-shard channels are ephemeral (created per round), while the global channel is persistent (created once). The concurrent execution pattern, while documented as intentional for performance, creates an exploitable race condition when combined with the persistent channel architecture and lack of message replay protection.

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

**File:** aptos-move/aptos-vm/src/sharded_block_executor/local_executor_shard.rs (L95-104)
```rust
        let (cross_shard_msg_txs, cross_shard_msg_rxs): (
            Vec<Vec<Sender<CrossShardMsg>>>,
            Vec<Vec<Receiver<CrossShardMsg>>>,
        ) = (0..num_shards)
            .map(|_| {
                (0..MAX_ALLOWED_PARTITIONING_ROUNDS)
                    .map(|_| unbounded())
                    .unzip()
            })
            .unzip();
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

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_executor_service.rs (L115-118)
```rust
        let cross_shard_state_view = Arc::new(CrossShardStateView::create_cross_shard_state_view(
            state_view,
            &transactions,
        ));
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_executor_service.rs (L169-173)
```rust
                } else {
                    trace!("executed block for global shard and round {}", round);
                    // Send a self message to stop the cross-shard commit receiver.
                    cross_shard_client_clone.send_global_msg(CrossShardMsg::StopMsg);
                }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_client.rs (L31-45)
```rust
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

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_client.rs (L116-131)
```rust
                for (dependent_shard_id, round_id) in dependent_shard_ids.iter() {
                    trace!("Sending remote update for success for shard id {:?} and txn_idx: {:?}, state_key: {:?}, dependent shard id: {:?}", self.shard_id, txn_idx, state_key, dependent_shard_id);
                    let message = RemoteTxnWriteMsg(RemoteTxnWrite::new(
                        state_key.clone(),
                        Some(write_op.clone()),
                    ));
                    if *round_id == GLOBAL_ROUND_ID {
                        self.cross_shard_client.send_global_msg(message);
                    } else {
                        self.cross_shard_client.send_cross_shard_msg(
                            *dependent_shard_id,
                            *round_id,
                            message,
                        );
                    }
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

**File:** aptos-move/aptos-vm/src/sharded_block_executor/messages.rs (L13-26)
```rust
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
```
