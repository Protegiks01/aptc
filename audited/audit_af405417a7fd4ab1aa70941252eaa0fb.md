# Audit Report

## Title
Cross-Block Round Pollution in Sharded Execution Causes Consensus Divergence

## Summary
The sharded block executor maintains persistent message channels indexed only by round number without block-level isolation. When multiple blocks reuse round numbers, unconsumed messages from earlier blocks remain in channels and are incorrectly processed by later blocks, causing state corruption and consensus divergence.

## Finding Description

The sharded execution system uses cross-shard messaging to coordinate state updates between execution shards. The critical flaw exists in how these message channels are managed:

**1. Persistent Channel Initialization**

The executor services are initialized as static lazy singletons that persist across all block executions: [1](#0-0) [2](#0-1) 

The `RemoteCrossShardClient` creates message receiver channels once during initialization, indexed only by round number: [3](#0-2) 

These channels persist for the entire lifetime of the service and are reused across multiple block executions.

**2. Message Reception Without Block Isolation**

When receiving messages, the code simply reads from the channel indexed by the current round with no block or version validation: [4](#0-3) 

The `CrossShardCommitReceiver` loops receiving messages until it gets a `StopMsg`: [5](#0-4) 

**3. No Channel Draining Mechanism**

When `StopMsg` is received, the receiver loop simply breaks with no mechanism to drain unconsumed messages: [6](#0-5) 

Any messages that arrived after the last `RemoteTxnWriteMsg` was processed remain in the channel.

**4. No Block Identifiers in Messages**

The `RemoteTxnWrite` message contains no block ID, version, or epoch information for validation: [7](#0-6) 

**5. Validator Crash via Unwrap Panic**

For each block execution, a new `CrossShardStateView` is created with only the state keys needed for that specific block: [8](#0-7) 

When a stale message is received with a state key not in the new view, the `set_value` method panics: [9](#0-8) 

**Attack Scenario:**

Block N execution (round 0):
- Creates `CrossShardStateView` with keys {A, B, C}
- Messages sent for keys {A, B, C}
- Message for key C arrives late after `StopMsg`
- Message remains in `message_rxs[0]`

Block N+1 execution (round 0):  
- Creates new `CrossShardStateView` with keys {D, E, F}
- Starts `CrossShardCommitReceiver` using same `message_rxs[0]`
- Receives stale message for key C from Block N
- Calls `cross_shard_data.get(&key_C).unwrap()`
- **Panics** because key C is not in the new view → validator crashes

Alternatively, if key C is in both blocks, it gets the wrong value from Block N, causing state corruption and consensus divergence.

## Impact Explanation

This vulnerability qualifies as **Critical Severity** under Aptos bug bounty criteria:

**Consensus Safety Violation:** Different validators will have different message arrival patterns based on network timing. When processing Block N+1, validators with stale messages will execute with different cross-shard state values, producing different state roots for identical blocks. This directly violates AptosBFT's fundamental safety guarantee that all honest validators agree on the same chain state.

**Validator Availability Impact:** Validators crash due to panic when stale messages reference unexpected state keys, causing loss of liveness.

**Non-Deterministic Failures:** The bug manifests non-deterministically based on network message timing, execution speed differences between shards, and cross-shard dependency patterns, making it extremely difficult to debug in production.

The sharded execution path is used when `num_shards > 1`: [10](#0-9) [11](#0-10) 

## Likelihood Explanation

The likelihood depends on whether sharded execution is enabled in production. The default configuration is `num_shards = 1` (non-sharded): [12](#0-11) 

However, when sharded execution is enabled (`num_shards > 1`), the vulnerability has **HIGH** likelihood:

1. **Natural Occurrence**: Requires only normal network delays causing messages to arrive after `StopMsg`
2. **Round Reuse**: Consecutive blocks will reuse round numbers (0, 1, 2...), maximizing exposure
3. **No Detection**: No validation prevents processing stale messages
4. **Distributed System Reality**: Message reordering and delays are common in production networks

The comments acknowledge the need for round isolation within a single block: [13](#0-12) 

But isolation between **blocks** reusing the same round numbers is completely missing.

## Recommendation

Implement block-level isolation for cross-shard message channels:

1. **Add block identifiers to messages**: Include `block_id` or `version` in `RemoteTxnWrite` for validation
2. **Drain channels between blocks**: After receiving `StopMsg`, drain all remaining messages from the channel before starting the next block
3. **Create fresh channels per block**: Instead of reusing persistent channels, create new channels for each block execution
4. **Add validation**: Check message block IDs against current block being executed and reject mismatches

Example fix for channel draining:
```rust
// After StopMsg, drain any remaining messages
while let Ok(msg) = rx.try_recv() {
    // Log and discard stale messages
    warn!("Discarding stale cross-shard message: {:?}", msg);
}
```

## Proof of Concept

This vulnerability requires setting up a multi-shard execution environment with `num_shards > 1` and introducing network delays to cause message arrival after `StopMsg`. A complete PoC would require:

1. Configure executor with `num_shards = 2` or higher
2. Execute Block N with cross-shard dependencies
3. Inject network delay causing late message arrival
4. Execute Block N+1 with different transaction set
5. Observe panic or state corruption

The vulnerability is confirmed by the code structure analysis showing persistent channels without block isolation and the unwrap panic in `set_value`.

## Notes

While the technical analysis is sound and the vulnerability is real, the practical impact depends on whether sharded execution (`num_shards > 1`) is deployed in production environments. The code exists in the production codebase and represents a critical design flaw that must be addressed before wider deployment of sharded execution features.

### Citations

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

**File:** execution/executor-service/src/remote_executor_client.rs (L57-72)
```rust
pub static REMOTE_SHARDED_BLOCK_EXECUTOR: Lazy<
    Arc<
        aptos_infallible::Mutex<
            ShardedBlockExecutor<CachedStateView, RemoteExecutorClient<CachedStateView>>,
        >,
    >,
> = Lazy::new(|| {
    info!("REMOTE_SHARDED_BLOCK_EXECUTOR created");
    Arc::new(aptos_infallible::Mutex::new(
        RemoteExecutorClient::create_remote_sharded_block_executor(
            get_coordinator_address(),
            get_remote_addresses(),
            None,
        ),
    ))
});
```

**File:** execution/executor-service/src/remote_cross_shard_client.rs (L36-41)
```rust
        // Create inbound channels for each round
        for round in 0..MAX_ALLOWED_PARTITIONING_ROUNDS {
            let message_type = format!("cross_shard_{}", round);
            let rx = controller.create_inbound_channel(message_type);
            message_rxs.push(Mutex::new(rx));
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

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_client.rs (L31-44)
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
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/messages.rs (L14-27)
```rust
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

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_executor_service.rs (L115-118)
```rust
        let cross_shard_state_view = Arc::new(CrossShardStateView::create_cross_shard_state_view(
            state_view,
            &transactions,
        ));
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_state_view.rs (L49-53)
```rust
    pub fn set_value(&self, state_key: &StateKey, state_value: Option<StateValue>) {
        self.cross_shard_data
            .get(state_key)
            .unwrap()
            .set_value(state_value);
```

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L68-89)
```rust
        let out = match transactions {
            ExecutableTransactions::Unsharded(txns) => {
                Self::by_transaction_execution_unsharded::<V>(
                    executor,
                    txns,
                    auxiliary_infos,
                    parent_state,
                    state_view,
                    onchain_config,
                    transaction_slice_metadata,
                )?
            },
            // TODO: Execution with auxiliary info is yet to be supported properly here for sharded transactions
            ExecutableTransactions::Sharded(txns) => Self::by_transaction_execution_sharded::<V>(
                txns,
                auxiliary_infos,
                parent_state,
                state_view,
                onchain_config,
                transaction_slice_metadata.append_state_checkpoint_to_block(),
            )?,
        };
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

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L463-467)
```rust
    pub fn get_num_shards() -> usize {
        match NUM_EXECUTION_SHARD.get() {
            Some(num_shards) => *num_shards,
            None => 1,
        }
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/local_executor_shard.rs (L92-94)
```rust
        // We need to create channels for each shard and each round. This is needed because individual
        // shards might send cross shard messages to other shards that will be consumed in different rounds.
        // Having a single channel per shard will cause a shard to receiver messages that is not intended in the current round.
```
