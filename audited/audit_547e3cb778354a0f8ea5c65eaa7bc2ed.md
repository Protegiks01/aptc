# Audit Report

## Title
Array Index Out-of-Bounds Panic in Remote Cross-Shard Message Reception Causes Executor Shard Crash

## Summary
The `receive_cross_shard_msg` function in `RemoteCrossShardClient` performs an unchecked array access that causes a panic when the round number exceeds `MAX_ALLOWED_PARTITIONING_ROUNDS` (8). An attacker with network access to the executor service can send a malicious `ExecuteBlockCommand` containing more than 8 rounds, triggering an index out-of-bounds panic that crashes the executor shard.

## Finding Description

The vulnerability exists in the cross-shard message reception mechanism used by the remote sharded execution system. [1](#0-0) 

The `message_rxs` array is initialized with exactly `MAX_ALLOWED_PARTITIONING_ROUNDS` (8) elements during construction: [2](#0-1) [3](#0-2) 

When a remote executor shard receives an `ExecuteBlockCommand`, it processes each sub-block sequentially by round number: [4](#0-3) 

The round number comes from `enumerate()` and is unbounded. This round is passed to the cross-shard commit receiver: [5](#0-4) 

Which calls `receive_cross_shard_msg` with the potentially out-of-bounds round value: [6](#0-5) 

**Attack Path:**
1. Attacker sends a `RemoteExecutionRequest::ExecuteBlock` containing `SubBlocksForShard` with > 8 sub-blocks
2. The remote executor deserializes and accepts this command without validation (no authentication exists): [7](#0-6) 

3. During execution iteration, when `round >= 8`, the code attempts `message_rxs[round]` access
4. This triggers an index out-of-bounds panic, crashing the executor shard

**Broken Invariant:** This violates the "Resource Limits" invariant requiring all operations to respect computational limits and handle errors gracefully, as well as availability guarantees for the execution layer.

## Impact Explanation

This is a **High Severity** vulnerability according to Aptos bug bounty criteria:

- **API/Node Crashes**: The executor shard process terminates with a panic, causing complete loss of that shard's availability
- **Validator Node Slowdowns**: If this occurs during block execution, it delays or prevents block processing
- **Significant Protocol Violations**: The sharded execution mechanism fails, requiring manual intervention to restart affected shards

The vulnerability enables a **Denial of Service** attack against remote executor shards. While not directly affecting consensus safety or causing fund loss, it disrupts the execution layer's availability, which is critical for block processing in sharded execution deployments.

## Likelihood Explanation

**Likelihood: Medium to High**

The vulnerability is easily exploitable if the remote executor service is deployed:

1. **No Authentication Required**: The remote coordinator client accepts and deserializes messages without authentication checks [8](#0-7) 

2. **No Input Validation**: There is no validation that `SubBlocksForShard.num_sub_blocks() <= MAX_ALLOWED_PARTITIONING_ROUNDS`

3. **Network Accessibility**: An attacker only needs network access to the executor service's listening port to send crafted messages

4. **Deterministic Trigger**: The attack reliably causes a panic every time

The primary limiting factor is whether this remote execution feature is actually deployed in production environments. The lack of authentication suggests it may be primarily used for benchmarking, but if deployed, the vulnerability is immediately exploitable.

## Recommendation

Implement bounds checking before array access and add validation at multiple defense layers:

**Immediate Fix - Add Bounds Check in `receive_cross_shard_msg`:**

```rust
fn receive_cross_shard_msg(&self, current_round: RoundId) -> CrossShardMsg {
    assert!(
        current_round < MAX_ALLOWED_PARTITIONING_ROUNDS,
        "Round {} exceeds MAX_ALLOWED_PARTITIONING_ROUNDS ({})",
        current_round,
        MAX_ALLOWED_PARTITIONING_ROUNDS
    );
    let rx = self.message_rxs[current_round].lock().unwrap();
    let message = rx.recv().unwrap();
    let msg: CrossShardMsg = bcs::from_bytes(&message.to_bytes()).unwrap();
    msg
}
```

**Defense in Depth - Add Validation in Multiple Locations:**

1. **Partitioner Configuration Validation** - Ensure `max_partitioning_rounds <= MAX_ALLOWED_PARTITIONING_ROUNDS`:

```rust
pub fn new(
    num_threads: usize,
    num_rounds_limit: usize,
    // ... other params
) -> Self {
    assert!(
        num_rounds_limit <= MAX_ALLOWED_PARTITIONING_ROUNDS,
        "max_partitioning_rounds ({}) exceeds MAX_ALLOWED_PARTITIONING_ROUNDS ({})",
        num_rounds_limit,
        MAX_ALLOWED_PARTITIONING_ROUNDS
    );
    // ... rest of constructor
}
```

2. **Remote Command Validation** - Validate received commands before processing:

```rust
fn receive_execute_command(&self) -> ExecutorShardCommand<RemoteStateViewClient> {
    // ... after deserializing request ...
    match request {
        RemoteExecutionRequest::ExecuteBlock(command) => {
            // Add validation
            if command.sub_blocks.num_sub_blocks() > MAX_ALLOWED_PARTITIONING_ROUNDS {
                panic!("Received sub_blocks with {} rounds, exceeds maximum of {}",
                    command.sub_blocks.num_sub_blocks(),
                    MAX_ALLOWED_PARTITIONING_ROUNDS);
            }
            // ... rest of processing
        }
    }
}
```

3. **Add Authentication** - Implement message authentication to prevent unauthorized command injection

## Proof of Concept

```rust
// Reproduction steps for testing:
// 
// 1. Setup a remote executor service with RemoteCrossShardClient
// 2. Create a malicious ExecuteBlockCommand with 9+ rounds
// 3. Send it to the executor service
//
// Expected: Executor shard panics with "index out of bounds"

use aptos_types::block_executor::partitioner::{
    SubBlocksForShard, SubBlock, TransactionWithDependencies, CrossShardDependencies
};
use aptos_types::transaction::analyzed_transaction::AnalyzedTransaction;

fn create_malicious_command() -> SubBlocksForShard<AnalyzedTransaction> {
    let mut sub_blocks = vec![];
    
    // Create 9 sub-blocks (exceeds MAX_ALLOWED_PARTITIONING_ROUNDS of 8)
    for i in 0..9 {
        let empty_txns: Vec<TransactionWithDependencies<AnalyzedTransaction>> = vec![];
        let sub_block = SubBlock::new(i * 100, empty_txns);
        sub_blocks.push(sub_block);
    }
    
    SubBlocksForShard::new(0, sub_blocks) // shard_id = 0
}

// When this SubBlocksForShard is sent via RemoteExecutionRequest::ExecuteBlock
// and processed by the executor, it will panic at round 8 with:
// "index out of bounds: the len is 8 but the index is 8"
```

## Notes

This vulnerability specifically affects the **remote sharded execution** feature, which appears to be primarily used for distributed benchmarking and testing rather than production consensus. However, the vulnerability is real and exploitable if this feature is deployed in any environment where the executor service is network-accessible.

The root cause is the mismatch between:
- The fixed-size array allocation based on `MAX_ALLOWED_PARTITIONING_ROUNDS` constant
- The unbounded iteration over sub-blocks using `enumerate()` without validation

A comprehensive fix requires validation at multiple layers to ensure defense in depth, as well as implementing proper authentication for the remote execution protocol.

### Citations

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

**File:** types/src/block_executor/partitioner.rs (L20-20)
```rust
pub static MAX_ALLOWED_PARTITIONING_ROUNDS: usize = 8;
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_executor_service.rs (L134-141)
```rust
        executor_thread_pool.clone().scope(|s| {
            s.spawn(move |_| {
                CrossShardCommitReceiver::start(
                    cross_shard_state_view_clone,
                    cross_shard_client,
                    round,
                );
            });
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_executor_service.rs (L192-205)
```rust
        for (round, sub_block) in transactions.into_sub_blocks().into_iter().enumerate() {
            let _timer = SHARDED_BLOCK_EXECUTION_BY_ROUNDS_SECONDS
                .timer_with(&[&self.shard_id.to_string(), &round.to_string()]);
            SHARDED_BLOCK_EXECUTOR_TXN_COUNT.observe_with(
                &[&self.shard_id.to_string(), &round.to_string()],
                sub_block.transactions.len() as f64,
            );
            info!(
                "executing sub block for shard {} and round {}, number of txns {}",
                self.shard_id,
                round,
                sub_block.transactions.len()
            );
            result.push(self.execute_sub_block(sub_block, round, state_view, config.clone())?);
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_client.rs (L31-32)
```rust
        loop {
            let msg = cross_shard_client.receive_cross_shard_msg(round);
```

**File:** execution/executor-service/src/remote_cordinator_client.rs (L80-89)
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
```
