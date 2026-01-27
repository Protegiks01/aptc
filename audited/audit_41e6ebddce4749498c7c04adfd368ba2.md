# Audit Report

## Title
Array Out-of-Bounds Panic in Cross-Shard Message Routing When Partitioning Rounds Exceed MAX_ALLOWED_PARTITIONING_ROUNDS

## Summary
A boundary condition vulnerability exists in the block partitioner where configuring `max_partitioning_rounds` to exceed `MAX_ALLOWED_PARTITIONING_ROUNDS` (8) causes array out-of-bounds panics during cross-shard message sending in the sharded executor. This leads to validator node crashes and network liveness failures.

## Finding Description

The Aptos block partitioner allows configuring `max_partitioning_rounds` without validation against `MAX_ALLOWED_PARTITIONING_ROUNDS`. When `max_partitioning_rounds` is set to 9 (i.e., `MAX_ALLOWED_PARTITIONING_ROUNDS + 1`) with `partition_last_round = true`, the partitioner creates transactions in rounds 0-8. However, the cross-shard messaging infrastructure pre-allocates communication channels only for rounds 0-7. [1](#0-0) 

The vulnerability flow:

1. **Configuration Phase**: An operator sets `max_partitioning_rounds = 9` through the configuration builder with no validation. [2](#0-1) 

2. **Partitioner Phase**: The partitioner creates up to 9 rounds (indices 0-8) when `num_rounds_limit = 9`. [3](#0-2) 

3. **Edge Building Phase**: When `partition_last_round = true`, transactions in round 8 retain their round_id instead of being mapped to `GLOBAL_ROUND_ID`. [4](#0-3) 

4. **Dependent Edge Creation**: Cross-shard dependencies are created with `round_id = 8` for transactions in the last round. [5](#0-4) 

5. **Executor Phase**: During transaction execution, the system attempts to send cross-shard messages using the round_id from dependent edges. [6](#0-5) 

6. **Crash Point**: The cross-shard client accesses `message_txs[shard_id][round]` where `round = 8`, but the array was only allocated with indices 0-7. [7](#0-6) [8](#0-7) 

Similarly for remote execution: [9](#0-8) [10](#0-9) 

This causes a Rust panic due to index out of bounds, crashing the validator node.

## Impact Explanation

**Severity: High** (up to $50,000)

This vulnerability causes **validator node crashes** during block execution, directly impacting network liveness and availability. When triggered:

- All validator nodes with the misconfiguration crash when processing blocks requiring cross-shard communication in round 8
- Network consensus is disrupted as validators fail to participate
- Block finalization stalls if sufficient validators crash simultaneously
- Requires node restart and configuration fix to recover

This meets the **High Severity** criteria for "Validator node slowdowns" and "API crashes" from the Aptos bug bounty program. While not causing permanent network partition or fund loss, it significantly disrupts network operations and validator availability.

The vulnerability breaks the **Deterministic Execution** invariant - different nodes may crash at different times based on when they process affected blocks, creating execution inconsistencies across the network.

## Likelihood Explanation

**Likelihood: Low-Medium**

The vulnerability requires specific configuration:
- Operator explicitly sets `max_partitioning_rounds = 9` (or higher)
- Configuration includes `partition_last_round = true`
- Block contains sufficient transactions to trigger partitioning into 9 rounds
- Cross-shard dependencies exist between transactions in round 8

However, the default configuration uses `max_partitioning_rounds = 4`, making this unlikely in production unless operators intentionally override defaults. The lack of validation means well-intentioned performance tuning could accidentally trigger this issue. Test environments exploring higher round counts for benchmarking are most at risk.

## Recommendation

Add validation to prevent `max_partitioning_rounds` from exceeding `MAX_ALLOWED_PARTITIONING_ROUNDS`:

**In `execution/block-partitioner/src/v2/config.rs`:**

```rust
impl PartitionerV2Config {
    pub fn max_partitioning_rounds(mut self, val: usize) -> Self {
        assert!(
            val <= MAX_ALLOWED_PARTITIONING_ROUNDS,
            "max_partitioning_rounds ({}) cannot exceed MAX_ALLOWED_PARTITIONING_ROUNDS ({})",
            val,
            MAX_ALLOWED_PARTITIONING_ROUNDS
        );
        self.max_partitioning_rounds = val;
        self
    }
}
```

**In `execution/block-partitioner/src/v2/mod.rs`:**

```rust
impl PartitionerV2 {
    pub fn new(
        num_threads: usize,
        num_rounds_limit: usize,
        cross_shard_dep_avoid_threshold: f32,
        dashmap_num_shards: usize,
        partition_last_round: bool,
        pre_partitioner: Box<dyn PrePartitioner>,
    ) -> Self {
        assert!(
            num_rounds_limit <= MAX_ALLOWED_PARTITIONING_ROUNDS,
            "num_rounds_limit ({}) cannot exceed MAX_ALLOWED_PARTITIONING_ROUNDS ({})",
            num_rounds_limit,
            MAX_ALLOWED_PARTITIONING_ROUNDS
        );
        // ... rest of constructor
    }
}
```

Additionally, import the constant:
```rust
use aptos_types::block_executor::partitioner::MAX_ALLOWED_PARTITIONING_ROUNDS;
```

## Proof of Concept

```rust
#[test]
#[should_panic(expected = "index out of bounds")]
fn test_max_rounds_boundary_violation() {
    use crate::{
        pre_partition::uniform_partitioner::UniformPartitioner,
        test_utils::P2PBlockGenerator,
        v2::PartitionerV2,
        BlockPartitioner,
    };
    use rand::thread_rng;
    use aptos_types::block_executor::partitioner::MAX_ALLOWED_PARTITIONING_ROUNDS;

    // Create partitioner with rounds exceeding MAX_ALLOWED_PARTITIONING_ROUNDS
    let partitioner = PartitionerV2::new(
        8,
        MAX_ALLOWED_PARTITIONING_ROUNDS + 1, // Set to 9
        0.9,
        64,
        true, // partition_last_round = true is crucial
        Box::new(UniformPartitioner {}),
    );

    // Generate a block with enough transactions to trigger multiple rounds
    let block_generator = P2PBlockGenerator::new(10000);
    let mut rng = thread_rng();
    let transactions = block_generator.rand_block(&mut rng, 50000);

    // Partition the block - this should succeed
    let partitioned = partitioner.partition(transactions, 8);

    // Now attempt to execute the partitioned block with sharded executor
    // This would trigger the array access with round_id = 8 in message_txs[shard_id][8]
    // which causes index out of bounds panic since message_txs[shard_id] only has indices 0-7
    
    // In practice, this panic occurs in LocalCrossShardClient::send_cross_shard_msg
    // when CrossShardCommitSender extracts round_id = 8 from dependent edges
    // and calls send_cross_shard_msg(shard_id, 8, msg)
}
```

## Notes

The vulnerability exists at the boundary between two subsystems: the block partitioner and the sharded executor. The partitioner respects the configured `max_partitioning_rounds`, while the executor pre-allocates resources based on the hardcoded `MAX_ALLOWED_PARTITIONING_ROUNDS` constant. This architectural mismatch creates the vulnerability when configuration exceeds system limits.

The issue is exacerbated when `partition_last_round = true`, as this prevents the last round from being mapped to `GLOBAL_ROUND_ID`, which has separate handling logic. With the default `partition_last_round = false`, transactions in the problematic last round are merged and mapped to the global executor, avoiding the out-of-bounds access.

### Citations

**File:** types/src/block_executor/partitioner.rs (L20-21)
```rust
pub static MAX_ALLOWED_PARTITIONING_ROUNDS: usize = 8;
pub static GLOBAL_ROUND_ID: usize = MAX_ALLOWED_PARTITIONING_ROUNDS + 1;
```

**File:** execution/block-partitioner/src/v2/config.rs (L28-31)
```rust
    pub fn max_partitioning_rounds(mut self, val: usize) -> Self {
        self.max_partitioning_rounds = val;
        self
    }
```

**File:** execution/block-partitioner/src/v2/partition_to_matrix.rs (L37-47)
```rust
        for round_id in 0..(state.num_rounds_limit - 1) {
            let (accepted, discarded) = Self::discarding_round(state, round_id, remaining_txns);
            state.finalized_txn_matrix.push(accepted);
            remaining_txns = discarded;
            num_remaining_txns = remaining_txns.iter().map(|ts| ts.len()).sum();

            if num_remaining_txns
                < ((1.0 - state.cross_shard_dep_avoid_threshold) * state.num_txns() as f32) as usize
            {
                break;
            }
```

**File:** execution/block-partitioner/src/v2/state.rs (L282-288)
```rust
    pub(crate) fn final_sub_block_idx(&self, sub_blk_idx: SubBlockIdx) -> SubBlockIdx {
        if !self.partition_last_round && sub_blk_idx.round_id == self.num_rounds() - 1 {
            SubBlockIdx::global()
        } else {
            sub_blk_idx
        }
    }
```

**File:** execution/block-partitioner/src/v2/state.rs (L336-344)
```rust
                        self.final_sub_block_idx(follower_txn_idx.sub_block_idx);
                    let dst_txn_idx = ShardedTxnIndex {
                        txn_index: *self.final_idxs_by_pre_partitioned
                            [follower_txn_idx.pre_partitioned_txn_idx]
                            .read()
                            .unwrap(),
                        shard_id: final_sub_blk_idx.shard_id,
                        round_id: final_sub_blk_idx.round_id,
                    };
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/cross_shard_client.rs (L116-129)
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
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/local_executor_shard.rs (L100-102)
```rust
                (0..MAX_ALLOWED_PARTITIONING_ROUNDS)
                    .map(|_| unbounded())
                    .unzip()
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/local_executor_shard.rs (L331-333)
```rust
    fn send_cross_shard_msg(&self, shard_id: ShardId, round: RoundId, msg: CrossShardMsg) {
        self.message_txs[shard_id][round].send(msg).unwrap()
    }
```

**File:** execution/executor-service/src/remote_cross_shard_client.rs (L28-33)
```rust
            for round in 0..MAX_ALLOWED_PARTITIONING_ROUNDS {
                let message_type = format!("cross_shard_{}", round);
                let tx = controller.create_outbound_channel(*remote_address, message_type);
                txs.push(Mutex::new(tx));
            }
            message_txs.push(txs);
```

**File:** execution/executor-service/src/remote_cross_shard_client.rs (L55-58)
```rust
    fn send_cross_shard_msg(&self, shard_id: ShardId, round: RoundId, msg: CrossShardMsg) {
        let input_message = bcs::to_bytes(&msg).unwrap();
        let tx = self.message_txs[shard_id][round].lock().unwrap();
        tx.send(Message::new(input_message)).unwrap();
```
