# Audit Report

## Title
Byzantine Executor Shard Can Cause Coordinator Panic via Malformed Round Count in Sharded Block Execution

## Summary
A Byzantine remote executor shard can send execution results with more rounds than expected, causing an index-out-of-bounds panic in the block execution coordinator. Additionally, misconfiguration where `num_shards = 0` causes multiple panic conditions including division by zero during transaction partitioning.

## Finding Description

The sharded block executor system has critical validation gaps that allow malformed execution results to crash validator nodes:

**Vulnerability 1: Missing Round Count Validation**

The coordinator assumes all executor shards return the same number of rounds and sizes its result buffer based only on the first shard's output: [1](#0-0) 

If a Byzantine shard returns more rounds than shard 0, the index calculation `round * num_executor_shards + shard_id` exceeds the pre-allocated `ordered_results` vector size, causing a panic.

**Vulnerability 2: Division by Zero with num_shards = 0**

The transaction partitioner's anchor shard calculation performs modulo without validation: [2](#0-1) 

If `num_shards` is 0, this causes division by zero (modulo is implemented as division). This same zero-check failure affects multiple locations: [3](#0-2) 

**Vulnerability 3: MAX_ALLOWED_PARTITIONING_ROUNDS Buffer Overflow**

Cross-shard message channels are pre-allocated for exactly `MAX_ALLOWED_PARTITIONING_ROUNDS`: [4](#0-3) 

But the partitioner configuration allows arbitrary `max_partitioning_rounds` values without validation: [5](#0-4) 

If configured above 8, cross-shard message sends will panic: [6](#0-5) 

## Impact Explanation

This breaks the **Deterministic Execution** invariant (all validators must produce identical state roots for identical blocks) and enables **High Severity** impacts:

- **Validator Node Crashes**: A Byzantine executor shard can crash the coordinator by returning malformed results
- **Consensus Liveness Impact**: If multiple validators use remote executor shards and a malicious shard targets them, network liveness degrades
- **Deterministic Execution Violation**: Validators with different shard configurations (local vs remote) may behave differently when attacked

Per the Aptos bug bounty criteria, this qualifies as **High Severity** ($50,000): "Validator node slowdowns/crashes" and "Significant protocol violations."

## Likelihood Explanation

**High Likelihood** for exploitation:

1. The remote executor architecture (RemoteExecutorClient) accepts execution results over the network without validating round counts
2. A compromised or malicious executor shard can easily craft `RemoteExecutionResult` with arbitrary round counts
3. No authentication or validation of result structure integrity beyond deserialization
4. The misconfiguration scenario (num_shards=0 or max_rounds>8) can occur during validator setup

## Recommendation

Add comprehensive input validation at result aggregation boundaries:

```rust
// In ShardedBlockExecutor::execute_block (mod.rs)
let num_rounds = sharded_output[0].len();

// VALIDATE: All shards must return same number of rounds
for (shard_id, shard_results) in sharded_output.iter().enumerate() {
    if shard_results.len() != num_rounds {
        return Err(VMStatus::Error(StatusCode::INTERNAL_ERROR, 
            Some(format!("Shard {} returned {} rounds but expected {}", 
                shard_id, shard_results.len(), num_rounds))));
    }
}

// VALIDATE: num_shards must be non-zero
if num_executor_shards == 0 {
    return Err(VMStatus::Error(StatusCode::INTERNAL_ERROR,
        Some("num_executor_shards cannot be zero".to_string())));
}
```

```rust
// In get_anchor_shard_id (lib.rs)
fn get_anchor_shard_id(storage_location: &StorageLocation, num_shards: usize) -> ShardId {
    assert!(num_shards > 0, "num_shards must be greater than 0");
    let mut hasher = DefaultHasher::new();
    storage_location.hash(&mut hasher);
    (hasher.finish() % num_shards as u64) as usize
}
```

```rust
// In PartitionerV2Config validation
pub fn max_partitioning_rounds(mut self, val: usize) -> Self {
    assert!(val <= MAX_ALLOWED_PARTITIONING_ROUNDS,
        "max_partitioning_rounds {} exceeds MAX_ALLOWED_PARTITIONING_ROUNDS {}",
        val, MAX_ALLOWED_PARTITIONING_ROUNDS);
    self.max_partitioning_rounds = val;
    self
}
```

## Proof of Concept

```rust
// Mock Byzantine executor shard returning excessive rounds
use aptos_executor_service::RemoteExecutionResult;
use aptos_types::transaction::TransactionOutput;

fn create_malicious_result(honest_rounds: usize, malicious_rounds: usize) 
    -> RemoteExecutionResult {
    let mut results = vec![];
    for _ in 0..malicious_rounds {
        results.push(vec![TransactionOutput::default()]);
    }
    RemoteExecutionResult::new(Ok(results))
}

// Attack scenario:
// 1. Honest shard 0 returns 3 rounds
// 2. Byzantine shard 1 returns 10 rounds
// 3. Coordinator allocates buffer for 3 * num_shards entries
// 4. When processing shard 1's round 9, index = 9 * 2 + 1 = 19
// 5. Buffer only has 3 * 2 = 6 entries
// 6. PANIC: index out of bounds
```

## Notes

The vulnerabilities stem from implicit trust in executor shard outputs and lack of defensive validation at aggregation boundaries. While remote executor shards are part of validator infrastructure, the threat model must account for compromised components. The `num_shards=0` scenario, while appearing as misconfiguration, can occur during validator initialization race conditions or during recovery from crashes.

### Citations

**File:** aptos-move/aptos-vm/src/sharded_block_executor/mod.rs (L98-105)
```rust
        let num_rounds = sharded_output[0].len();
        let mut aggregated_results = vec![];
        let mut ordered_results = vec![vec![]; num_executor_shards * num_rounds];
        // Append the output from individual shards in the round order
        for (shard_id, results_from_shard) in sharded_output.into_iter().enumerate() {
            for (round, result) in results_from_shard.into_iter().enumerate() {
                ordered_results[round * num_executor_shards + shard_id] = result;
            }
```

**File:** execution/block-partitioner/src/lib.rs (L39-43)
```rust
fn get_anchor_shard_id(storage_location: &StorageLocation, num_shards: usize) -> ShardId {
    let mut hasher = DefaultHasher::new();
    storage_location.hash(&mut hasher);
    (hasher.finish() % num_shards as u64) as usize
}
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_aggregator_service.rs (L174-175)
```rust
    let num_shards = sharded_output.len();
    let num_rounds = sharded_output[0].len();
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

**File:** aptos-move/aptos-vm/src/sharded_block_executor/local_executor_shard.rs (L331-332)
```rust
    fn send_cross_shard_msg(&self, shard_id: ShardId, round: RoundId, msg: CrossShardMsg) {
        self.message_txs[shard_id][round].send(msg).unwrap()
```

**File:** execution/block-partitioner/src/v2/config.rs (L28-31)
```rust
    pub fn max_partitioning_rounds(mut self, val: usize) -> Self {
        self.max_partitioning_rounds = val;
        self
    }
```
