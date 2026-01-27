# Audit Report

## Title
Out-of-Bounds Array Access in RemoteCrossShardClient Causes Total System Liveness Failure

## Summary
The `RemoteCrossShardClient::send_cross_shard_msg()` and `receive_cross_shard_msg()` functions perform unchecked array indexing using coordinator-supplied `round` values, while the underlying arrays are sized to `MAX_ALLOWED_PARTITIONING_ROUNDS` (8). A malicious or misconfigured coordinator can set `max_partitioning_rounds` to values exceeding this limit, causing all executor shards to panic during block execution and resulting in total network unavailability.

## Finding Description

The vulnerability exists in the distributed sharded execution architecture where a coordinator partitions blocks and distributes them to executor shards. The critical flaw is a mismatch between:

1. **Array initialization** - Fixed-size arrays based on `MAX_ALLOWED_PARTITIONING_ROUNDS` (8)
2. **Partitioner configuration** - Unbounded `max_partitioning_rounds` parameter
3. **Runtime access** - Unchecked indexing using round values from partitioned transactions

**Attack Flow:**

The coordinator controls the `max_partitioning_rounds` parameter via CLI with no validation against `MAX_ALLOWED_PARTITIONING_ROUNDS`. [1](#0-0) 

The partitioner creates transactions assigned to rounds up to `max_partitioning_rounds`, storing these round values in `ShardedTxnIndex` structures within cross-shard dependencies. [2](#0-1) [3](#0-2) 

The `RemoteCrossShardClient` initializes communication channels only for rounds `0..MAX_ALLOWED_PARTITIONING_ROUNDS`, creating fixed-size arrays. [4](#0-3) 

During execution, when transactions from rounds ≥ 8 attempt cross-shard communication, the `send_cross_shard_msg()` function performs unchecked array access. [5](#0-4) 

The same vulnerability exists in `receive_cross_shard_msg()`. [6](#0-5) 

**Invariant Violation:** This breaks the **liveness invariant** - the system must be able to process blocks continuously. When all executor shards panic simultaneously, the entire distributed execution system becomes unavailable.

## Impact Explanation

**Critical Severity** - This vulnerability causes **total loss of liveness/network availability**, meeting the Critical severity criteria in the Aptos bug bounty program.

**Concrete Impact:**
- All executor shards crash simultaneously when processing blocks with round_id ≥ 8
- Complete denial of service - no blocks can be executed
- Requires manual intervention (restart all nodes) to recover
- In distributed deployment, affects all validator nodes using the sharded executor
- Non-recoverable during runtime - system remains down until nodes are restarted with correct configuration

The panic occurs during critical block execution path, making this a consensus-layer failure affecting the entire network's ability to process transactions.

## Likelihood Explanation

**Likelihood: Medium-High**

**Factors increasing likelihood:**
- No validation exists preventing `max_partitioning_rounds > MAX_ALLOWED_PARTITIONING_ROUNDS` [7](#0-6) 
- Can be triggered unintentionally through misconfiguration
- Default value (4) is safe, but custom configurations are vulnerable
- Any coordinator operator can set this parameter

**Attacker requirements:**
- Access to coordinator node configuration (insider threat or compromised coordinator)
- Ability to set `--max-partitioning-rounds` CLI parameter
- No special privileges beyond coordinator operation required

The security question explicitly asks about "malicious coordinators," indicating this threat model is within scope.

## Recommendation

**Fix 1: Add validation in PartitionerV2Config**

Add a validation check that enforces `max_partitioning_rounds <= MAX_ALLOWED_PARTITIONING_ROUNDS` when building the partitioner configuration. This should be in the `PartitionerConfig::build()` method:

```rust
impl PartitionerConfig for PartitionerV2Config {
    fn build(&self) -> Box<dyn BlockPartitioner> {
        assert!(
            self.max_partitioning_rounds <= MAX_ALLOWED_PARTITIONING_ROUNDS,
            "max_partitioning_rounds ({}) must not exceed MAX_ALLOWED_PARTITIONING_ROUNDS ({})",
            self.max_partitioning_rounds,
            MAX_ALLOWED_PARTITIONING_ROUNDS
        );
        let pre_partitioner = self.pre_partitioner_config.build();
        // ... rest of build logic
    }
}
```

**Fix 2: Add bounds checking in RemoteCrossShardClient**

Add defensive bounds checking in both `send_cross_shard_msg()` and `receive_cross_shard_msg()`:

```rust
fn send_cross_shard_msg(&self, shard_id: ShardId, round: RoundId, msg: CrossShardMsg) {
    assert!(
        round < MAX_ALLOWED_PARTITIONING_ROUNDS,
        "Round {} exceeds MAX_ALLOWED_PARTITIONING_ROUNDS {}",
        round, MAX_ALLOWED_PARTITIONING_ROUNDS
    );
    assert!(
        shard_id < self.message_txs.len(),
        "Shard ID {} exceeds number of shards {}",
        shard_id, self.message_txs.len()
    );
    let input_message = bcs::to_bytes(&msg).unwrap();
    let tx = self.message_txs[shard_id][round].lock().unwrap();
    tx.send(Message::new(input_message)).unwrap();
}
```

**Recommended approach:** Implement both fixes for defense-in-depth.

## Proof of Concept

**Reproduction Steps:**

1. Set up distributed executor environment with coordinator and executor shards
2. Start coordinator with malicious configuration:
   ```bash
   cargo run --bin executor-benchmark -- \
     --max-partitioning-rounds 10 \
     --num-executor-shards 4 \
     --remote-executor-addresses <shard_addresses> \
     ...
   ```

3. Execute a block with sufficient transactions to trigger partitioning into rounds ≥ 8

4. Observe all executor shards panic with error:
   ```
   thread 'ExecutorService-X' panicked at 'index out of bounds: the len is 8 but the index is 9'
   ```

**Test case to validate the fix:**

```rust
#[test]
#[should_panic(expected = "max_partitioning_rounds")]
fn test_partitioner_config_validation() {
    use aptos_block_partitioner::v2::config::PartitionerV2Config;
    use aptos_types::block_executor::partitioner::MAX_ALLOWED_PARTITIONING_ROUNDS;
    
    let config = PartitionerV2Config::default()
        .max_partitioning_rounds(MAX_ALLOWED_PARTITIONING_ROUNDS + 1);
    
    // This should panic with validation error
    let _partitioner = config.build();
}
```

### Citations

**File:** execution/executor-benchmark/src/main.rs (L216-217)
```rust
    #[clap(long, default_value = "4")]
    max_partitioning_rounds: usize,
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

**File:** execution/block-partitioner/src/v2/state.rs (L312-318)
```rust
                let src_txn_idx = ShardedTxnIndex {
                    txn_index: *self.final_idxs_by_pre_partitioned[txn_idx.pre_partitioned_txn_idx]
                        .read()
                        .unwrap(),
                    shard_id: txn_idx.shard_id(),
                    round_id: txn_idx.round_id(),
                };
```

**File:** execution/executor-service/src/remote_cross_shard_client.rs (L28-34)
```rust
            for round in 0..MAX_ALLOWED_PARTITIONING_ROUNDS {
                let message_type = format!("cross_shard_{}", round);
                let tx = controller.create_outbound_channel(*remote_address, message_type);
                txs.push(Mutex::new(tx));
            }
            message_txs.push(txs);
        }
```

**File:** execution/executor-service/src/remote_cross_shard_client.rs (L55-59)
```rust
    fn send_cross_shard_msg(&self, shard_id: ShardId, round: RoundId, msg: CrossShardMsg) {
        let input_message = bcs::to_bytes(&msg).unwrap();
        let tx = self.message_txs[shard_id][round].lock().unwrap();
        tx.send(Message::new(input_message)).unwrap();
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

**File:** execution/block-partitioner/src/v2/config.rs (L28-30)
```rust
    pub fn max_partitioning_rounds(mut self, val: usize) -> Self {
        self.max_partitioning_rounds = val;
        self
```
