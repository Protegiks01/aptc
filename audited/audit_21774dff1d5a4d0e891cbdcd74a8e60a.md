# Audit Report

## Title
Transaction Count Metric Fails to Detect Shard Imbalance Leading to Resource Exhaustion and Liveness Degradation

## Summary
The `SHARDED_BLOCK_EXECUTOR_TXN_COUNT` metric in `aptos-move/aptos-vm/src/sharded_block_executor/counters.rs` is a passive observation metric that only records transaction counts per shard without any active detection, alerting, or prevention mechanisms for shard imbalance. This allows malicious block proposers to craft blocks where transactions disproportionately target a single shard, causing resource exhaustion on that shard while others remain idle, leading to execution delays and network liveness degradation.

## Finding Description

The sharded block executor partitions transactions across multiple shards for parallel execution. The partitioning is deterministic, based on hashing storage locations to anchor shards. [1](#0-0) 

The metric `SHARDED_BLOCK_EXECUTOR_TXN_COUNT` is defined as a histogram that tracks transaction counts per shard and round. [2](#0-1) 

This metric is recorded during block execution, passively observing the number of transactions assigned to each shard. [3](#0-2) 

**Critical Security Gap**: The consensus layer performs extensive validation of proposed blocks, including transaction count limits, payload size limits, and proposer validity. [4](#0-3)  However, there is **no validation whatsoever** that checks whether a proposed block would result in severe shard imbalance when partitioned.

**Attack Mechanism**: A malicious block proposer can:
1. Craft or select transactions that predominantly access storage locations hashing to the same shard anchor
2. Since partitioning is deterministic via `get_anchor_shard_id`, all validators will independently arrive at the same imbalanced partitioning
3. This causes one shard to process the majority of transactions while others remain idle
4. The overloaded shard becomes a bottleneck, causing execution delays

The metric provides no protection because:
- It only records counts after partitioning has already occurred
- It has no alerting thresholds or detection logic
- It doesn't trigger any fallback mechanisms or block rejection
- It's merely exported to Prometheus for post-hoc analysis

## Impact Explanation

This vulnerability causes **validator node slowdowns** and degrades **network liveness**, qualifying as **Medium to High severity** per the Aptos bug bounty program.

**Specific Impacts**:
- Resource exhaustion on the overloaded shard (CPU, memory, I/O)
- Execution delays as the bottleneck shard processes all transactions sequentially
- Wasted resources on idle shards that could otherwise contribute to parallel execution
- Degraded network throughput and increased latency for users
- Potential timeout issues if the imbalanced execution exceeds round deadlines

While the system has consensus-level timeout mechanisms and backpressure controls, these react to symptoms rather than preventing the root cause. [5](#0-4) 

## Likelihood Explanation

**Likelihood: Medium**

The attack requires the malicious actor to be the block proposer for a round, which rotates among validators. However:
- Validators are trusted actors in normal operation
- The question explicitly considers malicious validator behavior
- A compromised or Byzantine validator could execute this attack
- The attack is repeatable whenever the malicious validator is the proposer
- Natural transaction patterns could accidentally create imbalances, which would also go undetected

The deterministic nature of partitioning makes this attack feasible - the proposer simply needs to select transactions from the mempool that hash to the same shard, or submit their own crafted transactions.

## Recommendation

Implement shard imbalance detection and prevention at multiple levels:

**1. Proposal Validation** - Add checks in consensus to reject blocks with excessive imbalance:
```rust
// In consensus/src/round_manager.rs, add to process_proposal():
if let Some(partitioned) = proposal.get_partitioned_preview() {
    let imbalance_ratio = calculate_shard_imbalance(&partitioned);
    ensure!(
        imbalance_ratio < MAX_ALLOWED_SHARD_IMBALANCE_RATIO,
        "Block rejected due to excessive shard imbalance: {:.2}",
        imbalance_ratio
    );
}
```

**2. Metric Enhancement** - Upgrade the metric to include active monitoring:
```rust
// In sharded_executor_service.rs, add detection:
let txn_count = sub_block.transactions.len();
SHARDED_BLOCK_EXECUTOR_TXN_COUNT.observe_with(..., txn_count as f64);

// Add imbalance detection
if txn_count > SHARD_IMBALANCE_THRESHOLD * average_txn_count_per_shard {
    warn!("Shard {} has {} transactions, significantly above average {}",
          self.shard_id, txn_count, average_txn_count_per_shard);
    SHARD_IMBALANCE_DETECTED_COUNT.inc();
}
```

**3. Partitioner Improvement** - Enhance the partitioner to enforce balance constraints or use dynamic rebalancing when imbalance is detected.

## Proof of Concept

```rust
#[test]
fn test_metric_fails_to_detect_shard_imbalance() {
    // Create a block with all transactions accessing storage locations
    // that hash to shard 0
    let num_shards = 4;
    let num_txns = 100;
    
    let mut transactions = Vec::new();
    for i in 0..num_txns {
        // Craft transactions that all hash to shard 0
        let storage_location = craft_storage_location_for_shard(0, num_shards);
        let txn = create_transaction_accessing(storage_location);
        transactions.push(txn);
    }
    
    // Partition the block
    let partitioner = PartitionerV2::new(...);
    let partitioned = partitioner.partition(
        transactions.into_iter().map(|t| t.into()).collect(),
        num_shards
    );
    
    // Verify severe imbalance exists
    let shard_0_count = partitioned.sharded_txns()[0].total_txn_count();
    let shard_1_count = partitioned.sharded_txns()[1].total_txn_count();
    
    assert!(shard_0_count >= 90); // Most transactions in shard 0
    assert!(shard_1_count <= 10);  // Few in other shards
    
    // The metric would only record this, NOT detect or prevent it
    // Execute and verify no rejection occurs
    let result = executor.execute_block(Arc::new(state_view), partitioned, ...);
    assert!(result.is_ok()); // Block executes despite severe imbalance!
}

fn craft_storage_location_for_shard(target_shard: usize, num_shards: usize) -> StorageLocation {
    // Brute force find a storage location that hashes to target_shard
    loop {
        let candidate = generate_random_storage_location();
        let mut hasher = DefaultHasher::new();
        candidate.hash(&mut hasher);
        if (hasher.finish() % num_shards as u64) as usize == target_shard {
            return candidate;
        }
    }
}
```

**Notes**

The vulnerability exists because the metric is purely observational rather than protective. While block execution has various limits and timeouts, none specifically prevent or detect shard imbalance at proposal time. The deterministic partitioning ensures all validators experience the same imbalance, making it a consensus-wide performance degradation rather than a node-specific issue.

### Citations

**File:** execution/block-partitioner/src/lib.rs (L39-43)
```rust
fn get_anchor_shard_id(storage_location: &StorageLocation, num_shards: usize) -> ShardId {
    let mut hasher = DefaultHasher::new();
    storage_location.hash(&mut hasher);
    (hasher.finish() % num_shards as u64) as usize
}
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/counters.rs (L52-59)
```rust
pub static SHARDED_BLOCK_EXECUTOR_TXN_COUNT: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "sharded_block_executor_txn_count",
        "Count of number of transactions per shard per round in sharded execution",
        &["shard_id", "round_id"]
    )
    .unwrap()
});
```

**File:** aptos-move/aptos-vm/src/sharded_block_executor/sharded_executor_service.rs (L195-198)
```rust
            SHARDED_BLOCK_EXECUTOR_TXN_COUNT.observe_with(
                &[&self.shard_id.to_string(), &round.to_string()],
                sub_block.transactions.len() as f64,
            );
```

**File:** consensus/src/round_manager.rs (L1166-1193)
```rust
        ensure!(
            num_validator_txns <= vtxn_count_limit,
            "process_proposal failed with per-block vtxn count limit exceeded: limit={}, actual={}",
            self.vtxn_config.per_block_limit_txn_count(),
            num_validator_txns
        );
        ensure!(
            validator_txns_total_bytes <= vtxn_bytes_limit,
            "process_proposal failed with per-block vtxn bytes limit exceeded: limit={}, actual={}",
            self.vtxn_config.per_block_limit_total_bytes(),
            validator_txns_total_bytes
        );
        let payload_len = proposal.payload().map_or(0, |payload| payload.len());
        let payload_size = proposal.payload().map_or(0, |payload| payload.size());
        ensure!(
            num_validator_txns + payload_len as u64 <= self.local_config.max_receiving_block_txns,
            "Payload len {} exceeds the limit {}",
            payload_len,
            self.local_config.max_receiving_block_txns,
        );

        ensure!(
            validator_txns_total_bytes + payload_size as u64
                <= self.local_config.max_receiving_block_bytes,
            "Payload size {} exceeds the limit {}",
            payload_size,
            self.local_config.max_receiving_block_bytes,
        );
```

**File:** consensus/src/liveness/proposal_generator.rs (L10-12)
```rust
        CHAIN_HEALTH_BACKOFF_TRIGGERED, EXECUTION_BACKPRESSURE_ON_PROPOSAL_TRIGGERED,
        PIPELINE_BACKPRESSURE_ON_PROPOSAL_TRIGGERED, PROPOSER_DELAY_PROPOSAL,
        PROPOSER_ESTIMATED_CALIBRATED_BLOCK_GAS, PROPOSER_ESTIMATED_CALIBRATED_BLOCK_TXNS,
```
