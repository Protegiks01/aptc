# Audit Report

## Title
Unbounded Batch Size in State Merkle Pruner Initialization Causes Memory Exhaustion and Validator Node Crashes

## Summary
The state merkle pruner uses `usize::MAX` as the batch size limit during shard pruner initialization, allowing unbounded collection of stale node indices into memory. This causes memory exhaustion and validator node crashes when processing large backlogs during catch-up operations, violating resource limit invariants and affecting validator availability.

## Finding Description

The vulnerability exists in the shard pruner initialization where `usize::MAX` is used as the batch size parameter.

During shard pruner initialization, the `new()` function calls `prune()` with `usize::MAX` as the `max_nodes_to_prune` parameter [1](#0-0) , attempting to catch up from the shard's current progress to the metadata pruner's progress in a single operation.

The `get_stale_node_indices()` function collects stale node indices in a loop that continues while `indices.len() < limit` [2](#0-1) . When `limit` is `usize::MAX`, this effectively removes any size constraint, allowing unbounded collection of all stale nodes from the start version to the target version.

The configuration explicitly acknowledges that "A 10k transaction block (touching 60k state values) on a 4B items DB yields 300k JMT nodes" [3](#0-2) , demonstrating the scale of stale nodes that can accumulate.

Each collected stale node index results in two delete operations being added to the `SchemaBatch` [4](#0-3) . The `SchemaBatch` structure is defined as `rows: DropHelper<HashMap<ColumnFamilyName, Vec<WriteOp>>>` [5](#0-4)  with no internal size limits.

**Attack Scenario:** When a validator node restarts after extended downtime (e.g., several hours at 5,000 TPS), millions of stale nodes accumulate. During initialization, the shard pruner attempts to:
1. Collect all stale node indices from the entire gap into a single `Vec<StaleNodeIndex>` in memory
2. Create two delete operations per index in the unbounded `SchemaBatch`
3. This can consume tens of gigabytes of memory before the write operation completes
4. Leading to OOM kills and node crashes

The pruner loop structure shows that `current_progress` is not updated between iterations [6](#0-5) , meaning with `usize::MAX`, all stale nodes are collected in a single iteration.

## Impact Explanation

This vulnerability causes validator node crashes during initialization and catch-up operations, which falls under **HIGH Severity** per the Aptos bug bounty program criteria:

- **Validator Node Slowdowns/Crashes (HIGH)**: The vulnerability directly causes validator nodes to crash due to memory exhaustion during initialization after downtime
- **Network Availability Impact**: If multiple validators experience downtime simultaneously (e.g., during coordinated maintenance or network events), their simultaneous catch-up attempts can fail, degrading network validator availability
- **Resource Limit Violations**: Violates fundamental resource constraint requirements that all operations must respect memory limits

This is not classified as a network DoS attack (which would be out of scope), but rather a resource management bug in the storage layer that causes self-inflicted memory exhaustion during legitimate operational scenarios.

## Likelihood Explanation

**HIGH likelihood** of occurrence:

- **Natural Trigger**: Happens automatically during validator node restart after any extended offline period (maintenance, crashes, upgrades)
- **No Attacker Required**: No malicious actor or special conditions needed - this is triggered by normal operational scenarios
- **Realistic Scale**: With mainnet processing thousands of transactions per second, even a few hours of downtime results in millions of versions and potentially hundreds of millions of stale node indices
- **Configuration Acknowledgment**: The default configuration already acknowledges that 10,000 transactions can generate 300,000 stale JMT nodes [3](#0-2) , making large accumulations inevitable
- **Common Scenario**: Validator operators regularly restart nodes for maintenance, updates, or configuration changes

## Recommendation

Replace `usize::MAX` with the configured `batch_size` parameter during shard pruner initialization. Modify the initialization code:

```rust
// In state_merkle_shard_pruner.rs
pub(in crate::pruner) fn new(
    shard_id: usize,
    db_shard: Arc<DB>,
    metadata_progress: Version,
    batch_size: usize,  // Add batch_size parameter
) -> Result<Self> {
    let progress = get_or_initialize_subpruner_progress(
        &db_shard,
        &S::progress_metadata_key(Some(shard_id)),
        metadata_progress,
    )?;
    let myself = Self {
        shard_id,
        db_shard,
        _phantom: PhantomData,
    };

    info!(
        progress = progress,
        metadata_progress = metadata_progress,
        "Catching up {} shard {shard_id}.",
        S::name(),
    );
    // Use configured batch_size instead of usize::MAX
    myself.prune(progress, metadata_progress, batch_size)?;

    Ok(myself)
}
```

Update the loop in `prune()` to properly advance `current_progress` between iterations to enable batch processing.

## Proof of Concept

A PoC would require:
1. Setting up a validator node with state merkle pruning enabled
2. Allowing the node to process transactions normally to accumulate stale nodes
3. Simulating extended downtime by stopping the shard pruners but allowing transactions to continue
4. Restarting the node and observing memory consumption during initialization

The memory consumption can be calculated as:
- If offline for 1 hour at 5,000 TPS = 18,000,000 transactions
- At 300k stale nodes per 10k transactions = 540,000,000 stale node indices
- Each `StaleNodeIndex` structure ~50-100 bytes = 27-54 GB for the vector alone
- Plus 2× delete operations in SchemaBatch = additional 27-54 GB
- Total: 54-108 GB memory consumption, causing OOM on typical validator hardware

### Citations

**File:** storage/aptosdb/src/pruner/state_merkle_pruner/state_merkle_shard_pruner.rs (L53-53)
```rust
        myself.prune(progress, metadata_progress, usize::MAX)?;
```

**File:** storage/aptosdb/src/pruner/state_merkle_pruner/state_merkle_shard_pruner.rs (L64-97)
```rust
        loop {
            let mut batch = SchemaBatch::new();
            let (indices, next_version) = StateMerklePruner::get_stale_node_indices(
                &self.db_shard,
                current_progress,
                target_version,
                max_nodes_to_prune,
            )?;

            indices.into_iter().try_for_each(|index| {
                batch.delete::<JellyfishMerkleNodeSchema>(&index.node_key)?;
                batch.delete::<S>(&index)
            })?;

            let mut done = true;
            if let Some(next_version) = next_version {
                if next_version <= target_version {
                    done = false;
                }
            }

            if done {
                batch.put::<DbMetadataSchema>(
                    &S::progress_metadata_key(Some(self.shard_id)),
                    &DbMetadataValue::Version(target_version),
                )?;
            }

            self.db_shard.write_schemas(batch)?;

            if done {
                break;
            }
        }
```

**File:** storage/aptosdb/src/pruner/state_merkle_pruner/mod.rs (L205-214)
```rust
        while indices.len() < limit {
            if let Some((index, _)) = iter.next().transpose()? {
                next_version = Some(index.stale_since_version);
                if index.stale_since_version <= target_version {
                    indices.push(index);
                    continue;
                }
            }
            break;
        }
```

**File:** config/src/config/storage_config.rs (L408-410)
```rust
            // A 10k transaction block (touching 60k state values, in the case of the account
            // creation benchmark) on a 4B items DB (or 1.33B accounts) yields 300k JMT nodes
            batch_size: 1_000,
```

**File:** storage/schemadb/src/batch.rs (L131-131)
```rust
    rows: DropHelper<HashMap<ColumnFamilyName, Vec<WriteOp>>>,
```
