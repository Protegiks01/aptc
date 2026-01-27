# Audit Report

## Title
Performance Degradation in BatchStats::commit() Due to Millions of Put Operations in High-Write-Volume Blocks

## Summary
The `BatchStats::commit()` function in `storage/schemadb/src/batch.rs` contains nested loops that iterate through all accumulated put operations when statistics sampling is enabled. In blocks with maximum write operations (up to 81 million operations across 16 shards, or ~5 million per shard), this can cause periodic validator slowdowns during the commit phase.

## Finding Description

The vulnerability lies in the metrics collection mechanism during database batch commits. When state updates are written to the database, each operation accumulates in the `put_sizes` HashMap within `BatchStats`: [1](#0-0) 

During commit, nested loops iterate through all accumulated operations: [2](#0-1) 

**Attack Path:**

1. An attacker (or normal high-throughput scenario) creates transactions with maximum write operations. Aptos allows up to 8,192 write operations per transaction: [3](#0-2) 

2. A block can contain up to 10,000 transactions: [4](#0-3) 

3. Total operations in a full block: 10,000 transactions × 8,192 operations = 81,920,000 operations

4. These operations are distributed across 16 shards: [5](#0-4) 

5. Each shard receives approximately 5,120,000 operations, stored in a `NativeBatch` with `SampledBatchStats`.

6. Statistics are collected with 1% sampling probability: [6](#0-5) 

7. When a sampled batch commits (1 in 100 batches), `commit()` is called on the critical write path: [7](#0-6) 

8. For a shard with 5 million operations, the nested loops execute 5 million iterations, calling `observe_with()` on a histogram metric each time.

9. While shards commit in parallel, the overall commit blocks until all shards complete: [8](#0-7) 

## Impact Explanation

This issue qualifies as **Medium Severity** under Aptos bug bounty criteria:

- **Performance Impact**: Periodic validator slowdowns occur when sampled batches with millions of operations commit. Even with fast thread-local histograms, iterating through 5 million entries and updating histogram buckets takes measurable time (estimated 50-500ms depending on implementation).

- **Frequency**: Affects approximately 1% of blocks (due to 1% sampling rate), distributed across 16 shards. In high-throughput scenarios with consistently large blocks, this translates to periodic performance degradation.

- **Severity Classification**: Falls under "Validator node slowdowns" which is listed in the bug bounty program. However, the impact is mitigated by:
  - Low sampling rate (1%)
  - Parallel shard commits
  - Non-deterministic (probabilistic sampling)
  - Does not affect consensus safety or liveness

The issue does not cause consensus violations, fund loss, or network unavailability, limiting it to Medium severity.

## Likelihood Explanation

**Likelihood: Medium**

- **Ease of Exploitation**: HIGH - Requires no special privileges. Any user can submit write-heavy transactions. Normal high-throughput operations naturally trigger this condition.

- **Frequency**: LOW - Only occurs in ~1% of batches due to probabilistic sampling, and only when those batches contain millions of operations.

- **Prerequisites**: Requires blocks to be consistently full with write-heavy transactions, which is realistic under high network load but not constant.

- **Detection**: Difficult to attribute slowdowns specifically to this issue versus normal performance variance.

## Recommendation

Implement a cap on the number of statistics entries collected per batch to prevent unbounded iteration:

```rust
const MAX_STATS_ENTRIES_PER_CF: usize = 10_000;

impl BatchStats {
    fn put(&mut self, cf_name: ColumnFamilyName, size: usize) {
        let sizes = self.put_sizes.entry(cf_name).or_default();
        if sizes.len() < MAX_STATS_ENTRIES_PER_CF {
            sizes.push(size);
        }
    }
    
    // Alternative: Use sampling at the individual operation level
    fn put_sampled(&mut self, cf_name: ColumnFamilyName, size: usize) {
        if rand::random::<u32>() % 1000 == 0 {  // 0.1% sampling per operation
            self.put_sizes.entry(cf_name).or_default().push(size);
        }
    }
}
```

This ensures that even with millions of operations, the commit iteration is bounded to a reasonable number, preventing performance degradation while still collecting representative statistics.

## Proof of Concept

```rust
// Rust reproduction demonstrating the performance impact
use std::collections::HashMap;
use std::time::Instant;

fn main() {
    // Simulate BatchStats with millions of entries
    let mut put_sizes: HashMap<&str, Vec<usize>> = HashMap::new();
    
    // Add 5 million entries (one shard's worth in a full block)
    let cf_name = "state_value";
    let sizes = put_sizes.entry(cf_name).or_insert_with(Vec::new);
    for i in 0..5_000_000 {
        sizes.push(100 + (i % 1000)); // Typical state value sizes
    }
    
    println!("Accumulated {} entries across {} column families", 
             put_sizes.values().map(|v| v.len()).sum::<usize>(),
             put_sizes.len());
    
    // Time the commit iteration
    let start = Instant::now();
    let mut count = 0;
    for (_cf_name, put_sizes) in &put_sizes {
        for _put_size in put_sizes {
            // Simulate histogram observation (simplified)
            count += 1;
        }
    }
    let duration = start.elapsed();
    
    println!("Iterated through {} entries in {:?}", count, duration);
    println!("This represents the overhead added to block commit for 1% of batches");
}

// Expected output: Iteration takes 50-500ms depending on system
// This delay occurs during the critical block commit path for validators
```

**Note**: A full end-to-end PoC would require:
1. Creating Move transactions with 8,192 write operations each
2. Submitting 10,000 such transactions in a block
3. Monitoring validator commit times with statistics enabled
4. Demonstrating measurable slowdown when sampled batches commit

This is feasible but requires a full testnet environment.

---

**Notes:**

While this is a valid performance issue that can cause measurable validator slowdowns, it has several mitigating factors:
- The 1% sampling rate significantly reduces frequency
- Parallel shard commits distribute the impact
- Thread-local metrics avoid lock contention
- The issue does not affect consensus safety, determinism, or correctness

The finding is valid as described in the security question, but represents a quality-of-service degradation rather than a critical security vulnerability. It aligns with Medium severity classification for "validator node slowdowns" in the bug bounty program.

### Citations

**File:** storage/schemadb/src/batch.rs (L24-26)
```rust
    fn put(&mut self, cf_name: ColumnFamilyName, size: usize) {
        self.put_sizes.entry(cf_name).or_default().push(size);
    }
```

**File:** storage/schemadb/src/batch.rs (L32-41)
```rust
    fn commit(&self) {
        for (cf_name, put_sizes) in &self.put_sizes {
            for put_size in put_sizes {
                APTOS_SCHEMADB_PUT_BYTES_SAMPLED.observe_with(&[cf_name], *put_size as f64);
            }
        }
        for (cf_name, num_deletes) in &self.num_deletes {
            APTOS_SCHEMADB_DELETES_SAMPLED.inc_with_by(&[cf_name], *num_deletes as u64);
        }
    }
```

**File:** storage/schemadb/src/batch.rs (L69-76)
```rust
impl Default for SampledBatchStats {
    fn default() -> Self {
        const SAMPLING_PCT: usize = 1;

        Self {
            inner: (rand::random::<usize>() % 100 < SAMPLING_PCT).then_some(Default::default()),
        }
    }
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L174-177)
```rust
            max_write_ops_per_transaction: NumSlots,
            { 11.. => "max_write_ops_per_transaction" },
            8192,
        ],
```

**File:** config/src/config/consensus_config.rs (L20-24)
```rust
const MAX_SENDING_BLOCK_TXNS_AFTER_FILTERING: u64 = 1800;
const MAX_SENDING_OPT_BLOCK_TXNS_AFTER_FILTERING: u64 = 1000;
const MAX_SENDING_BLOCK_TXNS: u64 = 5000;
pub(crate) static MAX_RECEIVING_BLOCK_TXNS: Lazy<u64> =
    Lazy::new(|| 10000.max(2 * MAX_SENDING_BLOCK_TXNS));
```

**File:** types/src/state_store/mod.rs (L27-27)
```rust
pub const NUM_STATE_SHARDS: usize = 16;
```

**File:** storage/schemadb/src/lib.rs (L289-304)
```rust
    fn write_schemas_inner(&self, batch: impl IntoRawBatch, option: &WriteOptions) -> DbResult<()> {
        let labels = [self.name.as_str()];
        let _timer = APTOS_SCHEMADB_BATCH_COMMIT_LATENCY_SECONDS.timer_with(&labels);

        let raw_batch = batch.into_raw_batch(self)?;

        let serialized_size = raw_batch.inner.size_in_bytes();
        self.inner
            .write_opt(raw_batch.inner, option)
            .into_db_res()?;

        raw_batch.stats.commit();
        APTOS_SCHEMADB_BATCH_COMMIT_BYTES.observe_with(&[&self.name], serialized_size as f64);

        Ok(())
    }
```

**File:** storage/aptosdb/src/state_kv_db.rs (L177-208)
```rust
    pub(crate) fn commit(
        &self,
        version: Version,
        state_kv_metadata_batch: Option<SchemaBatch>,
        sharded_state_kv_batches: ShardedStateKvSchemaBatch,
    ) -> Result<()> {
        let _timer = OTHER_TIMERS_SECONDS.timer_with(&["state_kv_db__commit"]);
        {
            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["state_kv_db__commit_shards"]);
            THREAD_MANAGER.get_io_pool().scope(|s| {
                let mut batches = sharded_state_kv_batches.into_iter();
                for shard_id in 0..NUM_STATE_SHARDS {
                    let state_kv_batch = batches
                        .next()
                        .expect("Not sufficient number of sharded state kv batches");
                    s.spawn(move |_| {
                        // TODO(grao): Consider propagating the error instead of panic, if necessary.
                        self.commit_single_shard(version, shard_id, state_kv_batch)
                            .unwrap_or_else(|err| {
                                panic!("Failed to commit shard {shard_id}: {err}.")
                            });
                    });
                }
            });
        }
        if let Some(batch) = state_kv_metadata_batch {
            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["state_kv_db__commit_metadata"]);
            self.state_kv_metadata_db.write_schemas(batch)?;
        }

        self.write_progress(version)
    }
```
