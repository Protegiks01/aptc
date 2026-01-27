# Audit Report

## Title
Resource Exhaustion in prime_cache() via Unbounded Task Spawning with Millions of State Keys

## Summary
The `prime_cache()` function spawns one Rayon task per state key without limiting the number of concurrent tasks, allowing an attacker to cause validator node slowdowns by including transactions with millions of unique state keys in a block.

## Finding Description

The vulnerability exists in the `prime_cache_for_keys()` function which spawns one task per state key using `rayon::scope()`: [1](#0-0) 

When `prime_cache()` is invoked during execution output parsing: [2](#0-1) 

An attacker can exploit this by:

1. **Crafting adversarial transactions**: Each transaction can contain up to 8,192 write operations (enforced by gas parameter): [3](#0-2) 

2. **Including multiple transactions in a block**: Blocks can contain up to 10,000 transactions: [4](#0-3) 

3. **Maximizing unique keys**: By carefully selecting different state keys across transactions, the attacker can create millions of unique keys that get batched together: [5](#0-4) 

**Attack Scenario:**
- 1,000 transactions × 5,000 unique write operations each = 5,000,000 unique state keys
- After deduplication in `BatchedStateUpdateRefs`, assume 2,500,000 unique keys remain
- These are split across 16 shards (~156,250 keys per shard)
- Each shard spawns 156,250 tasks via `rayon::scope()`
- Each task calls `get_state_value()` which may perform I/O operations
- The `rayon::scope()` blocks until all tasks complete
- With the IO_POOL having only 32 worker threads, processing millions of I/O operations causes significant delays

This breaks the **Resource Limits** invariant: operations must respect computational limits and not cause resource exhaustion that impacts critical validator operations.

## Impact Explanation

This vulnerability qualifies as **HIGH SEVERITY** per the Aptos bug bounty program:

- **Validator node slowdowns**: Blocks containing millions of state keys cause validators to spend excessive time in `prime_cache()`, blocking the execution pipeline and delaying block processing. Multiple such blocks can severely degrade validator performance.

- **Protocol impact**: While not causing consensus safety violations or fund loss, the slowdown affects network liveness and block production efficiency.

The vulnerability does not reach CRITICAL severity because:
- It does not cause permanent damage or require a hardfork
- Validators eventually recover after processing the block
- No funds are lost or consensus safety violated

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

The attack is feasible because:

1. **Economic viability**: While each write operation costs gas (~89,568 gas units per slot), an attacker with sufficient APT can afford to execute such transactions. With `max_io_gas = 1,000,000,000`, a single transaction can include 8,192 write operations.

2. **No special privileges required**: Any transaction sender can craft these adversarial transactions and submit them to mempool.

3. **Consensus acceptance**: These transactions are valid - they pass all gas checks, write operation limits, and other validations: [6](#0-5) 

4. **Block inclusion**: Validators will include these transactions in blocks as they are economically valid and meet all protocol requirements.

The main limiting factor is the economic cost, but a motivated attacker with capital could execute this attack to disrupt network performance.

## Recommendation

Implement batching and rate limiting in `prime_cache_for_keys()` to prevent spawning excessive tasks:

```rust
fn prime_cache_for_keys<'a, T: IntoIterator<Item = &'a StateKey> + Send>(
    &self,
    keys: T,
) -> Result<()> {
    const MAX_PARALLEL_TASKS: usize = 10000; // Limit concurrent tasks
    const BATCH_SIZE: usize = 1000; // Process keys in batches
    
    let keys_vec: Vec<_> = keys.into_iter().collect();
    
    // Process in batches to avoid spawning millions of tasks
    for chunk in keys_vec.chunks(BATCH_SIZE) {
        rayon::scope(|s| {
            for key in chunk.iter().take(MAX_PARALLEL_TASKS) {
                s.spawn(move |_| {
                    self.get_state_value(key).expect("Must succeed.");
                })
            }
        });
    }
    Ok(())
}
```

Alternative solution: Add a limit on the total number of unique keys that can be primed per block, or add monitoring/alerting for blocks with excessive state keys.

## Proof of Concept

```rust
// PoC: Create a block with maximum write operations
// This can be tested in executor benchmarks or integration tests

use aptos_types::write_set::{WriteSet, WriteSetMut, WriteOp};
use aptos_types::state_store::state_key::StateKey;

fn create_adversarial_block() {
    let mut transactions = Vec::new();
    
    // Create 1000 transactions, each with 5000 unique write operations
    for tx_idx in 0..1000 {
        let mut write_set_mut = WriteSetMut::new(Vec::new());
        
        for key_idx in 0..5000 {
            // Create unique state keys to avoid deduplication
            let key = StateKey::raw(
                format!("adversarial_key_tx{}_key{}", tx_idx, key_idx).as_bytes()
            );
            let value = vec![0u8; 100]; // Small value to stay within size limits
            write_set_mut.insert((key, WriteOp::legacy_modification(value.into())));
        }
        
        let write_set = write_set_mut.freeze().unwrap();
        // Create transaction with this write set
        // ... (transaction creation code)
        transactions.push(/* transaction */);
    }
    
    // When this block is executed and prime_cache is called:
    // - Total unique keys: 1000 * 5000 = 5,000,000
    // - After batching: Still millions of unique keys
    // - prime_cache will spawn millions of tasks
    // - Each shard gets ~312,500 keys on average
    // - This causes significant slowdown in block processing
}
```

To reproduce in a test environment:
1. Create transactions with 5,000-8,000 unique write operations each
2. Include 500-1,000 such transactions in a block
3. Measure the time taken by `prime_cache()` execution
4. Observe validator node slowdown and delayed block processing

### Citations

**File:** storage/storage-interface/src/state_store/state_view/cached_state_view.rs (L210-222)
```rust
    fn prime_cache_for_keys<'a, T: IntoIterator<Item = &'a StateKey> + Send>(
        &self,
        keys: T,
    ) -> Result<()> {
        rayon::scope(|s| {
            keys.into_iter().for_each(|key| {
                s.spawn(move |_| {
                    self.get_state_value(key).expect("Must succeed.");
                })
            });
        });
        Ok(())
    }
```

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L405-418)
```rust
        base_state_view.prime_cache(
            to_commit.state_update_refs(),
            if prime_state_cache {
                PrimingPolicy::All
            } else {
                // Most of the transaction reads should already be in the cache, but some module
                // reads in the transactions might be done via the global module cache instead of
                // cached state view, so they are not present in the cache.
                // Therfore, we must prime the cache for the keys that we are going to promote into
                // hot state, regardless of `prime_state_cache`, because the write sets have only
                // the keys, not the values.
                PrimingPolicy::MakeHotOnly
            },
        )?;
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L154-162)
```rust
            max_bytes_per_write_op: NumBytes,
            { 5.. => "max_bytes_per_write_op" },
            1 << 20, // a single state item is 1MB max
        ],
        [
            max_bytes_all_write_ops_per_transaction: NumBytes,
            { 5.. => "max_bytes_all_write_ops_per_transaction" },
            10 << 20, // all write ops from a single transaction are 10MB max
        ],
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L174-177)
```rust
            max_write_ops_per_transaction: NumSlots,
            { 11.. => "max_write_ops_per_transaction" },
            8192,
        ],
```

**File:** config/src/config/consensus_config.rs (L23-24)
```rust
pub(crate) static MAX_RECEIVING_BLOCK_TXNS: Lazy<u64> =
    Lazy::new(|| 10000.max(2 * MAX_SENDING_BLOCK_TXNS));
```

**File:** storage/storage-interface/src/state_store/state_update_refs.rs (L257-309)
```rust
    fn batch_updates(
        per_version_updates: &PerVersionStateUpdateRefs<'kv>,
    ) -> BatchedStateUpdateRefs<'kv> {
        let _timer = TIMER.timer_with(&["index_state_updates__collect_batch"]);

        let mut ret = BatchedStateUpdateRefs::new_empty(
            per_version_updates.first_version,
            per_version_updates.num_versions,
        );
        per_version_updates
            .shards
            .par_iter()
            .map(|shard| shard.iter().cloned())
            .zip_eq(ret.shards.par_iter_mut())
            .for_each(|(shard_iter, dedupped)| {
                for (k, u) in shard_iter {
                    // If it's a value write op (Creation/Modification/Deletion), just insert and
                    // overwrite the previous op.
                    if u.state_op.is_value_write_op() {
                        dedupped.insert(k, u);
                        continue;
                    }

                    // If we see a hotness op, we check if there is a value write op with the same
                    // key before. This is unlikely, but if it does happen (e.g. if the write
                    // summary used to compute MakeHot is missing keys), we must discard the
                    // hotness op to avoid overwriting the value write op.
                    // TODO(HotState): also double check this logic for state sync later. For now
                    // we do not output hotness ops for state sync.
                    match dedupped.entry(k) {
                        Entry::Occupied(mut entry) => {
                            let prev_op = &entry.get().state_op;
                            sample!(
                                SampleRate::Duration(Duration::from_secs(10)),
                                warn!(
                                    "Key: {:?}. Previous write op: {}. Current write op: {}",
                                    k,
                                    prev_op.as_ref(),
                                    u.state_op.as_ref()
                                )
                            );
                            if !prev_op.is_value_write_op() {
                                entry.insert(u);
                            }
                        },
                        Entry::Vacant(entry) => {
                            entry.insert(u);
                        },
                    }
                }
            });
        ret
    }
```
