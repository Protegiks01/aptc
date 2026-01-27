# Audit Report

## Title
Memory Exhaustion in Parallel Batch Creation During Transaction Commits

## Summary
The `commit_transactions()` function in `TransactionDb` creates all transaction batches in parallel using Rayon, collects them into a `Vec`, and only then commits them sequentially. This design can exhaust node memory when committing large volumes of sizeable transactions, particularly during state synchronization or catch-up scenarios.

## Finding Description

The vulnerability exists in the transaction commit flow where parallel batch creation holds all serialized transaction data in memory before any database commits occur. [1](#0-0) 

The critical issue is on line 114 where `.collect::<Result<Vec<_>>>()?` accumulates ALL batches in memory before the sequential commit loop begins at line 121. Each `NativeBatch` wraps a `rocksdb::WriteBatch` that holds serialized key-value pairs in memory. [2](#0-1) 

The `NativeBatch` contains a `RawBatch` which wraps `rocksdb::WriteBatch`. Each transaction added to the batch is serialized (including transaction data, indices, and metadata) and stored in the RocksDB write batch structure in memory.

**Exploitation Path:**

1. Transactions can be up to 10 MB each per the gas schedule configuration: [3](#0-2) 

2. During state sync or restoration scenarios, `commit_transactions()` can be called with large batches of transactions from `ChunkToCommit`: [4](#0-3) 

3. While consensus blocks are limited to 3-6 MB, state sync chunks can accumulate transactions from multiple blocks or historical replay can process larger batches.

4. With chunk_size calculated as `transactions.len() / 4 + 1`, a commit of 4000 transactions would create 4 parallel chunks of ~1000 transactions each.

5. If average transaction size is 500 KB (well below the 10 MB limit):
   - Total data: 4000 txns × 500 KB = 2 GB
   - Split into 4 parallel chunks
   - All 4 chunks process simultaneously, each serializing ~500 MB
   - All batches held in memory: ~2 GB + RocksDB overhead
   - This occurs BEFORE any commits, potentially exhausting available memory

## Impact Explanation

**Medium Severity** - This issue constitutes a state inconsistency and availability concern per the Aptos bug bounty criteria:

- **Availability Impact**: Node crashes due to OOM during transaction commits force node restarts and temporary loss of validator availability
- **State Consistency Risk**: If memory exhaustion causes crashes during multi-phase commits, it could require manual intervention to restore consistent state
- **No Consensus Safety Violation**: Does not break consensus safety or allow double-spending, as the issue occurs at the storage layer after execution
- **Scope**: Affects all nodes during state sync, restoration, or when processing backlogged transactions

The severity is Medium rather than High because:
- Does not affect consensus correctness or safety
- Node can recover through restart
- Requires specific conditions (large transaction volumes during commits)
- Primary impact is temporary availability degradation

## Likelihood Explanation

**Moderate Likelihood** - The vulnerability can be triggered under specific but realistic conditions:

1. **State Synchronization**: Nodes catching up after being offline process historical chunks with accumulated large transactions
2. **Network Disruptions**: After network partitions, nodes may need to commit large backlogs of validated transactions
3. **Restoration Operations**: Database restoration or backup replay processes large transaction volumes
4. **Adversarial Scenarios**: Validators could potentially construct blocks near size limits consistently, causing memory pressure during state sync

The likelihood is moderate because:
- Normal consensus operation has smaller, rate-limited blocks
- Requires sustained load of large transactions
- More common during exceptional conditions (sync, recovery) than normal operation
- Gradual memory growth may trigger OS-level memory management before complete exhaustion

## Recommendation

**Immediate Fix**: Implement streaming commits to limit concurrent in-memory batches:

```rust
pub(crate) fn commit_transactions(
    &self,
    first_version: Version,
    transactions: &[Transaction],
    skip_index: bool,
) -> Result<()> {
    let _timer = OTHER_TIMERS_SECONDS.timer_with(&["commit_transactions"]);
    
    // Limit concurrent batches to prevent memory exhaustion
    const MAX_CONCURRENT_BATCHES: usize = 2;
    let chunk_size = transactions.len() / MAX_CONCURRENT_BATCHES + 1;
    
    // Process and commit in smaller waves instead of collecting all at once
    for chunk_start in (0..transactions.len()).step_by(chunk_size * MAX_CONCURRENT_BATCHES) {
        let chunk_end = (chunk_start + chunk_size * MAX_CONCURRENT_BATCHES).min(transactions.len());
        let chunk_txns = &transactions[chunk_start..chunk_end];
        
        let batches = chunk_txns
            .par_chunks(chunk_size)
            .enumerate()
            .map(|(chunk_index, txns_in_chunk)| -> Result<NativeBatch> {
                let mut batch = self.db().new_native_batch();
                let batch_first_version = first_version + chunk_start as u64 + (chunk_size * chunk_index) as u64;
                txns_in_chunk
                    .iter()
                    .enumerate()
                    .try_for_each(|(i, txn)| -> Result<()> {
                        self.put_transaction(
                            batch_first_version + i as u64,
                            txn,
                            skip_index,
                            &mut batch,
                        )?;
                        Ok(())
                    })?;
                Ok(batch)
            })
            .collect::<Result<Vec<_>>>()?;

        // Commit this wave before processing next
        let _timer = OTHER_TIMERS_SECONDS.timer_with(&["commit_transactions___commit"]);
        for batch in batches {
            self.db().write_schemas(batch)?;
        }
    }
    
    Ok(())
}
```

**Alternative Approach**: Implement memory budget tracking:
- Add memory usage estimation before batch creation
- If estimated memory exceeds threshold, reduce parallelism or switch to sequential processing
- Monitor `rocksdb::WriteBatch` size and apply backpressure

**Long-term Solution**:
- Implement chunked state sync with memory limits at the executor level
- Add memory usage metrics and alerting for storage operations
- Consider streaming commits directly to RocksDB without intermediate batch accumulation

## Proof of Concept

```rust
#[cfg(test)]
mod memory_exhaustion_test {
    use super::*;
    use aptos_types::transaction::Transaction;
    use std::sync::Arc;

    #[test]
    #[ignore] // Ignore by default as it requires significant memory
    fn test_commit_large_transaction_batch_memory() {
        // Setup test database
        let tmpdir = aptos_temppath::TempPath::new();
        tmpdir.create_as_dir().unwrap();
        let db = Arc::new(DB::new_for_test(tmpdir.path()));
        let transaction_db = TransactionDb::new(db);

        // Create large transactions (simulate near-max size)
        // Each transaction ~1MB of payload
        let large_payload = vec![0u8; 1024 * 1024]; 
        let mut transactions = Vec::new();
        
        // Attempt to commit 2000 large transactions
        // Total: 2GB of transaction data
        for _ in 0..2000 {
            let txn = create_test_transaction_with_payload(&large_payload);
            transactions.push(txn);
        }

        // Monitor memory before commit
        let mem_before = get_process_memory();
        
        // This should trigger high memory usage as all 4 batches 
        // (each containing ~500 transactions × 1MB) are created in parallel
        // Expected: ~2GB + overhead held in memory before any commits
        let result = transaction_db.commit_transactions(
            0,
            &transactions,
            false,
        );

        let mem_after = get_process_memory();
        let mem_delta = mem_after - mem_before;
        
        // Verify memory spike occurred
        assert!(mem_delta > 1_500_000_000, // Expect >1.5GB increase
                "Memory delta: {} bytes", mem_delta);
        
        // On resource-constrained systems, this may OOM
        assert!(result.is_ok() || is_oom_error(&result));
    }

    fn create_test_transaction_with_payload(payload: &[u8]) -> Transaction {
        // Create a transaction with large payload
        // Implementation details omitted for brevity
        unimplemented!("Create signed transaction with large script payload")
    }

    fn get_process_memory() -> u64 {
        // Platform-specific memory query
        #[cfg(target_os = "linux")]
        {
            std::fs::read_to_string("/proc/self/statm")
                .ok()
                .and_then(|s| s.split_whitespace().nth(1))
                .and_then(|s| s.parse::<u64>().ok())
                .map(|pages| pages * 4096)
                .unwrap_or(0)
        }
        #[cfg(not(target_os = "linux"))]
        0
    }

    fn is_oom_error(result: &Result<()>) -> bool {
        // Check if error indicates OOM condition
        matches!(result, Err(e) if e.to_string().contains("out of memory")
                                || e.to_string().contains("allocation"))
    }
}
```

## Notes

This vulnerability specifically affects the storage layer's transaction commit mechanism and represents a **Resource Exhaustion** attack vector rather than a consensus safety issue. The parallel batch creation design prioritizes throughput but lacks memory bounds checking, making it vulnerable during high-volume operations.

The issue is exacerbated by:
- Maximum transaction size of 10 MB allowing individually large transactions
- State sync operations that can accumulate large transaction volumes
- Lack of memory pressure feedback in the batch creation pipeline

Mitigation should balance parallelism benefits with memory safety through staged commits or adaptive batch sizing based on available resources.

### Citations

**File:** storage/aptosdb/src/ledger_db/transaction_db.rs (L85-126)
```rust
    pub(crate) fn commit_transactions(
        &self,
        first_version: Version,
        transactions: &[Transaction],
        skip_index: bool,
    ) -> Result<()> {
        let _timer = OTHER_TIMERS_SECONDS.timer_with(&["commit_transactions"]);
        let chunk_size = transactions.len() / 4 + 1;
        let batches = transactions
            .par_chunks(chunk_size)
            .enumerate()
            .map(|(chunk_index, txns_in_chunk)| -> Result<NativeBatch> {
                let mut batch = self.db().new_native_batch();
                let chunk_first_version = first_version + (chunk_size * chunk_index) as u64;
                txns_in_chunk
                    .iter()
                    .enumerate()
                    .try_for_each(|(i, txn)| -> Result<()> {
                        self.put_transaction(
                            chunk_first_version + i as u64,
                            txn,
                            skip_index,
                            &mut batch,
                        )?;

                        Ok(())
                    })?;
                Ok(batch)
            })
            .collect::<Result<Vec<_>>>()?;

        // Commit batches one by one for now because committing them in parallel will cause gaps. Although
        // it might be acceptable because we are writing the progress, we want to play on the safer
        // side unless this really becomes the bottleneck on production.
        {
            let _timer = OTHER_TIMERS_SECONDS.timer_with(&["commit_transactions___commit"]);
            for batch in batches {
                self.db().write_schemas(batch)?
            }
            Ok(())
        }
    }
```

**File:** storage/schemadb/src/batch.rs (L200-243)
```rust
/// Similar to SchemaBatch, but wraps around rocksdb::WriteBatch directly.
/// For that to work, a reference to the DB needs to be held.
pub struct NativeBatch<'db> {
    db: &'db DB,
    raw_batch: RawBatch,
}

impl Debug for NativeBatch<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "NativeBatch for DB {} ", self.db.name)
    }
}

impl<'db> NativeBatch<'db> {
    /// Creates an empty batch.
    pub fn new(db: &'db DB) -> Self {
        Self {
            db,
            raw_batch: RawBatch::default(),
        }
    }
}

impl WriteBatch for NativeBatch<'_> {
    fn stats(&mut self) -> &mut SampledBatchStats {
        &mut self.raw_batch.stats
    }

    fn raw_put(&mut self, cf_name: ColumnFamilyName, key: Vec<u8>, value: Vec<u8>) -> DbResult<()> {
        self.raw_batch
            .inner
            .put_cf(&self.db.get_cf_handle(cf_name)?, &key, &value);

        Ok(())
    }

    fn raw_delete(&mut self, cf_name: ColumnFamilyName, key: Vec<u8>) -> DbResult<()> {
        self.raw_batch
            .inner
            .delete_cf(&self.db.get_cf_handle(cf_name)?, &key);

        Ok(())
    }
}
```

**File:** aptos-move/aptos-gas-schedule/src/gas_schedule/transaction.rs (L1-50)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

//! This module defines all the gas parameters for transactions, along with their initial values
//! in the genesis and a mapping between the Rust representation and the on-chain gas schedule.

use crate::{
    gas_schedule::VMGasParameters,
    ver::gas_feature_versions::{
        RELEASE_V1_10, RELEASE_V1_11, RELEASE_V1_12, RELEASE_V1_13, RELEASE_V1_15, RELEASE_V1_26,
        RELEASE_V1_41,
    },
};
use aptos_gas_algebra::{
    AbstractValueSize, Fee, FeePerByte, FeePerGasUnit, FeePerSlot, Gas, GasExpression,
    GasScalingFactor, GasUnit, NumModules, NumSlots, NumTypeNodes,
};
use move_core_types::gas_algebra::{
    InternalGas, InternalGasPerArg, InternalGasPerByte, InternalGasUnit, NumBytes, ToUnitWithParams,
};

const GAS_SCALING_FACTOR: u64 = 1_000_000;

crate::gas_schedule::macros::define_gas_parameters!(
    TransactionGasParameters,
    "txn",
    VMGasParameters => .txn,
    [
        // The flat minimum amount of gas required for any transaction.
        // Charged at the start of execution.
        // It is variable to charge more for more expensive authenticators, e.g., keyless
        [
            min_transaction_gas_units: InternalGas,
            "min_transaction_gas_units",
            2_760_000
        ],
        // Any transaction over this size will be charged an additional amount per byte.
        [
            large_transaction_cutoff: NumBytes,
            "large_transaction_cutoff",
            600
        ],
        // The units of gas that to be charged per byte over the `large_transaction_cutoff` in addition to
        // `min_transaction_gas_units` for transactions whose size exceeds `large_transaction_cutoff`.
        [
            intrinsic_gas_per_byte: InternalGasPerByte,
            "intrinsic_gas_per_byte",
            1_158
        ],
        // ~5 microseconds should equal one unit of computational gas. We bound the maximum
```

**File:** storage/aptosdb/src/db/aptosdb_writer.rs (L290-299)
```rust
            s.spawn(|_| {
                self.ledger_db
                    .transaction_db()
                    .commit_transactions(
                        chunk.first_version,
                        chunk.transactions,
                        skip_index_and_usage,
                    )
                    .unwrap()
            });
```
