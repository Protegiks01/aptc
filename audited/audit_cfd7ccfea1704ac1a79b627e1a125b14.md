# Audit Report

## Title
Out-of-Memory Crash in TransactionPruner During Initialization Catch-Up Phase

## Summary
The `TransactionPruner` initialization process in Aptos storage layer contains a critical resource management flaw that causes validator nodes to crash with out-of-memory (OOM) errors when restarting after extended downtime. During the initialization catch-up phase, the pruner attempts to load millions of transactions into memory without batching constraints, leading to memory exhaustion and node crashes.

## Finding Description

The vulnerability exists in the initialization flow of `TransactionPruner` within the Aptos storage layer. When a validator node restarts, the pruner must catch up from its last recorded progress to the current metadata progress. However, this catch-up operation bypasses the batching mechanism that protects normal pruning operations.

**The Critical Flaw:**

During initialization, `TransactionPruner::new()` directly calls `myself.prune(progress, metadata_progress)` without any batching constraints. [1](#0-0) 

This `prune()` method then calls `get_pruning_candidate_transactions(current_progress, target_version)` with the full version range. [2](#0-1) 

The `get_pruning_candidate_transactions()` function contains the vulnerability: it pre-allocates a `Vec` with capacity `(end - start)` and loads ALL transactions in that range into memory. [3](#0-2) 

The comment on lines 119-120 incorrectly claims "The capacity is capped by the max number of txns we prune in a single batch," but this is **FALSE** during initialization—there is no batch size constraint applied.

**Normal Operation vs Initialization:**

During normal operation through `LedgerPruner::prune()`, batching IS properly applied: `current_batch_target_version = min(progress + max_versions, target_version)` caps the range to the configured batch size. [4](#0-3) 

However, the initialization path in `TransactionPruner::new()` bypasses this entirely, calling the sub-pruner's `prune()` method directly with unbounded ranges.

**Configuration:**

The default pruner configuration sets `batch_size` to 5,000 versions and `prune_window` to 90 million versions. [5](#0-4) 

**Memory Impact:**

If a validator has been offline for several hours (realistic for hardware failures or maintenance), the gap `metadata_progress - progress` can easily reach 50-100 million versions. At 5,000 TPS (transactions per second), 50 million versions represents approximately 2.8 hours of chain progress.

With 50 million versions:
- Memory allocation: 50M × (8 bytes for Version + ~300 bytes for Transaction) ≈ **15GB**
- This exceeds available memory on many validator nodes
- Result: **OOM crash preventing validator restart**

## Impact Explanation

**Severity: HIGH**

This vulnerability qualifies as **High Severity** under the Aptos Bug Bounty program's "Validator Node Slowdowns" category (up to $50,000), though this actually causes complete validator crashes rather than mere slowdowns, which is more severe.

**Concrete Impacts:**

1. **Validator Availability:** Single validator crashes reduce consensus participation and network decentralization
2. **Network Liveness:** Multiple validators experiencing simultaneous restarts (e.g., after network partition or coordinated maintenance) can significantly degrade network performance
3. **Operational Risk:** Validators become unable to restart without manual intervention (clearing pruner progress, reducing prune_window, or adding more RAM)
4. **Security Posture:** Reduced validator availability weakens the network's Byzantine fault tolerance margin

**Affected Scenarios:**
- Validator restarts after hardware failures or extended maintenance
- Pruning temporarily disabled for I/O optimization, then re-enabled
- Database restoration from backups with outdated pruner progress
- New validators syncing with pruning enabled after chain has grown significantly

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

This vulnerability triggers automatically in common operational scenarios that occur regularly in production blockchain networks:

1. **Extended Node Downtime:** Hardware failures, kernel panics, or scheduled maintenance causing validators to be offline for hours while the chain progresses millions of versions

2. **Chain Throughput:** At Aptos's target of 5,000 TPS, the chain progresses 50 million versions in just 2.8 hours, making dangerous gaps highly achievable

3. **Pruner Configuration:** The default 90-million-version prune window means gaps of 50M+ versions are well within normal operational parameters

4. **No Attacker Required:** This is an operational bug, not an attack vector. It triggers through normal node lifecycle events without any malicious actor

5. **Increasing Probability:** As the Aptos blockchain matures and processes billions of transactions, any outage creates larger gaps, increasing the likelihood of triggering this vulnerability

## Recommendation

Implement batching for the initialization catch-up phase to match the protection used in normal pruning operations:

```rust
// In TransactionPruner::new()
let batch_size = 5_000; // Or pass as parameter
let mut current = progress;
while current < metadata_progress {
    let target = std::cmp::min(current + batch_size as u64, metadata_progress);
    myself.prune(current, target)?;
    current = target;
}
```

Alternatively, enforce a maximum catch-up range and log warnings when gaps are too large, requiring operators to manually clear pruner progress for safe recovery.

## Proof of Concept

While a full PoC would require running a validator node, the vulnerability can be reproduced with the following steps:

1. Start an Aptos validator node with pruning enabled (default configuration)
2. Let the node run normally for several hours, processing transactions and pruning
3. Stop the validator node (simulating hardware failure or maintenance)
4. Keep the node offline for 3+ hours while the network continues processing ~5,000 TPS
5. Attempt to restart the validator node
6. Observe OOM crash during `TransactionPruner::new()` initialization when it attempts to allocate memory for 50M+ transactions

The crash will occur at the memory allocation on line 121 of `transaction_pruner.rs` with the unbounded `(end - start)` capacity.

## Notes

This vulnerability is particularly concerning because:

1. **Silent Failure During Catch-up:** The misleading comment suggests the code is safe, but the safety mechanism is not applied during initialization
2. **Amplification Over Time:** As the blockchain grows, even brief outages create larger gaps, making the problem progressively worse
3. **Operational Blind Spot:** Operators may not realize that validator restarts after downtime are dangerous, leading to unexpected production outages
4. **No Graceful Degradation:** The system crashes rather than falling back to slower but safer catch-up strategies

The fix should include both immediate batching implementation and improved observability (logging warnings when large catch-up gaps are detected).

### Citations

**File:** storage/aptosdb/src/pruner/ledger_pruner/transaction_pruner.rs (L37-74)
```rust
    fn prune(&self, current_progress: Version, target_version: Version) -> Result<()> {
        let mut batch = SchemaBatch::new();
        let candidate_transactions =
            self.get_pruning_candidate_transactions(current_progress, target_version)?;
        self.ledger_db
            .transaction_db()
            .prune_transaction_by_hash_indices(
                candidate_transactions.iter().map(|(_, txn)| txn.hash()),
                &mut batch,
            )?;
        self.ledger_db.transaction_db().prune_transactions(
            current_progress,
            target_version,
            &mut batch,
        )?;
        self.transaction_store
            .prune_transaction_summaries_by_account(&candidate_transactions, &mut batch)?;
        batch.put::<DbMetadataSchema>(
            &DbMetadataKey::TransactionPrunerProgress,
            &DbMetadataValue::Version(target_version),
        )?;
        if let Some(indexer_db) = self.internal_indexer_db.as_ref() {
            if indexer_db.transaction_enabled() {
                let mut index_batch = SchemaBatch::new();
                self.transaction_store
                    .prune_transaction_by_account(&candidate_transactions, &mut index_batch)?;
                index_batch.put::<InternalIndexerMetadataSchema>(
                    &IndexerMetadataKey::TransactionPrunerProgress,
                    &IndexerMetadataValue::Version(target_version),
                )?;
                indexer_db.get_inner_db_ref().write_schemas(index_batch)?;
            } else {
                self.transaction_store
                    .prune_transaction_by_account(&candidate_transactions, &mut batch)?;
            }
        }
        self.ledger_db.transaction_db().write_schemas(batch)
    }
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/transaction_pruner.rs (L77-104)
```rust
impl TransactionPruner {
    pub(in crate::pruner) fn new(
        transaction_store: Arc<TransactionStore>,
        ledger_db: Arc<LedgerDb>,
        metadata_progress: Version,
        internal_indexer_db: Option<InternalIndexerDB>,
    ) -> Result<Self> {
        let progress = get_or_initialize_subpruner_progress(
            ledger_db.transaction_db_raw(),
            &DbMetadataKey::TransactionPrunerProgress,
            metadata_progress,
        )?;

        let myself = TransactionPruner {
            transaction_store,
            ledger_db,
            internal_indexer_db,
        };

        info!(
            progress = progress,
            metadata_progress = metadata_progress,
            "Catching up TransactionPruner."
        );
        myself.prune(progress, metadata_progress)?;

        Ok(myself)
    }
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/transaction_pruner.rs (L106-132)
```rust
    fn get_pruning_candidate_transactions(
        &self,
        start: Version,
        end: Version,
    ) -> Result<Vec<(Version, Transaction)>> {
        ensure!(end >= start, "{} must be >= {}", end, start);

        let mut iter = self
            .ledger_db
            .transaction_db_raw()
            .iter::<TransactionSchema>()?;
        iter.seek(&start)?;

        // The capacity is capped by the max number of txns we prune in a single batch. It's a
        // relatively small number set in the config, so it won't cause high memory usage here.
        let mut txns = Vec::with_capacity((end - start) as usize);
        for item in iter {
            let (version, txn) = item?;
            if version >= end {
                break;
            }
            txns.push((version, txn));
        }

        Ok(txns)
    }
}
```

**File:** storage/aptosdb/src/pruner/ledger_pruner/mod.rs (L62-92)
```rust
    fn prune(&self, max_versions: usize) -> Result<Version> {
        let mut progress = self.progress();
        let target_version = self.target_version();

        while progress < target_version {
            let current_batch_target_version =
                min(progress + max_versions as Version, target_version);

            info!(
                progress = progress,
                target_version = current_batch_target_version,
                "Pruning ledger data."
            );
            self.ledger_metadata_pruner
                .prune(progress, current_batch_target_version)?;

            THREAD_MANAGER.get_background_pool().install(|| {
                self.sub_pruners.par_iter().try_for_each(|sub_pruner| {
                    sub_pruner
                        .prune(progress, current_batch_target_version)
                        .map_err(|err| anyhow!("{} failed to prune: {err}", sub_pruner.name()))
                })
            })?;

            progress = current_batch_target_version;
            self.record_progress(progress);
            info!(progress = progress, "Pruning ledger data is done.");
        }

        Ok(target_version)
    }
```

**File:** config/src/config/storage_config.rs (L387-396)
```rust
impl Default for LedgerPrunerConfig {
    fn default() -> Self {
        LedgerPrunerConfig {
            enable: true,
            prune_window: 90_000_000,
            batch_size: 5_000,
            user_pruning_window_offset: 200_000,
        }
    }
}
```
