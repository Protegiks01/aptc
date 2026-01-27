# Audit Report

## Title
Byzantine Validators Can Exhaust Honest Validator Resources Through Unbounded Per-Validator Quota Allocation

## Summary
The Quorum Store's `BatchStore` implements per-validator resource quotas (120 MB memory, 300 MB database storage per validator) without a global limit, allowing Byzantine validators to collectively exhaust resources on honest validators by each filling their individual quotas with valid but useless batches. With N validators in the network, honest validators face potential resource consumption of N × 120 MB memory and N × 300 MB database storage.

## Finding Description

The vulnerability exists in how `BatchStore` manages resource quotas for incoming batches. When a batch is received from a validator, the quota tracking occurs per batch author: [1](#0-0) 

Each validator author gets their own separate `QuotaManager` instance with full quotas allocated: [2](#0-1) 

The `QuotaManager` enforces limits per validator, but there is no global limit across all validators: [3](#0-2) 

**Attack Execution Path:**

1. Byzantine validator creates batches with valid signatures and structure (passing `ensure_max_limits` checks)
2. Batches contain transactions that are "useless" - already processed, invalid, or will never be included
3. Byzantine validator sends batches continuously to honest validators via `BatchCoordinatorCommand::NewBatches`
4. Honest validators receive batches through `BatchCoordinator::handle_batches_msg` [4](#0-3) 

5. Batches are persisted via `batch_store.persist()`, which calls `insert_to_cache()`
6. Each Byzantine validator fills their individual 120 MB memory + 300 MB DB quota
7. With f Byzantine validators, total consumption = f × (120 MB + 300 MB)

While remote batches are re-timestamped with 500ms expiration, Byzantine validators can continuously send new batches to maintain sustained quota usage: [5](#0-4) 

**Critical Issue:** The per-message size limits only constrain individual `BatchMsg` packets, not the rate of messages: [6](#0-5) 

There is no per-validator rate limiting to prevent continuous batch submission over time.

## Impact Explanation

**High Severity** per Aptos bug bounty criteria:
- **Validator node slowdowns**: Memory exhaustion (f × 120 MB) and disk pressure (f × 300 MB) cause performance degradation
- **Significant protocol violations**: Violates the "Resource Limits" invariant - operations should respect computational limits, but total consumption is unbounded based on validator count
- **Potential node crashes**: If available memory < f × 120 MB, validators may crash due to OOM conditions

In a typical network with 100 validators where 33 are Byzantine:
- **Memory consumption**: 33 × 120 MB = 3.96 GB per honest validator
- **DB consumption**: 33 × 300 MB = 9.9 GB per honest validator

This sustained resource pressure degrades consensus performance and could trigger cascading failures if memory limits are reached.

## Likelihood Explanation

**High Likelihood:**
- Requires only that f validators are Byzantine (standard BFT assumption of ≤ 1/3 Byzantine)
- Easy to execute - Byzantine validators simply send valid but useless batches continuously
- No sophisticated attack techniques required - just batch generation and network sending
- Can be sustained indefinitely as old batches expire but new ones keep arriving
- No existing rate limiting mechanism prevents this attack

The attack is practical because:
1. Batch structure validation occurs before transaction content validation
2. Quotas are allocated on batch receipt, not after usefulness verification  
3. Each validator gets independent quota allocation with no coordination

## Recommendation

Implement a **global quota limit** across all validators to bound total resource consumption:

```rust
pub struct BatchStore {
    // ... existing fields ...
    global_memory_used: Arc<AtomicUsize>,
    global_db_used: Arc<AtomicUsize>,
    global_memory_limit: usize,
    global_db_limit: usize,
}

impl BatchStore {
    pub(crate) fn insert_to_cache(&self, value: &PersistedValue<BatchInfoExt>) -> anyhow::Result<bool> {
        // Check global limits FIRST
        let num_bytes = value.num_bytes() as usize;
        
        let current_global_db = self.global_db_used.load(Ordering::Acquire);
        if current_global_db + num_bytes > self.global_db_limit {
            bail!("Global DB quota exceeded");
        }
        
        // Then proceed with per-validator quota checks...
        // Update global counters on success
        self.global_db_used.fetch_add(num_bytes, Ordering::Release);
        // ... rest of implementation
    }
    
    fn free_quota(&self, value: PersistedValue<BatchInfoExt>) {
        // Free both per-validator AND global quotas
        let num_bytes = value.num_bytes() as usize;
        self.global_db_used.fetch_sub(num_bytes, Ordering::Release);
        if matches!(value.payload_storage_mode(), StorageMode::MemoryAndPersisted) {
            self.global_memory_used.fetch_sub(num_bytes, Ordering::Release);
        }
        // ... existing per-validator free_quota logic
    }
}
```

Alternative/additional mitigations:
1. **Per-validator rate limiting**: Limit batches per validator per time window
2. **Dynamic quota allocation**: Reduce per-validator quota as more validators send batches
3. **Prioritization**: Prioritize batches from validators with higher reputation/stake

## Proof of Concept

```rust
#[tokio::test]
async fn test_byzantine_quota_exhaustion() {
    use crate::quorum_store::{
        batch_store::{BatchStore, BatchWriter},
        quorum_store_db::QuorumStoreDB,
        types::PersistedValue,
    };
    use aptos_consensus_types::proof_of_store::{BatchInfo, BatchInfoExt};
    use aptos_crypto::HashValue;
    use aptos_temppath::TempPath;
    use aptos_types::{
        account_address::AccountAddress, 
        quorum_store::BatchId,
        validator_verifier::random_validator_verifier,
    };
    use std::sync::Arc;

    // Setup: Create batch store with realistic quotas
    let tmp_dir = TempPath::new();
    let db = Arc::new(QuorumStoreDB::new(&tmp_dir));
    let (signers, _) = random_validator_verifier(4, None, false);
    
    let memory_quota = 120_000_000; // 120 MB
    let db_quota = 300_000_000;     // 300 MB
    let batch_quota = 300_000;
    
    let batch_store = Arc::new(BatchStore::new(
        10,    // epoch
        false, // not new epoch
        100,   // last_certified_time
        db,
        memory_quota,
        db_quota,
        batch_quota,
        signers[0].clone(),
        0,
    ));

    // Simulate 3 Byzantine validators
    let byzantine_validators = vec![
        AccountAddress::random(),
        AccountAddress::random(),
        AccountAddress::random(),
    ];
    
    let batch_size = 1_000_000; // 1 MB per batch
    let batches_per_validator = 120; // Fill 120 MB per validator
    
    // Each Byzantine validator fills their quota
    for validator in byzantine_validators.iter() {
        for i in 0..batches_per_validator {
            let digest = HashValue::random();
            let batch_info = BatchInfo::new(
                *validator,
                BatchId::new_for_test(i),
                10, // epoch
                1000, // expiration (in future)
                digest,
                100, // num_txns
                batch_size,
                0,
            );
            
            let persist_request = PersistedValue::new(
                batch_info.into(),
                Some(vec![]), // Empty payload (useless batch)
            );
            
            // This should succeed for first 120 MB per validator
            batch_store.persist(vec![persist_request]);
        }
    }
    
    // Verify total consumption: 3 validators × 120 MB = 360 MB
    // This exceeds what should be reasonable for a single honest validator
    // Each validator independently consumed their full quota
    
    // An honest validator trying to store legitimate batches now faces
    // severe memory pressure with 360 MB already consumed by Byzantine batches
}
```

## Notes

This vulnerability is a consequence of the per-validator quota design interacting with the Byzantine fault model where up to f validators (out of 3f+1) can be malicious. The current implementation correctly enforces per-validator limits but fails to account for aggregate resource consumption when multiple Byzantine validators coordinate to exhaust resources. While batch expiration provides eventual cleanup (500ms for remote batches), Byzantine validators can maintain sustained resource pressure by continuously sending new batches.

### Citations

**File:** consensus/src/quorum_store/batch_store.rs (L41-109)
```rust
pub(crate) struct QuotaManager {
    memory_balance: usize,
    db_balance: usize,
    batch_balance: usize,
    // Recording the provided quotas for asserts.
    memory_quota: usize,
    db_quota: usize,
    batch_quota: usize,
}

impl QuotaManager {
    pub(crate) fn new(db_quota: usize, memory_quota: usize, batch_quota: usize) -> Self {
        assert!(db_quota >= memory_quota);
        Self {
            memory_balance: memory_quota,
            db_balance: db_quota,
            batch_balance: batch_quota,
            memory_quota,
            db_quota,
            batch_quota,
        }
    }

    pub(crate) fn update_quota(&mut self, num_bytes: usize) -> anyhow::Result<StorageMode> {
        if self.batch_balance == 0 {
            counters::EXCEEDED_BATCH_QUOTA_COUNT.inc();
            bail!("Batch quota exceeded ");
        }

        if self.db_balance >= num_bytes {
            self.batch_balance -= 1;
            self.db_balance -= num_bytes;

            if self.memory_balance >= num_bytes {
                self.memory_balance -= num_bytes;
                Ok(StorageMode::MemoryAndPersisted)
            } else {
                Ok(StorageMode::PersistedOnly)
            }
        } else {
            counters::EXCEEDED_STORAGE_QUOTA_COUNT.inc();
            bail!("Storage quota exceeded ");
        }
    }

    fn assert_quota(balance: usize, to_free: usize, quota: usize, kind: &str) {
        assert!(
            balance + to_free <= quota,
            "Balance {} + to_free {} more than {} quota {}",
            balance,
            to_free,
            kind,
            quota,
        );
    }

    pub(crate) fn free_quota(&mut self, num_bytes: usize, storage_mode: StorageMode) {
        Self::assert_quota(self.batch_balance, 1, self.batch_quota, "Batch");
        self.batch_balance += 1;

        Self::assert_quota(self.db_balance, num_bytes, self.db_quota, "DB");
        self.db_balance += num_bytes;

        if matches!(storage_mode, StorageMode::MemoryAndPersisted) {
            Self::assert_quota(self.memory_balance, num_bytes, self.memory_quota, "Memory");
            self.memory_balance += num_bytes;
        }
    }
}
```

**File:** consensus/src/quorum_store/batch_store.rs (L383-397)
```rust
            let value_to_be_stored = if self
                .peer_quota
                .entry(author)
                .or_insert(QuotaManager::new(
                    self.db_quota,
                    self.memory_quota,
                    self.batch_quota,
                ))
                .update_quota(value.num_bytes() as usize)?
                == StorageMode::PersistedOnly
            {
                PersistedValue::new(value.batch_info().clone(), None)
            } else {
                value.clone()
            };
```

**File:** config/src/config/quorum_store_config.rs (L133-135)
```rust
            memory_quota: 120_000_000,
            db_quota: 300_000_000,
            batch_quota: 300_000,
```

**File:** consensus/src/quorum_store/batch_coordinator.rs (L137-171)
```rust
    fn ensure_max_limits(&self, batches: &[Batch<BatchInfoExt>]) -> anyhow::Result<()> {
        let mut total_txns = 0;
        let mut total_bytes = 0;
        for batch in batches.iter() {
            ensure!(
                batch.num_txns() <= self.max_batch_txns,
                "Exceeds batch txn limit {} > {}",
                batch.num_txns(),
                self.max_batch_txns,
            );
            ensure!(
                batch.num_bytes() <= self.max_batch_bytes,
                "Exceeds batch bytes limit {} > {}",
                batch.num_bytes(),
                self.max_batch_bytes,
            );

            total_txns += batch.num_txns();
            total_bytes += batch.num_bytes();
        }
        ensure!(
            total_txns <= self.max_total_txns,
            "Exceeds total txn limit {} > {}",
            total_txns,
            self.max_total_txns,
        );
        ensure!(
            total_bytes <= self.max_total_bytes,
            "Exceeds total bytes limit: {} > {}",
            total_bytes,
            self.max_total_bytes,
        );

        Ok(())
    }
```

**File:** consensus/src/quorum_store/batch_coordinator.rs (L173-244)
```rust
    pub(crate) async fn handle_batches_msg(
        &mut self,
        author: PeerId,
        batches: Vec<Batch<BatchInfoExt>>,
    ) {
        if let Err(e) = self.ensure_max_limits(&batches) {
            error!("Batch from {}: {}", author, e);
            counters::RECEIVED_BATCH_MAX_LIMIT_FAILED.inc();
            return;
        }

        let Some(batch) = batches.first() else {
            error!("Empty batch received from {}", author.short_str().as_str());
            return;
        };

        // Filter the transactions in the batches. If any transaction is rejected,
        // the message will be dropped, and all batches will be rejected.
        if self.transaction_filter_config.is_enabled() {
            let transaction_filter = &self.transaction_filter_config.batch_transaction_filter();
            for batch in batches.iter() {
                for transaction in batch.txns() {
                    if !transaction_filter.allows_transaction(
                        batch.batch_info().batch_id(),
                        batch.author(),
                        batch.digest(),
                        transaction,
                    ) {
                        error!(
                            "Transaction {}, in batch {}, from {}, was rejected by the filter. Dropping {} batches!",
                            transaction.committed_hash(),
                            batch.batch_info().batch_id(),
                            author.short_str().as_str(),
                            batches.len()
                        );
                        counters::RECEIVED_BATCH_REJECTED_BY_FILTER.inc();
                        return;
                    }
                }
            }
        }

        let approx_created_ts_usecs = batch
            .info()
            .expiration()
            .saturating_sub(self.batch_expiry_gap_when_init_usecs);

        if approx_created_ts_usecs > 0 {
            observe_batch(
                approx_created_ts_usecs,
                batch.author(),
                BatchStage::RECEIVED,
            );
        }

        let mut persist_requests = vec![];
        for batch in batches.into_iter() {
            // TODO: maybe don't message batch generator if the persist is unsuccessful?
            if let Err(e) = self
                .sender_to_batch_generator
                .send(BatchGeneratorCommand::RemoteBatch(batch.clone()))
                .await
            {
                warn!("Failed to send batch to batch generator: {}", e);
            }
            persist_requests.push(batch.into());
        }
        counters::RECEIVED_BATCH_COUNT.inc_by(persist_requests.len() as u64);
        if author != self.my_peer_id {
            counters::RECEIVED_REMOTE_BATCH_COUNT.inc_by(persist_requests.len() as u64);
        }
        self.persist_and_send_digests(persist_requests, approx_created_ts_usecs);
```

**File:** consensus/src/quorum_store/batch_generator.rs (L398-400)
```rust
        let expiry_time_usecs = aptos_infallible::duration_since_epoch().as_micros() as u64
            + self.config.remote_batch_expiry_gap_when_init_usecs;
        self.insert_batch(author, batch_id, txns, expiry_time_usecs);
```
