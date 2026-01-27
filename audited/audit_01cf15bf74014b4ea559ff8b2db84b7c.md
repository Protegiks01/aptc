# Audit Report

## Title
Byzantine Validators Can Bypass Batch Creation Monitoring Through Direct Batch Construction

## Summary
Byzantine validators can create and broadcast batches through alternative code paths that completely bypass the `CREATED_BATCHES_COUNT` metric, hiding their batch creation activity from network-wide monitoring systems. This is achieved by constructing batches directly using `Batch::new_v1()` or `Batch::new_v2()` instead of the intended `create_new_batch()` function, combined with the lack of batch_id validation when receiving batches from the network.

## Finding Description

The `CREATED_BATCHES_COUNT` counter is designed to track batch creation activity, but has a critical blind spot: it only tracks batches created through the `create_new_batch()` function path. [1](#0-0) 

A Byzantine validator can bypass this monitoring by:

1. **Direct Batch Construction**: Creating batches directly using `Batch::new_v1()` or `Batch::new_v2()` from the types module, which are public constructors that don't increment any counters: [2](#0-1) 

2. **Lack of Batch ID Validation**: When honest validators receive these batches via `BatchMsg`, the verification only checks author validity, digest correctness, and epoch matching - but performs NO validation of batch_id monotonicity, uniqueness, or proper sequence: [3](#0-2) 

3. **No Per-Author Tracking**: Honest validators receiving these batches process them through `handle_batches_msg()` which increments `RECEIVED_BATCH_COUNT` (a global counter) but has no per-author batch creation tracking: [4](#0-3) 

4. **Remote Batch Processing Bypasses Counter**: When remote batches are processed, they go through `handle_remote_batch()` which calls `insert_batch()` WITHOUT incrementing `CREATED_BATCHES_COUNT`: [5](#0-4) 

The counter definition itself confirms this is meant to track creation activity but lacks proper scope definition: [6](#0-5) 

## Impact Explanation

This vulnerability enables **HIGH severity** impacts:

1. **Resource Exhaustion**: Byzantine validators can flood the network with batches, consuming memory, storage, and bandwidth on honest validators while remaining undetected by monitoring systems.

2. **Monitoring Blind Spots**: Network operators cannot reliably track batch creation activity per validator. The only observable counter (`CREATED_BATCHES_COUNT`) is controlled by the Byzantine validator themselves and only reflects local activity.

3. **Rate Limiting Bypass**: Any rate limiting mechanisms based on batch creation counts can be circumvented.

4. **Consensus Liveness Risk**: Excessive batch flooding could impact consensus performance and liveness, as nodes must process, validate, and store all received batches.

The quota management system in `batch_store.rs` provides some protection but operates per-peer rather than globally tracking Byzantine activity: [7](#0-6) 

This meets **High Severity** criteria per Aptos bug bounty: "Validator node slowdowns" and "Significant protocol violations" through undetectable resource exhaustion.

## Likelihood Explanation

**Likelihood: HIGH**

This attack is highly likely because:

1. **Low Complexity**: Byzantine validators only need to construct batches using public APIs and broadcast them through normal network channels
2. **No Detection**: Current monitoring infrastructure cannot detect this attack pattern
3. **No Prevention**: No batch_id validation exists to prevent arbitrary batch creation
4. **Immediate Effect**: The attack takes effect immediately upon broadcast

The BatchId structure provides no enforcement mechanisms: [8](#0-7) 

## Recommendation

Implement comprehensive batch creation tracking and validation:

1. **Add Per-Author Batch Counters**: Create `IntCounterVec` with author labels to track batch creation from all validators network-wide:

```rust
pub static BATCHES_BY_AUTHOR: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "quorum_store_batches_by_author",
        "Count of batches received per author since last restart.",
        &["author"]
    ).unwrap()
});
```

Increment this counter in `handle_batches_msg()` for all received batches.

2. **Implement Batch ID Validation**: In `BatchMsg::verify()`, add validation to ensure batch_ids from each author follow a valid sequence (though perfect monotonicity checking requires per-author state).

3. **Add Rate Limiting**: Implement per-author batch rate limiting in `batch_coordinator.rs` based on sliding time windows.

4. **Enhanced Monitoring**: Add alerts for validators exceeding normal batch creation rates based on the new per-author counters.

## Proof of Concept

```rust
// PoC demonstrating bypass of CREATED_BATCHES_COUNT
// This would be implemented by a Byzantine validator

use aptos_types::{transaction::SignedTransaction, PeerId};
use consensus::quorum_store::types::Batch;
use aptos_consensus_types::proof_of_store::BatchKind;

fn byzantine_batch_creation(
    my_peer_id: PeerId,
    epoch: u64,
    transactions: Vec<SignedTransaction>,
) -> Batch<BatchInfoExt> {
    // Byzantine validator creates batch directly, bypassing create_new_batch()
    // and thus bypassing CREATED_BATCHES_COUNT increment
    let arbitrary_batch_id = BatchId::new(12345); // Arbitrary, no validation
    let expiry = current_time() + 10_000_000; // 10 seconds
    
    // Direct construction - no counter increment
    let batch = Batch::new_v2(
        arbitrary_batch_id,
        transactions,
        epoch,
        expiry,
        my_peer_id,
        0, // gas_bucket_start
        BatchKind::Normal,
    );
    
    // Broadcast this batch through normal network channels
    // It will pass all verification checks on honest validators
    // But CREATED_BATCHES_COUNT remains at 0 on the Byzantine validator
    // And honest validators have no per-author counter to track this
    
    batch
}

// Honest validators will process this batch through:
// network_listener -> BatchCoordinatorCommand::NewBatches -> handle_batches_msg
// -> handle_remote_batch -> insert_batch (NO COUNTER INCREMENT)
```

The Byzantine validator can repeat this process to create unlimited batches while monitoring systems see no increase in batch creation activity for that validator.

**Notes**

This vulnerability fundamentally breaks the monitoring and observability guarantees of the quorum store system. While `BATCH_TRACING` exists for latency monitoring, there is no equivalent counting mechanism for detecting abnormal batch creation patterns from specific validators. The combination of unrestricted batch construction, lack of batch_id validation, and absence of per-author tracking creates a significant security gap that Byzantine validators can exploit for resource exhaustion attacks while remaining undetected.

### Citations

**File:** consensus/src/quorum_store/batch_generator.rs (L173-212)
```rust
    fn create_new_batch(
        &mut self,
        txns: Vec<SignedTransaction>,
        expiry_time: u64,
        bucket_start: u64,
    ) -> Batch<BatchInfoExt> {
        let batch_id = self.batch_id;
        self.batch_id.increment();
        self.db
            .save_batch_id(self.epoch, self.batch_id)
            .expect("Could not save to db");

        self.insert_batch(self.my_peer_id, batch_id, txns.clone(), expiry_time);

        counters::CREATED_BATCHES_COUNT.inc();
        counters::num_txn_per_batch(bucket_start.to_string().as_str(), txns.len());

        if self.config.enable_batch_v2 {
            // TODO(ibalajiarun): Specify accurate batch kind
            let batch_kind = BatchKind::Normal;
            Batch::new_v2(
                batch_id,
                txns,
                self.epoch,
                expiry_time,
                self.my_peer_id,
                bucket_start,
                batch_kind,
            )
        } else {
            Batch::new_v1(
                batch_id,
                txns,
                self.epoch,
                expiry_time,
                self.my_peer_id,
                bucket_start,
            )
        }
    }
```

**File:** consensus/src/quorum_store/batch_generator.rs (L392-401)
```rust
    pub(crate) fn handle_remote_batch(
        &mut self,
        author: PeerId,
        batch_id: BatchId,
        txns: Vec<SignedTransaction>,
    ) {
        let expiry_time_usecs = aptos_infallible::duration_since_epoch().as_micros() as u64
            + self.config.remote_batch_expiry_gap_when_init_usecs;
        self.insert_batch(author, batch_id, txns, expiry_time_usecs);
    }
```

**File:** consensus/src/quorum_store/types.rs (L206-252)
```rust
impl Batch<BatchInfoExt> {
    pub fn new_v2(
        batch_id: BatchId,
        payload: Vec<SignedTransaction>,
        epoch: u64,
        expiration: u64,
        batch_author: PeerId,
        gas_bucket_start: u64,
        batch_kind: BatchKind,
    ) -> Self {
        let payload = BatchPayload::new(batch_author, payload);
        let batch_info = BatchInfoExt::new_v2(
            batch_author,
            batch_id,
            epoch,
            expiration,
            payload.hash(),
            payload.num_txns() as u64,
            payload.num_bytes() as u64,
            gas_bucket_start,
            batch_kind,
        );
        Self::new_generic(batch_info, payload)
    }

    pub fn new_v1(
        batch_id: BatchId,
        payload: Vec<SignedTransaction>,
        epoch: u64,
        expiration: u64,
        batch_author: PeerId,
        gas_bucket_start: u64,
    ) -> Self {
        let payload = BatchPayload::new(batch_author, payload);
        let batch_info = BatchInfoExt::new_v1(
            batch_author,
            batch_id,
            epoch,
            expiration,
            payload.hash(),
            payload.num_txns() as u64,
            payload.num_bytes() as u64,
            gas_bucket_start,
        );
        Self::new_generic(batch_info, payload)
    }
}
```

**File:** consensus/src/quorum_store/types.rs (L433-461)
```rust
    pub fn verify(
        &self,
        peer_id: PeerId,
        max_num_batches: usize,
        verifier: &ValidatorVerifier,
    ) -> anyhow::Result<()> {
        ensure!(!self.batches.is_empty(), "Empty message");
        ensure!(
            self.batches.len() <= max_num_batches,
            "Too many batches: {} > {}",
            self.batches.len(),
            max_num_batches
        );
        let epoch_authors = verifier.address_to_validator_index();
        for batch in self.batches.iter() {
            ensure!(
                epoch_authors.contains_key(&batch.author()),
                "Invalid author {} for batch {} in current epoch",
                batch.author(),
                batch.digest()
            );
            ensure!(
                batch.author() == peer_id,
                "Batch author doesn't match sender"
            );
            batch.verify()?
        }
        Ok(())
    }
```

**File:** consensus/src/quorum_store/batch_coordinator.rs (L173-245)
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
    }
```

**File:** consensus/src/quorum_store/counters.rs (L617-624)
```rust
/// Count of the created batches since last restart.
pub static CREATED_BATCHES_COUNT: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "quorum_store_created_batch_count",
        "Count of the created batches since last restart."
    )
    .unwrap()
});
```

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

**File:** types/src/quorum_store/mod.rs (L11-57)
```rust
/// A unique identifier for a batch of transactions in quorum store
#[derive(
    Copy, Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Hash, CryptoHasher, BCSCryptoHash,
)]
pub struct BatchId {
    pub id: u64,
    /// A number that is stored in the DB and updated only if the value does not exist in
    /// the DB: (a) at the start of an epoch, or (b) the DB was wiped. When the nonce is updated,
    /// id starts again at 0. Using the current system time allows the nonce to be ordering.
    pub nonce: u64,
}

impl BatchId {
    pub fn new(nonce: u64) -> Self {
        Self { id: 0, nonce }
    }

    pub fn new_for_test(id: u64) -> Self {
        Self { id, nonce: 0 }
    }

    pub fn increment(&mut self) {
        self.id += 1;
    }
}

impl PartialOrd<Self> for BatchId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BatchId {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.nonce.cmp(&other.nonce) {
            Ordering::Equal => {},
            ordering => return ordering,
        }
        self.id.cmp(&other.id)
    }
}

impl Display for BatchId {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "({}, {})", self.id, self.nonce)
    }
}
```
