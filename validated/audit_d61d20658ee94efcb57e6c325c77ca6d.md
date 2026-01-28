# Audit Report

## Title
Unbounded Batch Accumulation via Far-Future Expiration Time Manipulation in Quorum Store

## Summary
A malicious validator can send `BatchMsg` messages with batches containing expiration times set to `u64::MAX`, bypassing all expiration cleanup mechanisms in the quorum store. The absence of upper-bound validation on batch expiration times during `BatchMsg` processing allows these batches to accumulate indefinitely in memory, causing validator node resource exhaustion and performance degradation.

## Finding Description

The vulnerability exists in the quorum store's batch verification pipeline where `BatchMsg` messages from peer validators lack expiration time upper-bound validation, unlike `SignedBatchInfo` messages which have explicit upper-bound checks.

**Attack Execution Path:**

1. **Missing Validation in Batch::verify()**: When a batch is verified, only payload integrity is checked—expiration time is never validated. [1](#0-0) 

2. **Missing Validation in BatchMsg::verify()**: Network message verification checks batch count limits and author validity but completely omits expiration time bounds checking. [2](#0-1) 

3. **Insufficient BatchStore Validation**: The `save()` method only validates that `expiration > last_certified_time` (lower bound), allowing `u64::MAX` to pass validation. [3](#0-2) 

4. **Unconstrained Queue Insertion**: Batches are inserted into `BatchProofQueue` with their malicious expiration times stored directly in the expirations index without validation. [4](#0-3) 

5. **Expiration Cleanup Bypass**: The `handle_updated_block_timestamp()` method calls `expirations.expire(block_timestamp)`, which only removes batches where `expiration <= block_timestamp`. Since `u64::MAX >> block_timestamp`, malicious batches are never expired. [5](#0-4) 

6. **Garbage Collection Bypass**: Periodic GC retains items where `item.info.expiration() > timestamp`, which is always true for `u64::MAX`, preventing cleanup. [6](#0-5) 

**Contrast with Protected Path**: `SignedBatchInfo` messages DO have upper-bound validation that rejects batches with `expiration > current_time + max_batch_expiry_gap_usecs`. [7](#0-6)  However, this protection only applies to `SignedBatchInfo` messages, not `BatchMsg` messages received from remote peers.

**Affected Data Structures**: Unbounded accumulation occurs in `BatchStore::db_cache` (DashMap) [8](#0-7)  and `BatchProofQueue` structures including `items`, `author_to_batches`, and `expirations`. [9](#0-8) 

## Impact Explanation

**Severity: HIGH**

This vulnerability qualifies as **High Severity ($50,000 tier)** under the Aptos Bug Bounty program's "Validator Node Slowdowns" category, specifically "DoS through resource exhaustion."

**Impact Categories:**

1. **Unbounded Memory Accumulation**: Each malicious batch permanently consumes memory across multiple concurrent data structures (DashMap, HashMap, BTreeMap, TimeExpirations), with no automatic cleanup mechanism.

2. **Validator Performance Degradation**: Growing data structures increase lookup times, memory pressure, and CPU usage for hash operations, directly degrading consensus participation and block processing speed.

3. **Network Decentralization Risk**: Sustained attacks can crash validator nodes through memory exhaustion, reducing the active validator set and weakening network security.

4. **Economic Asymmetry**: An attacker controlling a single validator can impose continuous resource costs on all honest validators without corresponding stake penalties, as invalid expiration times are not detected as Byzantine behavior.

## Likelihood Explanation

**Likelihood: HIGH**

This attack is highly likely because:

1. **Minimal Attack Complexity**: Creating batches with `u64::MAX` expiration requires only modifying a single field during batch construction—no cryptographic operations or complex protocol manipulation needed.

2. **Single Attacker Sufficient**: Any individual malicious or compromised validator can execute this attack against the entire network without coordination.

3. **No Detection or Penalty**: The protocol lacks mechanisms to detect or penalize validators sending batches with unreasonable expiration times, making this a zero-cost attack for the perpetrator.

4. **Persistent Impact**: Effects are cumulative—each malicious batch permanently increases memory usage until manual intervention or node restart.

5. **Operational Stealth**: Memory growth may be gradual enough to avoid immediate detection, allowing sustained attacks before operators identify the root cause.

## Recommendation

Add upper-bound expiration validation to `BatchMsg::verify()` matching the protection already present in `SignedBatchInfo::verify()`:

```rust
pub fn verify(
    &self,
    peer_id: PeerId,
    max_num_batches: usize,
    max_batch_expiry_gap_usecs: u64,  // Add parameter
    verifier: &ValidatorVerifier,
) -> anyhow::Result<()> {
    ensure!(!self.batches.is_empty(), "Empty message");
    ensure!(
        self.batches.len() <= max_num_batches,
        "Too many batches: {} > {}",
        self.batches.len(),
        max_num_batches
    );
    
    let current_time = aptos_infallible::duration_since_epoch().as_micros() as u64;
    let max_expiration = current_time + max_batch_expiry_gap_usecs;
    
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
        
        // Add expiration upper bound check
        ensure!(
            batch.expiration() <= max_expiration,
            "Batch expiration too far in future: {} > {}",
            batch.expiration(),
            max_expiration
        );
        
        batch.verify()?
    }
    Ok(())
}
```

Update the call sites in `round_manager.rs` to pass `max_batch_expiry_gap_usecs` to `BatchMsg::verify()`, matching the existing pattern for `SignedBatchInfo` verification.

## Proof of Concept

The vulnerability can be demonstrated by creating a malicious validator that sends `BatchMsg` with `u64::MAX` expiration:

```rust
// Create batch with far-future expiration
let malicious_batch = Batch::new(
    batch_id,
    vec![txn1, txn2],
    current_epoch,
    u64::MAX,  // Malicious expiration time
    validator_peer_id,
    gas_bucket_start,
);

// Send via BatchMsg - will pass all verification
let batch_msg = BatchMsg::new(vec![malicious_batch]);
network.broadcast_batch_msg(batch_msg);

// On receiving validator:
// - BatchMsg::verify() passes (no expiration check)
// - BatchStore::save() passes (u64::MAX > last_certified_time)
// - BatchProofQueue stores indefinitely (u64::MAX > any timestamp)
// - Memory grows unbounded as batches accumulate
```

Over time, repeated sending of such batches will cause:
- Linear growth in `db_cache`, `items`, `author_to_batches` sizes
- Increased memory consumption measurable via system metrics
- Degraded lookup performance in growing HashMaps
- Eventual OOM conditions on resource-constrained validators

## Notes

The vulnerability is particularly concerning because the codebase already demonstrates awareness of expiration upper-bound validation through the `SignedBatchInfo` implementation, but this protection was not applied to the `BatchMsg` code path. This represents an incomplete security control implementation rather than a fundamental design flaw, making it straightforward to remediate by applying consistent validation across all batch ingestion paths.

### Citations

**File:** consensus/src/quorum_store/types.rs (L262-290)
```rust
    pub fn verify(&self) -> anyhow::Result<()> {
        ensure!(
            self.payload.author() == self.author(),
            "Payload author doesn't match the info"
        );
        ensure!(
            self.payload.hash() == *self.digest(),
            "Payload hash doesn't match the digest"
        );
        ensure!(
            self.payload.num_txns() as u64 == self.num_txns(),
            "Payload num txns doesn't match batch info"
        );
        ensure!(
            self.payload.num_bytes() as u64 == self.num_bytes(),
            "Payload num bytes doesn't match batch info"
        );
        for txn in self.payload.txns() {
            ensure!(
                txn.gas_unit_price() >= self.gas_bucket_start(),
                "Payload gas unit price doesn't match batch info"
            );
            ensure!(
                !txn.payload().is_encrypted_variant(),
                "Encrypted transaction is not supported yet"
            );
        }
        Ok(())
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

**File:** consensus/src/quorum_store/batch_store.rs (L113-120)
```rust
pub struct BatchStore {
    epoch: OnceCell<u64>,
    last_certified_time: AtomicU64,
    db_cache: DashMap<HashValue, PersistedValue<BatchInfoExt>>,
    peer_quota: DashMap<PeerId, QuotaManager>,
    expirations: Mutex<TimeExpirations<HashValue>>,
    db: Arc<dyn QuorumStoreStorage>,
    memory_quota: usize,
```

**File:** consensus/src/quorum_store/batch_store.rs (L419-439)
```rust
    pub(crate) fn save(&self, value: &PersistedValue<BatchInfoExt>) -> anyhow::Result<bool> {
        let last_certified_time = self.last_certified_time();
        if value.expiration() > last_certified_time {
            fail_point!("quorum_store::save", |_| {
                // Skip caching and storing value to the db
                Ok(false)
            });
            counters::GAP_BETWEEN_BATCH_EXPIRATION_AND_CURRENT_TIME_WHEN_SAVE.observe(
                Duration::from_micros(value.expiration() - last_certified_time).as_secs_f64(),
            );

            return self.insert_to_cache(value);
        }
        counters::NUM_BATCH_EXPIRED_WHEN_SAVE.inc();
        bail!(
            "Incorrect expiration {} in epoch {}, last committed timestamp {}",
            value.expiration(),
            self.epoch(),
            last_certified_time,
        );
    }
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L56-76)
```rust
pub struct BatchProofQueue {
    my_peer_id: PeerId,
    // Queue per peer to ensure fairness between peers and priority within peer
    author_to_batches: HashMap<PeerId, BTreeMap<BatchSortKey, BatchInfoExt>>,
    // Map of Batch key to QueueItem containing Batch data and proofs
    items: HashMap<BatchKey, QueueItem>,
    // Number of unexpired and uncommitted proofs in which the txn_summary = (sender, replay protector, hash, expiration)
    // has been included. We only count those batches that are in both author_to_batches and items along with proofs.
    txn_summary_num_occurrences: HashMap<TxnSummaryWithExpiration, u64>,
    // Expiration index
    expirations: TimeExpirations<BatchSortKey>,
    batch_store: Arc<BatchStore>,

    latest_block_timestamp: u64,
    remaining_txns_with_duplicates: u64,
    remaining_proofs: u64,
    remaining_local_txns: u64,
    remaining_local_proofs: u64,

    batch_expiry_gap_when_init_usecs: u64,
}
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L278-283)
```rust
            self.author_to_batches
                .entry(batch_info.author())
                .or_default()
                .insert(batch_sort_key.clone(), batch_info.clone());
            self.expirations
                .add_item(batch_sort_key, batch_info.expiration());
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L324-339)
```rust
    fn gc_expired_batch_summaries_without_proofs(&mut self) {
        let timestamp = aptos_infallible::duration_since_epoch().as_micros() as u64;
        self.items.retain(|_, item| {
            if item.is_committed() || item.proof.is_some() || item.info.expiration() > timestamp {
                true
            } else {
                self.author_to_batches
                    .get_mut(&item.info.author())
                    .map(|queue| queue.remove(&BatchSortKey::from_info(&item.info)));
                counters::GARBAGE_COLLECTED_IN_PROOF_QUEUE_COUNTER
                    .with_label_values(&["expired_batch_without_proof"])
                    .inc();
                false
            }
        });
    }
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L716-769)
```rust
    pub(crate) fn handle_updated_block_timestamp(&mut self, block_timestamp: u64) {
        // tolerate asynchronous notification
        if self.latest_block_timestamp > block_timestamp {
            return;
        }
        let start = Instant::now();
        self.latest_block_timestamp = block_timestamp;
        if let Some(time_lag) = aptos_infallible::duration_since_epoch()
            .checked_sub(Duration::from_micros(block_timestamp))
        {
            counters::TIME_LAG_IN_BATCH_PROOF_QUEUE.observe_duration(time_lag);
        }

        let expired = self.expirations.expire(block_timestamp);
        let mut num_expired_but_not_committed = 0;
        for key in &expired {
            if let Some(mut queue) = self.author_to_batches.remove(&key.author()) {
                if let Some(batch) = queue.remove(key) {
                    let item = self
                        .items
                        .get(&key.batch_key)
                        .expect("Entry for unexpired batch must exist");
                    if item.proof.is_some() {
                        // not committed proof that is expired
                        num_expired_but_not_committed += 1;
                        counters::GAP_BETWEEN_BATCH_EXPIRATION_AND_CURRENT_TIME_WHEN_COMMIT
                            .observe((block_timestamp - batch.expiration()) as f64);
                        if let Some(ref txn_summaries) = item.txn_summaries {
                            for txn_summary in txn_summaries {
                                if let Some(count) =
                                    self.txn_summary_num_occurrences.get_mut(txn_summary)
                                {
                                    *count -= 1;
                                    if *count == 0 {
                                        self.txn_summary_num_occurrences.remove(txn_summary);
                                    }
                                };
                            }
                        }
                        self.dec_remaining_proofs(&batch.author(), batch.num_txns());
                        counters::GARBAGE_COLLECTED_IN_PROOF_QUEUE_COUNTER
                            .with_label_values(&["expired_proof"])
                            .inc();
                    }
                    claims::assert_some!(self.items.remove(&key.batch_key));
                }
                if !queue.is_empty() {
                    self.author_to_batches.insert(key.author(), queue);
                }
            }
        }
        counters::PROOF_QUEUE_UPDATE_TIMESTAMP_DURATION.observe_duration(start.elapsed());
        counters::NUM_PROOFS_EXPIRED_WHEN_COMMIT.inc_by(num_expired_but_not_committed);
    }
```

**File:** consensus/consensus-types/src/proof_of_store.rs (L459-482)
```rust
    pub fn verify(
        &self,
        sender: PeerId,
        max_batch_expiry_gap_usecs: u64,
        validator: &ValidatorVerifier,
    ) -> anyhow::Result<()> {
        if sender != self.signer {
            bail!("Sender {} mismatch signer {}", sender, self.signer);
        }

        if self.expiration()
            > aptos_infallible::duration_since_epoch().as_micros() as u64
                + max_batch_expiry_gap_usecs
        {
            bail!(
                "Batch expiration too far in future: {} > {}",
                self.expiration(),
                aptos_infallible::duration_since_epoch().as_micros() as u64
                    + max_batch_expiry_gap_usecs
            );
        }

        Ok(validator.optimistic_verify(self.signer, &self.info, &self.signature)?)
    }
```
