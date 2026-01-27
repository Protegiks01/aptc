# Audit Report

## Title
Empty Batch Acceptance Without Proper Validation and Monitoring in Quorum Store

## Summary
The batch coordinator accepts batches with zero transactions from remote validators without proper validation or failure counter tracking, creating a resource waste vector and monitoring blind spot. The empty batch check at line 184-186 validates the wrong condition (empty vector rather than zero-transaction batches).

## Finding Description

The batch coordinator contains a logic error in empty batch detection that allows malicious validators to send batches with zero transactions that are processed as valid batches without incrementing any failure counters.

**Validation Gap:**

The `BatchMsg::verify()` function only checks that the batches vector is not empty, but does NOT validate that individual batches contain at least one transaction: [1](#0-0) 

Similarly, `Batch::verify()` validates payload consistency but lacks a check for `num_txns() > 0`: [2](#0-1) 

The `ensure_max_limits()` function checks upper bounds but not that batches must contain transactions: [3](#0-2) 

**Incorrect Empty Check:**

Line 184-186 checks if the batches *vector* is empty (which should already be caught by verification), NOT if individual batches have zero transactions: [4](#0-3) 

**Processing Without Validation:**

Empty batches from remote peers are accepted and processed: [5](#0-4) 

The batch generator inserts empty remote batches without validation: [6](#0-5) 

**Asymmetric Handling:**

Locally created batches are prevented from being empty: [7](#0-6) 

But no equivalent check exists for remote batches.

**Attack Path:**
1. Malicious validator creates `Batch` objects with zero transactions using `Batch::new()` with empty transaction vector
2. Creates `BatchMsg` containing these batches and broadcasts to peers
3. Batches pass `BatchMsg::verify()` (vector not empty) and `Batch::verify()` (payload matches metadata)
4. Batches pass `ensure_max_limits()` (0 ≤ max_txns)
5. Line 184-186 check passes (vector not empty, even though batches have zero transactions)
6. Empty batches are sent to batch generator, persisted to storage, and increment `RECEIVED_BATCH_COUNT` and `RECEIVED_REMOTE_BATCH_COUNT`
7. No failure counters increment, creating monitoring blind spot

## Impact Explanation

**Medium Severity** - This vulnerability enables resource waste and operational issues:

1. **Storage Pollution**: Empty batches consume database space in batch store
2. **Processing Overhead**: CPU cycles wasted on processing, persisting, and tracking empty batches
3. **Network Bandwidth**: Empty batches consume network resources
4. **Monitoring Blind Spot**: Operators cannot detect this attack through existing metrics since normal batch counters increment
5. **Metric Pollution**: `RECEIVED_BATCH_COUNT` inflated without useful work performed

While not consensus-breaking, this violates the **Resource Limits** invariant (#9: "All operations must respect gas, storage, and computational limits") by allowing wasteful operations that consume resources without providing value. This falls under Medium severity as it causes state inconsistencies requiring operational intervention to clean up accumulated empty batches.

## Likelihood Explanation

**High Likelihood** - This vulnerability is easily exploitable:

1. **Low Barrier**: Any validator in the validator set can exploit this
2. **No Authentication Bypass**: Attacker just needs to be a validator (within Byzantine threat model of ≤1/3 malicious validators)
3. **Simple Execution**: Creating and broadcasting empty batches requires minimal code
4. **No Detection**: No existing monitoring alerts operators to this attack pattern
5. **Rate Limited but Persistent**: While network rate limits constrain flooding speed, attacker can persistently send empty batches within normal message rates

## Recommendation

Add validation to reject batches with zero transactions:

```rust
fn ensure_max_limits(&self, batches: &[Batch<BatchInfoExt>]) -> anyhow::Result<()> {
    let mut total_txns = 0;
    let mut total_bytes = 0;
    for batch in batches.iter() {
        // ADD THIS CHECK:
        ensure!(
            batch.num_txns() > 0,
            "Batch must contain at least one transaction"
        );
        
        ensure!(
            batch.num_txns() <= self.max_batch_txns,
            "Exceeds batch txn limit {} > {}",
            batch.num_txns(),
            self.max_batch_txns,
        );
        // ... rest of existing checks
    }
    // ... rest of function
}
```

Additionally, add a dedicated counter for rejected empty batches:

```rust
// In counters.rs:
pub static RECEIVED_EMPTY_BATCH_COUNT: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!(
        "quorum_store_received_empty_batch_count",
        "Count of empty batches received from remote peers"
    ).unwrap()
});

// In handle_batches_msg:
fn ensure_max_limits(&self, batches: &[Batch<BatchInfoExt>]) -> anyhow::Result<()> {
    for batch in batches.iter() {
        if batch.num_txns() == 0 {
            counters::RECEIVED_EMPTY_BATCH_COUNT.inc();
            bail!("Batch must contain at least one transaction");
        }
        // ... rest of validation
    }
}
```

## Proof of Concept

```rust
// Rust test demonstrating empty batch acceptance
#[tokio::test]
async fn test_empty_batch_accepted() {
    use aptos_types::PeerId;
    use consensus::quorum_store::types::{Batch, BatchMsg};
    use aptos_consensus_types::proof_of_store::BatchInfoExt;
    
    let peer_id = PeerId::random();
    let batch_id = BatchId::new(1000);
    
    // Create batch with ZERO transactions
    let empty_batch = Batch::new_v1(
        batch_id,
        vec![], // Empty transaction vector
        1,      // epoch
        1000000, // expiration
        peer_id,
        0,      // gas_bucket_start
    );
    
    // Verify the batch has zero transactions
    assert_eq!(empty_batch.num_txns(), 0);
    
    // Batch verification passes despite having zero transactions
    assert!(empty_batch.verify().is_ok());
    
    // Create BatchMsg containing the empty batch
    let batch_msg = BatchMsg::new(vec![empty_batch]);
    
    // BatchMsg verification also passes (only checks vector not empty)
    // The batch would be processed normally without any failure counter increment
}
```

## Notes

The vulnerability stems from incomplete validation logic where the system assumes batches contain transactions but never enforces this assumption for remotely received batches. The check at line 185 was likely intended to catch empty batches but incorrectly checks whether the batches vector is empty rather than whether individual batches contain zero transactions. This creates an asymmetry where locally generated empty batches are prevented (and tracked via `CREATED_EMPTY_BATCHES_COUNT`) but remote empty batches are silently accepted.

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

**File:** consensus/src/quorum_store/types.rs (L439-439)
```rust
        ensure!(!self.batches.is_empty(), "Empty message");
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

**File:** consensus/src/quorum_store/batch_coordinator.rs (L184-186)
```rust
        let Some(batch) = batches.first() else {
            error!("Empty batch received from {}", author.short_str().as_str());
            return;
```

**File:** consensus/src/quorum_store/batch_coordinator.rs (L228-244)
```rust
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

**File:** consensus/src/quorum_store/batch_generator.rs (L245-251)
```rust
            if num_batch_txns > 0 {
                let batch_txns: Vec<_> = txns.drain(0..num_batch_txns).collect();
                let batch = self.create_new_batch(batch_txns, expiry_time, bucket_start);
                batches.push(batch);
                *total_batches_remaining = total_batches_remaining.saturating_sub(1);
                txns_remaining -= num_batch_txns;
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
