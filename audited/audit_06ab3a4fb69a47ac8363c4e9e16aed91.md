# Audit Report

## Title
Empty Batch Spam Vulnerability in Quorum Store Verification

## Summary
The `Batch::verify()` function in the consensus quorum store does not validate that batches contain at least one transaction (`num_txns > 0`), allowing malicious validators to create and broadcast empty batches that consume network resources without processing any gas-paying transactions.

## Finding Description
The vulnerability exists in the batch verification logic that validates incoming batches from other validators. [1](#0-0) 

The `verify()` function checks that:
1. Payload author matches batch info author
2. Payload hash matches digest
3. Payload transaction count **matches** batch info count (but not that it's > 0)
4. Payload byte size matches batch info
5. Each transaction meets gas and encryption requirements (but skips if no transactions)

**The Critical Gap**: Line 272 only ensures `self.payload.num_txns() as u64 == self.num_txns()`, meaning if both are 0, the check passes. The transaction validation loop (lines 279-288) executes zero iterations when `num_txns=0`, so no rejection occurs.

**Attack Flow**:
1. Malicious validator crafts `Batch` with `num_txns=0` and empty payload vector
2. Batch passes `BatchMsg::verify()` which calls `batch.verify()` [2](#0-1) 
3. Batch passes coordinator limits check which only validates upper bounds [3](#0-2) 
4. Empty batch is persisted to disk, broadcast as `SignedBatchInfo`, and added to proof queues [4](#0-3) 

**Why This Bypasses Normal Controls**: Honest validators have a check preventing local creation of empty batches [5](#0-4) , but this doesn't prevent accepting maliciously-crafted empty batches from the network.

**Evidence**: The codebase already creates empty `BatchPayload` in tests, demonstrating it's structurally valid [6](#0-5) 

## Impact Explanation
**Severity: Medium** (per Aptos Bug Bounty criteria)

This enables a resource exhaustion attack:
- **Network Bandwidth**: Empty batches consume broadcast capacity for `BatchMsg` and `SignedBatchInfo` propagation
- **Disk Storage**: Each empty batch is persisted via `batch_store.persist()`
- **CPU Resources**: Signature verification, hash computation, and queue management occur for zero-transaction batches
- **Memory Consumption**: Empty batches occupy slots in proof queues and tracking structures

**Why Not Higher Severity**:
- Does not cause consensus safety violations or fund loss
- Does not completely halt the network (legitimate batches can still process)
- Rate-limited by validator bandwidth and network capacity
- Does not require the critical "hardfork to resolve" threshold

**Why Not Lower Severity**:
- Requires manual intervention to detect and mitigate spam
- Degrades network performance for all validators
- No gas fees paid for consumed resources (breaks economic model)
- Could impact consensus liveness if spam is sustained

## Likelihood Explanation
**Likelihood: Low-Medium**

**Requirements**:
- Attacker must operate a validator node (high barrier)
- Must modify node software to bypass local empty-batch prevention
- Must maintain validator status (requires stake)

**Mitigating Factors**:
- Validator reputation at risk if detected
- Slashing mechanisms may apply for malicious behavior
- Network monitoring can detect unusual batch patterns
- Requires sustained effort to cause significant impact

**However**: The vulnerability is trivially exploitable once validator access is obtained - no complex cryptographic or timing attacks required.

## Recommendation
Add explicit validation that batches must contain at least one transaction:

```rust
pub fn verify(&self) -> anyhow::Result<()> {
    // NEW: Reject empty batches
    ensure!(
        self.num_txns() > 0,
        "Batch must contain at least one transaction"
    );
    
    ensure!(
        self.payload.author() == self.author(),
        "Payload author doesn't match the info"
    );
    // ... rest of existing checks
}
```

Additionally, consider adding the same check in `BatchCoordinator::ensure_max_limits()`:

```rust
fn ensure_max_limits(&self, batches: &[Batch<BatchInfoExt>]) -> anyhow::Result<()> {
    let mut total_txns = 0;
    let mut total_bytes = 0;
    for batch in batches.iter() {
        // NEW: Reject empty batches
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
    Ok(())
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod empty_batch_exploit_test {
    use super::*;
    use aptos_types::{
        account_address::AccountAddress,
        quorum_store::BatchId,
    };
    use aptos_consensus_types::{
        common::BatchPayload,
        proof_of_store::BatchInfo,
    };

    #[test]
    fn test_empty_batch_passes_verification() {
        // Create an empty batch (0 transactions)
        let author = AccountAddress::random();
        let batch_id = BatchId::new_for_test(1);
        let epoch = 1;
        let expiration = 1000000;
        let empty_txns = vec![];
        
        // Create batch with empty payload
        let payload = BatchPayload::new(author, empty_txns);
        let batch_info = BatchInfo::new(
            author,
            batch_id,
            epoch,
            expiration,
            payload.hash(),
            0, // num_txns = 0
            payload.num_bytes() as u64,
            0, // gas_bucket_start
        );
        
        let empty_batch = Batch::new_generic(batch_info, payload);
        
        // VULNERABILITY: This should fail but passes
        let result = empty_batch.verify();
        assert!(result.is_ok(), "Empty batch incorrectly passes verification");
        
        // Demonstrate the batch has zero transactions
        assert_eq!(empty_batch.num_txns(), 0);
        assert_eq!(empty_batch.txns().len(), 0);
    }
}
```

**Notes**

This vulnerability requires a **malicious validator** to exploit, as regular users cannot broadcast batch messages to the consensus network. While honest validators have local checks preventing empty batch creation, the network-level verification (`Batch::verify()`) lacks this protection, creating a defense gap exploitable by Byzantine validators.

The fix is straightforward: add `ensure!(self.num_txns() > 0)` to reject empty batches at verification time, preventing resource exhaustion from zero-transaction batch spam.

### Citations

**File:** consensus/src/quorum_store/types.rs (L134-142)
```rust
    fn test_batch_payload_padding() {
        use super::*;
        let empty_batch_payload = BatchPayload::new(PeerId::random(), vec![]);
        // We overestimate the ULEB128 encoding of the number of transactions as 128 bytes.
        assert_eq!(
            empty_batch_payload.num_bytes() + 127,
            config::BATCH_PADDING_BYTES
        );
    }
```

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
