# Audit Report

## Title
Validator Node Crash via Mixed V1/V2 Batch Variant Attack in Batch Coordinator

## Summary
A malicious validator can crash other validators by sending a `BatchMsg` containing mixed V1 and V2 `BatchInfoExt` variants. The `BatchCoordinator::persist_and_send_digests` function only checks the first batch's variant to determine the processing path for all batches, causing a panic when subsequent batches have different variants.

## Finding Description
The vulnerability exists in the batch processing logic where variant consistency is assumed but not enforced across multiple validation and processing layers.

**1. No Variant Validation in BatchMsg::verify**

The `BatchMsg::verify` method validates author, epoch, and individual batch integrity, but does NOT check that all batches have the same `BatchInfoExt` variant (V1 or V2). [1](#0-0) 

The verification iterates through batches and calls `batch.verify()` on each individually, with no cross-batch variant consistency check.

**2. Incorrect Variant Assumption in persist_and_send_digests**

In `persist_and_send_digests`, the code checks only the first batch's variant using `is_v2()` to determine the processing path for ALL batches in the message. [2](#0-1) 

This single check at line 102 determines whether the V2 path (lines 103-111) or V1 path (lines 112-129) is taken for processing all batches.

**3. Panic on Variant Mismatch**

If the first batch is V1 (triggering the else branch), the code attempts to convert all `SignedBatchInfo<BatchInfoExt>` to `SignedBatchInfo<BatchInfo>` using `.try_into().expect()`, which will panic on any V2 variant. [3](#0-2) 

The `.expect("Batch must be V1 batch")` at line 124 causes an unrecoverable panic if the conversion fails.

**4. TryFrom Implementation Explicitly Fails on V2**

The `TryFrom` implementation for converting `SignedBatchInfo<BatchInfoExt>` to `SignedBatchInfo<BatchInfo>` explicitly validates that the variant must be V1 and fails with an error on V2 variants. [4](#0-3) 

The `ensure!` check at line 525 guarantees failure with "Batch must be V1 type" when encountering a V2 variant.

**Attack Execution Path:**

1. A malicious validator crafts a `BatchMsg<BatchInfoExt>` where the first batch uses `BatchInfoExt::V1` and subsequent batches use `BatchInfoExt::V2`. This is possible because `BatchInfoExt` is an enum that can hold either variant. [5](#0-4) 

2. The message is sent via `ConsensusMsg::BatchMsgV2` over the network. [6](#0-5) 

3. Message verification occurs in `RoundManager`, which calls `b.verify()` but does not check variant consistency. [7](#0-6) 

4. The verified message is routed to `BatchCoordinator::handle_batches_msg`. [8](#0-7) 

5. Processing reaches `persist_and_send_digests` at line 244, which checks only the first batch variant and attempts to process all batches uniformly.

6. When the else branch (V1 path) attempts to convert a V2 batch at line 124, the `TryFrom` conversion fails and the `.expect()` call causes a panic, crashing the validator node.

## Impact Explanation
**Severity: High**

This vulnerability meets the **High Severity** criteria per Aptos bug bounty framework:

- **Validator Node Slowdowns (High)**: Directly causes validator node crashes through unhandled panic in the consensus layer
- **API Crashes (High)**: Consensus processing crashes due to panic in batch coordination

**Concrete Impacts:**
- **Consensus Disruption**: Crashed validators cannot participate in consensus until manually restarted
- **Liveness Attack Vector**: If sufficient validators are repeatedly crashed, the network could lose liveness (though this requires targeting multiple validators)
- **Byzantine Fault Amplification**: A single malicious validator (< 1/3 Byzantine threshold) can disrupt multiple honest validators
- **Repeated Exploitation**: Attacker can continuously send malicious messages after validator restarts to maintain disruption

This is a protocol-level vulnerability in the consensus layer's batch processing logic, not a network DoS attack. The panic occurs due to incorrect type variant handling, making it a valid security issue within scope.

## Likelihood Explanation
**Likelihood: Medium-High**

**Attack Requirements:**
- Attacker must be a validator in the current epoch (required to pass author validation in the verify method)
- Ability to send consensus messages through the network layer
- No additional cryptographic barriers beyond being a valid validator

**Attack Complexity: Low**
- Simple to construct: Create batches with valid signatures where first is V1 and subsequent are V2
- No timing dependencies or race conditions required
- Deterministic outcome (guaranteed panic on mixed variants)
- Can be repeated indefinitely after any validator restart

**Realistic Threat Scenario:** 

Aptos's Byzantine fault tolerance model is designed to handle up to 1/3 malicious validators. A compromised validator node or malicious validator operator represents a realistic threat within this security model. The vulnerability allows such an actor to disrupt honest validators through a simple, repeatable attack that requires no special privileges beyond validator status.

## Recommendation

Add variant consistency validation in `BatchMsg::verify` to ensure all batches in a message use the same `BatchInfoExt` variant:

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
    
    // Add variant consistency check
    if self.batches.len() > 1 {
        let first_is_v2 = self.batches[0].batch_info().is_v2();
        for batch in self.batches.iter().skip(1) {
            ensure!(
                batch.batch_info().is_v2() == first_is_v2,
                "Inconsistent batch variants detected: all batches must be same variant"
            );
        }
    }
    
    let epoch_authors = verifier.address_to_validator_index();
    for batch in self.batches.iter() {
        // ... existing validation
    }
    Ok(())
}
```

Alternatively, enforce variant consistency in `persist_and_send_digests` by checking all batches before processing, though validation at the verify stage is preferable.

## Proof of Concept

A proof of concept would require:
1. Setting up a test validator network
2. Creating a `BatchMsg<BatchInfoExt>` with first batch as V1 and second batch as V2
3. Sending this message from a validator node
4. Observing the panic in the receiving validator's batch coordinator

The PoC structure would follow Rust test patterns in the consensus test suite, creating batches using `Batch::new_v1()` and `Batch::new_v2()` methods, then constructing a mixed-variant `BatchMsg` and sending it through the verification and coordination flow. [9](#0-8) 

## Notes

The vulnerability stems from an implicit assumption in the code that all batches in a `BatchMsg<BatchInfoExt>` will have uniform variants, when in fact the type system allows mixed variants. The `BatchInfoExt` enum definition explicitly supports both V1 and V2 variants, and there is no enforcement mechanism to ensure consistency across batches in a message. This represents a gap between the type-level flexibility and the runtime assumptions in the processing logic.

### Citations

**File:** consensus/src/quorum_store/types.rs (L231-251)
```rust
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

**File:** consensus/src/quorum_store/batch_coordinator.rs (L102-102)
```rust
            if persist_requests[0].batch_info().is_v2() {
```

**File:** consensus/src/quorum_store/batch_coordinator.rs (L122-125)
```rust
                    let signed_batch_infos = signed_batch_infos
                        .into_iter()
                        .map(|sbi| sbi.try_into().expect("Batch must be V1 batch"))
                        .collect();
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

**File:** consensus/consensus-types/src/proof_of_store.rs (L195-203)
```rust
pub enum BatchInfoExt {
    V1 {
        info: BatchInfo,
    },
    V2 {
        info: BatchInfo,
        extra: ExtraBatchInfo,
    },
}
```

**File:** consensus/consensus-types/src/proof_of_store.rs (L520-527)
```rust
impl TryFrom<SignedBatchInfo<BatchInfoExt>> for SignedBatchInfo<BatchInfo> {
    type Error = anyhow::Error;

    fn try_from(signed_batch_info: SignedBatchInfo<BatchInfoExt>) -> Result<Self, Self::Error> {
        ensure!(
            matches!(signed_batch_info.batch_info(), &BatchInfoExt::V1 { .. }),
            "Batch must be V1 type"
        );
```

**File:** consensus/src/network_interface.rs (L97-97)
```rust
    BatchMsgV2(Box<BatchMsg<BatchInfoExt>>),
```

**File:** consensus/src/round_manager.rs (L175-182)
```rust
            UnverifiedEvent::BatchMsgV2(b) => {
                if !self_message {
                    b.verify(peer_id, max_num_batches, validator)?;
                    counters::VERIFY_MSG
                        .with_label_values(&["batch_v2"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::BatchMsg(b)
```
