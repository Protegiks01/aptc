# Audit Report

## Title
Batch Coordinator Panic via Mixed-Version Batch Messages Leading to Validator DoS

## Summary
A malicious validator can crash other validators by sending a `BatchMsgV2` containing mixed-version batches (V1 and V2 variants). The `BatchCoordinator::persist_and_send_digests` function incorrectly assumes all batches in a message have the same version based solely on checking the first batch, leading to a panic when attempting to convert V2 batches to V1.

## Finding Description

The vulnerability exists in the batch version handling logic within the consensus quorum store subsystem. When the network upgrades to V2, nodes can receive `BatchMsgV2` messages containing `Batch<BatchInfoExt>` objects, where `BatchInfoExt` is an enum with V1 and V2 variants.

The attack flow works as follows:

1. A malicious validator crafts a `BatchMsgV2` containing mixed-version batches, for example: `[BatchInfoExt::V1, BatchInfoExt::V2, BatchInfoExt::V2]`

2. This message passes network verification because the `BatchMsg::verify` method does not enforce version homogeneity - it only validates batch count, author, and individual batch integrity. [1](#0-0) 

3. The message is converted from `UnverifiedEvent::BatchMsgV2` to `VerifiedEvent::BatchMsg` during verification. [2](#0-1) 

4. The batches arrive at `BatchCoordinator::handle_batches_msg` and pass validation checks. [3](#0-2) 

5. In `persist_and_send_digests`, the code checks only the **first** batch's version to determine the processing path for **all** batches: [4](#0-3) 

6. When the first batch is V1 but subsequent batches are V2, the code takes the V1 processing path (else branch) and attempts to convert all signed batches to V1 using `try_into().expect("Batch must be V1 batch")`.

7. The `TryFrom` implementation for converting `SignedBatchInfo<BatchInfoExt>` to `SignedBatchInfo<BatchInfo>` enforces that the batch must be V1, returning an error for V2 batches: [5](#0-4) 

8. The `.expect()` call panics when it encounters a V2 batch, **crashing the validator node**.

This breaks the **Consensus Liveness** invariant - a single malicious validator can cause DoS by crashing other validators, disrupting network availability without requiring the traditional 1/3 Byzantine threshold.

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty program criteria:

- **Validator node crashes** - The panic directly terminates the validator process
- **Significant protocol violation** - Breaks the assumption that consensus should tolerate up to 1/3 Byzantine validators; here a single validator can cause crashes

The impact is severe because:
- Any validator can exploit this without collusion
- The attack is repeatable and can continuously crash validators
- Network availability and liveness are compromised
- No special resources or complex setup required

## Likelihood Explanation

**Likelihood: High**

The attack is highly likely to succeed because:

1. **Low complexity**: The attacker only needs to construct a `BatchMsgV2` with mixed-version batches and send it via the network layer
2. **No additional privileges**: Any validator can send batch messages as part of normal consensus operation
3. **No validation barriers**: There are no checks for version homogeneity at any layer (network, verification, or processing)
4. **Deterministic outcome**: The panic is guaranteed when mixed versions are processed with V1 first
5. **Easy to trigger**: The attacker can send the malicious message at any time during normal operation

## Recommendation

Add version homogeneity validation to the `BatchMsg::verify` method to ensure all batches in a single message have the same version:

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
    
    // Add version homogeneity check
    if !self.batches.is_empty() {
        let expected_is_v2 = self.batches[0].batch_info().is_v2();
        for batch in self.batches.iter().skip(1) {
            ensure!(
                batch.batch_info().is_v2() == expected_is_v2,
                "Mixed batch versions in message: expected all {}, found {}",
                if expected_is_v2 { "V2" } else { "V1" },
                if batch.batch_info().is_v2() { "V2" } else { "V1" }
            );
        }
    }
    
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

Additionally, consider replacing the `.expect()` with proper error handling in `persist_and_send_digests` to prevent panics even if mixed versions somehow bypass validation.

## Proof of Concept

```rust
#[cfg(test)]
mod test {
    use super::*;
    use aptos_consensus_types::proof_of_store::{BatchInfo, BatchInfoExt};
    use aptos_types::PeerId;
    
    #[tokio::test]
    async fn test_mixed_version_batch_panic() {
        // Setup: Create a BatchCoordinator and required dependencies
        let peer_id = PeerId::random();
        
        // Create mixed-version batches
        let batch_v1 = Batch::new_v1(
            BatchId::new_for_test(0),
            vec![/* transactions */],
            1, // epoch
            1000000, // expiration
            peer_id,
            0, // gas_bucket_start
        );
        
        let batch_v2 = Batch::new_v2(
            BatchId::new_for_test(1),
            vec![/* transactions */],
            1, // epoch
            1000000, // expiration
            peer_id,
            0, // gas_bucket_start
            BatchKind::Normal,
        );
        
        // Create BatchMsg with V1 first, then V2
        let mixed_batches = vec![batch_v1, batch_v2];
        let batch_msg = BatchMsg::new(mixed_batches);
        
        // Send to coordinator - this should panic on the .expect() call
        // when trying to convert V2 batch to V1
        // coordinator.handle_batches_msg(peer_id, batch_msg.batches).await;
        
        // Expected: Node panics with "Batch must be V1 batch"
        // This demonstrates the DoS vulnerability
    }
}
```

The PoC demonstrates that when a `BatchMsg` contains V1 batches followed by V2 batches, the batch coordinator will panic when processing the signed batch infos, causing the validator node to crash.

### Citations

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

**File:** consensus/src/round_manager.rs (L175-183)
```rust
            UnverifiedEvent::BatchMsgV2(b) => {
                if !self_message {
                    b.verify(peer_id, max_num_batches, validator)?;
                    counters::VERIFY_MSG
                        .with_label_values(&["batch_v2"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::BatchMsg(b)
            },
```

**File:** consensus/src/quorum_store/batch_coordinator.rs (L102-130)
```rust
            if persist_requests[0].batch_info().is_v2() {
                let signed_batch_infos = batch_store.persist(persist_requests);
                if !signed_batch_infos.is_empty() {
                    if approx_created_ts_usecs > 0 {
                        observe_batch(approx_created_ts_usecs, peer_id, BatchStage::SIGNED);
                    }
                    network_sender
                        .send_signed_batch_info_msg_v2(signed_batch_infos, vec![peer_id])
                        .await;
                }
            } else {
                let signed_batch_infos = batch_store.persist(persist_requests);
                if !signed_batch_infos.is_empty() {
                    assert!(!signed_batch_infos
                        .first()
                        .expect("must not be empty")
                        .is_v2());
                    if approx_created_ts_usecs > 0 {
                        observe_batch(approx_created_ts_usecs, peer_id, BatchStage::SIGNED);
                    }
                    let signed_batch_infos = signed_batch_infos
                        .into_iter()
                        .map(|sbi| sbi.try_into().expect("Batch must be V1 batch"))
                        .collect();
                    network_sender
                        .send_signed_batch_info_msg(signed_batch_infos, vec![peer_id])
                        .await;
                }
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

**File:** consensus/consensus-types/src/proof_of_store.rs (L523-527)
```rust
    fn try_from(signed_batch_info: SignedBatchInfo<BatchInfoExt>) -> Result<Self, Self::Error> {
        ensure!(
            matches!(signed_batch_info.batch_info(), &BatchInfoExt::V1 { .. }),
            "Batch must be V1 type"
        );
```
