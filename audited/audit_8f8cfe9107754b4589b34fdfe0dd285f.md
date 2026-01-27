# Audit Report

## Title
SignedBatchInfo Ordering Dependency Causes Liveness Degradation Under Byzantine Timing Attacks

## Summary
The quorum store network listener has an implicit ordering dependency where `SignedBatchInfo` messages can only be processed after the corresponding `BatchMsg` has been persisted to `BatchStore`. Byzantine validators can exploit this by sending `SignedBatchInfo` messages before the batch author completes persistence, causing legitimate signatures to be rejected and delaying proof aggregation, which impacts consensus liveness.

## Finding Description

The `ProofCoordinator` enforces an implicit ordering requirement when processing `SignedBatchInfo` messages. When a `SignedBatchInfo` arrives, the `init_proof()` method checks if the corresponding batch exists in the local `BatchStore`: [1](#0-0) 

If the batch doesn't exist (i.e., `BatchMsg` hasn't been processed yet), the signature is rejected: [2](#0-1) 

**Attack Flow:**

1. Honest Node A broadcasts `BatchMsg` to all validators
2. Node A begins persisting the batch locally (asynchronous operation in `BatchCoordinator`) [3](#0-2) 

3. Byzantine Node B receives and quickly processes the `BatchMsg`, persisting it locally
4. Node B immediately sends `SignedBatchInfo` back to Node A **before** Node A finishes its own persistence
5. Node A's `ProofCoordinator` receives the `SignedBatchInfo` and calls `init_proof()`
6. Since Node A's persistence hasn't completed, `batch_reader.exists()` returns `None`
7. The valid `SignedBatchInfo` from Node B is rejected with `SignedBatchInfoError::NotFound` [4](#0-3) 

If multiple Byzantine validators coordinate to send signatures prematurely, the batch author may fail to collect sufficient signatures within the timeout period, preventing `ProofOfStore` formation. [5](#0-4) 

**Contrast with ProofOfStore:** 

Notably, `ProofOfStore` messages have NO such ordering dependency - they can be accepted even if the corresponding batch doesn't exist locally: [6](#0-5) 

This asymmetry creates an exploitable timing window.

## Impact Explanation

**Severity: Medium**

This vulnerability causes **liveness degradation** rather than safety violations:

- Valid batches fail to form `ProofOfStore` within the timeout window
- Blocks cannot include these batches, reducing throughput
- The system remains safe (no incorrect state transitions), but efficiency is impacted
- Requires intervention through retries or increased timeouts

According to Aptos bug bounty criteria, this qualifies as **Medium Severity** ($10,000): "State inconsistencies requiring intervention" - batches remain uncertified, requiring timeout-based recovery mechanisms.

The vulnerability does NOT:
- Break consensus safety (all nodes eventually converge)
- Cause fund loss or theft
- Enable unauthorized state modifications
- Require a hard fork to recover

## Likelihood Explanation

**Likelihood: Medium-High**

This attack is feasible because:

1. **Low Attack Complexity:** Byzantine validators simply need to send `SignedBatchInfo` messages immediately upon receiving `BatchMsg`, before the author completes persistence
2. **No Collusion Required:** Each Byzantine validator can independently exploit the timing window
3. **Persistent Effect:** With <33% Byzantine validators sending premature signatures, proof aggregation is delayed but will eventually succeed
4. **Race Condition:** The vulnerability exploits a natural race between network message propagation and local disk I/O

However:
- The system has timeouts and retries that mitigate the impact
- Honest validators will eventually send valid signatures
- The attack only delays certification, it doesn't prevent it permanently

## Recommendation

**Solution 1: Delayed Signature Processing (Preferred)**

Modify `ProofCoordinator` to queue `SignedBatchInfo` messages that arrive before the batch exists, and process them once the batch becomes available:

```rust
// Add to ProofCoordinator struct
pending_signatures: HashMap<HashValue, Vec<SignedBatchInfo<BatchInfoExt>>>,

fn add_signature(
    &mut self,
    signed_batch_info: SignedBatchInfo<BatchInfoExt>,
    validator_verifier: &ValidatorVerifier,
) -> Result<Option<ProofOfStore<BatchInfoExt>>, SignedBatchInfoError> {
    let digest = *signed_batch_info.digest();
    
    // Check if batch exists
    if !self.batch_reader.exists(&digest).is_some() {
        // Queue for later processing instead of rejecting
        self.pending_signatures
            .entry(digest)
            .or_default()
            .push(signed_batch_info);
        return Ok(None);
    }
    
    // Process normally...
}

// Add batch availability notification
fn notify_batch_available(&mut self, digest: HashValue) {
    if let Some(signatures) = self.pending_signatures.remove(&digest) {
        for sig in signatures {
            let _ = self.add_signature(sig, validator_verifier);
        }
    }
}
```

**Solution 2: Increase Timeout Tolerance**

Adjust proof timeout configuration to account for worst-case persistence delays, reducing the impact of premature signature rejection.

**Solution 3: Parallel Persistence and Signature Broadcasting**

Ensure `BatchCoordinator` completes local persistence before broadcasting `BatchMsg` to other validators, eliminating the race condition.

## Proof of Concept

```rust
// Rust integration test demonstrating the vulnerability
#[tokio::test]
async fn test_premature_signed_batch_info_rejection() {
    // Setup: Create validator nodes A and B
    let (node_a, node_b) = setup_test_nodes().await;
    
    // Step 1: Node A creates and broadcasts BatchMsg
    let batch = create_test_batch(node_a.peer_id(), 100);
    node_a.broadcast_batch(batch.clone()).await;
    
    // Step 2: Node B receives, processes, and signs immediately
    node_b.receive_batch(batch.clone()).await;
    let signed_batch_info = node_b.sign_batch(batch.info()).await;
    
    // Step 3: Send signature to Node A BEFORE its persistence completes
    // (simulate fast network + slow disk)
    tokio::time::sleep(Duration::from_millis(10)).await;
    
    // Step 4: Node A receives signature while still persisting
    let result = node_a.receive_signature(signed_batch_info).await;
    
    // Assertion: Signature is rejected with NotFound error
    assert!(matches!(result, Err(SignedBatchInfoError::NotFound)));
    
    // Step 5: Wait for persistence to complete
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Step 6: Signature would now be accepted, but proof timeout may have passed
    let proof_state = node_a.get_proof_state(batch.digest());
    assert!(proof_state.is_none() || !proof_state.unwrap().completed);
}
```

## Notes

This vulnerability represents a **design trade-off** between safety and liveness. The batch existence check in `init_proof()` is intentional - it prevents signature aggregation for non-existent batches, which is a correct safety property. However, the implementation doesn't gracefully handle the case where valid signatures arrive before local persistence completes.

The vulnerability is exploitable by Byzantine validators with <33% stake but does not break consensus safety invariants. It's classified as Medium severity due to its impact on system liveness and throughput rather than security.

### Citations

**File:** consensus/src/quorum_store/proof_coordinator.rs (L269-283)
```rust
    fn init_proof(
        &mut self,
        signed_batch_info: &SignedBatchInfo<BatchInfoExt>,
    ) -> Result<(), SignedBatchInfoError> {
        // Check if the signed digest corresponding to our batch
        if signed_batch_info.author() != self.peer_id {
            return Err(SignedBatchInfoError::WrongAuthor);
        }
        let batch_author = self
            .batch_reader
            .exists(signed_batch_info.digest())
            .ok_or(SignedBatchInfoError::NotFound)?;
        if batch_author != signed_batch_info.author() {
            return Err(SignedBatchInfoError::WrongAuthor);
        }
```

**File:** consensus/src/quorum_store/proof_coordinator.rs (L313-323)
```rust
    fn add_signature(
        &mut self,
        signed_batch_info: SignedBatchInfo<BatchInfoExt>,
        validator_verifier: &ValidatorVerifier,
    ) -> Result<Option<ProofOfStore<BatchInfoExt>>, SignedBatchInfoError> {
        if !self
            .batch_info_to_proof
            .contains_key(signed_batch_info.batch_info())
        {
            self.init_proof(&signed_batch_info)?;
        }
```

**File:** consensus/src/quorum_store/proof_coordinator.rs (L369-402)
```rust
    async fn expire(&mut self) {
        let mut batch_ids = vec![];
        for signed_batch_info_info in self.timeouts.expire() {
            if let Some(state) = self.batch_info_to_proof.remove(&signed_batch_info_info) {
                if !state.completed {
                    batch_ids.push(signed_batch_info_info.batch_id());
                }
                Self::update_counters_on_expire(&state);

                // We skip metrics if the proof did not complete and did not get a self vote, as it
                // is considered a proof that was re-inited due to a very late vote.
                if !state.completed && !state.self_voted {
                    continue;
                }

                if !state.completed {
                    counters::TIMEOUT_BATCHES_COUNT.inc();
                    info!(
                        LogSchema::new(LogEvent::IncrementalProofExpired),
                        digest = signed_batch_info_info.digest(),
                        self_voted = state.self_voted,
                    );
                }
            }
        }
        if self
            .batch_generator_cmd_tx
            .send(BatchGeneratorCommand::ProofExpiration(batch_ids))
            .await
            .is_err()
        {
            warn!("Failed to send proof expiration to batch generator");
        }
    }
```

**File:** consensus/src/quorum_store/batch_coordinator.rs (L78-135)
```rust
    fn persist_and_send_digests(
        &self,
        persist_requests: Vec<PersistedValue<BatchInfoExt>>,
        approx_created_ts_usecs: u64,
    ) {
        if persist_requests.is_empty() {
            return;
        }

        let batch_store = self.batch_store.clone();
        let network_sender = self.network_sender.clone();
        let sender_to_proof_manager = self.sender_to_proof_manager.clone();
        tokio::spawn(async move {
            let peer_id = persist_requests[0].author();
            let batches = persist_requests
                .iter()
                .map(|persisted_value| {
                    (
                        persisted_value.batch_info().clone(),
                        persisted_value.summary(),
                    )
                })
                .collect();

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
            let _ = sender_to_proof_manager
                .send(ProofManagerCommand::ReceiveBatches(batches))
                .await;
        });
    }
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L175-256)
```rust
    pub(crate) fn insert_proof(&mut self, proof: ProofOfStore<BatchInfoExt>) {
        if proof.expiration() <= self.latest_block_timestamp {
            counters::inc_rejected_pos_count(counters::POS_EXPIRED_LABEL);
            return;
        }
        let batch_key = BatchKey::from_info(proof.info());
        if self
            .items
            .get(&batch_key)
            .is_some_and(|item| item.proof.is_some() || item.is_committed())
        {
            counters::inc_rejected_pos_count(counters::POS_DUPLICATE_LABEL);
            return;
        }

        let author = proof.author();
        let bucket = proof.gas_bucket_start();
        let num_txns = proof.num_txns();
        let expiration = proof.expiration();

        let batch_sort_key = BatchSortKey::from_info(proof.info());
        let batches_for_author = self.author_to_batches.entry(author).or_default();
        batches_for_author.insert(batch_sort_key.clone(), proof.info().clone());

        // Check if a batch with a higher batch Id (reverse sorted) exists
        if let Some((prev_batch_key, _)) = batches_for_author
            .range((Bound::Unbounded, Bound::Excluded(batch_sort_key.clone())))
            .next_back()
        {
            if prev_batch_key.gas_bucket_start() == batch_sort_key.gas_bucket_start() {
                counters::PROOF_MANAGER_OUT_OF_ORDER_PROOF_INSERTION
                    .with_label_values(&[author.short_str().as_str()])
                    .inc();
            }
        }

        self.expirations.add_item(batch_sort_key, expiration);

        // If we are here, then proof is added for the first time. Otherwise, we will
        // return early. We only count when proof is added for the first time and txn
        // summary exists.
        if let Some(txn_summaries) = self
            .items
            .get(&batch_key)
            .and_then(|item| item.txn_summaries.as_ref())
        {
            for txn_summary in txn_summaries {
                *self
                    .txn_summary_num_occurrences
                    .entry(*txn_summary)
                    .or_insert(0) += 1;
            }
        }

        match self.items.entry(batch_key) {
            Entry::Occupied(mut entry) => {
                let item = entry.get_mut();
                item.proof = Some(proof);
                item.proof_insertion_time = Some(Instant::now());
            },
            Entry::Vacant(entry) => {
                entry.insert(QueueItem {
                    info: proof.info().clone(),
                    proof: Some(proof),
                    proof_insertion_time: Some(Instant::now()),
                    txn_summaries: None,
                });
            },
        }

        if author == self.my_peer_id {
            counters::inc_local_pos_count(bucket);
        } else {
            counters::inc_remote_pos_count(bucket);
        }
        self.inc_remaining_proofs(&author, num_txns);

        sample!(
            SampleRate::Duration(Duration::from_millis(500)),
            self.gc_expired_batch_summaries_without_proofs()
        );
    }
```
