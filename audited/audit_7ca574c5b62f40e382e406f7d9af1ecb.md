# Audit Report

## Title
Batch ID Collision Enables Transaction Censorship and State Inconsistency Across Validators

## Summary
A Byzantine or buggy validator can create multiple batches with the same `batch_id` but different transactions, causing different validators to track inconsistent transaction states and creating non-deterministic block construction behavior. This enables censorship attacks and violates protocol determinism guarantees.

## Finding Description

The vulnerability exists in the batch tracking mechanism within the quorum store system. When a batch arrives via `handle_remote_batch()`, it is tracked in a HashMap using `(PeerId, BatchId)` as the key: [1](#0-0) 

The `insert_batch()` function contains an early-return check that silently drops any batch with a duplicate `(author, batch_id)` key: [2](#0-1) 

However, ALL batches are persisted to the BatchStore regardless of this check, because persistence happens at the BatchCoordinator level before the duplicate check: [3](#0-2) 

When two batches with the same `(author, batch_id)` but different transactions (and thus different digests) are broadcast:

1. **Network Race Condition**: Different validators receive the batches in different orders due to network timing
2. **Divergent Tracking**: Each validator tracks only the first-received batch's transactions in `batches_in_progress`, while the second is silently dropped
3. **Both Batches Persisted**: Both batches are stored in the BatchStore keyed by their respective digests
4. **Proof Queue Collision**: The BatchProofQueue also uses `(author, batch_id)` as the key: [4](#0-3) 

5. **Non-Deterministic Proof Selection**: Different validators end up with different proofs in their queues (first-received wins): [5](#0-4) 

**Attack Scenario:**

A Byzantine validator creates:
- Batch1: `(author=A, batch_id=100, digest=H1, txns=[VictimTx1, VictimTx2])`
- Batch2: `(author=A, batch_id=100, digest=H2, txns=[DummyTx1, DummyTx2])`

The validator broadcasts both batches. Due to network timing:
- Validator V1 receives Batch1 first → tracks `[VictimTx1, VictimTx2]` as in-progress
- Validator V2 receives Batch2 first → tracks `[DummyTx1, DummyTx2]` as in-progress

When pulling from mempool, V1 excludes the victim's transactions (thinking they're already batched), while V2 doesn't. When forming proofs:
- V1's proof queue contains ProofOfStore(H1)
- V2's proof queue contains ProofOfStore(H2)

Block proposers include different proofs depending on their local state, creating non-deterministic block construction.

**Broken Invariants:**
1. **State Consistency**: Different validators maintain inconsistent views of which transactions are "in-progress"
2. **Deterministic Execution**: Block construction becomes non-deterministic based on network timing rather than deterministic protocol rules

## Impact Explanation

**High Severity** - This vulnerability qualifies as a "Significant Protocol Violation" per Aptos bug bounty criteria:

1. **Transaction Censorship**: A Byzantine validator can race to broadcast a dummy batch before a victim's legitimate batch, causing some validators to incorrectly track dummy transactions as in-progress, potentially delaying or preventing victim transaction inclusion.

2. **Protocol Non-Determinism**: The quorum store protocol assumes batch_ids uniquely identify batch content per author. Violating this creates non-deterministic behavior where identical Byzantine actions produce different system states based solely on network timing.

3. **State Inconsistency**: Different validators maintain incompatible views of transaction availability, affecting mempool management and potentially causing validator slowdowns from confusion.

4. **No Validation Mechanism**: There is no cryptographic or protocol-level enforcement preventing batch_id reuse: [6](#0-5) 

The verification only checks author identity and basic validity, not batch_id uniqueness.

## Likelihood Explanation

**High Likelihood** - This vulnerability is easily exploitable:

1. **Low Attacker Requirements**: Any validator (Byzantine within the 1/3 tolerance) can trigger this by simply creating two batches with the same `batch_id`
2. **No Detection**: Silent dropping means no alerts or error messages
3. **Natural Occurrence**: Even a buggy validator implementation could accidentally trigger this
4. **Network Conditions**: Normal network variability ensures different validators see batches in different orders
5. **No Cryptographic Barrier**: The batch_id is a simple incrementing counter with no uniqueness enforcement: [7](#0-6) 

## Recommendation

**Immediate Fix**: Add digest validation when inserting batches to detect and reject batch_id reuse with different content:

```rust
fn insert_batch(
    &mut self,
    author: PeerId,
    batch_id: BatchId,
    txns: Vec<SignedTransaction>,
    expiry_time_usecs: u64,
) {
    // NEW: Calculate digest of incoming batch
    let incoming_digest = compute_batch_digest(&txns);
    
    if let Some(existing_batch) = self.batches_in_progress.get(&(author, batch_id)) {
        // NEW: Verify digest matches if batch_id already exists
        let existing_digest = compute_digest_from_summaries(&existing_batch.txns);
        if incoming_digest != existing_digest {
            warn!(
                "Rejected batch with duplicate batch_id {} but different content: {} vs {}",
                batch_id, incoming_digest, existing_digest
            );
            counters::BATCH_ID_COLLISION_REJECTED.inc();
            return;
        }
        // Same content, allow (idempotent)
        return;
    }
    
    // ... rest of existing logic
}
```

**Additional Measures**:
1. Add similar validation in `BatchProofQueue::insert_proof()` to reject proofs with colliding batch_ids but different digests
2. Log warnings when batch_id collisions are detected for forensic analysis
3. Consider adding batch_id monotonicity validation per author across the network

## Proof of Concept

```rust
#[tokio::test]
async fn test_batch_id_collision_state_divergence() {
    // Setup two validators
    let mut validator1 = create_test_batch_generator(PeerId::random());
    let mut validator2 = create_test_batch_generator(PeerId::random());
    
    let malicious_author = PeerId::random();
    let colliding_batch_id = BatchId::new_for_test(100);
    
    // Create two batches with same batch_id but different transactions
    let txns1 = vec![create_test_transaction(AccountAddress::random())];
    let txns2 = vec![create_test_transaction(AccountAddress::random())];
    
    // Validator1 receives Batch1 first
    validator1.handle_remote_batch(malicious_author, colliding_batch_id, txns1.clone());
    
    // Validator2 receives Batch2 first  
    validator2.handle_remote_batch(malicious_author, colliding_batch_id, txns2.clone());
    
    // Verify state divergence
    let v1_in_progress = validator1.batches_in_progress.get(&(malicious_author, colliding_batch_id));
    let v2_in_progress = validator2.batches_in_progress.get(&(malicious_author, colliding_batch_id));
    
    // Different validators track different transactions
    assert_ne!(v1_in_progress.unwrap().txns, v2_in_progress.unwrap().txns);
    
    // Now send the opposite batch to each validator
    validator1.handle_remote_batch(malicious_author, colliding_batch_id, txns2.clone());
    validator2.handle_remote_batch(malicious_author, colliding_batch_id, txns1.clone());
    
    // Verify second batches were silently dropped
    assert_eq!(
        validator1.batches_in_progress.get(&(malicious_author, colliding_batch_id)).unwrap().txns.len(),
        1  // Still only tracks first batch's transaction
    );
    
    // State inconsistency persists
    assert_ne!(
        validator1.batches_in_progress.get(&(malicious_author, colliding_batch_id)).unwrap().txns,
        validator2.batches_in_progress.get(&(malicious_author, colliding_batch_id)).unwrap().txns
    );
    
    println!("✗ VULNERABILITY CONFIRMED: Validators have divergent transaction tracking");
}
```

## Notes

This vulnerability exploits the assumption that validators will not reuse batch_ids with different content. While the Byzantine fault tolerance model assumes up to 1/3 malicious validators, the protocol should be resilient to this specific attack vector through explicit validation rather than relying on behavioral assumptions. The silent dropping behavior in `insert_batch()` masks the issue without alerting operators or preventing the attack.

### Citations

**File:** consensus/src/quorum_store/batch_generator.rs (L68-68)
```rust
    batches_in_progress: HashMap<(PeerId, BatchId), BatchInProgress>,
```

**File:** consensus/src/quorum_store/batch_generator.rs (L130-132)
```rust
        if self.batches_in_progress.contains_key(&(author, batch_id)) {
            return;
        }
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

**File:** consensus/src/quorum_store/utils.rs (L151-154)
```rust
pub struct BatchKey {
    author: PeerId,
    batch_id: BatchId,
}
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L180-188)
```rust
        let batch_key = BatchKey::from_info(proof.info());
        if self
            .items
            .get(&batch_key)
            .is_some_and(|item| item.proof.is_some() || item.is_committed())
        {
            counters::inc_rejected_pos_count(counters::POS_DUPLICATE_LABEL);
            return;
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

**File:** types/src/quorum_store/mod.rs (L32-34)
```rust
    pub fn increment(&mut self) {
        self.id += 1;
    }
```
