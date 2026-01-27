# Audit Report

## Title
Batch Author Field Authentication Bypass in Inline Batches Allows Quota Manipulation and Validator Impersonation

## Summary
The `batch.author()` field lacks cryptographic authentication for inline batches included in block proposals. While regular batches are verified through `BatchMsg::verify()`, inline batches only verify payload digests without authenticating the author field. This allows malicious proposers to forge batch authors, bypassing quota limits and misattributing resource consumption to other validators.

## Finding Description

The Aptos quorum store implements two verification paths for batches:

**Path 1 - Regular Batches (Authenticated):**
When batches are broadcast through `BatchMsg`, they undergo verification that ensures the claimed author matches the network sender: [1](#0-0) 

This check ensures `batch.author() == peer_id`, where `peer_id` is the cryptographically authenticated network sender.

**Path 2 - Self-Messages (Authentication Bypassed):**
However, when validators send messages to themselves (self-messages), this verification is explicitly skipped: [2](#0-1) 

The `self_message` flag is set when `peer_id == my_peer_id`: [3](#0-2) 

**Path 3 - Inline Batches (No Author Authentication):**
When inline batches are included in block proposals, they are verified only by checking that the payload digest matches: [4](#0-3) 

This verification computes the digest using `batch.author()` but never validates that this author field is authentic or matches the actual creator.

**Attack Scenario:**
1. Malicious Validator A creates a batch claiming `author = Validator B` (forged)
2. Broadcasts the batch - self-message path skips verification, batch is persisted locally with forged author
3. Other validators reject the batch (verification fails: author B ≠ sender A)  
4. Validator A becomes block proposer
5. Includes the forged batch as an inline batch in their proposal
6. Other validators verify via `verify_inline_batches()` - only checks digest, accepts forged author
7. The batch is attributed to Validator B, consuming B's quota instead of A's

**Quota Enforcement:**
Quotas are enforced per `batch.author()`: [5](#0-4) 

This means forged authors directly bypass the attacker's quota limits and consume the victim's quota.

## Impact Explanation

This vulnerability enables:

1. **Quota Bypass**: Malicious validators can exceed their batch/memory/storage quotas by attributing batches to other validators
2. **Resource Exhaustion DoS**: Attackers can exhaust victims' quotas, preventing them from creating legitimate batches
3. **Attribution Manipulation**: Batches appear to originate from validators who never created them, breaking accountability
4. **Validator node slowdowns** due to quota exhaustion and resource contention

Per the Aptos bug bounty criteria, this represents **High Severity** as it causes "Validator node slowdowns" and "Significant protocol violations" by breaking the invariant that batch authorship must be cryptographically authenticated.

## Likelihood Explanation

**Likelihood: High**

Requirements for exploitation:
- Attacker must be a validator (standard Byzantine threat model)
- Attacker must be selected as block proposer (happens regularly in round-robin)
- Inline batches must be enabled (`allow_batches_without_pos_in_proposal` configuration) [6](#0-5) 

The attack is straightforward to execute and requires no coordination with other validators. Under normal operation with rotating proposers, any Byzantine validator will eventually have opportunities to exploit this vulnerability.

## Recommendation

Add author authentication for inline batches by verifying that the batch author is a valid validator who could have created the batch. Two options:

**Option 1**: Require inline batches to also go through `BatchMsg::verify()` before inclusion:

```rust
pub fn verify_inline_batches<'a, T: TBatchInfo + 'a>(
    inline_batches: impl Iterator<Item = (&'a T, &'a Vec<SignedTransaction>)>,
    proposer: PeerId, // Add proposer parameter
) -> anyhow::Result<()> {
    for (batch, payload) in inline_batches {
        // Add authentication check
        ensure!(
            batch.author() == proposer,
            "Inline batch author {} doesn't match proposer {}",
            batch.author(),
            proposer
        );
        
        let computed_digest = BatchPayload::new(batch.author(), payload.clone()).hash();
        ensure!(
            computed_digest == *batch.digest(),
            "Hash mismatch for batch"
        );
    }
    Ok(())
}
```

**Option 2**: Disable inline batches entirely if they cannot be properly authenticated, or require them to have `ProofOfStore` signatures which inherently authenticate the author through quorum voting.

## Proof of Concept

```rust
// Conceptual PoC - demonstrates the authentication gap
// This would need to be integrated into consensus tests

#[test]
fn test_forged_inline_batch_author() {
    // Setup: validator A wants to forge a batch claiming to be from validator B
    let validator_a = create_test_validator("A");
    let validator_b = create_test_validator("B");
    
    // Step 1: Create batch with forged author
    let transactions = vec![create_test_transaction()];
    let forged_batch = Batch::new(
        BatchId::new_random(),
        transactions.clone(),
        epoch,
        expiration,
        validator_b.address(), // FORGED: claiming to be from B
        gas_bucket_start,
    );
    
    // Step 2: Process as self-message on validator A's node
    // Verification is skipped for self-messages
    let batch_msg = BatchMsg::new(vec![forged_batch.clone()]);
    // When peer_id == my_peer_id, verify is skipped
    
    // Step 3: Include in proposal as inline batch
    let inline_batches = vec![(forged_batch.batch_info().clone(), transactions)];
    
    // Step 4: Verify inline batch (only checks digest, not author)
    let result = Payload::verify_inline_batches(inline_batches.iter().map(|(info, txns)| (info, txns)));
    
    // BUG: Verification passes even though author is forged!
    assert!(result.is_ok());
    
    // The batch is now attributed to validator B
    // B's quota is consumed instead of A's quota
}
```

**Notes**

The authentication gap exists because inline batches follow a different verification path than regular batches. While `BatchMsg::verify()` ensures `batch.author() == peer_id`, inline batches in proposals only verify payload integrity through digest matching, not author authenticity. This breaks the cryptographic authentication invariant for batch authorship and enables quota manipulation attacks by Byzantine validators.

### Citations

**File:** consensus/src/quorum_store/types.rs (L454-457)
```rust
            ensure!(
                batch.author() == peer_id,
                "Batch author doesn't match sender"
            );
```

**File:** consensus/src/round_manager.rs (L166-173)
```rust
            UnverifiedEvent::BatchMsg(b) => {
                if !self_message {
                    b.verify(peer_id, max_num_batches, validator)?;
                    counters::VERIFY_MSG
                        .with_label_values(&["batch"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::BatchMsg(Box::new((*b).into()))
```

**File:** consensus/src/epoch_manager.rs (L1596-1596)
```rust
                            peer_id == my_peer_id,
```

**File:** consensus/consensus-types/src/common.rs (L541-556)
```rust
    pub fn verify_inline_batches<'a, T: TBatchInfo + 'a>(
        inline_batches: impl Iterator<Item = (&'a T, &'a Vec<SignedTransaction>)>,
    ) -> anyhow::Result<()> {
        for (batch, payload) in inline_batches {
            // TODO: Can cloning be avoided here?
            let computed_digest = BatchPayload::new(batch.author(), payload.clone()).hash();
            ensure!(
                computed_digest == *batch.digest(),
                "Hash of the received inline batch doesn't match the digest value for batch {:?}: {} != {}",
                batch,
                computed_digest,
                batch.digest()
            );
        }
        Ok(())
    }
```

**File:** consensus/src/quorum_store/batch_store.rs (L383-391)
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
```

**File:** consensus/src/quorum_store/proof_manager.rs (L156-156)
```rust
            if self.allow_batches_without_pos_in_proposal && proof_queue_fully_utilized {
```
