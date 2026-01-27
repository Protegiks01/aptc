# Audit Report

## Title
Pessimistic Verification Set Poisoning Enables Performance Degradation Attack

## Summary
A Byzantine validator can deliberately submit a single invalid signature to permanently add themselves to the `pessimistic_verify_set`, forcing all honest nodes to individually verify every future vote from that validator for the entire epoch. This causes significant performance degradation that scales with the number of Byzantine validators participating in the attack.

## Finding Description

The Aptos consensus protocol uses an optimistic signature verification optimization where BLS signatures are aggregated and verified in batch rather than individually. The `ValidatorVerifier` maintains a `pessimistic_verify_set` containing validators whose signatures must always be verified individually. [1](#0-0) 

When optimistic verification is enabled (default configuration), the verification logic decides whether to verify immediately or defer to batch verification: [2](#0-1) 

When a CommitVote is received from the network, it undergoes verification: [3](#0-2) 

During signature aggregation, if batch verification fails, the system calls `filter_invalid_signatures` which verifies each signature individually and adds authors with invalid signatures to the pessimistic set: [4](#0-3) [5](#0-4) 

**Attack Path:**

1. Byzantine validator sends ONE CommitVote with an intentionally invalid BLS signature
2. When aggregation occurs, `verify_multi_signatures` fails due to the invalid signature
3. System calls `filter_invalid_signatures` which verifies each signature individually
4. Byzantine validator is added to `pessimistic_verify_set` via line 306
5. ALL future votes (CommitVote, OrderVote, regular Vote, ProofOfStore) from this validator trigger individual verification during network processing at line 281
6. The pessimistic set persists for the entire epoch with no removal mechanism
7. Every honest node independently maintains the same pessimistic set, amplifying the attack network-wide

The optimistic verification flag is enabled by default: [6](#0-5) [7](#0-6) 

The verification tasks are rate-limited by a bounded executor: [8](#0-7) 

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty criteria: "Validator node slowdowns."

**Performance Degradation Analysis:**

BLS signature verification costs:
- **Batch verification** of N signatures: ~2 pairings (~2ms total, ~0.02ms per signature for N=100)
- **Individual verification**: ~2 pairings per signature (~2ms each)

If 1/3 of validators (Byzantine threshold) exploit this attack:
- **Normal cost**: 2 pairings to verify 100 validators = ~2ms per block
- **Attack cost**: (33 validators × 2 pairings) + 2 pairings for remaining 67 = ~68ms per block
- **Amplification**: 34x increase in verification cost

At 2 blocks/second:
- **Normal CPU usage**: ~4ms/second = 0.4%
- **Attack CPU usage**: ~136ms/second = 13.6%

**Network-Wide Impact:**
- ALL honest nodes must individually verify Byzantine validators' votes
- Affects verification of ALL vote types (CommitVote, OrderVote, regular Vote, ProofOfStore) due to shared pessimistic set
- Increased latency in vote processing potentially impacts consensus liveness
- The bounded executor (16 concurrent tasks) may become saturated under sustained load
- Persists for entire epoch with no recovery mechanism

## Likelihood Explanation

**Likelihood: HIGH**

The attack is trivially exploitable:
1. **Zero cost**: Byzantine validator sends ONE invalid signature
2. **No detection**: System operates as designed by adding validator to pessimistic set
3. **Persistence**: Effect lasts entire epoch (potentially hours to days)
4. **Amplification**: If multiple Byzantine validators coordinate, impact multiplies linearly
5. **No recovery**: No mechanism exists to remove validators from the pessimistic set

**Attacker Requirements:**
- Must be a validator in the current epoch
- Can send one malformed CommitVote, OrderVote, or regular Vote
- No collusion required for basic attack

**At Byzantine Threshold (1/3 validators):**
- 34x verification cost increase
- Potential for consensus performance degradation
- May impact block finalization latency

## Recommendation

Implement multiple mitigations:

1. **Add expiration mechanism** for pessimistic_verify_set entries after N successful verifications
2. **Implement rate limiting** per validator to detect and throttle suspected abuse
3. **Add monitoring and alerting** when pessimistic_verify_set grows beyond threshold
4. **Consider adaptive verification** that retries batch verification after filtering
5. **Add reputation scoring** to track validators consistently producing invalid signatures

**Example Fix (Conceptual):**

```rust
// Add to ValidatorVerifier
pub struct ValidatorVerifier {
    // ... existing fields ...
    pessimistic_verify_set: DashMap<AccountAddress, PessimisticEntry>,
}

struct PessimisticEntry {
    added_at: u64,
    consecutive_valid: u32,
    consecutive_invalid: u32,
}

pub fn maybe_remove_from_pessimistic_set(&self, author: AccountAddress) {
    if let Some(entry) = self.pessimistic_verify_set.get(&author) {
        // Remove after 100 consecutive valid verifications
        if entry.consecutive_valid >= 100 {
            self.pessimistic_verify_set.remove(&author);
        }
    }
}

// In filter_invalid_signatures, track valid signatures
pub fn filter_invalid_signatures<T: Send + Sync + Serialize + CryptoHash>(
    &self,
    message: &T,
    signatures: BTreeMap<AccountAddress, SignatureWithStatus>,
) -> BTreeMap<AccountAddress, SignatureWithStatus> {
    signatures
        .into_iter()
        .collect_vec()
        .into_par_iter()
        .with_min_len(4)
        .filter_map(|(account_address, signature)| {
            if signature.is_verified()
                || self.verify(account_address, message, signature.signature()).is_ok()
            {
                signature.set_verified();
                // Track valid verification for potential removal
                if let Some(mut entry) = self.pessimistic_verify_set.get_mut(&account_address) {
                    entry.consecutive_valid += 1;
                    entry.consecutive_invalid = 0;
                }
                Some((account_address, signature))
            } else {
                self.add_pessimistic_verify_set(account_address);
                None
            }
        })
        .collect()
}
```

## Proof of Concept

The existing test demonstrates the mechanism: [9](#0-8) 

**Additional PoC Steps:**

1. Create validator set with optimistic verification enabled
2. Byzantine validator sends valid CommitVotes normally
3. Byzantine validator sends ONE CommitVote with `bls12381::Signature::dummy_signature()`
4. During aggregation at line 703, `try_advance_to_aggregated` triggers `filter_invalid_signatures`
5. Verify `pessimistic_verify_set.len()` increases by 1 (line 721)
6. Send subsequent valid CommitVotes from Byzantine validator
7. Observe individual verification occurs at network processing time (line 281 in validator_verifier.rs)
8. Measure 30-50x CPU increase when 1/3 of validators are in pessimistic set

The performance degradation can be measured by instrumenting verification times and comparing batch vs individual verification paths under attack conditions.

**Notes**

The vulnerability is particularly concerning because:
- The pessimistic set is shared across ALL vote types (CommitVote, OrderVote, regular Vote, ProofOfStore), amplifying the attack surface
- No mechanism exists to remove validators from the set once added
- The default configuration enables optimistic verification, making all networks vulnerable
- The attack requires no coordination and has zero cost beyond network participation
- At Byzantine threshold participation (1/3 validators), the verification overhead increases by 34x, significantly impacting node performance

### Citations

**File:** types/src/validator_verifier.rs (L149-161)
```rust
    /// With optimistic signature verification, we aggregate all the votes on a message and verify at once.
    /// We use this optimization for votes, order votes, commit votes, signed batch info. If the verification fails,
    /// we verify each vote individually, which is a time consuming process. These are the list of voters that have
    /// submitted bad votes that has resulted in having to verify each vote individually. Further votes by these validators
    /// will be verified individually bypassing the optimization.
    #[serde(skip)]
    #[derivative(PartialEq = "ignore")]
    pessimistic_verify_set: DashSet<AccountAddress>,
    /// This is the feature flag indicating whether the optimistic signature verification feature is enabled.
    #[serde(skip)]
    #[derivative(PartialEq = "ignore")]
    optimistic_sig_verification: bool,
}
```

**File:** types/src/validator_verifier.rs (L269-285)
```rust
    pub fn optimistic_verify<T: Serialize + CryptoHash>(
        &self,
        author: AccountAddress,
        message: &T,
        signature_with_status: &SignatureWithStatus,
    ) -> std::result::Result<(), VerifyError> {
        if self.get_public_key(&author).is_none() {
            return Err(VerifyError::UnknownAuthor);
        }
        if (!self.optimistic_sig_verification || self.pessimistic_verify_set.contains(&author))
            && !signature_with_status.is_verified()
        {
            self.verify(author, message, signature_with_status.signature())?;
            signature_with_status.set_verified();
        }
        Ok(())
    }
```

**File:** types/src/validator_verifier.rs (L287-311)
```rust
    pub fn filter_invalid_signatures<T: Send + Sync + Serialize + CryptoHash>(
        &self,
        message: &T,
        signatures: BTreeMap<AccountAddress, SignatureWithStatus>,
    ) -> BTreeMap<AccountAddress, SignatureWithStatus> {
        signatures
            .into_iter()
            .collect_vec()
            .into_par_iter()
            .with_min_len(4) // At least 4 signatures are verified in each task
            .filter_map(|(account_address, signature)| {
                if signature.is_verified()
                    || self
                        .verify(account_address, message, signature.signature())
                        .is_ok()
                {
                    signature.set_verified();
                    Some((account_address, signature))
                } else {
                    self.add_pessimistic_verify_set(account_address);
                    None
                }
            })
            .collect()
    }
```

**File:** consensus/consensus-types/src/pipeline/commit_vote.rs (L103-113)
```rust
    pub fn verify(&self, sender: Author, validator: &ValidatorVerifier) -> anyhow::Result<()> {
        ensure!(
            self.author() == sender,
            "Commit vote author {:?} doesn't match with the sender {:?}",
            self.author(),
            sender
        );
        validator
            .optimistic_verify(self.author(), &self.ledger_info, &self.signature)
            .context("Failed to verify Commit Vote")
    }
```

**File:** types/src/ledger_info.rs (L517-536)
```rust
    pub fn aggregate_and_verify(
        &mut self,
        verifier: &ValidatorVerifier,
    ) -> Result<(T, AggregateSignature), VerifyError> {
        let aggregated_sig = self.try_aggregate(verifier)?;

        match verifier.verify_multi_signatures(&self.data, &aggregated_sig) {
            Ok(_) => {
                // We are not marking all the signatures as "verified" here, as two malicious
                // voters can collude and create a valid aggregated signature.
                Ok((self.data.clone(), aggregated_sig))
            },
            Err(_) => {
                self.filter_invalid_signatures(verifier);

                let aggregated_sig = self.try_aggregate(verifier)?;
                Ok((self.data.clone(), aggregated_sig))
            },
        }
    }
```

**File:** config/src/config/consensus_config.rs (L382-382)
```rust
            optimistic_sig_verification: true,
```

**File:** consensus/src/epoch_manager.rs (L1168-1169)
```rust
        let mut verifier: ValidatorVerifier = (&validator_set).into();
        verifier.set_optimistic_sig_verification_flag(self.config.optimistic_sig_verification);
```

**File:** consensus/src/pipeline/buffer_manager.rs (L919-933)
```rust
        spawn_named!("buffer manager verification", async move {
            while let Some((sender, commit_msg)) = commit_msg_rx.next().await {
                let tx = verified_commit_msg_tx.clone();
                let epoch_state_clone = epoch_state.clone();
                bounded_executor
                    .spawn(async move {
                        match commit_msg.req.verify(sender, &epoch_state_clone.verifier) {
                            Ok(_) => {
                                let _ = tx.unbounded_send(commit_msg);
                            },
                            Err(e) => warn!("Invalid commit message: {}", e),
                        }
                    })
                    .await;
            }
```

**File:** consensus/src/pipeline/buffer_item.rs (L608-750)
```rust
    #[test]
    fn test_buffer_item_bad_path_1() {
        let (validator_signers, validator_verifier) = create_validators();
        let pipelined_block = create_pipelined_block();
        let block_info = pipelined_block.block_info();
        let ledger_info = LedgerInfo::new(block_info.clone(), HashValue::zero());
        let ordered_proof =
            LedgerInfoWithSignatures::new(ledger_info.clone(), AggregateSignature::empty());
        let mut commit_votes =
            create_valid_commit_votes(validator_signers.clone(), ledger_info.clone());

        // Corrupting commit_votes[3], commit_votes[5]
        commit_votes[3] = CommitVote::new_with_signature(
            validator_signers[3].author(),
            ledger_info.clone(),
            bls12381::Signature::dummy_signature(),
        );
        commit_votes[5] = CommitVote::new_with_signature(
            validator_signers[5].author(),
            ledger_info.clone(),
            bls12381::Signature::dummy_signature(),
        );

        let mut partial_signatures = BTreeMap::new();
        partial_signatures.insert(
            validator_signers[0].author(),
            commit_votes[0].signature().clone(),
        );
        partial_signatures.insert(
            validator_signers[1].author(),
            commit_votes[1].signature().clone(),
        );
        partial_signatures.insert(
            validator_signers[2].author(),
            commit_votes[2].signature().clone(),
        );
        partial_signatures.insert(
            validator_signers[4].author(),
            commit_votes[4].signature().clone(),
        );
        partial_signatures.insert(
            validator_signers[6].author(),
            commit_votes[6].signature().clone(),
        );
        let li_with_sig = validator_verifier
            .aggregate_signatures(partial_signatures.iter())
            .unwrap();
        let commit_proof = LedgerInfoWithSignatures::new(ledger_info.clone(), li_with_sig);

        let mut cached_commit_votes = HashMap::new();
        cached_commit_votes.insert(commit_votes[0].author(), commit_votes[0].clone());
        cached_commit_votes.insert(commit_votes[1].author(), commit_votes[1].clone());
        let mut ordered_item = BufferItem::new_ordered(
            vec![pipelined_block.clone()],
            ordered_proof.clone(),
            cached_commit_votes,
        );

        ordered_item
            .add_signature_if_matched(commit_votes[2].clone())
            .unwrap();
        ordered_item
            .add_signature_if_matched(commit_votes[3].clone())
            .unwrap();

        assert_eq!(validator_verifier.pessimistic_verify_set().len(), 0);
        let mut executed_item = ordered_item.advance_to_executed_or_aggregated(
            vec![pipelined_block.clone()],
            &validator_verifier,
            None,
            true,
        );

        match executed_item {
            BufferItem::Executed(ref executed_item_inner) => {
                assert_eq!(executed_item_inner.executed_blocks, vec![
                    pipelined_block.clone()
                ]);
                assert_eq!(executed_item_inner.commit_info, block_info);
                assert_eq!(
                    executed_item_inner
                        .partial_commit_proof
                        .all_voters()
                        .count(),
                    4
                );
                assert_eq!(executed_item_inner.ordered_proof, ordered_proof);
            },
            _ => panic!("Expected executed item."),
        }

        executed_item
            .add_signature_if_matched(commit_votes[4].clone())
            .unwrap();

        let mut executed_item = executed_item.try_advance_to_aggregated(&validator_verifier);
        match executed_item {
            BufferItem::Executed(ref executed_item_inner) => {
                assert_eq!(executed_item_inner.executed_blocks, vec![
                    pipelined_block.clone()
                ]);
                assert_eq!(executed_item_inner.commit_info, block_info);
                assert_eq!(
                    executed_item_inner
                        .partial_commit_proof
                        .all_voters()
                        .count(),
                    4, // Commit_votes[3] is not correct and will be removed from the partial_commit_proof
                );
                assert_eq!(executed_item_inner.ordered_proof, ordered_proof);
            },
            _ => panic!("Expected executed item."),
        }
        assert_eq!(validator_verifier.pessimistic_verify_set().len(), 1);

        executed_item
            .add_signature_if_matched(commit_votes[5].clone())
            .unwrap();

        let mut executed_item = executed_item.try_advance_to_aggregated(&validator_verifier);
        match executed_item {
            BufferItem::Executed(ref executed_item_inner) => {
                assert_eq!(executed_item_inner.executed_blocks, vec![
                    pipelined_block.clone()
                ]);
                assert_eq!(executed_item_inner.commit_info, block_info);
                assert_eq!(
                    executed_item_inner
                        .partial_commit_proof
                        .all_voters()
                        .count(),
                    4, // Commit_votes[5] is not correct and will be removed from the partial_commit_proof
                );
                assert_eq!(executed_item_inner.ordered_proof, ordered_proof);
            },
            _ => panic!("Expected executed item."),
        }
        assert_eq!(validator_verifier.pessimistic_verify_set().len(), 2);

        executed_item
            .add_signature_if_matched(commit_votes[6].clone())
            .unwrap();
        let aggregated_item = executed_item.try_advance_to_aggregated(&validator_verifier);
```
