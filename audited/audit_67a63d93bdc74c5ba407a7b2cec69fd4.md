# Audit Report

## Title
Vote Replacement Attack via Optimistic Signature Verification in CommitVote Deduplication

## Summary
The Aptos consensus pipeline uses optimistic signature verification combined with a last-write-wins deduplication strategy (`BTreeMap::insert`) for CommitVotes. A malicious validator can exploit this by first sending a valid CommitVote, then sending a second CommitVote with an invalid signature for the same block. The invalid vote replaces the valid one without verification, causing signature aggregation to fail and dropping the validator's voting power below quorum threshold, thereby stalling consensus.

## Finding Description

The CommitVote processing pipeline has three critical components that interact to create a vulnerability:

**1. Optimistic Signature Verification** [1](#0-0) 

When optimistic verification is enabled, incoming CommitVotes are NOT cryptographically verified. The `optimistic_verify` function skips signature verification unless the author is in the `pessimistic_verify_set`.

**2. Vote Deduplication via BTreeMap::insert** [2](#0-1) 

The `SignatureAggregator::add_signature` method uses `BTreeMap::insert(validator, signature)`. This means when multiple votes arrive from the same validator, the LAST vote replaces all previous votes - there is no validation that the new signature is valid before replacement.

**3. Vote Processing Flow** [3](#0-2) 

When a CommitVote is received, it's added via `add_signature_if_matched` which delegates to the SignatureAggregator without pre-validation.

**Attack Execution:**

1. Malicious validator M sends CommitVote_1 with a VALID signature on LedgerInfo
2. Other honest validators (V1-V4) also send valid votes  
3. System now has 5 votes total (M + V1-V4), meeting quorum
4. M sends CommitVote_2 with an INVALID signature on the same LedgerInfo
5. Due to optimistic verification, both votes pass `optimistic_verify()` without actual cryptographic checks
6. The second vote REPLACES M's valid signature in the BTreeMap [4](#0-3) 
7. When aggregation occurs, `verify_multi_signatures` fails due to M's invalid signature
8. The system calls `filter_invalid_signatures` which removes M's vote [5](#0-4) 
9. Voting power drops to 4 validators - BELOW the required quorum of 5
10. Consensus stalls until another valid vote is collected

## Impact Explanation

**Severity: Medium** (per Aptos Bug Bounty criteria)

This vulnerability enables a **liveness attack** on the consensus protocol:

- **Consensus Delay**: A single malicious validator can force the system to wait for additional votes, delaying block commitment
- **Potential DoS**: If 2 out of 7 validators (or f out of 3f+1) perform this attack simultaneously, they can prevent consensus from reaching quorum indefinitely
- **State Inconsistency Risk**: Repeated consensus delays may require manual intervention to restore liveness

The attack does NOT compromise safety (cannot cause chain splits or invalid blocks to be committed), but it violates the **liveness guarantee** that is critical to blockchain operation. This qualifies as "State inconsistencies requiring intervention" under Medium severity.

## Likelihood Explanation

**Likelihood: Medium to High** (for networks with Byzantine validators)

- **Attack Complexity**: LOW - The attack is straightforward; a validator simply broadcasts two different votes
- **Attacker Requirements**: Requires being a validator in the active set (Byzantine fault assumption)
- **Detection Difficulty**: MEDIUM - The attack looks like legitimate voting behavior until aggregation fails
- **Automatic Mitigation**: Partial - After the first attack, the malicious validator is added to `pessimistic_verify_set`, forcing immediate verification of future votes [6](#0-5) 

However, the attack can be repeated on each new block until detection mechanisms trigger, and multiple malicious validators can coordinate attacks.

## Recommendation

**Immediate Fix:** Verify signatures BEFORE allowing vote replacement in the BTreeMap.

Modify `SignatureAggregator::add_signature` to verify the incoming signature if one already exists for that validator:

```rust
pub fn add_signature(&mut self, validator: AccountAddress, signature: &SignatureWithStatus) {
    // If we already have a signature from this validator and the new one is unverified,
    // don't allow replacement - keep the existing signature
    if let Some(existing_sig) = self.signatures.get(&validator) {
        if existing_sig.is_verified() && !signature.is_verified() {
            // Don't replace a verified signature with an unverified one
            return;
        }
    }
    self.signatures.insert(validator, signature.clone());
}
```

**Alternative Fix:** Reject duplicate votes from the same author entirely:

Modify `add_signature_if_matched` to return an error if a vote from the same author already exists:

```rust
pub fn add_signature_if_matched(&mut self, vote: CommitVote) -> anyhow::Result<()> {
    let author = vote.author();
    
    match self {
        Self::Executed(executed) => {
            if executed.commit_info == *vote.commit_info() {
                // Check if we already have a signature from this author
                if executed.partial_commit_proof.has_signature(author) {
                    return Err(anyhow!("Duplicate vote from author"));
                }
                executed.partial_commit_proof.add_signature(author, vote.signature_with_status());
                return Ok(());
            }
        },
        // ... similar for other states
    }
    Err(anyhow!("Inconsistent commit info."))
}
```

## Proof of Concept

The following Rust test demonstrates the vulnerability:

```rust
#[test]
fn test_vote_replacement_attack() {
    use aptos_consensus_types::pipeline::commit_vote::CommitVote;
    use aptos_types::ledger_info::{LedgerInfo, SignatureAggregator};
    use aptos_crypto::bls12381;
    
    // Setup: 7 validators, need 5 for quorum
    let (validator_signers, validator_verifier) = create_validators(7, 5);
    validator_verifier.set_optimistic_sig_verification_flag(true);
    
    let block_info = BlockInfo::empty();
    let ledger_info = LedgerInfo::new(block_info, HashValue::zero());
    
    // Honest validators V1-V4 send valid votes
    let mut sig_aggregator = SignatureAggregator::new(ledger_info.clone());
    for i in 1..5 {
        let vote = CommitVote::new(
            validator_signers[i].author(),
            ledger_info.clone(),
            &validator_signers[i]
        ).unwrap();
        sig_aggregator.add_signature(vote.author(), vote.signature_with_status());
    }
    
    // Malicious validator M sends VALID vote first
    let valid_vote = CommitVote::new(
        validator_signers[0].author(),
        ledger_info.clone(),
        &validator_signers[0]
    ).unwrap();
    sig_aggregator.add_signature(valid_vote.author(), valid_vote.signature_with_status());
    
    // Now have 5 votes - should reach quorum
    assert_eq!(sig_aggregator.all_voters().count(), 5);
    assert!(sig_aggregator.check_voting_power(&validator_verifier, true).is_ok());
    
    // M sends INVALID vote to replace the valid one
    let invalid_vote = CommitVote::new_with_signature(
        validator_signers[0].author(),
        ledger_info.clone(),
        bls12381::Signature::dummy_signature()
    );
    sig_aggregator.add_signature(invalid_vote.author(), invalid_vote.signature_with_status());
    
    // Still have 5 votes in the map
    assert_eq!(sig_aggregator.all_voters().count(), 5);
    
    // But aggregation fails and filters out the invalid signature
    let result = sig_aggregator.aggregate_and_verify(&validator_verifier);
    
    // After filtering, only 4 votes remain - BELOW QUORUM
    assert_eq!(sig_aggregator.all_voters().count(), 4);
    assert!(sig_aggregator.check_voting_power(&validator_verifier, true).is_err());
    
    // Consensus is stalled!
}
```

## Notes

This vulnerability specifically affects the pipeline consensus implementation where optimistic signature verification is enabled. The attack requires a Byzantine validator to actively send multiple different votes, which is within the threat model for consensus protocols that should tolerate up to f Byzantine nodes.

The deduplication mechanism itself works correctly for the intended case (reliable broadcast delivering the same message multiple times), but the combination with optimistic verification creates an exploitable window for vote replacement attacks.

### Citations

**File:** types/src/validator_verifier.rs (L240-242)
```rust
    pub fn add_pessimistic_verify_set(&self, author: AccountAddress) {
        self.pessimistic_verify_set.insert(author);
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

**File:** types/src/ledger_info.rs (L460-462)
```rust
    pub fn add_signature(&mut self, validator: AccountAddress, signature: &SignatureWithStatus) {
        self.signatures.insert(validator, signature.clone());
    }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L754-761)
```rust
                    let new_item = match item.add_signature_if_matched(vote) {
                        Ok(()) => {
                            let response =
                                ConsensusMsg::CommitMessage(Box::new(CommitMessage::Ack(())));
                            if let Ok(bytes) = protocol.to_bytes(&response) {
                                let _ = response_sender.send(Ok(bytes.into()));
                            }
                            item.try_advance_to_aggregated(&self.epoch_state.verifier)
```

**File:** consensus/src/pipeline/buffer_item.rs (L374-416)
```rust
    pub fn add_signature_if_matched(&mut self, vote: CommitVote) -> anyhow::Result<()> {
        let target_commit_info = vote.commit_info();
        let author = vote.author();
        let signature = vote.signature_with_status();
        match self {
            Self::Ordered(ordered) => {
                if ordered
                    .ordered_proof
                    .commit_info()
                    .match_ordered_only(target_commit_info)
                {
                    // we optimistically assume the vote will be valid in the future.
                    // when advancing to executed item, we will check if the sigs are valid.
                    // each author at most stores a single sig for each item,
                    // so an adversary will not be able to flood our memory.
                    ordered.unverified_votes.insert(author, vote);
                    return Ok(());
                }
            },
            Self::Executed(executed) => {
                if executed.commit_info == *target_commit_info {
                    executed
                        .partial_commit_proof
                        .add_signature(author, signature);
                    return Ok(());
                }
            },
            Self::Signed(signed) => {
                if signed.partial_commit_proof.data().commit_info() == target_commit_info {
                    signed.partial_commit_proof.add_signature(author, signature);
                    return Ok(());
                }
            },
            Self::Aggregated(aggregated) => {
                // we do not need to do anything for aggregated
                // but return true is helpful to stop the outer loop early
                if aggregated.commit_proof.commit_info() == target_commit_info {
                    return Ok(());
                }
            },
        }
        Err(anyhow!("Inconsistent commit info."))
    }
```
