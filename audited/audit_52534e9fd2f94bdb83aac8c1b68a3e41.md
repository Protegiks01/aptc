# Audit Report

## Title
CommitVote Signature Overwriting Enables Byzantine Liveness Attack via Message Reordering

## Summary
When CommitVotes are broadcast via reliable broadcast, a Byzantine validator can exploit the combination of optimistic signature verification and signature overwriting in `SignatureAggregator` to cause consensus liveness failures. By sending multiple CommitVotes with different signatures for the same block, message reordering can cause valid signatures to be overwritten by invalid ones, preventing quorum from being reached.

## Finding Description

The vulnerability exists in the interaction between three components:

1. **Optimistic Signature Verification**: When `optimistic_sig_verification` is enabled (production default), incoming CommitVotes are not immediately verified. The `optimistic_verify()` method only checks if the author is a known validator. [1](#0-0) 

2. **Signature Overwriting in SignatureAggregator**: The `SignatureAggregator` stores signatures in a `BTreeMap<AccountAddress, SignatureWithStatus>`. The `add_signature()` method uses `insert()`, which overwrites any existing signature from the same validator. [2](#0-1) 

3. **No Duplicate Vote Detection**: When processing incoming CommitVotes, there is no mechanism to prevent multiple votes from the same validator for the same block from being processed. [3](#0-2) 

**Attack Flow:**

1. A Byzantine validator creates two CommitVotes for the same block:
   - **Vote A**: Valid CommitVote with correctly computed signature
   - **Vote B**: Invalid CommitVote with dummy/incorrect signature

2. The Byzantine validator sends both votes to all other validators through the network (either via separate sends or by manipulating the reliable broadcast mechanism)

3. Due to asynchronous message delivery and network reordering:
   - Vote A arrives first and is added to the `SignatureAggregator`
   - Both votes pass `optimistic_verify()` because it only checks if the author is known [4](#0-3) 
   - Vote B arrives second and overwrites Vote A in the BTreeMap

4. When signature aggregation is attempted:
   - The `aggregate_and_verify()` method tries to aggregate all signatures
   - The invalid signature from Vote B causes verification to fail
   - `filter_invalid_signatures()` removes the invalid signature
   - The Byzantine validator's vote is completely lost [5](#0-4) 

5. If the network is at the quorum threshold (e.g., exactly 5 out of 7 validators needed), losing one valid vote prevents quorum from being reached, causing **consensus liveness failure**.

The vulnerability violates the BFT safety guarantee that states: "AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine". A single Byzantine validator should not be able to halt consensus progress.

## Impact Explanation

**High Severity** - This vulnerability enables a single Byzantine validator to cause consensus liveness failures, preventing blocks from being committed network-wide. 

According to Aptos bug bounty criteria:
- **Critical**: "Total loss of liveness/network availability" - While this could cause liveness failure, it requires specific conditions (network at quorum threshold)
- **High**: "Significant protocol violations" - This clearly qualifies as the Byzantine validator can violate BFT liveness guarantees

The impact is severe because:
- A single Byzantine validator (well within the <1/3 Byzantine tolerance threshold) can halt the network
- The attack can be repeated for every block, causing sustained liveness failure
- All validator nodes are affected network-wide
- Requires manual intervention or validator set changes to recover

## Likelihood Explanation

**Medium to High Likelihood**:

**Prerequisites:**
- One Byzantine validator in the validator set (assumed tolerable by BFT)
- Network operating at or near quorum threshold
- Optimistic signature verification enabled (production default)

**Ease of Exploitation:**
- Attack is straightforward - create two votes with different signatures
- No complex timing or coordination required
- Can be executed repeatedly
- Byzantine validator has full control over when to trigger the attack

The attack becomes more likely when:
- Validator set size is small (more likely to be at threshold)
- Network has validators with intermittent connectivity
- Byzantine validator waits for moments when the network is at exactly quorum threshold

## Recommendation

Implement one or more of the following mitigations:

**Option 1: Add Duplicate Vote Detection**
```rust
// In BufferItem::add_signature_if_matched()
pub fn add_signature_if_matched(&mut self, vote: CommitVote) -> anyhow::Result<()> {
    let target_commit_info = vote.commit_info();
    let author = vote.author();
    let signature = vote.signature_with_status();
    
    match self {
        Self::Executed(executed) => {
            if executed.commit_info == *target_commit_info {
                // Check if signature already exists for this author
                if executed.partial_commit_proof.has_signature(author) {
                    // Verify the new signature matches the existing one
                    let existing_sig = executed.partial_commit_proof.get_signature(author)?;
                    ensure!(
                        existing_sig.signature() == signature.signature(),
                        "Duplicate vote from {} with different signature",
                        author
                    );
                    return Ok(()); // Ignore duplicate with same signature
                }
                executed.partial_commit_proof.add_signature(author, signature);
                return Ok(());
            }
        },
        // Similar checks for other states...
    }
    Err(anyhow!("Inconsistent commit info."))
}
```

**Option 2: Eagerly Verify Signatures Before Adding**
Modify the verification flow to always verify signatures before adding them to the aggregator, even with optimistic verification enabled. This prevents invalid signatures from being added in the first place.

**Option 3: Add Sequence Numbers to CommitVotes**
Include a monotonically increasing sequence number in CommitVotes to detect and reject replays or multiple votes from the same validator.

## Proof of Concept

```rust
// Proof of Concept - Byzantine validator sending conflicting votes
// This would be implemented as a modification to buffer_manager.rs

#[cfg(test)]
mod byzantine_vote_attack {
    use super::*;
    
    #[tokio::test]
    async fn test_signature_overwriting_liveness_attack() {
        // Setup: 7 validators, quorum = 5
        let (validator_signers, validator_verifier) = create_test_validators(7, 5);
        let byzantine_validator = &validator_signers[4];
        
        // Create a test block
        let block = create_test_block();
        let ledger_info = create_test_ledger_info(&block);
        
        // Byzantine validator creates TWO votes
        let valid_vote = CommitVote::new(
            byzantine_validator.author(),
            ledger_info.clone(),
            byzantine_validator
        ).unwrap();
        
        let invalid_vote = CommitVote::new_with_signature(
            byzantine_validator.author(),
            ledger_info.clone(),
            bls12381::Signature::dummy_signature()
        );
        
        // Simulate votes from honest validators (4 validators)
        let mut buffer_item = create_buffer_item_with_votes(
            &validator_signers[0..4],
            &ledger_info
        );
        
        // Add Byzantine validator's valid vote first
        buffer_item.add_signature_if_matched(valid_vote.clone()).unwrap();
        
        // Verify we have 5 signatures (quorum)
        assert_eq!(count_signatures(&buffer_item), 5);
        
        // Byzantine validator's invalid vote arrives later and OVERWRITES
        buffer_item.add_signature_if_matched(invalid_vote).unwrap();
        
        // Try to aggregate - should fail!
        let result = buffer_item.try_advance_to_aggregated(&validator_verifier);
        
        // After filtering invalid signatures, only 4 valid votes remain
        // Quorum NOT reached - liveness failure!
        assert!(!result.is_aggregated());
        assert_eq!(count_valid_signatures(&result), 4); // Lost Byzantine vote
    }
}
```

**Notes**

This vulnerability specifically exploits the interaction between reliable broadcast message reordering and optimistic signature verification. While the attack requires a Byzantine validator, this is within the threat model that BFT consensus protocols are designed to tolerate (< 1/3 Byzantine). The fact that a single Byzantine validator can cause network-wide liveness failure violates the fundamental BFT liveness guarantee and constitutes a significant protocol violation.

The fix should prioritize duplicate vote detection to prevent signature overwriting, as this is the root cause enabling the attack. Additionally, consider whether optimistic verification provides sufficient security benefits to justify the attack surface it introduces.

### Citations

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

**File:** types/src/ledger_info.rs (L460-462)
```rust
    pub fn add_signature(&mut self, validator: AccountAddress, signature: &SignatureWithStatus) {
        self.signatures.insert(validator, signature.clone());
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

**File:** consensus/src/pipeline/buffer_manager.rs (L925-929)
```rust
                        match commit_msg.req.verify(sender, &epoch_state_clone.verifier) {
                            Ok(_) => {
                                let _ = tx.unbounded_send(commit_msg);
                            },
                            Err(e) => warn!("Invalid commit message: {}", e),
```
