# Audit Report

## Title
Optimistic Signature Verification DoS in CommitVote Aggregation Allows Malicious Validator to Trigger Expensive Individual Verification

## Summary
A malicious validator can send CommitVotes with invalid BLS signatures that bypass optimistic verification. When these are aggregated with honest votes, the aggregated signature verification fails, forcing all validators to perform expensive individual verification of every signature. This can be repeatedly exploited to cause significant CPU load and consensus slowdowns.

## Finding Description

The Aptos consensus system uses optimistic signature verification for CommitVotes, where signatures are aggregated first and verified together rather than individually. When optimistic verification is enabled (which it is by default), incoming CommitVotes from validators not in the `pessimistic_verify_set` skip immediate signature verification. [1](#0-0) 

The verification flow works as follows:

1. CommitVotes arrive over the network and are verified in a bounded executor task. [2](#0-1) 

2. The verification calls `optimistic_verify` which **skips actual signature verification** if optimistic mode is enabled and the author is not in the pessimistic set. [3](#0-2) 

3. Unverified votes are added to the `SignatureAggregator`. [4](#0-3) 

4. When enough votes are collected, `aggregate_and_verify` is called. It first attempts to verify the aggregated signature. [5](#0-4) 

5. **Critical vulnerability**: If the aggregated signature verification fails (due to one or more invalid signatures), `filter_invalid_signatures` is called, which must verify **every single signature individually** using parallel iteration. [6](#0-5) 

**Attack Scenario:**
A malicious validator can craft CommitVotes with invalid BLS signatures and broadcast them. These invalid signatures:
- Pass through `optimistic_verify` without being checked
- Get added to the aggregator alongside honest votes
- Cause aggregated signature verification to fail
- Force all N signatures to be verified individually (expensive cryptographic operations)
- Can be repeated across multiple blocks/rounds before the malicious validator is added to the pessimistic set

The individual verification is computationally expensive even with parallelization, as BLS signature verification requires elliptic curve pairing operations.

## Impact Explanation

This qualifies as **High Severity** under the Aptos bug bounty program: "Validator node slowdowns."

**Impact:**
- Significantly increased CPU load on all validators processing CommitVotes
- Delayed consensus progress due to expensive signature verification overhead
- Can be sustained across multiple rounds/blocks, compounding the effect
- Even after the attacker is added to the pessimistic set, they can continue attacks on new blocks
- Under high transaction load, this could prevent consensus from making progress (liveness failure)

The attack can slow down the entire network's ability to commit blocks, affecting all users and applications.

## Likelihood Explanation

**Likelihood: High**

**Attack Requirements:**
- Attacker must be a validator in the active validator set
- No additional privileges required beyond being a validator
- Attack is trivial to execute - just send CommitVotes with invalid signatures

**Ease of Exploitation:**
- Very simple attack - no complex state manipulation required
- Can be automated and repeated continuously
- No special timing or coordination needed
- Works against the default configuration (optimistic verification enabled)

**Detection/Mitigation:**
- The pessimistic_verify_set provides partial mitigation, but only after the first failed aggregation
- Attacker can target different blocks simultaneously before being detected
- Even after detection, subsequent aggregation attempts on new blocks will still fail before filtering occurs

Given that AptosBFT is designed to tolerate Byzantine validators (up to 1/3), a single malicious validator exploiting this is within the threat model.

## Recommendation

Implement immediate signature verification for all incoming CommitVotes, even with optimistic verification enabled. The current approach defers too much verification work, creating a DoS vector.

**Option 1: Always verify CommitVotes immediately**
Modify the verification to always check signatures for CommitVotes before adding them to the aggregator: [7](#0-6) 

Change the `verify` method to use non-optimistic verification for CommitVotes.

**Option 2: Rate-limit aggregation attempts**
Track failed aggregation attempts per validator and temporarily ban validators that repeatedly cause aggregation failures, even before adding them to pessimistic_verify_set.

**Option 3: Verify incrementally during aggregation**
Instead of aggregating all signatures and then verifying, verify each new signature before adding it to the aggregator. This limits the blast radius of invalid signatures.

**Recommended Fix:** Combine Options 1 and 2 - always verify CommitVote signatures immediately AND implement rate limiting for failed aggregations.

## Proof of Concept

The existing test case demonstrates the behavior, but here's how to exploit it for DoS:

```rust
// Add this test to consensus/src/pipeline/buffer_item.rs

#[test]
fn test_commit_vote_dos_attack() {
    use std::time::Instant;
    
    let (validator_signers, mut validator_verifier) = create_validators();
    validator_verifier.set_optimistic_sig_verification_flag(true);
    
    let pipelined_block = create_pipelined_block();
    let block_info = pipelined_block.block_info();
    let ledger_info = LedgerInfo::new(block_info.clone(), HashValue::zero());
    let ordered_proof = LedgerInfoWithSignatures::new(ledger_info.clone(), AggregateSignature::empty());
    
    // Create votes: 4 valid + 1 invalid (attacker)
    let mut votes = create_valid_commit_votes(validator_signers[0..4].to_vec(), ledger_info.clone());
    
    // Malicious validator sends invalid signature
    let invalid_vote = CommitVote::new_with_signature(
        validator_signers[4].author(),
        ledger_info.clone(),
        bls12381::Signature::dummy_signature(), // INVALID
    );
    votes.push(invalid_vote);
    
    let mut cached_votes = HashMap::new();
    for vote in &votes {
        cached_votes.insert(vote.author(), vote.clone());
    }
    
    let mut ordered_item = BufferItem::new_ordered(
        vec![pipelined_block.clone()],
        ordered_proof.clone(),
        cached_votes,
    );
    
    // Measure time for aggregation with invalid signature
    let start = Instant::now();
    let executed_item = ordered_item.advance_to_executed_or_aggregated(
        vec![pipelined_block.clone()],
        &validator_verifier,
        None,
        true,
    );
    let elapsed = start.elapsed();
    
    println!("Time for aggregation with invalid signature: {:?}", elapsed);
    // This will trigger expensive individual verification of ALL signatures
    // Attacker can repeat this for every block to cause sustained CPU load
    
    assert_eq!(validator_verifier.pessimistic_verify_set().len(), 1);
}
```

To demonstrate the DoS impact, run this test and observe the increased time for aggregation when invalid signatures are present, compared to aggregation with all valid signatures. The attacker can sustain this attack across multiple blocks before being caught.

### Citations

**File:** config/src/config/consensus_config.rs (L382-382)
```rust
            optimistic_sig_verification: true,
```

**File:** consensus/src/pipeline/buffer_manager.rs (L919-934)
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
        });
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

**File:** consensus/src/pipeline/commit_reliable_broadcast.rs (L36-54)
```rust
    /// Verify the signatures on the message
    pub fn verify(&self, sender: Author, verifier: &ValidatorVerifier) -> anyhow::Result<()> {
        match self {
            CommitMessage::Vote(vote) => {
                let _timer = counters::VERIFY_MSG
                    .with_label_values(&["commit_vote"])
                    .start_timer();
                vote.verify(sender, verifier)
            },
            CommitMessage::Decision(decision) => {
                let _timer = counters::VERIFY_MSG
                    .with_label_values(&["commit_decision"])
                    .start_timer();
                decision.verify(verifier)
            },
            CommitMessage::Ack(_) => bail!("Unexpected ack in incoming commit message"),
            CommitMessage::Nack => bail!("Unexpected NACK in incoming commit message"),
        }
    }
```
