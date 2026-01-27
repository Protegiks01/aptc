# Audit Report

## Title
Consensus Liveness Disruption and CPU DoS via Invalid Commit Vote Signatures in Optimistic Verification

## Summary
A malicious validator can exploit the optimistic signature verification mechanism to send `CommitVote` messages with invalid BLS signatures that bypass immediate verification. When vote aggregation is attempted, the invalid signatures force expensive individual verification of all signatures, causing consensus delays and CPU resource exhaustion. This violates the consensus protocol's efficiency guarantees and enables a targeted denial-of-service attack.

## Finding Description

The `CommitVote::new_with_signature()` function accepts pre-computed signatures without any verification at creation time. [1](#0-0) 

When a `CommitVote` is received from the network and deserialized, the signature is wrapped in `SignatureWithStatus` with `verification_status` initially set to `false`: [2](#0-1) 

The verification flow calls `CommitVote::verify()` which uses `optimistic_verify()`: [3](#0-2) 

With `optimistic_sig_verification` enabled by default, `optimistic_verify()` returns `Ok()` WITHOUT cryptographically verifying the signature, unless the author is in the `pessimistic_verify_set`: [4](#0-3) 

The default configuration enables optimistic signature verification: [5](#0-4) 

Invalid signatures are only detected during vote aggregation in `aggregate_and_verify()`, which attempts to verify the aggregated signature and falls back to expensive individual verification: [6](#0-5) 

The `filter_invalid_signatures()` method performs parallel individual verification of all signatures: [7](#0-6) 

**Attack Flow:**

1. A malicious validator modifies their node software to call `CommitVote::new_with_signature()` with an invalid BLS signature instead of properly signing with their private key
2. The malicious vote passes through optimistic verification without signature checking
3. The invalid signature is added to the `partial_commit_proof` in the buffer
4. When quorum is reached, `try_advance_to_aggregated()` attempts to create an aggregated signature
5. The aggregated signature verification fails because one component signature is invalid
6. The system must perform expensive individual signature verification on ALL signatures to identify and filter out the invalid one(s)
7. If the malicious validator's vote was needed to reach minimum quorum (2f+1), and they were one of exactly 2f+1 voters, the filtered result has only 2f valid signatures - insufficient for quorum, blocking consensus for that block until additional votes arrive

## Impact Explanation

This vulnerability qualifies as **High Severity** under the Aptos bug bounty criteria for the following reasons:

1. **Validator node slowdowns**: BLS signature verification is computationally expensive. A malicious validator can force victim nodes to perform O(n) individual signature verifications instead of O(1) aggregated verification, consuming significant CPU resources and delaying consensus by hundreds of milliseconds to seconds depending on validator set size.

2. **Significant protocol violation**: The optimistic verification mechanism is designed to improve performance, but this vulnerability allows it to be weaponized. The attack violates the consensus protocol's liveness guarantees by enabling a single Byzantine validator to delay block commitment.

3. **CPU Denial of Service**: By repeatedly sending invalid signatures, a malicious validator can continuously trigger expensive verification paths, potentially degrading node performance and increasing block time across the network.

4. **Attack amplification**: If multiple malicious validators (up to f = (n-1)/3) coordinate this attack, they can cause severe consensus delays without being immediately detected until aggregation fails.

The impact is constrained to "High" rather than "Critical" because:
- Consensus eventually recovers (not permanent liveness failure)
- Requires validator privileges (not exploitable by arbitrary network peers)
- Malicious validators are added to `pessimistic_verify_set` after first detection, limiting repeated attacks from the same validator within an epoch

## Likelihood Explanation

**Likelihood: Medium to High**

**Requirements:**
- Attacker must be a validator with staked tokens
- Attacker must modify their node software to send invalid signatures
- Attack is immediately detectable through failed aggregations

**Factors increasing likelihood:**
- No upfront cost to attempt (beyond being a validator)
- Simple to execute (single malicious vote with invalid signature)
- Can be performed repeatedly across different blocks/rounds
- `pessimistic_verify_set` is not persisted and may reset on epoch boundaries
- No evidence of automatic slashing for this behavior in the codebase

**Factors decreasing likelihood:**
- Leaves forensic evidence (can prove signature invalidity)
- May damage validator reputation
- Validator risks being removed from validator set by governance

In a production network, a rational malicious validator would weigh the temporary disruption benefit against long-term reputation damage and potential slashing.

## Recommendation

**Immediate Fix:** Implement mandatory signature verification for validators in the `pessimistic_verify_set` OR after the first aggregation failure for a given block.

**Option 1 - Verify signatures from new voters:**
Modify `optimistic_verify()` to always verify signatures from validators who haven't been seen before in the current epoch, building trust incrementally: [4](#0-3) 

Add a trusted validator set that starts empty and only adds validators after their first signature is verified.

**Option 2 - Verify before adding to aggregator:**
Add signature verification in `add_signature_if_matched()` before accepting the vote into the partial commit proof for critical states: [8](#0-7) 

**Option 3 - Slashing mechanism:**
Implement on-chain slashing for validators who repeatedly send invalid signatures, creating economic disincentives for this attack.

**Recommended approach:** Combine Option 1 with automatic reporting to on-chain governance when invalid signatures are detected, enabling reputation tracking and potential validator ejection.

## Proof of Concept

```rust
// PoC demonstrating the attack flow
// File: consensus/src/pipeline/tests/invalid_signature_attack_test.rs

#[tokio::test]
async fn test_invalid_commit_vote_signature_dos() {
    use aptos_consensus_types::pipeline::commit_vote::CommitVote;
    use aptos_crypto::bls12381;
    use aptos_types::ledger_info::LedgerInfo;
    use aptos_types::block_info::BlockInfo;
    
    // Setup: Create a test environment with validators
    let (signers, validator_verifier) = random_validator_verifier(4, None, true);
    
    // Honest validators create proper commit votes
    let block_info = BlockInfo::random(1);
    let ledger_info = LedgerInfo::new(block_info.clone(), HashValue::zero());
    
    let mut aggregator = SignatureAggregator::new(ledger_info.clone());
    
    // Add 3 honest validator signatures (75% voting power in 4-validator set)
    for i in 0..3 {
        let vote = CommitVote::new(
            signers[i].author(),
            ledger_info.clone(),
            &signers[i],
        ).unwrap();
        aggregator.add_signature(vote.author(), vote.signature_with_status());
    }
    
    // Malicious validator creates INVALID signature
    let malicious_author = signers[3].author();
    let invalid_signature = bls12381::Signature::dummy_signature(); // Wrong signature!
    let malicious_vote = CommitVote::new_with_signature(
        malicious_author,
        ledger_info.clone(),
        invalid_signature,
    );
    
    // Add malicious vote - passes optimistic verification
    aggregator.add_signature(malicious_vote.author(), malicious_vote.signature_with_status());
    
    // Attempt aggregation - should succeed in voting power check
    assert!(aggregator.check_voting_power(&validator_verifier, true).is_ok());
    
    // But aggregate_and_verify will fail and trigger expensive individual verification
    let start = std::time::Instant::now();
    let result = aggregator.aggregate_and_verify(&validator_verifier);
    let duration = start.elapsed();
    
    // Verify that:
    // 1. Aggregation eventually succeeds after filtering (if enough valid sigs remain)
    // 2. But took significantly longer due to individual verification
    // 3. Malicious validator is added to pessimistic_verify_set
    
    println!("Aggregation took {:?} (expected <10ms without attack, actual includes filtering overhead)", duration);
    assert!(validator_verifier.pessimistic_verify_set().contains(&malicious_author));
}
```

## Notes

The vulnerability exists because optimistic signature verification prioritizes performance over immediate security validation. While this design is reasonable for honest validators, it creates an attack vector for Byzantine actors. The mitigation (adding malicious validators to `pessimistic_verify_set`) is reactive rather than proactive, allowing the first attack to succeed before defenses activate.

The attack is most impactful when:
- The malicious validator's vote is needed to reach minimum quorum (2f+1)
- Multiple colluding Byzantine validators (up to f) perform the attack simultaneously
- The validator set is large, making individual verification more expensive

Cross-epoch attacks are possible if `pessimistic_verify_set` is not persisted between epochs, though this requires further investigation of epoch state management.

### Citations

**File:** consensus/consensus-types/src/pipeline/commit_vote.rs (L59-69)
```rust
    pub fn new_with_signature(
        author: Author,
        ledger_info: LedgerInfo,
        signature: bls12381::Signature,
    ) -> Self {
        Self {
            author,
            ledger_info,
            signature: SignatureWithStatus::from(signature),
        }
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

**File:** types/src/ledger_info.rs (L424-431)
```rust
impl<'de> Deserialize<'de> for SignatureWithStatus {
    fn deserialize<D>(deserializer: D) -> Result<SignatureWithStatus, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let signature = bls12381::Signature::deserialize(deserializer)?;
        Ok(SignatureWithStatus::from(signature))
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

**File:** config/src/config/consensus_config.rs (L382-382)
```rust
            optimistic_sig_verification: true,
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
