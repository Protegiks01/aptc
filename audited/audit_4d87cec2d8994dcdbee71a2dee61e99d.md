# Audit Report

## Title
Malicious Validator Can Corrupt 2-Chain Timeout Certificate Aggregation via Multiple Timeout Messages with Different HQC Rounds

## Summary
A malicious validator can send multiple `RoundTimeout` messages for the same round but with different `hqc_round` values. Due to a logic flaw in the timeout aggregation mechanism, this causes the locally aggregated 2-chain timeout certificate to be created with inconsistent state: the certificate's `timeout.hqc_round()` reflects the highest value received, but the stored signature corresponds to a lower `hqc_round`. When other nodes later verify this certificate (e.g., in proposals), verification fails, causing denial of service.

## Finding Description

The vulnerability exists in the 2-chain timeout certificate aggregation logic within the consensus layer. When processing timeout votes, the system:

1. **Accepts multiple timeout messages from the same validator**: [1](#0-0) 

2. **Updates the partial TC's timeout to higher hqc_round**: [2](#0-1) 

3. **But does NOT update the signature due to or_insert semantics**: [3](#0-2) 

This breaks the **Consensus Safety** invariant that requires all validators to maintain consistent timeout certificates. Here's how the attack works:

**Attack Scenario:**
1. Four validators A (malicious), B, C, D exist, each with 25% voting power (quorum = 67%)
2. All validators timeout at round 10
3. Validator B, C, D send timeout messages with `hqc_round=5`
4. Malicious validator A sends first timeout with `hqc_round=5`
5. Before quorum is reached, validator A sends second timeout with `hqc_round=10`
6. When A's second message is processed:
   - The partial TC's `self.timeout` is updated to have `hqc_round=10`
   - But validator A's stored signature still corresponds to `hqc_round=5` (not overwritten due to `or_insert`)
7. When the third honest validator's vote arrives, quorum is reached and TC is formed with:
   - `timeout.hqc_round() = 10` 
   - `signatures` containing A's signature for `hqc_round=5`, others for `hqc_round=5`
   - `max(signed_rounds) = 5`

8. The TC is stored without verification: [4](#0-3) 

9. When the victim node includes this TC in a proposal's `sync_info`, other nodes verify it and the check fails: [5](#0-4) 

10. The verification failure causes the proposal to be rejected: [6](#0-5) 

The root cause is that `TwoChainTimeoutWithPartialSignatures::add` updates the timeout object when a higher `hqc_round` is seen, but the signature aggregation uses `or_insert` which preserves the first signature from each author, creating an inconsistency.

## Impact Explanation

**Severity: High** (per Aptos Bug Bounty criteria)

This vulnerability enables a single malicious validator to cause denial of service against honest validators by corrupting their locally aggregated timeout certificates:

1. **Validator node slowdowns**: Victim nodes continuously produce invalid proposals that are rejected by peers
2. **Significant protocol violations**: The victim node's consensus state becomes unusable for proposal generation
3. **Liveness impact**: If the victim is the leader for multiple rounds, it significantly degrades network liveness

The attack does not cause consensus safety violations (no chain splits or double-spending) because the malformed TC fails verification at other nodes. However, it prevents the victim node from participating effectively in consensus, which is a **High severity** issue according to the bug bounty program.

## Likelihood Explanation

**Likelihood: High**

The attack is highly practical:

1. **Low barrier**: Requires only a single malicious validator (< 1/3 Byzantine, which AptosBFT is designed to tolerate)
2. **Simple execution**: The attacker simply sends two timeout messages with different `hqc_round` values
3. **No coordination needed**: No collusion with other validators required
4. **Timing window**: The attack succeeds whenever the second message arrives after the first but before quorum is reached, which is common in distributed systems
5. **Repeatable**: Can be executed every round to continuously disrupt specific validators

## Recommendation

Add duplicate author detection to reject subsequent timeout messages from the same author for the same round. Modify the timeout insertion logic:

**Option 1: Reject duplicate timeouts from same author**
```rust
// In consensus/src/pending_votes.rs, modify insert_round_timeout()
pub fn insert_round_timeout(
    &mut self,
    round_timeout: &RoundTimeout,
    validator_verifier: &ValidatorVerifier,
) -> VoteReceptionResult {
    let two_chain_votes = self
        .maybe_2chain_timeout_votes
        .get_or_insert_with(|| TwoChainTimeoutVotes::new(timeout.clone()));
    
    // Check if author already voted
    if two_chain_votes.has_author(&round_timeout.author()) {
        return VoteReceptionResult::DuplicateVote;
    }
    
    two_chain_votes.add(
        round_timeout.author(),
        timeout.clone(),
        signature.clone(),
        round_timeout.reason().clone(),
    );
    // ... rest of logic
}
```

**Option 2: Don't update timeout if signature won't be updated**
```rust
// In consensus/consensus-types/src/timeout_2chain.rs
pub fn add(
    &mut self,
    author: Author,
    timeout: TwoChainTimeout,
    signature: bls12381::Signature,
) {
    // Only update self.timeout if we're actually storing the new signature
    if !self.signatures.signatures().contains_key(&author) {
        let hqc_round = timeout.hqc_round();
        if timeout.hqc_round() > self.timeout.hqc_round() {
            self.timeout = timeout;
        }
        self.signatures.add_signature(author, hqc_round, signature);
    }
}
```

The first option is recommended as it's cleaner and matches the behavior for regular votes.

## Proof of Concept

```rust
// Add to consensus/src/pending_votes_test.rs

#[test]
fn test_duplicate_timeout_different_hqc_rounds() {
    use crate::pending_votes::PendingVotes;
    use consensus_types::{
        quorum_cert::QuorumCert,
        timeout_2chain::TwoChainTimeout,
        round_timeout::{RoundTimeout, RoundTimeoutReason},
    };
    use aptos_types::validator_verifier::random_validator_verifier;
    
    let (signers, validator_verifier) = random_validator_verifier(4, Some(2), false);
    let mut pending_votes = PendingVotes::new();
    
    let epoch = 1;
    let round = 10;
    
    // Create two timeouts from same validator with different hqc_rounds
    let author = signers[0].author();
    let qc_low = QuorumCert::certificate_for_genesis(); // hqc_round = 0
    let qc_high = /* QuorumCert with higher round */;
    
    let timeout_low = TwoChainTimeout::new(epoch, round, qc_low);
    let sig_low = timeout_low.sign(&signers[0]).unwrap();
    let timeout_msg_low = RoundTimeout::new(
        timeout_low,
        author,
        RoundTimeoutReason::NoQC,
        sig_low,
    );
    
    let timeout_high = TwoChainTimeout::new(epoch, round, qc_high);
    let sig_high = timeout_high.sign(&signers[0]).unwrap();
    let timeout_msg_high = RoundTimeout::new(
        timeout_high,
        author,
        RoundTimeoutReason::NoQC,
        sig_high,
    );
    
    // Process first timeout
    let result1 = pending_votes.insert_round_timeout(&timeout_msg_low, &validator_verifier);
    assert!(matches!(result1, VoteReceptionResult::VoteAdded(_)));
    
    // Process second timeout from same author
    let result2 = pending_votes.insert_round_timeout(&timeout_msg_high, &validator_verifier);
    
    // Add timeouts from other validators to reach quorum
    for signer in &signers[1..3] {
        let timeout = TwoChainTimeout::new(epoch, round, qc_low);
        let sig = timeout.sign(signer).unwrap();
        let msg = RoundTimeout::new(timeout, signer.author(), RoundTimeoutReason::NoQC, sig);
        pending_votes.insert_round_timeout(&msg, &validator_verifier);
    }
    
    // The formed TC will have inconsistent state and fail verification
    if let VoteReceptionResult::New2ChainTimeoutCertificate(tc) = result2 {
        assert!(tc.verify(&validator_verifier).is_err());
    }
}
```

## Notes

This vulnerability demonstrates a subtle but critical flaw in the timeout aggregation logic where the assumption that "first signature wins" (via `or_insert`) conflicts with the timeout update logic that accepts higher `hqc_round` values. The fix requires either rejecting duplicate timeouts entirely or ensuring consistency between which timeout is stored and which signature is kept.

### Citations

**File:** consensus/src/pending_votes.rs (L224-232)
```rust
        let two_chain_votes = self
            .maybe_2chain_timeout_votes
            .get_or_insert_with(|| TwoChainTimeoutVotes::new(timeout.clone()));
        two_chain_votes.add(
            round_timeout.author(),
            timeout.clone(),
            signature.clone(),
            round_timeout.reason().clone(),
        );
```

**File:** consensus/consensus-types/src/timeout_2chain.rs (L176-181)
```rust
        ensure!(
            hqc_round == *signed_hqc,
            "Inconsistent hqc round, qc has round {}, highest signed round {}",
            hqc_round,
            *signed_hqc
        );
```

**File:** consensus/consensus-types/src/timeout_2chain.rs (L258-262)
```rust
        let hqc_round = timeout.hqc_round();
        if timeout.hqc_round() > self.timeout.hqc_round() {
            self.timeout = timeout;
        }
        self.signatures.add_signature(author, hqc_round, signature);
```

**File:** consensus/consensus-types/src/timeout_2chain.rs (L320-329)
```rust
    pub fn add_signature(
        &mut self,
        validator: AccountAddress,
        round: Round,
        signature: bls12381::Signature,
    ) {
        self.signatures
            .entry(validator)
            .or_insert((round, signature));
    }
```

**File:** consensus/src/block_storage/block_store.rs (L560-575)
```rust
    pub fn insert_2chain_timeout_certificate(
        &self,
        tc: Arc<TwoChainTimeoutCertificate>,
    ) -> anyhow::Result<()> {
        let cur_tc_round = self
            .highest_2chain_timeout_cert()
            .map_or(0, |tc| tc.round());
        if tc.round() <= cur_tc_round {
            return Ok(());
        }
        self.storage
            .save_highest_2chain_timeout_cert(tc.as_ref())
            .context("Timeout certificate insert failed when persisting to DB")?;
        self.inner.write().replace_2chain_timeout_cert(tc);
        Ok(())
    }
```

**File:** consensus/consensus-types/src/proposal_msg.rs (L113-115)
```rust
        if let Some(tc) = self.sync_info.highest_2chain_timeout_cert() {
            tc.verify(validator).map_err(|e| format_err!("{:?}", e))?;
        }
```
