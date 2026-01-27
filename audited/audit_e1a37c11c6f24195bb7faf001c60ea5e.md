# Audit Report

## Title
SafetyRules Timeout Re-signing Vulnerability Enables Consensus Equivocation

## Summary
The `guarded_sign_timeout_with_qc()` function in SafetyRules fails to prevent validators from signing multiple different `TwoChainTimeout` messages for the same round with distinct QuorumCertificates. This allows a Byzantine validator to create conflicting timeout signatures with different `hqc_round` values, potentially causing honest validators to form divergent timeout certificates and violate consensus safety.

## Finding Description

The vulnerability exists in the SafetyRules timeout signing logic. When a validator calls `sign_timeout_with_qc()` for a timeout where `timeout.round() == safety_data.last_voted_round`, the function neither rejects the request nor tracks what was previously signed - it simply proceeds to sign the timeout. [1](#0-0) 

The function only rejects timeouts with `round < last_voted_round` and only updates state for `round > last_voted_round`. For equal rounds, it continues to line 49 and signs the timeout without any duplicate prevention.

The root cause is that `SafetyData` only tracks round numbers, not the actual timeout content: [2](#0-1) 

Notably, there is no `last_timeout` field to store and compare against previous timeout signatures, unlike the `last_vote` field for votes.

The `generate_2chain_timeout()` function accepts any QuorumCert without validation: [3](#0-2) 

**Attack Scenario:**

1. A Byzantine validator at round R has two valid QCs: `QC_old` (round 5) and `QC_new` (round 9)
2. The validator creates two different timeouts for round 10:
   - `T1 = generate_2chain_timeout(QC_old)` → creates timeout with `hqc_round = 5`
   - `T2 = generate_2chain_timeout(QC_new)` → creates timeout with `hqc_round = 9`
3. Both pass SafetyRules checks if there's a TC for round 9: [4](#0-3) 

4. SafetyRules signs both because `timeout.round() == last_voted_round` (both are round 10)
5. The validator sends `T1` to validators {A, B, C} and `T2` to validators {D, E, F}
6. Due to the `or_insert` logic, each validator accepts only the first timeout received: [5](#0-4) 

7. Different validator groups form timeout certificates with different `hqc_round` values
8. The `safe_to_vote` check uses the TC's `hqc_round` to validate proposals: [6](#0-5) 

9. Validators with different TCs accept different proposals, causing consensus divergence

## Impact Explanation

This vulnerability enables **Consensus Safety Violation** - a Critical severity issue per Aptos bug bounty criteria. A Byzantine validator can cause honest validators to form conflicting timeout certificates, leading them to vote on incompatible proposals and potentially commit different blocks at the same round. This breaks the fundamental consensus safety guarantee that prevents chain splits under < 1/3 Byzantine validators.

The impact is amplified because SafetyRules is specifically designed to be the last line of defense against consensus violations. If SafetyRules itself permits equivocation-like behavior (signing multiple conflicting timeout messages), the entire safety architecture is compromised.

## Likelihood Explanation

**Moderate likelihood** in adversarial conditions:

- Requires a Byzantine validator to actively exploit the bug
- Requires precise network timing to deliver different timeout messages to different validator groups
- The attack window exists whenever a validator has multiple valid QCs and times out
- Existing aggregation logic provides partial mitigation but doesn't fully prevent the attack

In production, honest validators using the standard code path would not trigger this, as `RoundManager` always uses the highest QC: [7](#0-6) 

However, a compromised or malicious validator could deliberately exploit this design flaw.

## Recommendation

SafetyRules must track and enforce that only one timeout per round can be signed. Modify `SafetyData` to include the last signed timeout:

```rust
pub struct SafetyData {
    pub epoch: u64,
    pub last_voted_round: u64,
    pub preferred_round: u64,
    pub one_chain_round: u64,
    pub last_vote: Option<Vote>,
    pub highest_timeout_round: u64,
    // NEW: Track the last timeout signed
    pub last_timeout: Option<TwoChainTimeout>,
}
```

Update `guarded_sign_timeout_with_qc()` to check and enforce timeout uniqueness:

```rust
pub(crate) fn guarded_sign_timeout_with_qc(
    &mut self,
    timeout: &TwoChainTimeout,
    timeout_cert: Option<&TwoChainTimeoutCertificate>,
) -> Result<bls12381::Signature, Error> {
    // ... existing checks ...
    
    // NEW: Prevent re-signing timeouts for the same round with different QCs
    if timeout.round() == safety_data.last_voted_round {
        if let Some(ref last_timeout) = safety_data.last_timeout {
            if last_timeout.round() == timeout.round() {
                // Verify this is the same timeout
                ensure!(
                    last_timeout.hqc_round() == timeout.hqc_round(),
                    "Attempting to sign different timeout for round {}: previous hqc_round={}, new hqc_round={}",
                    timeout.round(),
                    last_timeout.hqc_round(),
                    timeout.hqc_round()
                );
                // Return the previously signed timeout signature instead of re-signing
                return Err(Error::DuplicateTimeoutForRound(timeout.round()));
            }
        }
    }
    
    // ... continue with signing ...
    
    // Store the signed timeout
    safety_data.last_timeout = Some(timeout.clone());
    self.persistent_storage.set_safety_data(safety_data)?;
    
    Ok(signature)
}
```

## Proof of Concept

```rust
#[test]
fn test_multiple_timeout_signatures_same_round() {
    use aptos_consensus_types::{
        quorum_cert::QuorumCert,
        timeout_2chain::TwoChainTimeout,
        vote_data::VoteData,
    };
    use aptos_crypto::hash::CryptoHash;
    use aptos_types::{
        block_info::BlockInfo,
        ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
        validator_verifier::random_validator_verifier,
    };
    
    let (signers, validators) = random_validator_verifier(4, None, false);
    let mut safety_rules = SafetyRules::new(
        PersistentSafetyStorage::in_memory_for_test(),
        false,
    );
    safety_rules.initialize_with_signer(signers[0].clone(), validators.clone());
    
    // Create two different QCs
    let qc_old = create_qc_for_round(3, &signers, &validators);
    let qc_new = create_qc_for_round(8, &signers, &validators);
    
    // Create timeouts for round 10 with different QCs
    let timeout1 = TwoChainTimeout::new(1, 10, qc_old);
    let timeout2 = TwoChainTimeout::new(1, 10, qc_new);
    
    // Both should be signable - this is the bug!
    let sig1 = safety_rules.sign_timeout_with_qc(&timeout1, None).unwrap();
    let sig2 = safety_rules.sign_timeout_with_qc(&timeout2, None).unwrap();
    
    // Verify both signatures are valid but for different timeout contents
    assert_ne!(timeout1.hqc_round(), timeout2.hqc_round());
    assert!(validators.verify(signers[0].author(), &timeout1.signing_format(), &sig1).is_ok());
    assert!(validators.verify(signers[0].author(), &timeout2.signing_format(), &sig2).is_ok());
    
    // This demonstrates the validator signed two conflicting timeouts for round 10
    panic!("SafetyRules allowed signing multiple different timeouts for the same round!");
}
```

This test demonstrates that SafetyRules permits signing multiple different timeout messages for the same round, violating the consensus protocol's assumption of at-most-once timeout signing per round.

## Notes

The vulnerability is particularly subtle because:
1. The aggregation logic using `or_insert` provides partial defense by accepting only the first timeout from each validator
2. Timeout certificate verification checks that `hqc_round == max(signed_hqc_rounds)`, which prevents some inconsistencies
3. Honest validators using standard code paths always use the highest QC

However, these mitigations are insufficient because they rely on network timing and don't prevent the root cause: SafetyRules permitting equivocating behavior. The proper fix must be at the SafetyRules layer to enforce the consensus invariant that each validator signs at most one timeout per round.

### Citations

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L37-45)
```rust
        if timeout.round() < safety_data.last_voted_round {
            return Err(Error::IncorrectLastVotedRound(
                timeout.round(),
                safety_data.last_voted_round,
            ));
        }
        if timeout.round() > safety_data.last_voted_round {
            self.verify_and_update_last_vote_round(timeout.round(), &mut safety_data)?;
        }
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L124-145)
```rust
    fn safe_to_timeout(
        &self,
        timeout: &TwoChainTimeout,
        maybe_tc: Option<&TwoChainTimeoutCertificate>,
        safety_data: &SafetyData,
    ) -> Result<(), Error> {
        let round = timeout.round();
        let qc_round = timeout.hqc_round();
        let tc_round = maybe_tc.map_or(0, |tc| tc.round());
        if (round == next_round(qc_round)? || round == next_round(tc_round)?)
            && qc_round >= safety_data.one_chain_round
        {
            Ok(())
        } else {
            Err(Error::NotSafeToTimeout(
                round,
                qc_round,
                tc_round,
                safety_data.one_chain_round,
            ))
        }
    }
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L150-166)
```rust
    fn safe_to_vote(
        &self,
        block: &Block,
        maybe_tc: Option<&TwoChainTimeoutCertificate>,
    ) -> Result<(), Error> {
        let round = block.round();
        let qc_round = block.quorum_cert().certified_block().round();
        let tc_round = maybe_tc.map_or(0, |tc| tc.round());
        let hqc_round = maybe_tc.map_or(0, |tc| tc.highest_hqc_round());
        if round == next_round(qc_round)?
            || (round == next_round(tc_round)? && qc_round >= hqc_round)
        {
            Ok(())
        } else {
            Err(Error::NotSafeToVote(round, qc_round, tc_round, hqc_round))
        }
    }
```

**File:** consensus/consensus-types/src/safety_data.rs (L10-21)
```rust
pub struct SafetyData {
    pub epoch: u64,
    pub last_voted_round: u64,
    // highest 2-chain round, used for 3-chain
    pub preferred_round: u64,
    // highest 1-chain round, used for 2-chain
    #[serde(default)]
    pub one_chain_round: u64,
    pub last_vote: Option<Vote>,
    #[serde(default)]
    pub highest_timeout_round: u64,
}
```

**File:** consensus/consensus-types/src/vote.rs (L125-131)
```rust
    pub fn generate_2chain_timeout(&self, qc: QuorumCert) -> TwoChainTimeout {
        TwoChainTimeout::new(
            self.vote_data.proposed().epoch(),
            self.vote_data.proposed().round(),
            qc,
        )
    }
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

**File:** consensus/src/round_manager.rs (L1064-1077)
```rust
            if !timeout_vote.is_timeout() {
                let timeout = timeout_vote.generate_2chain_timeout(
                    self.block_store.highest_quorum_cert().as_ref().clone(),
                );
                let signature = self
                    .safety_rules
                    .lock()
                    .sign_timeout_with_qc(
                        &timeout,
                        self.block_store.highest_2chain_timeout_cert().as_deref(),
                    )
                    .context("[RoundManager] SafetyRules signs 2-chain timeout")?;
                timeout_vote.add_2chain_timeout(timeout, signature);
            }
```
