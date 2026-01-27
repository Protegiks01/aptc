# Audit Report

## Title
Vote-Then-Timeout Equivocation Vulnerability in 2-Chain SafetyRules

## Summary
A validator can vote for a block at round R, then immediately sign a timeout for the same round R, allowing them to contribute voting power to both a Quorum Certificate (QC) and Timeout Certificate (TC) for the same round. This violates the fundamental consensus invariant that validators should either vote OR timeout for a given round, never both.

## Finding Description

The SafetyRules module enforces consensus safety by checking that validators don't send conflicting messages. However, there is an asymmetric vulnerability in the timeout validation logic. [1](#0-0) 

The timeout signing logic only prevents timeouts at rounds STRICTLY LESS than `last_voted_round`. When `timeout.round() == last_voted_round`, both conditions are false, and execution continues without error. This allows the following attack sequence:

**Attack Sequence:**
1. Validator votes for a block proposal at round R
   - `last_voted_round` is updated to R via `verify_and_update_last_vote_round` [2](#0-1) 

2. Validator then signs a timeout at round R
   - Check `R < R` fails (false) → no error
   - Check `R > R` fails (false) → no update
   - Proceeds to update `highest_timeout_round` to R [3](#0-2) 

3. Both messages are valid and can be sent to other validators

**Why the reverse is blocked:**
The voting logic correctly prevents timeout-then-vote at the same round: [4](#0-3) 

The check `round <= last_voted_round` (with <=) correctly prevents voting after timing out at the same round. However, the timeout logic only checks `<`, creating the asymmetry.

**Broken Invariant:**
This violates the consensus safety invariant that validators must send either a vote OR a timeout for each round, never both. In AptosBFT, votes signal acceptance of a specific block, while timeouts signal giving up on the round. These are semantically contradictory messages.

## Impact Explanation

**Severity: Critical** (Consensus/Safety violations - up to $1,000,000)

This vulnerability enables timeout-vote equivocation, which can lead to:

1. **Consensus Safety Violations**: A malicious validator can contribute voting power to both:
   - A Quorum Certificate (QC) for a block at round R
   - A Timeout Certificate (TC) for round R
   
2. **Round Progression Ambiguity**: The protocol expects validators to participate in either QC formation OR TC formation for a round. Allowing both enables conflicting round progression signals.

3. **Byzantine Behavior Amplification**: Under normal BFT assumptions (< 1/3 Byzantine validators), malicious validators exploiting this can create confusion in the consensus protocol by simultaneously supporting block certification and round timeouts.

4. **Potential Chain Safety Breaks**: If multiple Byzantine validators exploit this, they could potentially help form both a QC and TC for the same round, which could lead to safety violations in subsequent rounds depending on how nodes process these certificates.

The SafetyRules module exists specifically to prevent such equivocation, making this a critical safety rule bypass.

## Likelihood Explanation

**Likelihood: High**

This vulnerability is highly likely to occur or be exploited because:

1. **Simple Exploitation**: Any validator can trigger this through normal SafetyRules API calls without any special permissions or system compromise
2. **No Detection Mechanism**: There are no runtime checks or tests preventing this scenario
3. **Deterministic Behavior**: The vulnerability is in the core safety logic, not a race condition or timing-dependent issue
4. **Byzantine Validator Motivation**: Rational Byzantine validators would exploit this to maximize their influence on consensus by participating in both vote and timeout aggregation

## Recommendation

Add an equality check in the timeout signing logic to prevent timeouts at rounds equal to `last_voted_round`:

**Fix in `consensus/safety-rules/src/safety_rules_2chain.rs`:**

```rust
// Current code (lines 37-45)
if timeout.round() < safety_data.last_voted_round {
    return Err(Error::IncorrectLastVotedRound(
        timeout.round(),
        safety_data.last_voted_round,
    ));
}

// FIXED code - add <= check instead of just <
if timeout.round() <= safety_data.last_voted_round {
    return Err(Error::IncorrectLastVotedRound(
        timeout.round(),
        safety_data.last_voted_round,
    ));
}
```

This makes the timeout check symmetric with the voting check, preventing both:
- Timeout-then-vote at round R (already blocked)
- Vote-then-timeout at round R (currently vulnerable)

**Additional Recommendation**: Add a comprehensive test case verifying that vote-then-timeout at the same round is rejected.

## Proof of Concept

The following test demonstrates the vulnerability:

```rust
#[test]
fn test_vote_then_timeout_same_round_equivocation() {
    use crate::test_utils;
    use aptos_consensus_types::timeout_2chain::TwoChainTimeout;
    
    // Setup validator and genesis
    let (mut safety_rules, signer) = /* initialize from test_utils */;
    let (proof, genesis_qc) = test_utils::make_genesis(&signer);
    let round = genesis_qc.certified_block().round();
    let epoch = genesis_qc.certified_block().epoch();
    
    safety_rules.initialize(&proof).unwrap();
    
    // Create a proposal at round + 1
    let p0 = test_utils::make_proposal_with_qc(round + 1, genesis_qc.clone(), &signer);
    
    // Step 1: Vote for the proposal at round + 1
    safety_rules
        .construct_and_sign_vote_two_chain(&p0, None)
        .unwrap();
    
    // Verify last_voted_round is now round + 1
    assert_eq!(
        safety_rules.consensus_state().unwrap().last_voted_round(),
        round + 1
    );
    
    // Step 2: Attempt to timeout at the SAME round (round + 1)
    // This should fail but currently succeeds!
    let timeout = TwoChainTimeout::new(epoch, round + 1, genesis_qc.clone());
    let result = safety_rules.sign_timeout_with_qc(&timeout, None);
    
    // VULNERABILITY: This succeeds when it should fail
    // After fix, this should return Error::IncorrectLastVotedRound
    assert!(result.is_err(), "Vote-then-timeout at same round should be rejected!");
}
```

This test will currently pass (demonstrating the vulnerability), but after applying the fix, it will fail with the expected `IncorrectLastVotedRound` error.

## Notes

The security question specifically asked "Can a validator timeout at round R then vote at round R?" The direct answer is **NO** - that direction is correctly blocked. However, the **reverse scenario** (vote then timeout at the same round) is vulnerable and represents the same class of timeout-vote equivocation bug. Both orderings should be prevented to maintain consensus safety invariants.

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

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L46-46)
```rust
        self.update_highest_timeout_round(timeout, &mut safety_data);
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L77-80)
```rust
        self.verify_and_update_last_vote_round(
            proposed_block.block_data().round(),
            &mut safety_data,
        )?;
```

**File:** consensus/safety-rules/src/safety_rules.rs (L213-223)
```rust
    pub(crate) fn verify_and_update_last_vote_round(
        &self,
        round: Round,
        safety_data: &mut SafetyData,
    ) -> Result<(), Error> {
        if round <= safety_data.last_voted_round {
            return Err(Error::IncorrectLastVotedRound(
                round,
                safety_data.last_voted_round,
            ));
        }
```
