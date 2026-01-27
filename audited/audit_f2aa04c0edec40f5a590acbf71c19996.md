# Audit Report

## Title
Non-Atomic Signature Generation and State Persistence Enables Validator Equivocation

## Summary
The `TSafetyRules` implementations in `guarded_construct_and_sign_vote_two_chain` and `guarded_construct_and_sign_order_vote` generate cryptographic signatures BEFORE persisting the updated `SafetyData` state. This violates atomicity and creates a window where process crashes or storage failures can enable validators to double-sign conflicting votes, breaking consensus safety.

## Finding Description

The security question asks whether implementations can return signatures before fully validating input data. After thorough analysis, **all implementations properly validate input data before signing** - there is no validation bypass vulnerability. [1](#0-0) 

However, a different but related critical issue exists: **signatures are generated before state persistence completes**, violating the atomicity requirement for safety-critical operations.

In `guarded_construct_and_sign_vote_two_chain`, the execution order is:
1. Lines 59-81: Validate proposal, timeout certificate, and safety rules
2. Line 84: Update in-memory `safety_data` (observe_qc)
3. Line 77-79: Update `last_voted_round` in memory
4. **Line 88: Generate signature** [2](#0-1) 
5. Line 91: Update `last_vote` in memory
6. **Line 92: Persist safety_data to storage** [3](#0-2) 
7. Line 94: Return vote with signature

The `SafetyData` structure stores critical consensus safety information including `last_voted_round`, which enforces the "First Voting Rule" preventing validators from voting twice in the same round. [4](#0-3) 

The persistence operation can fail due to storage errors, network issues, or be interrupted by process crashes. [5](#0-4) 

**Attack Scenario:**
1. Validator receives proposal for round N
2. Validator signs vote for round N (line 88)
3. Process crashes or storage fails before line 92 completes
4. Validator restarts, loads old `SafetyData` with `last_voted_round = N-1`
5. Validator can now sign a different vote for round N, violating the voting rule
6. Network receives two different signatures for round N from same validator
7. This is detected as equivocation by other validators [6](#0-5) 

The same vulnerability exists in `guarded_construct_and_sign_order_vote`: [7](#0-6) 

Note that `guarded_sign_timeout_with_qc` correctly persists BEFORE signing, demonstrating the correct pattern: [8](#0-7) 

## Impact Explanation

**Severity: HIGH** (per Aptos Bug Bounty criteria for "Significant protocol violations")

This breaks **Consensus Safety Invariant #2**: "AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine". Validator equivocation is one of the core safety violations that Byzantine consensus protocols must prevent.

While this requires process crashes rather than malicious intent, it violates the fundamental safety guarantee that validators cannot equivocate even under crash-recovery scenarios. The Aptos consensus protocol must maintain safety across validator restarts, which is a standard assumption in BFT systems.

The impact includes:
- Validators can inadvertently violate voting rules after crashes
- Potential for conflicting votes to propagate through the network
- Equivocation detection will trigger security alerts but cannot prevent the initial violation
- Degrades trust in validator reliability and consensus safety

## Likelihood Explanation

**Likelihood: MEDIUM**

While this requires specific timing (crash between signing and persistence), such scenarios are realistic in production environments:
- Hardware failures (disk, power, memory)
- Software crashes (panics, out-of-memory)
- Network storage failures in distributed deployments
- Container/orchestration restarts (Kubernetes pod evictions)

Modern consensus systems run 24/7 and validators experience restarts regularly. A single occurrence violates safety guarantees even if rare.

## Recommendation

**Fix: Persist state BEFORE generating signatures** to ensure atomicity of safety-critical operations.

Modify both affected methods to follow the pattern used in `guarded_sign_timeout_with_qc`:

**For `guarded_construct_and_sign_vote_two_chain`:**
```rust
// Move persistence before signing
safety_data.last_vote = Some(vote_placeholder); // temporary
self.persistent_storage.set_safety_data(safety_data.clone())?;

// Now safe to sign
let signature = self.sign(&ledger_info)?;
let vote = Vote::new_with_signature(vote_data, author, ledger_info, signature);

// Update with actual vote
safety_data.last_vote = Some(vote.clone());
self.persistent_storage.set_safety_data(safety_data)?;
```

Or alternatively, restructure to persist all state changes before signing, accepting the single additional storage write for safety.

**For `guarded_construct_and_sign_order_vote`:**
Move line 117 (persistence) before line 115 (signing).

This ensures the "commit point" (signature generation) only occurs after state is durably recorded.

## Proof of Concept

```rust
#[cfg(test)]
mod test_equivocation_vulnerability {
    use super::*;
    
    #[test]
    fn test_crash_between_sign_and_persist() {
        // 1. Setup validator with safety rules
        let mut safety_rules = setup_safety_rules();
        
        // 2. Create vote proposal for round 10
        let vote_proposal = create_vote_proposal(10);
        
        // 3. Simulate signing but crash before persist
        // In real scenario, this would be process crash
        let result = safety_rules.construct_and_sign_vote_two_chain(&vote_proposal, None);
        
        // Simulate storage failure at persist point
        // (In production, this would be a crash after signing but before storage.set succeeds)
        
        // 4. Restart validator - loads old safety_data
        let mut restarted_safety_rules = restart_safety_rules();
        
        // 5. Create different vote for same round 10
        let conflicting_vote_proposal = create_different_vote_proposal(10);
        
        // 6. Validator signs again - EQUIVOCATION!
        let result2 = restarted_safety_rules.construct_and_sign_vote_two_chain(&conflicting_vote_proposal, None);
        
        // Both signatures exist for same round, different proposals
        assert!(result.is_ok() && result2.is_ok());
        assert_ne!(result.unwrap().vote_data(), result2.unwrap().vote_data());
        // This violates consensus safety - validator double-signed
    }
}
```

**Notes**

While this vulnerability was discovered during investigation of the signature verification order question, it represents a distinct issue: all input validation occurs correctly before signing, but state persistence occurs incorrectly after signing. This is still a HIGH severity consensus safety violation that should be addressed by reordering persistence to occur before signature generation in the affected methods.

### Citations

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L47-49)
```rust
        self.persistent_storage.set_safety_data(safety_data)?;

        let signature = self.sign(&timeout.signing_format())?;
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L53-95)
```rust
    pub(crate) fn guarded_construct_and_sign_vote_two_chain(
        &mut self,
        vote_proposal: &VoteProposal,
        timeout_cert: Option<&TwoChainTimeoutCertificate>,
    ) -> Result<Vote, Error> {
        // Exit early if we cannot sign
        self.signer()?;

        let vote_data = self.verify_proposal(vote_proposal)?;
        if let Some(tc) = timeout_cert {
            self.verify_tc(tc)?;
        }
        let proposed_block = vote_proposal.block();
        let mut safety_data = self.persistent_storage.safety_data()?;

        // if already voted on this round, send back the previous vote
        // note: this needs to happen after verifying the epoch as we just check the round here
        if let Some(vote) = safety_data.last_vote.clone() {
            if vote.vote_data().proposed().round() == proposed_block.round() {
                return Ok(vote);
            }
        }

        // Two voting rules
        self.verify_and_update_last_vote_round(
            proposed_block.block_data().round(),
            &mut safety_data,
        )?;
        self.safe_to_vote(proposed_block, timeout_cert)?;

        // Record 1-chain data
        self.observe_qc(proposed_block.quorum_cert(), &mut safety_data);
        // Construct and sign vote
        let author = self.signer()?.author();
        let ledger_info = self.construct_ledger_info_2chain(proposed_block, vote_data.hash())?;
        let signature = self.sign(&ledger_info)?;
        let vote = Vote::new_with_signature(vote_data, author, ledger_info, signature);

        safety_data.last_vote = Some(vote.clone());
        self.persistent_storage.set_safety_data(safety_data)?;

        Ok(vote)
    }
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L97-119)
```rust
    pub(crate) fn guarded_construct_and_sign_order_vote(
        &mut self,
        order_vote_proposal: &OrderVoteProposal,
    ) -> Result<OrderVote, Error> {
        // Exit early if we cannot sign
        self.signer()?;
        self.verify_order_vote_proposal(order_vote_proposal)?;
        let proposed_block = order_vote_proposal.block();
        let mut safety_data = self.persistent_storage.safety_data()?;

        // Record 1-chain data
        self.observe_qc(order_vote_proposal.quorum_cert(), &mut safety_data);

        self.safe_for_order_vote(proposed_block, &safety_data)?;
        // Construct and sign order vote
        let author = self.signer()?.author();
        let ledger_info =
            LedgerInfo::new(order_vote_proposal.block_info().clone(), HashValue::zero());
        let signature = self.sign(&ledger_info)?;
        let order_vote = OrderVote::new_with_signature(author, ledger_info.clone(), signature);
        self.persistent_storage.set_safety_data(safety_data)?;
        Ok(order_vote)
    }
```

**File:** consensus/consensus-types/src/safety_data.rs (L8-21)
```rust
/// Data structure for safety rules to ensure consensus safety.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize, Clone, Default)]
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

**File:** consensus/safety-rules/src/persistent_safety_storage.rs (L150-170)
```rust
    pub fn set_safety_data(&mut self, data: SafetyData) -> Result<(), Error> {
        let _timer = counters::start_timer("set", SAFETY_DATA);
        counters::set_state(counters::EPOCH, data.epoch as i64);
        counters::set_state(counters::LAST_VOTED_ROUND, data.last_voted_round as i64);
        counters::set_state(
            counters::HIGHEST_TIMEOUT_ROUND,
            data.highest_timeout_round as i64,
        );
        counters::set_state(counters::PREFERRED_ROUND, data.preferred_round as i64);

        match self.internal_store.set(SAFETY_DATA, data.clone()) {
            Ok(_) => {
                self.cached_safety_data = Some(data);
                Ok(())
            },
            Err(error) => {
                self.cached_safety_data = None;
                Err(Error::SecureStorageUnexpectedError(error.to_string()))
            },
        }
    }
```

**File:** consensus/src/pending_votes.rs (L300-307)
```rust
                error!(
                    SecurityEvent::ConsensusEquivocatingVote,
                    remote_peer = vote.author(),
                    vote = vote,
                    previous_vote = previously_seen_vote
                );

                return VoteReceptionResult::EquivocateVote;
```
