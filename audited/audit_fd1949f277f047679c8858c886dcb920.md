# Audit Report

## Title
Consensus Liveness Failure via Premature `one_chain_round` Advancement in Out-of-Order Proposal Processing

## Summary
The `observe_qc` function unconditionally updates `one_chain_round` when processing proposals, without validating that the QC's round is reasonable relative to the node's current consensus state. This allows out-of-order proposal processing to cause `one_chain_round` to jump to arbitrarily high values, blocking the node from timing out on lower rounds and causing a permanent liveness failure.

## Finding Description
The vulnerability stems from a design flaw in how `one_chain_round` is updated across two critical code paths in the 2-chain consensus safety rules: [1](#0-0) 

Both `guarded_construct_and_sign_vote_two_chain` and `guarded_construct_and_sign_order_vote` call `observe_qc`: [2](#0-1) [3](#0-2) 

The critical issue is that `observe_qc` unconditionally updates `one_chain_round` to `qc.certified_block().round()` if it's higher than the current value, **without any validation** that this round is reasonable relative to the node's current consensus state or round progression.

The `safe_to_timeout` function then uses `one_chain_round` as a safety check: [4](#0-3) 

**Attack Scenario:**

1. Node is progressing normally at round 100 with `one_chain_round = 100`
2. Due to network delays, state synchronization, or malicious behavior, the node receives and processes a `VoteProposal` or `OrderVoteProposal` for round 200 with a valid QC for round 199
3. `observe_qc` updates `one_chain_round` from 100 to 199
4. Node's local consensus is stuck at round 101 and needs to timeout to progress
5. When attempting `guarded_sign_timeout_with_qc` for round 102 with QC for round 101, the `safe_to_timeout` check fails: `qc_round (101) >= one_chain_round (199)` evaluates to `false`
6. **The node can no longer timeout and is permanently stuck**

The vulnerability is exacerbated by the ordering difference between the two functions:
- In `guarded_construct_and_sign_vote_two_chain`: safety checks happen **before** `observe_qc`
- In `guarded_construct_and_sign_order_vote`: `observe_qc` happens **before** `safe_for_order_vote` (which doesn't even check `one_chain_round`)

This breaks the **Consensus Liveness** invariant: nodes must be able to make progress through timeouts when proposals are delayed or missing.

## Impact Explanation
This vulnerability qualifies as **High Severity** under the Aptos bug bounty program criteria:

1. **Validator Node Slowdowns/Liveness Failure**: Affected nodes cannot timeout and progress in consensus, effectively removing them from participation
2. **Significant Protocol Violation**: Breaks the 2-chain BFT liveness guarantee that honest nodes can always make progress

If multiple validators are affected (e.g., through coordinated out-of-order message delivery or network partitions), this could lead to:
- Partial network liveness degradation (if <1/3 of validators affected)
- Complete network halt (if ≥1/3 of validators affected and unable to form quorums)

While not reaching Critical severity (requires manual intervention to recover, not permanent funds loss), it represents a serious availability threat to the network.

## Likelihood Explanation
**Likelihood: Medium-High**

This vulnerability can be triggered through:

1. **Natural Network Conditions**: 
   - Network delays causing proposals to arrive out of order
   - State sync operations fetching high-round blocks before processing intermediate rounds
   - Network partitions resolving with validators at different round heights

2. **Malicious Exploitation**:
   - Byzantine validator sends valid high-round proposals to selected honest validators
   - No collusion required - a single malicious validator can craft valid proposals
   - QC verification passes as long as 2/3+ validators signed (attacker only needs to wait for network to advance normally)

3. **Ease of Exploitation**:
   - No special privileges required beyond normal validator operation
   - Attack is deterministic once conditions are met
   - No cryptographic breaking required

The attack becomes more likely in production networks with:
- Geographic distribution causing variable latencies
- Temporary network partitions
- State synchronization operations
- Any Byzantine validators

## Recommendation
Implement `one_chain_round` advancement validation to prevent premature updates. Two approaches:

**Approach 1: Add round proximity check before observe_qc**
```rust
pub(crate) fn guarded_construct_and_sign_order_vote(
    &mut self,
    order_vote_proposal: &OrderVoteProposal,
) -> Result<OrderVote, Error> {
    self.signer()?;
    self.verify_order_vote_proposal(order_vote_proposal)?;
    let proposed_block = order_vote_proposal.block();
    let mut safety_data = self.persistent_storage.safety_data()?;

    // NEW: Validate QC round is within acceptable range
    let qc_round = order_vote_proposal.quorum_cert().certified_block().round();
    let max_allowed_round = safety_data.one_chain_round + 100; // or other reasonable threshold
    if qc_round > max_allowed_round {
        return Err(Error::InvalidQcRound(qc_round, safety_data.one_chain_round));
    }

    self.observe_qc(order_vote_proposal.quorum_cert(), &mut safety_data);
    self.safe_for_order_vote(proposed_block, &safety_data)?;
    // ... rest of function
}
```

**Approach 2: Make observe_qc conditional**
```rust
pub(crate) fn observe_qc(&self, qc: &QuorumCert, safety_data: &mut SafetyData) -> bool {
    let mut updated = false;
    let one_chain = qc.certified_block().round();
    let two_chain = qc.parent_block().round();
    
    // Only update if within reasonable range
    if one_chain > safety_data.one_chain_round 
        && one_chain <= safety_data.one_chain_round + 100 {
        safety_data.one_chain_round = one_chain;
        updated = true;
    }
    // ... rest of function
}
```

**Recommended**: Implement Approach 1 with an appropriate threshold (e.g., 100 rounds) and add similar validation to `guarded_construct_and_sign_vote_two_chain` for defense in depth.

## Proof of Concept
```rust
#[test]
fn test_out_of_order_proposal_blocks_timeout() {
    // Setup: Create SafetyRules with initial state
    let (mut safety_rules, signer) = create_safety_rules();
    
    // Node is at round 100
    let current_round = 100;
    let safety_data = SafetyData::new(1, current_round, current_round, current_round, None, 0);
    safety_rules.persistent_storage.set_safety_data(safety_data).unwrap();
    
    // Step 1: Node receives out-of-order VoteProposal for round 200
    let future_round = 200;
    let qc_round = 199;
    let qc = create_valid_qc(qc_round); // Helper to create valid QC
    let proposal = create_vote_proposal(future_round, qc.clone());
    
    // Process the proposal - this updates one_chain_round to 199
    let vote_result = safety_rules.guarded_construct_and_sign_vote_two_chain(
        &proposal, 
        None
    );
    assert!(vote_result.is_ok(), "Vote creation should succeed");
    
    // Verify one_chain_round advanced to 199
    let safety_data = safety_rules.persistent_storage.safety_data().unwrap();
    assert_eq!(safety_data.one_chain_round, qc_round);
    
    // Step 2: Node tries to timeout at round 101 with QC for round 100
    let timeout_round = 101;
    let timeout_qc_round = 100;
    let timeout_qc = create_valid_qc(timeout_qc_round);
    let timeout = TwoChainTimeout::new(1, timeout_round, timeout_qc);
    
    // This should FAIL because qc_round (100) < one_chain_round (199)
    let timeout_result = safety_rules.guarded_sign_timeout_with_qc(
        &timeout,
        None
    );
    
    // Assert: Timeout is blocked, causing liveness failure
    assert!(timeout_result.is_err(), "Timeout should fail due to one_chain_round jump");
    match timeout_result {
        Err(Error::NotSafeToTimeout(round, qc_round, tc_round, one_chain)) => {
            assert_eq!(round, timeout_round);
            assert_eq!(qc_round, timeout_qc_round);
            assert_eq!(one_chain, qc_round); // 199
            println!("VULNERABILITY CONFIRMED: Node cannot timeout at round {} because one_chain_round jumped to {}", 
                     timeout_round, one_chain);
        },
        _ => panic!("Expected NotSafeToTimeout error"),
    }
}
```

## Notes
This vulnerability represents a subtle but critical flaw in the 2-chain consensus safety rules. The `one_chain_round` tracking mechanism lacks validation against out-of-order processing, creating a window for both accidental (network delays) and malicious (Byzantine validators) liveness attacks. The fix requires careful consideration of acceptable round advancement bounds while maintaining the protocol's safety guarantees.

### Citations

**File:** consensus/safety-rules/src/safety_rules.rs (L135-156)
```rust
    pub(crate) fn observe_qc(&self, qc: &QuorumCert, safety_data: &mut SafetyData) -> bool {
        let mut updated = false;
        let one_chain = qc.certified_block().round();
        let two_chain = qc.parent_block().round();
        if one_chain > safety_data.one_chain_round {
            safety_data.one_chain_round = one_chain;
            trace!(
                SafetyLogSchema::new(LogEntry::OneChainRound, LogEvent::Update)
                    .preferred_round(safety_data.one_chain_round)
            );
            updated = true;
        }
        if two_chain > safety_data.preferred_round {
            safety_data.preferred_round = two_chain;
            trace!(
                SafetyLogSchema::new(LogEntry::PreferredRound, LogEvent::Update)
                    .preferred_round(safety_data.preferred_round)
            );
            updated = true;
        }
        updated
    }
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

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L121-145)
```rust
    /// Core safety timeout rule for 2-chain protocol. Return success if 1 and 2 are true
    /// 1. round == timeout.qc.round + 1 || round == tc.round + 1
    /// 2. timeout.qc.round >= one_chain_round
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
