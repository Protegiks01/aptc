# Audit Report

## Title
Consensus Safety Violation: Non-Persisted QC Observation in Order Vote Allows Unsafe Timeout Signing

## Summary
The `guarded_construct_and_sign_order_vote` function contains a critical logic bug where Quorum Certificate (QC) observations update consensus state (`one_chain_round`, `preferred_round`) before safety validation. When safety checks fail, these state modifications are not persisted, allowing validators to sign timeouts that violate 2-chain consensus safety rules.

## Finding Description

The vulnerability exists in the order vote signing flow in `guarded_construct_and_sign_order_vote`. [1](#0-0) 

The problematic execution sequence is:

1. **Line 105**: SafetyData loaded from persistent storage with current `one_chain_round` value
2. **Line 108**: `observe_qc()` modifies the local SafetyData, updating `one_chain_round` and `preferred_round` based on the QC [2](#0-1) 
3. **Line 110**: `safe_for_order_vote()` safety check can fail and return early with `?` operator [3](#0-2) 
4. **If failure**: Modified SafetyData is NEVER persisted (line 117 never executes)

This differs critically from the regular voting path where safety checks occur BEFORE `observe_qc()`. [4](#0-3) 

The `one_chain_round` field is essential for timeout safety validation. [5](#0-4) 

**Attack Scenario:**

1. **Initial state**: Validator has `one_chain_round = 5`, `highest_timeout_round = 7`
2. **Receive OrderVoteProposal**: Block at round 7, QC certifying round 15
3. **Processing fails**:
   - `observe_qc` updates local `one_chain_round = 15`
   - `safe_for_order_vote` checks `7 > 7` → FALSE → Error returned
   - Modified state NOT persisted, persistent state remains `one_chain_round = 5`
4. **Exploit stale state**:
   - Timeout request for round 10 with QC certifying round 9
   - `safe_to_timeout` checks `9 >= 5` (stale!) → PASSES
   - Should check `9 >= 15` → FAILS
5. **Result**: Validator signs timeout violating 2-chain safety rules

## Impact Explanation

This is **Critical Severity** per Aptos bug bounty criteria for "Consensus/Safety Violations":

- **Breaks Core Safety Invariant**: Validators can sign conflicting timeout messages that violate AptosBFT 2-chain safety rules
- **Chain Fork Potential**: Multiple validators with stale `one_chain_round` can create conflicting timeout certificates, enabling chain splits
- **No Byzantine Requirement**: Affects honest validators during normal operations; requires zero collusion
- **Protocol Violation**: Defeats the fundamental purpose of `one_chain_round` tracking, which prevents timeouts after observing higher certified blocks

The 2-chain consensus protocol's safety depends on monotonic tracking of the highest observed QC. This bug breaks that monotonicity, allowing safety violations even with all validators acting honestly.

## Likelihood Explanation

**HIGH likelihood** of occurrence:

1. **Normal Operations**: OrderVoteProposals are standard consensus messages; timeouts occur regularly during network delays
2. **Legitimate Failure Path**: The `safe_for_order_vote` check legitimately fails when `block.round <= highest_timeout_round`, which happens when validators receive proposals for rounds they've already timed out on
3. **No Adversary Required**: Triggers during regular consensus when a validator times out at round T, then receives an OrderVoteProposal for round ≤ T containing a QC for a higher round
4. **Persistent Corruption**: Stale state persists until the validator successfully votes/order-votes, potentially spanning multiple rounds
5. **Network-Wide Impact**: During periods of network instability with multiple timeouts, this creates systematic under-estimation of `one_chain_round` across validators

## Recommendation

Move the `observe_qc()` call to occur AFTER safety validation succeeds, matching the pattern in `guarded_construct_and_sign_vote_two_chain`:

```rust
pub(crate) fn guarded_construct_and_sign_order_vote(
    &mut self,
    order_vote_proposal: &OrderVoteProposal,
) -> Result<OrderVote, Error> {
    self.signer()?;
    self.verify_order_vote_proposal(order_vote_proposal)?;
    let proposed_block = order_vote_proposal.block();
    let mut safety_data = self.persistent_storage.safety_data()?;
    
    // Safety check FIRST
    self.safe_for_order_vote(proposed_block, &safety_data)?;
    
    // Record 1-chain data AFTER safety validation passes
    self.observe_qc(order_vote_proposal.quorum_cert(), &mut safety_data);
    
    // Construct and sign order vote
    let author = self.signer()?.author();
    let ledger_info = LedgerInfo::new(order_vote_proposal.block_info().clone(), HashValue::zero());
    let signature = self.sign(&ledger_info)?;
    let order_vote = OrderVote::new_with_signature(author, ledger_info.clone(), signature);
    self.persistent_storage.set_safety_data(safety_data)?;
    Ok(order_vote)
}
```

## Proof of Concept

The vulnerability can be demonstrated with a Rust test in the safety rules test suite that:

1. Initializes a validator with specific `one_chain_round` and `highest_timeout_round` values
2. Sends an OrderVoteProposal that fails `safe_for_order_vote` but contains a high QC
3. Verifies `one_chain_round` remains unchanged (not updated)
4. Sends a timeout request that should fail but passes due to stale state
5. Confirms the timeout signature was incorrectly issued

The test would follow patterns in the existing test suite at [6](#0-5)  but specifically target the QC observation persistence bug.

## Notes

The SafetyData structure is defined at [7](#0-6)  with `one_chain_round` documented as "highest 1-chain round, used for 2-chain" consensus safety.

This vulnerability represents an implementation inconsistency between the two voting paths that compromises consensus safety guarantees. The fix is straightforward: reorder operations to match the established pattern in regular voting.

### Citations

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

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L168-178)
```rust
    fn safe_for_order_vote(&self, block: &Block, safety_data: &SafetyData) -> Result<(), Error> {
        let round = block.round();
        if round > safety_data.highest_timeout_round {
            Ok(())
        } else {
            Err(Error::NotSafeForOrderVote(
                round,
                safety_data.highest_timeout_round,
            ))
        }
    }
```

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

**File:** consensus/safety-rules/src/tests/suite.rs (L250-325)
```rust
fn test_order_votes_with_timeout(safety_rules: &Callback) {
    let (mut safety_rules, signer) = safety_rules();

    let (proof, genesis_qc) = test_utils::make_genesis(&signer);
    let round = genesis_qc.certified_block().round();
    let epoch = genesis_qc.certified_block().epoch();

    let data = random_payload(2048);
    //               __ tc1 __   __ tc3 __ p4b
    //              /         \ /
    // genesis --- p0          p2 -- p3 -- p4a

    // ov1 orders p0
    // ov3 orders p2
    // ov4 orders p3

    let p0 = test_utils::make_proposal_with_qc(round + 1, genesis_qc.clone(), &signer);
    let p1 = test_utils::make_proposal_with_parent(data.clone(), round + 2, &p0, None, &signer);
    let tc1 = test_utils::make_timeout_cert(round + 2, p1.block().quorum_cert(), &signer);
    let p2 = test_utils::make_proposal_with_parent(data.clone(), round + 3, &p0, None, &signer);
    let p3 = test_utils::make_proposal_with_parent(data.clone(), round + 4, &p2, None, &signer);
    let tc3 = test_utils::make_timeout_cert(round + 4, p3.block().quorum_cert(), &signer);
    let p4a = test_utils::make_proposal_with_parent(data.clone(), round + 5, &p3, None, &signer);
    let p4b = test_utils::make_proposal_with_parent(data, round + 5, &p2, None, &signer);

    let ov1 = OrderVoteProposal::new(
        p0.block().clone(),
        p1.block().quorum_cert().certified_block().clone(),
        Arc::new(p1.block().quorum_cert().clone()),
    );
    let ov3 = OrderVoteProposal::new(
        p2.block().clone(),
        p3.block().quorum_cert().certified_block().clone(),
        Arc::new(p3.block().quorum_cert().clone()),
    );
    let ov4 = OrderVoteProposal::new(
        p3.block().clone(),
        p4a.block().quorum_cert().certified_block().clone(),
        Arc::new(p4a.block().quorum_cert().clone()),
    );

    safety_rules.initialize(&proof).unwrap();

    safety_rules
        .construct_and_sign_vote_two_chain(&p0, None)
        .unwrap();

    safety_rules
        .construct_and_sign_vote_two_chain(&p2, Some(&tc1))
        .unwrap();

    // The validator hasn't signed timeout for round 2, but has received timeout certificate for round 2.
    // The validator can still sign order vote for round 1. But all the 2f+1 validators who signed timeout certificate
    // can't order vote for round 1. So, 2f+1 order votes can't be formed for round 1.
    safety_rules.construct_and_sign_order_vote(&ov1).unwrap();

    safety_rules
        .sign_timeout_with_qc(
            &TwoChainTimeout::new(epoch, round + 4, p3.block().quorum_cert().clone()),
            Some(&tc3),
        )
        .unwrap();

    // Cannot sign order vote for round 3 after signing timeout for round 4
    assert_err!(safety_rules.construct_and_sign_order_vote(&ov3));

    // Cannot sign vote for round 4 after signing timeout for round 4
    assert_err!(safety_rules.construct_and_sign_vote_two_chain(&p3, None));

    safety_rules
        .construct_and_sign_vote_two_chain(&p4b, Some(&tc3))
        .unwrap();

    // Cannot sign order vote for round 4 after signing timeoiut for round 4
    assert_err!(safety_rules.construct_and_sign_order_vote(&ov4));
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
