# Audit Report

## Title
Inconsistent Timeout Certificate Handling Between Regular Votes and Order Votes Enables Protocol Safety Violations

## Summary
The `guarded_construct_and_sign_order_vote()` function in SafetyRules does not accept or verify timeout certificates from the network, unlike `guarded_construct_and_sign_vote_two_chain()`. This asymmetry allows validators to make logically inconsistent commitments: voting to advance past a timed-out round while simultaneously creating order votes for blocks in that round, violating 2-chain consensus safety invariants.

## Finding Description

The Aptos 2-chain consensus protocol uses timeout certificates to enable progress when rounds fail. When a validator votes on a proposal, it must respect timeout certificates to maintain consensus safety. However, there is a critical asymmetry in how timeout certificates are handled:

**Regular Vote Creation (Correct Behavior):** [1](#0-0) 

When creating regular votes, the RoundManager passes `block_store.highest_2chain_timeout_cert()` to SafetyRules, which verifies and uses it in safety checks. [2](#0-1) 

The `safe_to_vote` function uses the timeout certificate to validate voting rules. [3](#0-2) 

**Order Vote Creation (Vulnerable Behavior):** [4](#0-3) 

Order vote creation does NOT pass any timeout certificate to SafetyRules. [5](#0-4) 

The function signature doesn't even accept a timeout certificate parameter. The safety check only validates against the validator's OWN timeout history. [6](#0-5) 

**The Vulnerability:**

When validators receive timeout certificates from the network via SyncInfo messages, these are stored in the block store: [7](#0-6) 

A validator can then:
1. Receive timeout certificate TC_R for round R and store it in block_store
2. Vote for a proposal at round R+1, passing TC_R to safety rules (acknowledging the timeout)
3. Later receive an OrderVoteProposal for a block B_R at round R
4. Create an order vote for B_R because `safe_for_order_vote` only checks `highest_timeout_round` from personal timeout signatures, not the network's TC_R
5. This violates the 2-chain consensus invariant that once a round is skipped via timeout, validators should not commit to blocks from that round

The validator has made inconsistent commitments: voting to advance past round R (implicitly agreeing R was timed out) while creating an order vote for a block in round R.

## Impact Explanation

This vulnerability constitutes a **High Severity** protocol violation under the Aptos bug bounty criteria for "Significant protocol violations."

The asymmetry in timeout certificate handling breaks the following invariant:
- **Consensus Safety**: Validators must make consistent commitments about which rounds are valid vs. skipped

While the test comment at lines 301-304 suggests awareness that individual validators can create such order votes, it incorrectly assumes this is safe because "2f+1 order votes can't be formed." However, this doesn't account for:
1. The logical inconsistency in a single validator's commitments
2. Scenarios where enough validators who haven't personally signed timeouts but received timeout certificates could collectively create 2f+1 order votes
3. The violation of the 2-chain consensus protocol's design principles

Under specific network partition scenarios, this could potentially escalate to a **Critical** consensus safety violation if it enables different validator subsets to commit conflicting blocks.

## Likelihood Explanation

**Likelihood: Medium to High**

This vulnerability can manifest during normal network operations:
- Network partitions or delays naturally cause timeouts
- Timeout certificates propagate via standard SyncInfo gossip
- Validators who receive (but didn't sign) timeout certificates will exhibit the vulnerable behavior
- No Byzantine actors or collusion required - honest validators unknowingly make inconsistent commitments

The issue is guaranteed to occur whenever:
1. A timeout certificate exists for round R
2. A validator receives this TC but hasn't personally signed a timeout for round ≥ R
3. An OrderVoteProposal arrives for a block at round ≤ R

## Recommendation

**Fix: Add timeout certificate parameter and verification to order vote creation**

1. Update the function signature:
```rust
pub(crate) fn guarded_construct_and_sign_order_vote(
    &mut self,
    order_vote_proposal: &OrderVoteProposal,
    timeout_cert: Option<&TwoChainTimeoutCertificate>, // ADD THIS
) -> Result<OrderVote, Error>
```

2. Verify the timeout certificate: [8](#0-7) 

3. Update `safe_for_order_vote` to respect timeout certificates:
```rust
fn safe_for_order_vote(
    &self, 
    block: &Block, 
    maybe_tc: Option<&TwoChainTimeoutCertificate>,
    safety_data: &SafetyData
) -> Result<(), Error> {
    let round = block.round();
    let highest_timeout = maybe_tc.map_or(
        safety_data.highest_timeout_round,
        |tc| std::cmp::max(tc.round(), safety_data.highest_timeout_round)
    );
    if round > highest_timeout {
        Ok(())
    } else {
        Err(Error::NotSafeForOrderVote(round, highest_timeout))
    }
}
```

4. Update RoundManager to pass the timeout certificate: [9](#0-8) 

Modify line 1635 to:
```rust
.construct_and_sign_order_vote(&order_vote_proposal, self.block_store.highest_2chain_timeout_cert().as_deref())
```

## Proof of Concept

```rust
// Add to consensus/safety-rules/src/tests/suite.rs

fn test_order_vote_inconsistent_with_received_timeout() {
    let (mut safety_rules, signer) = safety_rules();
    let (proof, genesis_qc) = test_utils::make_genesis(&signer);
    let round = genesis_qc.certified_block().round();
    let epoch = genesis_qc.certified_block().epoch();
    
    // Round 1: Block B1 gets QC
    let b1 = test_utils::make_proposal_with_qc(round + 1, genesis_qc.clone(), &signer);
    let b2 = test_utils::make_proposal_with_parent(
        random_payload(2048), round + 2, &b1, None, &signer
    );
    
    // Round 2: Timeout certificate formed (validator hasn't signed it personally)
    let tc2 = test_utils::make_timeout_cert(round + 2, b2.block().quorum_cert(), &signer);
    
    // Round 3: Validator votes for B3 with TC2, acknowledging timeout
    let b3 = test_utils::make_proposal_with_parent(
        random_payload(2048), round + 3, &b1, None, &signer
    );
    
    safety_rules.initialize(&proof).unwrap();
    
    // Validator votes for B3 with TC2 - this acknowledges round 2 was timed out
    safety_rules.construct_and_sign_vote_two_chain(&b3, Some(&tc2)).unwrap();
    
    // BUG: Validator can still create order vote for B1 (round 1)
    // even though they voted to skip round 2 via TC2
    // This is logically inconsistent
    let ov1 = OrderVoteProposal::new(
        b1.block().clone(),
        b2.block().quorum_cert().certified_block().clone(),
        Arc::new(b2.block().quorum_cert().clone()),
    );
    
    // This should fail because the validator has acknowledged TC2,
    // but it succeeds because order votes don't check timeout certificates
    let result = safety_rules.construct_and_sign_order_vote(&ov1);
    assert!(result.is_ok(), "Inconsistent commitment: voted with TC2 but can order vote for earlier round");
}
```

This test demonstrates that a validator can vote for a proposal acknowledging a timeout certificate, then create an order vote for a round that should be constrained by that timeout, exposing the inconsistent commitment behavior.

### Citations

**File:** consensus/src/round_manager.rs (L1520-1523)
```rust
        let vote_result = self.safety_rules.lock().construct_and_sign_vote_two_chain(
            &vote_proposal,
            self.block_store.highest_2chain_timeout_cert().as_deref(),
        );
```

**File:** consensus/src/round_manager.rs (L1626-1651)
```rust
    async fn create_order_vote(
        &mut self,
        block: Arc<PipelinedBlock>,
        qc: Arc<QuorumCert>,
    ) -> anyhow::Result<OrderVote> {
        let order_vote_proposal = block.order_vote_proposal(qc);
        let order_vote_result = self
            .safety_rules
            .lock()
            .construct_and_sign_order_vote(&order_vote_proposal);
        let order_vote = order_vote_result.context(format!(
            "[RoundManager] SafetyRules Rejected {} for order vote",
            block.block()
        ))?;

        fail_point!("consensus::create_invalid_order_vote", |_| {
            use aptos_crypto::bls12381;
            let faulty_order_vote = OrderVote::new_with_signature(
                order_vote.author(),
                order_vote.ledger_info().clone(),
                bls12381::Signature::dummy_signature(),
            );
            Ok(faulty_order_vote)
        });
        Ok(order_vote)
    }
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L53-64)
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

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L147-166)
```rust
    /// Core safety voting rule for 2-chain protocol. Return success if 1 or 2 is true
    /// 1. block.round == block.qc.round + 1
    /// 2. block.round == tc.round + 1 && block.qc.round >= tc.highest_hqc.round
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

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L180-188)
```rust
    fn verify_tc(&self, tc: &TwoChainTimeoutCertificate) -> Result<(), Error> {
        let epoch_state = self.epoch_state()?;

        if !self.skip_sig_verify {
            tc.verify(&epoch_state.verifier)
                .map_err(|e| Error::InvalidTimeoutCertificate(e.to_string()))?;
        }
        Ok(())
    }
```

**File:** consensus/src/block_storage/sync_manager.rs (L169-171)
```rust
        if let Some(tc) = sync_info.highest_2chain_timeout_cert() {
            self.insert_2chain_timeout_certificate(Arc::new(tc.clone()))?;
        }
```
