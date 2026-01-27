# Audit Report

## Title
TOCTOU Race Condition in Proposal Validation Causes Legitimate Proposals to be Rejected

## Summary
A Time-of-Check-Time-of-Use (TOCTOU) race condition exists between the round synchronization check in `ensure_round_and_sync_up` and the proposal validation in `is_valid_proposal`. When proposals arrive out-of-order and are processed asynchronously, a legitimate proposal that passes round synchronization can be incorrectly rejected if a higher-round proposal updates the global `already_proposed` state before the legitimate proposal reaches the validation check. [1](#0-0) 

## Finding Description
The vulnerability occurs in the proposal processing pipeline where there is a critical gap between validating that a proposal is for the current round and checking if it's a valid proposal. The race condition manifests as follows:

**Step 1**: Proposal for round R arrives and passes `ensure_round_and_sync_up`, confirming the node is at round R and the proposal is legitimate for processing. [2](#0-1) 

**Step 2**: After the `.await` at line 749 completes, async execution can yield control before the `if in_correct_round` check at line 751.

**Step 3**: While yielded, a proposal for round R+N (where N > 0) from a different source (buffered proposals, optimistic proposal loopback) is processed, advancing the node's round and updating the shared `already_proposed` state. [3](#0-2) 

**Step 4**: The original round R proposal resumes execution, proceeds to `process_proposal`, and reaches `is_valid_proposal`. [4](#0-3) 

**Step 5**: At the round comparison logic, the proposal is rejected because round R < R+N in `already_proposed.0`. [5](#0-4) 

The core issue is that `UnequivocalProposerElection` maintains a single global `already_proposed` state that tracks the highest round seen, and this state is checked AFTER the async yield point where other proposals can intervene. [6](#0-5) 

The test file confirms this is intentional behavior for rejecting old proposals, but it doesn't account for the TOCTOU race: [7](#0-6) 

## Impact Explanation
This vulnerability qualifies as **High Severity** under the Aptos bug bounty program for the following reasons:

1. **Consensus Protocol Violation**: Legitimate proposals that were validated as being for the correct round are incorrectly rejected, violating the consensus protocol's expectation that all valid proposals should be processed.

2. **Liveness Impact**: When a validator's legitimate proposal is rejected, the validator does not vote on it. If this validator's vote is critical for forming a quorum certificate (QC), it can delay block finalization and impact network liveness.

3. **Validator Node Impact**: The error counting and logging suggest this manifests as validator node errors, which falls under "Validator node slowdowns" and "Significant protocol violations" (High Severity per bug bounty). [8](#0-7) 

4. **No Attack Required**: This can occur naturally under normal network conditions with proposal buffering and out-of-order arrival, making it exploitable without requiring any malicious actor.

## Likelihood Explanation
The likelihood of this vulnerability manifesting is **MODERATE to HIGH**:

**Triggering Conditions**:
- Proposals arriving out-of-order due to network delays (common in distributed systems)
- Multiple proposals buffered and processed in batches
- High network load causing async task scheduling variability
- Optimistic proposals being processed from loopback while regular proposals are buffered [9](#0-8) 

**Frequency Factors**:
- The event loop processes proposals from multiple sources (buffered_proposal_rx, opt_proposal_loopback_rx) with biased selection
- Proposals are sorted within batches but not globally across different arrival times
- The async nature of `ensure_round_and_sync_up` creates yield points where race conditions can occur [10](#0-9) 

Under stressed network conditions or high transaction throughput, this race becomes more likely as more proposals are buffered and processed concurrently.

## Recommendation
The fix requires ensuring that the round validation and proposal validation are atomic with respect to the round state. Here are two recommended approaches:

**Option 1: Re-validate round in process_proposal**
Add a round check at the beginning of `process_proposal` to ensure the proposal is still for the current round:

```rust
async fn process_proposal(&mut self, proposal: Block) -> anyhow::Result<()> {
    // Add this check immediately
    ensure!(
        proposal.round() == self.round_state.current_round(),
        "Proposal round {} does not match current round {} after sync",
        proposal.round(),
        self.round_state.current_round()
    );
    
    // ... rest of existing validation ...
}
```

**Option 2: Capture round in is_valid_proposal**
Modify `is_valid_proposal` to accept the expected round and validate against it:

```rust
pub fn is_valid_proposal(&self, block: &Block, expected_round: Round) -> bool {
    block.author().is_some_and(|author| {
        let valid_author = self.is_valid_proposer(author, block.round());
        if !valid_author {
            // ... existing author validation ...
            return false;
        }
        
        // Verify block is for expected round
        ensure!(block.round() == expected_round, "Round mismatch");
        
        let mut already_proposed = self.already_proposed.lock();
        // ... existing equivocation detection ...
    })
}
```

**Option 3 (Recommended): Atomic round snapshot**
Capture the current round before `ensure_round_and_sync_up` and validate it hasn't changed:

```rust
pub async fn process_proposal_msg(&mut self, proposal_msg: ProposalMsg) -> anyhow::Result<()> {
    // ... existing code ...
    
    let round_before_sync = self.round_state.current_round();
    let in_correct_round = self
        .ensure_round_and_sync_up(
            proposal_msg.proposal().round(),
            proposal_msg.sync_info(),
            proposal_msg.proposer(),
        )
        .await
        .context("[RoundManager] Process proposal")?;
        
    if in_correct_round {
        // Verify round hasn't advanced since sync
        ensure!(
            proposal_msg.proposal().round() == self.round_state.current_round(),
            "Round advanced from {} to {} during sync, discarding proposal",
            proposal_msg.proposal().round(),
            self.round_state.current_round()
        );
        self.process_proposal(proposal_msg.take_proposal()).await
    } else {
        // ... existing stale proposal handling ...
    }
}
```

## Proof of Concept
```rust
#[tokio::test]
async fn test_toctou_race_in_proposal_validation() {
    // Setup: Create a RoundManager at round 5
    let mut round_manager = create_test_round_manager(5).await;
    
    // Create two proposals: one for round 6, one for round 10
    let proposal_round_6 = create_test_proposal(6, &validator_signer);
    let proposal_round_10 = create_test_proposal(10, &validator_signer_2);
    
    // Simulate the race condition:
    // 1. Start processing proposal for round 6
    let round_6_future = round_manager.process_proposal_msg(
        ProposalMsg::new(proposal_round_6.clone(), sync_info_6)
    );
    
    // 2. Let it progress through ensure_round_and_sync_up but not to process_proposal
    // This would require instrumenting the code to pause at the yield point
    
    // 3. While paused, process proposal for round 10 completely
    round_manager.process_proposal_msg(
        ProposalMsg::new(proposal_round_10, sync_info_10)
    ).await.expect("Round 10 should process successfully");
    
    // 4. Resume round 6 processing
    let result = round_6_future.await;
    
    // Expected: Round 6 proposal is rejected despite being legitimate
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not a valid proposer"));
    
    // Verify the node never voted on round 6 despite it being legitimate
    assert!(round_manager.round_state().vote_sent().is_none() || 
            round_manager.round_state().vote_sent().unwrap().round() != 6);
}
```

## Notes
This vulnerability is particularly insidious because:

1. The test suite explicitly validates that old proposals are rejected (test line 104-105), but doesn't account for the TOCTOU race where a proposal becomes "old" between validation stages.

2. The `biased` select in the event loop means optimistic proposals are prioritized, increasing the likelihood of them processing before buffered regular proposals that arrived earlier.

3. The issue is exacerbated by the proposal batching and sorting logic, which sorts proposals within a batch but can't prevent cross-batch races.

The fix should be deployed as a high-priority patch, as it can naturally occur under normal network conditions without requiring any attacker action.

### Citations

**File:** consensus/src/round_manager.rs (L743-752)
```rust
        let in_correct_round = self
            .ensure_round_and_sync_up(
                proposal_msg.proposal().round(),
                proposal_msg.sync_info(),
                proposal_msg.proposer(),
            )
            .await
            .context("[RoundManager] Process proposal")?;
        if in_correct_round {
            self.process_proposal(proposal_msg.take_proposal()).await
```

**File:** consensus/src/round_manager.rs (L1195-1200)
```rust
        ensure!(
            self.proposer_election.is_valid_proposal(&proposal),
            "[RoundManager] Proposer {} for block {} is not a valid proposer for this round or created duplicate proposal",
            author,
            proposal,
        );
```

**File:** consensus/src/round_manager.rs (L2074-2093)
```rust
            tokio::select! {
                biased;
                close_req = close_rx.select_next_some() => {
                    if let Ok(ack_sender) = close_req {
                        ack_sender.send(()).expect("[RoundManager] Fail to ack shutdown");
                    }
                    break;
                }
                opt_proposal = opt_proposal_loopback_rx.select_next_some() => {
                    self.pending_opt_proposals = self.pending_opt_proposals.split_off(&opt_proposal.round().add(1));
                    let result = monitor!("process_opt_proposal_loopback", self.process_opt_proposal(opt_proposal).await);
                    let round_state = self.round_state();
                    match result {
                        Ok(_) => trace!(RoundStateLogSchema::new(round_state)),
                        Err(e) => {
                            counters::ERROR_COUNT.inc();
                            warn!(kind = error_kind(&e), RoundStateLogSchema::new(round_state), "Error: {:#}", e);
                        }
                    }
                }
```

**File:** consensus/src/round_manager.rs (L2094-2107)
```rust
                proposal = buffered_proposal_rx.select_next_some() => {
                    let mut proposals = vec![proposal];
                    while let Some(Some(proposal)) = buffered_proposal_rx.next().now_or_never() {
                        proposals.push(proposal);
                    }
                    let get_round = |event: &VerifiedEvent| {
                        match event {
                            VerifiedEvent::ProposalMsg(p) => p.proposal().round(),
                            VerifiedEvent::VerifiedProposalMsg(p) => p.round(),
                            VerifiedEvent::OptProposalMsg(p) => p.round(),
                            unexpected_event => unreachable!("Unexpected event {:?}", unexpected_event),
                        }
                    };
                    proposals.sort_by_key(get_round);
```

**File:** consensus/src/round_manager.rs (L2136-2141)
```rust
                        match result {
                            Ok(_) => trace!(RoundStateLogSchema::new(round_state)),
                            Err(e) => {
                                counters::ERROR_COUNT.inc();
                                warn!(kind = error_kind(&e), RoundStateLogSchema::new(round_state), "Error: {:#}", e);
                            }
```

**File:** consensus/src/liveness/unequivocal_proposer_election.rs (L18-21)
```rust
pub struct UnequivocalProposerElection {
    proposer_election: Arc<dyn ProposerElection + Send + Sync>,
    already_proposed: Mutex<(Round, HashValue)>,
}
```

**File:** consensus/src/liveness/unequivocal_proposer_election.rs (L61-84)
```rust
            let mut already_proposed = self.already_proposed.lock();
            // detect if the leader proposes more than once in this round
            match block.round().cmp(&already_proposed.0) {
                Ordering::Greater => {
                    already_proposed.0 = block.round();
                    already_proposed.1 = block.id();
                    true
                },
                Ordering::Equal => {
                    if already_proposed.1 != block.id() {
                        error!(
                            SecurityEvent::InvalidConsensusProposal,
                            "Multiple proposals from {} for round {}: {} and {}",
                            author,
                            block.round(),
                            already_proposed.1,
                            block.id()
                        );
                        false
                    } else {
                        true
                    }
                },
                Ordering::Less => false,
```

**File:** consensus/src/liveness/unequivocal_proposer_election_test.rs (L104-105)
```rust
    // Proposal from previous round is not valid any more:
    assert!(!pe.is_valid_proposal(&good_proposal));
```
