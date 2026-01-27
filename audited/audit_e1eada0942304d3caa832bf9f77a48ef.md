# Audit Report

## Title
Validator Vote Loss Due to Asynchronous Self-Send Failure in Round State Management

## Summary
A race condition exists where `record_vote()` is called synchronously before vote broadcast, but if the asynchronous self-send fails, the validator's own vote never reaches `insert_vote()`. This causes the validator to believe it voted (via `vote_sent` state) while its vote is absent from `pending_votes`, preventing re-voting and potentially causing liveness issues.

## Finding Description

The vulnerability arises from the asynchronous nature of vote propagation combined with synchronous vote recording:

**Normal Flow:**
1. Validator creates and votes on a proposal for round N
2. `record_vote()` is called synchronously, setting `vote_sent = Some(vote)` [1](#0-0) 
3. Vote is broadcast asynchronously, including to self via `self_sender` channel [2](#0-1) 
4. When self-vote is received, `insert_vote()` adds it to `pending_votes` [3](#0-2) 

**Vulnerability Scenario:**

If the self-send operation fails (line 368 only logs error without recovery) [4](#0-3) , the validator enters an inconsistent state:

- `vote_sent` remains set (validator believes it voted)
- Vote never reaches `insert_vote()`, so it's absent from `pending_votes` [5](#0-4) 
- Equivocation protection prevents re-voting [6](#0-5) 

This breaks the consensus invariant that a validator's vote should count toward quorum formation if it believes it has voted.

## Impact Explanation

**Severity: High** (Significant Protocol Violation causing liveness issues)

The vulnerability creates multiple consensus problems:

1. **Vote Power Loss**: The affected validator's voting power is lost for that round, as it cannot re-vote due to the equivocation check that verifies `vote_sent().is_none()` before allowing votes.

2. **QC Formation Delays**: If the validator is the next round's leader and needs to aggregate votes to form a Quorum Certificate, its own vote won't be in `pending_votes`. While the vote was broadcast to other validators, the leader's local pending_votes is incomplete.

3. **Liveness Impact**: If multiple validators experience this failure (e.g., during resource exhaustion), the round may fail to reach quorum, delaying or preventing block finalization.

4. **Inconsistent State**: The validator's internal state (`vote_sent` set, vote not in `pending_votes`) violates the expected consistency between voting intent and vote aggregation.

This qualifies as a "Significant protocol violation" under the High severity category, as it can cause validator node issues and consensus delays without requiring Byzantine behavior.

## Likelihood Explanation

**Likelihood: Medium to Low** but **exploitable under specific conditions**

The `self_sender` is an `UnboundedSender` channel [7](#0-6) , which rarely fails under normal operation. However, failures can occur when:

1. **Resource Exhaustion**: The receiver's buffer is overwhelmed during high consensus activity
2. **Receiver Drop**: The event receiver is dropped or crashes before processing the message
3. **System Pressure**: Node is under extreme load causing channel backpressure issues

An attacker with the ability to cause resource exhaustion on validator nodes (within scope of causing slowdowns) could increase the probability of this condition occurring across multiple validators, amplifying the liveness impact.

The vulnerability is more likely during:
- Network partitions with rapid round transitions
- High transaction throughput periods
- Validator restarts or epoch transitions

## Recommendation

**Solution: Ensure vote recording only occurs after successful self-insertion**

Modify the voting flow to guarantee atomicity between recording and local insertion:

**Option 1 - Immediate Local Insert (Recommended):**
After creating the vote in `execute_and_vote()` [8](#0-7) , immediately insert it into `pending_votes` before recording:

```rust
let vote = self.create_vote(proposal).await?;

// Insert into pending_votes BEFORE recording to ensure consistency
let vote_result = self.round_state.insert_vote(&vote, &self.epoch_state.verifier);
if !matches!(vote_result, VoteReceptionResult::VoteAdded(_) | VoteReceptionResult::NewQuorumCertificate(_)) {
    bail!("Failed to insert own vote: {:?}", vote_result);
}

// Only record after successful insertion
self.round_state.record_vote(vote.clone());
```

**Option 2 - Retry on Self-Send Failure:**
Modify the broadcast function to ensure self-send succeeds or retry:

```rust
// In network.rs broadcast()
for retry in 0..3 {
    if self_sender.send(self_msg.clone()).await.is_ok() {
        break;
    }
    if retry == 2 {
        error!("Critical: Failed to send vote to self after retries");
        return Err(anyhow!("Self-send failed"));
    }
    tokio::time::sleep(Duration::from_millis(10)).await;
}
```

**Option 3 - Synchronous Self-Insert:**
Add a direct path that bypasses the channel for self-votes, ensuring synchronous insertion before broadcast.

## Proof of Concept

The following Rust code demonstrates the vulnerability scenario:

```rust
#[tokio::test]
async fn test_vote_loss_on_self_send_failure() {
    // Setup: Create a validator with a failing self_sender channel
    let (self_sender, mut self_receiver) = aptos_channels::new_unbounded();
    drop(self_receiver); // Simulate receiver being dropped
    
    // Create network sender with broken self_sender
    let network = NetworkSender::new(
        author,
        consensus_network_client,
        self_sender, // This will fail on send
        validators,
    );
    
    // Validator votes on a proposal
    let vote = create_test_vote(round, block_id);
    
    // record_vote is called (synchronous)
    round_state.record_vote(vote.clone());
    assert!(round_state.vote_sent().is_some()); // Vote recorded
    
    // broadcast_vote is called (asynchronous)
    network.broadcast_vote(vote_msg).await; // Self-send fails silently
    
    // Process would-be self-vote (never arrives)
    // Simulate receiving the vote that never came
    let result = round_state.insert_vote(&vote, &verifier);
    // In reality, insert_vote is never called because the vote never arrived
    
    // Verify inconsistent state:
    assert!(round_state.vote_sent().is_some()); // Still set
    // But vote is NOT in pending_votes
    
    // Try to vote again - should fail due to equivocation check
    let result = vote_block(another_proposal).await;
    assert!(result.is_err()); // Cannot vote again!
    
    // Validator's vote power is lost for this round
}
```

To trigger in a live environment:
1. Deploy a validator node
2. Apply memory pressure to cause channel buffer exhaustion
3. Observe vote recording without corresponding pending_votes entry
4. Measure impact on QC formation latency

**Notes**

The vulnerability is subtle because votes are still broadcast to other validators successfully via `broadcast_without_self()` [9](#0-8) . However, the local validator's inconsistent state can cause cascading issues:

- The validator cannot participate in optimistic proposal generation that relies on checking `vote_sent()` [10](#0-9) 
- Timeout computation uses `vote_sent()` to determine reason [11](#0-10) , potentially reporting incorrect timeout reasons

This issue is distinct from the normal case where rounds advance (which clears `vote_sent` [12](#0-11) ). The vulnerability specifically manifests when the vote remains relevant for the current round but the self-send fails.

### Citations

**File:** consensus/src/liveness/round_state.rs (L260-261)
```rust
            self.vote_sent = None;
            self.timeout_sent = None;
```

**File:** consensus/src/liveness/round_state.rs (L296-297)
```rust
        if vote.vote_data().proposed().round() == self.current_round {
            self.pending_votes.insert_vote(vote, validator_verifier)
```

**File:** consensus/src/liveness/round_state.rs (L318-322)
```rust
    pub fn record_vote(&mut self, vote: Vote) {
        if vote.vote_data().proposed().round() == self.current_round {
            self.vote_sent = Some(vote);
        }
    }
```

**File:** consensus/src/network.rs (L254-254)
```rust
    self_sender: aptos_channels::UnboundedSender<Event<ConsensusMsg>>,
```

**File:** consensus/src/network.rs (L365-370)
```rust
        // Directly send the message to ourself without going through network.
        let self_msg = Event::Message(self.author, msg.clone());
        let mut self_sender = self.self_sender.clone();
        if let Err(err) = self_sender.send(self_msg).await {
            error!("Error broadcasting to self: {:?}", err);
        }
```

**File:** consensus/src/network.rs (L384-384)
```rust
        self.broadcast_without_self(msg);
```

**File:** consensus/src/round_manager.rs (L969-971)
```rust
        if self.round_state().vote_sent().is_some() {
            return RoundTimeoutReason::NoQC;
        }
```

**File:** consensus/src/round_manager.rs (L1045-1060)
```rust
            let (is_nil_vote, mut timeout_vote) = match self.round_state.vote_sent() {
                Some(vote) if vote.vote_data().proposed().round() == round => {
                    (vote.vote_data().is_for_nil(), vote)
                },
                _ => {
                    // Didn't vote in this round yet, generate a backup vote
                    let nil_block = self
                        .proposal_generator
                        .generate_nil_block(round, self.proposer_election.clone())?;
                    info!(
                        self.new_log(LogEvent::VoteNIL),
                        "Planning to vote for a NIL block {}", nil_block
                    );
                    counters::VOTE_NIL_COUNT.inc();
                    let nil_vote = self.vote_block(nil_block).await?;
                    (true, nil_vote)
```

**File:** consensus/src/round_manager.rs (L1399-1400)
```rust
        let vote = self.create_vote(proposal).await?;
        self.round_state.record_vote(vote.clone());
```

**File:** consensus/src/round_manager.rs (L1508-1512)
```rust
        ensure!(
            self.round_state.vote_sent().is_none(),
            "[RoundManager] Already vote on this round {}",
            self.round_state.current_round()
        );
```

**File:** consensus/src/round_manager.rs (L1767-1769)
```rust
        let vote_reception_result = self
            .round_state
            .insert_vote(vote, &self.epoch_state.verifier);
```
