# Audit Report

## Title
Undetected Validator Equivocation Due to Missing Timeout Recovery After Node Restart

## Summary
After a validator node restarts, the `timeout_sent` field in `RoundState` is not restored from persistent storage, remaining `None` even if the validator had previously broadcast a timeout for the current round. This allows the validator to create and broadcast a second, different timeout message for the same round with different consensus-critical content (different highest QC). The system fails to detect this equivocation, violating consensus safety guarantees.

## Finding Description

The vulnerability stems from asymmetric recovery of consensus state after node restart. The `RoundState` structure tracks whether a validator has sent a vote or timeout in the current round using `Option<>` fields: [1](#0-0) 

When a validator node restarts, the `RoundManager.init()` function restores the last vote but **not** the last timeout: [2](#0-1) 

The recovery data structure only includes `last_vote`, not a `last_timeout` field: [3](#0-2) 

This creates the following attack sequence:

**Phase 1 - Initial Timeout:**
1. Validator V times out in round R with highest QC for round R-5
2. Creates and broadcasts `RoundTimeout` with `hqc_round = R-5`
3. Records it locally in `timeout_sent`
4. SafetyRules persists `last_voted_round = R`

**Phase 2 - Node Restart:**
5. Validator V crashes/restarts
6. `init()` restores `vote_sent` but leaves `timeout_sent = None`
7. V's `is_timeout_sent()` now incorrectly returns false

**Phase 3 - Second Timeout (Equivocation):**
8. V receives a new QC for round R-2 (higher than R-5)
9. Upon receiving f+1 timeouts, `is_timeout_sent()` returns false
10. V calls `process_local_timeout()` again for the same round R
11. Creates a **new** `RoundTimeout` with `hqc_round = R-2` (different content!) [4](#0-3) 

12. SafetyRules signs this second timeout because `round == last_voted_round` doesn't error: [5](#0-4) 

13. V broadcasts the second timeout with different `hqc_round`

**Phase 4 - Undetected Equivocation:**
14. Other validators receive both conflicting timeouts from V
15. `insert_round_timeout()` has **no** equivocation detection (unlike `insert_vote()`): [6](#0-5) 

Compare this to vote equivocation detection which explicitly checks and returns `EquivocateVote`: [7](#0-6) 

16. The `add_signature()` method uses `or_insert()`, silently ignoring subsequent timeouts: [8](#0-7) 

The validator has successfully equivocated (signed two conflicting messages for the same round) without detection.

## Impact Explanation

This is a **High Severity** issue representing a significant consensus protocol violation. Validator equivocation is a fundamental Byzantine fault that Byzantine Fault Tolerant protocols must detect and prevent. The AptosBFT protocol assumes validators will not equivocate, or that equivocation will be detected and potentially slashed.

Key impacts:
- **Consensus Safety Violation**: Validator signs conflicting consensus messages
- **Undetected Byzantine Behavior**: No `EquivocateVote` error, no logging, no consequences
- **Potential for Exploitation**: Malicious validators could intentionally trigger restarts to equivocate
- **Trust Model Breach**: Other validators unknowingly aggregate signatures from equivocating validator

While this doesn't immediately cause consensus failure (one timeout is silently dropped), it violates the fundamental safety invariant that validators should not equivocate undetected.

## Likelihood Explanation

**Likelihood: Medium-High**

This vulnerability triggers automatically in the following realistic scenarios:
1. **Validator crash during consensus**: Common in production systems
2. **Validator restart for maintenance**: Regular operational procedure
3. **Network partition recovery**: Node reconnects after isolation
4. **Resource exhaustion causing restart**: Out of memory, disk issues

The vulnerability requires:
- Node restart between sending timeout and round completion (timing window)
- Receipt of a new higher QC after restart (common in normal operation)
- f+1 timeouts received triggering echo (standard timeout aggregation)

No malicious intent required - this happens during normal operational failures. However, a malicious validator could intentionally exploit this by triggering strategic restarts.

## Recommendation

**Fix 1: Restore timeout state during recovery**

Extend `RecoveryData` to include `last_timeout`:

```rust
pub struct RecoveryData {
    last_vote: Option<Vote>,
    last_timeout: Option<RoundTimeout>,  // Add this field
    root: RootInfo,
    // ... rest of fields
}
```

Modify `RoundManager.init()` to restore both:

```rust
pub async fn init(&mut self, last_vote_sent: Option<Vote>, last_timeout_sent: Option<RoundTimeout>) {
    let epoch_state = self.epoch_state.clone();
    let new_round_event = self
        .round_state
        .process_certificates(self.block_store.sync_info(), &epoch_state.verifier)
        .expect("Can not jump start a round_state from existing certificates.");
    if let Some(vote) = last_vote_sent {
        self.round_state.record_vote(vote);
    }
    if let Some(timeout) = last_timeout_sent {
        self.round_state.record_round_timeout(timeout);
    }
    // ... rest of init
}
```

**Fix 2: Add timeout equivocation detection**

Add equivocation check in `insert_round_timeout()`:

```rust
pub fn insert_round_timeout(
    &mut self,
    round_timeout: &RoundTimeout,
    validator_verifier: &ValidatorVerifier,
) -> VoteReceptionResult {
    // Check for duplicate author (like in insert_vote)
    if let Some(previous_timeout) = self.author_to_timeout.get(&round_timeout.author()) {
        if previous_timeout.two_chain_timeout().hqc_round() 
            != round_timeout.two_chain_timeout().hqc_round() {
            error!(
                SecurityEvent::ConsensusEquivocatingTimeout,
                remote_peer = round_timeout.author(),
                timeout = round_timeout,
                previous_timeout = previous_timeout
            );
            return VoteReceptionResult::EquivocateVote;
        }
    }
    // ... rest of function
}
```

**Fix 3: Add timeout caching in SafetyRules**

Store last timeout in SafetyData (similar to `last_vote`) and return cached timeout if signing same round again.

## Proof of Concept

```rust
#[tokio::test]
async fn test_timeout_equivocation_after_restart() {
    // Setup: Create validator node with RoundManager
    let (mut round_manager, mut network_rx) = create_test_round_manager();
    
    // Phase 1: Initial timeout
    let round = 10;
    round_manager.process_local_timeout(round).await.unwrap_err(); // Times out
    let first_timeout = network_rx.next().await.unwrap(); // Capture first timeout broadcast
    let first_hqc_round = first_timeout.timeout().two_chain_timeout().hqc_round();
    
    // Phase 2: Simulate restart - create new RoundManager with same storage
    // Note: last_timeout is NOT restored, only last_vote
    let (mut restarted_manager, mut network_rx2) = 
        create_round_manager_from_storage(round_manager.storage());
    
    // Phase 3: Receive new higher QC and trigger echo timeout
    let new_qc = create_qc_for_round(first_hqc_round + 3); // Higher than first timeout
    restarted_manager.process_qc(new_qc).await.unwrap();
    
    // Trigger echo timeout
    for i in 0..F+1 {
        let timeout_msg = create_timeout_msg(round, i);
        restarted_manager.process_round_timeout_msg(timeout_msg).await.unwrap();
    }
    
    // Phase 4: Verify second timeout was sent (equivocation!)
    let second_timeout = network_rx2.next().await.unwrap();
    let second_hqc_round = second_timeout.timeout().two_chain_timeout().hqc_round();
    
    // VULNERABILITY: Two different timeouts for same round
    assert_eq!(first_timeout.round(), second_timeout.round());
    assert_ne!(first_hqc_round, second_hqc_round);
    assert!(first_hqc_round < second_hqc_round);
    
    // VULNERABILITY: No equivocation detected
    // In correct implementation, this should have returned EquivocateVote error
    
    println!("EQUIVOCATION DETECTED: Validator sent two different timeouts for round {}:", round);
    println!("  First timeout: hqc_round = {}", first_hqc_round);
    println!("  Second timeout: hqc_round = {}", second_hqc_round);
}
```

## Notes

The root cause is the asymmetric treatment of votes versus timeouts in recovery logic. Votes are properly persisted and restored because they're stored in `SafetyData.last_vote` and `RecoveryData.last_vote`. However, timeouts only update `last_voted_round` without storing the actual timeout message, and `RoundState.timeout_sent` is purely transient state that's lost on restart.

This violates the principle that all consensus-critical state that determines whether a validator can send messages should be persisted and restored atomically with the SafetyRules state.

### Citations

**File:** consensus/src/liveness/round_state.rs (L161-163)
```rust
    vote_sent: Option<Vote>,
    // Timeout sent locally for the current round.
    timeout_sent: Option<RoundTimeout>,
```

**File:** consensus/src/round_manager.rs (L1005-1033)
```rust
        if self.local_config.enable_round_timeout_msg {
            let timeout = if let Some(timeout) = self.round_state.timeout_sent() {
                timeout
            } else {
                let timeout = TwoChainTimeout::new(
                    self.epoch_state.epoch,
                    round,
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

                let timeout_reason = self.compute_timeout_reason(round);

                RoundTimeout::new(
                    timeout,
                    self.proposal_generator.author(),
                    timeout_reason,
                    signature,
                )
            };

            self.round_state.record_round_timeout(timeout.clone());
```

**File:** consensus/src/round_manager.rs (L2018-2026)
```rust
    pub async fn init(&mut self, last_vote_sent: Option<Vote>) {
        let epoch_state = self.epoch_state.clone();
        let new_round_event = self
            .round_state
            .process_certificates(self.block_store.sync_info(), &epoch_state.verifier)
            .expect("Can not jump start a round_state from existing certificates.");
        if let Some(vote) = last_vote_sent {
            self.round_state.record_vote(vote);
        }
```

**File:** consensus/src/persistent_liveness_storage.rs (L332-345)
```rust
pub struct RecoveryData {
    // The last vote message sent by this validator.
    last_vote: Option<Vote>,
    root: RootInfo,
    root_metadata: RootMetadata,
    // 1. the blocks guarantee the topological ordering - parent <- child.
    // 2. all blocks are children of the root.
    blocks: Vec<Block>,
    quorum_certs: Vec<QuorumCert>,
    blocks_to_prune: Option<Vec<HashValue>>,

    // Liveness data
    highest_2chain_timeout_certificate: Option<TwoChainTimeoutCertificate>,
}
```

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

**File:** consensus/src/pending_votes.rs (L190-232)
```rust
    pub fn insert_round_timeout(
        &mut self,
        round_timeout: &RoundTimeout,
        validator_verifier: &ValidatorVerifier,
    ) -> VoteReceptionResult {
        //
        // Let's check if we can create a TC
        //

        let timeout = round_timeout.two_chain_timeout();
        let signature = round_timeout.signature();

        let validator_voting_power = validator_verifier
            .get_voting_power(&round_timeout.author())
            .unwrap_or(0);
        if validator_voting_power == 0 {
            warn!(
                "Received vote with no voting power, from {}",
                round_timeout.author()
            );
        }
        let cur_epoch = round_timeout.epoch();
        let cur_round = round_timeout.round();

        counters::CONSENSUS_CURRENT_ROUND_TIMEOUT_VOTED_POWER
            .with_label_values(&[&round_timeout.author().to_string()])
            .set(validator_voting_power as f64);
        counters::CONSENSUS_LAST_TIMEOUT_VOTE_EPOCH
            .with_label_values(&[&round_timeout.author().to_string()])
            .set(cur_epoch as i64);
        counters::CONSENSUS_LAST_TIMEOUT_VOTE_ROUND
            .with_label_values(&[&round_timeout.author().to_string()])
            .set(cur_round as i64);

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

**File:** consensus/src/pending_votes.rs (L287-309)
```rust
        if let Some((previously_seen_vote, previous_li_digest)) =
            self.author_to_vote.get(&vote.author())
        {
            // is it the same vote?
            if &li_digest == previous_li_digest {
                // we've already seen an equivalent vote before
                let new_timeout_vote = vote.is_timeout() && !previously_seen_vote.is_timeout();
                if !new_timeout_vote {
                    // it's not a new timeout vote
                    return VoteReceptionResult::DuplicateVote;
                }
            } else {
                // we have seen a different vote for the same round
                error!(
                    SecurityEvent::ConsensusEquivocatingVote,
                    remote_peer = vote.author(),
                    vote = vote,
                    previous_vote = previously_seen_vote
                );

                return VoteReceptionResult::EquivocateVote;
            }
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
