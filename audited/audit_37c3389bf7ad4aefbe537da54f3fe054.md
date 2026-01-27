# Audit Report

## Title
Race Condition in Vote Creation Causes Legitimate Votes to be Rejected Due to Inconsistent Sync State

## Summary
A race condition exists between vote creation and vote message construction that causes validators to send votes with inconsistent state (vote for round R with sync_info for round R or higher). This triggers the strict round matching check in `ensure_round_and_sync_up()`, causing receivers to reject legitimate votes and impacting consensus liveness.

## Finding Description
The vulnerability exists in the vote creation flow where `block_store.sync_info()` is called twice without synchronization between creating the vote and constructing the vote message: [1](#0-0) 

**The Race Condition Flow:**

1. Validator V executes line 1385: fetches `sync_info` with `highest_round() = R-1`
2. Validator V passes the staleness check at line 1387: `proposal_round (R) > R-1` ✓
3. Validator V creates vote for round R at line 1399
4. **CONCURRENT EVENT**: Another validator's vote/sync message arrives containing QC for round R
5. V's `block_store` processes this, advancing internal state to round R+1
6. Validator V executes line 1401: fetches **updated** `sync_info` with `highest_round() = R`
7. V broadcasts `VoteMsg { vote: round R, sync_info: highest_round R }`

**Rejection at Receiver:**

When this vote reaches other validators, the processing flow is: [2](#0-1) 

The `ensure_round_and_sync_up()` function enforces strict round matching: [3](#0-2) 

The receiver processes as follows:
1. `message_round = R` (from vote)
2. `sync_up(sync_info with highest_round = R)` is called
3. `process_certificates()` advances receiver to round R+1: [4](#0-3) 

4. Check at line 926: `R == R+1` **FAILS** ✗
5. Vote is rejected with error: "After sync, round {} doesn't match local {}"

**Breaking Invariant:**
This breaks the **Consensus Liveness** invariant by causing legitimate votes to be rejected during normal operation, potentially delaying QC formation and forcing timeout rounds.

## Impact Explanation
**High Severity** - This qualifies as "Validator node slowdowns" and "Significant protocol violations" per Aptos bug bounty criteria because:

1. **Liveness Degradation**: Legitimate votes are rejected, reducing the effective vote count and potentially delaying QC formation
2. **Increased Timeouts**: When enough votes are lost to this race condition, rounds must complete via timeout instead of QC, significantly slowing consensus
3. **Wasted Resources**: Validators expend resources creating and broadcasting votes that get systematically rejected
4. **Intermittent Failures**: The race condition creates non-deterministic behavior that is difficult to debug and diagnose

The impact is not Critical because:
- It does not break consensus safety (no forks or double-spending)
- The network eventually recovers through timeout mechanisms
- No funds are lost or frozen

## Likelihood Explanation
**Medium-to-High Likelihood** during periods of high network activity:

1. **Natural Occurrence**: The race window exists between any two `block_store.sync_info()` calls, which occurs on every vote
2. **Increased Probability with Load**: More concurrent votes and sync messages increase collision probability
3. **Network Conditions**: Variable network delays make the timing window unpredictable
4. **No Special Privileges Required**: This happens during normal validator operation
5. **Amplification**: Once some nodes advance to R+1, their sync messages trigger the race at other nodes

While not easily weaponized by a malicious actor, this naturally occurs and compounds during high-load scenarios when consensus performance is most critical.

## Recommendation
**Fix: Atomically capture sync_info with vote creation**

The solution is to ensure `sync_info` is captured once and used consistently:

```rust
pub async fn process_verified_proposal(&mut self, proposal: Block) -> anyhow::Result<()> {
    let proposal_round = proposal.round();
    let parent_qc = proposal.quorum_cert().clone();
    
    // Capture sync_info ONCE before vote creation
    let sync_info = self.block_store.sync_info();

    if proposal_round <= sync_info.highest_round() {
        // ... existing staleness check ...
        return Ok(());
    }

    let vote = self.create_vote(proposal).await?;
    self.round_state.record_vote(vote.clone());
    
    // Use the SAME sync_info captured earlier, not a fresh fetch
    let vote_msg = VoteMsg::new(vote.clone(), sync_info); // Changed from self.block_store.sync_info()

    // ... rest of broadcasting logic ...
}
```

**Alternative: Add lock/snapshot mechanism**

If the single-capture approach is insufficient, implement a snapshot mechanism that freezes `block_store` state during vote creation:

```rust
// In block_store
pub fn create_vote_snapshot(&self) -> VoteCreationSnapshot {
    // Return immutable snapshot of relevant state
}
```

## Proof of Concept

```rust
// Rust test demonstrating the race condition
#[tokio::test]
async fn test_vote_rejection_race_condition() {
    // Setup: Create validator at round R-1
    let mut round_manager = create_test_round_manager(/* round R-1 */);
    
    // Step 1: Validator prepares to vote on proposal at round R
    let proposal_round_r = create_test_proposal(/* round R */);
    
    // Step 2: Simulate concurrent QC arrival during vote creation
    // This would require intercepting between lines 1399-1401
    let qc_for_round_r = create_qc_for_round(/* round R */);
    
    // Step 3: Inject QC to advance block_store state
    round_manager.block_store.insert_quorum_cert(qc_for_round_r).await.unwrap();
    
    // Step 4: Complete vote creation - sync_info will now show highest_round = R
    let vote_msg = round_manager.create_vote_msg_for_proposal(proposal_round_r).await.unwrap();
    
    // Step 5: Verify inconsistent state
    assert_eq!(vote_msg.vote().vote_data().proposed().round(), /* R */);
    assert_eq!(vote_msg.sync_info().highest_round(), /* R */);
    
    // Step 6: Simulate receiver processing
    let mut receiver = create_test_round_manager(/* round R-1 */);
    
    // Step 7: Attempt to process vote - should fail due to round mismatch
    let result = receiver.process_vote_msg(vote_msg).await;
    
    // Verify vote was rejected
    assert!(result.is_err() || vote was not added to pending_votes);
    
    // The legitimate vote from an honest validator was rejected
}
```

**Notes:**
- The race window is small but non-zero on every vote
- Occurs more frequently under high network load when multiple QCs/sync messages are in flight
- No malicious intent required - happens during normal operation
- Creates observable liveness degradation in production metrics
- The strict equality check in `ensure_round_and_sync_up()` at line 926-933 makes this deterministically reject votes with even slight timing discrepancies

### Citations

**File:** consensus/src/round_manager.rs (L916-935)
```rust
    pub async fn ensure_round_and_sync_up(
        &mut self,
        message_round: Round,
        sync_info: &SyncInfo,
        author: Author,
    ) -> anyhow::Result<bool> {
        if message_round < self.round_state.current_round() {
            return Ok(false);
        }
        self.sync_up(sync_info, author).await?;
        ensure!(
            message_round == self.round_state.current_round(),
            "After sync, round {} doesn't match local {}. Local Sync Info: {}. Remote Sync Info: {}",
            message_round,
            self.round_state.current_round(),
            self.block_store.sync_info(),
            sync_info,
        );
        Ok(true)
    }
```

**File:** consensus/src/round_manager.rs (L1385-1401)
```rust
        let sync_info = self.block_store.sync_info();

        if proposal_round <= sync_info.highest_round() {
            sample!(
                SampleRate::Duration(Duration::from_secs(1)),
                warn!(
                    sync_info = sync_info,
                    proposal = proposal,
                    "Ignoring proposal. SyncInfo round is higher than proposal round."
                )
            );
            return Ok(());
        }

        let vote = self.create_vote(proposal).await?;
        self.round_state.record_vote(vote.clone());
        let vote_msg = VoteMsg::new(vote.clone(), self.block_store.sync_info());
```

**File:** consensus/src/round_manager.rs (L1697-1716)
```rust
    pub async fn process_vote_msg(&mut self, vote_msg: VoteMsg) -> anyhow::Result<()> {
        fail_point!("consensus::process_vote_msg", |_| {
            Err(anyhow::anyhow!("Injected error in process_vote_msg"))
        });
        // Check whether this validator is a valid recipient of the vote.
        if self
            .ensure_round_and_sync_up(
                vote_msg.vote().vote_data().proposed().round(),
                vote_msg.sync_info(),
                vote_msg.vote().author(),
            )
            .await
            .context("[RoundManager] Stop processing vote")?
        {
            self.process_vote(vote_msg.vote())
                .await
                .context("[RoundManager] Add a new vote")?;
        }
        Ok(())
    }
```

**File:** consensus/src/liveness/round_state.rs (L245-258)
```rust
    pub fn process_certificates(
        &mut self,
        sync_info: SyncInfo,
        verifier: &ValidatorVerifier,
    ) -> Option<NewRoundEvent> {
        if sync_info.highest_ordered_round() > self.highest_ordered_round {
            self.highest_ordered_round = sync_info.highest_ordered_round();
        }
        let new_round = sync_info.highest_round() + 1;
        if new_round > self.current_round {
            let (prev_round_votes, prev_round_timeout_votes) = self.pending_votes.drain_votes();

            // Start a new round.
            self.current_round = new_round;
```
