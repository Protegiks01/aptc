# Audit Report

## Title
Execution Duration Causes Incorrect Round Timeouts via Vote Back Pressure Race Condition

## Summary
When block execution takes longer than expected, the vote back pressure mechanism delays voting while the round timeout continues to run independently. This creates a race condition where validators timeout on valid proposals instead of voting, causing unnecessary round failures and incorrect timeout attribution.

## Finding Description

The vulnerability exists in the interaction between three consensus mechanisms:

1. **Vote Back Pressure**: When execution lags and `ordered_round - commit_round > vote_back_pressure_limit` (12 rounds), voting is blocked to prevent further congestion. [1](#0-0) 

2. **Back Pressure Retry Logic**: When back pressure is detected, the proposal is resent to self, polling every 10ms for up to `round_initial_timeout_ms` (1000ms) to check if back pressure clears. [2](#0-1) 

3. **Round Timeout**: Independent of back pressure, the round timeout fires after `round_initial_timeout_ms` (1000ms) and triggers timeout message broadcasting. [3](#0-2) 

**The Attack Flow**:

1. Execution becomes slow due to computationally expensive transactions or resource contention
2. The gap between ordered and committed rounds exceeds 12 rounds
3. Vote back pressure activates, blocking new votes
4. When a new valid proposal arrives, `check_backpressure_and_process_proposal` delays voting
5. The retry loop polls for up to 1000ms waiting for back pressure to clear
6. Meanwhile, the round timeout (also ~1000ms) runs in parallel
7. If execution doesn't catch up in time, the round timeout fires first
8. `process_local_timeout` broadcasts a timeout vote/message for a valid proposal
9. The timeout reason is incorrectly attributed (likely `RoundTimeoutReason::Unknown` or `RoundTimeoutReason::NoQC`) [4](#0-3) 

**Configuration Values** that create the race condition: [5](#0-4) 

Both the back pressure retry timeout and round timeout use the same duration (1000ms), creating a race condition where either mechanism can win depending on exact timing.

## Impact Explanation

This vulnerability qualifies as **High Severity** under "Validator node slowdowns":

1. **Consensus Liveness Degradation**: Validators timeout on valid proposals unnecessarily, wasting rounds and slowing block production
2. **Cascading Failures**: If multiple validators experience slow execution simultaneously (e.g., due to a computationally expensive block), they may all timeout, causing round failure despite having a valid proposal
3. **Incorrect Timeout Attribution**: Timeout metrics and logs show incorrect reasons, breaking observability and making debugging difficult
4. **DoS Vector**: An attacker submitting computationally expensive transactions can trigger sustained execution slowdown, forcing validators into repeated timeouts

The issue doesn't violate consensus safety (no chain splits or double-spending) but significantly impacts liveness and validator performance.

## Likelihood Explanation

**Likelihood: Medium to High**

- **Natural Occurrence**: Execution spikes can happen legitimately during high load, complex Move contracts, or resource contention
- **Attack Feasibility**: Attackers can craft expensive transactions (within gas limits) to slow execution across validators
- **Sustained Effect**: The 12-round back pressure threshold means execution must lag significantly, but this is achievable under load
- **Observable in Production**: The default configuration values (1000ms timeout, 12-round limit) make this race condition realistic

The race condition is more likely to trigger when:
- Network experiences high transaction volume
- Blocks contain computationally expensive Move operations
- Multiple validators experience similar execution delays
- An attacker deliberately submits expensive transactions

## Recommendation

**Solution**: Decouple the back pressure retry timeout from the round timeout to eliminate the race condition.

**Proposed Fix**:

1. **Extend back pressure retry duration** to be significantly longer than the round timeout:

```rust
// In resend_verified_proposal_to_self
let retry_timeout_ms = timeout_ms.saturating_mul(3); // 3x the round timeout

while start.elapsed() < Duration::from_millis(retry_timeout_ms) {
    if !block_store.vote_back_pressure() {
        // ... send proposal
        break;
    }
    sleep(Duration::from_millis(polling_interval_ms)).await;
}
```

2. **Add back pressure awareness to timeout computation** to delay timeouts when back pressure is active:

```rust
// In compute_timeout_reason
fn compute_timeout_reason(&self, round: Round) -> RoundTimeoutReason {
    if self.block_store.vote_back_pressure() {
        return RoundTimeoutReason::ExecutionBackpressure;
    }
    // ... existing logic
}
```

3. **Adjust timeout duration when back pressure is active** to give execution more time:

```rust
// In setup_timeout
fn setup_timeout(&mut self, multiplier: u32) -> Duration {
    let base_multiplier = if self.is_back_pressure_active() {
        multiplier.saturating_mul(2) // Double timeout under back pressure
    } else {
        multiplier
    };
    // ... rest of calculation
}
```

## Proof of Concept

**Reproduction Steps**:

1. **Setup**: Configure a validator node with default consensus config (1000ms timeout, 12-round back pressure limit)

2. **Trigger Slow Execution**: Submit blocks with computationally expensive Move transactions that cause execution to take >100ms per block

3. **Build Up Back Pressure**: Continue for >12 rounds until `ordered_round - commit_round > 12`

4. **Observe Race Condition**: 
   - Send a new valid proposal
   - Monitor that vote back pressure activates
   - Watch both the back pressure retry loop and round timeout
   - Observe that the round timeout fires before voting completes
   - Check logs showing incorrect timeout reason despite valid proposal

**Expected Behavior**: Validators should either:
- Vote if back pressure clears before timeout
- Have timeout duration extended when back pressure is active

**Actual Behavior**: Validators timeout on valid proposals when back pressure doesn't clear within 1000ms, causing unnecessary round failures.

**Metrics to Monitor**:
- `CONSENSUS_WITHOLD_VOTE_BACKPRESSURE_TRIGGERED`: Shows when back pressure activates
- `TIMEOUT_ROUNDS_COUNT`: Shows increased timeout frequency
- `AGGREGATED_ROUND_TIMEOUT_REASON`: Shows incorrect timeout reasons

## Notes

This vulnerability breaks the expectation that round timeouts should only occur when:
- The proposer is malicious/offline
- The proposal wasn't received
- The proposal payload is unavailable

Instead, timeouts now incorrectly trigger due to slow execution, which is a separate concern that should be handled independently through back pressure mechanisms rather than causing timeouts on valid proposals.

### Citations

**File:** consensus/src/block_storage/block_store.rs (L691-704)
```rust
    fn vote_back_pressure(&self) -> bool {
        #[cfg(any(test, feature = "fuzzing"))]
        {
            if self.back_pressure_for_test.load(Ordering::Relaxed) {
                return true;
            }
        }
        let commit_round = self.commit_root().round();
        let ordered_round = self.ordered_root().round();
        counters::OP_COUNTERS
            .gauge("back_pressure")
            .set((ordered_round - commit_round) as i64);
        ordered_round > self.vote_back_pressure_limit + commit_round
    }
```

**File:** consensus/src/round_manager.rs (L968-983)
```rust
    fn compute_timeout_reason(&self, round: Round) -> RoundTimeoutReason {
        if self.round_state().vote_sent().is_some() {
            return RoundTimeoutReason::NoQC;
        }

        match self.block_store.get_block_for_round(round) {
            None => RoundTimeoutReason::ProposalNotReceived,
            Some(block) => {
                if let Err(missing_authors) = self.block_store.check_payload(block.block()) {
                    RoundTimeoutReason::PayloadUnavailable { missing_authors }
                } else {
                    RoundTimeoutReason::Unknown
                }
            },
        }
    }
```

**File:** consensus/src/round_manager.rs (L1288-1337)
```rust
    async fn check_backpressure_and_process_proposal(
        &mut self,
        proposal: Block,
    ) -> anyhow::Result<()> {
        let author = proposal
            .author()
            .expect("Proposal should be verified having an author");

        if self.block_store.vote_back_pressure() {
            counters::CONSENSUS_WITHOLD_VOTE_BACKPRESSURE_TRIGGERED.observe(1.0);
            // In case of back pressure, we delay processing proposal. This is done by resending the
            // same proposal to self after some time.
            Self::resend_verified_proposal_to_self(
                self.block_store.clone(),
                self.buffered_proposal_tx.clone(),
                proposal,
                author,
                BACK_PRESSURE_POLLING_INTERVAL_MS,
                self.local_config.round_initial_timeout_ms,
            )
            .await;
            return Ok(());
        }

        counters::CONSENSUS_WITHOLD_VOTE_BACKPRESSURE_TRIGGERED.observe(0.0);
        self.process_verified_proposal(proposal).await
    }

    async fn resend_verified_proposal_to_self(
        block_store: Arc<BlockStore>,
        self_sender: aptos_channel::Sender<Author, VerifiedEvent>,
        proposal: Block,
        author: Author,
        polling_interval_ms: u64,
        timeout_ms: u64,
    ) {
        let start = Instant::now();
        let event = VerifiedEvent::VerifiedProposalMsg(Box::new(proposal));
        tokio::spawn(async move {
            while start.elapsed() < Duration::from_millis(timeout_ms) {
                if !block_store.vote_back_pressure() {
                    if let Err(e) = self_sender.push(author, event) {
                        warn!("Failed to send event to round manager {:?}", e);
                    }
                    break;
                }
                sleep(Duration::from_millis(polling_interval_ms)).await;
            }
        });
    }
```

**File:** consensus/src/liveness/round_state.rs (L233-241)
```rust
    pub fn process_local_timeout(&mut self, round: Round) -> bool {
        if round != self.current_round {
            return false;
        }
        warn!(round = round, "Local timeout");
        counters::TIMEOUT_COUNT.inc();
        self.setup_timeout(1);
        true
    }
```

**File:** config/src/config/consensus_config.rs (L235-257)
```rust
            round_initial_timeout_ms: 1000,
            // 1.2^6 ~= 3
            // Timeout goes from initial_timeout to initial_timeout*3 in 6 steps
            round_timeout_backoff_exponent_base: 1.2,
            round_timeout_backoff_max_exponent: 6,
            safety_rules: SafetyRulesConfig::default(),
            sync_only: false,
            internal_per_key_channel_size: 10,
            quorum_store_pull_timeout_ms: 400,
            quorum_store_poll_time_ms: 300,
            // disable wait_for_full until fully tested
            // We never go above 20-30 pending blocks, so this disables it
            wait_for_full_blocks_above_pending_blocks: 100,
            // Max is 1, so 1.1 disables it.
            wait_for_full_blocks_above_recent_fill_threshold: 1.1,
            intra_consensus_channel_buffer_size: 10,
            quorum_store: QuorumStoreConfig::default(),

            // Voting backpressure is only used as a backup, to make sure pending rounds don't
            // increase uncontrollably, and we know when to go to state sync.
            // Considering block gas limit and pipeline backpressure should keep number of blocks
            // in the pipline very low, we can keep this limit pretty low, too.
            vote_back_pressure_limit: 12,
```
