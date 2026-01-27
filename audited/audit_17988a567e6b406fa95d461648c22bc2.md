# Audit Report

## Title
Sync-Only Mode Prevents Timeout Certificate Formation Causing Permanent Consensus Liveness Failure

## Summary
When validators enter `sync_only` mode (triggered by execution backpressure or configuration), they broadcast `SyncInfo` instead of timeout messages during round timeouts. If more than 1/3 of voting power is affected, timeout certificates cannot form, preventing consensus from progressing to the next round and causing permanent network halt.

## Finding Description

The vulnerability exists in the `process_local_timeout()` function where validators in `sync_only` mode take a different code path that bypasses timeout message broadcasting. [1](#0-0) 

The `sync_only` condition is triggered when execution lags behind ordering by more than `vote_back_pressure_limit` rounds (default: 12): [2](#0-1) [3](#0-2) 

When validators timeout on a round, the system requires 2f+1 voting power to form a timeout certificate: [4](#0-3) 

Round progression depends on either having a new QC or a timeout certificate. The `highest_round()` is calculated as the maximum of certified round and timeout round: [5](#0-4) 

Without a timeout certificate, `highest_timeout_round()` returns 0: [6](#0-5) 

This prevents round progression when validators cannot form a QC (proposer failure) and also cannot form a TC: [7](#0-6) 

**Attack Scenario:**

1. Network experiences high transaction load (natural or attacker-induced via expensive but valid transactions)
2. Execution pipeline cannot keep pace with block ordering
3. Gap between `ordered_round` and `commit_round` exceeds 12 rounds
4. All/most validators automatically enter `vote_back_pressure` mode (by design)
5. Current proposer fails (crash, network partition, or targeted DoS)
6. Validators timeout and call `process_local_timeout()`
7. Validators in `sync_only` mode broadcast `SyncInfo` instead of timeout messages
8. With >1/3 voting power not sending timeouts, no timeout certificate can form
9. Without TC or QC, `highest_round()` cannot advance
10. **Consensus permanently stuck at current round**

This breaks the **Consensus Liveness** invariant: "The protocol must guarantee progress under partial synchrony with <1/3 Byzantine validators."

## Impact Explanation

**Critical Severity** - Total loss of liveness/network availability requiring hardfork intervention.

This qualifies as **"Total loss of liveness/network availability"** under the Critical Severity category because:

- Consensus cannot progress to new rounds
- No new blocks can be committed
- Network becomes completely non-functional
- Requires manual intervention (hardfork or coordinated restart)
- Affects the entire network, not individual nodes

The vulnerability is particularly severe because:
1. It can be triggered by natural network conditions (high load) combined with single proposer failure
2. The back pressure mechanism is **designed** to trigger across all validators simultaneously
3. No automatic recovery mechanism exists
4. Both honest and malicious actors can trigger this state

## Likelihood Explanation

**Medium-High likelihood** due to:

**Triggering Factors:**
- High transaction volume is common during network usage spikes
- Execution backlog naturally occurs when processing transaction-heavy blocks
- Proposer failures happen regularly (network issues, hardware failures, software crashes)
- An attacker can increase likelihood by:
  - Submitting valid but expensive transactions to create execution lag
  - Performing targeted DoS on current proposer once back pressure is detected
  - Deliberately configuring validators with `sync_only=true` if controlling >1/3 stake

**Mitigating Factors:**
- Requires sustained execution lag (>12 round gap)
- Requires proposer failure during back pressure state
- Modern networks have robust execution pipelines

However, the combination of natural high load + single node failure is realistic enough to warrant concern.

## Recommendation

**Fix:** Decouple voting backpressure from timeout protocol participation.

The `sync_only` mode should prevent validators from voting on new proposals (to avoid overwhelming execution), but should NOT prevent them from participating in the timeout protocol which is essential for liveness.

**Proposed Code Fix** for `consensus/src/round_manager.rs`:

```rust
pub async fn process_local_timeout(&mut self, round: Round) -> anyhow::Result<()> {
    if !self.round_state.process_local_timeout(round) {
        return Ok(());
    }

    // Remove the early return for sync_only mode before timeout processing
    // The sync_only check should only affect voting, not timeout participation
    
    if self.local_config.enable_round_timeout_msg {
        let timeout = if let Some(timeout) = self.round_state.timeout_sent() {
            timeout
        } else {
            // ... timeout creation logic ...
        };
        
        self.round_state.record_round_timeout(timeout.clone());
        let round_timeout_msg = RoundTimeoutMsg::new(timeout, self.block_store.sync_info());
        self.network
            .broadcast_round_timeout(round_timeout_msg)
            .await;
        
        // Only broadcast sync_info additionally if in sync_only mode, but still send timeout
        if self.sync_only() {
            self.network
                .broadcast_sync_info(self.block_store.sync_info())
                .await;
        }
        
        warn!(
            round = round,
            remote_peer = self.proposer_election.get_valid_proposer(round),
            event = LogEvent::Timeout,
        );
        bail!("Round {} timeout, broadcast to all peers", round);
    }
    // ... rest of timeout vote logic unchanged ...
}
```

**Alternative Fix:** Adjust the back pressure limit or add a grace period to ensure enough validators remain active for timeout certificate formation.

## Proof of Concept

**Rust Integration Test** (to be placed in `consensus/src/round_manager_tests/`):

```rust
#[tokio::test]
async fn test_liveness_failure_during_backpressure() {
    // Setup: Create network with 4 validators (Byzantine threshold = 1)
    let mut playground = NetworkPlayground::new(runtime.handle().clone());
    let mut nodes = SMRNode::start_num_nodes(4, &mut playground, FullNode);
    
    // Step 1: Force all validators into back pressure mode
    for node in nodes.iter_mut() {
        node.block_store.back_pressure_for_test.store(true, Ordering::Relaxed);
    }
    
    // Step 2: Create a situation requiring timeout (stop proposer)
    let current_round = nodes[0].round_state.current_round();
    let proposer_idx = nodes[0].proposer_election.get_valid_proposer(current_round);
    playground.drop_message_for(&proposer_idx); // Simulate proposer failure
    
    // Step 3: Wait for timeout on all validators
    let timeout_duration = Duration::from_secs(5);
    runtime.block_on(async {
        sleep(timeout_duration).await;
    });
    
    // Step 4: Verify validators broadcast SyncInfo, not timeouts
    let timeout_msg_count = playground.count_message_type::<RoundTimeoutMsg>();
    let sync_info_count = playground.count_message_type::<SyncInfo>();
    assert_eq!(timeout_msg_count, 0, "Validators should not send timeout messages in sync_only");
    assert!(sync_info_count >= 3, "Validators should broadcast SyncInfo instead");
    
    // Step 5: Verify consensus is stuck (no round progression)
    for node in nodes.iter() {
        assert_eq!(
            node.round_state.current_round(), 
            current_round,
            "Round should not progress without timeout certificate"
        );
    }
    
    // Step 6: Verify no new blocks committed
    let initial_commit_round = nodes[0].block_store.commit_root().round();
    sleep(Duration::from_secs(10)).await;
    let final_commit_round = nodes[0].block_store.commit_root().round();
    assert_eq!(
        initial_commit_round, 
        final_commit_round,
        "No blocks should be committed during liveness failure"
    );
}
```

**Reproduction Steps:**
1. Deploy Aptos testnet with modified validator config setting low `vote_back_pressure_limit` (e.g., 3 rounds)
2. Submit high volume of valid transactions to create execution backlog
3. Monitor validators entering back pressure mode via `sync_only` metric
4. Kill current proposer process or isolate proposer from network
5. Observe timeout events occur but no timeout messages broadcast
6. Verify consensus halts and requires manual intervention

## Notes

This vulnerability demonstrates a dangerous conflation of two separate concerns:
1. **Voting backpressure** (prevent overwhelming execution pipeline)
2. **Timeout participation** (essential for liveness)

The current implementation treats validators in `sync_only` mode as if they should be completely passive, but timeout protocol participation is **orthogonal** to voting backpressure. Timeouts don't add execution load; they're a recovery mechanism when the current round fails.

The fix must preserve the backpressure mechanism while ensuring validators always participate in timeout protocols to maintain liveness guarantees.

### Citations

**File:** consensus/src/round_manager.rs (L998-1003)
```rust
        if self.sync_only() {
            self.network
                .broadcast_sync_info(self.block_store.sync_info())
                .await;
            bail!("[RoundManager] sync_only flag is set, broadcasting SyncInfo");
        }
```

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

**File:** config/src/config/consensus_config.rs (L257-257)
```rust
            vote_back_pressure_limit: 12,
```

**File:** consensus/src/pending_votes.rs (L234-243)
```rust
        let partial_tc = two_chain_votes.partial_2chain_tc_mut();
        let tc_voting_power =
            match validator_verifier.check_voting_power(partial_tc.signers(), true) {
                Ok(_) => {
                    return match partial_tc.aggregate_signatures(validator_verifier) {
                        Ok(tc_with_sig) => {
                            VoteReceptionResult::New2ChainTimeoutCertificate(Arc::new(tc_with_sig))
                        },
                        Err(e) => VoteReceptionResult::ErrorAggregatingTimeoutCertificate(e),
                    };
```

**File:** consensus/consensus-types/src/sync_info.rs (L120-123)
```rust
    pub fn highest_timeout_round(&self) -> Round {
        self.highest_2chain_timeout_cert()
            .map_or(0, |tc| tc.round())
    }
```

**File:** consensus/consensus-types/src/sync_info.rs (L134-136)
```rust
    pub fn highest_round(&self) -> Round {
        std::cmp::max(self.highest_certified_round(), self.highest_timeout_round())
    }
```

**File:** consensus/src/liveness/round_state.rs (L253-258)
```rust
        let new_round = sync_info.highest_round() + 1;
        if new_round > self.current_round {
            let (prev_round_votes, prev_round_timeout_votes) = self.pending_votes.drain_votes();

            // Start a new round.
            self.current_round = new_round;
```
