# Audit Report

## Title
Malicious Proposer Can Cause Round Failures via Late Proposal Delivery and Deadline Manipulation

## Summary
A malicious block proposer can intentionally send consensus proposals late in a round, causing honest validators to timeout when fetching payloads due to insufficient time remaining before the round deadline. This leads to round failures, liveness degradation, and wasted validator resources without any accountability mechanism.

## Finding Description

The vulnerability exists in the interaction between the timestamp validation logic in `round_manager.rs` and the deadline-based timeout in `wait_for_payload()` in `block_store.rs`. [1](#0-0) 

The `wait_for_payload()` function calculates the effective timeout duration by subtracting the current timestamp from the deadline. If the current time is close to the deadline, this results in an extremely short timeout. [2](#0-1) 

The timestamp validation check only verifies that the block's timestamp is before the round deadline, but it does NOT validate when the proposal was actually received or whether sufficient time remains for payload fetching.

**Attack Path:**

1. Malicious proposer is elected for round R with deadline at time T
2. Proposer creates a valid block with timestamp T-50 (passes the timestamp check)
3. Proposer waits until time T-5 before broadcasting the proposal
4. Honest validators receive the proposal at time T-5
5. The timestamp check passes (T-50 < T)
6. Validators call `wait_for_payload(block, deadline=T)`
7. At line 590, `duration = T - (T-5) = 5` time units
8. The `tokio::time::timeout` triggers after only 5 time units
9. Legitimate payloads that require more time to fetch will timeout
10. Validators fail to fetch payload and do not vote [3](#0-2) 

When the payload fetch times out, validators simply log a warning and do not vote for the proposal, causing the round to fail.

The vulnerability breaks the **Liveness** invariant: legitimate proposals with available payloads should be processed and voted on by honest validators.

## Impact Explanation

**Severity: Medium** (up to $10,000 per Aptos Bug Bounty)

This vulnerability causes:

1. **Validator Node Slowdowns**: Validators waste resources waiting for payloads that will timeout
2. **Round Failures**: Rounds fail to achieve quorum due to lack of votes
3. **Liveness Degradation**: Each exploited round adds timeout delay (exponentially growing with consecutive failures)
4. **Resource Waste**: Network bandwidth and computation wasted on proposals that cannot be processed

The impact is limited to Medium severity because:
- Only affects rounds where the attacker is the proposer (proposer election rotates)
- Does not cause permanent liveness halt or consensus safety violations
- Does not lead to fund loss or state corruption
- Network eventually progresses after timeout

However, if multiple validators are malicious (but < 1/3 Byzantine threshold), they can cause sustained liveness degradation by repeatedly exploiting this during their proposal turns.

## Likelihood Explanation

**Likelihood: High** - The attack is straightforward to execute:

**Attacker Requirements:**
- Must be a validator in the active set
- Only needs to wait to be elected as proposer (happens regularly through rotation)
- No special privileges or collusion required

**Complexity:** Low
- No cryptographic attacks required
- No complex state manipulation needed
- Simply requires delaying proposal broadcast until late in the round

**Detection:** Difficult
- No accountability mechanism identifies late proposals
- Appears as normal timeout due to network delays
- No punishment for proposers whose blocks don't get voted on

The attack is realistic and can be executed repeatedly by any validator during their proposer turns.

## Recommendation

Add a minimum time buffer check to ensure sufficient time remains for payload fetching before accepting proposals. The fix should be implemented in `round_manager.rs`:

```rust
// In process_verified_proposal, after line 1241, add:
const MIN_PAYLOAD_FETCH_TIME: Duration = Duration::from_secs(2); // Configurable
let time_remaining = self.round_state.current_round_deadline()
    .saturating_sub(self.time_service.get_current_timestamp());

ensure!(
    time_remaining >= MIN_PAYLOAD_FETCH_TIME,
    "[RoundManager] Insufficient time remaining ({:?}) for payload fetch (minimum {:?} required). \
    Proposal received too late in round.",
    time_remaining,
    MIN_PAYLOAD_FETCH_TIME,
);
```

Additionally, consider:

1. **Reception Time Validation**: Record when proposals are received and validate against round start time
2. **Proposer Accountability**: Track proposers whose blocks consistently fail to get votes
3. **Adaptive Timeouts**: Use separate configurable timeout for payload fetching instead of round deadline
4. **Early Rejection**: Reject proposals received with insufficient time buffer before processing

## Proof of Concept

```rust
#[tokio::test]
async fn test_late_proposal_causes_payload_timeout() {
    // Setup: Create a mock time service and block store
    let time_service = Arc::new(SimulatedTimeService::new());
    let payload_manager = Arc::new(MockPayloadManager::new_with_delay(
        Duration::from_secs(3) // Payload fetch takes 3 seconds
    ));
    
    // Set round deadline to T+10
    let round_start = Duration::from_secs(100);
    let round_deadline = round_start + Duration::from_secs(10); // T+110
    time_service.set_current_time(round_start);
    
    let block_store = create_block_store_with_mocks(
        time_service.clone(),
        payload_manager.clone()
    );
    
    // Create a block with timestamp at T+5 (passes timestamp check)
    let block_timestamp = round_start + Duration::from_secs(5); // T+105
    let block = create_test_block(block_timestamp);
    
    // Simulate late delivery: advance time to T+9 (only 1 second before deadline)
    time_service.set_current_time(round_start + Duration::from_secs(9)); // T+109
    
    // Attempt to fetch payload with round deadline
    let result = block_store.wait_for_payload(&block, round_deadline).await;
    
    // Expected: Timeout error because effective timeout = 110 - 109 = 1 second
    // But payload fetch requires 3 seconds
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("timeout"));
    
    // Verify: If block was received early, it would succeed
    time_service.set_current_time(round_start + Duration::from_secs(2)); // T+102
    let result_early = block_store.wait_for_payload(&block, round_deadline).await;
    assert!(result_early.is_ok()); // 8 seconds available, enough for 3 second fetch
}
```

**Notes:**

The vulnerability stems from two design issues:
1. The timestamp validation at line 1236 only checks the block's embedded timestamp, not the proposal's reception time
2. The `wait_for_payload()` function uses the round deadline directly without accounting for minimum required payload fetch time

This allows a malicious proposer to game the system by creating valid-timestamped blocks but delivering them with insufficient time for validators to process them, causing unnecessary round failures and degrading network liveness.

### Citations

**File:** consensus/src/block_storage/block_store.rs (L589-594)
```rust
    pub async fn wait_for_payload(&self, block: &Block, deadline: Duration) -> anyhow::Result<()> {
        let duration = deadline.saturating_sub(self.time_service.get_current_timestamp());
        tokio::time::timeout(duration, self.payload_manager.get_transactions(block, None))
            .await??;
        Ok(())
    }
```

**File:** consensus/src/round_manager.rs (L1233-1241)
```rust
        let block_time_since_epoch = Duration::from_micros(proposal.timestamp_usecs());

        ensure!(
            block_time_since_epoch < self.round_state.current_round_deadline(),
            "[RoundManager] Waiting until proposal block timestamp usecs {:?} \
            would exceed the round duration {:?}, hence will not vote for this round",
            block_time_since_epoch,
            self.round_state.current_round_deadline(),
        );
```

**File:** consensus/src/round_manager.rs (L2145-2159)
```rust
                Some((result, block, start_time)) = self.futures.next() => {
                    let elapsed = start_time.elapsed().as_secs_f64();
                    let id = block.id();
                    match result {
                        Ok(()) => {
                            counters::CONSENSUS_PROPOSAL_PAYLOAD_FETCH_DURATION.with_label_values(&["success"]).observe(elapsed);
                            if let Err(e) = monitor!("payload_fetch_proposal_process", self.check_backpressure_and_process_proposal(block)).await {
                                warn!("failed process proposal after payload fetch for block {}: {}", id, e);
                            }
                        },
                        Err(err) => {
                            counters::CONSENSUS_PROPOSAL_PAYLOAD_FETCH_DURATION.with_label_values(&["error"]).observe(elapsed);
                            warn!("unable to fetch payload for block {}: {}", id, err);
                        },
                    };
```
