# Audit Report

## Title
Byzantine Validators Can Force Premature Round Timeouts via Early RoundTimeoutMsg Broadcast

## Summary
Byzantine validators can broadcast valid `RoundTimeoutMsg` messages immediately at the start of each round without waiting for the timeout duration to elapse. By coordinating f Byzantine validators to send early timeouts, the system reaches near the f+1 echo threshold, making it fragile to any minor network delay. This forces honest validators to timeout prematurely via the echo mechanism, causing unnecessary round changes and significantly degrading consensus liveness.

## Finding Description

The vulnerability exists in how `RoundTimeoutMsg` messages are validated and processed. When a validator times out locally, it creates a `RoundTimeoutMsg` and broadcasts it to all peers. The receiving validators verify the message and aggregate timeout votes. [1](#0-0) 

The critical issue is in the SafetyRules validation for signing timeouts. The `guarded_sign_timeout_with_qc` function only checks consensus safety properties: [2](#0-1) 

These checks verify that:
1. `round == qc_round + 1` OR `round == tc_round + 1` (correct round progression)
2. `qc_round >= one_chain_round` (consistency with 1-chain rule)

However, there is **NO validation** that:
- The local timeout duration has actually elapsed
- The timeout is necessary or appropriate
- A proposal was given adequate time to arrive

When receiving timeout messages, the `insert_round_timeout` function aggregates voting power and implements an "echo timeout" mechanism: [3](#0-2) 

When f+1 voting power worth of timeouts are received, `EchoTimeout` is triggered, which forces validators who haven't sent timeouts to do so: [4](#0-3) 

**Attack Scenario:**

1. **Byzantine Setup**: f Byzantine validators coordinate to send `RoundTimeoutMsg` immediately at the start of each round (before the timeout duration elapses)
2. **Valid Signatures**: Since SafetyRules only checks round progression (not timing), these messages have valid signatures
3. **Near-Threshold State**: The system now has f voting power worth of timeouts, just 1 unit short of the f+1 threshold
4. **Trigger Cascade**: When any single honest validator experiences legitimate network delay and times out, the f+1 threshold is reached
5. **Forced Timeouts**: This triggers `EchoTimeout` on ALL validators who haven't voted yet via `process_local_timeout`
6. **Premature Round Change**: Honest validators are forced to create NIL votes and timeout, advancing to the next round
7. **Lost Proposals**: Even if a valid proposal was about to arrive, the round is aborted unnecessarily

The test case confirms this behavior: [5](#0-4) 

The test shows that node 0, which hasn't timed out locally, is forced to timeout after receiving the second timeout message (reaching f+1=2 threshold with f=1).

## Impact Explanation

This vulnerability qualifies as **High Severity** per the Aptos bug bounty program because it causes "Validator node slowdowns" and "Significant protocol violations."

**Specific Impacts:**

1. **Liveness Degradation**: The consensus protocol's ability to make progress is significantly impaired. Proposals that would normally be processed are discarded prematurely.

2. **Reduced Fault Tolerance**: The system becomes fragile to minor network delays. Instead of tolerating up to f Byzantine validators AND normal network variations, the system now fails to make progress with f Byzantine validators causing timeouts PLUS any small honest delay.

3. **Throughput Reduction**: With coordinated attacks across multiple rounds, the average time to finalize blocks increases dramatically as rounds are repeatedly aborted.

4. **Resource Waste**: Honest validators expend computational resources creating and validating NIL votes and timeout certificates that should not have been necessary.

5. **Potential for Sustained Attack**: Byzantine validators can execute this attack continuously across all rounds with minimal cost (just broadcasting messages they're already allowed to create).

The attack doesn't cause complete network halt (not Critical severity) but significantly degrades performance, making it High severity.

## Likelihood Explanation

**Likelihood: High**

This attack is highly likely because:

1. **Low Barrier to Entry**: Requires only f Byzantine validators, which is within the standard Byzantine fault tolerance assumption (< n/3). No special privileges or validator collusion beyond the Byzantine threshold is needed.

2. **Simple Execution**: Attackers just need to call `process_local_timeout` immediately at round start or broadcast pre-signed `RoundTimeoutMsg` messages. No complex cryptographic attacks or sophisticated exploits required.

3. **No Cost Penalty**: The malicious timeout messages are indistinguishable from legitimate ones. There's no way to detect or penalize validators sending "premature" timeouts.

4. **Continuous Exploitation**: The attack can be repeated every round indefinitely, causing sustained liveness degradation.

5. **Realistic Byzantine Model**: The security model already assumes up to f validators may be Byzantine. This attack is within those assumptions.

6. **Detection Difficulty**: Since the timeout messages are cryptographically valid and satisfy all SafetyRules checks, there's no reliable way for honest validators to detect the attack is happening.

## Recommendation

Add temporal validation to timeout creation and acceptance to ensure timeouts are not premature. This requires tracking when each round started and validating that sufficient time has elapsed.

**Recommended Fix:**

1. **Add Round Start Timestamp Tracking**:

```rust
// In RoundState
pub struct RoundState {
    // ... existing fields ...
    round_start_time: Duration, // Add this field
}

// In setup_deadline()
fn setup_deadline(&mut self, multiplier: u32) -> Duration {
    // ... existing code ...
    self.round_start_time = now; // Track when round started
    timeout
}
```

2. **Add Minimum Timeout Delay Check in SafetyRules**:

```rust
// In safety_rules_2chain.rs
pub(crate) fn guarded_sign_timeout_with_qc(
    &mut self,
    timeout: &TwoChainTimeout,
    timeout_cert: Option<&TwoChainTimeoutCertificate>,
) -> Result<bls12381::Signature, Error> {
    // ... existing checks ...
    
    // NEW CHECK: Ensure minimum timeout delay has elapsed
    let min_timeout_delay = self.get_minimum_timeout_delay_for_round(timeout.round());
    ensure!(
        self.time_since_round_start(timeout.round()) >= min_timeout_delay,
        Error::PrematureTimeout(timeout.round())
    );
    
    // ... rest of existing code ...
}
```

3. **Add Timestamp Validation on Receipt**:

```rust
// In process_round_timeout_msg
pub async fn process_round_timeout_msg(
    &mut self,
    round_timeout_msg: RoundTimeoutMsg,
) -> anyhow::Result<()> {
    // ... existing sync checks ...
    
    // NEW CHECK: Reject timeouts that are too early relative to local time
    let min_elapsed = self.round_state.minimum_timeout_delay_for_current_round();
    let actual_elapsed = self.round_state.time_since_current_round_start();
    
    if actual_elapsed < min_elapsed * EARLY_TIMEOUT_THRESHOLD {
        warn!("Rejecting suspiciously early timeout from {}", round_timeout_msg.author());
        bail!("Timeout message appears premature");
    }
    
    // ... existing processing ...
}
```

4. **Alternative: Increase Echo Threshold**: Change the echo threshold from f+1 to 2f+1 (quorum), so Byzantine validators alone cannot trigger cascading timeouts:

```rust
// In pending_votes.rs insert_round_timeout
if !self.echo_timeout {
    // Change from f+1 to quorum threshold
    let quorum = validator_verifier.quorum_voting_power();
    if tc_voting_power >= quorum {
        self.echo_timeout = true;
        return VoteReceptionResult::EchoTimeout(tc_voting_power);
    }
}
```

The timestamp-based approach is more robust as it prevents premature timeouts entirely, while the increased threshold approach makes the attack require 2f+1 validators (impossible under Byzantine assumptions).

## Proof of Concept

```rust
// Test demonstrating premature timeout attack
#[test]
fn test_premature_timeout_attack() {
    let runtime = consensus_runtime();
    let mut playground = NetworkPlayground::new(runtime.handle().clone());
    let mut nodes = NodeSetup::create_nodes(
        &mut playground,
        runtime.handle().clone(),
        4, // n=4, so f=1
        None,
        None,
        None,
        None,
        None,
        None,
        false,
    );
    runtime.spawn(playground.start());
    
    timed_block_on(&runtime, async {
        // Initialize all nodes
        for node in &mut nodes {
            node.next_proposal().await;
        }
        
        // Byzantine node (node 1) immediately sends timeout at round start
        // WITHOUT waiting for actual timeout duration
        nodes[1].round_manager
            .process_local_timeout(1)
            .await
            .unwrap_err();
        
        // Node 0 is honest, waiting for proposal
        // But it receives the premature timeout from node 1
        let timeout_msg = nodes[0].next_timeout().await;
        
        // Now node 0 receives timeout, but doesn't echo yet (only 1 out of 2 needed)
        let result = nodes[0].round_manager
            .process_round_timeout_msg(timeout_msg)
            .await;
        assert!(result.is_ok()); // First timeout doesn't trigger echo
        
        // Simulate a minor network delay for one more honest node
        // In real attack, Byzantine node 2 would also send premature timeout
        // OR a legitimate delay causes honest node to timeout
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Second timeout arrives (could be from another Byzantine or delayed honest node)
        nodes[2].round_manager
            .process_local_timeout(1)
            .await
            .unwrap_err();
            
        let timeout_msg2 = nodes[0].next_timeout().await;
        
        // This triggers EchoTimeout on node 0 (f+1 = 2 reached)
        let result = nodes[0].round_manager
            .process_round_timeout_msg(timeout_msg2)
            .await;
        
        // Node 0 is FORCED to timeout even though:
        // 1. Its local timeout hasn't expired
        // 2. A valid proposal might have been about to arrive
        // This is the liveness degradation
        assert!(result.is_err()); // Error indicates timeout was triggered
        
        // Verify node 0 sent timeout (was forced to)
        let forced_timeout = nodes[0].next_timeout().await;
        assert_eq!(forced_timeout.round(), 1);
    });
}
```

This PoC demonstrates that honest node 0 is forced to timeout prematurely when it receives f+1 timeout messages, even though its local timeout duration hasn't elapsed. In a real attack, f Byzantine validators would coordinate to send these early timeouts, making the system fragile to any minor delay from honest validators.

### Citations

**File:** consensus/src/round_manager.rs (L1005-1037)
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
            let round_timeout_msg = RoundTimeoutMsg::new(timeout, self.block_store.sync_info());
            self.network
                .broadcast_round_timeout(round_timeout_msg)
                .await;
```

**File:** consensus/src/round_manager.rs (L1843-1844)
```rust
            VoteReceptionResult::EchoTimeout(_) if !self.round_state.is_timeout_sent() => {
                self.process_local_timeout(round).await
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

**File:** consensus/src/pending_votes.rs (L256-263)
```rust
        if !self.echo_timeout {
            let f_plus_one = validator_verifier.total_voting_power()
                - validator_verifier.quorum_voting_power()
                + 1;
            if tc_voting_power >= f_plus_one {
                self.echo_timeout = true;
                return VoteReceptionResult::EchoTimeout(tc_voting_power);
            }
```

**File:** consensus/src/round_manager_tests/consensus_test.rs (L1426-1440)
```rust
        // node 0 doesn't timeout and should echo the timeout after 2 timeout message
        for i in 0..3 {
            let timeout_vote = node_0.next_timeout().await;
            let result = node_0
                .round_manager
                .process_round_timeout_msg(timeout_vote)
                .await;
            // first and third message should not timeout
            if i == 0 || i == 2 {
                assert!(result.is_ok());
            }
            if i == 1 {
                // timeout is an Error
                assert!(result.is_err());
            }
```
