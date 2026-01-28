# Audit Report

## Title
Byzantine Validators Can Force Premature Round Timeouts via Early RoundTimeoutMsg Broadcast

## Summary
Byzantine validators can broadcast valid `RoundTimeoutMsg` messages immediately at the start of each round without waiting for the timeout duration to elapse. By coordinating f Byzantine validators to send early timeouts, the system reaches near the f+1 echo threshold, making it fragile to any minor network delay. This forces honest validators to timeout prematurely via the echo mechanism, causing unnecessary round changes and significantly degrading consensus liveness.

## Finding Description

The vulnerability exists in how `RoundTimeoutMsg` messages are validated and processed in the AptosBFT consensus protocol. When a validator times out locally, it creates a `RoundTimeoutMsg` and broadcasts it to all peers. The receiving validators verify the message and aggregate timeout votes.

The critical issue is in the SafetyRules validation for signing timeouts. The `safe_to_timeout` function only checks consensus safety properties without any timing validation: [1](#0-0) 

These checks verify only that:
1. `round == qc_round + 1` OR `round == tc_round + 1` (correct round progression)
2. `qc_round >= one_chain_round` (consistency with 1-chain rule)

There is **NO validation** that:
- The local timeout duration has actually elapsed
- The timeout is necessary or appropriate  
- A proposal was given adequate time to arrive

When receiving timeout messages, the `insert_round_timeout` function aggregates voting power and implements an "echo timeout" mechanism: [2](#0-1) 

When f+1 voting power worth of timeouts are received, `EchoTimeout` is triggered, which forces validators who haven't sent timeouts to do so: [3](#0-2) 

The `process_local_timeout` function creates and signs timeout messages without any check that the timeout duration has elapsed: [4](#0-3) [5](#0-4) 

**Attack Scenario:**

1. **Byzantine Setup**: f Byzantine validators coordinate to send `RoundTimeoutMsg` immediately at the start of each round
2. **Valid Signatures**: Since SafetyRules only checks round progression (not timing), these messages have valid signatures
3. **Near-Threshold State**: The system now has f voting power worth of timeouts, just 1 unit short of the f+1 threshold
4. **Trigger Cascade**: When any single honest validator experiences legitimate network delay and times out, the f+1 threshold is reached
5. **Forced Timeouts**: This triggers `EchoTimeout` on ALL validators who haven't voted yet
6. **Premature Round Change**: Honest validators are forced to timeout, advancing to the next round
7. **Lost Proposals**: Valid proposals are discarded unnecessarily

The test case confirms this behavior: [6](#0-5) 

The test shows that node 0, which hasn't timed out locally, is forced to timeout after receiving the second timeout message (reaching f+1=2 threshold with f=1 in a 4-validator setup).

## Impact Explanation

This vulnerability qualifies as **High Severity** per the Aptos bug bounty program because it causes "Validator node slowdowns" and significant liveness degradation.

**Specific Impacts:**

1. **Liveness Degradation**: The consensus protocol's ability to make progress is significantly impaired. Proposals that would normally be processed are discarded prematurely.

2. **Reduced Fault Tolerance**: The system becomes fragile to minor network delays. Instead of tolerating f Byzantine validators AND normal network variations independently, any small honest delay combined with f Byzantine timeouts triggers system-wide premature timeouts.

3. **Throughput Reduction**: With coordinated attacks across multiple rounds, the average time to finalize blocks increases dramatically as rounds are repeatedly aborted.

4. **Resource Waste**: Honest validators expend computational resources creating and validating NIL votes and timeout certificates that should not have been necessary.

5. **Sustained Attack Potential**: Byzantine validators can execute this attack continuously across all rounds with minimal cost.

The attack does not cause complete network halt (which would be Critical severity) but significantly degrades performance and violates the AptosBFT liveness guarantee that the protocol should tolerate f Byzantine validators without liveness degradation.

## Likelihood Explanation

**Likelihood: High**

This attack is highly likely because:

1. **Low Barrier to Entry**: Requires only f Byzantine validators, which is within the standard Byzantine fault tolerance assumption (< n/3). The protocol is designed to tolerate f Byzantine validators while maintaining liveness, but this vulnerability breaks that guarantee.

2. **Simple Execution**: Attackers just need to call `process_local_timeout` immediately at round start or broadcast pre-signed `RoundTimeoutMsg` messages. No complex cryptographic attacks or sophisticated exploits required.

3. **No Cost Penalty**: The malicious timeout messages are cryptographically valid and satisfy all SafetyRules checks. There's no way to detect or penalize validators sending premature timeouts.

4. **Continuous Exploitation**: The attack can be repeated every round indefinitely, causing sustained liveness degradation.

5. **No Timing Validation**: The absence of any mechanism to validate that timeout durations have elapsed makes this attack trivially executable.

6. **Detection Difficulty**: Since the timeout messages pass all validation checks, there's no reliable way for honest validators to detect the attack is happening.

## Recommendation

Add timing validation to the timeout signing logic. The SafetyRules component should track when each round started and enforce a minimum timeout duration before signing timeout messages. This could be implemented by:

1. Recording the round start time in SafetyRules persistent storage
2. Adding a validation check in `guarded_sign_timeout_with_qc` that ensures sufficient time has elapsed
3. Configuring a minimum timeout duration parameter that must be respected before signing

Alternatively, implement a reputation or penalty system for validators that frequently timeout early, though this is more complex and may have its own challenges.

## Proof of Concept

The existing test case demonstrates the vulnerability: [6](#0-5) 

To create a malicious scenario, a Byzantine validator would simply call `process_local_timeout(current_round)` immediately upon entering a new round, rather than waiting for the configured timeout duration to elapse. The signed timeout messages will be accepted by all validators because SafetyRules only validates round progression, not timing.

## Notes

This vulnerability represents a gap between the theoretical Byzantine fault tolerance guarantees of AptosBFT and its actual implementation. While the protocol is designed to tolerate f Byzantine validators while maintaining liveness, the lack of timing validation in timeout signing allows Byzantine validators to degrade liveness beyond what should be tolerable. The echo timeout mechanism, which is designed to improve liveness by ensuring all validators move together when enough have timed out, becomes exploitable when there's no validation that the initial timeouts are legitimate.

### Citations

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

**File:** consensus/src/pending_votes.rs (L255-264)
```rust
        // Echo timeout if receive f+1 timeout message.
        if !self.echo_timeout {
            let f_plus_one = validator_verifier.total_voting_power()
                - validator_verifier.quorum_voting_power()
                + 1;
            if tc_voting_power >= f_plus_one {
                self.echo_timeout = true;
                return VoteReceptionResult::EchoTimeout(tc_voting_power);
            }
        }
```

**File:** consensus/src/round_manager.rs (L993-1037)
```rust
    pub async fn process_local_timeout(&mut self, round: Round) -> anyhow::Result<()> {
        if !self.round_state.process_local_timeout(round) {
            return Ok(());
        }

        if self.sync_only() {
            self.network
                .broadcast_sync_info(self.block_store.sync_info())
                .await;
            bail!("[RoundManager] sync_only flag is set, broadcasting SyncInfo");
        }

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

**File:** consensus/src/round_manager.rs (L1843-1845)
```rust
            VoteReceptionResult::EchoTimeout(_) if !self.round_state.is_timeout_sent() => {
                self.process_local_timeout(round).await
            },
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

**File:** consensus/src/round_manager_tests/consensus_test.rs (L1397-1450)
```rust
fn echo_round_timeout_msg() {
    let runtime = consensus_runtime();
    let mut playground = NetworkPlayground::new(runtime.handle().clone());
    let mut nodes = NodeSetup::create_nodes(
        &mut playground,
        runtime.handle().clone(),
        4,
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
        // clear the message queue
        for node in &mut nodes {
            node.next_proposal().await;
        }
        // timeout 3 nodes
        for node in &mut nodes[1..] {
            node.round_manager
                .process_local_timeout(1)
                .await
                .unwrap_err();
        }
        let node_0 = &mut nodes[0];
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
        }

        let node_1 = &mut nodes[1];
        // it receives 4 timeout messages (1 from each) and doesn't echo since it already timeout
        for _ in 0..4 {
            let timeout_vote = node_1.next_timeout().await;
            node_1
                .round_manager
                .process_round_timeout_msg(timeout_vote)
                .await
```
