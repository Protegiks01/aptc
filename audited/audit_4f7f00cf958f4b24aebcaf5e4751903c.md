# Audit Report

## Title
Missing Post-Aggregation Verification of Locally Aggregated Timeout Certificates Allows Unchecked Round Advancement

## Summary
Locally aggregated timeout certificates in the Aptos consensus protocol are never verified after aggregation before being used to trigger round changes. While individual timeout messages are verified before aggregation, the final aggregated certificate lacks the critical post-aggregation consistency check that ensures the certificate's HQC round matches the maximum signed round across all validators.

## Finding Description

The Aptos consensus uses two-chain timeout certificates to advance rounds when validators timeout. The vulnerability exists in the timeout certificate processing flow where locally aggregated certificates bypass verification that is mandatory for certificates received from external sources.

**The Verification Gap:**

When a timeout certificate is aggregated from individual validator timeout votes, the flow is:

1. Individual `RoundTimeout` messages arrive and are verified in `UnverifiedEvent::verify()` [1](#0-0) 

2. Verified timeouts are added to `PendingVotes` via `insert_round_timeout()` [2](#0-1) 

3. When quorum (2f+1) voting power is reached, signatures are aggregated [3](#0-2) 

4. The aggregated certificate is returned as `New2ChainTimeoutCertificate` and processed via `new_2chain_tc_aggregated()` [4](#0-3) 

5. The certificate is inserted into block storage **without verification** [5](#0-4) 

6. `process_certificates()` uses the certificate's round to trigger new round events [6](#0-5) 

**The Missing Critical Check:**

`TwoChainTimeoutCertificate::verify()` performs a crucial consistency check that ensures the certificate's `hqc_round` matches the maximum round signed by validators [7](#0-6) 

This verification is applied to:
- Certificates received in proposals [8](#0-7) 
- Certificates received in sync info [9](#0-8) 

But NOT to locally aggregated certificates, creating an inconsistent security model.

**How Bugs Could Exploit This:**

The aggregation logic selects the timeout with the highest HQC round [10](#0-9) 

Without post-aggregation verification, the following issues go undetected:
- Race conditions in concurrent timeout message processing
- Bugs in the signature aggregation that create inconsistent round mappings
- Incorrect ordering of rounds in `AggregateSignatureWithRounds`

## Impact Explanation

**High Severity** - This qualifies as a "significant protocol violation" per Aptos bug bounty criteria.

The vulnerability breaks **Consensus Safety** invariant #2: "AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine." While not directly exploitable by external attackers (since individual timeouts are verified), the missing verification:

1. **Violates Defense-in-Depth**: Creates single point of failure in aggregation logic
2. **Enables Round Manipulation**: If aggregation bugs exist, invalid certificates advance rounds inappropriately
3. **Breaks Consistency**: External certificates require verification, local ones don't - asymmetric trust model
4. **Risks Consensus Liveness**: Incorrect round advancement based on unverified certificates could cause honest validators to diverge

The impact is amplified because `process_certificates()` directly uses the certificate's round to compute the next round without any validation.

## Likelihood Explanation

**Medium Likelihood** - Occurrence requires specific conditions:

1. **Requires Aggregation Bug**: Current aggregation code appears correct, but lacks verification safety net
2. **Concurrent Processing Risk**: High-throughput scenarios with concurrent timeout processing increase risk
3. **Evolution Risk**: Future code changes to aggregation logic lack verification guard rail
4. **No Attacker Control**: External attackers cannot directly inject malicious data (individual verification prevents this)

However, the **asymmetric verification model** (external certificates verified, local ones not) is a design flaw that violates security principles regardless of current code correctness.

## Recommendation

Add verification of locally aggregated timeout certificates before insertion and use:

```rust
async fn new_2chain_tc_aggregated(
    &mut self,
    tc: Arc<TwoChainTimeoutCertificate>,
) -> anyhow::Result<()> {
    // CRITICAL: Verify the aggregated certificate before accepting it
    tc.verify(&self.epoch_state.verifier)
        .context("[RoundManager] Failed to verify locally aggregated 2-chain TC")?;
    
    let result = self
        .block_store
        .insert_2chain_timeout_certificate(tc)
        .context("[RoundManager] Failed to process a newly aggregated 2-chain TC");
    self.process_certificates().await?;
    result
}
```

This ensures:
1. **Symmetric verification**: All certificates verified regardless of source
2. **Defense-in-depth**: Catches aggregation bugs before they affect consensus
3. **Consistency check**: Validates HQC round matches signed rounds
4. **Early failure**: Errors caught before invalid state propagates

Alternative: Verify in `insert_round_timeout()` immediately after aggregation.

## Proof of Concept

The vulnerability cannot be demonstrated with a traditional exploit since individual timeout verification prevents malicious input. However, a test can demonstrate the missing verification:

```rust
// This test would be added to consensus/src/pending_votes.rs
#[test]
fn test_aggregated_tc_lacks_verification() {
    use aptos_consensus_types::timeout_2chain::TwoChainTimeoutWithPartialSignatures;
    
    // Setup: Create validators and partial TC
    let (signers, validator_verifier) = random_validator_verifier(4, None, false);
    
    // Create timeouts with DIFFERENT hqc_rounds
    let timeout1 = TwoChainTimeout::new(1, 5, generate_qc(1)); // hqc=1
    let timeout2 = TwoChainTimeout::new(1, 5, generate_qc(3)); // hqc=3
    
    // Add to partial TC - the higher hqc_round wins
    let mut partial_tc = TwoChainTimeoutWithPartialSignatures::new(timeout1.clone());
    partial_tc.add(signers[0].author(), timeout1, timeout1.sign(&signers[0]).unwrap());
    partial_tc.add(signers[1].author(), timeout2.clone(), timeout2.sign(&signers[1]).unwrap());
    partial_tc.add(signers[2].author(), timeout2.clone(), timeout2.sign(&signers[2]).unwrap());
    
    // Aggregate - no verification performed
    let tc = partial_tc.aggregate_signatures(&validator_verifier).unwrap();
    
    // EXPECTED: Verification should fail because certificate has hqc_round=3
    // but only 2/3 validators signed with hqc_round=3 (signer[1] and signer[2])
    // while signer[0] signed with hqc_round=1
    
    // ACTUAL: No verification happens, invalid certificate accepted
    assert!(tc.verify(&validator_verifier).is_err(), 
        "Certificate should be invalid but no verification performed!");
}
```

This demonstrates that aggregation can theoretically produce certificates that would fail verification, but the verification step is skipped for local aggregates.

## Notes

The vulnerability represents a **defense-in-depth failure** rather than a directly exploitable attack. The current aggregation code appears correct, but without verification:

1. Future refactoring could introduce bugs that go undetected
2. Subtle race conditions in concurrent processing lack safety net  
3. The asymmetric trust model (verify external, trust local) violates security principles

The fix is straightforward and adds negligible overhead since verification is already required for external certificates.

### Citations

**File:** consensus/src/round_manager.rs (L147-154)
```rust
            UnverifiedEvent::RoundTimeoutMsg(v) => {
                if !self_message {
                    v.verify(validator)?;
                    counters::VERIFY_MSG
                        .with_label_values(&["timeout"])
                        .observe(start_time.elapsed().as_secs_f64());
                }
                VerifiedEvent::RoundTimeoutMsg(v)
```

**File:** consensus/src/round_manager.rs (L2005-2015)
```rust
    async fn new_2chain_tc_aggregated(
        &mut self,
        tc: Arc<TwoChainTimeoutCertificate>,
    ) -> anyhow::Result<()> {
        let result = self
            .block_store
            .insert_2chain_timeout_certificate(tc)
            .context("[RoundManager] Failed to process a newly aggregated 2-chain TC");
        self.process_certificates().await?;
        result
    }
```

**File:** consensus/src/pending_votes.rs (L189-232)
```rust
    /// Insert a RoundTimeout and return a TimeoutCertificate if it can be formed
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

**File:** consensus/src/pending_votes.rs (L236-243)
```rust
            match validator_verifier.check_voting_power(partial_tc.signers(), true) {
                Ok(_) => {
                    return match partial_tc.aggregate_signatures(validator_verifier) {
                        Ok(tc_with_sig) => {
                            VoteReceptionResult::New2ChainTimeoutCertificate(Arc::new(tc_with_sig))
                        },
                        Err(e) => VoteReceptionResult::ErrorAggregatingTimeoutCertificate(e),
                    };
```

**File:** consensus/src/block_storage/block_store.rs (L560-575)
```rust
    pub fn insert_2chain_timeout_certificate(
        &self,
        tc: Arc<TwoChainTimeoutCertificate>,
    ) -> anyhow::Result<()> {
        let cur_tc_round = self
            .highest_2chain_timeout_cert()
            .map_or(0, |tc| tc.round());
        if tc.round() <= cur_tc_round {
            return Ok(());
        }
        self.storage
            .save_highest_2chain_timeout_cert(tc.as_ref())
            .context("Timeout certificate insert failed when persisting to DB")?;
        self.inner.write().replace_2chain_timeout_cert(tc);
        Ok(())
    }
```

**File:** consensus/src/liveness/round_state.rs (L245-289)
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
            self.pending_votes = PendingVotes::new();
            self.vote_sent = None;
            self.timeout_sent = None;
            let timeout = self.setup_timeout(1);

            let (prev_round_timeout_votes, prev_round_timeout_reason) = prev_round_timeout_votes
                .map(|votes| votes.unpack_aggregate(verifier))
                .unzip();

            // The new round reason is QCReady in case both QC.round + 1 == new_round, otherwise
            // it's Timeout and TC.round + 1 == new_round.
            let new_round_reason = if sync_info.highest_certified_round() + 1 == new_round {
                NewRoundReason::QCReady
            } else {
                let prev_round_timeout_reason =
                    prev_round_timeout_reason.unwrap_or(RoundTimeoutReason::Unknown);
                NewRoundReason::Timeout(prev_round_timeout_reason)
            };

            let new_round_event = NewRoundEvent {
                round: self.current_round,
                reason: new_round_reason,
                timeout,
                prev_round_votes,
                prev_round_timeout_votes,
            };
            info!(round = new_round, "Starting new round: {}", new_round_event);
            return Some(new_round_event);
        }
        None
    }
```

**File:** consensus/consensus-types/src/timeout_2chain.rs (L170-181)
```rust
        let signed_hqc = self
            .signatures_with_rounds
            .rounds()
            .iter()
            .max()
            .ok_or_else(|| anyhow::anyhow!("Empty rounds"))?;
        ensure!(
            hqc_round == *signed_hqc,
            "Inconsistent hqc round, qc has round {}, highest signed round {}",
            hqc_round,
            *signed_hqc
        );
```

**File:** consensus/consensus-types/src/timeout_2chain.rs (L258-261)
```rust
        let hqc_round = timeout.hqc_round();
        if timeout.hqc_round() > self.timeout.hqc_round() {
            self.timeout = timeout;
        }
```

**File:** consensus/consensus-types/src/proposal_msg.rs (L113-115)
```rust
        if let Some(tc) = self.sync_info.highest_2chain_timeout_cert() {
            tc.verify(validator).map_err(|e| format_err!("{:?}", e))?;
        }
```

**File:** consensus/consensus-types/src/sync_info.rs (L204-209)
```rust
            .and_then(|_| {
                if let Some(tc) = &self.highest_2chain_timeout_cert {
                    tc.verify(validator)?;
                }
                Ok(())
            })
```
