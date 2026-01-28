# Audit Report

## Title
Critical Double-Signing Vulnerability in Safety Rules Due to Sign-Before-Persist Pattern and Cache Invalidation

## Summary
The safety rules voting implementation contains a critical vulnerability where storage write failures combined with cache invalidation enable honest validators to sign conflicting votes for the same consensus round (equivocation), violating BFT consensus safety guarantees.

## Finding Description

The vulnerability exists in the `guarded_construct_and_sign_vote_two_chain` function where the sign-before-persist pattern creates an equivocation window during storage failures.

**Sign-Before-Persist Pattern**: The cryptographic signature is created before safety state persistence. [1](#0-0) 

The signature is created at line 88, but the safety data (including `last_voted_round` and `last_vote`) is only persisted at line 92. If storage write fails, the signature was created but safety guards are not durably recorded.

**Cache Invalidation on Storage Errors**: When `set_safety_data` fails, the cache is explicitly cleared. [2](#0-1) 

Line 166 sets `self.cached_safety_data = None` on storage write failure. Subsequent reads fetch stale data from storage that doesn't include the failed update.

**Attack Scenario**:

1. Validator receives Proposal A for Round 10
2. SafetyRules reads `safety_data` from storage: `last_voted_round = 9` [3](#0-2) 
3. SafetyRules updates in-memory `last_voted_round = 10` [4](#0-3) 
4. SafetyRules signs Vote(Block A, Round 10)
5. Storage write **FAILS** at line 92
6. Cache cleared, error propagates to consensus
7. Consensus layer does not call `record_vote` since `vote_block` failed [5](#0-4) 
8. Validator receives Proposal B for Round 10 (Byzantine proposer sends conflicting proposal)
9. Consensus check passes because `vote_sent()` is None [6](#0-5) 
10. SafetyRules reads stale `safety_data` with `last_voted_round = 9` (cache was cleared)
11. Voting round check passes: 10 > 9 [7](#0-6) 
12. SafetyRules signs Vote(Block B, Round 10)
13. **EQUIVOCATION**: Two votes signed for same round, different blocks

**Why Idempotency Check Fails**: The idempotency check only works if `last_vote` was successfully persisted. [8](#0-7) 

After storage failure, `last_vote` is not in storage, so this check doesn't prevent double-signing.

**Contrast with Timeout Signing**: The timeout signing function uses persist-before-sign pattern (persists at line 47, signs at line 49), which is safe. [9](#0-8) 

This inconsistency suggests the vulnerability may have been overlooked during development.

## Impact Explanation

**Critical Severity** - This enables "Consensus/Safety violations" per Aptos Bug Bounty criteria (up to $1,000,000).

The vulnerability violates the fundamental BFT safety invariant: honest validators (< 2/3) cannot equivocate. Specifically:

- **Breaks BFT Safety Guarantees**: Even with < 1/3 Byzantine validators, consensus safety can be violated because honest validators unintentionally contribute to equivocation during operational failures
- **Chain Splits**: Equivocation enables double-spending and chain forks without requiring > 1/3 Byzantine stake
- **Cryptographic Accountability Violation**: The system assumes only malicious validators equivocate; this bug makes honest validators appear Byzantine
- **Loss of Funds**: Chain splits and double-spending can lead to direct financial losses

## Likelihood Explanation

**Medium-High Likelihood** - All required conditions are realistic in production:

**Storage Failures**: Common causes include:
- Disk space exhaustion
- File system errors  
- Network-attached storage unavailability
- HashiCorp Vault service disruptions
- Permission issues
- Hardware failures

**Byzantine Proposals**: The system is designed to tolerate < 1/3 Byzantine validators who can send conflicting proposals - this is within the threat model and expected to occur.

**No Special Timing Required**: The attack doesn't require precise coordination - storage failure and Byzantine proposal just need to occur in sequence.

**Operational Reality**: Validators experience storage issues during normal operations, and Byzantine behavior is continuously tested by the protocol.

## Recommendation

**Fix: Implement Persist-Before-Sign Pattern**

Modify `guarded_construct_and_sign_vote_two_chain` to persist safety data BEFORE creating the signature, matching the pattern used in `guarded_sign_timeout_with_qc`:

```rust
// Move these lines BEFORE signature creation
safety_data.last_vote = Some(vote.clone());
self.persistent_storage.set_safety_data(safety_data)?;

// Then create signature
let signature = self.sign(&ledger_info)?;
let vote = Vote::new_with_signature(vote_data, author, ledger_info, signature);
```

**Alternative Fix: Add Transaction ID Tracking**

Implement request deduplication by tracking processed request IDs to prevent signing multiple votes for the same round even if persistence fails.

## Proof of Concept

The vulnerability can be demonstrated with a Rust integration test:

1. Configure SafetyRules with a mock storage backend that fails on the second write
2. Send vote request for Block A, Round 10 - signature created, storage fails
3. Send vote request for Block B, Round 10 - different proposal, same round
4. Verify two different signatures were created for the same round
5. Confirm equivocation occurred

A complete PoC would require mocking the storage layer to inject failures at the specific point after signature creation but before persistence completes.

## Notes

The infinite retry loop mentioned in the original report [10](#0-9)  only retries on network errors, not storage errors. The core vulnerability exists even without the retry mechanism - it's the sign-before-persist pattern combined with cache invalidation that enables equivocation.

The timeout signing implementation demonstrates the correct pattern (persist-before-sign), suggesting this vulnerability may be an oversight rather than a systematic architectural flaw.

### Citations

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L19-51)
```rust
    pub(crate) fn guarded_sign_timeout_with_qc(
        &mut self,
        timeout: &TwoChainTimeout,
        timeout_cert: Option<&TwoChainTimeoutCertificate>,
    ) -> Result<bls12381::Signature, Error> {
        self.signer()?;
        let mut safety_data = self.persistent_storage.safety_data()?;
        self.verify_epoch(timeout.epoch(), &safety_data)?;
        if !self.skip_sig_verify {
            timeout
                .verify(&self.epoch_state()?.verifier)
                .map_err(|e| Error::InvalidTimeout(e.to_string()))?;
        }
        if let Some(tc) = timeout_cert {
            self.verify_tc(tc)?;
        }

        self.safe_to_timeout(timeout, timeout_cert, &safety_data)?;
        if timeout.round() < safety_data.last_voted_round {
            return Err(Error::IncorrectLastVotedRound(
                timeout.round(),
                safety_data.last_voted_round,
            ));
        }
        if timeout.round() > safety_data.last_voted_round {
            self.verify_and_update_last_vote_round(timeout.round(), &mut safety_data)?;
        }
        self.update_highest_timeout_round(timeout, &mut safety_data);
        self.persistent_storage.set_safety_data(safety_data)?;

        let signature = self.sign(&timeout.signing_format())?;
        Ok(signature)
    }
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L66-66)
```rust
        let mut safety_data = self.persistent_storage.safety_data()?;
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L68-74)
```rust
        // if already voted on this round, send back the previous vote
        // note: this needs to happen after verifying the epoch as we just check the round here
        if let Some(vote) = safety_data.last_vote.clone() {
            if vote.vote_data().proposed().round() == proposed_block.round() {
                return Ok(vote);
            }
        }
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L88-92)
```rust
        let signature = self.sign(&ledger_info)?;
        let vote = Vote::new_with_signature(vote_data, author, ledger_info, signature);

        safety_data.last_vote = Some(vote.clone());
        self.persistent_storage.set_safety_data(safety_data)?;
```

**File:** consensus/safety-rules/src/persistent_safety_storage.rs (L160-169)
```rust
        match self.internal_store.set(SAFETY_DATA, data.clone()) {
            Ok(_) => {
                self.cached_safety_data = Some(data);
                Ok(())
            },
            Err(error) => {
                self.cached_safety_data = None;
                Err(Error::SecureStorageUnexpectedError(error.to_string()))
            },
        }
```

**File:** consensus/safety-rules/src/safety_rules.rs (L213-232)
```rust
    pub(crate) fn verify_and_update_last_vote_round(
        &self,
        round: Round,
        safety_data: &mut SafetyData,
    ) -> Result<(), Error> {
        if round <= safety_data.last_voted_round {
            return Err(Error::IncorrectLastVotedRound(
                round,
                safety_data.last_voted_round,
            ));
        }

        safety_data.last_voted_round = round;
        trace!(
            SafetyLogSchema::new(LogEntry::LastVotedRound, LogEvent::Update)
                .last_voted_round(safety_data.last_voted_round)
        );

        Ok(())
    }
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

**File:** consensus/safety-rules/src/remote_service.rs (L73-81)
```rust
    fn request(&mut self, input: SafetyRulesInput) -> Result<Vec<u8>, Error> {
        let input_message = serde_json::to_vec(&input)?;
        loop {
            match self.process_one_message(&input_message) {
                Err(err) => warn!("Failed to communicate with SafetyRules service: {}", err),
                Ok(value) => return Ok(value),
            }
        }
    }
```
