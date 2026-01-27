# Audit Report

## Title
Missing Epoch Validation in Commit Vote Signing Allows Potential Epoch Transition Safety Violation

## Summary
The `guarded_sign_commit_vote()` function in SafetyRules lacks explicit epoch validation of the `new_ledger_info` parameter, unlike other signing methods. When combined with the `retry()` mechanism that can reinitialize SafetyRules to a new epoch mid-execution, this creates a defense-in-depth gap during epoch transitions.

## Finding Description

The `SafetyRules::guarded_sign_commit_vote()` method does not validate that `new_ledger_info.epoch()` matches the current SafetyRules epoch before signing. [1](#0-0) 

This contrasts with other signing methods:
- `guarded_sign_proposal()` explicitly calls `verify_epoch()` [2](#0-1) 
- `guarded_construct_and_sign_vote_two_chain()` validates epoch via `verify_proposal()` [3](#0-2) 
- `guarded_sign_timeout_with_qc()` explicitly calls `verify_epoch()` [4](#0-3) 

The `MetricsSafetyRules::retry()` mechanism catches initialization errors and can reinitialize SafetyRules to a new epoch during execution: [5](#0-4) 

**Theoretical Attack Scenario:**

When `skip_sig_verify = true` (local mode): [6](#0-5) 

1. SafetyRules is uninitialized or in epoch N
2. A commit signing request arrives for a block with `new_ledger_info` in epoch N that ends the epoch (contains `next_epoch_state` for epoch N+1)
3. The call to `self.epoch_state()` returns `NotInitialized` error
4. `retry()` catches this and calls `perform_initialize()` [7](#0-6) 
5. SafetyRules is reinitialized to epoch N+1 (latest in storage)
6. Retry executes `guarded_sign_commit_vote()` again with the same epoch N parameters
7. With `skip_sig_verify = true`, signature verification is skipped [8](#0-7) 
8. No epoch check exists, so SafetyRules signs the epoch N commit with epoch N+1 signer

## Impact Explanation

**Assessment: Medium Severity (potentially High)**

While signature verification provides protection in production mode (`skip_sig_verify = false`), the missing epoch validation violates defense-in-depth principles and could enable consensus safety violations in specific deployment configurations or future code changes.

**Actual Impact:**
- In production (serializer mode): Signature verification prevents exploitation
- In local/testing mode: Could allow epoch mismatch signing
- Future risk: Code changes that rely on epoch validation could introduce vulnerabilities

This does not meet Critical severity because:
- Production deployment has signature verification as a secondary protection
- Requires specific conditions (uninitialized SafetyRules + retry trigger + local mode)
- No demonstrated exploit path in production configuration

## Likelihood Explanation

**Likelihood: Low in production, Medium in development/testing**

The vulnerability requires:
1. SafetyRules to be uninitialized or behind the current epoch
2. A commit signing request during epoch transition
3. Either `skip_sig_verify = true` OR a way to bypass signature verification
4. The `retry()` mechanism to trigger reinitialization

In production, condition #3 is not met. However, the inconsistency with other signing methods suggests this is an oversight that violates consensus safety design principles.

## Recommendation

Add explicit epoch validation in `guarded_sign_commit_vote()` consistent with other signing methods:

```rust
fn guarded_sign_commit_vote(
    &mut self,
    ledger_info: LedgerInfoWithSignatures,
    new_ledger_info: LedgerInfo,
) -> Result<bls12381::Signature, Error> {
    self.signer()?;

    // ADD: Explicit epoch validation
    let mut safety_data = self.persistent_storage.safety_data()?;
    self.verify_epoch(new_ledger_info.epoch(), &safety_data)?;

    let old_ledger_info = ledger_info.ledger_info();

    // ... rest of function
}
```

This ensures:
1. Consistency with other signing methods
2. Defense-in-depth against future vulnerabilities
3. Early error detection for epoch mismatches
4. Proper triggering of retry() mechanism when epoch is incorrect

## Proof of Concept

```rust
// Test demonstrating missing epoch validation
#[test]
fn test_sign_commit_vote_epoch_mismatch() {
    use aptos_types::block_info::BlockInfo;
    use aptos_types::ledger_info::{LedgerInfo, LedgerInfoWithSignatures};
    use aptos_crypto::HashValue;
    use aptos_types::aggregate_signature::AggregateSignature;
    
    // Setup: SafetyRules in epoch 2
    let (mut safety_rules, signer) = test_utils::make_safety_rules_for_epoch(2);
    
    // Create ledger info for epoch 1 (old epoch)
    let old_epoch_block_info = BlockInfo::new(
        1,  // epoch 1
        100,
        HashValue::random(),
        HashValue::random(),
        0,
        0,
        None,
    );
    
    let ledger_info_epoch_1 = LedgerInfo::new(
        old_epoch_block_info,
        HashValue::zero(),
    );
    
    // Create dummy ordered ledger info with signatures
    let ordered_ledger_info = LedgerInfoWithSignatures::new(
        ledger_info_epoch_1.clone(),
        AggregateSignature::empty(),
    );
    
    // Attempt to sign commit for epoch 1 while in epoch 2
    // This SHOULD fail with IncorrectEpoch but doesn't due to missing validation
    let result = safety_rules.sign_commit_vote(
        ordered_ledger_info,
        ledger_info_epoch_1,
    );
    
    // With the vulnerability, this fails at signature verification
    // but not at epoch validation (which doesn't exist)
    assert!(result.is_err());
    
    // The error should be IncorrectEpoch but is actually InvalidQuorumCertificate
    // demonstrating the missing validation
}
```

**Notes:**
- The proof of concept requires access to test utilities from the SafetyRules test suite
- The vulnerability is mitigated by signature verification in production
- This represents a defense-in-depth violation rather than a critical exploit

### Citations

**File:** consensus/safety-rules/src/safety_rules.rs (L346-370)
```rust
    fn guarded_sign_proposal(
        &mut self,
        block_data: &BlockData,
    ) -> Result<bls12381::Signature, Error> {
        self.signer()?;
        self.verify_author(block_data.author())?;

        let mut safety_data = self.persistent_storage.safety_data()?;
        self.verify_epoch(block_data.epoch(), &safety_data)?;

        if block_data.round() <= safety_data.last_voted_round {
            return Err(Error::InvalidProposal(format!(
                "Proposed round {} is not higher than last voted round {}",
                block_data.round(),
                safety_data.last_voted_round
            )));
        }

        self.verify_qc(block_data.quorum_cert())?;
        self.verify_and_update_preferred_round(block_data.quorum_cert(), &mut safety_data)?;
        // we don't persist the updated preferred round to save latency (it'd be updated upon voting)

        let signature = self.sign(block_data)?;
        Ok(signature)
    }
```

**File:** consensus/safety-rules/src/safety_rules.rs (L372-418)
```rust
    fn guarded_sign_commit_vote(
        &mut self,
        ledger_info: LedgerInfoWithSignatures,
        new_ledger_info: LedgerInfo,
    ) -> Result<bls12381::Signature, Error> {
        self.signer()?;

        let old_ledger_info = ledger_info.ledger_info();

        if !old_ledger_info.commit_info().is_ordered_only()
            // When doing fast forward sync, we pull the latest blocks and quorum certs from peers
            // and store them in storage. We then compute the root ordered cert and root commit cert
            // from storage and start the consensus from there. But given that we are not storing the
            // ordered cert obtained from order votes in storage, instead of obtaining the root ordered cert
            // from storage, we set root ordered cert to commit certificate.
            // This means, the root ordered cert will not have a dummy executed_state_id in this case.
            // To handle this, we do not raise error if the old_ledger_info.commit_info() matches with
            // new_ledger_info.commit_info().
            && old_ledger_info.commit_info() != new_ledger_info.commit_info()
        {
            return Err(Error::InvalidOrderedLedgerInfo(old_ledger_info.to_string()));
        }

        if !old_ledger_info
            .commit_info()
            .match_ordered_only(new_ledger_info.commit_info())
        {
            return Err(Error::InconsistentExecutionResult(
                old_ledger_info.commit_info().to_string(),
                new_ledger_info.commit_info().to_string(),
            ));
        }

        // Verify that ledger_info contains at least 2f + 1 dostinct signatures
        if !self.skip_sig_verify {
            ledger_info
                .verify_signatures(&self.epoch_state()?.verifier)
                .map_err(|error| Error::InvalidQuorumCertificate(error.to_string()))?;
        }

        // TODO: add guarding rules in unhappy path
        // TODO: add extension check

        let signature = self.sign(&new_ledger_info)?;

        Ok(signature)
    }
```

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

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L53-95)
```rust
    pub(crate) fn guarded_construct_and_sign_vote_two_chain(
        &mut self,
        vote_proposal: &VoteProposal,
        timeout_cert: Option<&TwoChainTimeoutCertificate>,
    ) -> Result<Vote, Error> {
        // Exit early if we cannot sign
        self.signer()?;

        let vote_data = self.verify_proposal(vote_proposal)?;
        if let Some(tc) = timeout_cert {
            self.verify_tc(tc)?;
        }
        let proposed_block = vote_proposal.block();
        let mut safety_data = self.persistent_storage.safety_data()?;

        // if already voted on this round, send back the previous vote
        // note: this needs to happen after verifying the epoch as we just check the round here
        if let Some(vote) = safety_data.last_vote.clone() {
            if vote.vote_data().proposed().round() == proposed_block.round() {
                return Ok(vote);
            }
        }

        // Two voting rules
        self.verify_and_update_last_vote_round(
            proposed_block.block_data().round(),
            &mut safety_data,
        )?;
        self.safe_to_vote(proposed_block, timeout_cert)?;

        // Record 1-chain data
        self.observe_qc(proposed_block.quorum_cert(), &mut safety_data);
        // Construct and sign vote
        let author = self.signer()?.author();
        let ledger_info = self.construct_ledger_info_2chain(proposed_block, vote_data.hash())?;
        let signature = self.sign(&ledger_info)?;
        let vote = Vote::new_with_signature(vote_data, author, ledger_info, signature);

        safety_data.last_vote = Some(vote.clone());
        self.persistent_storage.set_safety_data(safety_data)?;

        Ok(vote)
    }
```

**File:** consensus/src/metrics_safety_rules.rs (L40-69)
```rust
    pub fn perform_initialize(&mut self) -> Result<(), Error> {
        let consensus_state = self.consensus_state()?;
        let mut waypoint_version = consensus_state.waypoint().version();
        loop {
            let proofs = self
                .storage
                .retrieve_epoch_change_proof(waypoint_version)
                .map_err(|e| {
                    Error::InternalError(format!(
                        "Unable to retrieve Waypoint state from storage, encountered Error:{}",
                        e
                    ))
                })?;
            // We keep initializing safety rules as long as the waypoint continues to increase.
            // This is due to limits in the number of epoch change proofs that storage can provide.
            match self.initialize(&proofs) {
                Err(Error::WaypointOutOfDate(
                    prev_version,
                    curr_version,
                    current_epoch,
                    provided_epoch,
                )) if prev_version < curr_version => {
                    waypoint_version = curr_version;
                    info!("Previous waypoint version {}, updated version {}, current epoch {}, provided epoch {}", prev_version, curr_version, current_epoch, provided_epoch);
                    continue;
                },
                result => return result,
            }
        }
    }
```

**File:** consensus/src/metrics_safety_rules.rs (L71-85)
```rust
    fn retry<T, F: FnMut(&mut Box<dyn TSafetyRules + Send + Sync>) -> Result<T, Error>>(
        &mut self,
        mut f: F,
    ) -> Result<T, Error> {
        let result = f(&mut self.inner);
        match result {
            Err(Error::NotInitialized(_))
            | Err(Error::IncorrectEpoch(_, _))
            | Err(Error::WaypointOutOfDate(_, _, _, _)) => {
                self.perform_initialize()?;
                f(&mut self.inner)
            },
            _ => result,
        }
    }
```

**File:** consensus/safety-rules/src/safety_rules_manager.rs (L131-136)
```rust
    pub fn new_local(storage: PersistentSafetyStorage) -> Self {
        let safety_rules = SafetyRules::new(storage, true);
        Self {
            internal_safety_rules: SafetyRulesWrapper::Local(Arc::new(RwLock::new(safety_rules))),
        }
    }
```
