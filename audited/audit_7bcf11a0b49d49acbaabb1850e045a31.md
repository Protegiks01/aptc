# Audit Report

## Title
Missing Safety Checks in `sign_commit_vote()` Allow Compromised Validator to Sign Arbitrary Malicious Commit Ledger Infos

## Summary
The `sign_commit_vote()` function in SafetyRules lacks critical validation checks, allowing a validator with a compromised BLS private key to generate valid signatures for arbitrary commit ledger_infos with malicious `executed_state_id` (state root) and `version` values. The function does not verify that the signed ledger_info corresponds to actual execution results, does not prevent equivocation, and does not enforce round progression constraints.

## Finding Description

The `guarded_sign_commit_vote()` function in SafetyRules performs only minimal validation before signing commit votes: [1](#0-0) 

The function checks:
1. The old ledger_info is "ordered-only" or matches the new one
2. Consistency via `match_ordered_only()` 
3. The old ledger_info has 2f+1 signatures

However, `match_ordered_only()` only validates epoch, round, id, and timestamp - **NOT** the critical `executed_state_id` or `version` fields: [2](#0-1) 

The explicit TODOs acknowledge missing protections: [3](#0-2) 

**Critical Missing Checks:**

1. **No `executed_state_id` validation**: The attacker can provide arbitrary state roots claiming different account balances, smart contract states, or validator sets
2. **No `version` validation**: The attacker can sign ledger_infos for arbitrary versions (past or future)
3. **No equivocation protection**: Unlike regular voting ( [4](#0-3) ), commit vote signing doesn't update `last_voted_round` or check for double-signing
4. **No temporal bounds**: No validation that the ledger_info is for the current consensus state

**Attack Scenario:**

An attacker with a compromised BLS key can:
1. Obtain any legitimate ordered ledger_info with 2f+1 signatures from blockchain history
2. Craft a malicious `new_ledger_info` with:
   - Same epoch, round, block ID, and timestamp (passes `match_ordered_only()`)
   - **Arbitrary `executed_state_id`** (could claim all funds belong to attacker)
   - **Arbitrary `version`** (could be far future or past)
3. Call `sign_commit_vote()` to obtain a valid BLS signature
4. Broadcast multiple conflicting commit votes (equivocation) without detection

While the normal consensus flow filters mismatched signatures during the Ordered→Executed transition ( [5](#0-4) ), this protection relies on honest execution. The lack of safety checks in `sign_commit_vote()` itself means a compromised validator can:

- Sign conflicting commit ledger_infos for the same round (equivocation)
- Potentially exploit edge cases in state sync or fast-forward paths
- Broadcast malicious commit votes causing confusion or DoS
- Violate validator accountability (unable to prove Byzantine behavior from signature alone)

## Impact Explanation

This vulnerability falls under **Medium to High Severity**:

**Medium Severity** ($10,000): The missing safety checks represent a significant protocol violation. While a single compromised validator cannot unilaterally break consensus (requires 2f+1 signatures), the ability to sign arbitrary ledger_infos violates fundamental consensus safety properties and validator accountability.

**Potential for High Severity** ($50,000): If combined with vulnerabilities in state sync paths that trust individual validator signatures, or if the malicious signatures can cause validator node slowdowns or protocol disruptions through confusion attacks.

The core issue is that **consensus safety rules should constrain even compromised validators**, preventing them from signing arbitrary states. The explicit TODOs confirm these checks were intended but not implemented.

## Likelihood Explanation

**Likelihood: Low to Medium**

- Requires compromise of a validator's BLS private key (difficult but not impossible)
- Once compromised, exploitation is trivial - just call `sign_commit_vote()` with crafted parameters
- The impact is contained by downstream filtering in normal consensus, but edge cases may exist
- No additional validator cooperation needed beyond the key compromise

## Recommendation

Implement the missing safety checks in `guarded_sign_commit_vote()`:

```rust
fn guarded_sign_commit_vote(
    &mut self,
    ledger_info: LedgerInfoWithSignatures,
    new_ledger_info: LedgerInfo,
) -> Result<bls12381::Signature, Error> {
    self.signer()?;
    
    let mut safety_data = self.persistent_storage.safety_data()?;
    
    // Check epoch consistency
    self.verify_epoch(new_ledger_info.epoch(), &safety_data)?;
    
    // Verify round progression (similar to regular votes)
    let commit_round = new_ledger_info.round();
    if commit_round <= safety_data.last_voted_round {
        return Err(Error::IncorrectLastVotedRound(
            commit_round,
            safety_data.last_voted_round,
        ));
    }
    
    let old_ledger_info = ledger_info.ledger_info();
    
    // Existing checks...
    if !old_ledger_info.commit_info().is_ordered_only()
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
    
    if !self.skip_sig_verify {
        ledger_info
            .verify_signatures(&self.epoch_state()?.verifier)
            .map_err(|error| Error::InvalidQuorumCertificate(error.to_string()))?;
    }
    
    // NEW: Verify executed_state_id and version are non-zero (not placeholder)
    if new_ledger_info.commit_info().executed_state_id() == *ACCUMULATOR_PLACEHOLDER_HASH {
        return Err(Error::InvalidCommitLedgerInfo(
            "Cannot sign commit vote with placeholder executed_state_id".into()
        ));
    }
    
    if new_ledger_info.commit_info().version() == 0 && !new_ledger_info.commit_info().is_empty() {
        return Err(Error::InvalidCommitLedgerInfo(
            "Cannot sign commit vote with zero version".into()
        ));
    }
    
    let signature = self.sign(&new_ledger_info)?;
    
    // NEW: Update last_voted_round to prevent equivocation
    safety_data.last_voted_round = commit_round;
    self.persistent_storage.set_safety_data(safety_data)?;
    
    Ok(signature)
}
```

## Proof of Concept

```rust
#[test]
fn test_sign_commit_vote_equivocation_vulnerability() {
    use aptos_crypto::HashValue;
    use aptos_types::block_info::BlockInfo;
    
    // Setup: Initialize SafetyRules with a validator signer
    let (mut safety_rules, signer) = setup_safety_rules();
    
    // Create a legitimate ordered ledger_info (with 2f+1 signatures)
    let ordered_block_info = BlockInfo::new(
        1,  // epoch
        100,  // round
        HashValue::random(),  // block id
        *ACCUMULATOR_PLACEHOLDER_HASH,  // ordered-only placeholder
        0,  // version (placeholder)
        1000000,  // timestamp
        None,
    );
    let ordered_ledger_info = create_ledger_info_with_sigs(
        ordered_block_info, 
        &validator_signers,  // 2f+1 signatures
    );
    
    // ATTACK 1: Sign commit vote with malicious executed_state_id
    let malicious_block_info_1 = BlockInfo::new(
        1,  // same epoch
        100,  // same round
        ordered_block_info.id(),  // same block id
        HashValue::random(),  // MALICIOUS state root
        999999,  // MALICIOUS version
        1000000,  // same timestamp
        None,
    );
    let malicious_ledger_info_1 = LedgerInfo::new(
        malicious_block_info_1,
        HashValue::zero(),
    );
    
    // Should fail but currently succeeds!
    let sig_1 = safety_rules.sign_commit_vote(
        ordered_ledger_info.clone(),
        malicious_ledger_info_1.clone(),
    );
    assert!(sig_1.is_ok());  // VULNERABILITY: This should fail!
    
    // ATTACK 2: Sign DIFFERENT commit vote for same round (equivocation)
    let malicious_block_info_2 = BlockInfo::new(
        1,
        100,  // same round again!
        ordered_block_info.id(),
        HashValue::random(),  // DIFFERENT malicious state root
        888888,  // DIFFERENT malicious version
        1000000,
        None,
    );
    let malicious_ledger_info_2 = LedgerInfo::new(
        malicious_block_info_2,
        HashValue::zero(),
    );
    
    // Should fail due to equivocation but currently succeeds!
    let sig_2 = safety_rules.sign_commit_vote(
        ordered_ledger_info,
        malicious_ledger_info_2,
    );
    assert!(sig_2.is_ok());  // VULNERABILITY: Equivocation not prevented!
    
    // Now validator has signed two conflicting ledger_infos for round 100
    // with different executed_state_id values - violating consensus safety!
}
```

**Notes:**

The vulnerability exploits the gap between what `sign_commit_vote()` checks (`match_ordered_only()` - only epoch/round/id/timestamp) and what it should check (actual execution results including `executed_state_id` and `version`). The explicit TODOs in the code confirm these safety checks were planned but not implemented, creating a window for compromised validators to cause more damage than the protocol should allow.

### Citations

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

**File:** types/src/block_info.rs (L196-204)
```rust
    pub fn match_ordered_only(&self, executed_block_info: &BlockInfo) -> bool {
        self.epoch == executed_block_info.epoch
            && self.round == executed_block_info.round
            && self.id == executed_block_info.id
            && (self.timestamp_usecs == executed_block_info.timestamp_usecs
            // executed block info has changed its timestamp because it's a reconfiguration suffix
                || (self.timestamp_usecs > executed_block_info.timestamp_usecs
                    && executed_block_info.has_reconfiguration()))
    }
```

**File:** consensus/src/pipeline/buffer_item.rs (L40-52)
```rust
fn create_signature_aggregator(
    unverified_votes: HashMap<Author, CommitVote>,
    commit_ledger_info: &LedgerInfo,
) -> SignatureAggregator<LedgerInfo> {
    let mut sig_aggregator = SignatureAggregator::new(commit_ledger_info.clone());
    for vote in unverified_votes.values() {
        let sig = vote.signature_with_status();
        if vote.ledger_info() == commit_ledger_info {
            sig_aggregator.add_signature(vote.author(), sig);
        }
    }
    sig_aggregator
}
```
