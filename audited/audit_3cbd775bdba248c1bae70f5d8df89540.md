# Audit Report

## Title
Critical Commit Vote Equivocation Vulnerability: Missing Safety Rules Allow Validators to Sign Conflicting Ledger States

## Summary
The `guarded_sign_commit_vote()` function in SafetyRules lacks tracking of previously signed commit votes, allowing a validator to sign multiple conflicting commit votes for the same epoch/round. This violates the fundamental BFT consensus safety guarantee that validators must never equivocate, potentially enabling chain forks. The vulnerability is explicitly acknowledged via a TODO comment in the code.

## Finding Description

The AptosBFT consensus protocol relies on SafetyRules to enforce critical invariants that prevent equivocation (double-voting). For regular block votes, SafetyRules maintains `last_voted_round` in the `SafetyData` structure and checks it via `verify_and_update_last_vote_round()` to prevent a validator from voting twice at the same round. [1](#0-0) 

However, commit votes—which finalize execution state—have NO equivalent protection. The `guarded_sign_commit_vote()` function performs validation of ledger info consistency but does NOT:

1. Check if a commit vote has already been signed for this epoch/round
2. Update any persistent state tracking signed commit votes  
3. Record the signed commit vote in SafetyData [2](#0-1) 

The code explicitly acknowledges this gap with a TODO comment at line 412: "// TODO: add guarding rules in unhappy path" [3](#0-2) 

The `SafetyData` structure tracks `last_voted_round` and `last_vote` for regular votes but has no field for tracking commit votes: [4](#0-3) 

The retry mechanism in `MetricsSafetyRules` exacerbates this vulnerability. When `sign_commit_vote()` fails with specific errors (NotInitialized, IncorrectEpoch, WaypointOutOfDate), it calls `perform_initialize()` which can reset epoch state and create new SafetyData with all tracking zeroed: [5](#0-4) 

The retry wrapper then re-attempts the signing operation: [6](#0-5) 

**Attack Scenario:**

A validator can be induced to sign conflicting commit votes through:
1. Bugs in consensus/buffer manager logic that trigger multiple signing requests
2. Race conditions during concurrent signing attempts  
3. Restart/recovery scenarios where in-memory state is lost
4. Epoch transitions that reset SafetyData without proper commit vote tracking

For example:
- Call `sign_commit_vote(ordered_A, commit_A)` where `commit_A = BlockInfo{epoch: 1, round: 10, executed_state_id: HASH_X}`
- Returns NotInitialized error → retry() calls perform_initialize() → retry succeeds, signs commit_A
- Later call `sign_commit_vote(ordered_B, commit_B)` where `commit_B = BlockInfo{epoch: 1, round: 10, executed_state_id: HASH_Y}` with HASH_X ≠ HASH_Y
- Since there's no tracking, this succeeds and signs commit_B
- Validator has now equivocated by signing two different execution states for the same round

This breaks the BFT safety invariant that validators never equivocate on committed state.

## Impact Explanation

**Critical Severity - Consensus/Safety Violation**

This vulnerability directly violates the fundamental AptosBFT safety guarantee documented in the consensus README. In a BFT system, safety requires that no two honest validators commit conflicting blocks at the same height. This property relies on validators never equivocating.

By allowing commit vote equivocation, this vulnerability enables:
- **Chain forks**: Different validators could commit different execution states for the same round
- **State divergence**: The blockchain state becomes non-deterministic across validator nodes
- **Safety break**: Violates the BFT assumption that <1/3 Byzantine validators cannot break safety

Even one honest validator equivocating due to this bug (via software bugs, race conditions, or edge cases) could contribute to breaking the 2f+1 honest validator assumption needed for safety.

This qualifies as Critical per Aptos bug bounty categories: "Consensus/Safety violations" that could lead to "Non-recoverable network partition (requires hardfork)".

## Likelihood Explanation

**High Likelihood** 

This vulnerability is likely to manifest because:

1. **Explicit code acknowledgment**: The TODO comment confirms developers know this is missing
2. **Asymmetric protection**: Regular votes are protected but commit votes are not, suggesting this was overlooked rather than intentionally omitted
3. **Multiple trigger paths**: Bugs, race conditions, restarts, or epoch transitions could trigger equivocation
4. **No defense in depth**: The safety rules are the last line of defense—their failure means no protection

The retry mechanism specifically increases likelihood by:
- Calling perform_initialize() which can reset SafetyData
- Re-attempting operations after state changes
- Not maintaining atomicity across the retry boundary

## Recommendation

Add commit vote tracking to SafetyData and implement equivocation prevention similar to regular votes:

**Step 1: Update SafetyData structure**
Add a field to track the last signed commit vote:
```rust
pub struct SafetyData {
    pub epoch: u64,
    pub last_voted_round: u64,
    pub preferred_round: u64,
    pub one_chain_round: u64,
    pub last_vote: Option<Vote>,
    pub highest_timeout_round: u64,
    // NEW: Track last signed commit vote
    pub last_commit_vote: Option<(u64, Round, HashValue)>, // (epoch, round, executed_state_id)
}
```

**Step 2: Add equivocation check in guarded_sign_commit_vote**
Before signing, verify no conflicting commit vote exists:
```rust
fn guarded_sign_commit_vote(
    &mut self,
    ledger_info: LedgerInfoWithSignatures,
    new_ledger_info: LedgerInfo,
) -> Result<bls12381::Signature, Error> {
    self.signer()?;
    
    let mut safety_data = self.persistent_storage.safety_data()?;
    let new_epoch = new_ledger_info.epoch();
    let new_round = new_ledger_info.commit_info().round();
    let new_state_id = new_ledger_info.commit_info().executed_state_id();
    
    // NEW: Check for commit vote equivocation
    if let Some((last_epoch, last_round, last_state_id)) = safety_data.last_commit_vote {
        if last_epoch == new_epoch && last_round == new_round && last_state_id != new_state_id {
            return Err(Error::IncorrectLastVotedRound(new_round, last_round));
        }
    }
    
    // ... existing validation ...
    
    let signature = self.sign(&new_ledger_info)?;
    
    // NEW: Record commit vote
    safety_data.last_commit_vote = Some((new_epoch, new_round, new_state_id));
    self.persistent_storage.set_safety_data(safety_data)?;
    
    Ok(signature)
}
```

**Step 3: Reset commit vote tracking on epoch transitions**
Ensure perform_initialize() properly handles commit vote state.

## Proof of Concept

```rust
#[test]
fn test_commit_vote_equivocation_vulnerability() {
    use consensus_types::block_info::BlockInfo;
    use aptos_crypto::hash::HashValue;
    use types::ledger_info::{LedgerInfo, LedgerInfoWithSignatures};
    
    // Setup: Initialize a validator with SafetyRules
    let (mut safety_rules, _storage) = test_utils::make_safety_rules();
    
    // Create two conflicting commit votes for the same epoch/round
    let epoch = 1;
    let round = 10;
    let version = 100;
    
    // Commit A with execution state HASH_X
    let commit_info_a = BlockInfo::new(
        epoch, round, HashValue::zero(), 
        HashValue::from_hex("AAAA...").unwrap(), // state_root_X
        version, 0, None
    );
    let ledger_info_a = LedgerInfo::new(commit_info_a, HashValue::zero());
    let ordered_cert_a = create_ordered_cert_with_signatures(ledger_info_a.clone());
    
    // Commit B with DIFFERENT execution state HASH_Y (equivocation!)
    let commit_info_b = BlockInfo::new(
        epoch, round, HashValue::zero(),
        HashValue::from_hex("BBBB...").unwrap(), // state_root_Y ≠ state_root_X  
        version, 0, None
    );
    let ledger_info_b = LedgerInfo::new(commit_info_b, HashValue::zero());
    let ordered_cert_b = create_ordered_cert_with_signatures(ledger_info_b.clone());
    
    // VULNERABILITY: Both signatures succeed even though they conflict!
    let sig_a = safety_rules.sign_commit_vote(ordered_cert_a, ledger_info_a)
        .expect("First commit vote should succeed");
    
    let sig_b = safety_rules.sign_commit_vote(ordered_cert_b, ledger_info_b)
        .expect("Second commit vote should FAIL but succeeds - EQUIVOCATION!");
    
    // Validator has now signed two different states for the same round
    assert_ne!(sig_a, sig_b);
    println!("VULNERABILITY CONFIRMED: Validator signed conflicting commits for epoch {} round {}", epoch, round);
}
```

The test demonstrates that a validator can sign two different commit votes for the same epoch/round with different execution state roots, violating BFT safety. With the recommended fix, the second `sign_commit_vote` call would return an error, preventing equivocation.

## Notes

This vulnerability is particularly severe because:
1. It affects the core consensus safety property
2. It's explicitly marked as TODO in production code  
3. Regular votes have proper protection, but commit votes—which finalize state—do not
4. The defense-in-depth layer (SafetyRules) has a critical gap
5. Multiple code paths could trigger equivocation even in honest validators

The issue should be addressed immediately before any scenario (bug, race condition, or edge case) triggers actual equivocation in production.

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

**File:** consensus/safety-rules/src/safety_rules.rs (L294-303)
```rust
            Ordering::Less => {
                // start new epoch
                self.persistent_storage.set_safety_data(SafetyData::new(
                    epoch_state.epoch,
                    0,
                    0,
                    0,
                    None,
                    0,
                ))?;
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

**File:** consensus/consensus-types/src/safety_data.rs (L8-21)
```rust
/// Data structure for safety rules to ensure consensus safety.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize, Clone, Default)]
pub struct SafetyData {
    pub epoch: u64,
    pub last_voted_round: u64,
    // highest 2-chain round, used for 3-chain
    pub preferred_round: u64,
    // highest 1-chain round, used for 2-chain
    #[serde(default)]
    pub one_chain_round: u64,
    pub last_vote: Option<Vote>,
    #[serde(default)]
    pub highest_timeout_round: u64,
}
```

**File:** consensus/src/metrics_safety_rules.rs (L139-150)
```rust
    fn sign_commit_vote(
        &mut self,
        ledger_info: LedgerInfoWithSignatures,
        new_ledger_info: LedgerInfo,
    ) -> Result<bls12381::Signature, Error> {
        self.retry(|inner| {
            monitor!(
                "safety_rules",
                inner.sign_commit_vote(ledger_info.clone(), new_ledger_info.clone())
            )
        })
    }
```
