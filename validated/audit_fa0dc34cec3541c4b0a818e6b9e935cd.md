# Audit Report

## Title
Missing next_epoch_state Validation in BlockInfo Consistency Check Causes Silent Failure During Epoch Transitions

## Summary
The `match_ordered_only()` validation in BlockInfo does not check the `next_epoch_state` field, creating a validation gap where validators with divergent epoch states can pass consistency checks but fail to aggregate signatures during epoch transitions. This results in silent liveness failures without raising the `InconsistentExecutionResult` error that should alert operators to execution divergence.

## Finding Description

The consensus pipeline validates consistency between ordered and executed BlockInfo using `match_ordered_only()`, which only compares four fields: epoch, round, id, and timestamp_usecs. [1](#0-0) 

Critically, this validation omits the `next_epoch_state` field, which contains the validator set for the next epoch populated during reconfiguration. [2](#0-1) 

When validators execute a reconfiguration block, the `ensure_next_epoch_state()` function extracts the ValidatorSet from the transaction write set: [3](#0-2) 

If execution produces different ValidatorSet values across validators (due to non-deterministic execution bugs or state divergence), the safety rules validation in `guarded_sign_commit_vote()` uses only `match_ordered_only()` and thus fails to detect the divergence: [4](#0-3) 

However, during signature aggregation, votes are filtered by exact LedgerInfo equality, which DOES compare all BlockInfo fields including `next_epoch_state`: [5](#0-4) 

This creates a validation gap where validators pass the consistency check but cannot aggregate signatures. When voting power splits across different `next_epoch_state` values, no group reaches the 2/3 threshold, causing network halt without the expected `InconsistentExecutionResult` error. [6](#0-5) 

## Impact Explanation

**Severity: Medium** - State inconsistency requiring manual intervention

This vulnerability does NOT cause consensus safety violations because BLS signature aggregation requires validators to sign identical messages. Validators with different `next_epoch_state` values cannot aggregate their signatures, preventing invalid blocks from being committed.

However, it causes **liveness failures** during epoch transitions:
- Network halts when validators execute reconfigurations with divergent results
- The `InconsistentExecutionResult` error is never raised because `match_ordered_only()` doesn't validate execution result fields
- Operators see timeout/liveness issues without clear diagnostic errors indicating execution divergence
- Manual intervention is required to identify and resolve the underlying non-determinism

This fits the Medium severity category of "state inconsistencies requiring manual intervention" as it degrades the system's ability to detect and report execution divergence.

## Likelihood Explanation

**Likelihood: Low to Medium**

This issue manifests only when two conditions are met:
1. A reconfiguration block is executed (regular occurrence during epoch changes)
2. Validators produce different ValidatorSet values due to execution non-determinism

The second condition should be rare in a properly implemented system. Execution determinism is a core property of Aptos. However, this validation serves as a critical defense-in-depth mechanism to detect when that property is violated.

Potential triggers include:
- Subtle bugs in Move VM execution causing non-deterministic behavior
- State synchronization issues where validators have different base states
- Bugs in the staking framework's epoch transition logic
- Race conditions in validator set computation

While such bugs should not exist, historical blockchain incidents demonstrate that subtle non-determinism issues do occur in practice, making this defensive validation gap a legitimate concern.

## Recommendation

Extend the `match_ordered_only()` validation to explicitly verify that both BlockInfo instances agree on the presence/absence of epoch transitions, even if the exact `next_epoch_state` values differ between ordered and executed states:

```rust
pub fn match_ordered_only(&self, executed_block_info: &BlockInfo) -> bool {
    self.epoch == executed_block_info.epoch
        && self.round == executed_block_info.round
        && self.id == executed_block_info.id
        && (self.timestamp_usecs == executed_block_info.timestamp_usecs
            || (self.timestamp_usecs > executed_block_info.timestamp_usecs
                && executed_block_info.has_reconfiguration()))
        // Validate both agree on reconfiguration status
        && self.has_reconfiguration() == executed_block_info.has_reconfiguration()
}
```

Alternatively, introduce a separate validation in `guarded_sign_commit_vote()` that compares execution result fields (including `next_epoch_state`, `executed_state_id`, and `version`) between validators' executed BlockInfo instances before signing, raising `InconsistentExecutionResult` when divergence is detected.

## Proof of Concept

The existing test suite validates that `InconsistentExecutionResult` is raised when ordered-only fields differ: [7](#0-6) 

However, no test validates the scenario where ordered-only fields match but execution result fields (like `next_epoch_state`) differ. This gap in test coverage reflects the validation gap in production code.

A complete PoC would require:
1. Simulating execution non-determinism to produce different `next_epoch_state` values
2. Demonstrating that `match_ordered_only()` passes validation
3. Showing that signature aggregation fails without raising `InconsistentExecutionResult`
4. Confirming network liveness failure without diagnostic errors

This scenario is difficult to reproduce in a unit test as it requires actual execution divergence across multiple validator instances.

---

## Notes

This is a **defense-in-depth validation gap** rather than a directly exploitable vulnerability. It only manifests when a separate bug (execution non-determinism) exists elsewhere in the system. However, it represents a legitimate security concern because:

1. The validation logic has an inconsistency: fields affecting signature aggregation are not validated before signing
2. This makes debugging execution divergence significantly harder by suppressing the appropriate error
3. The same gap affects other execution result fields (`executed_state_id`, `version`) not just `next_epoch_state`
4. Historical blockchain incidents show non-determinism bugs do occur, making defensive validation critical

The Medium severity and Low-Medium likelihood assessments appropriately reflect that this is a validation completeness issue requiring a prerequisite bug to manifest, rather than a standalone critical vulnerability.

### Citations

**File:** types/src/block_info.rs (L42-43)
```rust
    /// An optional field containing the next epoch info
    next_epoch_state: Option<EpochState>,
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

**File:** execution/executor/src/workflow/do_get_execution_output.rs (L520-540)
```rust
    fn ensure_next_epoch_state(to_commit: &TransactionsWithOutput) -> Result<EpochState> {
        let last_write_set = to_commit
            .transaction_outputs
            .last()
            .ok_or_else(|| anyhow!("to_commit is empty."))?
            .write_set();

        let write_set_view = WriteSetStateView {
            write_set: last_write_set,
        };

        let validator_set = ValidatorSet::fetch_config(&write_set_view)
            .ok_or_else(|| anyhow!("ValidatorSet not touched on epoch change"))?;
        let configuration = ConfigurationResource::fetch_config(&write_set_view)
            .ok_or_else(|| anyhow!("Configuration resource not touched on epoch change"))?;

        Ok(EpochState::new(
            configuration.epoch(),
            (&validator_set).into(),
        ))
    }
```

**File:** consensus/safety-rules/src/safety_rules.rs (L395-403)
```rust
        if !old_ledger_info
            .commit_info()
            .match_ordered_only(new_ledger_info.commit_info())
        {
            return Err(Error::InconsistentExecutionResult(
                old_ledger_info.commit_info().to_string(),
                new_ledger_info.commit_info().to_string(),
            ));
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

**File:** consensus/safety-rules/src/error.rs (L53-54)
```rust
    #[error("Inconsistent Execution Result: Ordered BlockInfo doesn't match executed BlockInfo. Ordered: {0}, Executed: {1}")]
    InconsistentExecutionResult(String, String),
```

**File:** consensus/safety-rules/src/tests/suite.rs (L924-936)
```rust
    // inconsistent ledger_info test
    let bad_ledger_info = LedgerInfo::new(
        BlockInfo::random(ledger_info_with_sigs.ledger_info().round()),
        ledger_info_with_sigs.ledger_info().consensus_data_hash(),
    );

    assert!(matches!(
        safety_rules
            .sign_commit_vote(ledger_info_with_sigs.clone(), bad_ledger_info,)
            .unwrap_err(),
        Error::InconsistentExecutionResult(_, _)
    ));
}
```
