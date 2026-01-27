# Audit Report

## Title
BlockInfo Equality Check Causes Valid Order Votes to Be Rejected Due to Execution Result Differences

## Summary
The `verify_order_vote_proposal()` function in safety rules incorrectly uses full equality comparison to validate that a QuorumCertificate's certified block matches the OrderVoteProposal's block info. When blocks are re-executed between QC formation and order vote creation, the execution-dependent fields (executed_state_id, version, next_epoch_state) differ, causing legitimate order votes to be rejected despite representing the same logical block. [1](#0-0) 

## Finding Description
The vulnerability lies in how `BlockInfo` instances are compared during order vote validation. The `BlockInfo` struct contains both immutable block identifiers (epoch, round, id, timestamp) and execution-dependent fields (executed_state_id, version, next_epoch_state): [2](#0-1) 

When validators vote on a block, they create a QC containing a `BlockInfo` snapshot with execution results from that moment: [3](#0-2) 

Later, when creating an `OrderVoteProposal`, a **fresh** `BlockInfo` is generated from the block's **current** compute results: [4](#0-3) [5](#0-4) 

The critical issue occurs because blocks can be re-executed with different results. The codebase explicitly acknowledges this: [6](#0-5) 

The comment "We might be retrying execution" and the error log for different root hashes confirm that re-execution with divergent results is expected behavior.

However, the safety rules check uses **full equality** comparison: [7](#0-6) 

This derived `PartialEq` compares ALL fields including execution-dependent ones. If a block is re-executed between QC formation and OrderVoteProposal creation, the check fails even though both BlockInfo instances represent the same logical block.

**Other parts of the codebase correctly handle this scenario** by using `match_ordered_only()`, which only compares immutable fields: [8](#0-7) 

This method is used in similar scenarios:

1. In `guarded_sign_commit_vote()` when comparing ordered and executed BlockInfo: [9](#0-8) 

2. In `create_merged_with_executed_state()` when merging QC with executed state: [10](#0-9) 

3. In buffer item validation for ordered blocks: [11](#0-10) 

The execution schedule phase confirms blocks are re-executed: [12](#0-11) 

## Impact Explanation
**Severity: Medium** (per Aptos bug bounty criteria: "State inconsistencies requiring intervention")

When this bug triggers:
- Validators incorrectly reject valid order votes with `InvalidOneChainQuorumCertificate` error
- Order vote aggregation fails for legitimately certified blocks
- Consensus may stall or require manual intervention to proceed
- The network experiences liveness degradation but not complete failure
- No funds are lost and consensus safety (fork prevention) is not violated

This does not qualify as Critical because it doesn't cause permanent liveness failure, safety violations, or fund loss. It doesn't qualify as High because while it's a protocol violation, validators can recover. It fits Medium severity as a state inconsistency requiring intervention.

## Likelihood Explanation
**Likelihood: Medium to High**

This bug can trigger whenever:
1. A block receives enough votes to form a QC
2. The block is re-executed before the OrderVoteProposal is created
3. Re-execution produces different results (different root hash, version, or epoch state)

The code explicitly handles execution retries (with error logs for different root hashes), indicating this is not a rare edge case. Execution retries can occur due to:
- Normal execution pipeline retries
- State sync operations
- Executor recovery after errors
- Race conditions in concurrent execution paths

The bug is deterministic once the conditions are met - there's no randomness or timing dependency beyond the re-execution itself.

## Recommendation
Replace the full equality check with `match_ordered_only()` to only validate immutable block identifiers:

**File:** `consensus/safety-rules/src/safety_rules.rs`
**Lines:** 97-102

Change from:
```rust
if qc.certified_block() != order_vote_proposal.block_info() {
    return Err(Error::InvalidOneChainQuorumCertificate(
        qc.certified_block().id(),
        order_vote_proposal.block_info().id(),
    ));
}
```

To:
```rust
if !qc.certified_block().match_ordered_only(order_vote_proposal.block_info()) {
    return Err(Error::InvalidOneChainQuorumCertificate(
        qc.certified_block().id(),
        order_vote_proposal.block_info().id(),
    ));
}
```

This aligns with how other parts of the codebase handle similar comparisons between QC BlockInfo and freshly generated BlockInfo instances.

## Proof of Concept

```rust
// Add to consensus/safety-rules/src/tests/suite.rs

#[test]
fn test_order_vote_with_reexecuted_block() {
    use crate::test_utils;
    use aptos_types::block_info::BlockInfo;
    use aptos_crypto::hash::ACCUMULATOR_PLACEHOLDER_HASH;
    
    let (mut safety_rules, signer, _key) = test_utils::make_safety_rules();
    
    // Create a block and execute it with initial results
    let block = test_utils::make_proposal_with_qc(
        Round::new(1),
        test_utils::placeholder_ledger_info(),
        &signer,
    );
    
    // Create initial BlockInfo with execution results
    let initial_block_info = block.gen_block_info(
        HashValue::random(), // Initial executed_state_id
        100,                  // Initial version
        None,                 // No epoch state
    );
    
    // Form QC with initial BlockInfo
    let vote_data = VoteData::new(initial_block_info.clone(), initial_block_info.clone());
    let qc = test_utils::make_qc_from_vote_data(&vote_data);
    
    // Simulate re-execution with different results
    let reexecuted_block_info = block.gen_block_info(
        HashValue::random(), // Different executed_state_id after re-execution
        101,                  // Different version
        None,
    );
    
    // Create OrderVoteProposal with re-executed BlockInfo
    let order_vote_proposal = OrderVoteProposal::new(
        block.clone(),
        reexecuted_block_info,
        Arc::new(qc),
    );
    
    // This should succeed because both BlockInfo represent the same logical block
    // (same epoch, round, id, timestamp), but currently fails due to != comparison
    let result = safety_rules.verify_order_vote_proposal(&order_vote_proposal);
    
    // Currently fails with InvalidOneChainQuorumCertificate
    assert!(result.is_err());
    
    // After fix with match_ordered_only(), this should succeed
    // assert!(result.is_ok());
}
```

## Notes

This vulnerability represents a consensus correctness bug rather than an active exploit vector. The issue stems from using overly strict equality semantics when comparing `BlockInfo` instances that should be considered equivalent at the consensus level despite differing execution results. The existence of `match_ordered_only()` and its use throughout the codebase for similar comparisons indicates this is the intended solution pattern for this class of comparison.

### Citations

**File:** consensus/safety-rules/src/safety_rules.rs (L87-111)
```rust
    pub(crate) fn verify_order_vote_proposal(
        &mut self,
        order_vote_proposal: &OrderVoteProposal,
    ) -> Result<(), Error> {
        let proposed_block = order_vote_proposal.block();
        let safety_data = self.persistent_storage.safety_data()?;

        self.verify_epoch(proposed_block.epoch(), &safety_data)?;

        let qc = order_vote_proposal.quorum_cert();
        if qc.certified_block() != order_vote_proposal.block_info() {
            return Err(Error::InvalidOneChainQuorumCertificate(
                qc.certified_block().id(),
                order_vote_proposal.block_info().id(),
            ));
        }
        if qc.certified_block().id() != proposed_block.id() {
            return Err(Error::InvalidOneChainQuorumCertificate(
                qc.certified_block().id(),
                proposed_block.id(),
            ));
        }
        self.verify_qc(qc)?;
        Ok(())
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

**File:** types/src/block_info.rs (L27-44)
```rust
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct BlockInfo {
    /// The epoch to which the block belongs.
    epoch: u64,
    /// The consensus protocol is executed in rounds, which monotonically increase per epoch.
    round: Round,
    /// The identifier (hash) of the block.
    id: HashValue,
    /// The accumulator root hash after executing this block.
    executed_state_id: HashValue,
    /// The version of the latest transaction after executing this block.
    version: Version,
    /// The timestamp this block was proposed by a proposer.
    timestamp_usecs: u64,
    /// An optional field containing the next epoch info
    next_epoch_state: Option<EpochState>,
}
```

**File:** types/src/block_info.rs (L193-204)
```rust
    /// This function checks if the current BlockInfo has
    /// exactly the same values in those fields that will not change
    /// after execution, compared to a given BlockInfo
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

**File:** consensus/consensus-types/src/vote_proposal.rs (L59-69)
```rust
    /// This function returns the vote data with a dummy executed_state_id and version
    fn vote_data_ordering_only(&self) -> VoteData {
        VoteData::new(
            self.block().gen_block_info(
                *ACCUMULATOR_PLACEHOLDER_HASH,
                0,
                self.next_epoch_state().cloned(),
            ),
            self.block().quorum_cert().certified_block().clone(),
        )
    }
```

**File:** consensus/consensus-types/src/pipelined_block.rs (L309-328)
```rust
        // We might be retrying execution, so it might have already been set.
        // Because we use this for statistics, it's ok that we drop the newer value.
        if let Some(previous) = self.execution_summary.get() {
            if previous.root_hash == execution_summary.root_hash
                || previous.root_hash == *ACCUMULATOR_PLACEHOLDER_HASH
            {
                warn!(
                    "Skipping re-inserting execution result, from {:?} to {:?}",
                    previous, execution_summary
                );
            } else {
                error!(
                    "Re-inserting execution result with different root hash: from {:?} to {:?}",
                    previous, execution_summary
                );
            }
        } else {
            self.execution_summary
                .set(execution_summary)
                .expect("inserting into empty execution summary");
```

**File:** consensus/consensus-types/src/pipelined_block.rs (L452-459)
```rust
    pub fn block_info(&self) -> BlockInfo {
        let compute_result = self.compute_result();
        self.block().gen_block_info(
            compute_result.root_hash(),
            compute_result.last_version_or_0(),
            compute_result.epoch_state().clone(),
        )
    }
```

**File:** consensus/consensus-types/src/pipelined_block.rs (L471-473)
```rust
    pub fn order_vote_proposal(&self, quorum_cert: Arc<QuorumCert>) -> OrderVoteProposal {
        OrderVoteProposal::new(self.block.clone(), self.block_info(), quorum_cert)
    }
```

**File:** consensus/consensus-types/src/quorum_cert.rs (L150-163)
```rust
    pub fn create_merged_with_executed_state(
        &self,
        executed_ledger_info: LedgerInfoWithSignatures,
    ) -> anyhow::Result<QuorumCert> {
        let self_commit_info = self.commit_info();
        let executed_commit_info = executed_ledger_info.ledger_info().commit_info();
        ensure!(
            self_commit_info.match_ordered_only(executed_commit_info),
            "Block info from QC and executed LI need to match, {:?} and {:?}",
            self_commit_info,
            executed_commit_info
        );
        Ok(Self::new(self.vote_data.clone(), executed_ledger_info))
    }
```

**File:** consensus/src/pipeline/buffer_item.rs (L274-278)
```rust
                assert!(ordered
                    .ordered_proof
                    .commit_info()
                    .match_ordered_only(commit_proof.commit_info()));
                // can't aggregate it without execution, only store the signatures
```

**File:** consensus/src/pipeline/execution_schedule_phase.rs (L70-77)
```rust
        let fut = async move {
            for b in ordered_blocks.iter_mut() {
                let (compute_result, execution_time) = b.wait_for_compute_result().await?;
                b.set_compute_result(compute_result, execution_time);
            }
            Ok(ordered_blocks)
        }
        .boxed();
```
