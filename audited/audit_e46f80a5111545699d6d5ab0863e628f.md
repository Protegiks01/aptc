# Audit Report

## Title
Order Vote Aggregation Failure Due to Race Condition Between Block Execution and Order Vote Creation

## Summary
When order votes are enabled in JolteonV2 consensus, a timing race condition exists between asynchronous block execution completing and order vote creation. Validators whose execution completes before they create their order vote will fail the safety check because their `BlockInfo` contains real execution results while the `QuorumCert` contains placeholder values, preventing order vote QC formation and potentially blocking consensus liveness.

## Finding Description

In Aptos's decoupled execution model with order votes enabled, the following sequence occurs:

1. **Voting Phase**: Validators vote on block ordering using `vote_data_ordering_only()` which creates `BlockInfo` with `ACCUMULATOR_PLACEHOLDER_HASH` as the `executed_state_id` and version 0. [1](#0-0) 

2. **QC Formation**: When enough votes aggregate, a `QuorumCert` is formed with `certified_block()` containing the placeholder values. [2](#0-1) 

3. **Block Insertion**: The `new_qc_aggregated` function inserts the QC and block, which starts asynchronous pipeline execution. [3](#0-2) 

4. **Async Execution**: Pipeline execution starts immediately when the block is inserted, running in the background. [4](#0-3) 

5. **Order Vote Creation**: After `new_qc_aggregated` completes, `broadcast_order_vote` is called. [5](#0-4) 

**The Race Condition**: Between steps 4 and 5, execution can complete and call `set_compute_result`, updating the block's state with real execution results. [6](#0-5) 

When creating the `OrderVoteProposal`, the code calls `block.block_info()` which derives `BlockInfo` from the current `compute_result()`: [7](#0-6) 

If execution has completed, `compute_result()` returns the real state root instead of `ACCUMULATOR_PLACEHOLDER_HASH`. The safety verification then fails: [8](#0-7) 

The check at line 97 compares `BlockInfo` structs which include `executed_state_id` and `version` fields: [9](#0-8) 

**Result**: Validators with fast execution cannot create order votes because the verification fails (QC has placeholder, block_info has real values). If enough validators experience this timing issue, order vote QC formation fails, blocking consensus progress.

## Impact Explanation

**Severity: High** (Significant protocol violations / Validator node slowdowns)

This vulnerability breaks the **Consensus Safety** invariant that all validators must produce and sign identical consensus data. While the safety check prevents validators from signing inconsistent data (avoiding a worse consensus split), the failure to create order votes has serious consequences:

1. **Liveness Impact**: If a majority of validators have fast execution and hit this race condition, the order vote QC cannot form, blocking the decoupled execution pipeline
2. **Unpredictable Behavior**: The outcome depends on network latency, CPU speed, and execution workload - making it non-deterministic
3. **Protocol Violation**: The decoupled execution feature with order votes becomes unreliable in production

This does not qualify for **Critical** severity because:
- It doesn't enable fund theft or minting
- The safety check prevents consensus splits
- It's a liveness issue rather than a safety break

However, it meets **High** severity criteria as a significant protocol violation that can cause validator slowdowns and consensus delays.

## Likelihood Explanation

**Likelihood: High**

This race condition is highly likely to occur in production because:

1. **Always Enabled**: `decoupled_execution()` is hardcoded to return `true` [10](#0-9) 

2. **Feature Dependency**: When `order_vote_enabled` is true for JolteonV2, this code path is always executed [11](#0-10) 

3. **Variable Execution Times**: Different validators have different hardware, network conditions, and load, making execution completion times naturally variable

4. **Asynchronous Design**: The pipeline execution is explicitly asynchronous, allowing it to complete at any point after block insertion

5. **No Synchronization**: There's no mechanism to wait for execution to NOT complete before creating order votes - the code assumes blocks maintain dummy state

## Recommendation

The root cause is that `OrderVoteProposal` construction uses the current execution state via `block_info()`, which can change asynchronously. Since order votes should represent ordering consensus (not execution), they should use the same dummy/placeholder values that were used in the original QC voting.

**Fix**: Modify `order_vote_proposal()` to use the `certified_block` from the QC directly instead of calling `block_info()`:

```rust
// In consensus/consensus-types/src/pipelined_block.rs
pub fn order_vote_proposal(&self, quorum_cert: Arc<QuorumCert>) -> OrderVoteProposal {
    // Use the certified_block from the QC, which has the ordering-only values
    // that all validators agreed on during voting
    OrderVoteProposal::new(
        self.block.clone(), 
        quorum_cert.certified_block().clone(),  // Changed from self.block_info()
        quorum_cert
    )
}
```

This ensures:
1. All validators use the identical `BlockInfo` from the QC
2. No dependency on timing or execution state
3. Consistency with the original voting values
4. The verification check at `safety_rules.rs:97` will always pass

## Proof of Concept

```rust
// Reproduction test demonstrating the race condition
// File: consensus/src/round_manager_tests/order_vote_race_test.rs

#[tokio::test]
async fn test_order_vote_race_condition() {
    use consensus_types::pipelined_block::PipelinedBlock;
    use executor_types::state_compute_result::StateComputeResult;
    use aptos_crypto::hash::ACCUMULATOR_PLACEHOLDER_HASH;
    
    // Create block with dummy state (as done in new_ordered)
    let block = create_test_block();
    let pipelined_block = PipelinedBlock::new_ordered(
        block.clone(),
        OrderedBlockWindow::empty()
    );
    
    // Create QC with ACCUMULATOR_PLACEHOLDER_HASH (from decoupled execution voting)
    let qc = create_test_qc_with_placeholder_hash(&block);
    
    // Verify block_info initially has placeholder
    assert_eq!(
        pipelined_block.block_info().executed_state_id(),
        *ACCUMULATOR_PLACEHOLDER_HASH
    );
    
    // Create OrderVoteProposal BEFORE execution - should work
    let proposal_before = pipelined_block.order_vote_proposal(qc.clone());
    assert_eq!(
        qc.certified_block().executed_state_id(),
        proposal_before.block_info().executed_state_id()
    );
    
    // Simulate execution completing (race condition)
    let real_compute_result = StateComputeResult::new_dummy_with_root_hash(
        HashValue::random() // Real state root, not placeholder
    );
    pipelined_block.set_compute_result(real_compute_result, Duration::from_secs(1));
    
    // Verify block_info NOW has real state root
    assert_ne!(
        pipelined_block.block_info().executed_state_id(),
        *ACCUMULATOR_PLACEHOLDER_HASH
    );
    
    // Create OrderVoteProposal AFTER execution - FAILS verification
    let proposal_after = pipelined_block.order_vote_proposal(qc.clone());
    
    // This assertion demonstrates the bug:
    // QC has placeholder, but proposal_after has real execution state
    assert_ne!(
        qc.certified_block().executed_state_id(),
        proposal_after.block_info().executed_state_id()
    );
    
    // Safety rules verification would reject this:
    // qc.certified_block() != order_vote_proposal.block_info()
    let result = safety_rules.construct_and_sign_order_vote(&proposal_after);
    assert!(result.is_err()); // Fails with InvalidOneChainQuorumCertificate
}
```

## Notes

This vulnerability demonstrates a subtle but critical timing assumption violation in the decoupled execution design. The safety verification correctly prevents signing inconsistent data, but the failure mode (inability to create order votes) still impacts consensus liveness. The fix aligns the implementation with the conceptual model: order votes represent ordering consensus using the same `BlockInfo` that validators originally agreed upon via the QC.

### Citations

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

**File:** consensus/consensus-types/src/quorum_cert.rs (L58-60)
```rust
    pub fn certified_block(&self) -> &BlockInfo {
        self.vote_data().proposed()
    }
```

**File:** consensus/src/round_manager.rs (L1789-1807)
```rust
                self.new_qc_aggregated(qc.clone(), vote.author())
                    .await
                    .context(format!(
                        "[RoundManager] Unable to process the created QC {:?}",
                        qc
                    ))?;
                if self.onchain_config.order_vote_enabled() {
                    // This check is already done in safety rules. As printing the "failed to broadcast order vote"
                    // in humio logs could sometimes look scary, we are doing the same check again here.
                    if let Some(last_sent_vote) = self.round_state.vote_sent() {
                        if let Some((two_chain_timeout, _)) = last_sent_vote.two_chain_timeout() {
                            if round <= two_chain_timeout.round() {
                                return Ok(());
                            }
                        }
                    }
                    // Broadcast order vote if the QC is successfully aggregated
                    // Even if broadcast order vote fails, the function will return Ok
                    if let Err(e) = self.broadcast_order_vote(vote, qc.clone()).await {
```

**File:** consensus/src/round_manager.rs (L1925-1937)
```rust
    async fn new_qc_aggregated(
        &mut self,
        qc: Arc<QuorumCert>,
        preferred_peer: Author,
    ) -> anyhow::Result<()> {
        let result = self
            .block_store
            .insert_quorum_cert(&qc, &mut self.create_block_retriever(preferred_peer))
            .await
            .context("[RoundManager] Failed to process a newly aggregated QC");
        self.process_certificates().await?;
        result
    }
```

**File:** consensus/src/block_storage/block_store.rs (L490-496)
```rust
            pipeline_builder.build_for_consensus(
                &pipelined_block,
                parent_block.pipeline_futs().ok_or_else(|| {
                    anyhow::anyhow!("Parent future doesn't exist, potentially epoch ended")
                })?,
                callback,
            );
```

**File:** consensus/consensus-types/src/pipelined_block.rs (L277-330)
```rust
    pub fn set_compute_result(
        &self,
        state_compute_result: StateComputeResult,
        execution_time: Duration,
    ) {
        let mut to_commit = 0;
        let mut to_retry = 0;
        for txn in state_compute_result.compute_status_for_input_txns() {
            match txn {
                TransactionStatus::Keep(_) => to_commit += 1,
                TransactionStatus::Retry => to_retry += 1,
                _ => {},
            }
        }

        let execution_summary = ExecutionSummary {
            payload_len: self
                .block
                .payload()
                .map_or(0, |payload| payload.len_for_execution()),
            to_commit,
            to_retry,
            execution_time,
            root_hash: state_compute_result.root_hash(),
            gas_used: state_compute_result
                .execution_output
                .block_end_info
                .as_ref()
                .map(|info| info.block_effective_gas_units()),
        };
        *self.state_compute_result.lock() = state_compute_result;

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
        }
    }
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

**File:** types/src/on_chain_config/consensus_config.rs (L68-75)
```rust
    pub fn order_vote_enabled(&self) -> bool {
        match self {
            ConsensusAlgorithmConfig::JolteonV2 {
                order_vote_enabled, ..
            } => *order_vote_enabled,
            _ => false,
        }
    }
```

**File:** types/src/on_chain_config/consensus_config.rs (L238-241)
```rust
    /// Decouple execution from consensus or not.
    pub fn decoupled_execution(&self) -> bool {
        true
    }
```
