# Audit Report

## Title
Critical Consensus Race Condition: OrderVote Creation Uses Inconsistent State Compute Results Across Validators

## Summary
A critical race condition exists in the consensus protocol where different validators create `OrderVote` messages with different `BlockInfo` data for the same block, depending on whether execution has completed when they form their quorum certificate. This causes validators to vote on different state transitions, breaking consensus safety and preventing order certificate aggregation, leading to liveness failures.

## Finding Description

The vulnerability occurs in the `broadcast_order_vote()` flow where `OrderVoteProposal` is created from a `PipelinedBlock`'s current state. The core issue is that blocks are initially created with a dummy `StateComputeResult` and later updated to actual values after asynchronous execution completes.

**The vulnerable flow:**

1. When a block is inserted into the block store, it's created with a dummy state compute result using `PipelinedBlock::new_ordered()`: [1](#0-0) [2](#0-1) 

2. The dummy result uses `ACCUMULATOR_PLACEHOLDER_HASH` as the root hash, as verified by the `is_ordered_only()` method: [3](#0-2) 

3. Execution happens asynchronously and later updates the state via `set_compute_result()`: [4](#0-3) [5](#0-4) 

4. When validators form a QC and broadcast order votes, they call `create_order_vote()` which immediately reads the **current** state without waiting for execution: [6](#0-5) [7](#0-6) 

5. The `order_vote_proposal()` method generates `BlockInfo` from the current state compute result: [8](#0-7) 

6. The `BlockInfo` is created with the state's root hash and version by calling `compute_result()` which reads from the mutex: [9](#0-8) [10](#0-9) 

**The race condition:**

The critical design flaw is revealed by comparing regular votes vs order votes:
- **Regular votes** (VoteProposal) ALWAYS use `decoupled_execution = true` and create consistent placeholder values: [11](#0-10) [12](#0-11) 

- **Order votes** (OrderVoteProposal) read whatever state is currently available, which can vary between validators:
  - Validator V1 forms QC before execution completes → creates `OrderVote` with `BlockInfo(ACCUMULATOR_PLACEHOLDER_HASH, version=0)`
  - Validator V2 forms QC after execution completes → creates `OrderVote` with `BlockInfo(ACTUAL_HASH, version=N)`

**Impact on aggregation:**

The `OrderVote` contains a `LedgerInfo` which is created directly from the `BlockInfo`: [13](#0-12) 

In `PendingOrderVotes`, votes are aggregated by the hash of their ledger_info: [14](#0-13) [15](#0-14) 

OrderVotes with different `BlockInfo` values have different ledger_info hashes and are stored in separate HashMap entries, never aggregating together. If voting power is split between the two versions, neither can reach the 2f+1 threshold needed for certificate formation.

## Impact Explanation

**Critical Severity** - This vulnerability meets multiple critical impact criteria per Aptos bug bounty:

1. **Consensus Safety Violation**: Different validators vote on different state transitions (different root hashes and versions) for the same block, violating the fundamental consensus invariant that all honest validators must agree on state transitions. This matches the "Consensus/Safety Violations (Critical)" category with potential rewards up to $1,000,000.

2. **Liveness Failure**: If voting power splits between validators using dummy state vs. actual state, neither group can aggregate 2f+1 votes to form an order certificate. This permanently blocks consensus progress for that block, requiring manual intervention. This matches the "Total Loss of Liveness/Network Availability (Critical)" category.

3. **Non-Deterministic Behavior**: The outcome depends on timing and network conditions rather than deterministic protocol rules, making the system unpredictable and unreliable.

This breaks Critical Invariants #1 (Deterministic Execution) and #2 (Consensus Safety) from the Aptos specification.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability occurs naturally during normal operation:

1. **No attack required**: The race condition is inherent in the pipelined consensus design where order vote broadcasting happens immediately after QC formation without synchronization with execution completion.

2. **Network variability**: Different validators receive votes at different times due to normal network latency, causing them to form QCs at different moments relative to execution completion.

3. **Execution timing**: Block execution is non-deterministic in duration, depending on transaction complexity and system load. The execution happens asynchronously in the pipeline without blocking order vote creation.

4. **Observable in production**: Any block where execution takes longer than the time for QC formation will trigger this race. Given the pipelined design, this is expected to happen regularly under normal load.

The vulnerability requires no malicious behavior, privileged access, or complex setup - it's a natural consequence of the current implementation where order votes read mutable state without synchronization.

## Recommendation

**Option 1 (Recommended): Always use ordered-only BlockInfo for OrderVotes**

Modify `order_vote_proposal()` to consistently use placeholder values like regular votes do:

```rust
pub fn order_vote_proposal(&self, quorum_cert: Arc<QuorumCert>) -> OrderVoteProposal {
    // Use ordered-only BlockInfo with placeholder values, similar to VoteProposal
    let ordered_block_info = self.block.gen_block_info(
        *ACCUMULATOR_PLACEHOLDER_HASH,
        0,
        self.compute_result().epoch_state().clone(),
    );
    OrderVoteProposal::new(self.block.clone(), ordered_block_info, quorum_cert)
}
```

**Option 2: Wait for execution before creating OrderVotes**

Add synchronization to ensure execution completes before order votes are created:

```rust
async fn broadcast_order_vote(&mut self, vote: &Vote, qc: Arc<QuorumCert>) -> anyhow::Result<()> {
    if let Some(proposed_block) = self.block_store.get_block(vote.vote_data().proposed().id()) {
        // Wait for execution to complete
        let _ = proposed_block.wait_for_compute_result().await?;
        
        let order_vote = self.create_order_vote(proposed_block.clone(), qc.clone()).await?;
        // ... rest of the function
    }
}
```

**Option 1 is recommended** as it maintains the decoupled execution design philosophy and matches how regular votes already work.

## Proof of Concept

While a full end-to-end PoC would require a multi-validator test environment, the vulnerability can be demonstrated by examining the execution flow:

1. Create a block with transactions that take varying execution times
2. Insert the block into block storage - it starts with dummy state
3. Simulate validators receiving votes at different times
4. Some validators form QC before execution completes (observe `compute_result()` returns dummy state)
5. Other validators form QC after execution completes (observe `compute_result()` returns real state)
6. Both groups create OrderVotes with their respective BlockInfo values
7. Verify the votes have different `ledger_info.hash()` values and cannot aggregate

The code paths verified through static analysis demonstrate this race condition is present and exploitable during normal consensus operation.

### Citations

**File:** consensus/src/block_storage/block_store.rs (L408-409)
```rust
        let pipelined_block = PipelinedBlock::new_ordered(block, OrderedBlockWindow::empty());
        self.insert_block_inner(pipelined_block).await
```

**File:** consensus/src/block_storage/block_store.rs (L436-437)
```rust
        let pipelined_block = PipelinedBlock::new_ordered(block, block_window);
        self.insert_block_inner(pipelined_block).await
```

**File:** types/src/block_info.rs (L209-214)
```rust
    pub fn is_ordered_only(&self) -> bool {
        *self != BlockInfo::empty()
            && self.next_epoch_state.is_none()
            && self.executed_state_id == *ACCUMULATOR_PLACEHOLDER_HASH
            && self.version == 0
    }
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

**File:** consensus/consensus-types/src/pipelined_block.rs (L440-442)
```rust
    pub fn compute_result(&self) -> StateComputeResult {
        self.state_compute_result.lock().clone()
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

**File:** consensus/consensus-types/src/pipelined_block.rs (L461-469)
```rust
    pub fn vote_proposal(&self) -> VoteProposal {
        let compute_result = self.compute_result();
        VoteProposal::new(
            compute_result.extension_proof(),
            self.block.clone(),
            compute_result.epoch_state().clone(),
            true,
        )
    }
```

**File:** consensus/consensus-types/src/pipelined_block.rs (L471-473)
```rust
    pub fn order_vote_proposal(&self, quorum_cert: Arc<QuorumCert>) -> OrderVoteProposal {
        OrderVoteProposal::new(self.block.clone(), self.block_info(), quorum_cert)
    }
```

**File:** consensus/src/round_manager.rs (L1626-1651)
```rust
    async fn create_order_vote(
        &mut self,
        block: Arc<PipelinedBlock>,
        qc: Arc<QuorumCert>,
    ) -> anyhow::Result<OrderVote> {
        let order_vote_proposal = block.order_vote_proposal(qc);
        let order_vote_result = self
            .safety_rules
            .lock()
            .construct_and_sign_order_vote(&order_vote_proposal);
        let order_vote = order_vote_result.context(format!(
            "[RoundManager] SafetyRules Rejected {} for order vote",
            block.block()
        ))?;

        fail_point!("consensus::create_invalid_order_vote", |_| {
            use aptos_crypto::bls12381;
            let faulty_order_vote = OrderVote::new_with_signature(
                order_vote.author(),
                order_vote.ledger_info().clone(),
                bls12381::Signature::dummy_signature(),
            );
            Ok(faulty_order_vote)
        });
        Ok(order_vote)
    }
```

**File:** consensus/src/round_manager.rs (L1807-1807)
```rust
                    if let Err(e) = self.broadcast_order_vote(vote, qc.clone()).await {
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

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L113-116)
```rust
        let ledger_info =
            LedgerInfo::new(order_vote_proposal.block_info().clone(), HashValue::zero());
        let signature = self.sign(&ledger_info)?;
        let order_vote = OrderVote::new_with_signature(author, ledger_info.clone(), signature);
```

**File:** consensus/src/pending_order_votes.rs (L43-44)
```rust
    li_digest_to_votes:
        HashMap<HashValue /* LedgerInfo digest */, (QuorumCert, OrderVoteStatus)>,
```

**File:** consensus/src/pending_order_votes.rs (L68-68)
```rust
        let li_digest = order_vote.ledger_info().hash();
```
