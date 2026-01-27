# Audit Report

## Title
Interior Mutability in Arc<PipelinedBlock> Allows Non-Deterministic Block State Access in Order Vote Generation

## Summary
The `Arc<PipelinedBlock>` type uses interior mutability patterns (`Mutex`, `OnceCell`) that allow block execution state to be modified after the block is shared across consensus components. The `order_vote_proposal()` method reads mutable execution state without synchronization guarantees, potentially allowing different validators to sign order votes with different `BlockInfo` values for the same block, violating consensus determinism.

## Finding Description

The `PipelinedBlock` struct violates the immutability guarantee typically provided by `Arc` through extensive use of interior mutability patterns. [1](#0-0) 

When creating order vote proposals, the system calls `order_vote_proposal()` which invokes `block_info()`: [2](#0-1) 

This `block_info()` method reads from the **mutable** `state_compute_result` field: [3](#0-2) 

The `compute_result()` method simply locks and clones the current state: [4](#0-3) 

The critical issue is that `set_compute_result()` can be called **multiple times**, potentially with different execution results, and explicitly acknowledges this in its implementation: [5](#0-4) 

Notably, lines 320-323 **log an ERROR** when the root hash changes but do not prevent the mutation. The state is unconditionally overwritten at line 307.

When order votes are broadcast after QC aggregation, there is no guarantee that execution has completed: [6](#0-5) 

This creates a race condition where:
1. Block is inserted with dummy `StateComputeResult` containing `ACCUMULATOR_PLACEHOLDER_HASH`
2. Execution runs asynchronously
3. Order votes may be created before/during/after execution completes
4. Different validators may observe different execution states when creating order votes for the same block

## Impact Explanation

This issue constitutes a **High Severity** violation per the Aptos bug bounty criteria for "Significant protocol violations." It breaks the fundamental invariant of **Deterministic Execution**: "All validators must produce identical state roots for identical blocks."

The vulnerability allows:
- Different `BlockInfo` values (with different `executed_state_id` hashes) for the same block across validators
- Non-deterministic order vote generation
- Potential consensus disagreement on block execution state

While the system uses placeholder hashes for regular votes in decoupled execution (by design), order votes explicitly read actual execution state without proper synchronization, creating inconsistency.

## Likelihood Explanation

**Likelihood: Medium-High**

This issue can manifest in normal operation when:
- Execution completes at different times on different validators
- Network delays cause validators to create order votes at different stages of block processing
- Block re-execution occurs (acknowledged in code comments)

The code explicitly acknowledges execution retry scenarios and logs errors when root hashes change, indicating this is a known possibility but inadequately guarded against.

## Recommendation

Implement one of the following solutions:

**Option 1**: Make order votes use placeholder hashes like regular votes (consistent with decoupled execution design):
```rust
pub fn order_vote_proposal(&self, quorum_cert: Arc<QuorumCert>) -> OrderVoteProposal {
    let block_info = self.block().gen_block_info(
        *ACCUMULATOR_PLACEHOLDER_HASH,
        0,
        None,
    );
    OrderVoteProposal::new(self.block.clone(), block_info, quorum_cert)
}
```

**Option 2**: Synchronize order vote creation with execution completion:
```rust
pub async fn order_vote_proposal_after_execution(&self, quorum_cert: Arc<QuorumCert>) -> OrderVoteProposal {
    // Wait for execution to complete
    let _ = self.wait_for_compute_result().await;
    OrderVoteProposal::new(self.block.clone(), self.block_info(), quorum_cert)
}
```

**Option 3**: Make `state_compute_result` write-once using `OnceCell` instead of `Mutex`, preventing re-execution with different results.

## Proof of Concept

```rust
// Simulated race condition demonstrating the issue
use std::sync::Arc;
use std::thread;

// Validator A creates order vote before execution completes
let block_a = Arc::clone(&shared_block);
thread::spawn(move || {
    // Gets dummy StateComputeResult with ACCUMULATOR_PLACEHOLDER_HASH
    let order_vote_a = block_a.order_vote_proposal(qc.clone());
    // order_vote_a.block_info().executed_state_id() == ACCUMULATOR_PLACEHOLDER_HASH
});

// Execution completes with real results
shared_block.set_compute_result(real_state_compute_result, execution_time);

// Validator B creates order vote after execution completes
let block_b = Arc::clone(&shared_block);
thread::spawn(move || {
    // Gets real StateComputeResult with actual root hash
    let order_vote_b = block_b.order_vote_proposal(qc.clone());
    // order_vote_b.block_info().executed_state_id() == <actual_root_hash>
});

// Result: order_vote_a and order_vote_b have DIFFERENT BlockInfo
// for the SAME block, violating consensus determinism
```

## Notes

The issue is exacerbated by the fact that `set_compute_result()` explicitly allows multiple calls with different results (logging an error but not preventing it), as seen in the comment "We might be retrying execution." This design decision, combined with unsynchronized access in `order_vote_proposal()`, creates a consensus safety risk.

The system correctly uses placeholder hashes for regular votes in decoupled execution mode [7](#0-6) , but order votes inconsistently read mutable execution state, creating a design flaw.

### Citations

**File:** consensus/consensus-types/src/pipelined_block.rs (L197-217)
```rust
#[derive(Derivative)]
pub struct PipelinedBlock {
    /// Block data that cannot be regenerated.
    block: Block,
    /// A window of blocks that are needed for execution with the execution pool, EXCLUDING the current block
    block_window: OrderedBlockWindow,
    /// Input transactions in the order of execution. DEPRECATED stay for serialization compatibility.
    input_transactions: Vec<SignedTransaction>,
    /// The state_compute_result is calculated for all the pending blocks prior to insertion to
    /// the tree. The execution results are not persisted: they're recalculated again for the
    /// pending blocks upon restart.
    state_compute_result: Mutex<StateComputeResult>,
    randomness: OnceCell<Randomness>,
    pipeline_insertion_time: OnceCell<Instant>,
    execution_summary: OnceCell<ExecutionSummary>,
    /// pipeline related fields
    pipeline_futs: Mutex<Option<PipelineFutures>>,
    pipeline_tx: Mutex<Option<PipelineInputTx>>,
    pipeline_abort_handle: Mutex<Option<Vec<AbortHandle>>>,
    block_qc: Mutex<Option<Arc<QuorumCert>>>,
}
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
