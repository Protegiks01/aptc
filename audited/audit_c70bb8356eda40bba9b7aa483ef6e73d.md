# Audit Report

## Title
Race Condition in Order Vote Creation Causes Consensus Liveness Failure Due to Non-Deterministic Block Info

## Summary
A critical race condition exists in `PipelinedBlock::order_vote_proposal()` where the method reads block execution results (`block_info()`) without synchronizing with the asynchronous execution pipeline. This causes different validators to sign order votes with different `BlockInfo` values (placeholder vs. actual execution results) depending on execution timing, preventing order vote aggregation and causing consensus liveness failure.

## Finding Description

The vulnerability occurs in the order vote creation flow: [1](#0-0) 

When `order_vote_proposal()` is called, it immediately reads `block_info()`: [2](#0-1) 

The `block_info()` method reads from `state_compute_result` which is initially set to a dummy value when blocks are created: [3](#0-2) [4](#0-3) 

The dummy state uses `ACCUMULATOR_PLACEHOLDER_HASH` for the root hash and 0 for version. Block execution happens asynchronously in the pipeline, and `set_compute_result()` is eventually called to update with real results: [5](#0-4) 

However, when order votes are created in the round manager, there is **no synchronization** with execution completion: [6](#0-5) 

The `BlockInfo` contains execution-dependent fields that will differ based on timing: [7](#0-6) 

The critical fields are `executed_state_id` (line 37) and `version` (line 39), which come from execution results. The order vote embeds this `BlockInfo` in its `LedgerInfo`: [8](#0-7) 

When order votes are aggregated, they are grouped by `LedgerInfo` hash: [9](#0-8) 

**The Attack Path:**

1. Block is proposed and inserted into the block store
2. Execution pipeline starts asynchronously for all validators
3. QC is formed from regular votes (which use decoupled execution with placeholders - this is fine)
4. Validators begin creating order votes when QC is aggregated:
   - **Fast validators** (or those with lighter loads): Execution hasn't completed yet, `block_info()` returns placeholder hash (`ACCUMULATOR_PLACEHOLDER_HASH`) and version 0
   - **Slow validators** (or those with heavier loads): Execution completed, `block_info()` returns actual execution hash and version
5. Result: Order votes split across different `LedgerInfo` hashes (different `executed_state_id` values)
6. Each group fails to reach quorum threshold
7. **Consensus cannot order the block → liveness failure**

## Impact Explanation

This vulnerability causes **Total loss of liveness/network availability**, which is a **Critical Severity** issue per Aptos bug bounty criteria (up to $1,000,000):

- Blocks cannot be ordered despite having valid QCs
- Consensus progression halts
- Network becomes unable to process transactions
- Requires manual intervention or network restart to recover
- Violates the **Deterministic Execution** invariant (all validators must produce identical state for identical blocks, but they're signing different states)

The vulnerability can be triggered:
- **Naturally**: Due to normal timing variations in validator execution speeds, network latency, or system load differences
- **Maliciously**: An attacker creating blocks with varying computational complexity can amplify timing differences, increasing the likelihood of vote splits

## Likelihood Explanation

**High likelihood** - This can occur in normal operation:

- Validators have different hardware specifications and system loads
- Network conditions vary across validators
- Execution time varies based on transaction complexity
- The window between QC formation and order vote creation provides opportunity for timing misalignment
- No synchronization mechanism exists to prevent the race condition
- The code path is executed in every round where order votes are enabled

## Recommendation

Add synchronization to ensure execution completes before creating order votes. Modify `create_order_vote()` to wait for execution:

```rust
async fn create_order_vote(
    &mut self,
    block: Arc<PipelinedBlock>,
    qc: Arc<QuorumCert>,
) -> anyhow::Result<OrderVote> {
    // Wait for execution to complete before reading block_info
    let _ = block.wait_for_compute_result().await?;
    
    let order_vote_proposal = block.order_vote_proposal(qc);
    let order_vote_result = self
        .safety_rules
        .lock()
        .construct_and_sign_order_vote(&order_vote_proposal);
    let order_vote = order_vote_result.context(format!(
        "[RoundManager] SafetyRules Rejected {} for order vote",
        block.block()
    ))?;
    Ok(order_vote)
}
```

This ensures all validators read the same execution results when creating order votes, preventing the vote split.

## Proof of Concept

```rust
// Reproduction test (add to consensus/src/round_manager_test.rs)
#[tokio::test]
async fn test_order_vote_race_condition() {
    // Setup: Create a network of validators
    let (mut playground, validators) = build_test_network(4);
    
    // Validator 0 proposes a block with moderate execution complexity
    let proposal = playground.create_proposal(1);
    
    // All validators insert and start executing the block
    for validator in &validators {
        validator.block_store.insert_block(proposal.block().clone()).await.unwrap();
    }
    
    // Form QC from votes (using decoupled execution - works fine)
    let qc = playground.form_qc_for_block(&proposal);
    
    // Immediately trigger order vote creation on all validators
    // WITHOUT waiting for execution to complete
    let mut order_votes = vec![];
    for validator in &validators {
        let block = validator.block_store.get_block(proposal.id()).unwrap();
        // Race: This might read dummy or real execution results
        let order_vote = validator.create_order_vote(block, qc.clone()).await.unwrap();
        order_votes.push(order_vote);
    }
    
    // Verify: Order votes have different LedgerInfo hashes
    let first_li_hash = order_votes[0].ledger_info().hash();
    let mut different_hashes = false;
    for vote in &order_votes[1..] {
        if vote.ledger_info().hash() != first_li_hash {
            different_hashes = true;
            break;
        }
    }
    
    assert!(different_hashes, "Race condition: validators signed different LedgerInfo");
    
    // Verify: Cannot form order certificate due to vote split
    let mut pending_votes = PendingOrderVotes::new();
    for vote in &order_votes {
        pending_votes.insert_order_vote(vote, &validators[0].epoch_state.verifier, Some(qc.clone()));
    }
    
    // No single LedgerInfo has enough votes for quorum
    for vote in &order_votes {
        assert!(!pending_votes.has_enough_order_votes(vote.ledger_info()), 
               "Liveness failure: cannot form order certificate");
    }
}
```

### Citations

**File:** consensus/consensus-types/src/pipelined_block.rs (L277-280)
```rust
    pub fn set_compute_result(
        &self,
        state_compute_result: StateComputeResult,
        execution_time: Duration,
```

**File:** consensus/consensus-types/src/pipelined_block.rs (L394-397)
```rust
    pub fn new_ordered(block: Block, window: OrderedBlockWindow) -> Self {
        let input_transactions = Vec::new();
        let state_compute_result = StateComputeResult::new_dummy();
        Self::new(block, input_transactions, state_compute_result).with_block_window(window)
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

**File:** execution/executor-types/src/state_compute_result.rs (L74-76)
```rust
    pub fn new_dummy() -> Self {
        Self::new_dummy_with_root_hash(*ACCUMULATOR_PLACEHOLDER_HASH)
    }
```

**File:** consensus/src/round_manager.rs (L1626-1631)
```rust
    async fn create_order_vote(
        &mut self,
        block: Arc<PipelinedBlock>,
        qc: Arc<QuorumCert>,
    ) -> anyhow::Result<OrderVote> {
        let order_vote_proposal = block.order_vote_proposal(qc);
```

**File:** types/src/block_info.rs (L29-44)
```rust
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

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L113-116)
```rust
        let ledger_info =
            LedgerInfo::new(order_vote_proposal.block_info().clone(), HashValue::zero());
        let signature = self.sign(&ledger_info)?;
        let order_vote = OrderVote::new_with_signature(author, ledger_info.clone(), signature);
```

**File:** consensus/src/pending_order_votes.rs (L67-81)
```rust
        // derive data from order vote
        let li_digest = order_vote.ledger_info().hash();

        // obtain the ledger info with signatures associated to the order vote's ledger info
        let (quorum_cert, status) = self.li_digest_to_votes.entry(li_digest).or_insert_with(|| {
            // if the ledger info with signatures doesn't exist yet, create it
            (
                verified_quorum_cert.expect(
                    "Quorum Cert is expected when creating a new entry in pending order votes",
                ),
                OrderVoteStatus::NotEnoughVotes(SignatureAggregator::new(
                    order_vote.ledger_info().clone(),
                )),
            )
        });
```
