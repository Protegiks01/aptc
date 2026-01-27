# Audit Report

## Title
Critical Consensus Safety Violation: Non-Deterministic Execution Causes Permanent Chain Splits in Decoupled Execution Mode

## Summary
When decoupled execution is enabled (which is always true in production), the consensus protocol fails to verify that validators execute blocks to identical state roots. The `match_ordered_only()` validation only checks epoch/round/id/timestamp but ignores `executed_state_id`, allowing validators with divergent execution results to accept each other's quorum certificates without correcting their local state. This enables permanent chain splits where different validator subsets commit to different state roots for the same block sequence.

## Finding Description

The AptosBFT consensus protocol is designed to be resistant to non-deterministic execution bugs by having validators collectively sign the resulting state of a block. However, the implementation contains a critical flaw in how it validates execution consistency.

**The Vulnerability Chain:**

1. **Decoupled Execution Always Enabled**: The consensus configuration hardcodes `decoupled_execution()` to always return `true`, disabling execution state verification: [1](#0-0) 

2. **No Parent State Verification in Vote Proposals**: When validators vote on proposals, the `gen_vote_data()` function skips accumulator extension proof verification in decoupled mode, never checking the parent block's `executed_state_id`: [2](#0-1) 

3. **Insufficient Validation in `match_ordered_only()`**: The core validation function only checks epoch, round, id, and timestamp, explicitly ignoring the execution results (`executed_state_id`, `version`, `next_epoch_state`): [3](#0-2) 

4. **QC Insertion Accepts Divergent States**: When a quorum certificate is inserted, the validation uses `match_ordered_only()`, allowing QCs with different execution states to be accepted: [4](#0-3) 

5. **QC Merging Permits State Divergence**: The `create_merged_with_executed_state()` function also uses `match_ordered_only()`, allowing validators to merge QCs with execution results that differ from their local computation: [5](#0-4) 

6. **Commit Vote Aggregation Requires Exact Match**: Validators only aggregate commit vote signatures from validators who computed the exact same execution result: [6](#0-5) 

7. **Execution Continues from Divergent State**: When executing subsequent blocks, the executor retrieves the parent block from its local block tree, using the divergent local state: [7](#0-6) 

**Attack Scenario:**

If non-deterministic execution occurs (e.g., due to a Move VM bug, race condition, or floating-point operation):

1. Block X is ordered and validators execute it
2. Due to non-determinism, validators split:
   - Group A (2f+1 validators): compute state root H_A
   - Group B (f validators): compute state root H_B  
3. Group A forms a commit QC certifying state root H_A
4. Group B receives this QC:
   - `match_ordered_only()` check passes (doesn't verify `executed_state_id`)
   - QC is accepted and stored
   - BUT: Block X in Group B's block tree still has `executed_state_id = H_B`
5. Block Y is proposed extending Block X
6. Group B executes Block Y starting from their local state H_B (not H_A)
7. Group B gets execution result H_B', which differs from Group A's result
8. **The divergence continues indefinitely**

If the non-determinism is systematic (e.g., based on CPU architecture, OS version, or system configuration), different validator subsets could permanently maintain different state roots, violating consensus safety.

## Impact Explanation

**Critical Severity - Consensus Safety Violation**

This vulnerability breaks the fundamental safety guarantee of Byzantine Fault Tolerant consensus: all honest validators must agree on the same state. The impact is:

1. **Permanent Chain Split**: Different validator subsets can commit to different state roots for the same block sequence, creating multiple incompatible versions of the blockchain state.

2. **Non-Recoverable Without Hard Fork**: Once validators diverge, they continue building on their incorrect state indefinitely. State sync won't help because `need_sync_for_ledger_info()` checks round differences, not execution state consistency.

3. **Double-Spending Possible**: If validators split, different groups could commit conflicting transactions in different forks of the state.

4. **Network Partition**: The blockchain effectively splits into multiple incompatible networks, each believing they have the correct state.

Per the Aptos Bug Bounty program, this qualifies as **Critical Severity** under "Consensus/Safety violations" and "Non-recoverable network partition (requires hardfork)."

## Likelihood Explanation

**Moderate to High Likelihood**

While the Move VM is designed for deterministic execution, non-determinism can occur due to:

1. **Concurrency Bugs**: Race conditions in parallel execution (BlockSTM) could cause non-deterministic ordering
2. **Floating-Point Operations**: If ever introduced in native functions
3. **System Call Variations**: Differences in OS behavior, timestamps, or environment
4. **Memory Corruption**: Hardware errors or software bugs affecting execution
5. **VM Bugs**: Implementation errors in the Move VM that produce inconsistent results

The AptosBFT README explicitly states validators sign "the resulting state of a block rather than just the sequence of transactions" to be "resistant to non-determinism bugs", yet the implementation fails to enforce this. [8](#0-7) 

The fact that decoupled execution disables all state verification makes this vulnerability always active when any source of non-determinism exists.

## Recommendation

**Immediate Fix**: Add execution state verification even in decoupled mode:

1. **Extend `match_ordered_only()` to verify execution results** when not in ordered-only mode, or create a separate `match_with_execution()` function that validates `executed_state_id` when both BlockInfo objects have non-dummy execution results.

2. **Add state correction mechanism**: When a validator receives a QC with a different `executed_state_id` than their local computation, trigger state sync to re-execute from the committed state rather than silently accepting the divergence.

3. **Enhance QC insertion validation**: In `insert_single_quorum_cert()`, check if the local block has already been executed (non-dummy `executed_state_id`), and if so, verify it matches the QC's certified state. If mismatch, trigger re-execution.

4. **Add safety check in commit vote signing**: The `guarded_sign_commit_vote()` already uses `match_ordered_only()`, but should also verify that when signing a commit vote, the local execution result matches what the ordered cert claims. [9](#0-8) 

**Long-term Fix**: Implement a mechanism to detect and recover from execution divergence:

1. Add periodic state root verification checkpoints
2. Implement automatic state sync when execution divergence is detected  
3. Add metrics to monitor for execution result mismatches
4. Consider re-enabling accumulator extension proof verification in a way compatible with decoupled execution

## Proof of Concept

**Scenario Setup:**
```
Network: 7 validators (Byzantine threshold f=2, quorum 2f+1=5)
Trigger: Non-deterministic execution bug in Move VM
```

**Execution Flow:**

1. **Block 100 Ordering**: 
   - All 7 validators receive and order Block 100
   - Order QC formed with 2f+1 signatures

2. **Non-Deterministic Execution**:
   - Validators V1-V5 execute Block 100 → state root `0xAAAA...`
   - Validators V6-V7 execute Block 100 → state root `0xBBBB...` (due to VM bug)

3. **Commit Vote Phase**:
   - V1-V5 create commit votes for `LedgerInfo(executed_state_id=0xAAAA...)`
   - V6-V7 create commit votes for `LedgerInfo(executed_state_id=0xBBBB...)`
   - In `buffer_item.rs:add_signature_if_matched()`, V1's commit vote is rejected by V6 because `executed.commit_info != target_commit_info`
   - V1-V5 aggregate their 5 signatures → commit QC formed with `executed_state_id=0xAAAA...`
   - V6-V7 cannot form QC (only 2 signatures)

4. **QC Propagation**:
   - V6 receives commit QC from V1 certifying `executed_state_id=0xAAAA...`
   - In `block_store.rs:insert_single_quorum_cert()`:
     - Check: `pipelined_block.block_info().match_ordered_only(qc.certified_block())`
     - `match_ordered_only()` compares epoch/round/id/timestamp ONLY
     - Check PASSES (does not compare `executed_state_id`)
   - QC is accepted and stored
   - **CRITICAL**: V6's Block 100 still has `executed_state_id=0xBBBB...` in block tree

5. **Block 101 Proposal**:
   - Leader proposes Block 101 extending Block 100
   - V1-V5 execute from state `0xAAAA...` → result `0xCCCC...`
   - V6-V7 execute from their local state `0xBBBB...` → result `0xDDDD...` (different!)
   - In `block_executor/mod.rs:execute_and_update_state()`, parent block is retrieved from local block tree with wrong state

6. **Permanent Divergence**:
   - V1-V5 commit Block 101 with state `0xCCCC...`
   - V6-V7 accept this QC but maintain local state `0xDDDD...`
   - Process repeats for all subsequent blocks
   - **Two incompatible state histories emerge**

**Verification**:
The vulnerability can be tested by injecting a fail point in the Move VM executor to return different state roots for different validator IDs, then observing that validators accept QCs for divergent states without correction.

---

**Notes**

This vulnerability represents a fundamental gap between the design intent (validators signing execution results to detect non-determinism) and the implementation (validators accepting divergent execution results without verification). The `InconsistentBlockInfo` error mentioned in the security question is defined but never used in the consensus pipeline, and the related `InconsistentExecutionResult` error in safety rules only validates ordered vs executed BlockInfo consistency, not cross-validator execution consistency. [10](#0-9) [11](#0-10)

### Citations

**File:** types/src/on_chain_config/consensus_config.rs (L238-241)
```rust
    /// Decouple execution from consensus or not.
    pub fn decoupled_execution(&self) -> bool {
        true
    }
```

**File:** consensus/consensus-types/src/vote_proposal.rs (L88-101)
```rust
    pub fn gen_vote_data(&self) -> anyhow::Result<VoteData> {
        if self.decoupled_execution {
            Ok(self.vote_data_ordering_only())
        } else {
            let proposed_block = self.block();
            let new_tree = self.accumulator_extension_proof().verify(
                proposed_block
                    .quorum_cert()
                    .certified_block()
                    .executed_state_id(),
            )?;
            Ok(self.vote_data_with_extension_proof(&new_tree))
        }
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

**File:** consensus/src/block_storage/block_store.rs (L527-536)
```rust
                ensure!(
                    // decoupled execution allows dummy block infos
                    pipelined_block
                        .block_info()
                        .match_ordered_only(qc.certified_block()),
                    "QC for block {} has different {:?} than local {:?}",
                    qc.certified_block().id(),
                    qc.certified_block(),
                    pipelined_block.block_info()
                );
```

**File:** consensus/consensus-types/src/quorum_cert.rs (L156-161)
```rust
        ensure!(
            self_commit_info.match_ordered_only(executed_commit_info),
            "Block info from QC and executed LI need to match, {:?} and {:?}",
            self_commit_info,
            executed_commit_info
        );
```

**File:** consensus/src/pipeline/buffer_item.rs (L394-399)
```rust
                if executed.commit_info == *target_commit_info {
                    executed
                        .partial_commit_proof
                        .add_signature(author, signature);
                    return Ok(());
                }
```

**File:** execution/executor/src/block_executor/mod.rs (L203-210)
```rust
        let mut block_vec = self
            .block_tree
            .get_blocks_opt(&[block_id, parent_block_id])?;
        let parent_block = block_vec
            .pop()
            .expect("Must exist.")
            .ok_or(ExecutorError::BlockNotFound(parent_block_id))?;
        let parent_output = &parent_block.output;
```

**File:** consensus/README.md (L31-35)
```markdown
The AptosBFT protocol decomposes into modules for safety (voting and commit rules) and liveness (round_state). This decoupling provides the ability to develop and experiment independently and on different modules in parallel. Due to the simple voting and commit rules, protocol safety is easy to implement and verify. It is straightforward to integrate execution as a part of consensus to avoid forking issues that arise from non-deterministic execution in a leader-based protocol. We did not consider proof-of-work based protocols, such as [Bitcoin](https://bitcoin.org/bitcoin.pdf), due to their poor performance and high energy (and environmental) costs.

### Extensions and Modifications

We reformulate the safety conditions and provide extended proofs of safety, liveness, and optimistic responsiveness. We also implement a number of additional features. First, we make the protocol more resistant to non-determinism bugs, by having validators collectively sign the resulting state of a block rather than just the sequence of transactions. This also allows clients to use quorum certificates to authenticate reads from the database. Second, we design a round_state that emits explicit timeouts, and validators rely on a quorum of those to move to the next round — without requiring synchronized clocks. Third, we intend to design an unpredictable leader election mechanism in which the leader of a round is determined by the proposer of the latest committed block using a verifiable rand ... (truncated)
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

**File:** consensus/src/pipeline/errors.rs (L11-12)
```rust
    #[error("The block in the message, {0}, does not match expected block, {1}")]
    InconsistentBlockInfo(BlockInfo, BlockInfo),
```

**File:** consensus/safety-rules/src/error.rs (L53-54)
```rust
    #[error("Inconsistent Execution Result: Ordered BlockInfo doesn't match executed BlockInfo. Ordered: {0}, Executed: {1}")]
    InconsistentExecutionResult(String, String),
```
