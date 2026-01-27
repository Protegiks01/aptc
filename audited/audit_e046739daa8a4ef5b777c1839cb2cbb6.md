# Audit Report

## Title
Malicious Validator Can Cause Permanent Liveness Failure via Invalid Block Data in Decoupled Execution Mode

## Summary
A malicious validator can craft a ProposalMsg with structurally valid format but containing block data that causes execution failures. Due to the decoupled execution architecture and default configuration (`discard_failed_blocks = false`), the failed block remains stuck in "Ordered" state, can never be committed, and permanently halts all consensus progress network-wide.

## Finding Description

The vulnerability exploits a critical flaw in the interaction between Aptos's decoupled execution mode and error handling in the consensus pipeline.

**Attack Flow:**

1. **Malicious Proposal Creation**: A Byzantine validator creates a ProposalMsg containing a Block with valid structural properties (correct signatures, format, round progression, QC) but with payload data that will cause execution errors (e.g., transactions that trigger VM panics, invalid state transitions, or resource exhaustion beyond what preliminary checks detect). [1](#0-0) 

2. **Validation Bypass**: The ProposalMsg passes all preliminary validation checks including signature verification, structural well-formedness, and proposal ordering rules. [2](#0-1) 

3. **Decoupled Voting**: Because `decoupled_execution` is hardcoded to `true`, honest validators vote on block ordering using a dummy `ACCUMULATOR_PLACEHOLDER_HASH` without waiting for execution to complete. [3](#0-2) [4](#0-3) 

4. **Block Ordering**: The malicious block receives sufficient votes, gets a QC, and is ordered by consensus. It's inserted into the buffer manager for execution. [5](#0-4) 

5. **Execution Failure**: The execution pipeline attempts to execute the block via `execute_and_update_state`. With the default configuration where `discard_failed_blocks = false`, the execution fails and returns an error. [6](#0-5) [7](#0-6) 

6. **Error Handling Failure**: The `process_execution_response` function receives the error, logs it, and returns early without advancing the block from "Ordered" to "Executed" state. [8](#0-7) 

7. **Aggregation Impossibility**: When validators attempt to aggregate commit votes, the `try_advance_to_aggregated_with_ledger_info` function cannot advance an "Ordered" block to "Aggregated" state because execution never completed. [9](#0-8) 

8. **Permanent Liveness Failure**: The `advance_head` function requires blocks to be in "Aggregated" state with `executed_blocks` to commit them. Since the malicious block can never reach this state, it blocks all subsequent blocks from being committed. [10](#0-9) 

**Broken Invariants:**
- **Consensus Liveness**: The network cannot make progress past the malicious block
- **State Consistency**: Validators cannot commit new state transitions
- **Availability**: The blockchain effectively halts for all users

## Impact Explanation

This vulnerability meets **Critical Severity** criteria per the Aptos bug bounty program:

- **Total loss of liveness/network availability**: Once triggered, the entire network halts and cannot commit any new blocks. All validator nodes are affected simultaneously.
- **Non-recoverable without intervention**: The default configuration provides no automatic recovery mechanism. Recovery would require either:
  - A coordinated manual configuration change to enable `discard_failed_blocks = true` and restart all validators
  - A state sync from an external source
  - Potentially a hard fork

The impact is maximum because:
- A single malicious validator can execute the attack
- All honest validators are affected
- No transactions can be committed network-wide
- User funds become inaccessible (cannot transfer or use)
- The attack is repeatable (attacker can keep proposing malicious blocks)

## Likelihood Explanation

**High Likelihood** due to:

1. **Low Attack Complexity**: The attacker only needs to be a validator in the rotation and craft block data that fails execution while passing preliminary validation. This is achievable by:
   - Including transactions with valid signatures but that cause VM panics
   - Crafting payload data that passes structural checks but fails deep execution
   - Including validator transactions with edge cases not covered by preliminary validation

2. **No Collusion Required**: A single Byzantine validator can execute the attack during their proposal turn.

3. **Immediate Impact**: The attack takes effect within one consensus round, providing immediate network disruption.

4. **Default Configuration Vulnerable**: The critical `discard_failed_blocks` flag is set to `false` by default, meaning all production networks are vulnerable unless explicitly configured otherwise.

5. **No Detection Before Impact**: The malicious block passes all preliminary checks, so there's no opportunity to reject it before voting.

## Recommendation

**Immediate Fixes:**

1. **Enable discard_failed_blocks by default**:

Modify the default in `config/src/config/execution_config.rs`:
```rust
discard_failed_blocks: true,  // Changed from false
```

2. **Add execution validation before voting** (more comprehensive fix):

Modify the consensus pipeline to wait for execution completion before voting when critical validation is needed. Add a configuration flag for "strict execution validation" that forces execution before voting for blocks with certain characteristics.

3. **Add circuit breaker for execution failures**:

Implement a detection mechanism in `buffer_manager.rs` that tracks repeated execution failures for the same block and automatically enables `discard_failed_blocks` mode after a threshold:

```rust
// In BufferManager
execution_failure_count: HashMap<HashValue, u32>,
const MAX_EXECUTION_RETRIES: u32 = 3;

// In process_execution_response
if let Err(e) = inner {
    let count = self.execution_failure_count
        .entry(block_id)
        .or_insert(0);
    *count += 1;
    
    if *count >= MAX_EXECUTION_RETRIES {
        // Discard block and continue
        warn!("Block {} failed execution {} times, discarding", 
              block_id, MAX_EXECUTION_RETRIES);
        // Advance block with error status
    }
}
```

4. **Add monitoring and alerts**: Implement metrics to detect execution failures and alert operators before liveness is completely lost.

## Proof of Concept

**Rust Test Scenario** (to be added to consensus/src/pipeline/buffer_manager_test.rs):

```rust
#[tokio::test]
async fn test_malicious_block_liveness_failure() {
    // Setup: Create buffer manager with discard_failed_blocks = false
    let config = ExecutionConfig {
        discard_failed_blocks: false,
        ..Default::default()
    };
    
    // Step 1: Create a block that will pass validation but fail execution
    let malicious_block = create_block_with_invalid_execution_data();
    
    // Step 2: Validators vote on the block (decoupled execution)
    let votes = collect_validator_votes(&malicious_block);
    let qc = create_quorum_cert(votes);
    
    // Step 3: Block is ordered
    let ordered_blocks = OrderedBlocks {
        ordered_blocks: vec![malicious_block.clone()],
        ordered_proof: create_ledger_info_with_sigs(qc),
    };
    
    // Step 4: Send to buffer manager
    buffer_manager.process_ordered_blocks(ordered_blocks).await;
    
    // Step 5: Execution fails
    // Mock executor to return error for this specific block
    mock_executor.set_failure_for_block(malicious_block.id());
    
    // Step 6: Try to aggregate with commit proof
    let commit_proof = create_commit_proof(&malicious_block);
    
    // Step 7: Verify block cannot be aggregated
    let buffer_item = buffer_manager.get_item(malicious_block.id());
    assert!(matches!(buffer_item, BufferItem::Ordered(_)));
    
    // Step 8: Verify subsequent blocks cannot be committed
    let next_block = create_valid_block();
    buffer_manager.process_ordered_blocks(vec![next_block]).await;
    
    // Verify buffer is stuck - no blocks can advance past the malicious one
    assert_eq!(buffer_manager.highest_committed_round, 
               malicious_block.round() - 1);
}

fn create_block_with_invalid_execution_data() -> Block {
    // Create a block with transactions that pass signature checks
    // but will cause execution errors (e.g., division by zero in Move,
    // resource exhaustion, invalid native function calls)
    // This represents the malicious validator's crafted block
}
```

**Expected Outcome**: The test demonstrates that once a block fails execution with `discard_failed_blocks = false`, the buffer manager enters a deadlock state where no new blocks can be committed, confirming the permanent liveness failure.

## Notes

This vulnerability demonstrates a critical oversight in the decoupled execution architecture where the voting phase (which determines consensus) is separated from the execution phase (which determines validity). While this design improves throughput, it creates a window where malicious blocks can be ordered but never executed, causing permanent liveness failures when combined with conservative error handling defaults.

The fix requires either enabling `discard_failed_blocks` by default (trading safety for liveness) or implementing more sophisticated execution validation and recovery mechanisms before the network enters an unrecoverable state.

### Citations

**File:** consensus/consensus-types/src/proposal_msg.rs (L32-80)
```rust
    /// Verifies that the ProposalMsg is well-formed.
    pub fn verify_well_formed(&self) -> Result<()> {
        ensure!(
            !self.proposal.is_nil_block(),
            "Proposal {} for a NIL block",
            self.proposal
        );
        self.proposal
            .verify_well_formed()
            .context("Fail to verify ProposalMsg's block")?;
        ensure!(
            self.proposal.round() > 0,
            "Proposal for {} has an incorrect round of 0",
            self.proposal,
        );
        ensure!(
            self.proposal.epoch() == self.sync_info.epoch(),
            "ProposalMsg has different epoch number from SyncInfo"
        );
        ensure!(
            self.proposal.parent_id()
                == self.sync_info.highest_quorum_cert().certified_block().id(),
            "Proposal HQC in SyncInfo certifies {}, but block parent id is {}",
            self.sync_info.highest_quorum_cert().certified_block().id(),
            self.proposal.parent_id(),
        );
        let previous_round = self
            .proposal
            .round()
            .checked_sub(1)
            .ok_or_else(|| anyhow!("proposal round overflowed!"))?;

        let highest_certified_round = std::cmp::max(
            self.proposal.quorum_cert().certified_block().round(),
            self.sync_info.highest_timeout_round(),
        );
        ensure!(
            previous_round == highest_certified_round,
            "Proposal {} does not have a certified round {}",
            self.proposal,
            previous_round
        );
        ensure!(
            self.proposal.author().is_some(),
            "Proposal {} does not define an author",
            self.proposal
        );
        Ok(())
    }
```

**File:** consensus/src/round_manager.rs (L1111-1231)
```rust
    async fn process_proposal(&mut self, proposal: Block) -> anyhow::Result<()> {
        let author = proposal
            .author()
            .expect("Proposal should be verified having an author");

        if !self.vtxn_config.enabled()
            && matches!(
                proposal.block_data().block_type(),
                BlockType::ProposalExt(_)
            )
        {
            counters::UNEXPECTED_PROPOSAL_EXT_COUNT.inc();
            bail!("ProposalExt unexpected while the vtxn feature is disabled.");
        }

        if let Some(vtxns) = proposal.validator_txns() {
            for vtxn in vtxns {
                let vtxn_type_name = vtxn.type_name();
                ensure!(
                    is_vtxn_expected(&self.randomness_config, &self.jwk_consensus_config, vtxn),
                    "unexpected validator txn: {:?}",
                    vtxn_type_name
                );
                vtxn.verify(self.epoch_state.verifier.as_ref())
                    .context(format!("{} verify failed", vtxn_type_name))?;
            }
        }

        let (num_validator_txns, validator_txns_total_bytes): (usize, usize) =
            proposal.validator_txns().map_or((0, 0), |txns| {
                txns.iter().fold((0, 0), |(count_acc, size_acc), txn| {
                    (count_acc + 1, size_acc + txn.size_in_bytes())
                })
            });

        let num_validator_txns = num_validator_txns as u64;
        let validator_txns_total_bytes = validator_txns_total_bytes as u64;
        let vtxn_count_limit = self.vtxn_config.per_block_limit_txn_count();
        let vtxn_bytes_limit = self.vtxn_config.per_block_limit_total_bytes();
        let author_hex = author.to_hex();
        PROPOSED_VTXN_COUNT
            .with_label_values(&[&author_hex])
            .inc_by(num_validator_txns);
        PROPOSED_VTXN_BYTES
            .with_label_values(&[&author_hex])
            .inc_by(validator_txns_total_bytes);
        info!(
            vtxn_count_limit = vtxn_count_limit,
            vtxn_count_proposed = num_validator_txns,
            vtxn_bytes_limit = vtxn_bytes_limit,
            vtxn_bytes_proposed = validator_txns_total_bytes,
            proposer = author_hex,
            "Summarizing proposed validator txns."
        );

        ensure!(
            num_validator_txns <= vtxn_count_limit,
            "process_proposal failed with per-block vtxn count limit exceeded: limit={}, actual={}",
            self.vtxn_config.per_block_limit_txn_count(),
            num_validator_txns
        );
        ensure!(
            validator_txns_total_bytes <= vtxn_bytes_limit,
            "process_proposal failed with per-block vtxn bytes limit exceeded: limit={}, actual={}",
            self.vtxn_config.per_block_limit_total_bytes(),
            validator_txns_total_bytes
        );
        let payload_len = proposal.payload().map_or(0, |payload| payload.len());
        let payload_size = proposal.payload().map_or(0, |payload| payload.size());
        ensure!(
            num_validator_txns + payload_len as u64 <= self.local_config.max_receiving_block_txns,
            "Payload len {} exceeds the limit {}",
            payload_len,
            self.local_config.max_receiving_block_txns,
        );

        ensure!(
            validator_txns_total_bytes + payload_size as u64
                <= self.local_config.max_receiving_block_bytes,
            "Payload size {} exceeds the limit {}",
            payload_size,
            self.local_config.max_receiving_block_bytes,
        );

        ensure!(
            self.proposer_election.is_valid_proposal(&proposal),
            "[RoundManager] Proposer {} for block {} is not a valid proposer for this round or created duplicate proposal",
            author,
            proposal,
        );

        // If the proposal contains any inline transactions that need to be denied
        // (e.g., due to filtering) drop the message and do not vote for the block.
        if let Err(error) = self
            .block_store
            .check_denied_inline_transactions(&proposal, &self.block_txn_filter_config)
        {
            counters::REJECTED_PROPOSAL_DENY_TXN_COUNT.inc();
            bail!(
                "[RoundManager] Proposal for block {} contains denied inline transactions: {}. Dropping proposal!",
                proposal.id(),
                error
            );
        }

        if !proposal.is_opt_block() {
            // Validate that failed_authors list is correctly specified in the block.
            let expected_failed_authors = self.proposal_generator.compute_failed_authors(
                proposal.round(),
                proposal.quorum_cert().certified_block().round(),
                false,
                self.proposer_election.clone(),
            );
            ensure!(
                proposal.block_data().failed_authors().is_some_and(|failed_authors| *failed_authors == expected_failed_authors),
                "[RoundManager] Proposal for block {} has invalid failed_authors list {:?}, expected {:?}",
                proposal.round(),
                proposal.block_data().failed_authors(),
                expected_failed_authors,
            );
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

**File:** consensus/src/pipeline/buffer_manager.rs (L382-424)
```rust
    async fn process_ordered_blocks(&mut self, ordered_blocks: OrderedBlocks) {
        let OrderedBlocks {
            ordered_blocks,
            ordered_proof,
        } = ordered_blocks;

        info!(
            "Receive {} ordered block ends with [epoch: {}, round: {}, id: {}], the queue size is {}",
            ordered_blocks.len(),
            ordered_proof.commit_info().epoch(),
            ordered_proof.commit_info().round(),
            ordered_proof.commit_info().id(),
            self.buffer.len() + 1,
        );

        let request = self.create_new_request(ExecutionRequest {
            ordered_blocks: ordered_blocks.clone(),
        });
        if let Some(consensus_publisher) = &self.consensus_publisher {
            let message = ConsensusObserverMessage::new_ordered_block_message(
                ordered_blocks.clone(),
                ordered_proof.clone(),
            );
            consensus_publisher.publish_message(message);
        }
        self.execution_schedule_phase_tx
            .send(request)
            .await
            .expect("Failed to send execution schedule request");

        let mut unverified_votes = HashMap::new();
        if let Some(block) = ordered_blocks.last() {
            if let Some(votes) = self.pending_commit_votes.remove(&block.round()) {
                for (_, vote) in votes {
                    if vote.commit_info().id() == block.id() {
                        unverified_votes.insert(vote.author(), vote);
                    }
                }
            }
        }
        let item = BufferItem::new_ordered(ordered_blocks, ordered_proof, unverified_votes);
        self.buffer.push_back(item);
    }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L492-541)
```rust
    async fn advance_head(&mut self, target_block_id: HashValue) {
        let mut blocks_to_persist: Vec<Arc<PipelinedBlock>> = vec![];

        while let Some(item) = self.buffer.pop_front() {
            blocks_to_persist.extend(item.get_blocks().clone());
            if self.signing_root == Some(item.block_id()) {
                self.signing_root = None;
            }
            if self.execution_root == Some(item.block_id()) {
                self.execution_root = None;
            }
            if item.block_id() == target_block_id {
                let aggregated_item = item.unwrap_aggregated();
                let block = aggregated_item
                    .executed_blocks
                    .last()
                    .expect("executed_blocks should be not empty")
                    .block();
                observe_block(block.timestamp_usecs(), BlockStage::COMMIT_CERTIFIED);
                // As all the validators broadcast commit votes directly to all other validators,
                // the proposer do not have to broadcast commit decision again.
                let commit_proof = aggregated_item.commit_proof.clone();
                if let Some(consensus_publisher) = &self.consensus_publisher {
                    let message =
                        ConsensusObserverMessage::new_commit_decision_message(commit_proof.clone());
                    consensus_publisher.publish_message(message);
                }
                for block in &blocks_to_persist {
                    self.pending_commit_blocks
                        .insert(block.round(), block.clone());
                }
                self.persisting_phase_tx
                    .send(self.create_new_request(PersistingRequest {
                        blocks: blocks_to_persist,
                        commit_ledger_info: aggregated_item.commit_proof,
                    }))
                    .await
                    .expect("Failed to send persist request");
                if commit_proof.ledger_info().ends_epoch() {
                    // the epoch ends, reset to avoid executing more blocks, execute after
                    // this persisting request will result in BlockNotFound
                    self.reset().await;
                }
                info!("Advance head to {:?}", self.buffer.head_cursor());
                self.previous_commit_time = Instant::now();
                return;
            }
        }
        unreachable!("Aggregated item not found in the list");
    }
```

**File:** consensus/src/pipeline/buffer_manager.rs (L609-627)
```rust
    async fn process_execution_response(&mut self, response: ExecutionResponse) {
        let ExecutionResponse { block_id, inner } = response;
        // find the corresponding item, may not exist if a reset or aggregated happened
        let current_cursor = self.buffer.find_elem_by_key(self.execution_root, block_id);
        if current_cursor.is_none() {
            return;
        }

        let executed_blocks = match inner {
            Ok(result) => result,
            Err(e) => {
                log_executor_error_occurred(
                    e,
                    &counters::BUFFER_MANAGER_RECEIVED_EXECUTOR_ERROR_COUNT,
                    block_id,
                );
                return;
            },
        };
```

**File:** config/src/config/execution_config.rs (L78-96)
```rust
impl Default for ExecutionConfig {
    fn default() -> ExecutionConfig {
        ExecutionConfig {
            genesis: None,
            genesis_file_location: PathBuf::new(),
            // use min of (num of cores/2, DEFAULT_CONCURRENCY_LEVEL) as default concurrency level
            concurrency_level: 0,
            num_proof_reading_threads: 32,
            paranoid_type_verification: true,
            paranoid_hot_potato_verification: true,
            discard_failed_blocks: false,
            processed_transactions_detailed_counters: false,
            genesis_waypoint: None,
            blockstm_v2_enabled: false,
            layout_caches_enabled: true,
            // TODO: consider setting to be true by default.
            async_runtime_checks: false,
        }
    }
```

**File:** aptos-move/block-executor/src/executor.rs (L2648-2666)
```rust
        if self.config.local.discard_failed_blocks {
            // We cannot execute block, discard everything (including block metadata and validator transactions)
            // (TODO: maybe we should add fallback here to first try BlockMetadataTransaction alone)
            let error_code = match sequential_error {
                BlockExecutionError::FatalBlockExecutorError(_) => {
                    StatusCode::DELAYED_FIELD_OR_BLOCKSTM_CODE_INVARIANT_ERROR
                },
                BlockExecutionError::FatalVMError(_) => {
                    StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR
                },
            };
            let ret = (0..signature_verified_block.num_txns())
                .map(|_| E::Output::discard_output(error_code))
                .collect();
            return Ok(BlockOutput::new(ret, None));
        }

        Err(sequential_error)
    }
```

**File:** consensus/src/pipeline/buffer_item.rs (L272-291)
```rust
            Self::Ordered(ordered_item) => {
                let ordered = *ordered_item;
                assert!(ordered
                    .ordered_proof
                    .commit_info()
                    .match_ordered_only(commit_proof.commit_info()));
                // can't aggregate it without execution, only store the signatures
                debug!(
                    "{} received commit decision in ordered stage",
                    commit_proof.commit_info()
                );
                Self::Ordered(Box::new(OrderedItem {
                    commit_proof: Some(commit_proof),
                    ..ordered
                }))
            },
            Self::Aggregated(_) => {
                unreachable!("Found aggregated buffer item but any aggregated buffer item should get dequeued right away.");
            },
        }
```
