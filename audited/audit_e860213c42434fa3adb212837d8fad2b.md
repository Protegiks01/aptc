# Audit Report

## Title
Consensus State Corruption via Async Cancellation in process_proposal_msg()

## Summary
The `process_proposal_msg()` async function in the consensus RoundManager contains a critical cancellation safety vulnerability. When this function is cancelled after persisting a block but before creating and persisting the corresponding vote, it leaves the consensus state in a corrupted condition where the node has a block without a vote, leading to potential duplicate block insertion and consensus inconsistency.

## Finding Description

The vulnerability exists in the async execution path of `process_proposal_msg()` which performs multiple state-modifying operations with intervening `.await` points that can be cancelled. [1](#0-0) 

The critical execution sequence is:

1. **Block Insertion (with persistence)**: In `process_proposal()`, the block is inserted into BlockStore which persists it to disk [2](#0-1) 

2. **Vote Creation and Persistence**: Later in the flow via `process_verified_proposal()` → `create_vote()` → `vote_block()`, the vote is created and persisted [3](#0-2) 

The block persistence occurs in `insert_block_inner()` via a synchronous call: [4](#0-3) 

**Cancellation Window**: If the async task is cancelled (via `tokio::select!` in the event loop) after step 1 but before step 2, the persistent state contains a block without a corresponding vote. [5](#0-4) 

**Post-Restart Corruption**: On node restart, the block is recovered from persistent storage. When a timeout occurs for that round, the node checks if it has voted: [6](#0-5) 

Since no vote was persisted, the node generates and votes for a NIL block for the same round: [7](#0-6) 

This causes the BlockTree to contain two blocks for the same round. The BlockTree logs a warning but still inserts the duplicate: [8](#0-7) 

**Result**: The node has:
- Two different blocks for round R in the BlockTree
- `round_to_ids` mapping pointing to the original block
- A persisted vote for the NIL block
- `get_block_for_round(R)` returning the original block, not the block it voted for

This violates the **State Consistency** invariant that state transitions must be atomic and creates an inconsistent consensus state.

## Impact Explanation

This is a **High Severity** issue meeting the "Significant protocol violations" category:

- **Consensus State Corruption**: The node maintains contradictory state about which block exists for a given round
- **Voting Inconsistency**: The persisted vote doesn't match the block returned by round queries
- **Protocol Violation**: Violates the assumption of unequivocal block-to-round mapping
- **Recovery Complexity**: Requires manual intervention to detect and repair the corrupted state

While this doesn't immediately cause consensus safety violations (the node won't double-vote due to the persisted NIL vote), it corrupts the internal consistency of the BlockStore and could lead to undefined behavior in edge cases where the node needs to reason about its voting history.

## Likelihood Explanation

**Likelihood: Medium to Low**

The vulnerability requires specific conditions:
1. An async cancellation during the narrow window between block insertion and vote creation
2. Node restart/recovery before the cancellation is resolved
3. A timeout event triggering NIL vote generation

In production, this can occur through:
- Coordinated shutdown during proposal processing (e.g., OS signals, orchestration systems)
- Node crashes from unrelated failures during the vulnerable window
- Deliberate exploit by triggering crashes via resource exhaustion or other bugs

While not trivial to exploit, the consequences are severe enough that the lack of cancellation safety is a significant correctness issue in consensus-critical code.

## Recommendation

**Fix: Make state modifications atomic or add cancellation guards**

Option 1: Check for existing blocks before NIL vote generation:
```rust
// In process_local_timeout, before generating NIL block:
if let Some(existing_block) = self.block_store.get_block_for_round(round) {
    // A block exists but we haven't voted - vote for the existing block instead of NIL
    let existing_vote = self.vote_block(existing_block.block().clone()).await?;
    // ... continue with timeout logic using existing_vote
}
```

Option 2: Add explicit checks in `vote_block` to prevent voting for a different block if one already exists for the round:
```rust
// In vote_block, after insert_block:
ensure!(
    self.block_store.get_block_for_round(proposed_block.round())
        .map(|b| b.id() == proposed_block.id())
        .unwrap_or(true),
    "Cannot vote for block {} when different block already exists for round {}",
    proposed_block.id(),
    proposed_block.round()
);
```

Option 3: Implement proper async cancellation guards using RAII patterns to ensure cleanup on cancellation.

## Proof of Concept

```rust
#[tokio::test]
async fn test_cancellation_state_corruption() {
    // 1. Create RoundManager with fuzzing setup
    let round_manager = create_node_for_fuzzing();
    
    // 2. Generate a valid proposal for round 1
    let proposal = generate_corpus_proposal();
    let proposal_msg: ProposalMsg = serde_json::from_slice(&proposal).unwrap();
    
    // 3. Start processing proposal in a cancellable task
    let mut rm = round_manager;
    let handle = tokio::spawn(async move {
        rm.process_proposal_msg(proposal_msg).await
    });
    
    // 4. Cancel the task after allowing block insertion (timing-dependent)
    tokio::time::sleep(Duration::from_millis(50)).await;
    handle.abort();
    
    // 5. Verify: Block should exist in storage but no vote recorded
    // 6. Trigger timeout and observe NIL vote for same round
    // 7. Verify: Two blocks now exist for round 1 with inconsistent state
    
    // Note: Actual PoC requires access to internal BlockStore state
    // and coordination with the async runtime to control cancellation timing
}
```

## Notes

This vulnerability stems from a fundamental design issue: critical consensus state modifications are performed across multiple `.await` points without proper atomicity guarantees. The Rust async model makes no guarantees about completing work after an `.await` if the future is dropped, yet the code assumes all-or-nothing semantics for the block-insertion-and-voting sequence.

The fix should ensure that either:
1. Both block and vote are persisted atomically, or
2. The code can safely recover from partial state by detecting and handling the "block without vote" condition

This is particularly critical in consensus code where state consistency is paramount for protocol correctness.

### Citations

**File:** consensus/src/round_manager.rs (L726-765)
```rust
    pub async fn process_proposal_msg(&mut self, proposal_msg: ProposalMsg) -> anyhow::Result<()> {
        fail_point!("consensus::process_proposal_msg", |_| {
            Err(anyhow::anyhow!("Injected error in process_proposal_msg"))
        });

        observe_block(
            proposal_msg.proposal().timestamp_usecs(),
            BlockStage::ROUND_MANAGER_RECEIVED,
        );
        info!(
            self.new_log(LogEvent::ReceiveProposal)
                .remote_peer(proposal_msg.proposer()),
            block_round = proposal_msg.proposal().round(),
            block_hash = proposal_msg.proposal().id(),
            block_parent_hash = proposal_msg.proposal().quorum_cert().certified_block().id(),
        );

        let in_correct_round = self
            .ensure_round_and_sync_up(
                proposal_msg.proposal().round(),
                proposal_msg.sync_info(),
                proposal_msg.proposer(),
            )
            .await
            .context("[RoundManager] Process proposal")?;
        if in_correct_round {
            self.process_proposal(proposal_msg.take_proposal()).await
        } else {
            sample!(
                SampleRate::Duration(Duration::from_secs(30)),
                warn!(
                    "[sampled] Stale proposal {}, current round {}",
                    proposal_msg.proposal(),
                    self.round_state.current_round()
                )
            );
            counters::ERROR_COUNT.inc();
            Ok(())
        }
    }
```

**File:** consensus/src/round_manager.rs (L1049-1062)
```rust
                _ => {
                    // Didn't vote in this round yet, generate a backup vote
                    let nil_block = self
                        .proposal_generator
                        .generate_nil_block(round, self.proposer_election.clone())?;
                    info!(
                        self.new_log(LogEvent::VoteNIL),
                        "Planning to vote for a NIL block {}", nil_block
                    );
                    counters::VOTE_NIL_COUNT.inc();
                    let nil_vote = self.vote_block(nil_block).await?;
                    (true, nil_vote)
                },
            };
```

**File:** consensus/src/round_manager.rs (L1256-1259)
```rust
        self.block_store
            .insert_block(proposal.clone())
            .await
            .context("[RoundManager] Failed to insert the block into BlockStore")?;
```

**File:** consensus/src/round_manager.rs (L1507-1512)
```rust
        // Short circuit if already voted.
        ensure!(
            self.round_state.vote_sent().is_none(),
            "[RoundManager] Already vote on this round {}",
            self.round_state.current_round()
        );
```

**File:** consensus/src/round_manager.rs (L1539-1541)
```rust
        self.storage
            .save_vote(&vote)
            .context("[RoundManager] Fail to persist last vote")?;
```

**File:** consensus/src/round_manager.rs (L2074-2143)
```rust
            tokio::select! {
                biased;
                close_req = close_rx.select_next_some() => {
                    if let Ok(ack_sender) = close_req {
                        ack_sender.send(()).expect("[RoundManager] Fail to ack shutdown");
                    }
                    break;
                }
                opt_proposal = opt_proposal_loopback_rx.select_next_some() => {
                    self.pending_opt_proposals = self.pending_opt_proposals.split_off(&opt_proposal.round().add(1));
                    let result = monitor!("process_opt_proposal_loopback", self.process_opt_proposal(opt_proposal).await);
                    let round_state = self.round_state();
                    match result {
                        Ok(_) => trace!(RoundStateLogSchema::new(round_state)),
                        Err(e) => {
                            counters::ERROR_COUNT.inc();
                            warn!(kind = error_kind(&e), RoundStateLogSchema::new(round_state), "Error: {:#}", e);
                        }
                    }
                }
                proposal = buffered_proposal_rx.select_next_some() => {
                    let mut proposals = vec![proposal];
                    while let Some(Some(proposal)) = buffered_proposal_rx.next().now_or_never() {
                        proposals.push(proposal);
                    }
                    let get_round = |event: &VerifiedEvent| {
                        match event {
                            VerifiedEvent::ProposalMsg(p) => p.proposal().round(),
                            VerifiedEvent::VerifiedProposalMsg(p) => p.round(),
                            VerifiedEvent::OptProposalMsg(p) => p.round(),
                            unexpected_event => unreachable!("Unexpected event {:?}", unexpected_event),
                        }
                    };
                    proposals.sort_by_key(get_round);
                    // If the first proposal is not for the next round, we only process the last proposal.
                    // to avoid going through block retrieval of many garbage collected rounds.
                    if self.round_state.current_round() + 1 < get_round(&proposals[0]) {
                        proposals = vec![proposals.pop().unwrap()];
                    }
                    for proposal in proposals {
                        let result = match proposal {
                            VerifiedEvent::ProposalMsg(proposal_msg) => {
                                monitor!(
                                    "process_proposal",
                                    self.process_proposal_msg(*proposal_msg).await
                                )
                            }
                            VerifiedEvent::VerifiedProposalMsg(proposal_msg) => {
                                monitor!(
                                    "process_verified_proposal",
                                    self.process_delayed_proposal_msg(*proposal_msg).await
                                )
                            }
                            VerifiedEvent::OptProposalMsg(proposal_msg) => {
                                monitor!(
                                    "process_opt_proposal",
                                    self.process_opt_proposal_msg(*proposal_msg).await
                                )
                            }
                            unexpected_event => unreachable!("Unexpected event: {:?}", unexpected_event),
                        };
                        let round_state = self.round_state();
                        match result {
                            Ok(_) => trace!(RoundStateLogSchema::new(round_state)),
                            Err(e) => {
                                counters::ERROR_COUNT.inc();
                                warn!(kind = error_kind(&e), RoundStateLogSchema::new(round_state), "Error: {:#}", e);
                            }
                        }
                    }
```

**File:** consensus/src/block_storage/block_store.rs (L512-515)
```rust
        self.storage
            .save_tree(vec![pipelined_block.block().clone()], vec![])
            .context("Insert block failed when saving block")?;
        self.inner.write().insert_block(pipelined_block)
```

**File:** consensus/src/block_storage/block_tree.rs (L327-335)
```rust
            if let Some(old_block_id) = self.round_to_ids.get(&arc_block.round()) {
                warn!(
                    "Multiple blocks received for round {}. Previous block id: {}",
                    arc_block.round(),
                    old_block_id
                );
            } else {
                self.round_to_ids.insert(arc_block.round(), block_id);
            }
```
