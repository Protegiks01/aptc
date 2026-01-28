# Audit Report

## Title
Equivocation Detection Bypass After Validator Crash Allows Vote Manipulation

## Summary
The `UnequivocalProposerElection.already_proposed` state is not persisted to storage, causing it to reset after validator crash and recovery. This allows Byzantine validators to replay previously-rejected equivocal blocks, bypassing equivocation detection and manipulating which equivocal block an honest validator votes for after recovery.

## Finding Description

The `UnequivocalProposerElection` wrapper maintains in-memory state to detect and reject equivocal proposals from the same proposer within a round. The state is stored in a `Mutex<(Round, HashValue)>` field. [1](#0-0) 

This state is initialized in memory without persistence, defaulting to `(0, HashValue::zero())`. [2](#0-1) 

The `is_valid_proposal()` function rejects equivocal blocks by checking if a different block has already been proposed in the same round. [3](#0-2) 

However, recovery from crash does not restore this state. The `RecoveryData` struct used for consensus recovery contains blocks, QCs, and the last vote, but not the `already_proposed` state. [4](#0-3) 

When `RoundManager` is recreated after recovery, a new `UnequivocalProposerElection` instance is created with fresh state. [5](#0-4) [6](#0-5) 

**Attack Scenario:**
1. Byzantine proposer P creates equivocal blocks B1 and B2 for round R
2. Honest validator V receives B1, `is_valid_proposal(B1)` passes, `already_proposed = (R, B1.id())`
3. V begins processing B1 but crashes before voting (hardware failure, software panic, OOM)
4. V recovers with `already_proposed = (0, HashValue::zero())`
5. Byzantine validator replays B2 to V
6. `is_valid_proposal(B2)` passes because `R > 0`, setting `already_proposed = (R, B2.id())`
7. V votes for B2 instead of B1

The proposal validation check occurs before voting in the processing pipeline. [7](#0-6) 

The vulnerability window exists between the equivocation check and vote creation, which includes block insertion, payload availability checks, and backpressure handling. [8](#0-7)  During this window, if a crash occurs, the validator has updated `already_proposed` (in-memory only) but has not yet created or persisted a vote.

SafetyRules prevents double-voting in the same round by checking `last_vote`, [9](#0-8)  but does not prevent this attack when the validator hasn't voted yet, as `last_vote` will not contain a vote for the round if the crash occurred before vote creation. [10](#0-9) 

## Impact Explanation

This vulnerability qualifies as **Medium Severity** under Aptos bug bounty criteria for "Limited Protocol Violations":

1. **Equivocation Detection Bypass**: The security event logging for equivocation is bypassed after recovery, failing to detect and report Byzantine proposer behavior during the window between crash and recovery.

2. **Vote Manipulation**: Byzantine validators can control which equivocal block an honest validator votes for after crash, violating the expected deterministic first-received behavior.

3. **Temporary Liveness Impact**: By manipulating vote distribution across equivocal blocks B1 and B2, Byzantine actors can split honest validator votes between competing blocks, potentially delaying quorum certificate formation and temporarily reducing consensus progress.

4. **Protocol Invariant Violation**: The invariant that "equivocal blocks from the same proposer are consistently rejected" is broken for validators that crash during proposal processing.

This does not directly cause consensus safety violations (validators still cannot double-vote due to SafetyRules) and does not enable fund theft or permanent network failures. The impact is limited to temporary liveness degradation under specific crash conditions.

## Likelihood Explanation

**Likelihood: Medium**

Required conditions:
- Byzantine proposer creates equivocal blocks (expected under < 1/3 Byzantine assumption)
- Honest validator crashes after receiving proposal but before voting (realistic - hardware failures, software panics, resource exhaustion)
- Byzantine validators coordinate to replay specific equivocal blocks after recovery (requires network monitoring and coordination)

The attack window exists during proposal processing between equivocation check and vote persistence. While validator crashes are not frequent, they do occur in production distributed systems. Byzantine validators can monitor the network for missed heartbeats and strategically replay equivocal blocks during recovery windows.

## Recommendation

Persist the `already_proposed` state as part of `RecoveryData` or as a separate persistent field in liveness storage. 

Modify `RecoveryData` to include:
```rust
pub struct RecoveryData {
    last_vote: Option<Vote>,
    root: RootInfo,
    // ... existing fields ...
    already_proposed: Option<(Round, HashValue)>,
}
```

Update `UnequivocalProposerElection` to restore state from recovery data during initialization, and persist updates atomically with other consensus state.

Alternatively, persist the equivocation check state to ConsensusDB alongside the last vote, ensuring it's restored during recovery.

## Proof of Concept

A complete PoC would require:
1. Simulating a validator crash during proposal processing
2. Demonstrating recovery with reset `already_proposed` state
3. Showing acceptance of second equivocal block after recovery

This can be tested by adding crash injection points in the proposal processing pipeline and verifying that equivocal blocks are accepted after recovery.

## Notes

The severity assessment has been adjusted to Medium based on Aptos bug bounty criteria, as this represents a limited protocol violation with temporary liveness impact rather than a consensus safety violation or fund theft vulnerability. The core technical finding remains valid: `already_proposed` state is not persisted and can be exploited by Byzantine actors during validator recovery windows.

### Citations

**File:** consensus/src/liveness/unequivocal_proposer_election.rs (L20-20)
```rust
    already_proposed: Mutex<(Round, HashValue)>,
```

**File:** consensus/src/liveness/unequivocal_proposer_election.rs (L38-38)
```rust
            already_proposed: Mutex::new((0, HashValue::zero())),
```

**File:** consensus/src/liveness/unequivocal_proposer_election.rs (L46-87)
```rust
    pub fn is_valid_proposal(&self, block: &Block) -> bool {
        block.author().is_some_and(|author| {
            let valid_author = self.is_valid_proposer(author, block.round());
            if !valid_author {
                warn!(
                    SecurityEvent::InvalidConsensusProposal,
                    "Proposal is not from valid author {}, expected {} for round {} and id {}",
                    author,
                    self.get_valid_proposer(block.round()),
                    block.round(),
                    block.id()
                );

                return false;
            }
            let mut already_proposed = self.already_proposed.lock();
            // detect if the leader proposes more than once in this round
            match block.round().cmp(&already_proposed.0) {
                Ordering::Greater => {
                    already_proposed.0 = block.round();
                    already_proposed.1 = block.id();
                    true
                },
                Ordering::Equal => {
                    if already_proposed.1 != block.id() {
                        error!(
                            SecurityEvent::InvalidConsensusProposal,
                            "Multiple proposals from {} for round {}: {} and {}",
                            author,
                            block.round(),
                            already_proposed.1,
                            block.id()
                        );
                        false
                    } else {
                        true
                    }
                },
                Ordering::Less => false,
            }
        })
    }
```

**File:** consensus/src/persistent_liveness_storage.rs (L332-345)
```rust
pub struct RecoveryData {
    // The last vote message sent by this validator.
    last_vote: Option<Vote>,
    root: RootInfo,
    root_metadata: RootMetadata,
    // 1. the blocks guarantee the topological ordering - parent <- child.
    // 2. all blocks are children of the root.
    blocks: Vec<Block>,
    quorum_certs: Vec<QuorumCert>,
    blocks_to_prune: Option<Vec<HashValue>>,

    // Liveness data
    highest_2chain_timeout_certificate: Option<TwoChainTimeoutCertificate>,
}
```

**File:** consensus/src/round_manager.rs (L369-369)
```rust
            proposer_election: Arc::new(UnequivocalProposerElection::new(proposer_election)),
```

**File:** consensus/src/round_manager.rs (L1195-1200)
```rust
        ensure!(
            self.proposer_election.is_valid_proposal(&proposal),
            "[RoundManager] Proposer {} for block {} is not a valid proposer for this round or created duplicate proposal",
            author,
            proposal,
        );
```

**File:** consensus/src/round_manager.rs (L1256-1285)
```rust
        self.block_store
            .insert_block(proposal.clone())
            .await
            .context("[RoundManager] Failed to insert the block into BlockStore")?;

        let block_store = self.block_store.clone();
        if block_store.check_payload(&proposal).is_err() {
            debug!("Payload not available locally for block: {}", proposal.id());
            counters::CONSENSUS_PROPOSAL_PAYLOAD_AVAILABILITY
                .with_label_values(&["missing"])
                .inc();
            let start_time = Instant::now();
            let deadline = self.round_state.current_round_deadline();
            let future = async move {
                (
                    block_store.wait_for_payload(&proposal, deadline).await,
                    proposal,
                    start_time,
                )
            }
            .boxed();
            self.futures.push(future);
            return Ok(());
        }

        counters::CONSENSUS_PROPOSAL_PAYLOAD_AVAILABILITY
            .with_label_values(&["available"])
            .inc();

        self.check_backpressure_and_process_proposal(proposal).await
```

**File:** consensus/src/round_manager.rs (L1520-1541)
```rust
        let vote_result = self.safety_rules.lock().construct_and_sign_vote_two_chain(
            &vote_proposal,
            self.block_store.highest_2chain_timeout_cert().as_deref(),
        );
        let vote = vote_result.context(format!(
            "[RoundManager] SafetyRules Rejected {}",
            block_arc.block()
        ))?;
        if !block_arc.block().is_nil_block() {
            observe_block(block_arc.block().timestamp_usecs(), BlockStage::VOTED);
        }

        if block_arc.block().is_opt_block() {
            observe_block(
                block_arc.block().timestamp_usecs(),
                BlockStage::VOTED_OPT_BLOCK,
            );
        }

        self.storage
            .save_vote(&vote)
            .context("[RoundManager] Fail to persist last vote")?;
```

**File:** consensus/src/epoch_manager.rs (L971-991)
```rust
        let mut round_manager = RoundManager::new(
            epoch_state,
            block_store.clone(),
            round_state,
            proposer_election,
            proposal_generator,
            safety_rules_container,
            network_sender,
            self.storage.clone(),
            onchain_consensus_config,
            buffered_proposal_tx,
            self.consensus_txn_filter_config.clone(),
            self.config.clone(),
            onchain_randomness_config,
            onchain_jwk_consensus_config,
            fast_rand_config,
            failures_tracker,
            opt_proposal_loopback_tx,
        );

        round_manager.init(last_vote).await;
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L70-74)
```rust
        if let Some(vote) = safety_data.last_vote.clone() {
            if vote.vote_data().proposed().round() == proposed_block.round() {
                return Ok(vote);
            }
        }
```
