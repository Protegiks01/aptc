Based on my comprehensive validation of this security claim against the Aptos Core codebase, I have verified all assertions and traced the complete execution path. This is a **VALID VULNERABILITY**.

# Audit Report

## Title
Equivocation Detection State Loss on Validator Restart Enables Proposer Equivocation Attacks

## Summary
The `UnequivocalProposerElection` struct maintains equivocation detection state in a non-persistent in-memory `Mutex<(Round, HashValue)>`. This state is reset to `(0, HashValue::zero())` on every validator restart, allowing malicious proposers to successfully submit multiple conflicting blocks for the same round to validators that have restarted, bypassing equivocation detection for regular (non-optimistic) proposals.

## Finding Description

The `UnequivocalProposerElection` wrapper is designed to detect and reject equivocating proposals from block proposers. [1](#0-0) 

The vulnerability exists in the constructor, which initializes the equivocation detection state to a hardcoded initial value that is never recovered from persistent storage: [2](#0-1) 

When a validator receives a proposal, the `is_valid_proposal` method checks if the proposer has already proposed a different block for the same round by comparing against the in-memory `already_proposed` state: [3](#0-2) 

On every validator restart, `RoundManager` creates a fresh `UnequivocalProposerElection` instance with reset state: [4](#0-3) 

While blocks are persisted to storage before insertion into the block tree: [5](#0-4) 

The `BlockTree` implementation explicitly relies on the assumption that equivocal proposer election is enforced, only logging a warning (not rejecting) when multiple blocks exist for the same round: [6](#0-5) 

For regular proposals, the `is_valid_proposal` check is the sole equivocation defense during proposal processing: [7](#0-6) 

**Attack Execution Path:**

1. Malicious proposer P is elected for round R
2. P broadcasts block X to validators in Group A  
3. Validators in Group A receive block X:
   - `is_valid_proposal(&X)` accepts it (X.round() > 0, so Ordering::Greater)
   - Updates `already_proposed` to (R, X_hash)
   - Block X is persisted to storage
4. Validators in Group A restart (maintenance, crashes, updates):
   - `UnequivocalProposerElection` recreated with `already_proposed = (0, zero)`
   - Block X is loaded from storage into `BlockTree` (including `round_to_ids` mapping)
   - But `already_proposed` is NOT repopulated
5. Proposer P broadcasts different block Y for round R
6. Restarted validators receive block Y:
   - `is_valid_proposal(&Y)` checks: Y.round() (=R) > already_proposed.0 (=0)
   - Comparison returns Ordering::Greater → ACCEPTS block Y
   - Updates `already_proposed` to (R, Y_hash)
   - `BlockTree.insert_block(Y)` logs warning about multiple blocks for round R but inserts Y
   - Both X and Y now exist in persistent storage for the same round
7. If validators hadn't voted on X before restart, they can now vote on Y (SafetyRules only prevents double-voting, not receiving different blocks)

This violates the equivocation detection invariant that the code explicitly assumes is enforced.

## Impact Explanation

This represents a **High Severity** consensus security issue under the Aptos bug bounty program:

**Consensus Property Violation**: The vulnerability allows a Byzantine proposer to successfully equivocate (propose multiple different blocks for the same round) to validators that restart. This violates the fundamental assumption documented in the code that "we have/enforce unequivocal proposer election."

**State Corruption**: Multiple conflicting blocks for the same round can be permanently stored in the blockchain database, violating data integrity assumptions. The BlockTree explicitly assumes equivocation detection works and only logs warnings when this assumption is violated.

**Partial Consensus Impact**: While SafetyRules prevents individual validators from double-voting on the same round (preventing direct chain splits), the vulnerability enables:
- Proposers to get a "second chance" at forming a QC after validators restart
- Multiple blocks for the same round coexisting in storage
- Potential for validators to vote on different blocks if restarts occur during the critical window between proposal receipt and voting

**Mitigation Factors** (preventing Critical severity):
- SafetyRules persists `last_voted_round`, preventing double-voting even after restart
- Optimistic proposals have additional protection via `get_block_for_round` check: [8](#0-7) 
- Forming conflicting QCs requires precise timing and multiple simultaneous validator restarts

The issue qualifies as High severity because it breaks a documented security property and enables equivocation attacks within the threat model (< 1/3 Byzantine validators), though mitigating factors prevent direct consensus splits in most scenarios.

## Likelihood Explanation

**Likelihood: Medium**

The vulnerability is exploitable in realistic scenarios:

**Favorable Factors:**
1. **Validator restarts are common**: Validators regularly restart for software updates, maintenance, configuration changes, and crash recovery
2. **Within threat model**: Requires only a single Byzantine proposer (within the < 1/3 Byzantine assumption)
3. **No external coordination required**: Attack works with normal network operations
4. **Realistic timing windows**: Validators often have delays between receiving proposals and voting due to payload fetching delays, execution backpressure, network latency, and block execution time [9](#0-8) 

**Limiting Factors:**
1. **Timing dependency**: Requires validators to restart after receiving the first proposal but before voting on it
2. **SafetyRules protection**: Validators that already voted cannot vote again on a different block
3. **No state recovery**: The absence of recovery code means the vulnerability is persistent but also means there's no accidental mitigation

The test suite contains no coverage for equivocation detection after restart: [10](#0-9) 

## Recommendation

Implement persistent storage and recovery for the equivocation detection state:

1. **Store equivocation history in PersistentLivenessStorage**: Extend the storage interface to persist the last proposed (round, block_hash) for each epoch
2. **Recover state on initialization**: Modify `UnequivocalProposerElection::new` to accept recovery data and populate `already_proposed` from persistent storage
3. **Update state on proposal acceptance**: Persist updates to `already_proposed` when accepting new proposals

## Proof of Concept

The vulnerability can be demonstrated by:
1. Starting a validator network with a Byzantine proposer
2. Having the proposer send block X for round R to validators
3. Restarting validators before they vote
4. Having the proposer send different block Y for same round R
5. Observing that restarted validators accept block Y despite having previously received block X
6. Verifying that both blocks exist in persistent storage for round R

## Notes

This vulnerability is specific to **regular (non-optimistic) proposals**. Optimistic proposals have an additional protection layer via the `get_block_for_round` check which queries the persisted `BlockTree` state, preventing equivocation even after restart. However, regular proposals rely solely on the non-persistent `is_valid_proposal` check, making them vulnerable to this attack.

### Citations

**File:** consensus/src/liveness/unequivocal_proposer_election.rs (L14-21)
```rust
// Wrapper around ProposerElection.
//
// Provides is_valid_proposal that remembers, and rejects if
// the same leader proposes multiple blocks.
pub struct UnequivocalProposerElection {
    proposer_election: Arc<dyn ProposerElection + Send + Sync>,
    already_proposed: Mutex<(Round, HashValue)>,
}
```

**File:** consensus/src/liveness/unequivocal_proposer_election.rs (L35-40)
```rust
    pub fn new(proposer_election: Arc<dyn ProposerElection + Send + Sync>) -> Self {
        Self {
            proposer_election,
            already_proposed: Mutex::new((0, HashValue::zero())),
        }
    }
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

**File:** consensus/src/round_manager.rs (L369-369)
```rust
            proposer_election: Arc::new(UnequivocalProposerElection::new(proposer_election)),
```

**File:** consensus/src/round_manager.rs (L843-850)
```rust
    async fn process_opt_proposal(&mut self, opt_block_data: OptBlockData) -> anyhow::Result<()> {
        ensure!(
            self.block_store
                .get_block_for_round(opt_block_data.round())
                .is_none(),
            "Proposal has already been processed for round: {}",
            opt_block_data.round()
        );
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

**File:** consensus/src/round_manager.rs (L1248-1279)
```rust
        // Since processing proposal is delayed due to backpressure or payload availability, we add
        // the block to the block store so that we don't need to fetch it from remote once we
        // are out of the backpressure. Please note that delayed processing of proposal is not
        // guaranteed to add the block to the block store if we don't get out of the backpressure
        // before the timeout, so this is needed to ensure that the proposed block is added to
        // the block store irrespective. Also, it is possible that delayed processing of proposal
        // tries to add the same block again, which is okay as `insert_block` call
        // is idempotent.
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
```

**File:** consensus/src/block_storage/block_store.rs (L512-515)
```rust
        self.storage
            .save_tree(vec![pipelined_block.block().clone()], vec![])
            .context("Insert block failed when saving block")?;
        self.inner.write().insert_block(pipelined_block)
```

**File:** consensus/src/block_storage/block_tree.rs (L326-335)
```rust
            // Note: the assumption is that we have/enforce unequivocal proposer election.
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

**File:** consensus/src/liveness/unequivocal_proposer_election_test.rs (L29-106)
```rust
#[test]
fn test_is_valid_proposal() {
    let chosen_validator_signer = ValidatorSigner::random([0u8; 32]);
    let chosen_author = chosen_validator_signer.author();
    let another_validator_signer = ValidatorSigner::random([1u8; 32]);
    // let another_author = another_validator_signer.author();

    // Test genesis and the next block
    let quorum_cert = certificate_for_genesis();

    let good_proposal = Block::new_proposal(
        Payload::empty(false, true),
        1,
        1,
        quorum_cert.clone(),
        &chosen_validator_signer,
        Vec::new(),
    )
    .unwrap();
    let bad_author_proposal = Block::new_proposal(
        Payload::empty(false, true),
        1,
        1,
        quorum_cert.clone(),
        &another_validator_signer,
        Vec::new(),
    )
    .unwrap();
    let bad_duplicate_proposal = Block::new_proposal(
        Payload::empty(false, true),
        1,
        2,
        quorum_cert.clone(),
        &chosen_validator_signer,
        Vec::new(),
    )
    .unwrap();
    let next_good_proposal = Block::new_proposal(
        Payload::empty(false, true),
        2,
        3,
        quorum_cert.clone(),
        &chosen_validator_signer,
        Vec::new(),
    )
    .unwrap();
    let next_bad_duplicate_proposal = Block::new_proposal(
        Payload::empty(false, true),
        2,
        4,
        quorum_cert,
        &chosen_validator_signer,
        Vec::new(),
    )
    .unwrap();

    let pe =
        UnequivocalProposerElection::new(Arc::new(MockProposerElection::new(HashMap::from([
            (1, chosen_author),
            (2, chosen_author),
        ]))));

    assert!(pe.is_valid_proposer(chosen_author, 1));
    assert!(pe.is_valid_proposal(&good_proposal));
    assert!(!pe.is_valid_proposal(&bad_author_proposal));

    // another proposal from the valid proposer should fail
    assert!(!pe.is_valid_proposal(&bad_duplicate_proposal));
    // good proposal still passes
    assert!(pe.is_valid_proposal(&good_proposal));

    // going to the next round:
    assert!(pe.is_valid_proposal(&next_good_proposal));
    assert!(!pe.is_valid_proposal(&next_bad_duplicate_proposal));

    // Proposal from previous round is not valid any more:
    assert!(!pe.is_valid_proposal(&good_proposal));
}
```
