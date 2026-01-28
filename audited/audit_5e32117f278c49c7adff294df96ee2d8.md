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
4. **Realistic timing windows**: Validators often have delays between receiving proposals and voting due to:
   - Payload fetching delays
   - Execution backpressure (explicitly handled with polling)
   - Network latency
   - Block execution time

**Limiting Factors:**
1. **Timing dependency**: Requires validators to restart after receiving the first proposal but before voting on it
2. **SafetyRules protection**: Validators that already voted cannot vote again on a different block
3. **No state recovery**: The absence of recovery code means the vulnerability is persistent but also means there's no accidental mitigation

The test suite contains no coverage for equivocation detection after restart: [9](#0-8) 

## Recommendation

**Implement persistent equivocation detection state recovery:**

1. Add a method to recover `already_proposed` state from the `BlockTree`'s `round_to_ids` mapping during initialization:

```rust
impl UnequivocalProposerElection {
    pub fn new_with_recovery(
        proposer_election: Arc<dyn ProposerElection + Send + Sync>,
        block_store: Option<&BlockStore>,
    ) -> Self {
        let already_proposed = if let Some(store) = block_store {
            // Recover highest round and its block ID from BlockTree
            store.inner.read().get_highest_proposed_round()
                .map(|(round, block_id)| (round, block_id))
                .unwrap_or((0, HashValue::zero()))
        } else {
            (0, HashValue::zero())
        };
        
        Self {
            proposer_election,
            already_proposed: Mutex::new(already_proposed),
        }
    }
}
```

2. Alternatively, add a `get_block_for_round` check in the regular `process_proposal` flow (similar to optimistic proposals) to provide defense-in-depth:

```rust
// In process_proposal, before line 1196
ensure!(
    self.block_store.get_block_for_round(proposal.round()).is_none(),
    "[RoundManager] Proposal has already been processed for round: {}",
    proposal.round()
);
```

3. Add comprehensive test coverage for restart scenarios with equivocation attempts.

## Proof of Concept

The vulnerability can be demonstrated by creating a test that simulates validator restart:

```rust
#[test]
fn test_equivocation_after_restart() {
    // 1. Create validator with UnequivocalProposerElection
    let pe = UnequivocalProposerElection::new(Arc::new(MockProposerElection::new(...)));
    
    // 2. Create and validate first block for round 1
    let block_x = create_block(round: 1, timestamp: 1);
    assert!(pe.is_valid_proposal(&block_x)); // Accepts
    
    // 3. Simulate restart: create new UnequivocalProposerElection
    let pe_after_restart = UnequivocalProposerElection::new(Arc::new(MockProposerElection::new(...)));
    
    // 4. Create different block for same round 1
    let block_y = create_block(round: 1, timestamp: 2); // Different timestamp = different block ID
    
    // 5. Verify equivocation is not detected after restart
    assert!(pe_after_restart.is_valid_proposal(&block_y)); // INCORRECTLY ACCEPTS
    
    // This demonstrates the vulnerability: block_y should be rejected as equivocation
    // but is accepted because already_proposed state was lost
}
```

The test would show that after restart, the equivocation detection fails for regular proposals, allowing a second block for the same round to be accepted.

## Notes

- The vulnerability affects **regular proposals only**; optimistic proposals have additional protection through the `get_block_for_round` check
- The `round_to_ids` mapping in `BlockTree` IS recovered from storage (because blocks are recovered), which is why `get_block_for_round` would work as a defense
- Only the `already_proposed` state in `UnequivocalProposerElection` is lost on restart
- The grep search confirms `already_proposed` is only referenced within the `unequivocal_proposer_election.rs` file, with no recovery logic elsewhere in the codebase

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

**File:** consensus/src/round_manager.rs (L844-850)
```rust
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

**File:** consensus/src/liveness/unequivocal_proposer_election_test.rs (L30-106)
```rust
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
