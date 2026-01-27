# Audit Report

## Title
Equivocation Detection State Loss After Validator Restart Allows Multiple Blocks Per Round

## Summary
The `UnequivocalProposerElection.already_proposed` state is not persisted to disk, causing validators to lose equivocation detection capability after restart. This allows validators to accept multiple different blocks from the same proposer for the same round, violating the consensus invariant that "we have/enforce unequivocal proposer election."

## Finding Description

The `UnequivocalProposerElection` struct maintains in-memory state to prevent accepting multiple proposals from the same leader in a single round. [1](#0-0) 

This state is initialized to `(0, HashValue::zero())` on construction and is never persisted. [2](#0-1) 

The `is_valid_proposal` method enforces equivocation detection by comparing the current proposal's round against `already_proposed`. [3](#0-2) 

When a validator restarts, the `RecoveryData` structure recovers blocks and quorum certificates from persistent storage, but does NOT recover the `already_proposed` state. [4](#0-3) 

The `BlockTree` code explicitly relies on this assumption: [5](#0-4) 

**Attack Scenario:**

1. Validator V1 receives Block A (round R, hash H_A) from leader L
2. `is_valid_proposal(Block A)` passes, setting `already_proposed = (R, H_A)`
3. Block A is inserted into BlockStore and persisted to disk via `save_tree()`
4. V1 crashes BEFORE voting (or after voting but the attack still applies)
5. V1 restarts and recovers Block A from storage, but `already_proposed` resets to `(0, HashValue::zero())`
6. Leader L (malicious or also restarted) sends Block B (round R, hash H_B ≠ H_A) to V1
7. `is_valid_proposal(Block B)` evaluates: since `already_proposed.0 = 0 < R`, it returns `Ordering::Greater` and accepts Block B
8. Block B is inserted into BlockStore - the code logs a warning but allows the insertion
9. V1 now has BOTH Block A and Block B in its BlockStore for the same round R from the same proposer

This violates the unequivocal proposer election invariant that the block tree depends upon.

## Impact Explanation

This is a **High Severity** vulnerability (potentially Critical) per Aptos bug bounty criteria:

**Consensus Safety Violation**: The system allows multiple conflicting blocks from the same proposer in the same round to coexist in a validator's block tree. While `SafetyRules.last_voted_round` provides a secondary defense preventing double-voting for the same round, the consensus protocol should not rely solely on this last line of defense.

**Invariant Violation**: The BlockTree code explicitly states it assumes unequivocal proposer election is enforced. [6](#0-5) 

**Defense-in-Depth Failure**: Equivocation detection should occur at the proposal validation layer (`UnequivocalProposerElection`), not solely at the voting layer (`SafetyRules`). The current implementation creates a single point of failure.

**State Inconsistency**: Multiple blocks for the same round in the block tree can lead to:
- Confusing block tree topology
- Potential for validators to build on different blocks
- Risk of consensus splits if SafetyRules has any edge case bugs

This qualifies as a "Significant protocol violation" under High Severity criteria.

## Likelihood Explanation

**Likelihood: Medium to High**

The vulnerability triggers when:
1. A validator crashes and restarts (common in production environments)
2. A proposer sends different blocks for the same round (either due to the proposer also restarting with its own lost state, or malicious behavior)

The crash scenario is realistic - validators crash due to:
- Hardware failures
- Software bugs  
- Maintenance operations
- Resource exhaustion

The proposer sending different blocks can occur when:
- The proposer itself crashes and loses its `ProposalGenerator.last_round_generated` state (also not persisted) [7](#0-6) 
- A malicious proposer intentionally equivocates
- Network partitions cause delayed/reordered messages

## Recommendation

**Persist `already_proposed` state to disk alongside other liveness data:**

1. Add `already_proposed` to the persisted liveness storage data structure
2. Extend `RecoveryData` to include the last accepted proposal per round
3. Save `already_proposed` state in `PersistentLivenessStorage::save_tree()` or create a dedicated `save_last_proposal()` method
4. Restore `already_proposed` state during recovery in `StorageWriteProxy::start()`

**Proposed Implementation:**

```rust
// In PersistentLivenessStorage trait:
fn save_last_accepted_proposal(&self, round: Round, block_id: HashValue) -> Result<()>;

// In UnequivocalProposerElection::is_valid_proposal():
// After accepting a proposal, persist it:
if valid {
    self.storage.save_last_accepted_proposal(block.round(), block.id())?;
}

// During initialization in RoundManager::new():
// Recover already_proposed from storage
let last_accepted = storage.get_last_accepted_proposal()?;
let proposer_election = Arc::new(UnequivocalProposerElection::new_with_state(
    proposer_election,
    last_accepted
));
```

Additionally, consider persisting `ProposalGenerator.last_round_generated` to prevent proposer-side equivocation after restart.

## Proof of Concept

```rust
#[test]
fn test_equivocation_after_restart() {
    use aptos_consensus_types::block::{Block, block_test_utils::certificate_for_genesis};
    use aptos_types::validator_signer::ValidatorSigner;
    
    let proposer_signer = ValidatorSigner::random([0u8; 32]);
    let proposer = proposer_signer.author();
    
    // Setup proposer election
    let mut proposers = HashMap::new();
    proposers.insert(1, proposer);
    let pe = UnequivocalProposerElection::new(
        Arc::new(MockProposerElection::new(proposers))
    );
    
    // Round 1: Receive Block A
    let qc = certificate_for_genesis();
    let block_a = Block::new_proposal(
        Payload::empty(false, true),
        1, // round
        1, // timestamp  
        qc.clone(),
        &proposer_signer,
        Vec::new(),
    ).unwrap();
    
    // Validate Block A - should pass
    assert!(pe.is_valid_proposal(&block_a));
    
    // Simulate restart by creating new UnequivocalProposerElection
    // (already_proposed state is lost)
    let pe_after_restart = UnequivocalProposerElection::new(
        Arc::new(MockProposerElection::new(proposers.clone()))
    );
    
    // Round 1: Receive Block B (different block, same round)
    let block_b = Block::new_proposal(
        Payload::empty(false, true),
        1, // same round!
        2, // different timestamp
        qc,
        &proposer_signer,
        Vec::new(),
    ).unwrap();
    
    // Validate Block B after restart - INCORRECTLY PASSES
    // This should fail because we already accepted Block A for round 1
    // But after restart, already_proposed state is lost
    assert!(pe_after_restart.is_valid_proposal(&block_b));
    
    // This proves equivocation detection is lost after restart
    println!("VULNERABILITY: Accepted two different blocks for round 1!");
    println!("Block A ID: {}", block_a.id());
    println!("Block B ID: {}", block_b.id());
}
```

**Notes:**

The vulnerability stems from a fundamental design oversight where critical equivocation detection state is maintained in-memory only. While `SafetyRules` provides partial mitigation by preventing double-voting via persisted `last_voted_round`, the consensus protocol should enforce unequivocal proposer election at the proposal acceptance layer as designed. The explicit assumption in `BlockTree` that unequivocal proposer election is enforced indicates this is a required invariant that is currently violated after validator restarts.

### Citations

**File:** consensus/src/liveness/unequivocal_proposer_election.rs (L18-21)
```rust
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

**File:** consensus/src/liveness/proposal_generator.rs (L402-403)
```rust
    // Last round that a proposal was generated
    last_round_generated: Mutex<Round>,
```
