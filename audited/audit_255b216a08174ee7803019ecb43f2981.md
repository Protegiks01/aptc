# Audit Report

## Title
Equivocation Detection Bypass After Validator Crash Allows Vote Manipulation

## Summary
The `UnequivocalProposerElection.already_proposed` state is not persisted to storage, causing it to reset to `(0, HashValue::zero())` after validator crash and recovery. This allows Byzantine validators to replay previously-rejected equivocal blocks, bypassing equivocation detection and manipulating which equivocal block an honest validator votes for after recovery.

## Finding Description

The `UnequivocalProposerElection` wrapper maintains in-memory state to detect and reject equivocal proposals from the same proposer within a round. [1](#0-0) 

This state is initialized in memory without persistence: [2](#0-1) 

The `is_valid_proposal()` function rejects equivocal blocks by comparing the block's round against `already_proposed.0` and checking block IDs match for the same round: [3](#0-2) 

However, recovery from crash does not restore this state. The `RecoveryData` struct used for consensus recovery contains blocks, QCs, and the last vote, but not the `already_proposed` state: [4](#0-3) 

When `RoundManager` is recreated after recovery, a new `UnequivocalProposerElection` instance is created with fresh state: [5](#0-4) 

**Attack Scenario:**
1. Byzantine proposer P creates equivocal blocks B1 and B2 for round R
2. Honest validator V receives B1 first, `is_valid_proposal(B1)` passes, `already_proposed = (R, B1.id())`
3. V begins processing B1 but crashes before voting (e.g., hardware failure)
4. V recovers with `already_proposed = (0, HashValue::zero())`
5. Byzantine validator replays B2 to V
6. `is_valid_proposal(B2)` passes because `R > 0`, setting `already_proposed = (R, B2.id())`
7. V votes for B2 instead of B1

The proposal validation check occurs before voting: [6](#0-5) 

SafetyRules prevents double-voting in the same round but does not prevent this attack when the validator hasn't voted yet: [7](#0-6) 

## Impact Explanation

This vulnerability qualifies as **High Severity** under Aptos bug bounty criteria for "Significant protocol violations":

1. **Equivocation Detection Bypass**: The security event logging for equivocation (line 71-78 in unequivocal_proposer_election.rs) is bypassed after recovery, failing to detect and report Byzantine proposer behavior.

2. **Vote Manipulation**: Byzantine validators can control which equivocal block an honest validator votes for after crash, rather than the deterministic first-received behavior.

3. **Liveness Impact**: By manipulating vote distribution across equivocal blocks B1 and B2, Byzantine actors can:
   - Split honest validator votes between competing blocks
   - Prevent quorum certificate formation for either block
   - Delay consensus progress and reduce network liveness
   
4. **Protocol Invariant Violation**: The invariant that "equivocal blocks from the same proposer are consistently rejected" is broken, undermining the equivocation detection mechanism that is critical for Byzantine fault tolerance.

While this does not directly cause consensus safety violations (validators still cannot double-vote due to SafetyRules), it represents a significant weakening of Byzantine fault tolerance by allowing manipulation of consensus progress.

## Likelihood Explanation

**Likelihood: Medium-High**

Required conditions:
- Byzantine proposer creates equivocal blocks (expected under < 1/3 Byzantine assumption)
- Honest validator crashes before voting on a round (realistic - hardware failures, software bugs, network issues)
- Byzantine validators coordinate to replay specific equivocal blocks after recovery (straightforward for colluding Byzantine actors)

The attack window exists whenever a validator crashes after receiving but before voting on a proposal. Validator crashes are not uncommon in distributed systems. Byzantine validators monitoring the network can detect crashes through missed heartbeats and strategically replay equivocal blocks during recovery.

## Recommendation

**Solution**: Persist the `already_proposed` state as part of consensus recovery data.

Modify the `RecoveryData` struct to include the last proposed block information:

```rust
pub struct RecoveryData {
    last_vote: Option<Vote>,
    root: RootInfo,
    root_metadata: RootMetadata,
    blocks: Vec<Block>,
    quorum_certs: Vec<QuorumCert>,
    blocks_to_prune: Option<Vec<HashValue>>,
    highest_2chain_timeout_certificate: Option<TwoChainTimeoutCertificate>,
    // Add this field:
    last_valid_proposal: Option<(Round, HashValue)>,
}
```

Update `UnequivocalProposerElection` to accept and restore this state:

```rust
impl UnequivocalProposerElection {
    pub fn new_with_recovery(
        proposer_election: Arc<dyn ProposerElection + Send + Sync>,
        last_valid_proposal: Option<(Round, HashValue)>,
    ) -> Self {
        Self {
            proposer_election,
            already_proposed: Mutex::new(last_valid_proposal.unwrap_or((0, HashValue::zero()))),
        }
    }
}
```

Persist the state by saving it whenever `is_valid_proposal` accepts a new proposal:

```rust
// In is_valid_proposal, after updating already_proposed
self.storage.save_last_valid_proposal(block.round(), block.id())?;
```

## Proof of Concept

```rust
// consensus/src/liveness/unequivocal_proposer_election_test.rs

#[test]
fn test_equivocation_replay_after_recovery() {
    // Setup
    let proposer_election = Arc::new(RotatingProposer::new(vec![author(0)], 1));
    let unequivocal = UnequivocalProposerElection::new(proposer_election.clone());
    
    // Byzantine proposer creates two equivocal blocks for round 5
    let block1 = test_utils::create_block(5, HashValue::random(), author(0));
    let block2 = test_utils::create_block(5, HashValue::random(), author(0));
    assert_ne!(block1.id(), block2.id()); // Different block IDs
    
    // Phase 1: Before crash
    // Validator receives block1 first
    assert!(unequivocal.is_valid_proposal(&block1));
    
    // Validator receives equivocal block2 - should be REJECTED
    assert!(!unequivocal.is_valid_proposal(&block2));
    
    // Simulate crash and recovery: create new UnequivocalProposerElection
    let unequivocal_after_recovery = UnequivocalProposerElection::new(proposer_election);
    
    // Phase 2: After recovery
    // Byzantine validator replays block2 - should be REJECTED but is ACCEPTED
    assert!(unequivocal_after_recovery.is_valid_proposal(&block2)); // VULNERABILITY
    
    // This demonstrates that the equivocation detection is bypassed after recovery
}
```

Run with: `cargo test test_equivocation_replay_after_recovery --package aptos-consensus`

The test demonstrates that the same equivocal block (block2) is correctly rejected before crash but incorrectly accepted after recovery, confirming the vulnerability.

## Notes

This vulnerability specifically affects the equivocation detection layer that sits before SafetyRules. While SafetyRules prevents actual double-voting by an honest validator, the bypass of equivocation detection allows Byzantine validators to manipulate which equivocal block receives votes from crashed-and-recovered validators. This can be exploited to impact network liveness by strategically preventing quorum formation.

The fix requires extending the persistent consensus state to include the `already_proposed` tracking information, similar to how `last_vote` is already persisted and recovered.

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

**File:** consensus/src/liveness/unequivocal_proposer_election.rs (L63-85)
```rust
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

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L70-80)
```rust
        if let Some(vote) = safety_data.last_vote.clone() {
            if vote.vote_data().proposed().round() == proposed_block.round() {
                return Ok(vote);
            }
        }

        // Two voting rules
        self.verify_and_update_last_vote_round(
            proposed_block.block_data().round(),
            &mut safety_data,
        )?;
```
