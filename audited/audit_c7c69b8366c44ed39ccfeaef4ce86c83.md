# Audit Report

## Title
Equivocation Detection Bypass After Node Recovery Due to Non-Persistent `already_proposed` State

## Summary
The `UnequivocalProposerElection` component maintains equivocation detection state in a non-persistent in-memory field (`already_proposed`). If a validator node crashes after validating a proposal but before persisting it to storage, the `already_proposed` state is lost on recovery. This allows Byzantine validators to replay equivocating proposals that would have been rejected pre-crash, potentially enabling consensus safety violations.

## Finding Description

The `UnequivocalProposerElection::is_valid_proposal()` function is designed to prevent equivocation by tracking which proposals have been seen for each round using the `already_proposed` field: [1](#0-0) 

This field is initialized to `(0, HashValue::zero())` on creation: [2](#0-1) 

The equivocation check logic compares incoming proposals against this in-memory state: [3](#0-2) 

**Critical Flow Analysis:**

When a new `RoundManager` is created (including during recovery), a fresh `UnequivocalProposerElection` instance is created: [4](#0-3) 

The proposal processing flow in `RoundManager::process_proposal()` validates proposals BEFORE persisting them: [5](#0-4) 

Block persistence only occurs later: [6](#0-5) 

And the actual persistence call in `insert_block_inner`: [7](#0-6) 

**The Vulnerability Window:**

1. Validator node receives proposal A at round R
2. `is_valid_proposal()` executes, updating `already_proposed` to `(R, hash_A)` in memory
3. **Node crashes** before `insert_block_inner` persists the block at line 512-514
4. Node recovers, `UnequivocalProposerElection::new()` resets `already_proposed` to `(0, HashValue::zero())`
5. Recovery restores `current_round` based on persisted QCs, setting it to R
6. Byzantine validator sends equivocating proposal B at round R (different block ID)
7. `is_valid_proposal()` checks: round R > `already_proposed.0` (0), accepts and updates to `(R, hash_B)`
8. Node accepts the equivocating proposal and may vote for it

The `BlockTree` explicitly allows multiple blocks per round with only a warning: [8](#0-7) 

**Invariant Violation:**

This breaks **Consensus Safety** invariant #2: "AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine." The equivocation detection mechanism is a critical safety component that prevents Byzantine validators from proposing conflicting blocks in the same round. Bypassing this allows potential formation of conflicting quorum certificates.

## Impact Explanation

**Severity: Critical** (Consensus/Safety violation - up to $1,000,000)

This vulnerability allows Byzantine validators to bypass equivocation detection under specific timing conditions, which could lead to:

1. **Consensus Safety Violations**: Multiple conflicting blocks for the same round could receive votes from honest validators, potentially forming different quorum certificates
2. **Chain Fork Risk**: If conflicting QCs are formed, different validators may commit different blocks at the same height
3. **Undermines BFT Guarantees**: The core assumption that honest validators will reject equivocating proposals is violated

The impact qualifies as Critical because it directly threatens consensus safety, one of the most fundamental invariants in a Byzantine Fault Tolerant system. While it requires specific timing (node crash during the vulnerability window), the consequences of successful exploitation are severe enough to potentially require a hard fork to resolve.

## Likelihood Explanation

**Likelihood: Medium-High**

The attack requires:
- A Byzantine validator (assumed to exist in < 1/3 proportion per BFT threat model)
- An honest validator to crash during the specific window between proposal validation and block persistence
- Network conditions where the round doesn't advance past the target round before recovery

While node crashes are relatively rare, they do occur in production systems due to:
- Hardware failures
- Process crashes/OOM conditions  
- Network partitions causing restarts
- Planned maintenance with unexpected issues

The vulnerability window is narrow (between validation and persistence), but given the critical nature of consensus nodes and the potential for targeted attacks (e.g., triggering crashes through resource exhaustion), this presents a realistic attack surface. Byzantine validators could attempt to induce crashes or simply wait for natural crash events to exploit this weakness.

## Recommendation

**Solution: Persist equivocation detection state or rebuild from persisted blocks**

**Option 1: Rebuild `already_proposed` from persisted state on recovery**

Modify `UnequivocalProposerElection` to initialize from the highest persisted block for the current round:

```rust
impl UnequivocalProposerElection {
    pub fn new_from_recovery(
        proposer_election: Arc<dyn ProposerElection + Send + Sync>,
        current_round: Round,
        highest_block: Option<(Round, HashValue)>,
    ) -> Self {
        let already_proposed = highest_block
            .filter(|(round, _)| *round == current_round)
            .unwrap_or((0, HashValue::zero()));
        
        Self {
            proposer_election,
            already_proposed: Mutex::new(already_proposed),
        }
    }
}
```

Then in `RoundManager::new()`, pass the highest block information from the recovered state.

**Option 2: Persist equivocation state explicitly**

Add `already_proposed` state to `PersistentLivenessStorage` and save/restore it during recovery. This is more robust but requires storage schema changes.

**Recommended Approach:** Option 1 is simpler and leverages existing persistence. During recovery, scan persisted blocks for the current round and initialize `already_proposed` accordingly.

## Proof of Concept

```rust
#[cfg(test)]
mod equivocation_bypass_test {
    use super::*;
    use aptos_consensus_types::block::Block;
    use aptos_types::validator_signer::ValidatorSigner;
    
    #[test]
    fn test_equivocation_bypass_after_recovery() {
        // Setup: Create proposer election for round 100
        let proposers = HashMap::from([(100, validator_author)]);
        let pe = UnequivocalProposerElection::new(
            Arc::new(MockProposerElection::new(proposers))
        );
        
        // Step 1: Validate proposal A at round 100
        let proposal_a = create_test_proposal(100, 1, &validator_signer);
        assert!(pe.is_valid_proposal(&proposal_a));
        // already_proposed is now (100, hash_A)
        
        // Step 2: Attempt equivocating proposal B - should fail
        let proposal_b = create_test_proposal(100, 2, &validator_signer);
        assert!(!pe.is_valid_proposal(&proposal_b));
        
        // Step 3: Simulate crash and recovery by creating new instance
        let pe_after_crash = UnequivocalProposerElection::new(
            Arc::new(MockProposerElection::new(proposers))
        );
        // already_proposed reset to (0, HashValue::zero())
        
        // Step 4: Replay equivocating proposal B - VULNERABILITY!
        // This should fail but actually succeeds
        assert!(pe_after_crash.is_valid_proposal(&proposal_b));
        
        // The equivocation was accepted after recovery!
    }
}
```

**Notes**

The vulnerability stems from a fundamental architectural issue: equivocation detection state is kept purely in-memory while other consensus state (blocks, QCs, votes) is persisted. This creates an inconsistency where the system can "forget" which proposals it has seen for a given round.

The issue is particularly insidious because:
1. The `BlockTree` code explicitly assumes "unequivocal proposer election" is enforced (see comment at line 326)
2. The persistence happens AFTER validation, creating the race condition
3. Recovery correctly restores round state from QCs but has no mechanism to restore equivocation detection state

This represents a gap between the design assumption (equivocation detection is always enforced) and the implementation reality (it can be bypassed on recovery).

### Citations

**File:** consensus/src/liveness/unequivocal_proposer_election.rs (L20-21)
```rust
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

**File:** consensus/src/liveness/unequivocal_proposer_election.rs (L63-86)
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
        })
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

**File:** consensus/src/round_manager.rs (L1256-1259)
```rust
        self.block_store
            .insert_block(proposal.clone())
            .await
            .context("[RoundManager] Failed to insert the block into BlockStore")?;
```

**File:** consensus/src/block_storage/block_store.rs (L512-514)
```rust
        self.storage
            .save_tree(vec![pipelined_block.block().clone()], vec![])
            .context("Insert block failed when saving block")?;
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
