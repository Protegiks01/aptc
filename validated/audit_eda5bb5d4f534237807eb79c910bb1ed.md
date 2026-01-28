# Audit Report

## Title
Equivocation Detection Bypass After Validator Crash Allows Vote Manipulation

## Summary
The `UnequivocalProposerElection.already_proposed` state is not persisted to storage, causing it to reset after validator crash and recovery. This allows Byzantine validators to replay previously-rejected equivocal blocks, bypassing equivocation detection and manipulating which equivocal block an honest validator votes for after recovery.

## Finding Description

The `UnequivocalProposerElection` wrapper maintains in-memory state to detect and reject equivocal proposals from the same proposer within a round. [1](#0-0) 

This state is initialized in memory without persistence. [2](#0-1) 

The `is_valid_proposal()` function rejects equivocal blocks by comparing the block's round against `already_proposed` state and checking block IDs match for the same round. [3](#0-2) 

However, recovery from crash does not restore this state. The `RecoveryData` struct used for consensus recovery contains blocks, QCs, and the last vote, but not the `already_proposed` state. [4](#0-3) 

When `RoundManager` is recreated after recovery, a new `UnequivocalProposerElection` instance is created with fresh state. [5](#0-4) 

The recovery flow processes `RecoveryData` but does not restore `already_proposed` state. [6](#0-5) 

**Attack Scenario:**
1. Byzantine proposer P creates equivocal blocks B1 and B2 for round R
2. Honest validator V receives B1 first, `is_valid_proposal(B1)` passes at proposal validation [7](#0-6) 
3. V begins processing B1 but crashes before voting (between proposal validation and vote creation at [8](#0-7) )
4. V recovers with `already_proposed = (0, HashValue::zero())`
5. Byzantine validator replays B2 to V
6. `is_valid_proposal(B2)` passes because `already_proposed` has been reset
7. V votes for B2 instead of B1

SafetyRules prevents double-voting in the same round but does not prevent this attack when the validator hasn't voted yet. [9](#0-8) 

## Impact Explanation

This vulnerability qualifies as **Medium-to-High Severity** under Aptos bug bounty criteria:

1. **Equivocation Detection Bypass**: The security event logging for equivocation is bypassed after recovery, failing to detect and report Byzantine proposer behavior. [10](#0-9) 

2. **Vote Manipulation**: Byzantine validators can control which equivocal block an honest validator votes for after crash, rather than the deterministic first-received behavior.

3. **Liveness Impact**: By manipulating vote distribution across equivocal blocks, Byzantine actors can split honest validator votes between competing blocks, potentially delaying quorum certificate formation and reducing network liveness.

4. **Protocol Invariant Violation**: The invariant that "equivocal blocks from the same proposer are consistently rejected" is broken, undermining the equivocation detection mechanism.

**Important Note**: This does NOT cause consensus safety violations (validators still cannot double-vote due to SafetyRules) [11](#0-10) , but represents a weakening of Byzantine fault tolerance by allowing manipulation of consensus progress.

## Likelihood Explanation

**Likelihood: Medium**

Required conditions:
- Byzantine proposer creates equivocal blocks (expected under < 1/3 Byzantine assumption)
- Honest validator crashes after proposal validation but before voting (narrow but realistic window - hardware failures, software bugs)
- Byzantine validators coordinate to replay specific equivocal blocks after recovery (straightforward for colluding Byzantine actors)

The attack window exists between `is_valid_proposal()` check and vote creation, which includes block insertion, payload availability checks, and backpressure checks. While this window is narrow, it could be several seconds long under certain conditions, making the attack feasible but requiring precise timing.

## Recommendation

Persist the `already_proposed` state as part of `RecoveryData`:

1. Add `already_proposed` field to `RecoveryData` struct
2. Save this state to `PersistentLivenessStorage` when updated
3. Restore it during `UnequivocalProposerElection` initialization after recovery
4. Ensure the state is properly synchronized with the recovery process

This ensures equivocation detection remains consistent across validator restarts.

## Proof of Concept

The vulnerability can be demonstrated by:
1. Setting up a test network with a Byzantine proposer
2. Having the proposer create equivocal blocks B1 and B2 for round R
3. Sending B1 to an honest validator V
4. Simulating a crash of V after `is_valid_proposal(B1)` passes but before voting
5. Restarting V with recovery
6. Sending B2 to V
7. Observing that V accepts and votes for B2, demonstrating the equivocation detection bypass

The code paths verified show this attack is technically feasible within the current implementation.

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

**File:** consensus/src/liveness/unequivocal_proposer_election.rs (L61-86)
```rust
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

**File:** consensus/src/round_manager.rs (L1399-1399)
```rust
        let vote = self.create_vote(proposal).await?;
```

**File:** consensus/src/epoch_manager.rs (L1383-1417)
```rust
        match self.storage.start(
            consensus_config.order_vote_enabled(),
            consensus_config.window_size(),
        ) {
            LivenessStorageData::FullRecoveryData(initial_data) => {
                self.recovery_mode = false;
                self.start_round_manager(
                    consensus_key,
                    initial_data,
                    epoch_state,
                    consensus_config,
                    execution_config,
                    onchain_randomness_config,
                    jwk_consensus_config,
                    Arc::new(network_sender),
                    payload_client,
                    payload_manager,
                    rand_config,
                    fast_rand_config,
                    rand_msg_rx,
                    secret_share_msg_rx,
                )
                .await
            },
            LivenessStorageData::PartialRecoveryData(ledger_data) => {
                self.recovery_mode = true;
                self.start_recovery_manager(
                    ledger_data,
                    consensus_config,
                    epoch_state,
                    Arc::new(network_sender),
                )
                .await
            },
        }
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L68-74)
```rust
        // if already voted on this round, send back the previous vote
        // note: this needs to happen after verifying the epoch as we just check the round here
        if let Some(vote) = safety_data.last_vote.clone() {
            if vote.vote_data().proposed().round() == proposed_block.round() {
                return Ok(vote);
            }
        }
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L77-80)
```rust
        self.verify_and_update_last_vote_round(
            proposed_block.block_data().round(),
            &mut safety_data,
        )?;
```
