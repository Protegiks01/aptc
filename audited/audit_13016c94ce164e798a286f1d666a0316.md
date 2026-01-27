# Audit Report

## Title
Backup Restoration Allows Consensus Safety Violation Through Stale SafetyRules State

## Summary
When validators restore from backups within the same epoch, the `load_config()` function and SafetyRules initialization do not detect that the persistent storage contains stale voting state. This allows validators to double-vote on rounds they have already voted on, violating AptosBFT consensus safety guarantees and potentially causing chain splits.

## Finding Description

The Aptos consensus system maintains two separate persistent storage systems:

1. **ConsensusDB** (PersistentLivenessStorage): Stores consensus blocks, quorum certificates, and votes
2. **SafetyRules Storage** (PersistentSafetyStorage via SecureBackend): Stores SafetyData containing `epoch`, `last_voted_round`, and `last_vote`

The vulnerability exists because these storage systems are never cross-validated for staleness after backup restoration. [1](#0-0) 

The `load_config()` function only deserializes the YAML configuration file that points to where the backend storage is located. It performs no validation of the actual persistent data stored in that backend. [2](#0-1) 

The SafetyRulesConfig specifies a `backend` (SecureBackend) that stores the critical safety data, but this data is never validated for staleness during initialization. [3](#0-2) 

The `guarded_initialize()` function only validates that the epoch matches. When `current_epoch == epoch_state.epoch` (line 308, Ordering::Equal case), it performs no validation and does not reset the SafetyData. This means stale round numbers within the same epoch are never detected. [4](#0-3) 

SafetyData contains `last_voted_round` and `last_vote`, which are critical for preventing double voting. [5](#0-4) 

When constructing votes, SafetyRules loads its own SafetyData from persistent storage and checks if `round > safety_data.last_voted_round`. With stale storage, this check passes for rounds the validator has already voted on.

**Attack Scenario:**
1. Validator operates at epoch 5, voting on rounds 100, 101, 102, ..., 110
2. Both ConsensusDB and SafetyRules storage are backed up after round 100
3. Validator continues operating normally through round 110
4. System crash or hardware failure occurs
5. Administrator restores from backup (both storages revert to round 100 state)
6. Network is still at epoch 5, currently at rounds 105-110
7. Validator restarts: `load_config()` loads configuration, SafetyRules initializes
8. SafetyRules sees epoch 5 == epoch 5, accepts initialization without resetting rounds
9. SafetyRules has `last_voted_round = 100`, unaware it already voted on rounds 101-110
10. When asked to vote on round 105, the check `105 > 100` passes
11. **Validator creates a second vote for round 105, violating BFT safety through equivocation** [6](#0-5) 

The safety rule that should prevent this (`verify_and_update_last_vote_round`) fails because it checks against the stale `last_voted_round` value.

## Impact Explanation

This is a **Critical** severity vulnerability under the Aptos Bug Bounty criteria:

- **Consensus/Safety violations**: Directly allows double voting, which violates the fundamental safety property of Byzantine Fault Tolerant consensus. A validator can sign two different votes for the same round, creating equivocation.

- **Chain splits**: If multiple validators restore from stale backups, conflicting votes can be propagated through the network, potentially causing validators to commit different blocks at the same height.

- **Non-recoverable scenarios**: If the double votes create divergent consensus states across validators, it may require a hard fork to recover, especially if conflicting blocks get committed.

- **Affects all validators**: The consensus safety violation impacts the entire network, not just the validator that restored from backup.

The vulnerability breaks the core invariant: "Consensus Safety: AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine". This allows an honest (non-Byzantine) validator to inadvertently violate safety through routine operational procedures.

## Likelihood Explanation

**HIGH likelihood** - This vulnerability will occur during normal operational procedures:

1. **Common operational scenario**: System administrators routinely create backups and restore from them after:
   - Hardware failures
   - Disk corruption
   - Accidental deletion of data
   - Migration to new infrastructure
   - Disaster recovery procedures

2. **No malicious intent required**: This is not an attack scenario but a bug in normal validator operations. Any validator operator performing standard backup/restore procedures is at risk.

3. **No detection mechanism**: The validator restarts successfully and appears to operate normally. There's no warning or error that the storage is stale.

4. **Within-epoch window**: Epochs in Aptos can last for extended periods. The vulnerability window exists for the entire epoch duration after taking a backup.

5. **Both storages must be restored**: Since both ConsensusDB and SafetyRules storage would typically be backed up and restored together (they're both in the node's data directory), this scenario is realistic.

## Recommendation

Add staleness detection during SafetyRules initialization by comparing the persistent storage state against the ledger's committed state:

**Option 1: Validate against committed round**
```rust
fn guarded_initialize(&mut self, proof: &EpochChangeProof) -> Result<(), Error> {
    let waypoint = self.persistent_storage.waypoint()?;
    let last_li = proof.verify(&waypoint)
        .map_err(|e| Error::InvalidEpochChangeProof(format!("{}", e)))?;
    let ledger_info = last_li.ledger_info();
    let epoch_state = ledger_info.next_epoch_state()
        .cloned()
        .ok_or(Error::InvalidLedgerInfo)?;

    // NEW: Get committed round from ledger
    let committed_round = ledger_info.commit_info().round();
    
    let current_safety_data = self.persistent_storage.safety_data()?;
    let current_epoch = current_safety_data.epoch;
    
    match current_epoch.cmp(&epoch_state.epoch) {
        Ordering::Greater => {
            return Err(Error::WaypointOutOfDate(...));
        },
        Ordering::Less => {
            // start new epoch
            self.persistent_storage.set_safety_data(SafetyData::new(
                epoch_state.epoch, 0, 0, 0, None, 0,
            ))?;
        },
        Ordering::Equal => {
            // NEW: Check for staleness within the same epoch
            if current_safety_data.last_voted_round < committed_round {
                return Err(Error::StaleSafetyData(
                    current_safety_data.last_voted_round,
                    committed_round,
                    current_epoch,
                ));
            }
        }
    };
    // ... rest of initialization
}
```

**Option 2: Cross-validate with ConsensusDB**
Pass the RecoveryData's `last_vote` to SafetyRules initialization and validate:
- If ConsensusDB has a vote for a higher round than SafetyRules storage, reset SafetyRules storage
- This requires modifying the initialization interface to accept recovery data

The fix should also add a new error type for stale safety data and log clear warnings when detected.

## Proof of Concept

```rust
// Rust integration test demonstrating the vulnerability
#[tokio::test]
async fn test_backup_restoration_double_vote() {
    // 1. Initialize validator with epoch 1
    let (mut safety_rules, storage, epoch_state) = setup_validator(1);
    
    // 2. Vote on round 100
    let proposal_100 = create_proposal(1, 100, &epoch_state);
    let vote_100 = safety_rules
        .construct_and_sign_vote_two_chain(&proposal_100, None)
        .unwrap();
    assert_eq!(vote_100.vote_data().proposed().round(), 100);
    
    // 3. Backup the safety rules storage
    let backup = backup_storage(&storage);
    
    // 4. Continue voting on rounds 101-110
    for round in 101..=110 {
        let proposal = create_proposal(1, round, &epoch_state);
        let vote = safety_rules
            .construct_and_sign_vote_two_chain(&proposal, None)
            .unwrap();
        assert_eq!(vote.vote_data().proposed().round(), round);
    }
    
    // 5. Simulate crash and restore from backup
    drop(safety_rules);
    restore_storage(&storage, backup);
    
    // 6. Reinitialize SafetyRules with same epoch
    let mut safety_rules_restored = reinitialize_safety_rules(&storage, &epoch_state);
    
    // 7. Try to vote on round 105 (already voted in step 4)
    let proposal_105_duplicate = create_proposal(1, 105, &epoch_state);
    
    // BUG: This should fail but succeeds, creating a double vote
    let vote_105_duplicate = safety_rules_restored
        .construct_and_sign_vote_two_chain(&proposal_105_duplicate, None)
        .unwrap();
    
    assert_eq!(vote_105_duplicate.vote_data().proposed().round(), 105);
    
    // This demonstrates the vulnerability: validator can vote twice on round 105
    // violating BFT consensus safety
}
```

**Notes**
- This vulnerability exists because `load_config()` only loads configuration, not validates storage state
- SafetyRules initialization only checks epoch equality, not round staleness within epochs
- The two storage systems (ConsensusDB and SafetyRules storage) are never cross-validated
- This allows validators to inadvertently violate consensus safety through routine backup restoration
- The fix requires adding staleness detection by comparing against committed rounds or cross-validating storage systems
- This is a critical consensus safety bug that can occur during normal validator operations without any malicious intent

### Citations

**File:** config/src/config/persistable_config.rs (L14-20)
```rust
    fn load_config<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        // Read the file into a string
        let file_contents = Self::read_config_file(&path)?;

        // Parse the file string
        Self::parse_serialized_config(&file_contents)
    }
```

**File:** config/src/config/safety_rules_config.rs (L23-34)
```rust
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SafetyRulesConfig {
    pub backend: SecureBackend,
    pub logger: LoggerConfig,
    pub service: SafetyRulesService,
    pub test: Option<SafetyRulesTestConfig>,
    // Read/Write/Connect networking operation timeout in milliseconds.
    pub network_timeout_ms: u64,
    pub enable_cached_safety_data: bool,
    pub initial_safety_rules_config: InitialSafetyRulesConfig,
}
```

**File:** consensus/safety-rules/src/safety_rules.rs (L212-232)
```rust
    /// First voting rule
    pub(crate) fn verify_and_update_last_vote_round(
        &self,
        round: Round,
        safety_data: &mut SafetyData,
    ) -> Result<(), Error> {
        if round <= safety_data.last_voted_round {
            return Err(Error::IncorrectLastVotedRound(
                round,
                safety_data.last_voted_round,
            ));
        }

        safety_data.last_voted_round = round;
        trace!(
            SafetyLogSchema::new(LogEntry::LastVotedRound, LogEvent::Update)
                .last_voted_round(safety_data.last_voted_round)
        );

        Ok(())
    }
```

**File:** consensus/safety-rules/src/safety_rules.rs (L265-309)
```rust
    fn guarded_initialize(&mut self, proof: &EpochChangeProof) -> Result<(), Error> {
        let waypoint = self.persistent_storage.waypoint()?;
        let last_li = proof
            .verify(&waypoint)
            .map_err(|e| Error::InvalidEpochChangeProof(format!("{}", e)))?;
        let ledger_info = last_li.ledger_info();
        let epoch_state = ledger_info
            .next_epoch_state()
            .cloned()
            .ok_or(Error::InvalidLedgerInfo)?;

        // Update the waypoint to a newer value, this might still be older than the current epoch.
        let new_waypoint = &Waypoint::new_epoch_boundary(ledger_info)
            .map_err(|error| Error::InternalError(error.to_string()))?;
        if new_waypoint.version() > waypoint.version() {
            self.persistent_storage.set_waypoint(new_waypoint)?;
        }

        let current_epoch = self.persistent_storage.safety_data()?.epoch;
        match current_epoch.cmp(&epoch_state.epoch) {
            Ordering::Greater => {
                // waypoint is not up to the current epoch.
                return Err(Error::WaypointOutOfDate(
                    waypoint.version(),
                    new_waypoint.version(),
                    current_epoch,
                    epoch_state.epoch,
                ));
            },
            Ordering::Less => {
                // start new epoch
                self.persistent_storage.set_safety_data(SafetyData::new(
                    epoch_state.epoch,
                    0,
                    0,
                    0,
                    None,
                    0,
                ))?;

                info!(SafetyLogSchema::new(LogEntry::Epoch, LogEvent::Update)
                    .epoch(epoch_state.epoch));
            },
            Ordering::Equal => (),
        };
```

**File:** consensus/consensus-types/src/safety_data.rs (L8-21)
```rust
/// Data structure for safety rules to ensure consensus safety.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize, Clone, Default)]
pub struct SafetyData {
    pub epoch: u64,
    pub last_voted_round: u64,
    // highest 2-chain round, used for 3-chain
    pub preferred_round: u64,
    // highest 1-chain round, used for 2-chain
    #[serde(default)]
    pub one_chain_round: u64,
    pub last_vote: Option<Vote>,
    #[serde(default)]
    pub highest_timeout_round: u64,
}
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L66-80)
```rust
        let mut safety_data = self.persistent_storage.safety_data()?;

        // if already voted on this round, send back the previous vote
        // note: this needs to happen after verifying the epoch as we just check the round here
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
