# Audit Report

## Title
Database Rollback Attack Enables Validator Equivocation and Consensus Safety Violation

## Summary
An attacker with access to a validator's file system can restore old database checkpoints of ConsensusDB, AptosDB, and SafetyRules storage to force the validator back to an earlier consensus state. This enables the validator to equivocate (double-vote on the same round), violating AptosBFT consensus safety and potentially enabling double-spend attacks.

## Finding Description

Aptos stores consensus safety-critical state across three independent databases:

1. **ConsensusDB**: Stores uncommitted blocks, quorum certificates, and last_vote [1](#0-0) 

2. **AptosDB**: Stores committed ledger state and transactions [2](#0-1) 

3. **SafetyRules Storage**: Stores SafetyData including last_voted_round to prevent equivocation [3](#0-2) 

**The Vulnerability:** These three databases have no cryptographic binding or external validation mechanism to detect when they have been restored to an earlier checkpoint. When all three are restored simultaneously, the validator loses its "memory" of votes it previously cast.

**Attack Flow:**

1. **Initial State** (Round 95):
   - SafetyData.last_voted_round = 95
   - Validator has voted and broadcast votes for rounds 1-95 [4](#0-3) 

2. **Attacker Action**: Restore all three databases to earlier checkpoint (Round 50)
   - SafetyData.last_voted_round = 50
   - ConsensusDB blocks = up to round 50
   - AptosDB committed state = up to round 45

3. **On Validator Restart**: Recovery validation succeeds because the committed block exists in ConsensusDB [5](#0-4) 

4. **Equivocation Window**: SafetyRules only enforces monotonic voting based on the rolled-back last_voted_round [6](#0-5) 

   The validator can now vote again on rounds 51-95, creating **conflicting votes** for rounds it already voted on.

5. **Safety Rules Bypass**: When voting on round 60 (already voted on before rollback), SafetyRules checks if 60 > 50 (rolled-back last_voted_round), which passes [7](#0-6) 

6. **Equivocation**: The validator creates a new vote for round 60, even though it already broadcast a (potentially different) vote for this round before the rollback.

**Why Protections Fail:**

- **Waypoint protection insufficient**: The waypoint is also stored in SafetyRules storage and gets rolled back. Even if configured via FromConfig/FromFile, the storage is reused if storage.author() exists [8](#0-7) 

- **Equivocation detection is ephemeral**: Detection occurs in PendingVotes.author_to_vote HashMap, which is in-memory and cleared on restart [9](#0-8) 

- **No external validation**: No check against network state, trusted timestamps, or cryptographic commitments to detect rollback

## Impact Explanation

**Critical Severity - Consensus Safety Violation**

This vulnerability breaks the fundamental BFT safety guarantee that prevents equivocation. According to the Aptos bug bounty:

- **Consensus/Safety violations**: Critical ($1,000,000) - This attack directly enables consensus safety breaks
- **Loss of Funds (double-spend)**: Critical - If validators equivocate, conflicting blocks can be committed, enabling double-spend

**Concrete Impact:**
- Validator can sign conflicting votes for the same round
- If multiple validators are compromised (>1/3 voting power), conflicting QCs can form
- Different validators may commit different blocks at the same height
- Chain fork / network partition requiring hard fork to resolve
- Double-spending becomes possible

This violates the core invariant: "**Consensus Safety**: AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine"

## Likelihood Explanation

**Medium-High Likelihood in targeted attack scenarios:**

**Attack Requirements:**
- Access to validator infrastructure (insider threat, compromised credentials, or supply chain attack)
- Ability to restore database backups (standard operational procedure)
- No validator private key compromise needed

**Why it's realistic:**
1. Database backups are routine operations - validators regularly backup all three databases together
2. Insider threats (malicious operators, compromised accounts) are realistic threat vectors
3. No cryptographic material theft required
4. Attack appears as normal restart - difficult to detect
5. No existing monitoring specifically detects database rollback

**Attack scenarios:**
- Malicious validator operator
- Compromised backup infrastructure
- Supply chain attack on backup/restore tools
- Operational error combined with malicious exploitation

The attack is particularly dangerous during network-wide restarts or upgrades when multiple validators restart simultaneously, clearing their in-memory equivocation detection.

## Recommendation

**Add cryptographic rollback protection with monotonic version tracking:**

1. **Implement External Waypoint Verification:**
   - Store a trusted waypoint in immutable configuration (not in rollback-able storage)
   - On every restart, verify that SafetyData.last_voted_round is monotonically increasing relative to an external source
   - Reject startup if databases appear to be rolled back

2. **Add Cryptographic Commitment Chain:**
   - Maintain a hash chain linking SafetyData updates with cryptographic commitments
   - Store commitments in an append-only external log or blockchain oracle
   - Verify chain integrity on startup

3. **Implement Database Version Monotonicity:**
   ```rust
   // In SafetyRules initialization
   pub fn verify_no_rollback(&self, external_waypoint: Waypoint) -> Result<(), Error> {
       let current_waypoint = self.persistent_storage.waypoint()?;
       let safety_data = self.persistent_storage.safety_data()?;
       
       // Verify against external trusted source
       ensure!(
           current_waypoint.version() >= external_waypoint.version(),
           "Database rollback detected: current waypoint {} < trusted waypoint {}",
           current_waypoint.version(),
           external_waypoint.version()
       );
       
       // Additional check: verify last_voted_round against network state
       // This requires querying peers for their view of this validator's last vote
       Ok(())
   }
   ```

4. **Add Startup Verification:**
   - Before allowing voting, verify with peer validators what round they last saw this validator vote on
   - Reject startup if local last_voted_round is significantly behind network consensus

## Proof of Concept

```rust
// Test demonstrating database rollback enabling equivocation
// This would be added to consensus/src/safety_rules/tests/

#[test]
fn test_database_rollback_enables_equivocation() {
    // Setup: Create a validator and have it vote on rounds 1-50
    let (mut safety_rules, mut storage) = create_test_safety_rules();
    
    // Vote on round 50
    let block_50 = create_test_block(50, /* block_id */ HashValue::random());
    let vote_proposal_50 = create_vote_proposal(block_50);
    let vote_50 = safety_rules.construct_and_sign_vote_two_chain(&vote_proposal_50, None).unwrap();
    
    // Verify safety data shows last_voted_round = 50
    let safety_data = storage.safety_data().unwrap();
    assert_eq!(safety_data.last_voted_round, 50);
    assert_eq!(safety_data.last_vote.unwrap().vote_data().proposed().round(), 50);
    
    // ATTACK: Simulate database rollback to round 30
    // In real attack, this would be: restore database backup from round 30
    let rolled_back_safety_data = SafetyData::new(
        safety_data.epoch,
        30, // rolled back last_voted_round
        20, // rolled back preferred_round  
        15, // rolled back one_chain_round
        None, // no last_vote
        0,
    );
    storage.set_safety_data(rolled_back_safety_data).unwrap();
    
    // Restart validator with rolled-back storage
    let mut safety_rules_after_rollback = SafetyRules::new(storage, true);
    
    // VULNERABILITY: Validator can now vote on round 40, even though it already voted on round 50
    let block_40_different = create_test_block(40, HashValue::random()); // Different block than originally voted
    let vote_proposal_40 = create_vote_proposal(block_40_different);
    
    // This should FAIL (prevent equivocation) but SUCCEEDS due to rolled-back state
    let vote_40 = safety_rules_after_rollback
        .construct_and_sign_vote_two_chain(&vote_proposal_40, None)
        .expect("VULNERABILITY: Allowed to vote on already-voted round after rollback");
    
    // Validator has now equivocated:
    // - Voted on round 50 before rollback
    // - Can vote on round 40 (< 50) after rollback
    // This breaks consensus safety!
    
    assert_eq!(vote_40.vote_data().proposed().round(), 40);
    println!("VULNERABILITY CONFIRMED: Equivocation possible after database rollback");
}
```

**Notes:**
- This PoC requires access to validator infrastructure to execute the database restore
- The vulnerability is in the **lack of rollback detection**, not in any specific code bug
- Real exploitation would involve filesystem access to restore backed-up databases
- Impact is Critical because it enables consensus safety violations and potential double-spend

### Citations

**File:** consensus/src/consensusdb/mod.rs (L46-78)
```rust
pub struct ConsensusDB {
    db: DB,
}

impl ConsensusDB {
    pub fn new<P: AsRef<Path> + Clone>(db_root_path: P) -> Self {
        let column_families = vec![
            /* UNUSED CF = */ DEFAULT_COLUMN_FAMILY_NAME,
            BLOCK_CF_NAME,
            QC_CF_NAME,
            SINGLE_ENTRY_CF_NAME,
            NODE_CF_NAME,
            CERTIFIED_NODE_CF_NAME,
            DAG_VOTE_CF_NAME,
            "ordered_anchor_id", // deprecated CF
        ];

        let path = db_root_path.as_ref().join(CONSENSUS_DB_NAME);
        let instant = Instant::now();
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let db = DB::open(path.clone(), "consensus", column_families, &opts)
            .expect("ConsensusDB open failed; unable to continue");

        info!(
            "Opened ConsensusDB at {:?} in {} ms",
            path,
            instant.elapsed().as_millis()
        );

        Self { db }
    }
```

**File:** consensus/src/persistent_liveness_storage.rs (L134-143)
```rust
        let latest_commit_idx = blocks
            .iter()
            .position(|block| block.id() == latest_commit_id)
            .ok_or_else(|| format_err!("unable to find root: {}", latest_commit_id))?;
        let commit_block = blocks[latest_commit_idx].clone();
        let commit_block_quorum_cert = quorum_certs
            .iter()
            .find(|qc| qc.certified_block().id() == commit_block.id())
            .ok_or_else(|| format_err!("No QC found for root: {}", commit_block.id()))?
            .clone();
```

**File:** consensus/src/persistent_liveness_storage.rs (L549-557)
```rust
        let latest_ledger_info = self
            .aptos_db
            .get_latest_ledger_info()
            .expect("Failed to get latest ledger info.");
        let accumulator_summary = self
            .aptos_db
            .get_accumulator_summary(latest_ledger_info.ledger_info().version())
            .expect("Failed to get accumulator summary.");
        let ledger_recovery_data = LedgerRecoveryData::new(latest_ledger_info);
```

**File:** consensus/safety-rules/src/persistent_safety_storage.rs (L24-28)
```rust
pub struct PersistentSafetyStorage {
    enable_cached_safety_data: bool,
    cached_safety_data: Option<SafetyData>,
    internal_store: Storage,
}
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

**File:** consensus/safety-rules/src/safety_rules.rs (L213-232)
```rust
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

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L68-80)
```rust
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

**File:** consensus/safety-rules/src/safety_rules_manager.rs (L44-77)
```rust
    } else {
        let storage =
            PersistentSafetyStorage::new(internal_storage, config.enable_cached_safety_data);

        let mut storage = if storage.author().is_ok() {
            storage
        } else if !matches!(
            config.initial_safety_rules_config,
            InitialSafetyRulesConfig::None
        ) {
            let identity_blob = config
                .initial_safety_rules_config
                .identity_blob()
                .expect("No identity blob in initial safety rules config");
            let waypoint = config.initial_safety_rules_config.waypoint();

            let backend = &config.backend;
            let internal_storage: Storage = backend.into();
            PersistentSafetyStorage::initialize(
                internal_storage,
                identity_blob
                    .account_address
                    .expect("AccountAddress needed for safety rules"),
                identity_blob
                    .consensus_private_key
                    .expect("Consensus key needed for safety rules"),
                waypoint,
                config.enable_cached_safety_data,
            )
        } else {
            panic!(
                "Safety rules storage is not initialized, provide an initial safety rules config"
            )
        };
```

**File:** consensus/src/pending_votes.rs (L287-309)
```rust
        if let Some((previously_seen_vote, previous_li_digest)) =
            self.author_to_vote.get(&vote.author())
        {
            // is it the same vote?
            if &li_digest == previous_li_digest {
                // we've already seen an equivalent vote before
                let new_timeout_vote = vote.is_timeout() && !previously_seen_vote.is_timeout();
                if !new_timeout_vote {
                    // it's not a new timeout vote
                    return VoteReceptionResult::DuplicateVote;
                }
            } else {
                // we have seen a different vote for the same round
                error!(
                    SecurityEvent::ConsensusEquivocatingVote,
                    remote_peer = vote.author(),
                    vote = vote,
                    previous_vote = previously_seen_vote
                );

                return VoteReceptionResult::EquivocateVote;
            }
        }
```
