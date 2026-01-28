# Audit Report

## Title
Double Voting Vulnerability Due to Non-Durable Writes in ConsensusDB and SafetyRules Storage

## Summary
Both ConsensusDB and SafetyRules storage systems lack fsync operations when persisting vote data, allowing machine crashes to cause loss of voting records. This enables validators to double-vote on the same round after crash recovery, violating AptosBFT consensus safety guarantees and potentially leading to chain splits.

## Finding Description

The vulnerability exists in two critical storage systems that fail to provide durability guarantees for consensus safety-critical data:

**1. ConsensusDB Non-Durable Writes**

ConsensusDB's `commit()` function uses `write_schemas_relaxed()` which performs database writes without synchronization: [1](#0-0) 

The implementation explicitly documents that writes may be lost on machine crashes: [2](#0-1) 

**2. SafetyRules OnDiskStorage Lacks Fsync**

OnDiskStorage performs write-then-rename operations without fsync on either the file or parent directory: [3](#0-2) 

**Vote Persistence Flow**

When a validator votes on a block, SafetyRules first persists the vote through `set_safety_data()`: [4](#0-3) 

The persistent storage calls internal_store.set() which uses OnDiskStorage: [5](#0-4) 

Then, RoundManager persists the vote to ConsensusDB: [6](#0-5) 

This delegates to ConsensusDB.save_vote(): [7](#0-6) 

**SafetyRules Enforcement Mechanism**

SafetyRules enforces the "first voting rule" to prevent double voting through `verify_and_update_last_vote_round`: [8](#0-7) 

This is called during vote construction: [9](#0-8) 

The SafetyData structure contains the critical `last_voted_round` field: [10](#0-9) 

**Critical Gap: No Storage Synchronization**

During recovery, ConsensusDB data is loaded into RecoveryData: [11](#0-10) 

The recovered last_vote is passed to RoundManager initialization: [12](#0-11) [13](#0-12) 

RoundManager records it in round_state: [14](#0-13) 

However, SafetyRules loads its data independently from OnDiskStorage through the persistent_storage interface. There is **no code path that synchronizes SafetyRules storage from ConsensusDB recovery data**. This creates a critical vulnerability where the two storage systems can become inconsistent after a crash.

**Exploitation Scenario**

1. Validator votes on block B₁ in round R
2. SafetyRules persists `SafetyData{last_voted_round: R}` via OnDiskStorage.write() without fsync - data remains in OS buffer
3. RoundManager persists vote to ConsensusDB via write_schemas_relaxed() without fsync - data remains in OS buffer
4. Vote is broadcast to network (some validators receive it)
5. Machine crashes (power failure, kernel panic) before OS flushes buffers to disk
6. On recovery:
   - SafetyRules loads old SafetyData with `last_voted_round < R`
   - ConsensusDB may or may not have the vote (timing dependent)
   - RoundState initializes with recovered data from ConsensusDB only
7. Different block B₂ proposed for round R
8. SafetyRules checks: `R > last_voted_round` ✓ (passes because SafetyRules has stale data)
9. Validator votes on B₂ for round R and broadcasts
10. **Result: Double voting on round R** (two different votes broadcast for same round)

**Why Equivocation Detection Doesn't Prevent This**

While the network has equivocation detection in PendingVotes: [15](#0-14) 

This detection only rejects the second vote seen by each individual validator. Due to network asynchrony:
- Validator V₁ may receive vote(B₁) first and accept it, rejecting vote(B₂) as equivocation
- Validator V₂ may receive vote(B₂) first and accept it, rejecting vote(B₁) as equivocation
- Different validators end up counting different votes from the same author
- With multiple validators experiencing crashes and double-voting, different parts of the network can form conflicting QCs
- This directly violates BFT consensus safety guarantees

## Impact Explanation

**Severity: Critical**

This vulnerability qualifies for Critical severity under the Aptos Bug Bounty program category "Consensus/Safety Violations" because it breaks fundamental consensus safety guarantees:

1. **Consensus Safety Violation**: Validators can double-vote after machine crashes, violating the BFT assumption that fewer than 1/3 of validators behave Byzantine. The vulnerability allows honest validators to exhibit Byzantine behavior through operational failures.

2. **Potential Chain Splits**: If sufficient validators experience crashes and double-vote, different parts of the network can form conflicting quorum certificates for the same round, leading to chain splits that may require hard fork intervention.

3. **Loss of Funds**: Chain splits enable double-spending scenarios where transactions are valid on one fork but not another, leading to loss of user funds.

4. **Network Partition Risk**: Unlike recoverable liveness failures, consensus safety violations can create permanent network partitions requiring coordinated hard fork resolution.

The vulnerability affects the core consensus protocol and requires no Byzantine behavior - it is triggered by normal operational failures (machine crashes) that occur regularly in production deployments.

## Likelihood Explanation

**Likelihood: Medium-High**

The vulnerability has realistic likelihood in production environments:

1. **Common Trigger Condition**: Machine crashes occur regularly from power outages, hardware failures, OOM kills, kernel panics, and system updates. Validators experience such failures routinely.

2. **Substantial Timing Window**: OS buffer cache flush delays typically range from 5-30 seconds, providing a significant window where writes exist only in volatile memory. This is not a narrow race condition.

3. **Architectural Vulnerability**: The lack of fsync is architectural - ALL validators running the current codebase are vulnerable. This is explicitly documented in the code comments.

4. **Probability Amplification**: With dozens of validators in the active set, the probability that some validators experience this condition during any given epoch is substantial.

5. **No Active Exploitation Required**: The vulnerability is triggered by normal operational failures, not by active attack. It doesn't require adversarial behavior.

6. **Standard Fault Model**: Crash-recovery is an expected and common fault mode in distributed systems. BFT protocols must maintain safety guarantees even when validators crash and restart.

The combination of common triggering conditions, architectural vulnerability affecting all validators, and potential for multiple validators to experience concurrent crashes makes this a realistic threat to production deployments.

## Recommendation

Implement durable writes with fsync for safety-critical consensus data:

1. **For ConsensusDB**: Replace `write_schemas_relaxed()` with `write_schemas()` when persisting votes:
   - Modify `ConsensusDB::save_vote()` to use `write_schemas()` instead of the relaxed variant
   - Reference the durable write implementation at: [16](#0-15) 

2. **For SafetyRules OnDiskStorage**: Add fsync calls after file writes:
   - Call `file.sync_all()` or `file.sync_data()` after `file.write_all()` and before `fs::rename()`
   - Optionally fsync the parent directory after rename to ensure directory entry is persisted

3. **Synchronization Alternative**: If performance is critical, implement a mechanism to synchronize SafetyRules storage from ConsensusDB recovery data during startup to ensure consistency between the two storage systems.

## Proof of Concept

This vulnerability cannot be easily demonstrated with a simple code snippet as it requires:
1. Running multiple validator nodes
2. Forcing machine crashes (not process crashes) at precise timing windows
3. Observing network-level vote propagation and acceptance

However, the vulnerability can be validated by:
1. Inspecting the storage implementations to confirm lack of fsync (as cited above)
2. Tracing the code paths to verify no synchronization exists between SafetyRules and ConsensusDB
3. Understanding that the documented behavior (writes may be lost on machine crashes) directly enables double voting when both storage systems lose the same vote

The existence of this vulnerability is confirmed by the architectural design choices documented in the codebase itself.

## Notes

This vulnerability represents an architectural design choice where performance was prioritized over consensus safety guarantees. While the non-durable behavior is explicitly documented in code comments, the consequence—validators being able to double-vote after machine crashes—violates fundamental BFT consensus safety properties that production blockchains must maintain. The fact that the behavior is documented does not make it acceptable; rather, it acknowledges a critical security deficiency that should be addressed to ensure consensus safety under realistic operational failure scenarios.

### Citations

**File:** consensus/src/consensusdb/mod.rs (L156-159)
```rust
    fn commit(&self, batch: SchemaBatch) -> Result<(), DbError> {
        self.db.write_schemas_relaxed(batch)?;
        Ok(())
    }
```

**File:** storage/schemadb/src/lib.rs (L307-309)
```rust
    pub fn write_schemas(&self, batch: impl IntoRawBatch) -> DbResult<()> {
        self.write_schemas_inner(batch, &sync_write_option())
    }
```

**File:** storage/schemadb/src/lib.rs (L311-318)
```rust
    /// Writes without sync flag in write option.
    /// If this flag is false, and the machine crashes, some recent
    /// writes may be lost.  Note that if it is just the process that
    /// crashes (i.e., the machine does not reboot), no writes will be
    /// lost even if sync==false.
    pub fn write_schemas_relaxed(&self, batch: impl IntoRawBatch) -> DbResult<()> {
        self.write_schemas_inner(batch, &WriteOptions::default())
    }
```

**File:** secure/storage/src/on_disk.rs (L64-70)
```rust
    fn write(&self, data: &HashMap<String, Value>) -> Result<(), Error> {
        let contents = serde_json::to_vec(data)?;
        let mut file = File::create(self.temp_path.path())?;
        file.write_all(&contents)?;
        fs::rename(&self.temp_path, &self.file_path)?;
        Ok(())
    }
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L77-80)
```rust
        self.verify_and_update_last_vote_round(
            proposed_block.block_data().round(),
            &mut safety_data,
        )?;
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L91-92)
```rust
        safety_data.last_vote = Some(vote.clone());
        self.persistent_storage.set_safety_data(safety_data)?;
```

**File:** consensus/safety-rules/src/persistent_safety_storage.rs (L150-170)
```rust
    pub fn set_safety_data(&mut self, data: SafetyData) -> Result<(), Error> {
        let _timer = counters::start_timer("set", SAFETY_DATA);
        counters::set_state(counters::EPOCH, data.epoch as i64);
        counters::set_state(counters::LAST_VOTED_ROUND, data.last_voted_round as i64);
        counters::set_state(
            counters::HIGHEST_TIMEOUT_ROUND,
            data.highest_timeout_round as i64,
        );
        counters::set_state(counters::PREFERRED_ROUND, data.preferred_round as i64);

        match self.internal_store.set(SAFETY_DATA, data.clone()) {
            Ok(_) => {
                self.cached_safety_data = Some(data);
                Ok(())
            },
            Err(error) => {
                self.cached_safety_data = None;
                Err(Error::SecureStorageUnexpectedError(error.to_string()))
            },
        }
    }
```

**File:** consensus/src/round_manager.rs (L1539-1541)
```rust
        self.storage
            .save_vote(&vote)
            .context("[RoundManager] Fail to persist last vote")?;
```

**File:** consensus/src/round_manager.rs (L2018-2030)
```rust
    pub async fn init(&mut self, last_vote_sent: Option<Vote>) {
        let epoch_state = self.epoch_state.clone();
        let new_round_event = self
            .round_state
            .process_certificates(self.block_store.sync_info(), &epoch_state.verifier)
            .expect("Can not jump start a round_state from existing certificates.");
        if let Some(vote) = last_vote_sent {
            self.round_state.record_vote(vote);
        }
        if let Err(e) = self.process_new_round_event(new_round_event).await {
            warn!(error = ?e, "[RoundManager] Error during start");
        }
    }
```

**File:** consensus/src/persistent_liveness_storage.rs (L507-509)
```rust
    fn save_vote(&self, vote: &Vote) -> Result<()> {
        Ok(self.db.save_vote(bcs::to_bytes(vote)?)?)
    }
```

**File:** consensus/src/persistent_liveness_storage.rs (L519-596)
```rust
    fn start(&self, order_vote_enabled: bool, window_size: Option<u64>) -> LivenessStorageData {
        info!("Start consensus recovery.");
        let raw_data = self
            .db
            .get_data()
            .expect("unable to recover consensus data");

        let last_vote = raw_data
            .0
            .map(|bytes| bcs::from_bytes(&bytes[..]).expect("unable to deserialize last vote"));

        let highest_2chain_timeout_cert = raw_data.1.map(|b| {
            bcs::from_bytes(&b).expect("unable to deserialize highest 2-chain timeout cert")
        });
        let blocks = raw_data.2;
        let quorum_certs: Vec<_> = raw_data.3;
        let blocks_repr: Vec<String> = blocks.iter().map(|b| format!("\n\t{}", b)).collect();
        info!(
            "The following blocks were restored from ConsensusDB : {}",
            blocks_repr.concat()
        );
        let qc_repr: Vec<String> = quorum_certs
            .iter()
            .map(|qc| format!("\n\t{}", qc))
            .collect();
        info!(
            "The following quorum certs were restored from ConsensusDB: {}",
            qc_repr.concat()
        );
        // find the block corresponding to storage latest ledger info
        let latest_ledger_info = self
            .aptos_db
            .get_latest_ledger_info()
            .expect("Failed to get latest ledger info.");
        let accumulator_summary = self
            .aptos_db
            .get_accumulator_summary(latest_ledger_info.ledger_info().version())
            .expect("Failed to get accumulator summary.");
        let ledger_recovery_data = LedgerRecoveryData::new(latest_ledger_info);

        match RecoveryData::new(
            last_vote,
            ledger_recovery_data.clone(),
            blocks,
            accumulator_summary.into(),
            quorum_certs,
            highest_2chain_timeout_cert,
            order_vote_enabled,
            window_size,
        ) {
            Ok(mut initial_data) => {
                (self as &dyn PersistentLivenessStorage)
                    .prune_tree(initial_data.take_blocks_to_prune())
                    .expect("unable to prune dangling blocks during restart");
                if initial_data.last_vote.is_none() {
                    self.db
                        .delete_last_vote_msg()
                        .expect("unable to cleanup last vote");
                }
                if initial_data.highest_2chain_timeout_certificate.is_none() {
                    self.db
                        .delete_highest_2chain_timeout_certificate()
                        .expect("unable to cleanup highest 2-chain timeout cert");
                }
                info!(
                    "Starting up the consensus state machine with recovery data - [last_vote {}], [highest timeout certificate: {}]",
                    initial_data.last_vote.as_ref().map_or_else(|| "None".to_string(), |v| v.to_string()),
                    initial_data.highest_2chain_timeout_certificate().as_ref().map_or_else(|| "None".to_string(), |v| v.to_string()),
                );

                LivenessStorageData::FullRecoveryData(initial_data)
            },
            Err(e) => {
                error!(error = ?e, "Failed to construct recovery data");
                LivenessStorageData::PartialRecoveryData(ledger_recovery_data)
            },
        }
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

**File:** consensus/consensus-types/src/safety_data.rs (L10-21)
```rust
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

**File:** consensus/src/epoch_manager.rs (L886-886)
```rust
        let last_vote = recovery_data.last_vote();
```

**File:** consensus/src/epoch_manager.rs (L991-991)
```rust
        round_manager.init(last_vote).await;
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
