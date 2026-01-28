# Audit Report

## Title
Double Voting Vulnerability Due to Non-Durable Writes in ConsensusDB and SafetyRules Storage

## Summary
Both ConsensusDB and SafetyRules storage lack fsync operations when persisting vote data, allowing machine crashes to cause loss of voting records. This enables validators to double-vote on the same round after crash recovery, violating AptosBFT consensus safety guarantees.

## Finding Description

The vulnerability exists in two interconnected storage systems that fail to provide durability guarantees for consensus safety-critical data:

**1. ConsensusDB Relaxed Writes:**

The `commit()` function uses `write_schemas_relaxed()` which performs database writes without fsync: [1](#0-0) 

The implementation explicitly documents that writes may be lost on machine crashes: [2](#0-1) 

**2. SafetyRules OnDiskStorage Lacks Fsync:**

OnDiskStorage performs write-then-rename without fsync on either the file or parent directory, making writes non-durable: [3](#0-2) 

Critically, the code documentation explicitly warns this should not be used in production, yet production validators use it: [4](#0-3) 

**Vote Persistence Flow:**

When a validator votes on a block, two persistence operations occur:

First, SafetyRules persists the vote in SafetyData: [5](#0-4) 

Then, RoundManager persists the vote to ConsensusDB: [6](#0-5) 

Which calls the commit function with relaxed writes: [7](#0-6) 

**SafetyRules Enforcement:**

SafetyRules enforces the "first voting rule" to prevent double voting by checking last_voted_round: [8](#0-7) 

This check is performed during the voting process: [9](#0-8) 

The SafetyData structure contains the critical `last_voted_round` field: [10](#0-9) 

**Production Configuration:**

Production validators use OnDiskStorage: [11](#0-10) [12](#0-11) 

**Recovery Flow:**

On restart, the system attempts to recover persisted votes: [13](#0-12) 

The recovered vote is then recorded in RoundState: [14](#0-13) 

However, if both SafetyData and vote records were lost due to non-durable writes, the validator has no memory of having voted in round R.

**Exploitation Scenario:**

1. Validator votes on block B₁ in round R
2. SafetyRules persists `SafetyData{last_voted_round: R, last_vote: Vote(B₁, R)}` via OnDiskStorage.write() - no fsync, data in OS buffer
3. RoundManager persists vote to ConsensusDB via write_schemas_relaxed() - no fsync, data in OS buffer  
4. Machine crashes (power failure, kernel panic) before OS flushes buffers to disk
5. On recovery:
   - SafetyRules loads old SafetyData: `last_voted_round < R`
   - ConsensusDB.get_data() returns no vote for round R
   - RoundState has `vote_sent = None`
6. Different block B₂ ≠ B₁ proposed for round R
7. SafetyRules.verify_and_update_last_vote_round checks: `R > last_voted_round` ✓ (check passes incorrectly)
8. Validator votes on B₂ for round R
9. **Result: Double voting on round R** (voted for both B₁ and B₂)

This directly violates BFT consensus safety. With multiple validators experiencing this, the network can commit conflicting blocks, leading to chain splits.

## Impact Explanation

**Severity: Critical**

This vulnerability breaks the fundamental consensus safety guarantee of AptosBFT. According to the Aptos Bug Bounty program, "Consensus/Safety violations" qualify for Critical severity (up to $1,000,000).

Specific impacts:
- **Consensus Safety Violation**: Validators can double-vote, breaking the BFT assumption that ≥2/3 of validators are honest. Even a single validator double-voting can contribute to forming conflicting quorums.
- **Potential Chain Splits**: If sufficient validators double-vote after crashes, conflicting blocks can be finalized on different validator subsets, causing permanent chain divergence.
- **Loss of Funds**: Chain splits can lead to double-spending attacks and asset loss for users on the minority chain.
- **Network Partition**: May require emergency hard fork to resolve if safety is violated, causing significant network disruption.

The vulnerability violates the core BFT safety invariant: "No two honest validators vote for conflicting blocks in the same round." When crash-induced state loss causes a validator to forget its vote, it becomes effectively Byzantine from the protocol's perspective.

## Likelihood Explanation

**Likelihood: Medium-High**

While requiring a machine crash during a specific timing window, this is highly realistic in production:

1. **Crash Frequency**: Validators experience crashes from power outages, hardware failures, OOM kills, kernel panics, and OS updates. In a network with dozens of validators operating 24/7, such crashes occur regularly.

2. **Timing Window**: OS buffer cache flush delays are typically 5-30 seconds (configurable via `vm.dirty_expire_centisecs` on Linux). This provides a substantial vulnerability window after each vote where data exists only in volatile memory.

3. **Multiple Validators**: With dozens of validators, the probability that some subset experiences this race condition increases significantly. Even if the per-validator probability is low, the network-wide probability is much higher.

4. **No Mitigation**: The lack of fsync is architectural - ALL validators running standard configurations are vulnerable. There are no compensating controls or recovery mechanisms.

5. **Standard Fault Model**: Crash-recovery is an expected fault mode in distributed systems. The BFT literature assumes crash-recovery faults can occur, and consensus protocols must maintain safety across such events.

6. **Documented Warning Ignored**: The OnDiskStorage code explicitly warns "This should not be used in production" yet production configurations use it, indicating a deployment configuration issue that affects all validators.

The vulnerability doesn't require active exploitation - it's triggered by normal operational failures that occur in any large-scale deployment.

## Recommendation

Implement durable writes with proper fsync semantics for all consensus safety-critical data:

**For OnDiskStorage:**
```rust
fn write(&self, data: &HashMap<String, Value>) -> Result<(), Error> {
    let contents = serde_json::to_vec(data)?;
    let mut file = File::create(self.temp_path.path())?;
    file.write_all(&contents)?;
    file.sync_all()?; // ADD: Ensure data is flushed to disk
    fs::rename(&self.temp_path, &self.file_path)?;
    // Also sync parent directory to ensure rename is durable
    let parent = self.file_path.parent().ok_or(Error::...)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
```

**For ConsensusDB:**
Change `commit()` to use `write_schemas()` instead of `write_schemas_relaxed()`:
```rust
fn commit(&self, batch: SchemaBatch) -> Result<(), DbError> {
    self.db.write_schemas(batch)?; // Use synced writes
    Ok(())
}
```

**Alternative Migration Path:**
Replace OnDiskStorage with a proper secure storage backend (Vault, HSM, or database with durability guarantees) as the code comment suggests.

## Proof of Concept

This vulnerability can be demonstrated through crash injection testing:

1. Set up a test validator network
2. Instrument the code to vote on block B₁ at round R
3. After SafetyRules and ConsensusDB writes complete but before OS buffer flush (inject delay)
4. Trigger machine crash (e.g., `kill -9` or power cycle)
5. Restart validator
6. Observe that SafetyData shows `last_voted_round < R`
7. Propose different block B₂ at round R
8. Observe validator successfully votes on B₂
9. Network now has two votes from the same validator for different blocks at round R

The vulnerability can also be verified through code inspection of the write paths showing absence of fsync calls at critical persistence points.

## Notes

This is a **critical architectural vulnerability** affecting consensus safety. The issue is particularly concerning because:

1. The vulnerability affects ALL validators using standard production configurations
2. The code itself warns against using OnDiskStorage in production, yet production configs use it
3. Both persistence paths (SafetyRules and ConsensusDB) lack durability guarantees
4. The BFT safety assumption depends on validators not double-voting, which this bug violates

The fix requires careful coordination as it may impact consensus performance, but safety must take precedence over performance in BFT systems. Consider implementing this fix as a high-priority security patch.

### Citations

**File:** consensus/src/consensusdb/mod.rs (L115-119)
```rust
    pub fn save_vote(&self, last_vote: Vec<u8>) -> Result<(), DbError> {
        let mut batch = SchemaBatch::new();
        batch.put::<SingleEntrySchema>(&SingleEntryKey::LastVote, &last_vote)?;
        self.commit(batch)
    }
```

**File:** consensus/src/consensusdb/mod.rs (L156-159)
```rust
    fn commit(&self, batch: SchemaBatch) -> Result<(), DbError> {
        self.db.write_schemas_relaxed(batch)?;
        Ok(())
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

**File:** secure/storage/src/on_disk.rs (L16-22)
```rust
/// OnDiskStorage represents a key value store that is persisted to the local filesystem and is
/// intended for single threads (or must be wrapped by a Arc<RwLock<>>). This provides no permission
/// checks and simply offers a proof of concept to unblock building of applications without more
/// complex data stores. Internally, it reads and writes all data to a file, which means that it
/// must make copies of all key material which violates the code base. It violates it because
/// the anticipation is that data stores would securely handle key material. This should not be used
/// in production.
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

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L76-80)
```rust
        // Two voting rules
        self.verify_and_update_last_vote_round(
            proposed_block.block_data().round(),
            &mut safety_data,
        )?;
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

**File:** docker/compose/aptos-node/validator.yaml (L11-13)
```yaml
    backend:
      type: "on_disk_storage"
      path: secure-data.json
```

**File:** terraform/helm/aptos-node/files/configs/validator-base.yaml (L14-16)
```yaml
    backend:
      type: "on_disk_storage"
      path: secure-data.json
```

**File:** consensus/src/persistent_liveness_storage.rs (L519-547)
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
```
