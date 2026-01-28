# Audit Report

## Title
Vote Durability Failure Enables Consensus Safety Violation Through Equivocation After Machine Crash

## Summary
The Aptos consensus voting mechanism uses non-durable storage writes that can be lost during machine crashes, allowing validators to equivocate (vote twice for different blocks in the same round) after restart. This vulnerability violates BFT consensus safety guarantees when validators use OnDiskStorage for SafetyRules persistence.

## Finding Description

The vulnerability exists in the consensus voting persistence mechanism, which maintains vote data in two separate storage systems without durable write guarantees.

**Voting Flow:**

When `RoundManager::vote_block()` receives a proposal, it calls SafetyRules to create and sign a vote via `construct_and_sign_vote_two_chain()`. [1](#0-0) 

SafetyRules updates `safety_data.last_vote` and persists it via `set_safety_data()`. [2](#0-1) 

The vote is then persisted to ConsensusDB. [3](#0-2) 

**Critical Storage Durability Issues:**

ConsensusDB uses `write_schemas_relaxed()` which explicitly does NOT fsync to disk. [4](#0-3) 

The underlying storage layer confirms this lack of durability guarantee with explicit documentation stating "If this flag is false, and the machine crashes, some recent writes may be lost." [5](#0-4) 

When SafetyRules uses OnDiskStorage, it also lacks fsync. The `write()` method creates a temporary file, writes data, and renames without calling `sync_all()` or `sync_data()`. [6](#0-5) 

OnDiskStorage documentation explicitly states "This should not be used in production." [7](#0-6) 

**Production Configuration Analysis:**

Production deployment configurations use OnDiskStorage for SafetyRules. [8](#0-7) [9](#0-8) 

The configuration sanitizer for mainnet validators only prohibits InMemoryStorage but explicitly allows OnDiskStorage. [10](#0-9) 

**Equivocation Scenario After Machine Crash:**

During recovery, ConsensusDB attempts to load the last vote from storage. [11](#0-10) 

The recovery process sets `last_vote = None` when the data doesn't match the current epoch or is lost. [12](#0-11) 

If `last_vote` is None after recovery, it is explicitly deleted from storage. [13](#0-12) 

When receiving a different proposal for the same round, the duplicate vote check relies on `safety_data.last_vote` being present. [14](#0-13) 

The `verify_and_update_last_vote_round()` check compares against `safety_data.last_voted_round`, which may also be lost or stale after the crash. [15](#0-14) 

**Safety Guarantee Violation:**

This breaks the fundamental BFT consensus safety rule that honest validators never vote for two different blocks in the same round. The SafetyData structure that should prevent this contains the `last_vote` field that can be lost. [16](#0-15) 

While Aptos implements equivocation detection, this is reactive (detecting after the fact) rather than preventive. [17](#0-16) 

## Impact Explanation

**Severity: CRITICAL** (Consensus Safety Violation - aligns with Aptos Bug Bounty Critical category)

This vulnerability enables consensus safety violations that meet the Critical severity criteria defined in the Aptos Bug Bounty program:

1. **Consensus/Safety Violations**: Validators can vote twice for different blocks in the same round, exhibiting Byzantine behavior without malicious intent

2. **Chain Splits**: If different validators receive conflicting votes before/after the crash, they may form conflicting quorum certificates, leading to blockchain forks

3. **Double-Spending Potential**: Chain splits enable double-spending as different forks process different transaction histories

4. **BFT Assumption Violation**: The BFT safety guarantee assumes < 1/3 Byzantine validators. This bug allows honest validators to behave Byzantine-like due to infrastructure failures, effectively reducing the Byzantine fault tolerance threshold

5. **Network-Wide Impact**: Even a single validator experiencing this crash at critical timing can compromise consensus safety if it results in conflicting QCs

## Likelihood Explanation

**Likelihood: MEDIUM (for affected configurations)**

The likelihood assessment is configuration-dependent:

**Production Configuration Reality:**
Despite OnDiskStorage's documentation stating it should not be used in production, the official deployment configurations explicitly use it. Production mainnet validators may use more durable backends like VaultStorage (which provides better durability through external Vault servers), but the codebase configuration sanitizer explicitly allows OnDiskStorage for mainnet deployments.

**Triggering Conditions:**

1. **Machine crashes are realistic**: Power failures, kernel panics, hardware failures, and OOM kills occur regularly in infrastructure operations

2. **Timing window is significant**: The vulnerability window extends from write completion until OS buffer flush (potentially seconds, not just milliseconds)

3. **No preventive recovery mechanism**: The system lacks mechanisms to detect or recover from lost votes before creating new ones

4. **ConsensusDB always vulnerable**: Even with VaultStorage for SafetyRules, ConsensusDB uses non-durable writes, though SafetyRules' independent check provides a safety layer

## Recommendation

1. **Immediate Fix**: Modify ConsensusDB to use `write_schemas()` with fsync enabled instead of `write_schemas_relaxed()` for critical consensus data (votes, safety state)

2. **OnDiskStorage Enhancement**: Add fsync calls in OnDiskStorage's `write()` method:
   - Call `file.sync_all()` after `write_all()` and before `fs::rename()`
   - Optionally fsync the parent directory after rename to ensure directory entry persistence

3. **Configuration Enforcement**: Update the config sanitizer to warn or error when OnDiskStorage is used for mainnet validators, encouraging VaultStorage or other durable backends

4. **Recovery Mechanism**: Implement cross-validation during recovery - if SafetyRules storage and ConsensusDB disagree on last_vote, take the more conservative approach (higher round number)

5. **Documentation**: Clearly document the durability requirements for production validator deployments

## Proof of Concept

```rust
// This vulnerability can be demonstrated through the following scenario:
// 1. Validator votes for Block A in round 10
// 2. Vote is persisted to ConsensusDB (write_schemas_relaxed, no fsync)
// 3. Vote is persisted to OnDiskStorage (no fsync)
// 4. Machine crashes before OS buffer flush
// 5. On restart, both storage systems have lost the vote
// 6. Recovery process sets last_vote = None
// 7. Different proposal for round 10 (Block B) arrives
// 8. Duplicate vote check passes (last_vote is None)
// 9. verify_and_update_last_vote_round passes (last_voted_round was also lost)
// 10. Validator votes for Block B in round 10
// 11. EQUIVOCATION: Two votes for different blocks in same round

// Proof requires infrastructure-level testing:
// - Deploy validator with OnDiskStorage
// - Trigger vote creation
// - Force machine crash (power off, kill -9 with disk cache)
// - Restart and observe vote recreation for same round
```

## Notes

This vulnerability is particularly concerning because:

1. **Default Configuration Vulnerability**: The provided production deployment configurations use the vulnerable OnDiskStorage backend

2. **Sanitizer Gap**: The configuration sanitizer explicitly allows OnDiskStorage for mainnet, despite OnDiskStorage's own documentation warning against production use

3. **Double Storage Vulnerability**: Both ConsensusDB (always vulnerable via `write_schemas_relaxed`) and SafetyRules storage (when using OnDiskStorage) lack durability guarantees

4. **Honest Validator Byzantine Behavior**: This allows infrastructure failures to cause consensus safety violations without any malicious actor involvement

5. **Configuration Dependent**: The actual likelihood depends on whether production validators follow the example configurations (vulnerable) or use VaultStorage (more durable)

The existence of durable write operations (`write_schemas()` with `sync_write_option()`) in the codebase indicates the developers understand the need for fsync, but these are not used for consensus-critical vote persistence.

### Citations

**File:** consensus/src/round_manager.rs (L1520-1527)
```rust
        let vote_result = self.safety_rules.lock().construct_and_sign_vote_two_chain(
            &vote_proposal,
            self.block_store.highest_2chain_timeout_cert().as_deref(),
        );
        let vote = vote_result.context(format!(
            "[RoundManager] SafetyRules Rejected {}",
            block_arc.block()
        ))?;
```

**File:** consensus/src/round_manager.rs (L1539-1541)
```rust
        self.storage
            .save_vote(&vote)
            .context("[RoundManager] Fail to persist last vote")?;
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

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L91-92)
```rust
        safety_data.last_vote = Some(vote.clone());
        self.persistent_storage.set_safety_data(safety_data)?;
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

**File:** secure/storage/src/on_disk.rs (L64-69)
```rust
    fn write(&self, data: &HashMap<String, Value>) -> Result<(), Error> {
        let contents = serde_json::to_vec(data)?;
        let mut file = File::create(self.temp_path.path())?;
        file.write_all(&contents)?;
        fs::rename(&self.temp_path, &self.file_path)?;
        Ok(())
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

**File:** config/src/config/safety_rules_config.rs (L86-96)
```rust
            // Verify that the secure backend is appropriate for mainnet validators
            if chain_id.is_mainnet()
                && node_type.is_validator()
                && safety_rules_config.backend.is_in_memory()
            {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "The secure backend should not be set to in memory storage in mainnet!"
                        .to_string(),
                ));
            }
```

**File:** consensus/src/persistent_liveness_storage.rs (L405-408)
```rust
            last_vote: match last_vote {
                Some(v) if v.epoch() == epoch => Some(v),
                _ => None,
            },
```

**File:** consensus/src/persistent_liveness_storage.rs (L526-528)
```rust
        let last_vote = raw_data
            .0
            .map(|bytes| bcs::from_bytes(&bytes[..]).expect("unable to deserialize last vote"));
```

**File:** consensus/src/persistent_liveness_storage.rs (L573-577)
```rust
                if initial_data.last_vote.is_none() {
                    self.db
                        .delete_last_vote_msg()
                        .expect("unable to cleanup last vote");
                }
```

**File:** consensus/safety-rules/src/safety_rules.rs (L218-225)
```rust
        if round <= safety_data.last_voted_round {
            return Err(Error::IncorrectLastVotedRound(
                round,
                safety_data.last_voted_round,
            ));
        }

        safety_data.last_voted_round = round;
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

**File:** consensus/src/pending_votes.rs (L287-308)
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
```
