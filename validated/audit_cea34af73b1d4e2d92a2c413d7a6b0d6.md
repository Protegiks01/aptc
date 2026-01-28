# Audit Report

## Title
ConsensusDB WAL Non-Durability Enables Double-Voting and Consensus Safety Violations

## Summary
The Aptos consensus system uses non-durable storage writes for critical safety state in both ConsensusDB and SafetyRules storage. When validators use OnDiskStorage backend (permitted by configuration sanitizer), machine crashes can cause permanent loss of voting state records, enabling double-voting in the same round for different blocks. This violates AptosBFT consensus safety guarantees and can cause chain splits.

## Finding Description

This vulnerability exists due to non-durable writes in two critical storage layers that maintain consensus safety state:

**1. ConsensusDB Non-Durability**

When a validator votes, ConsensusDB persists the vote using `save_vote()` which calls `commit()`. [1](#0-0) 

The `commit()` function uses `write_schemas_relaxed()` which explicitly does NOT sync to disk. [2](#0-1) 

This method's documentation explicitly warns: "If this flag is false, and the machine crashes, some recent writes may be lost." [3](#0-2) 

**2. SafetyRules OnDiskStorage Non-Durability**

SafetyRules stores safety-critical state (including `last_voted_round` and `last_vote`) via PersistentSafetyStorage, which can use OnDiskStorage backend. The OnDiskStorage implementation writes without fsync(). [4](#0-3) 

OnDiskStorage is explicitly documented as unsuitable for production: "This should not be used in production." [5](#0-4) 

**3. Configuration Vulnerability**

Despite documentation warnings, the configuration sanitizer ONLY blocks InMemoryStorage for mainnet validators, but permits OnDiskStorage. [6](#0-5) 

The `is_in_memory()` check only returns true for InMemoryStorage, not OnDiskStorage. [7](#0-6) 

Additionally, default validator configurations demonstrate OnDiskStorage usage. [8](#0-7) 

**4. Double-Voting Prevention Mechanism**

SafetyRules prevents double-voting via `verify_and_update_last_vote_round()` which checks that new vote rounds exceed the last voted round. [9](#0-8) 

This check is enforced during vote construction in `guarded_construct_and_sign_vote_two_chain()`. [10](#0-9) 

After voting, the updated SafetyData (including last_voted_round) is persisted via `set_safety_data()`. [11](#0-10) 

The persistence goes through PersistentSafetyStorage to the underlying storage backend. [12](#0-11) 

**Attack Scenario:**

1. Validator votes at round R for block B1
2. `guarded_construct_and_sign_vote_two_chain()` updates `safety_data.last_voted_round = R`
3. `set_safety_data()` persists to OnDiskStorage (no fsync)
4. ConsensusDB also saves vote via `write_schemas_relaxed()` (no sync)
5. Machine crashes before OS page cache flush (~30 second window)
6. On recovery, SafetyData loads from OnDiskStorage with stale last_voted_round
7. Recovery logic in RecoveryData filters ConsensusDB votes by epoch, but this doesn't affect SafetyRules' separate storage. [13](#0-12) 
8. SafetyRules initialization loads stale SafetyData, keeping old last_voted_round value. [14](#0-13) 
9. New proposal arrives for round R with different block B2
10. Double-voting check passes because `R > last_voted_round` (stale value)
11. Validator votes for B2 at round R
12. **Result: Validator has double-voted in round R for conflicting blocks**

## Impact Explanation

This is **CRITICAL severity** per Aptos Bug Bounty criteria under "Consensus/Safety Violations":

1. **Direct Consensus Safety Violation**: Enables a single validator to vote twice in the same round for different blocks after crash recovery, violating the fundamental no-double-voting invariant of AptosBFT consensus protocol.

2. **Chain Split Risk**: If multiple validators experience correlated crashes (regional power outage, datacenter failure, cloud infrastructure issues), multiple validators can simultaneously double-vote, potentially creating competing quorum certificates for different blocks at the same round, causing permanent chain divergence.

3. **Requires Hardfork**: A consensus safety violation with diverged committed state would require manual intervention or hardfork to resolve, as the blockchain cannot automatically recover from conflicting committed blocks with valid quorum certificates.

4. **Affects Production Deployments**: Despite OnDiskStorage being documented as "not for production," the sanitizer explicitly permits it for mainnet validators, and example configurations demonstrate its usage, meaning production validators may unknowingly deploy with this vulnerable configuration.

## Likelihood Explanation

**Likelihood: Medium**

**Triggering Conditions:**
- Requires machine crash (power failure, kernel panic, hardware failure) during the ~30 second OS page cache flush window after voting
- Must occur during same epoch (epoch transitions reset SafetyData)
- Multiple validators must crash for significant impact (chain split requiring hardfork)
- More likely during regional infrastructure failures or correlated events

**Mitigating Factors:**
- Production validators SHOULD use VaultStorage per documentation best practices
- Requires configuration error (deploying with OnDiskStorage despite warnings)
- Process crashes without machine reboot don't trigger the vulnerability (page cache survives)
- Single validator double-vote alone doesn't cause chain split

**Amplifying Factors:**
- Default configurations show OnDiskStorage usage, potentially misleading operators
- Sanitizer doesn't enforce VaultStorage requirement for mainnet
- High vote frequency (every round) increases exposure to vulnerability window
- Cloud infrastructure can experience correlated failures (availability zone outages)
- No runtime monitoring alerts operators of non-durable storage usage

## Recommendation

**Immediate Fixes:**

1. **Enforce durable writes in SafetyRules storage**: Modify OnDiskStorage to call `File::sync_all()` after writes:
   ```rust
   // In secure/storage/src/on_disk.rs
   fn write(&self, data: &HashMap<String, Value>) -> Result<(), Error> {
       let contents = serde_json::to_vec(data)?;
       let mut file = File::create(self.temp_path.path())?;
       file.write_all(&contents)?;
       file.sync_all()?; // ADD THIS LINE
       fs::rename(&self.temp_path, &self.file_path)?;
       Ok(())
   }
   ```

2. **Strengthen configuration sanitizer**: Block OnDiskStorage for mainnet validators:
   ```rust
   // In config/src/config/safety_rules_config.rs
   if chain_id.is_mainnet() && node_type.is_validator() {
       match &safety_rules_config.backend {
           SecureBackend::InMemoryStorage => return Err(/* existing error */),
           SecureBackend::OnDiskStorage(_) => {
               return Err(Error::ConfigSanitizerFailed(
                   sanitizer_name,
                   "OnDiskStorage should not be used for mainnet validators. Use Vault backend.".to_string(),
               ));
           },
           _ => {}
       }
   }
   ```

3. **Use sync writes in ConsensusDB**: Change `commit()` to use `write_schemas()` instead of `write_schemas_relaxed()` for safety-critical data like votes.

4. **Add runtime validation**: Include startup checks that verify durable storage backends are configured for mainnet validators.

## Proof of Concept

The vulnerability can be demonstrated through the following scenario:

1. Deploy validator with OnDiskStorage backend configuration (as shown in docker/compose/aptos-node/validator.yaml)
2. Participate in consensus, voting on block proposals
3. During voting window, force machine crash (e.g., `echo b > /proc/sysrq-trigger` or power interruption)
4. Restart validator node
5. Observe that SafetyData loaded has stale `last_voted_round` value
6. When presented with new proposal at previously voted round, double-voting check incorrectly passes
7. Validator produces second vote for same round

While a complete executable PoC requires a multi-node testnet with controlled crash scenarios, the vulnerability path is clearly demonstrated through the codebase analysis showing non-durable writes at critical consensus safety checkpoints.

## Notes

The separation of concerns between ConsensusDB (storing blocks/votes for recovery) and SafetyRules storage (enforcing safety invariants) is correct architectural design. However, both storage layers must guarantee durability for consensus safety. The vulnerability arises because:

1. SafetyRules' `last_voted_round` in SafetyData is the authoritative source for double-voting prevention
2. OnDiskStorage backend can lose recent updates on machine crashes
3. The configuration system permits this unsafe backend for production validators
4. Recovery logic correctly filters ConsensusDB data by epoch, but this doesn't protect SafetyRules' separate persistent state

This is a real vulnerability requiring immediate remediation through enforced durable writes and strengthened configuration validation.

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

**File:** config/src/config/secure_backend_config.rs (L45-48)
```rust
    /// Returns true iff the backend is in memory
    pub fn is_in_memory(&self) -> bool {
        matches!(self, SecureBackend::InMemoryStorage)
    }
```

**File:** docker/compose/aptos-node/validator.yaml (L11-14)
```yaml
    backend:
      type: "on_disk_storage"
      path: secure-data.json
      namespace: ~
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

**File:** consensus/safety-rules/src/safety_rules.rs (L283-309)
```rust
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

**File:** consensus/safety-rules/src/persistent_safety_storage.rs (L150-169)
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
```

**File:** consensus/src/persistent_liveness_storage.rs (L405-408)
```rust
            last_vote: match last_vote {
                Some(v) if v.epoch() == epoch => Some(v),
                _ => None,
            },
```
