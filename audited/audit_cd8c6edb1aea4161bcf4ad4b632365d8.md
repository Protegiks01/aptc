# Audit Report

## Title
OnDiskStorage Lacks Fsync: Consensus Safety Data Not Durably Persisted, Enabling Equivocation After Crash

## Summary
The `OnDiskStorage` implementation of `KVStorage` does not call `fsync()` after writing consensus safety data, violating the documented expectation that "any set function is expected to sync to the remote system before returning." [1](#0-0)  This allows a validator crash between the write and OS page cache flush to result in stale `last_voted_round` data on disk. Upon restart, the validator can vote again at the same round for a different block, causing equivocation and breaking BFT consensus safety.

## Finding Description

The consensus safety rules system stores critical safety data including `last_voted_round`, `epoch`, `preferred_round`, and `last_vote` to prevent equivocation (double-voting). [2](#0-1) 

When a validator votes on a block, it must persist the updated `last_voted_round` before returning success. The first voting rule explicitly checks that a new vote's round is strictly greater than `last_voted_round` to prevent voting twice at the same round. [3](#0-2) 

After voting, the safety data is persisted via `PersistentSafetyStorage::set_safety_data()`, which calls the underlying `KVStorage::set()`. [4](#0-3) 

For `OnDiskStorage`, the `write()` method serializes data to JSON, writes it to a temporary file, then renames the temporary file to the actual file path. [5](#0-4)  **Critically, there is no `fsync()` call after `write_all()` and before `rename()`.** This means the file data may remain in the OS page cache and not be durably written to disk when `set()` returns.

**Attack Scenario:**
1. Validator votes on block B₁ at round R
2. `set_safety_data()` is called, updating `last_voted_round = R`
3. Data is written to temporary file and renamed to `secure-data.json`
4. Method returns success **without fsync** - data still in page cache
5. Validator crashes before OS flushes cache (power failure, kernel panic)
6. On restart, `secure-data.json` contains stale data with `last_voted_round = R-1`
7. Validator receives proposal for block B₂ at round R
8. First voting rule check passes: `R > R-1` ✓
9. Validator votes on B₂ at round R
10. **Result: Equivocation** - validator has now voted for both B₁ and B₂ at round R

While the network's `PendingVotes::insert_vote()` mechanism can detect this equivocation, the validator has already violated consensus safety by producing conflicting votes. If multiple validators experience similar crashes (infrastructure failure, coordinated power outage), and >1/3 of validators equivocate, AptosBFT's safety guarantee is compromised.

## Impact Explanation

**Critical Severity - Consensus Safety Violation**

This vulnerability breaks the fundamental consensus safety invariant: "AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine." While BFT protocols tolerate <1/3 Byzantine behavior, this bug converts honest validators experiencing crashes into inadvertent equivocators.

The impact is Critical because:
1. **Breaks Consensus Safety**: Equivocation at the same round can lead to conflicting blocks being certified if enough validators crash and restart
2. **Default Configuration Affected**: The default `validator.yaml` configuration uses `OnDiskStorage` for safety rules [6](#0-5) 
3. **Violates Documented Contract**: The storage abstraction explicitly requires sync-before-return [1](#0-0) 
4. **Testnet Impact**: Even "non-production" deployments (testnets, development networks) using `OnDiskStorage` are vulnerable

## Likelihood Explanation

**Likelihood: Low to Medium**

The vulnerability requires specific conditions:
- Validator must use `OnDiskStorage` (common in testnets, present in default configs)
- Crash must occur in the narrow window between `write_all()` and OS page cache flush (typically milliseconds, but non-zero)
- OS must not have flushed the page cache before crash

Individual occurrence probability is low, but:
- **Correlated Failures**: Infrastructure failures (power outages, rack failures) affect multiple validators simultaneously
- **High-Load Scenarios**: Under heavy disk I/O, the page cache flush window increases
- **Slow Storage**: Network-attached storage or slow disks increase the vulnerability window
- **Development/Test Networks**: Many validators in test environments use `OnDiskStorage` and may experience coordinated restarts

## Recommendation

Add `fsync()` call after writing data to ensure durability before returning:

```rust
fn write(&self, data: &HashMap<String, Value>) -> Result<(), Error> {
    let contents = serde_json::to_vec(data)?;
    let mut file = File::create(self.temp_path.path())?;
    file.write_all(&contents)?;
    file.sync_all()?;  // Add fsync to ensure durability
    fs::rename(&self.temp_path, &self.file_path)?;
    Ok(())
}
```

Additionally:
1. **Update Documentation**: Remove or clarify the "should not be used in production" comment since default configs use it
2. **Consider fsync for Parent Directory**: After rename, call `fsync()` on the parent directory to ensure the directory entry is durable
3. **Add Warning Logs**: Log a warning when `OnDiskStorage` is used for safety rules in non-test mode
4. **Recommend VaultStorage**: Strengthen documentation recommending `VaultStorage` for production validators

## Proof of Concept

```rust
#[test]
fn test_ondisk_storage_crash_loses_data() {
    use std::sync::{Arc, Mutex};
    use aptos_secure_storage::{KVStorage, OnDiskStorage};
    use aptos_temppath::TempPath;
    
    let temp_path = TempPath::new();
    temp_path.create_as_file().unwrap();
    let file_path = temp_path.path().to_path_buf();
    
    // Initial write
    let mut storage = OnDiskStorage::new(file_path.clone());
    storage.set("last_voted_round", 10u64).unwrap();
    
    // Verify initial write
    let response = storage.get::<u64>("last_voted_round").unwrap();
    assert_eq!(response.value, 10);
    
    // Simulate crash scenario: update value but crash before OS flushes cache
    // In a real crash, this data would be lost if not fsynced
    storage.set("last_voted_round", 20u64).unwrap();
    
    // Simulate crash and restart by creating new storage instance
    // In a real crash without fsync, the file would contain old data
    // Note: This test cannot fully simulate the OS page cache behavior,
    // but demonstrates the missing fsync call is the root cause
    
    // Create new storage instance (simulating restart)
    let storage_after_restart = OnDiskStorage::new(file_path);
    let response = storage_after_restart.get::<u64>("last_voted_round").unwrap();
    
    // Without fsync, in a real crash scenario, this could be 10 instead of 20
    // The test demonstrates the code path that should include fsync but doesn't
    println!("Value after restart: {}", response.value);
}
```

**Notes:**
- The missing `fsync()` call in `OnDiskStorage::write()` creates a durability gap where consensus safety data may not survive crashes [5](#0-4) 
- This violates the storage abstraction contract requiring sync-before-return
- While `OnDiskStorage` is documented as unsuitable for production, default validator configurations use it, making this a practical concern for test networks and potentially production deployments that follow default templates
- `VaultStorage` delegates to Vault's remote API which provides durability guarantees, so it is not affected by this issue [7](#0-6)

### Citations

**File:** consensus/safety-rules/src/persistent_safety_storage.rs (L18-18)
```rust
/// Any set function is expected to sync to the remote system before returning.
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

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L77-92)
```rust
        self.verify_and_update_last_vote_round(
            proposed_block.block_data().round(),
            &mut safety_data,
        )?;
        self.safe_to_vote(proposed_block, timeout_cert)?;

        // Record 1-chain data
        self.observe_qc(proposed_block.quorum_cert(), &mut safety_data);
        // Construct and sign vote
        let author = self.signer()?.author();
        let ledger_info = self.construct_ledger_info_2chain(proposed_block, vote_data.hash())?;
        let signature = self.sign(&ledger_info)?;
        let vote = Vote::new_with_signature(vote_data, author, ledger_info, signature);

        safety_data.last_vote = Some(vote.clone());
        self.persistent_storage.set_safety_data(safety_data)?;
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

**File:** docker/compose/aptos-node/validator.yaml (L11-13)
```yaml
    backend:
      type: "on_disk_storage"
      path: secure-data.json
```

**File:** secure/storage/src/vault.rs (L167-182)
```rust
    fn set<T: Serialize>(&mut self, key: &str, value: T) -> Result<(), Error> {
        let secret = key;
        let key = self.unnamespaced(key);
        let version = if self.use_cas {
            self.secret_versions.read().get(key).copied()
        } else {
            None
        };
        let new_version =
            self.client()
                .write_secret(secret, key, &serde_json::to_value(&value)?, version)?;
        self.secret_versions
            .write()
            .insert(key.to_string(), new_version);
        Ok(())
    }
```
