# Audit Report

## Title
SafetyData Storage Layer Race Condition Enables Consensus Safety Violations via Concurrent Process Access

## Summary
The `OnDiskStorage` backend used for persisting `SafetyData` lacks atomic read-modify-write operations and file-level synchronization. If multiple validator processes access the same storage file concurrently, lost updates to safety-critical fields (`last_voted_round`, `preferred_round`, `last_vote`) can occur, potentially enabling double-voting and consensus safety violations.

## Finding Description

The `SafetyData` structure stores consensus safety state including `last_voted_round`, `preferred_round`, `one_chain_round`, `last_vote`, and `highest_timeout_round`. [1](#0-0) 

SafetyRules operations follow a read-modify-write pattern:
1. **READ**: Load current SafetyData via `persistent_storage.safety_data()` [2](#0-1) 
2. **MODIFY**: Update safety fields in memory [3](#0-2) 
3. **WRITE**: Persist updated SafetyData via `persistent_storage.set_safety_data()` [4](#0-3) 

For `OnDiskStorage`, the `set()` method performs non-atomic operations:
- Reads entire file contents into memory [5](#0-4) 
- Modifies data structure [6](#0-5)   
- Writes back to disk via temp file and rename [7](#0-6) 

**No file locking or atomic transaction guarantees exist**. The README explicitly documents: "OnDisk storage does not currently support concurrent data accesses." [8](#0-7) 

**Attack Scenario:**
1. Process A reads SafetyData (last_voted_round=10, preferred_round=8)
2. Process B reads SafetyData (last_voted_round=10, preferred_round=8)  
3. Process A votes on round 11, updates last_voted_round=11, writes to disk
4. Process B signs timeout for round 11, updates highest_timeout_round=11, writes to disk
5. **Process B's write overwrites A's changes**, reverting last_voted_round back to 10
6. Next voting operation sees last_voted_round=10, allowing double-vote on round 11

Production configurations use `OnDiskStorage` with `type: "on_disk_storage"` [9](#0-8) , and the config sanitizer only prohibits `InMemoryStorage` for mainnet validators, not `OnDiskStorage`. [10](#0-9) 

## Impact Explanation

This is a **Critical Severity** vulnerability that enables **Consensus Safety Violations**:

- **Double-voting**: A validator could sign multiple conflicting votes for the same round, violating BFT safety assumptions
- **Equivocation**: Lost updates to `last_vote` allow creating conflicting signed messages
- **Safety rule bypass**: Resetting `last_voted_round` circumvents the monotonicity check that prevents double-voting
- **Potential chain split**: If validators vote inconsistently due to corrupted safety state, network could fork

This meets Critical Severity criteria: "Consensus/Safety violations" that could cause "Non-recoverable network partition (requires hardfork)".

## Likelihood Explanation

**Likelihood: Medium to High** in real-world deployments due to:

1. **Restart races**: During validator restarts, if the old process hasn't fully terminated, both instances may access storage simultaneously
2. **Container orchestration**: Kubernetes/Docker may spawn multiple pods before detecting the old one terminated
3. **Manual intervention**: Operators debugging issues might start backup processes
4. **Automated failover**: High-availability setups might launch standby processes prematurely
5. **Configuration drift**: Multiple validators sharing NFS/network storage could access the same file

While the codebase has application-level locking (Mutex/RwLock), this only protects single-process access. The storage layer provides no independent protection against multi-process races.

## Recommendation

**Immediate Fix - Add File Locking to OnDiskStorage:**

```rust
use std::fs::{File, OpenOptions};
use fs2::FileExt; // Add fs2 crate dependency

pub struct OnDiskStorage {
    file_path: PathBuf,
    temp_path: TempPath,
    time_service: TimeService,
    lock_file: PathBuf,
}

fn set<V: Serialize>(&mut self, key: &str, value: V) -> Result<(), Error> {
    let lock_path = self.file_path.with_extension("lock");
    let lock_file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(&lock_path)?;
    
    // Acquire exclusive lock
    lock_file.lock_exclusive()?;
    
    let now = self.time_service.now_secs();
    let mut data = self.read()?;
    data.insert(
        key.to_string(),
        serde_json::to_value(GetResponse::new(value, now))?,
    );
    let result = self.write(&data);
    
    // Release lock
    lock_file.unlock()?;
    result
}
```

**Long-term Recommendations:**
1. **Deprecate OnDiskStorage for production**: Update config sanitizer to require VaultStorage for mainnet
2. **Add process detection**: Check for existing running instances before starting
3. **Enable CAS by default**: Ensure VaultStorage check-and-set is always enabled [11](#0-10) 

## Proof of Concept

```rust
// consensus/safety-rules/src/tests/concurrent_safety_data.rs
#[test]
fn test_concurrent_ondisk_lost_update() {
    use std::sync::{Arc, Barrier};
    use std::thread;
    
    let temp_dir = TempPath::new();
    let storage_path = temp_dir.path().join("safety.json");
    
    // Initialize storage with SafetyData
    let initial_data = SafetyData::new(1, 10, 8, 0, None, 0);
    {
        let mut storage = PersistentSafetyStorage::new(
            Storage::from(OnDiskStorage::new(storage_path.clone())),
            false
        );
        storage.set_safety_data(initial_data).unwrap();
    }
    
    let barrier = Arc::new(Barrier::new(2));
    let storage_path_clone = storage_path.clone();
    
    // Thread 1: Update last_voted_round
    let b1 = barrier.clone();
    let t1 = thread::spawn(move || {
        let mut storage = PersistentSafetyStorage::new(
            Storage::from(OnDiskStorage::new(storage_path)),
            false
        );
        b1.wait();
        let mut data = storage.safety_data().unwrap();
        thread::sleep(Duration::from_millis(10));
        data.last_voted_round = 11;
        storage.set_safety_data(data).unwrap();
    });
    
    // Thread 2: Update highest_timeout_round  
    let b2 = barrier.clone();
    let t2 = thread::spawn(move || {
        let mut storage = PersistentSafetyStorage::new(
            Storage::from(OnDiskStorage::new(storage_path_clone)),
            false
        );
        b2.wait();
        let mut data = storage.safety_data().unwrap();
        thread::sleep(Duration::from_millis(10));
        data.highest_timeout_round = 11;
        storage.set_safety_data(data).unwrap();
    });
    
    t1.join().unwrap();
    t2.join().unwrap();
    
    // Verify lost update
    let storage = PersistentSafetyStorage::new(
        Storage::from(OnDiskStorage::new(storage_path)),
        false
    );
    let final_data = storage.safety_data().unwrap();
    
    // One of the updates should be lost
    assert!(
        final_data.last_voted_round == 10 || final_data.highest_timeout_round == 0,
        "Lost update detected: last_voted_round={}, highest_timeout_round={}",
        final_data.last_voted_round,
        final_data.highest_timeout_round
    );
}
```

## Notes

While VaultStorage provides CAS (Check-And-Set) protection when enabled, the version tracking is per-instance in-memory state [12](#0-11) , meaning fresh instances starting concurrently could still conflict initially until CAS enforcement kicks in. The defense-in-depth principle requires storage-layer atomicity independent of application-level synchronization.

### Citations

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

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L66-66)
```rust
        let mut safety_data = self.persistent_storage.safety_data()?;
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L77-91)
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
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L92-92)
```rust
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

**File:** secure/storage/src/on_disk.rs (L85-87)
```rust
    fn set<V: Serialize>(&mut self, key: &str, value: V) -> Result<(), Error> {
        let now = self.time_service.now_secs();
        let mut data = self.read()?;
```

**File:** secure/storage/src/on_disk.rs (L88-91)
```rust
        data.insert(
            key.to_string(),
            serde_json::to_value(GetResponse::new(value, now))?,
        );
```

**File:** secure/storage/README.md (L41-42)
```markdown
guarantees (e.g., encryption before writing to disk). Moreover, OnDisk storage does not
currently support concurrent data accesses.
```

**File:** docker/compose/aptos-node/validator.yaml (L11-13)
```yaml
    backend:
      type: "on_disk_storage"
      path: secure-data.json
```

**File:** config/src/config/safety_rules_config.rs (L87-95)
```rust
            if chain_id.is_mainnet()
                && node_type.is_validator()
                && safety_rules_config.backend.is_in_memory()
            {
                return Err(Error::ConfigSanitizerFailed(
                    sanitizer_name,
                    "The secure backend should not be set to in memory storage in mainnet!"
                        .to_string(),
                ));
```

**File:** config/src/config/secure_backend_config.rs (L183-183)
```rust
                    config.disable_cas.map_or_else(|| true, |disable| !disable),
```

**File:** secure/storage/src/vault.rs (L170-174)
```rust
        let version = if self.use_cas {
            self.secret_versions.read().get(key).copied()
        } else {
            None
        };
```
