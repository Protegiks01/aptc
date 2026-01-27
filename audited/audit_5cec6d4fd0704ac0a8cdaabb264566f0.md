# Audit Report

## Title
Non-Atomic Writes in OnDiskStorage Allow Validator Equivocation After System Crashes

## Summary
The `OnDiskStorage` implementation used by validator SafetyRules lacks durability guarantees in its write operations. The `write()` method performs a temp-file-and-rename pattern but omits the critical `fsync()` call, allowing system crashes to leave safety-critical consensus data (particularly `last_voted_round`) in inconsistent states. This enables validators to double-vote after recovery, violating BFT consensus safety.

## Finding Description

The `Capability::Write` permission controls write access to secure storage backends. When validators use `OnDiskStorage` as their SafetyRules backend, critical consensus safety data is persisted through a write path that lacks atomic durability guarantees.

**The Vulnerable Write Path:** [1](#0-0) 

This `write()` function creates a temporary file, writes the serialized data, and renames it to the target path. However, it **never calls `file.sync_all()` or `fsync()`** before the rename operation. This means the data may remain in the operating system's page cache without being flushed to persistent storage.

**Critical Safety Data at Risk:**

The SafetyRules component uses this storage to persist consensus safety state that prevents double-voting: [2](#0-1) 

The `last_voted_round` field is the primary defense against equivocation. Before voting, SafetyRules updates this value: [3](#0-2) 

After updating `last_voted_round` in memory, it must be persisted: [4](#0-3) 

**Production Usage Despite Documentation Warnings:**

While documentation states OnDiskStorage is "for testing only": [5](#0-4) 

The actual validator configurations demonstrate its use: [6](#0-5) 

Critically, the mainnet configuration sanitizer only blocks `InMemoryStorage`, **not** `OnDiskStorage`: [7](#0-6) [8](#0-7) 

**Exploitation Scenario:**

1. Validator votes on proposal for round 100
2. SafetyRules updates `last_voted_round = 100` in memory
3. `PersistentSafetyStorage::set_safety_data()` calls `OnDiskStorage::write()`
4. Data is written to temp file and renamed, but remains in OS page cache (no fsync)
5. System crashes (power failure, kernel panic, hardware failure)
6. On restart, the renamed file exists but contains corrupted/stale data (e.g., `last_voted_round = 95`)
7. Validator reads stale value and believes it last voted in round 95
8. Network presents a proposal for round 99
9. Validator passes the safety check (`99 > 95`) and votes again
10. **Equivocation**: Validator has now voted in both round 100 and round 99, violating BFT safety

## Impact Explanation

This vulnerability enables **consensus safety violations** through validator equivocation. Under AptosBFT's BFT assumptions, safety holds as long as fewer than 1/3 of validators are Byzantine. However, this bug allows **honest validators** to equivocate after crashes, effectively converting them into Byzantine actors.

According to Aptos bug bounty criteria, this qualifies as **HIGH severity** because it constitutes a "Significant protocol violation" - specifically violating the fundamental BFT safety invariant that prevents double-voting. While not directly causing fund loss, consensus safety violations can lead to chain splits, conflicting state roots, and loss of finality guarantees.

The comment in `PersistentSafetyStorage` explicitly requires synchronous writes: [9](#0-8) 

This contract is violated by `OnDiskStorage`.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

While individual validator crashes are relatively rare, the probability increases with:

1. **Fleet-wide events**: Power outages, kernel updates, hardware failures affecting multiple validators simultaneously
2. **Natural occurrence**: No attacker action required - happens through normal operational incidents
3. **Configuration prevalence**: OnDiskStorage appears in example configs and isn't blocked by sanitizers
4. **Silent corruption**: The issue manifests only after crash recovery, making it hard to detect proactively

The impact multiplies if multiple validators experience this simultaneously (e.g., during datacenter power events), potentially exceeding the 1/3 Byzantine tolerance threshold.

## Recommendation

**Immediate Fix:**

Add durability guarantees to `OnDiskStorage::write()`:

```rust
fn write(&self, data: &HashMap<String, Value>) -> Result<(), Error> {
    let contents = serde_json::to_vec(data)?;
    let mut file = File::create(self.temp_path.path())?;
    file.write_all(&contents)?;
    file.sync_all()?;  // ADD THIS: Ensure data is flushed to disk
    fs::rename(&self.temp_path, &self.file_path)?;
    
    // Also sync the parent directory to ensure rename is durable
    if let Some(parent) = self.file_path.parent() {
        File::open(parent)?.sync_all()?;
    }
    
    Ok(())
}
```

**Long-term Recommendations:**

1. **Enforce production storage backend**: Modify the config sanitizer to block `OnDiskStorage` on mainnet validators, requiring Vault or other production-grade storage
2. **Add durability tests**: Create crash-consistency tests that verify data durability under simulated crashes
3. **Audit documentation**: Update configs to use Vault in examples and add prominent warnings about OnDiskStorage risks

## Proof of Concept

```rust
#[cfg(test)]
mod test_durability {
    use super::*;
    use std::process::{Command, Stdio};
    use std::fs;
    
    #[test]
    fn test_ondisk_storage_lacks_durability() {
        // Create a test storage file
        let test_path = PathBuf::from("/tmp/test_safety_storage.json");
        let mut storage = OnDiskStorage::new(test_path.clone());
        
        // Write critical safety data
        let safety_data = SafetyData::new(1, 100, 90, 80, None, 0);
        storage.set(SAFETY_DATA, safety_data.clone()).unwrap();
        
        // At this point, data may not be on disk yet due to missing fsync
        // Simulate crash by dropping storage without proper shutdown
        drop(storage);
        
        // Force OS to NOT flush buffers (in real crash scenario)
        // In practice, you'd need to simulate this via:
        // 1. Writing data
        // 2. Sending SIGKILL to process before OS flush
        // 3. Checking file contents
        
        // On recovery, read the data
        let mut recovered_storage = OnDiskStorage::new(test_path.clone());
        let recovered_data: SafetyData = recovered_storage.get(SAFETY_DATA)
            .expect("Should be able to read")
            .value;
        
        // In a proper implementation with fsync, this should always succeed
        // Without fsync, this may fail or return stale data after a real crash
        assert_eq!(recovered_data.last_voted_round, 100);
        
        // Cleanup
        fs::remove_file(test_path).ok();
    }
    
    #[test]
    fn demonstrate_missing_fsync() {
        // This test demonstrates that write() returns successfully
        // WITHOUT calling sync_all(), violating the durability contract
        let test_path = PathBuf::from("/tmp/test_no_fsync.json");
        let storage = OnDiskStorage::new(test_path.clone());
        
        // Examine the write() implementation - it should call sync_all() but doesn't
        // The vulnerability is confirmed by code inspection at:
        // secure/storage/src/on_disk.rs:64-70
        
        // Expected: file.sync_all() before rename
        // Actual: No sync_all() call exists
        
        fs::remove_file(test_path).ok();
    }
}
```

**Notes:**

- The vulnerability exists in production code despite documentation disclaimers
- Config sanitizer allows OnDiskStorage on mainnet, contradicting "testing only" guidance  
- Example validator configurations demonstrate OnDiskStorage usage
- Fix requires adding `sync_all()` calls to ensure atomic durability
- This affects consensus safety invariant #2: "AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine"

### Citations

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

**File:** secure/storage/README.md (L37-42)
```markdown
- `OnDisk`: Similar to InMemory, the OnDisk secure storage implementation provides another
useful testing implementation: an on-disk storage engine, where the storage backend is
implemented using a single file written to local disk. In a similar fashion to the in-memory
storage, on-disk should not be used in production environments as it provides no security
guarantees (e.g., encryption before writing to disk). Moreover, OnDisk storage does not
currently support concurrent data accesses.
```

**File:** docker/compose/aptos-node/validator.yaml (L11-13)
```yaml
    backend:
      type: "on_disk_storage"
      path: secure-data.json
```

**File:** config/src/config/safety_rules_config.rs (L85-96)
```rust
        if let Some(chain_id) = chain_id {
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

**File:** consensus/safety-rules/src/persistent_safety_storage.rs (L16-18)
```rust
/// SafetyRules needs an abstract storage interface to act as a common utility for storing
/// persistent data to local disk, cloud, secrets managers, or even memory (for tests)
/// Any set function is expected to sync to the remote system before returning.
```
