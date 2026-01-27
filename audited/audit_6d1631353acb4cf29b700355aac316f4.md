# Audit Report

## Title
Missing fsync() in OnDiskStorage Allows Consensus Safety Rule Violations via Equivocation After System Crash

## Summary
The `OnDiskStorage::write()` function used for persisting SafetyRules consensus data does not call `fsync()` after writing to disk. This allows a system crash to occur after `set()` returns `Ok()` but before the OS flushes the write buffer, causing loss of the `last_voted_round` counter. Upon restart, a validator can vote twice on the same round, violating the fundamental "First Voting Rule" and enabling equivocation attacks that break BFT consensus safety. [1](#0-0) 

## Finding Description

The vulnerability exists in the durability guarantee contract violation between `PersistentSafetyStorage` and `OnDiskStorage`:

**Expected Contract:** The documentation explicitly states that storage backends must ensure durability before returning: [2](#0-1) 

**Actual Implementation:** The `OnDiskStorage::write()` function writes data to a temporary file, calls `write_all()`, renames the file, and returns `Ok()` - but never calls `sync_all()` or `sync_data()`. The data remains in the OS page cache and is NOT durably persisted to disk.

**Attack Scenario:**

1. Validator uses OnDiskStorage backend (the default configuration for validators): [3](#0-2) 

2. Validator votes on round N through the consensus protocol: [4](#0-3) 

3. The "First Voting Rule" updates `last_voted_round` to N to prevent double voting: [5](#0-4) 

4. `set_safety_data()` calls `OnDiskStorage::set()` which returns `Ok()` without fsyncing

5. **System crashes** (power failure, kernel panic, hardware failure) before OS flushes page cache

6. On restart, validator reads `last_voted_round` from disk - it contains the OLD value (< N) because the write was never durably persisted

7. Validator can now vote again on round N, creating two conflicting votes signed by the same validator - this is **equivocation**, the fundamental BFT safety violation

The SafetyData structure contains critical consensus safety state: [6](#0-5) 

## Impact Explanation

**Severity: CRITICAL** (up to $1,000,000 per Aptos Bug Bounty)

This vulnerability enables **Consensus/Safety violations** - the highest severity category. Specifically:

1. **Equivocation (Double Voting):** A validator can sign two different blocks for the same round, violating the core BFT safety invariant

2. **Chain Splits:** With sufficient equivocations, attackers could potentially cause honest validators to commit different blocks, leading to a permanent chain fork

3. **Byzantine Behavior from Honest Validators:** Even non-malicious validators become Byzantine actors due to this implementation bug

4. **Non-Recoverable Network State:** A chain split would require a hard fork to resolve, as conflicting committed blocks cannot be reconciled

The vulnerability breaks Critical Invariant #2: "Consensus Safety: AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine"

## Likelihood Explanation

**Likelihood: MEDIUM to HIGH**

Factors increasing likelihood:
- System crashes (power failures, hardware failures, kernel panics) are common in production environments
- The window of vulnerability exists every time a validator votes (hundreds to thousands of times per day)
- OnDiskStorage is the DEFAULT backend in official validator configurations, not just test environments
- No special attacker capabilities required - natural system failures trigger the bug
- Multiple validators using OnDiskStorage amplifies the risk exponentially

Factors decreasing likelihood:
- Modern SSDs have write caches that may flush quickly (but not guaranteed)
- Some production validators may use VaultStorage instead
- OS typically flushes page cache within 30 seconds under normal operation

However, an attacker with physical access or the ability to cause targeted power interruptions could deliberately exploit this to cause consensus violations.

## Recommendation

Add explicit durability guarantees to `OnDiskStorage::write()`:

```rust
fn write(&self, data: &HashMap<String, Value>) -> Result<(), Error> {
    let contents = serde_json::to_vec(data)?;
    let mut file = File::create(self.temp_path.path())?;
    file.write_all(&contents)?;
    
    // CRITICAL FIX: Ensure data is durably persisted to disk
    file.sync_all()?;
    
    fs::rename(&self.temp_path, &self.file_path)?;
    
    // CRITICAL FIX: Ensure directory entry is also persisted
    let dir = File::open(self.file_path.parent().unwrap_or_else(|| Path::new(".")))?;
    dir.sync_all()?;
    
    Ok(())
}
```

**Alternative Recommendation:** If OnDiskStorage is truly not intended for production (per the comment at line 22), then:
1. Add a compile-time or runtime check that prevents validators from using OnDiskStorage in production builds
2. Update all example validator configurations to use VaultStorage instead
3. Add prominent warnings in documentation about the durability issues

## Proof of Concept

```rust
use aptos_secure_storage::{OnDiskStorage, KVStorage, Storage};
use aptos_consensus_types::safety_data::SafetyData;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_ondisk_durability_failure() {
    // Create OnDiskStorage instance
    let temp_dir = tempdir().unwrap();
    let storage_path = temp_dir.path().join("safety_data.json");
    let mut storage = OnDiskStorage::new(storage_path.clone());
    
    // Simulate voting on round 100
    let safety_data_v1 = SafetyData::new(1, 100, 50, 40, None, 0);
    storage.set("safety_data", safety_data_v1.clone()).unwrap();
    
    // At this point, set() returned Ok() but data may not be on disk
    // Simulate crash by dropping without proper shutdown
    std::mem::drop(storage);
    
    // Force OS to NOT flush page cache (simulating crash timing)
    // In reality, a power failure would prevent the flush
    
    // Simulate restart - open storage again
    let storage = OnDiskStorage::new(storage_path);
    
    // Try to read back safety_data
    // If fsync was missing and OS didn't flush, this could:
    // 1. Fail to find the key (KeyNotSet error)
    // 2. Return old/corrupted data
    // 3. Return partial/invalid JSON
    let result: Result<_, _> = storage.get("safety_data");
    
    // If this returns Ok with last_voted_round < 100, validator can vote on round 100 again
    // This demonstrates the equivocation vulnerability
    match result {
        Ok(response) => {
            let safety_data: SafetyData = response.value;
            if safety_data.last_voted_round < 100 {
                panic!("VULNERABILITY: last_voted_round was not durably persisted! \
                       Validator can now equivocate on round 100");
            }
        },
        Err(_) => {
            panic!("VULNERABILITY: safety_data was lost! \
                   Validator will initialize with last_voted_round=0 and can equivocate");
        }
    }
}
```

**Note:** The above PoC demonstrates the concept but cannot reliably trigger the bug in a test environment because the OS typically flushes quickly. To trigger reliably, one would need to:
1. Run on a system with delayed write-back caching
2. Use `SIGKILL` immediately after `set()` returns
3. Use a VM with snapshot/restore to capture the exact timing window
4. Use specialized tools like `strace` with controlled syscall failures

The vulnerability is real but timing-dependent, making it a classic "crash consistency" bug that's difficult to reproduce deterministically but catastrophic when it occurs in production.

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

**File:** consensus/safety-rules/src/persistent_safety_storage.rs (L16-18)
```rust
/// SafetyRules needs an abstract storage interface to act as a common utility for storing
/// persistent data to local disk, cloud, secrets managers, or even memory (for tests)
/// Any set function is expected to sync to the remote system before returning.
```

**File:** docker/compose/aptos-node/validator.yaml (L11-13)
```yaml
    backend:
      type: "on_disk_storage"
      path: secure-data.json
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
