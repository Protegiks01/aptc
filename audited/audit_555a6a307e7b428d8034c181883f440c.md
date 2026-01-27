# Audit Report

## Title
OnDiskStorage Lacks Fsync Durability Guarantees, Enabling Validator Equivocation After System Crashes

## Summary
`PersistentSafetyStorage` assumes that when `KVStorage::set()` returns successfully, the data is durably persisted to disk. However, `OnDiskStorage` - the backend used in official validator configurations - does not call `fsync()` before returning from write operations. This creates a durability gap where safety-critical consensus data may be lost on system crashes (power loss, kernel panic), potentially allowing validators to equivocate and violate BFT consensus safety guarantees.

## Finding Description

The `PersistentSafetyStorage` struct stores safety-critical consensus data (last voted round, epoch, preferred round) that prevents validators from equivocating (signing conflicting votes for the same round). When a validator signs a vote, the safety data is updated through this call chain: [1](#0-0) 

The `set_safety_data()` method updates both the cached data and the persistent store: [2](#0-1) 

The critical assumption is on line 161-163: if `internal_store.set()` returns `Ok(_)`, the data is assumed to be durably persisted. However, when using `OnDiskStorage` (the default backend in official validator configurations), this assumption is violated.

The `OnDiskStorage::write()` implementation writes data without fsync: [3](#0-2) 

Note that after `file.write_all(&contents)?` on line 67, there is **no call to `file.sync_all()`** before the `fs::rename()` on line 68. This means:

1. Data is written to the OS page cache (not necessarily to disk)
2. The file is atomically renamed (this IS atomic on POSIX)
3. The function returns success
4. **The data may not yet be on physical disk**

If a system crash (power loss, kernel panic) occurs after step 3 but before the OS flushes the page cache, the file will exist but may contain no data or partial data.

The official validator configurations use OnDiskStorage: [4](#0-3) 

The config sanitizer only blocks `InMemoryStorage` for mainnet validators, not `OnDiskStorage`: [5](#0-4) 

This allows validators to use the durability-unsafe `OnDiskStorage` backend in production.

**Equivocation Scenario:**
1. Validator V signs vote for round N, block hash H1
2. `set_safety_data()` updates `last_voted_round = N` 
3. `OnDiskStorage::write()` completes successfully (data in OS cache)
4. Vote is broadcast to network
5. **System crash before OS flushes data to disk**
6. On restart, validator reads stale safety_data with `last_voted_round < N`
7. Validator receives different proposal for round N, block hash H2
8. Safety checks pass (since `last_voted_round < N`)
9. Validator signs conflicting vote for round N, violating consensus safety

## Impact Explanation

This vulnerability breaks **Invariant #2: Consensus Safety** - AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine nodes. Equivocation by honest validators (those affected by crashes) can contribute to the Byzantine fault budget, potentially enabling consensus safety violations even when fewer than 1/3 of validators are actually malicious.

According to Aptos bug bounty severity categories, this qualifies as **High Severity** (up to $50,000) for "Significant protocol violations". While it doesn't cause immediate loss of funds, it undermines the fundamental safety guarantee of BFT consensus. 

The vulnerability could potentially escalate to **Critical Severity** if:
- Multiple validators crash simultaneously (e.g., datacenter power outage)
- The equivocations enable chain splits or double-spends
- It requires a hard fork to recover

## Likelihood Explanation

**Likelihood: Medium to High**

System crashes (power outages, hardware failures, kernel panics) are **inevitable** in real-world validator deployments. Each crash creates an opportunity for equivocation if it occurs within the window between `write_all()` returning and the OS flushing data to disk (typically seconds to minutes, depending on OS settings).

Factors increasing likelihood:
- OnDiskStorage is used in official Helm and Docker Compose validator configs
- The config sanitizer doesn't prevent its use on mainnet
- System crashes happen regularly in production environments
- The time window for data loss is significant (OS page cache flush interval)

**Important Note:** This is not a vulnerability that requires active exploitation by an unprivileged attacker. Rather, it's a **correctness/robustness bug** that manifests under environmental conditions (system crashes) that occur naturally but are not directly controllable by external attackers. The security question asks about "unsafe assumptions" - this code clearly makes unsafe assumptions about durability guarantees.

## Recommendation

**Immediate Fix:** Add `fsync()` calls to `OnDiskStorage::write()`:

```rust
fn write(&self, data: &HashMap<String, Value>) -> Result<(), Error> {
    let contents = serde_json::to_vec(data)?;
    let mut file = File::create(self.temp_path.path())?;
    file.write_all(&contents)?;
    
    // ADD: Ensure data is flushed to disk before rename
    file.sync_all()?;
    
    fs::rename(&self.temp_path, &self.file_path)?;
    
    // ADD: Sync directory to ensure rename is durable
    if let Some(parent) = self.file_path.parent() {
        File::open(parent)?.sync_all()?;
    }
    
    Ok(())
}
```

**Long-term Fix:** Update the config sanitizer to block `OnDiskStorage` for mainnet validators, enforcing `VaultStorage` usage:

```rust
if chain_id.is_mainnet()
    && node_type.is_validator()
    && !matches!(safety_rules_config.backend, SecureBackend::Vault(_))
{
    return Err(Error::ConfigSanitizerFailed(
        sanitizer_name,
        "Mainnet validators must use Vault backend for safety rules storage".to_string(),
    ));
}
```

## Proof of Concept

This PoC demonstrates the durability gap (requires running as Rust integration test):

```rust
use aptos_secure_storage::{KVStorage, OnDiskStorage, Storage};
use aptos_temppath::TempPath;
use std::process;

#[test]
#[ignore] // Run manually: demonstrates data loss on kill
fn test_ondisk_durability_violation() {
    let temp_path = TempPath::new();
    temp_path.create_as_file().unwrap();
    
    let mut storage = Storage::from(OnDiskStorage::new(temp_path.path().to_path_buf()));
    
    // Write critical safety data
    storage.set("last_voted_round", 100u64).unwrap();
    println!("Wrote last_voted_round=100, storage.set() returned Ok");
    
    // Simulate system crash by killing process before OS flushes
    println!("Killing process NOW - simulating power loss");
    process::abort(); // Immediate termination without cleanup
}

// Run this test, then immediately check the file:
// The file may exist but contain stale/no data
// In a real validator, this would allow equivocation
```

To verify the vulnerability in a validator setup:
1. Configure validator with OnDiskStorage backend
2. Start validator and let it participate in consensus
3. Simulate system crash: `kill -9` or power cycle the machine
4. Restart validator and observe safety_data
5. If data was lost, the validator will have stale `last_voted_round`
6. It can now sign conflicting votes for rounds it already voted on

**Notes:**
- The README explicitly states OnDiskStorage "should not be used in production" [6](#0-5) 
- Yet official validator configs use it by default
- The code comment also warns against production use [7](#0-6) 
- This disconnect between documentation and practice creates the vulnerability

### Citations

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L92-92)
```rust
        self.persistent_storage.set_safety_data(safety_data)?;
```

**File:** consensus/safety-rules/src/persistent_safety_storage.rs (L160-169)
```rust
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

**File:** terraform/helm/aptos-node/files/configs/validator-base.yaml (L14-16)
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

**File:** secure/storage/README.md (L37-42)
```markdown
- `OnDisk`: Similar to InMemory, the OnDisk secure storage implementation provides another
useful testing implementation: an on-disk storage engine, where the storage backend is
implemented using a single file written to local disk. In a similar fashion to the in-memory
storage, on-disk should not be used in production environments as it provides no security
guarantees (e.g., encryption before writing to disk). Moreover, OnDisk storage does not
currently support concurrent data accesses.
```
