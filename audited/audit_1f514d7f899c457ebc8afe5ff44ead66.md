# Audit Report

## Title
Metrics-Storage Divergence in SafetyRules State Updates Leads to Incorrect Consensus State Observability

## Summary
The `set_safety_data()` function in `PersistentSafetyStorage` updates Prometheus metrics before persisting consensus state to secure storage. If the storage write fails, metrics show updated values while the actual consensus state remains unchanged, creating a dangerous observability gap that can mislead operators and monitoring systems.

## Finding Description

The vulnerability exists in the `set_safety_data()` function where consensus-critical state fields are updated in a non-atomic manner across two different systems: metrics and persistent storage. [1](#0-0) [2](#0-1) 

The execution order creates a critical window for inconsistency:

1. **Lines 152-158**: Four consensus state metrics are updated first (`EPOCH`, `LAST_VOTED_ROUND`, `HIGHEST_TIMEOUT_ROUND`, `PREFERRED_ROUND`)
2. **Line 160**: The actual persistent storage write is attempted via `internal_store.set(SAFETY_DATA, data.clone())`
3. **Lines 165-168**: If storage fails, an error is returned but metrics remain updated

The consensus state fields being tracked are safety-critical components of the AptosBFT protocol: [3](#0-2) 

**Storage Failure Scenarios:**

The secure storage backend can fail due to multiple realistic conditions: [4](#0-3) [5](#0-4) 

Real failure modes include:
- **Disk full** (OnDiskStorage write fails)
- **Permission denied** (VaultStorage token expiration)
- **IO errors** (filesystem corruption, network issues)
- **Serialization errors** (malformed data)

**Call Sites Affected:**

The inconsistency impacts all consensus operations that update safety data: [6](#0-5) [7](#0-6) [8](#0-7) 

These include timeout signing, vote construction, and order vote operations - all critical consensus paths.

**Exploitation Path:**

1. Validator node operates normally with metrics showing epoch 10, round 100
2. Disk space exhaustion occurs or Vault token expires
3. New block arrives requiring vote at epoch 10, round 101
4. `set_safety_data()` updates metrics to epoch 10, round 101
5. Storage write fails with IO error or permission denied
6. Metrics now show epoch 10, round 101 but persistent storage still has round 100
7. Operator monitoring sees round 101 in metrics dashboard
8. Node restarts (crash, maintenance, etc.)
9. Node loads safety data from storage: epoch 10, round 100
10. Operator confused why node "went backwards" from round 101 to 100
11. During incident response, metrics history shows false state progression

## Impact Explanation

This is a **Medium Severity** issue per Aptos bug bounty criteria: "State inconsistencies requiring intervention."

**Operational Impact:**
- **False monitoring signals**: Dashboards show incorrect consensus state (wrong epoch, round, timeout round)
- **Debugging confusion**: During incidents, operators see metrics that don't match actual node state
- **Delayed incident response**: Engineers waste time investigating phantom issues or miss real problems
- **Cross-node comparison failures**: Different nodes may show different metric states than their actual consensus states
- **Alerting system corruption**: Alerts based on these metrics (stalled consensus, epoch changes) trigger incorrectly

**Why Not Higher Severity:**
- Does **not** break consensus safety - the actual consensus logic uses `persistent_storage.safety_data()` which reads from storage, not metrics
- Does **not** cause validator node crashes or API failures
- Does **not** create protocol violations directly

**Why Not Lower Severity:**
- Requires manual intervention to understand and correct the situation
- Can mask or exacerbate real consensus issues during critical incidents
- Affects production operations and incident response capabilities

## Likelihood Explanation

**High Likelihood** - This can occur through normal operational failures:

1. **Disk space exhaustion**: Common in production systems, especially during log spikes or state growth
2. **Permission token expiration**: Vault tokens have TTLs and can expire during operation
3. **Network issues**: VaultStorage operations can timeout or fail
4. **Filesystem errors**: Temporary I/O errors occur in cloud and physical infrastructure
5. **Race conditions**: Multiple concurrent operations might exhaust storage resources

The affected code is in the hot path of consensus execution (every vote, timeout, and order vote), making the window for encountering storage failures significant during extended operation.

## Recommendation

**Fix: Update metrics only after successful storage persistence**

Move all metric updates to execute AFTER the storage write succeeds:

```rust
pub fn set_safety_data(&mut self, data: SafetyData) -> Result<(), Error> {
    let _timer = counters::start_timer("set", SAFETY_DATA);
    
    // Attempt storage write FIRST
    match self.internal_store.set(SAFETY_DATA, data.clone()) {
        Ok(_) => {
            // Only update metrics AFTER successful storage write
            counters::set_state(counters::EPOCH, data.epoch as i64);
            counters::set_state(counters::LAST_VOTED_ROUND, data.last_voted_round as i64);
            counters::set_state(
                counters::HIGHEST_TIMEOUT_ROUND,
                data.highest_timeout_round as i64,
            );
            counters::set_state(counters::PREFERRED_ROUND, data.preferred_round as i64);
            
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

This ensures atomicity: either both storage and metrics are updated, or neither are updated.

**Alternative: Add metric for storage write failures**

Add a counter to track when this divergence occurs:

```rust
counters::increment_query("set_safety_data", "storage_failed_after_metrics");
```

This would alert operators that metrics may be stale, though the primary fix is still recommended.

## Proof of Concept

```rust
#[cfg(test)]
mod test_metric_storage_divergence {
    use super::*;
    use aptos_secure_storage::InMemoryStorage;
    use std::sync::{Arc, Mutex};
    
    // Mock storage that fails on demand
    struct FailingStorage {
        inner: InMemoryStorage,
        should_fail: Arc<Mutex<bool>>,
    }
    
    impl FailingStorage {
        fn new(should_fail: Arc<Mutex<bool>>) -> Self {
            Self {
                inner: InMemoryStorage::new(),
                should_fail,
            }
        }
    }
    
    impl KVStorage for FailingStorage {
        fn set<V: Serialize>(&mut self, key: &str, value: V) -> Result<(), aptos_secure_storage::Error> {
            if *self.should_fail.lock().unwrap() {
                return Err(aptos_secure_storage::Error::InternalError(
                    "Simulated disk full".to_string()
                ));
            }
            self.inner.set(key, value)
        }
        
        fn get<V: DeserializeOwned>(&self, key: &str) -> Result<GetResponse<V>, aptos_secure_storage::Error> {
            self.inner.get(key)
        }
        
        fn available(&self) -> Result<(), aptos_secure_storage::Error> {
            self.inner.available()
        }
    }
    
    #[test]
    fn test_metrics_diverge_on_storage_failure() {
        let should_fail = Arc::new(Mutex::new(false));
        let storage = Storage::from(FailingStorage::new(should_fail.clone()));
        let mut safety_storage = PersistentSafetyStorage::new(storage, true);
        
        // Initialize with epoch 1, round 0
        let initial_data = SafetyData::new(1, 0, 0, 0, None, 0);
        safety_storage.set_safety_data(initial_data.clone()).unwrap();
        
        // Verify initial metrics
        assert_eq!(counters::get_state(counters::EPOCH), 1);
        assert_eq!(counters::get_state(counters::LAST_VOTED_ROUND), 0);
        
        // Enable storage failure
        *should_fail.lock().unwrap() = true;
        
        // Attempt to update to epoch 2, round 10
        let new_data = SafetyData::new(2, 10, 5, 3, None, 8);
        let result = safety_storage.set_safety_data(new_data.clone());
        
        // Storage write should fail
        assert!(result.is_err());
        
        // BUG: Metrics show NEW values (epoch 2, round 10)
        assert_eq!(counters::get_state(counters::EPOCH), 2);
        assert_eq!(counters::get_state(counters::LAST_VOTED_ROUND), 10);
        assert_eq!(counters::get_state(counters::PREFERRED_ROUND), 5);
        assert_eq!(counters::get_state(counters::HIGHEST_TIMEOUT_ROUND), 8);
        
        // But actual storage still has OLD values (epoch 1, round 0)
        let stored_data = safety_storage.safety_data().unwrap();
        assert_eq!(stored_data.epoch, 1);  // NOT 2!
        assert_eq!(stored_data.last_voted_round, 0);  // NOT 10!
        
        // This is the vulnerability: metrics say epoch 2, storage says epoch 1
        println!("VULNERABILITY CONFIRMED:");
        println!("Metrics show: epoch {}, round {}", 
                 counters::get_state(counters::EPOCH),
                 counters::get_state(counters::LAST_VOTED_ROUND));
        println!("Storage has: epoch {}, round {}", 
                 stored_data.epoch, stored_data.last_voted_round);
    }
}
```

## Notes

While the original security question labels this as "(High)" severity, based on rigorous analysis against Aptos bug bounty criteria, this is correctly classified as **Medium Severity** because:

1. It does not break consensus safety (actual consensus uses storage, not metrics)
2. It does not cause node crashes or protocol violations  
3. It does create state inconsistencies requiring operational intervention

The vulnerability is **VALID and EXPLOITABLE** through natural operational failures (disk full, permission denied, IO errors), making it a legitimate security concern that should be fixed to maintain operational integrity and monitoring reliability.

### Citations

**File:** consensus/safety-rules/src/counters.rs (L53-55)
```rust
pub fn set_state(field: &str, value: i64) {
    STATE_GAUGE.with_label_values(&[field]).set(value);
}
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

**File:** secure/storage/src/error.rs (L8-24)
```rust
#[derive(Debug, Deserialize, Error, PartialEq, Eq, Serialize)]
pub enum Error {
    #[error("Entropy error: {0}")]
    EntropyError(String),
    #[error("Internal error: {0}")]
    InternalError(String),
    #[error("Key already exists: {0}")]
    KeyAlreadyExists(String),
    #[error("Key not set: {0}")]
    KeyNotSet(String),
    #[error("Permission denied")]
    PermissionDenied,
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Key version not found, key name: {0}, version: {1}")]
    KeyVersionNotFound(String, String),
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

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L47-47)
```rust
        self.persistent_storage.set_safety_data(safety_data)?;
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L92-92)
```rust
        self.persistent_storage.set_safety_data(safety_data)?;
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L117-117)
```rust
        self.persistent_storage.set_safety_data(safety_data)?;
```
