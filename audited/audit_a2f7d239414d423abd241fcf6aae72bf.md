# Audit Report

## Title
Filesystem Audit Log Information Disclosure Through Consensus State Persistence

## Summary
Validator nodes using on-disk secure storage leak consensus participation patterns and internal state through filesystem audit logs. Each consensus vote triggers observable filesystem operations that allow attackers with audit log access to infer validator activity, round progression, and operational status.

## Finding Description
The Aptos validator's SafetyRules component persists consensus state to disk on every vote and timeout operation. When using `OnDiskStorage` backend, this creates a predictable pattern of filesystem operations that are recorded in system audit logs (e.g., auditd on Linux).

The vulnerability manifests through the following execution path:

1. During consensus, `SafetyRules::guarded_construct_and_sign_vote_two_chain()` calls `self.persistent_storage.set_safety_data(safety_data)` after constructing each vote [1](#0-0) 

2. Similarly, `SafetyRules::guarded_sign_timeout_with_qc()` persists safety data after signing timeouts [2](#0-1) 

3. `PersistentSafetyStorage::set_safety_data()` calls `self.internal_store.set(SAFETY_DATA, data)` which triggers the underlying storage backend's write operation [3](#0-2) 

4. For `OnDiskStorage`, each write operation performs: temp file creation, write, and atomic rename [4](#0-3) 

These filesystem operations generate audit trail entries revealing:
- **Consensus participation frequency**: Number of writes per time period correlates with voting activity
- **Round progression timing**: Time intervals between writes reveal round durations  
- **Validator liveness**: Gaps in filesystem activity indicate node downtime
- **Configuration structure**: Paths accessed reveal data directory layout and storage backend type

An attacker with access to centralized logging infrastructure collecting audit logs from multiple validators can correlate these patterns to map consensus behavior across the network without requiring direct access to validator nodes.

## Impact Explanation
This is a **Low Severity** information disclosure vulnerability per the Aptos bug bounty criteria for "Minor information leaks." While the leaked information is operationally sensitive, it does not directly compromise:
- Cryptographic key material
- Consensus safety or liveness
- Fund security
- Validator integrity

The primary risk is operational intelligence gathering that could support more sophisticated attacks (e.g., timing attacks coordinated with validator downtime periods).

## Likelihood Explanation
**Likelihood: Low to Medium**

The attack requires:
- Access to filesystem audit logs (typically requires root privileges OR compromised centralized logging infrastructure)
- Continuous monitoring over extended periods to establish patterns
- Correlation across multiple validator audit trails for network-wide intelligence

However, realistic scenarios exist:
- **Centralized logging compromise**: Many organizations aggregate audit logs from multiple hosts into centralized SIEM systems. Compromise of the logging infrastructure provides audit access without direct validator access.
- **Partial privilege escalation**: An attacker with limited access to a validator host in the `audit` group can read logs without accessing the actual secure storage files.
- **Cloud environment monitoring**: Some cloud providers expose audit logs through monitoring APIs with different permission models than direct file access.

## Recommendation

Implement mitigation strategies to reduce filesystem audit trail visibility:

1. **Use in-memory caching more aggressively**: The code already supports `enable_cached_safety_data` [5](#0-4) , but writes still occur on every vote. Consider batching safety data writes or implementing a write-back cache.

2. **Implement write coalescing**: Buffer safety data updates and flush periodically rather than on every vote, reducing the correlation between votes and filesystem operations.

3. **Use memory-locked storage for mainnet validators**: The config sanitizer already enforces that mainnet validators should not use in-memory storage [6](#0-5) , but consider requiring Vault or HSM-backed storage that doesn't generate local filesystem audit trails.

4. **Obfuscate filesystem operation patterns**: Add random delays or dummy writes to break the direct correlation between consensus events and filesystem operations.

Example mitigation (write coalescing):
```rust
// In PersistentSafetyStorage
pub struct PersistentSafetyStorage {
    enable_cached_safety_data: bool,
    cached_safety_data: Option<SafetyData>,
    internal_store: Storage,
    pending_write: Arc<Mutex<Option<SafetyData>>>,
    flush_interval: Duration,
}

pub fn set_safety_data(&mut self, data: SafetyData) -> Result<(), Error> {
    // Update cache immediately
    self.cached_safety_data = Some(data.clone());
    
    // Queue write for batching
    *self.pending_write.lock().unwrap() = Some(data);
    
    // Periodic flush happens in background task
    Ok(())
}
```

## Proof of Concept

**Prerequisites:**
- Linux system with auditd enabled
- Aptos validator node using OnDiskStorage backend
- Root access to configure audit rules

**PoC Steps:**

1. Configure auditd to monitor the secure storage file:
```bash
auditctl -w /opt/aptos/data/secure_storage.json -p wa -k aptos_consensus
```

2. Monitor audit logs in real-time:
```bash
ausearch -k aptos_consensus -i --start recent | grep -E "open|write|rename"
```

3. Observe output pattern during active consensus:
```
type=SYSCALL ... syscall=open ... name=/opt/aptos/data/.temp_XXXX
type=SYSCALL ... syscall=write ... name=/opt/aptos/data/.temp_XXXX  
type=SYSCALL ... syscall=rename ... name=/opt/aptos/data/secure_storage.json
```

4. Correlation analysis:
    - Count events per minute → Voting frequency
    - Measure inter-event timing → Round duration
    - Detect gaps > 5 seconds → Node downtime/issues

This PoC demonstrates that an attacker with audit log access can extract validator operational telemetry without accessing the secure storage files themselves, confirming the information disclosure vulnerability.

## Notes

While this is a valid Low severity information disclosure issue, the practical security impact is limited because:
- Attackers with audit log access typically have broader system access
- The leaked information is operational state, not cryptographic secrets
- Mainnet validators should use Vault/HSM backends that reduce local filesystem footprint

The vulnerability is most concerning in environments with centralized audit log aggregation where compromise of the logging infrastructure provides visibility into multiple validators simultaneously.

### Citations

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L47-47)
```rust
        self.persistent_storage.set_safety_data(safety_data)?;
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L92-92)
```rust
        self.persistent_storage.set_safety_data(safety_data)?;
```

**File:** consensus/safety-rules/src/persistent_safety_storage.rs (L25-26)
```rust
    enable_cached_safety_data: bool,
    cached_safety_data: Option<SafetyData>,
```

**File:** consensus/safety-rules/src/persistent_safety_storage.rs (L160-160)
```rust
        match self.internal_store.set(SAFETY_DATA, data.clone()) {
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
