# Audit Report

## Title
Crash Recovery SafetyData Tampering Enables Consensus Safety Violations via Unprotected Storage

## Summary
An attacker with filesystem access to a validator node can modify the persisted `SafetyData` structure during downtime, causing the validator to violate consensus safety rules after restart. The lack of integrity protection on `SafetyData` storage and absence of cross-validation during recovery enables attackers to roll back critical safety parameters like `last_voted_round`, allowing double-voting and equivocation that breaks AptosBFT consensus safety guarantees.

## Finding Description

The vulnerability exists in the crash recovery mechanism where `SafetyData` and voting state are persisted to independent storage locations without integrity validation or consistency checks between them.

**Two Independent Storage Locations:**

1. **SafetyData in Secure Storage** (via `PersistentSafetyStorage`): [1](#0-0) 

This structure stores consensus safety state including `last_voted_round`, which is persisted to secure storage (e.g., `OnDiskStorage` or `VaultStorage`) using the `SAFETY_DATA` constant as the key: [2](#0-1) 

2. **Last Vote in ConsensusDB** (via `PersistentLivenessStorage`): [3](#0-2) 

**Critical Gap - No Integrity Protection:**

The `OnDiskStorage` implementation provides no integrity checks on stored data: [4](#0-3) 

Data is simply serialized/deserialized as JSON with no HMAC, signature, or checksum verification.

**No Cross-Validation During Recovery:**

During crash recovery, `SafetyData` is loaded from secure storage: [5](#0-4) 

While `last_vote` is loaded separately from ConsensusDB: [6](#0-5) 

The epoch validation in `guarded_initialize` only resets `SafetyData` if the epoch changes: [7](#0-6) 

**Attack Exploitation:**

If an attacker modifies `SafetyData.last_voted_round` from 100 to 50 (keeping epoch unchanged), the system:
- Loads tampered `last_voted_round=50` into SafetyRules
- Loads correct `last_vote(round=100)` into RecoveryData
- **Never compares these values**
- Epoch validation passes (Ordering::Equal case, no reset)

When the validator receives a proposal for round 60: [8](#0-7) 

The check `60 > 50` passes, allowing the validator to vote on round 60 despite having already voted on rounds 51-100 before the crash. This is **double-voting**, a critical consensus safety violation.

## Impact Explanation

This vulnerability meets **Critical Severity** criteria under "Consensus/Safety violations":

- **Breaks Consensus Safety Invariant**: AptosBFT's safety guarantee that validators cannot equivocate (vote twice on same round or conflicting chains) is violated
- **Byzantine Behavior**: A compromised validator can create equivocating votes across rounds
- **Chain Split Risk**: If multiple validators are compromised, could enable chain splits or double-spend attacks
- **Undermines Trust**: Breaks the fundamental < 1/3 Byzantine fault tolerance assumption

The attack directly violates the documented critical invariant: "Consensus Safety: AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine."

## Likelihood Explanation

**Attack Requirements:**
- Filesystem access to validator node's secure storage location
- Validator downtime window for file modification
- Knowledge of storage format and SafetyData structure

**Realistic Attack Vectors:**
- Compromised validator node via malware or exploit
- Insider threat from operator with file access
- Supply chain attack on validator infrastructure
- Physical access to validator systems

**Likelihood Assessment: Medium-High**
- Validators are high-value targets actively targeted by attackers
- No detection mechanism for SafetyData tampering
- Modification persists silently across restarts
- Single compromised node can create Byzantine behavior

## Recommendation

Implement multi-layered integrity protection for SafetyData:

**1. Add HMAC/Signature to SafetyData:**
```rust
// In consensus/consensus-types/src/safety_data.rs
pub struct SafetyData {
    pub epoch: u64,
    pub last_voted_round: u64,
    pub preferred_round: u64,
    pub one_chain_round: u64,
    pub last_vote: Option<Vote>,
    pub highest_timeout_round: u64,
    // Add integrity field
    pub hmac: Option<HashValue>, // HMAC over all other fields
}
```

**2. Cross-Validate During Recovery:**
```rust
// In consensus/safety-rules/src/persistent_safety_storage.rs
pub fn safety_data(&mut self) -> Result<SafetyData, Error> {
    let safety_data = /* load from storage */;
    
    // Verify HMAC
    verify_safety_data_integrity(&safety_data)?;
    
    // Return validated data
    Ok(safety_data)
}
```

**3. Add Consistency Check in EpochManager:**
```rust
// In consensus/src/epoch_manager.rs, start_round_manager
// After loading both SafetyData and RecoveryData:
if let Some(last_vote) = recovery_data.last_vote() {
    let safety_data = safety_rules.consensus_state()?.safety_data();
    if last_vote.round() > safety_data.last_voted_round {
        warn!("SafetyData inconsistency detected - resetting to last_vote");
        // Reset SafetyData to match last_vote
    }
}
```

**4. Use Authenticated Storage Backend:**
- Implement authenticated encryption for sensitive data in secure storage
- Add version numbering and monotonic counters to detect rollback attacks

## Proof of Concept

```rust
// consensus/safety-rules/src/tests/safety_data_tampering_test.rs
#[test]
fn test_safety_data_tampering_allows_double_vote() {
    // Setup: Create validator with SafetyRules at epoch 1, round 100
    let consensus_key = ValidatorSigner::from_int(0).private_key().clone();
    let storage = Storage::from(InMemoryStorage::new());
    let mut safety_storage = PersistentSafetyStorage::initialize(
        storage.clone(),
        Author::random(),
        consensus_key,
        Waypoint::default(),
        true,
    );
    
    // Validator votes on round 100
    let safety_data = SafetyData::new(1, 100, 99, 100, None, 0);
    safety_storage.set_safety_data(safety_data.clone()).unwrap();
    
    // Simulate crash and attacker tampering with storage
    // Attacker reduces last_voted_round from 100 to 50
    let tampered_data = SafetyData::new(1, 50, 99, 100, None, 0);
    safety_storage.set_safety_data(tampered_data).unwrap();
    
    // Validator restarts and loads tampered data
    let mut safety_rules = SafetyRules::new(safety_storage, true);
    let loaded_data = safety_rules.persistent_storage.safety_data().unwrap();
    
    assert_eq!(loaded_data.last_voted_round, 50); // Tampered value loaded
    
    // Validator can now vote on round 60, despite having voted on round 100
    // This should fail but doesn't due to tampered last_voted_round
    let proposal_round = 60;
    let mut safety_data = loaded_data;
    
    // This check passes when it shouldn't
    let result = safety_rules.verify_and_update_last_vote_round(
        proposal_round,
        &mut safety_data
    );
    
    assert!(result.is_ok()); // VULNERABILITY: Should fail but passes
    assert_eq!(safety_data.last_voted_round, 60); // Double-vote enabled!
}
```

**Notes**

The vulnerability stems from treating filesystem/storage security as sufficient without protocol-level integrity protection. While secure storage backends (Vault) provide access control, they don't prevent malicious modification by privileged processes. Defense-in-depth requires cryptographic integrity verification at the protocol layer, independent of storage backend security assumptions.

This issue is particularly critical because SafetyData is the last line of defense preventing consensus safety violations - its integrity must be verifiable even under worst-case scenarios of storage compromise.

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

**File:** config/global-constants/src/lib.rs (L16-16)
```rust
pub const SAFETY_DATA: &str = "safety_data";
```

**File:** consensus/src/persistent_liveness_storage.rs (L507-509)
```rust
    fn save_vote(&self, vote: &Vote) -> Result<()> {
        Ok(self.db.save_vote(bcs::to_bytes(vote)?)?)
    }
```

**File:** consensus/src/persistent_liveness_storage.rs (L519-528)
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
```

**File:** secure/storage/src/on_disk.rs (L53-70)
```rust
    fn read(&self) -> Result<HashMap<String, Value>, Error> {
        let mut file = File::open(&self.file_path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        if contents.is_empty() {
            return Ok(HashMap::new());
        }
        let data = serde_json::from_str(&contents)?;
        Ok(data)
    }

    fn write(&self, data: &HashMap<String, Value>) -> Result<(), Error> {
        let contents = serde_json::to_vec(data)?;
        let mut file = File::create(self.temp_path.path())?;
        file.write_all(&contents)?;
        fs::rename(&self.temp_path, &self.file_path)?;
        Ok(())
    }
```

**File:** consensus/safety-rules/src/persistent_safety_storage.rs (L134-148)
```rust
    pub fn safety_data(&mut self) -> Result<SafetyData, Error> {
        if !self.enable_cached_safety_data {
            let _timer = counters::start_timer("get", SAFETY_DATA);
            return self.internal_store.get(SAFETY_DATA).map(|v| v.value)?;
        }

        if let Some(cached_safety_data) = self.cached_safety_data.clone() {
            Ok(cached_safety_data)
        } else {
            let _timer = counters::start_timer("get", SAFETY_DATA);
            let safety_data: SafetyData = self.internal_store.get(SAFETY_DATA).map(|v| v.value)?;
            self.cached_safety_data = Some(safety_data.clone());
            Ok(safety_data)
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

**File:** consensus/safety-rules/src/safety_rules.rs (L283-308)
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
```
