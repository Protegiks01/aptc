# Audit Report

## Title
Consensus Safety Violation via Version Downgrade: Loss of one_chain_round and highest_timeout_round Tracking

## Summary
A validator running newer consensus code can lose critical safety state (`one_chain_round` and `highest_timeout_round`) when downgraded to older code and then re-upgraded. This allows the validator to violate previously established consensus safety constraints, potentially enabling equivocation and consensus safety breaks.

## Finding Description

The `SafetyData` struct stores critical consensus safety state used by AptosBFT's 2-chain protocol. Two fields are essential for maintaining safety invariants: [1](#0-0) 

Both `one_chain_round` and `highest_timeout_round` are marked with `#[serde(default)]`, allowing backward compatibility with older code versions that lack these fields. The test demonstrates this upgrade path works: [2](#0-1) 

However, this creates a **downgrade vulnerability**. When SafetyData is persisted to storage via JSON serialization: [3](#0-2) 

**Attack Scenario:**

1. **Initial State**: Validator runs new code in epoch 10, round 100
   - `one_chain_round = 90` (highest 1-chain QC observed)
   - `highest_timeout_round = 85` (highest timeout signed)

2. **Downgrade**: Operator downgrades to old code (pre-2-chain version)
   - Old code has no `one_chain_round` or `highest_timeout_round` fields
   - Old code reads SafetyData from storage, ignoring unknown JSON fields
   - Old code processes some consensus messages, updates `last_voted_round`
   - Old code writes SafetyData back, **omitting the new fields**

3. **Re-upgrade**: Operator upgrades back to new code
   - New code reads SafetyData from storage
   - Missing fields default to 0 due to `#[serde(default)]`
   - Result: `one_chain_round = 0`, `highest_timeout_round = 0`
   - Epoch is still 10, but safety constraints are **reset**

**Consensus Safety Violation:**

The `safe_to_timeout` function enforces that timeout QC rounds must be at least `one_chain_round`: [4](#0-3) 

With `one_chain_round` reset to 0, the validator accepts timeouts with `qc_round < 90` that should be rejected. This violates the 2-chain safety rule: **"timeout.qc.round >= one_chain_round"**.

Similarly, `safe_for_order_vote` requires order vote rounds to exceed `highest_timeout_round`: [5](#0-4) 

With `highest_timeout_round` reset to 0, the validator can sign order votes for rounds ≤ 85 that were previously timed out. This violates the order vote safety rule.

The `observe_qc` function only prevents these fields from **decreasing during normal operation**: [6](#0-5) 

But there is **no validation** when SafetyData is loaded from storage to detect that these fields have been inappropriately reset within the same epoch.

## Impact Explanation

**Severity: High** (per Aptos Bug Bounty criteria: "Significant protocol violations")

This vulnerability enables a validator to violate AptosBFT consensus safety invariants:

1. **Equivocation Risk**: The validator can sign conflicting timeouts or votes that contradict its previous actions, potentially participating in double-voting scenarios.

2. **Safety Rule Bypass**: The validator bypasses the 2-chain safety rules designed to prevent consensus forks, specifically:
   - Timeout safety: Can timeout rounds with insufficient QC progress
   - Order vote safety: Can order blocks that were previously timed out

3. **Byzantine Behavior Without Fault**: A single honest validator operator's mistake (accidental downgrade-upgrade cycle) causes the validator to exhibit Byzantine behavior, weakening the network's < 1/3 Byzantine tolerance.

4. **Consensus Split Potential**: If multiple validators undergo this sequence during critical consensus moments, it could contribute to chain splits or liveness failures.

This breaks the **Consensus Safety** critical invariant: "AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine."

## Likelihood Explanation

**Likelihood: Medium**

**Required Conditions:**
- Validator operator must perform a version downgrade (new → old code)
- Old code must process and persist SafetyData
- Validator must be upgraded back to new code
- All within the same epoch

**Realistic Scenarios:**
1. **Rollback Operations**: During emergency rollbacks due to bugs, operators may downgrade validators
2. **Testing Procedures**: Operators testing version compatibility may cycle through versions
3. **Gradual Migrations**: During network upgrades, some validators may downgrade temporarily
4. **Compromised Infrastructure**: Attackers with infrastructure access could trigger downgrades

While requiring operator action, version downgrades are realistic operational scenarios. The lack of safeguards makes this exploitable whenever downgrades occur.

## Recommendation

**Immediate Fix: Add Version Field to SafetyData**

Add a version field to SafetyData to detect and prevent unsafe downgrades:

```rust
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize, Clone, Default)]
pub struct SafetyData {
    pub epoch: u64,
    pub last_voted_round: u64,
    pub preferred_round: u64,
    #[serde(default)]
    pub one_chain_round: u64,
    pub last_vote: Option<Vote>,
    #[serde(default)]
    pub highest_timeout_round: u64,
    #[serde(default = "default_safety_data_version")]
    pub version: u64, // NEW: Track SafetyData format version
}

fn default_safety_data_version() -> u64 { 2 }
```

**Validation on Load:**

Add validation in `PersistentSafetyStorage::safety_data()`:

```rust
pub fn safety_data(&mut self) -> Result<SafetyData, Error> {
    // ... existing code ...
    let safety_data: SafetyData = self.internal_store.get(SAFETY_DATA).map(|v| v.value)?;
    
    // Validate version and detect potential downgrade
    if safety_data.version < 2 {
        // Safety-critical fields may be missing - validate epoch transition
        if safety_data.epoch == self.current_epoch 
           && (safety_data.one_chain_round == 0 || safety_data.highest_timeout_round == 0) {
            return Err(Error::InternalError(
                "Unsafe downgrade detected: safety-critical fields reset within epoch".into()
            ));
        }
    }
    
    self.cached_safety_data = Some(safety_data.clone());
    Ok(safety_data)
}
```

**Alternative: Prevent Field Omission**

Remove `#[serde(default)]` and require explicit migration:

```rust
#[serde(default = "u64::default")] // Explicit default, but log warning
```

Add migration logic that explicitly handles the upgrade from old to new format with proper validation.

## Proof of Concept

```rust
#[test]
fn test_downgrade_attack_safety_violation() {
    use consensus_types::safety_data::SafetyData;
    use serde_json;

    // Simulate validator state in epoch 10 with safety constraints established
    let new_safety_data = SafetyData::new(
        10,    // epoch
        100,   // last_voted_round
        95,    // preferred_round
        90,    // one_chain_round - CRITICAL for safety
        None,  // last_vote
        85,    // highest_timeout_round - CRITICAL for safety
    );
    
    // Serialize to JSON (as OnDiskStorage does)
    let json_with_new_fields = serde_json::to_string(&new_safety_data).unwrap();
    println!("New code JSON: {}", json_with_new_fields);
    // Contains: "one_chain_round":90,"highest_timeout_round":85
    
    // Simulate OLD code struct (without new fields)
    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    struct OldSafetyData {
        pub epoch: u64,
        pub last_voted_round: u64,
        pub preferred_round: u64,
        pub last_vote: Option<consensus_types::vote::Vote>,
    }
    
    // Old code reads the data (ignores unknown fields due to serde's default behavior)
    let old_data: OldSafetyData = serde_json::from_str(&json_with_new_fields).unwrap();
    assert_eq!(old_data.epoch, 10); // Epoch preserved
    
    // Old code makes some updates (e.g., increments last_voted_round)
    let updated_old_data = OldSafetyData {
        epoch: 10,
        last_voted_round: 101, // Updated
        preferred_round: 95,
        last_vote: None,
    };
    
    // Old code writes back to storage - OMITS new fields!
    let json_from_old_code = serde_json::to_string(&updated_old_data).unwrap();
    println!("Old code JSON: {}", json_from_old_code);
    // Missing: one_chain_round and highest_timeout_round
    
    // New code reads the data back after re-upgrade
    let reloaded_new_data: SafetyData = serde_json::from_str(&json_from_old_code).unwrap();
    
    // VULNERABILITY: Safety-critical fields are reset!
    assert_eq!(reloaded_new_data.epoch, 10); // Same epoch
    assert_eq!(reloaded_new_data.last_voted_round, 101); // Updated by old code
    assert_eq!(reloaded_new_data.one_chain_round, 0); // RESET! Was 90
    assert_eq!(reloaded_new_data.highest_timeout_round, 0); // RESET! Was 85
    
    // IMPACT: Validator can now violate safety rules
    // - Can timeout with qc_round < 90 (previously forbidden)
    // - Can order vote for rounds <= 85 (previously timed out)
    println!("\n[VULNERABILITY DEMONSTRATED]");
    println!("Epoch: {} (unchanged)", reloaded_new_data.epoch);
    println!("one_chain_round: 90 → 0 (SAFETY VIOLATION)");
    println!("highest_timeout_round: 85 → 0 (SAFETY VIOLATION)");
    println!("Validator can now sign conflicting messages!");
}
```

**Notes:**

The vulnerability is real and exploitable during version downgrades. While it requires validator operator action rather than external attacker access, it represents a critical flaw in the consensus safety guarantees that should be hardened against operational errors. The system should maintain safety even when validators are downgraded and upgraded, not silently reset safety-critical state within an active epoch.

### Citations

**File:** consensus/consensus-types/src/safety_data.rs (L15-21)
```rust
    // highest 1-chain round, used for 2-chain
    #[serde(default)]
    pub one_chain_round: u64,
    pub last_vote: Option<Vote>,
    #[serde(default)]
    pub highest_timeout_round: u64,
}
```

**File:** consensus/consensus-types/src/safety_data.rs (L53-70)
```rust
#[test]
fn test_safety_data_upgrade() {
    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize, Clone, Default)]
    struct OldSafetyData {
        pub epoch: u64,
        pub last_voted_round: u64,
        pub preferred_round: u64,
        pub last_vote: Option<Vote>,
    }
    let old_data = OldSafetyData {
        epoch: 1,
        last_voted_round: 10,
        preferred_round: 100,
        last_vote: None,
    };
    let value = serde_json::to_value(old_data).unwrap();
    let _: SafetyData = serde_json::from_value(value).unwrap();
}
```

**File:** secure/storage/src/on_disk.rs (L85-93)
```rust
    fn set<V: Serialize>(&mut self, key: &str, value: V) -> Result<(), Error> {
        let now = self.time_service.now_secs();
        let mut data = self.read()?;
        data.insert(
            key.to_string(),
            serde_json::to_value(GetResponse::new(value, now))?,
        );
        self.write(&data)
    }
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L124-145)
```rust
    fn safe_to_timeout(
        &self,
        timeout: &TwoChainTimeout,
        maybe_tc: Option<&TwoChainTimeoutCertificate>,
        safety_data: &SafetyData,
    ) -> Result<(), Error> {
        let round = timeout.round();
        let qc_round = timeout.hqc_round();
        let tc_round = maybe_tc.map_or(0, |tc| tc.round());
        if (round == next_round(qc_round)? || round == next_round(tc_round)?)
            && qc_round >= safety_data.one_chain_round
        {
            Ok(())
        } else {
            Err(Error::NotSafeToTimeout(
                round,
                qc_round,
                tc_round,
                safety_data.one_chain_round,
            ))
        }
    }
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L168-178)
```rust
    fn safe_for_order_vote(&self, block: &Block, safety_data: &SafetyData) -> Result<(), Error> {
        let round = block.round();
        if round > safety_data.highest_timeout_round {
            Ok(())
        } else {
            Err(Error::NotSafeForOrderVote(
                round,
                safety_data.highest_timeout_round,
            ))
        }
    }
```

**File:** consensus/safety-rules/src/safety_rules.rs (L135-156)
```rust
    pub(crate) fn observe_qc(&self, qc: &QuorumCert, safety_data: &mut SafetyData) -> bool {
        let mut updated = false;
        let one_chain = qc.certified_block().round();
        let two_chain = qc.parent_block().round();
        if one_chain > safety_data.one_chain_round {
            safety_data.one_chain_round = one_chain;
            trace!(
                SafetyLogSchema::new(LogEntry::OneChainRound, LogEvent::Update)
                    .preferred_round(safety_data.one_chain_round)
            );
            updated = true;
        }
        if two_chain > safety_data.preferred_round {
            safety_data.preferred_round = two_chain;
            trace!(
                SafetyLogSchema::new(LogEntry::PreferredRound, LogEvent::Update)
                    .preferred_round(safety_data.preferred_round)
            );
            updated = true;
        }
        updated
    }
```
