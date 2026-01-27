# Audit Report

## Title
Consensus Safety Data Loss Vulnerability via InMemoryStorage Configuration Bypass

## Summary
The `InMemoryStorage` implementation provides no persistence mechanism for critical consensus safety data. While a configuration sanitizer exists to prevent its use on mainnet validators, this protection can be bypassed by setting `skip_config_sanitizer: true` in the node configuration, enabling a validator operator to run with ephemeral storage. Upon process restart, all safety data is lost, allowing the validator to violate consensus voting rules and potentially double-vote, breaking the fundamental BFT safety guarantee.

## Finding Description

The `InMemoryStorage` struct stores all data purely in memory with no backup or recovery mechanism. [1](#0-0) 

This storage backend is used by `PersistentSafetyStorage` to store critical consensus safety data including:
- **SafetyData**: Contains `last_voted_round`, `preferred_round`, `one_chain_round`, and `highest_timeout_round` [2](#0-1) 
- **Consensus private keys**: Stored under `CONSENSUS_KEY`
- **Waypoint**: Critical for epoch verification
- **Owner account**: Validator author identity

The Aptos consensus README explicitly guarantees: "SafetyRules guarantees that the two voting rules are followed — even in the case of restart (since all safety data is persisted to local storage)." [3](#0-2) 

**The Protection Mechanism:**

A configuration sanitizer prevents mainnet validators from using `InMemoryStorage`: [4](#0-3) 

**The Bypass:**

However, this sanitizer can be completely bypassed: [5](#0-4) 

The `skip_config_sanitizer` flag is a legitimate configuration option that can be set in the YAML config file: [6](#0-5) 

**Attack Scenario:**

1. A validator operator (either maliciously or through misconfiguration) sets:
   ```yaml
   node_startup:
     skip_config_sanitizer: true
   consensus:
     safety_rules:
       backend:
         type: "in_memory_storage"
   ```

2. The validator runs normally, accumulating voting history in memory

3. Upon process restart (crash, upgrade, maintenance):
   - All `SafetyData` is lost
   - Storage re-initializes with `SafetyData::new(1, 0, 0, 0, None, 0)`, resetting `last_voted_round` to 0 [7](#0-6) 

4. The validator can now vote on rounds it previously voted on, as the first voting rule check passes: [8](#0-7) 

**Why This Breaks Consensus Safety:**

The voting rule at line 218 checks `if round <= safety_data.last_voted_round`. After restart with lost data, `last_voted_round` is 0, allowing the validator to vote on any round ≥ 1, including rounds it voted on before the restart. This violates the fundamental "First voting rule" that prevents double-voting.

## Impact Explanation

**Severity: CRITICAL** 

This vulnerability breaks **Consensus Safety** (Critical impact category per Aptos bug bounty):

1. **Direct Safety Violation**: Enables double-voting, violating the core BFT safety guarantee that "at most f votes are controlled by Byzantine validators"

2. **Chain Fork Risk**: If multiple validators exploit this (>f Byzantine validators), different honest validators could commit different blocks, causing an irrecoverable chain fork requiring a hard fork

3. **Double-Spend Potential**: Chain forks enable double-spending attacks

4. **Breaks Documented Invariant**: Violates Critical Invariant #2: "Consensus Safety: AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine"

5. **Persistence Guarantee Violation**: The consensus README explicitly states safety data persists across restarts, but `InMemoryStorage` breaks this guarantee

## Likelihood Explanation

**Likelihood: Medium to Low**

**Factors Reducing Likelihood:**
- Requires validator operator to actively bypass sanitizer
- Default configuration has `skip_config_sanitizer: false` [9](#0-8) 
- Production validator templates use `on_disk_storage` [10](#0-9) 

**Factors Increasing Likelihood:**
- The bypass mechanism is a documented configuration option, not hidden
- Validator operators may use it for "testing" or "debugging" and forget to disable it
- No runtime enforcement beyond the bypassable sanitizer
- Once bypassed, the failure mode is silent until restart occurs

**Realistic Scenarios:**
1. **Accidental Misconfiguration**: Operator copies test config to production
2. **Malicious Insider**: Compromised or malicious validator operator intentionally enables this
3. **Ignorance**: Operator doesn't understand the security implications

## Recommendation

**Primary Fix: Remove the Bypass Capability**

The `skip_config_sanitizer` option should not be available for production builds. Recommend:

1. **Make sanitizer mandatory for production**: Remove the bypass option or make it compile-time only (test builds)

2. **Runtime validation**: Add a secondary check in `PersistentSafetyStorage` initialization that refuses to operate with `InMemoryStorage` on non-test chains

3. **Explicit warning**: If the bypass must remain for debugging, add a startup warning that logs loudly when `skip_config_sanitizer: true` or when using `InMemoryStorage`

**Code Fix Example:**

In `config/src/config/safety_rules_config.rs`, add a non-bypassable check:
```rust
pub fn validate_storage_backend(backend: &SecureBackend, chain_id: ChainId) -> Result<(), Error> {
    if chain_id.is_mainnet() && backend.is_in_memory() {
        // This check cannot be bypassed
        return Err(Error::InvariantViolation(
            "InMemoryStorage is forbidden on mainnet - this is non-negotiable for consensus safety"
        ));
    }
    Ok(())
}
```

Call this from `PersistentSafetyStorage::initialize()` and `new()` to enforce at runtime regardless of sanitizer configuration.

## Proof of Concept

**Test Configuration (validator-unsafe.yaml):**
```yaml
node_startup:
  skip_config_sanitizer: true

base:
  role: validator
  waypoint:
    from_file: /opt/aptos/genesis/waypoint.txt

consensus:
  safety_rules:
    backend:
      type: "in_memory_storage"  # Vulnerability enabled
    service:
      type: "local"
    initial_safety_rules_config:
      from_file:
        waypoint:
          from_file: /opt/aptos/genesis/waypoint.txt
        identity_blob_path: /opt/aptos/genesis/validator-identity.yaml
```

**Exploitation Steps:**

1. Start validator with above config on mainnet
2. Participate in consensus normally for N rounds (e.g., rounds 1-100)
3. `SafetyData.last_voted_round = 100` is stored in memory only
4. Restart validator process
5. `SafetyData.last_voted_round` resets to 0
6. Validator receives proposal for round 50 (already voted on before restart)
7. Check at `verify_and_update_last_vote_round()` passes: `50 > 0` ✓
8. Validator votes again on round 50 → **Double vote achieved**
9. If coordinated with >f validators, can cause chain fork

**Expected Behavior vs Actual:**
- **Expected**: Validator refuses to vote on round 50 (already voted)
- **Actual**: Validator votes on round 50, violating consensus safety

## Notes

This vulnerability demonstrates a critical gap between design intent (persistent safety data) and configuration reality (bypassable enforcement). While the sanitizer correctly identifies the risk, its optional nature creates a security hole. The Aptos consensus model fundamentally assumes safety data persistence, making this configuration option incompatible with production deployments.

### Citations

**File:** secure/storage/src/in_memory.rs (L9-19)
```rust
/// InMemoryStorage represents a key value store that is purely in memory and intended for single
/// threads (or must be wrapped by a Arc<RwLock<>>). This provides no permission checks and simply
/// is a proof of concept to unblock building of applications without more complex data stores.
/// Internally, it retains all data, which means that it must make copies of all key material which
/// violates the code base. It violates it because the anticipation is that data stores would
/// securely handle key material. This should not be used in production.
#[derive(Default)]
pub struct InMemoryStorage {
    data: HashMap<String, Vec<u8>>,
    time_service: TimeService,
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

**File:** consensus/README.md (L46-46)
```markdown
* **SafetyRules** is responsible for the safety of the consensus protocol. It processes quorum certificates and LedgerInfo to learn about new commits and guarantees that the two voting rules are followed &mdash; even in the case of restart (since all safety data is persisted to local storage).
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

**File:** config/src/config/config_sanitizer.rs (L45-48)
```rust
        // If config sanitization is disabled, don't do anything!
        if node_config.node_startup.skip_config_sanitizer {
            return Ok(());
        }
```

**File:** config/src/config/node_startup_config.rs (L8-11)
```rust
pub struct NodeStartupConfig {
    pub skip_config_optimizer: bool, // Whether or not to skip the config optimizer at startup
    pub skip_config_sanitizer: bool, // Whether or not to skip the config sanitizer at startup
}
```

**File:** config/src/config/node_startup_config.rs (L17-19)
```rust
            skip_config_optimizer: false,
            skip_config_sanitizer: false,
        }
```

**File:** consensus/safety-rules/src/persistent_safety_storage.rs (L45-45)
```rust
        let safety_data = SafetyData::new(1, 0, 0, 0, None, 0);
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

**File:** terraform/helm/aptos-node/files/configs/validator-base.yaml (L14-16)
```yaml
    backend:
      type: "on_disk_storage"
      path: secure-data.json
```
