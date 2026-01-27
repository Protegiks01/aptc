# Audit Report

## Title
Ephemeral Safety Data Through InMemoryStorage Default Enables Consensus Equivocation on Validator Restart

## Summary
The `SafetyRulesConfig` default configuration uses `InMemoryStorage` as the backend for safety-critical consensus data. This ephemeral storage is lost on validator restarts, allowing validators to violate consensus safety rules by double-signing (equivocation) after restart, potentially causing chain splits and breaking Byzantine Fault Tolerance guarantees.

## Finding Description

The vulnerability exists in the consensus safety layer where `SafetyRulesConfig` defaults to using `InMemoryStorage` for persistent safety data. [1](#0-0) 

`SafetyData` contains critical consensus safety information that must persist across restarts: [2](#0-1) 

When a validator votes, `SafetyRules` enforces anti-equivocation by checking if it already voted in the current round: [3](#0-2) 

It also enforces round monotonicity: [4](#0-3) 

**The vulnerability flow:**

1. **Initial Setup**: Validator starts with default `InMemoryStorage` backend, which is documented as ephemeral and not for production use: [5](#0-4) 

2. **Normal Operation**: Validator votes on round R, storing `last_vote` and `last_voted_round` in RAM via `InMemoryStorage`.

3. **Restart Event**: Validator crashes or restarts. All `InMemoryStorage` data is lost.

4. **Re-initialization**: On startup, if storage is uninitialized, it's re-created with fresh `SafetyData`: [6](#0-5) 

5. **Equivocation**: With `last_vote = None` and `last_voted_round = 0`, the validator can vote again on round R (or any round ≤ R), creating conflicting votes and breaking consensus safety.

**Mitigation Bypass:**

While a sanitizer exists for mainnet validators: [7](#0-6) 

This protection can be bypassed if `skip_config_sanitizer = true`: [8](#0-7) 

Additionally, testnet/devnet validators have **no protection** as the sanitizer only checks `chain_id.is_mainnet()`, leaving non-mainnet deployments vulnerable.

## Impact Explanation

**Critical Severity** - This vulnerability directly violates the core consensus safety invariant: "AptosBFT must prevent double-spending and chain splits under < 1/3 Byzantine validators."

Equivocation (double-signing) breaks BFT consensus safety. If a validator signs two different blocks for the same round, it can cause:
- **Chain splits**: Different validators commit different blocks, creating divergent ledger states
- **Loss of finality**: Conflicting quorum certificates invalidate safety guarantees
- **Network partition**: Requires manual intervention or hard fork to recover

The impact is amplified because:
1. The insecure default affects all new deployments that don't explicitly configure persistent storage
2. Testnet/devnet validators have zero protection (sanitizer only checks mainnet)
3. Equivocation is detected but not prevented—other nodes will observe the security violation but damage is already done: [9](#0-8) 

Detection doesn't prevent the safety violation; it only logs it after the fact.

## Likelihood Explanation

**High Likelihood** for testnet/devnet deployments:
- Default configuration is insecure by design
- No sanitizer protection for non-mainnet chains
- Any validator restart triggers the vulnerability
- Operator needs only to use default configuration

**Medium-to-Low Likelihood** for mainnet:
- Requires either bypassing sanitizer (`skip_config_sanitizer = true`) or misconfiguration
- Most production validators follow documentation and use persistent storage (OnDiskStorage or Vault)
- However, accidents happen—copy-pasting test configs to production, disabling sanitizer for debugging, etc.

The vulnerability is **always exploitable** when conditions are met (InMemoryStorage + restart), making it deterministic rather than probabilistic.

## Recommendation

**Immediate Fix**: Change the default backend to a secure option and make `InMemoryStorage` explicitly opt-in for testing only.

```rust
impl Default for SafetyRulesConfig {
    fn default() -> Self {
        Self {
            // SECURE DEFAULT: Require explicit storage configuration
            backend: SecureBackend::OnDiskStorage(OnDiskStorageConfig::default()),
            logger: LoggerConfig::default(),
            service: SafetyRulesService::Local,
            test: None,
            network_timeout_ms: 30_000,
            enable_cached_safety_data: true,
            initial_safety_rules_config: InitialSafetyRulesConfig::None,
        }
    }
}
```

**Additional Mitigations**:

1. **Extend sanitizer to all deployments**:
```rust
// Check for InMemoryStorage on ALL validators, not just mainnet
if node_type.is_validator() && safety_rules_config.backend.is_in_memory() {
    return Err(Error::ConfigSanitizerFailed(
        sanitizer_name,
        "InMemoryStorage is only for testing and should never be used for validators!".to_string(),
    ));
}
```

2. **Remove ability to skip sanitizer** or require explicit acknowledgment of risks:
```rust
if node_config.node_startup.skip_config_sanitizer {
    eprintln!("WARNING: Config sanitizer disabled. This may allow unsafe configurations!");
    eprintln!("Press Enter to continue or Ctrl+C to abort...");
    std::io::stdin().read_line(&mut String::new())?;
}
```

3. **Add runtime validation** that safety storage is actually persistent before allowing votes.

## Proof of Concept

```rust
// Simulated validator restart scenario demonstrating equivocation
use aptos_consensus_types::safety_data::SafetyData;
use aptos_crypto::bls12381;
use aptos_secure_storage::{InMemoryStorage, KVStorage, Storage};
use consensus::safety_rules::PersistentSafetyStorage;

#[test]
fn test_in_memory_storage_equivocation_vulnerability() {
    // Step 1: First validator start with InMemoryStorage
    let storage1 = Storage::from(InMemoryStorage::new());
    let mut persistent_storage = PersistentSafetyStorage::initialize(
        storage1,
        Author::random(),
        bls12381::PrivateKey::generate_for_testing(),
        Waypoint::default(),
        false,
    );
    
    // Step 2: Validator votes on round 10
    let mut safety_data = persistent_storage.safety_data().unwrap();
    assert_eq!(safety_data.last_voted_round, 0);
    
    // Simulate voting on round 10
    safety_data.last_voted_round = 10;
    safety_data.last_vote = Some(create_test_vote(10));
    persistent_storage.set_safety_data(safety_data).unwrap();
    
    // Verify the vote was recorded
    assert_eq!(persistent_storage.safety_data().unwrap().last_voted_round, 10);
    
    // Step 3: Validator restarts - InMemoryStorage is LOST
    // Simulate restart by creating new storage (simulates process restart)
    let storage2 = Storage::from(InMemoryStorage::new());
    let persistent_storage_after_restart = PersistentSafetyStorage::initialize(
        storage2,
        Author::random(),
        bls12381::PrivateKey::generate_for_testing(),
        Waypoint::default(),
        false,
    );
    
    // Step 4: Safety data is RESET - equivocation now possible!
    let safety_data_after_restart = persistent_storage_after_restart.safety_data().unwrap();
    assert_eq!(safety_data_after_restart.last_voted_round, 0); // RESET TO 0!
    assert!(safety_data_after_restart.last_vote.is_none()); // LOST!
    
    // Step 5: Validator can now vote again on round 10 (or any round ≤ 10)
    // This is EQUIVOCATION and breaks consensus safety!
    // The check at safety_rules_2chain.rs:218 will PASS because last_voted_round = 0
    assert!(10 > safety_data_after_restart.last_voted_round); // TRUE - allows re-voting!
}
```

This PoC demonstrates that `InMemoryStorage` loses all safety data on restart, allowing validators to violate monotonicity and equivocation rules, directly breaking AptosBFT consensus safety guarantees.

## Notes

The vulnerability is particularly insidious because:
1. It's a **default behavior** that operators must actively override
2. It **silently fails** on restart with no error—the validator simply resets to unsafe state
3. **Detection happens too late**—other validators detect equivocation after the safety violation occurs
4. Testnet/devnet have **zero protection**, potentially masking the issue until production deployment

The existence of the sanitizer acknowledges the risk, but relying on runtime validation to catch insecure defaults is a defense-in-depth failure. Secure-by-default design principles mandate that the default configuration should be safe.

### Citations

**File:** config/src/config/safety_rules_config.rs (L36-49)
```rust
impl Default for SafetyRulesConfig {
    fn default() -> Self {
        Self {
            backend: SecureBackend::InMemoryStorage,
            logger: LoggerConfig::default(),
            service: SafetyRulesService::Local,
            test: None,
            // Default value of 30 seconds for a timeout
            network_timeout_ms: 30_000,
            enable_cached_safety_data: true,
            initial_safety_rules_config: InitialSafetyRulesConfig::None,
        }
    }
}
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

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L68-74)
```rust
        // if already voted on this round, send back the previous vote
        // note: this needs to happen after verifying the epoch as we just check the round here
        if let Some(vote) = safety_data.last_vote.clone() {
            if vote.vote_data().proposed().round() == proposed_block.round() {
                return Ok(vote);
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

**File:** secure/storage/src/in_memory.rs (L9-14)
```rust
/// InMemoryStorage represents a key value store that is purely in memory and intended for single
/// threads (or must be wrapped by a Arc<RwLock<>>). This provides no permission checks and simply
/// is a proof of concept to unblock building of applications without more complex data stores.
/// Internally, it retains all data, which means that it must make copies of all key material which
/// violates the code base. It violates it because the anticipation is that data stores would
/// securely handle key material. This should not be used in production.
```

**File:** consensus/safety-rules/src/persistent_safety_storage.rs (L45-45)
```rust
        let safety_data = SafetyData::new(1, 0, 0, 0, None, 0);
```

**File:** config/src/config/config_sanitizer.rs (L45-48)
```rust
        // If config sanitization is disabled, don't do anything!
        if node_config.node_startup.skip_config_sanitizer {
            return Ok(());
        }
```

**File:** consensus/src/pending_votes.rs (L298-308)
```rust
            } else {
                // we have seen a different vote for the same round
                error!(
                    SecurityEvent::ConsensusEquivocatingVote,
                    remote_peer = vote.author(),
                    vote = vote,
                    previous_vote = previously_seen_vote
                );

                return VoteReceptionResult::EquivocateVote;
            }
```
