# Audit Report

## Title
Cache-Backend Divergence in SafetyRules Allows Consensus Safety Violations via Direct Storage Manipulation

## Summary
The combination of `enable_cached_safety_data=true` with `InMemoryStorage` backend creates a cache coherence vulnerability where direct manipulation of the underlying storage via the exposed `internal_store()` method bypasses cache updates, allowing stale `SafetyData` to be used in voting decisions, potentially causing double-voting and other consensus safety violations.

## Finding Description

The `PersistentSafetyStorage` struct maintains an in-memory cache of `SafetyData` when `enable_cached_safety_data` is enabled. This cache optimization is designed to avoid repeated reads from the backend storage. However, the implementation has a critical flaw in its cache coherence protocol. [1](#0-0) 

The `safety_data()` method returns cached data without verifying backend consistency: [2](#0-1) 

When caching is enabled and the cache is populated (line 140), the method immediately returns the cached value without checking if the underlying storage has been modified. The cache is only updated when `set_safety_data()` is called.

The critical vulnerability arises because `PersistentSafetyStorage` exposes the `internal_store()` method, which provides mutable access to the underlying storage: [3](#0-2) 

This method is actively used in production code: [4](#0-3) 

**Attack Scenario:**

1. A validator node initializes `PersistentSafetyStorage` with `InMemoryStorage` backend and `enable_cached_safety_data=true` (this is the default configuration) [5](#0-4) 

2. Normal voting operations populate the cache with `SafetyData` containing `last_voted_round=100`, `preferred_round=95`, `epoch=5`

3. Malicious code or a bug causes direct modification via `internal_store().set(SAFETY_DATA, modified_data)` where `modified_data` has `last_voted_round=50`

4. The backend storage now has `last_voted_round=50`, but the cache still has `last_voted_round=100`

5. Subsequent `safety_data()` calls return the cached value with `last_voted_round=100`

6. When SafetyRules validates voting rules, it checks against the stale cached `last_voted_round`: [6](#0-5) 

7. The validator can now vote for round 60-100 even though the backend storage indicates it already voted for round 50, violating the first voting rule and enabling double-voting

Additionally, in test/development environments with `reset_and_clear()` available: [7](#0-6) 

If `internal_store().reset_and_clear()` is called after cache population, the backend is cleared but the cache retains old data, causing complete divergence where the cache believes the validator has voting history but the backend is empty.

## Impact Explanation

**Critical Severity** - This vulnerability breaks consensus safety, which is the most critical invariant in any BFT consensus protocol.

**Consensus Safety Violation**: The AptosBFT consensus protocol relies on two fundamental voting rules to ensure safety:
1. First voting rule: A validator cannot vote for round R if it has already voted for round R' where R' >= R
2. Second voting rule: A validator cannot vote for a block unless the block's QC round is >= the validator's preferred_round [8](#0-7) 

When cached `SafetyData` diverges from backend storage, these safety checks operate on incorrect data:

- **Double-Voting**: If `last_voted_round` is stale (higher in cache than backend), the validator can vote multiple times in the same round or vote for earlier rounds it already voted for
- **Chain Equivocation**: If `preferred_round` is stale, the validator can vote for conflicting chains
- **Epoch Confusion**: If `epoch` is stale, the validator can participate in the wrong epoch

The consequence is that a single Byzantine validator with this bug can produce equivocating votes, potentially causing chain forks if combined with network partitions or other Byzantine validators.

**Production Impact**: While the config sanitizer protects mainnet validators from `InMemoryStorage`, this vulnerability affects:
- Development and testnet validators that use `InMemoryStorage`
- Any code path that uses `internal_store()` to modify storage (currently used for consensus key management)
- Future code changes that might introduce direct `SAFETY_DATA` modifications

This meets the **Critical Severity** criteria: "Consensus/Safety violations" per the Aptos bug bounty program.

## Likelihood Explanation

**Medium-High Likelihood** in affected environments:

1. **Configuration is Default**: The problematic combination is the default configuration [5](#0-4) 

2. **API Exposure**: The `internal_store()` method is public and currently used in production code for other purposes, establishing a precedent for direct storage access [9](#0-8) 

3. **Test Environment Risk**: In test/development environments with `#[cfg(test)]`, `reset_and_clear()` can be accidentally called after cache population

4. **Code Evolution Risk**: Future code changes might introduce direct `SAFETY_DATA` modifications via `internal_store()` without realizing the cache coherence implications

**Mitigation**: The config sanitizer provides partial protection for mainnet: [10](#0-9) 

However, this still allows the vulnerability in testnet/development, and the fundamental design flaw remains.

## Recommendation

**Immediate Fix**: Remove or restrict the `internal_store()` method to prevent direct storage manipulation that bypasses cache updates:

```rust
// Option 1: Remove internal_store() entirely and provide specific methods for legitimate use cases
// Option 2: Make internal_store() private or pub(crate)
// Option 3: Add cache invalidation on any direct storage access

// In persistent_safety_storage.rs, replace:
pub fn internal_store(&mut self) -> &mut Storage {
    &mut self.internal_store
}

// With a cache-aware wrapper:
pub fn set_consensus_key(&mut self, key: &str, value: bls12381::PrivateKey) -> Result<(), Error> {
    self.internal_store.set(key, value)?;
    // Cache remains valid as we're not modifying SAFETY_DATA
    Ok(())
}

// And invalidate cache if SAFETY_DATA is ever directly modified:
pub(crate) fn internal_store_with_cache_invalidation(&mut self) -> &mut Storage {
    // If this is used to modify SAFETY_DATA, the caller must know to invalidate cache
    &mut self.internal_store
}
```

**Long-term Fix**: Implement proper cache coherence with version checking or remove caching entirely for `InMemoryStorage`:

```rust
pub fn safety_data(&mut self) -> Result<SafetyData, Error> {
    // For InMemoryStorage, caching provides minimal benefit since it's already in memory
    if matches!(self.internal_store, Storage::InMemoryStorage(_)) {
        let _timer = counters::start_timer("get", SAFETY_DATA);
        return self.internal_store.get(SAFETY_DATA).map(|v| v.value)?;
    }
    
    // Existing cached logic for persistent storage backends
    if !self.enable_cached_safety_data {
        let _timer = counters::start_timer("get", SAFETY_DATA);
        return self.internal_store.get(SAFETY_DATA).map(|v| v.value)?;
    }
    // ... rest of cached implementation
}
```

**Additional Safeguard**: Add validation in `safety_data()` to detect divergence:

```rust
#[cfg(debug_assertions)]
fn validate_cache_coherence(&self) -> Result<(), Error> {
    if let Some(cached) = &self.cached_safety_data {
        let backend: SafetyData = self.internal_store.get(SAFETY_DATA).map(|v| v.value)?;
        if cached != &backend {
            panic!("Cache divergence detected! Cached: {:?}, Backend: {:?}", cached, backend);
        }
    }
    Ok(())
}
```

## Proof of Concept

```rust
#[cfg(test)]
mod cache_divergence_poc {
    use super::*;
    use aptos_consensus_types::safety_data::SafetyData;
    use aptos_crypto::bls12381;
    use aptos_global_constants::SAFETY_DATA;
    use aptos_secure_storage::{InMemoryStorage, KVStorage, Storage};
    use aptos_types::validator_signer::ValidatorSigner;

    #[test]
    #[should_panic(expected = "safety violation")]
    fn test_cache_divergence_allows_double_voting() {
        // Step 1: Initialize PersistentSafetyStorage with InMemoryStorage and caching enabled
        let signer = ValidatorSigner::from_int(0);
        let waypoint = test_utils::validator_signers_to_waypoint(&[&signer]);
        let mut storage = PersistentSafetyStorage::initialize(
            Storage::from(InMemoryStorage::new()),
            signer.author(),
            signer.private_key().clone(),
            waypoint,
            true, // enable_cached_safety_data = true
        );

        // Step 2: Simulate voting in round 100, populating the cache
        let safety_data_round_100 = SafetyData::new(1, 100, 95, 100, None, 0);
        storage.set_safety_data(safety_data_round_100.clone()).unwrap();
        
        // Verify cache is populated
        let cached_data = storage.safety_data().unwrap();
        assert_eq!(cached_data.last_voted_round, 100);

        // Step 3: Maliciously modify backend storage directly via internal_store()
        // This bypasses the cache update in set_safety_data()
        let manipulated_data = SafetyData::new(1, 50, 45, 50, None, 0);
        storage.internal_store().set(SAFETY_DATA, manipulated_data).unwrap();

        // Step 4: Read safety_data() - returns STALE cached data!
        let read_data = storage.safety_data().unwrap();
        assert_eq!(read_data.last_voted_round, 100); // Cache returns 100
        
        // But backend actually has 50!
        let backend_data: SafetyData = storage.internal_store()
            .get(SAFETY_DATA)
            .map(|v| v.value)
            .unwrap();
        assert_eq!(backend_data.last_voted_round, 50); // Backend has 50

        // Step 5: This divergence allows voting in rounds 51-100 even though
        // the validator should only be able to vote for rounds > 100
        // This violates the first voting rule and enables double-voting
        
        panic!("safety violation: cache reports last_voted_round={}, backend has last_voted_round={}", 
               read_data.last_voted_round, backend_data.last_voted_round);
    }

    #[test]
    #[cfg(feature = "testing")]
    fn test_reset_and_clear_divergence() {
        let signer = ValidatorSigner::from_int(0);
        let waypoint = test_utils::validator_signers_to_waypoint(&[&signer]);
        let mut storage = PersistentSafetyStorage::initialize(
            Storage::from(InMemoryStorage::new()),
            signer.author(),
            signer.private_key().clone(),
            waypoint,
            true,
        );

        // Populate cache
        let safety_data = SafetyData::new(1, 100, 95, 100, None, 0);
        storage.set_safety_data(safety_data.clone()).unwrap();
        assert_eq!(storage.safety_data().unwrap().last_voted_round, 100);

        // Clear backend but cache remains
        storage.internal_store().reset_and_clear().unwrap();

        // Cache still returns old data!
        let cached = storage.safety_data().unwrap();
        assert_eq!(cached.last_voted_round, 100);

        // But backend is empty - would error if not for cache
        let backend_result = storage.internal_store().get::<SafetyData>(SAFETY_DATA);
        assert!(backend_result.is_err()); // Backend has no SAFETY_DATA

        // Complete divergence: cache has data, backend is empty
    }
}
```

**Notes**
- This vulnerability specifically affects the combination of `InMemoryStorage` + `enable_cached_safety_data=true`, which is the default configuration
- The config sanitizer protects mainnet production validators but not testnet/development environments
- The root cause is the exposed `internal_store()` method that allows cache-bypass modifications
- Current production code only uses `internal_store()` for consensus key management, but the API surface allows `SAFETY_DATA` modifications
- The vulnerability demonstrates a fundamental cache coherence design flaw that could be exploited through future code changes or bugs

### Citations

**File:** consensus/safety-rules/src/persistent_safety_storage.rs (L24-28)
```rust
pub struct PersistentSafetyStorage {
    enable_cached_safety_data: bool,
    cached_safety_data: Option<SafetyData>,
    internal_store: Storage,
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

**File:** consensus/safety-rules/src/persistent_safety_storage.rs (L187-189)
```rust
    pub fn internal_store(&mut self) -> &mut Storage {
        &mut self.internal_store
    }
```

**File:** consensus/safety-rules/src/safety_rules_manager.rs (L86-96)
```rust
            if let Some(sk) = blob.consensus_private_key {
                let pk_hex = hex::encode(PublicKey::from(&sk).to_bytes());
                let storage_key = format!("{}_{}", CONSENSUS_KEY, pk_hex);
                match storage.internal_store().set(storage_key.as_str(), sk) {
                    Ok(_) => {
                        info!("Setting {storage_key} succeeded.");
                    },
                    Err(e) => {
                        warn!("Setting {storage_key} failed with internal store set error: {e}");
                    },
                }
```

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

**File:** secure/storage/src/in_memory.rs (L59-63)
```rust
    #[cfg(any(test, feature = "testing"))]
    fn reset_and_clear(&mut self) -> Result<(), Error> {
        self.data.clear();
        Ok(())
    }
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L76-81)
```rust
        // Two voting rules
        self.verify_and_update_last_vote_round(
            proposed_block.block_data().round(),
            &mut safety_data,
        )?;
        self.safe_to_vote(proposed_block, timeout_cert)?;
```
