# Audit Report

## Title
Consensus Safety Violation via Storage Backend Migration Without SafetyData Preservation

## Summary
When migrating SafetyRules storage from one backend (e.g., OnDiskStorage) to another (e.g., Vault/HSM), if the new storage backend is empty or missing SafetyData, the validator reinitializes with epoch=1 and last_voted_round=0. Upon subsequent epoch synchronization via `guarded_initialize()`, the validator updates to the current epoch but resets last_voted_round to 0, enabling the validator to re-vote on rounds it previously voted on, causing equivocation and violating consensus safety.

## Finding Description

The vulnerability exists in the storage initialization and epoch transition logic: [1](#0-0) 

When `PersistentSafetyStorage::initialize()` is called for a new storage backend, it hardcodes SafetyData creation with epoch=1 and last_voted_round=0. This occurs during the migration scenario when:

1. A validator operator migrates from OnDiskStorage (containing SafetyData with epoch=10, last_voted_round=1000) to an empty Vault backend
2. The storage initialization logic in `safety_rules_manager.rs` detects the new storage is empty (author check fails): [2](#0-1) 

3. Since the storage appears uninitialized, it calls `initialize()` which creates fresh SafetyData(epoch=1, last_voted_round=0)
4. When consensus starts, `guarded_initialize()` is called with the current EpochChangeProof: [3](#0-2) 

5. The comparison at line 284 finds current_epoch (1) < proof epoch (10), triggering lines 296-303 which create **new** SafetyData with the correct epoch but **reset last_voted_round to 0**

The validator can now vote on rounds 1-999 that it may have already voted on before migration, breaking the first voting rule: [4](#0-3) 

This violates the fundamental consensus safety invariant preventing double-voting in the same round.

## Impact Explanation

**Severity: Critical** - This constitutes a **Consensus Safety Violation** under the Aptos Bug Bounty Critical category.

**Impact:**
- **Equivocation**: The validator can cast multiple conflicting votes in the same round
- **Chain Fork Risk**: If multiple validators experience this during migration, different nodes may commit conflicting blocks
- **Byzantine Behavior**: The validator exhibits Byzantine behavior (voting twice) without any Byzantine actor
- **Consensus Safety Breach**: Violates the invariant that AptosBFT prevents safety breaks under < 1/3 Byzantine validators

The severity is Critical because:
1. It directly breaks consensus safety guarantees
2. It can cause non-recoverable state inconsistencies
3. It affects the core consensus protocol operation
4. Recovery may require coordinated intervention or potential fork resolution

## Likelihood Explanation

**Likelihood: Medium-to-High in Production Environments**

This vulnerability is likely to occur because:

1. **Legitimate Operational Need**: Migrating from OnDiskStorage to Vault/HSM is a recommended security upgrade for production validators
2. **No Built-in Migration Tool**: The codebase provides no migration utilities or documentation for safely transferring SafetyData between backends
3. **Silent Failure**: The code does not warn operators that SafetyData is missing or being reset
4. **Non-obvious Requirements**: Operators may focus on migrating consensus keys and waypoints but overlook SafetyData, which is stored separately: [5](#0-4) 

5. **Operational Complexity**: Manual migration requires extracting SafetyData from old storage and importing into new storage using storage-specific tools

However, this requires validator operator access to configuration files, which limits exploitability.

## Recommendation

**Primary Fix**: Implement SafetyData preservation checks during storage initialization:

```rust
pub fn initialize(
    mut internal_store: Storage,
    author: Author,
    consensus_private_key: bls12381::PrivateKey,
    waypoint: Waypoint,
    enable_cached_safety_data: bool,
) -> Self {
    // SECURITY: Check if this is a re-initialization attempt
    // If CONSENSUS_KEY exists but SAFETY_DATA doesn't, this indicates
    // a partial migration which is UNSAFE
    let has_consensus_key = internal_store.get::<bls12381::PrivateKey>(CONSENSUS_KEY).is_ok();
    let has_safety_data = internal_store.get::<SafetyData>(SAFETY_DATA).is_ok();
    
    if has_consensus_key && !has_safety_data {
        panic!(
            "CRITICAL: Storage contains consensus key but no safety data. \
             This indicates incomplete migration from another storage backend. \
             ALL safety-critical data (SAFETY_DATA, WAYPOINT, CONSENSUS_KEY, OWNER_ACCOUNT) \
             must be migrated together to prevent consensus safety violations. \
             See documentation on storage migration procedures."
        );
    }
    
    // Initialize the keys and accounts
    Self::initialize_keys_and_accounts(&mut internal_store, author, consensus_private_key)
        .expect("Unable to initialize keys and accounts in storage");

    // Only create fresh SafetyData if this is truly first initialization
    let safety_data = if has_safety_data {
        // This branch should never execute due to check above, but defensive
        panic!("Storage already initialized with safety data");
    } else {
        SafetyData::new(1, 0, 0, 0, None, 0)
    };
    
    // ... rest of initialization
}
```

**Secondary Fix**: Add migration validation in `safety_rules_manager.rs`:

```rust
// After line 46
let storage = PersistentSafetyStorage::new(internal_storage, config.enable_cached_safety_data);

// Add validation check
if storage.author().is_ok() {
    // Storage has author, verify all critical data exists
    if storage.safety_data().is_err() {
        panic!(
            "Storage backend has partial data (author present but SafetyData missing). \
             This indicates incomplete migration. All safety data must be migrated together."
        );
    }
    storage
} else if ...
```

**Additional Recommendation**: Provide a migration tool:
- Create `aptos-safety-rules-migration` CLI tool
- Validate source storage contains all required keys
- Export SafetyData, consensus keys, waypoint, and owner atomically
- Import into target storage with verification
- Add documentation on safe migration procedures

## Proof of Concept

```rust
// Reproduction steps (pseudo-code for clarity):

// Step 1: Setup validator with OnDiskStorage
let on_disk_storage = OnDiskStorage::new("/path/to/disk/storage");
let mut safety_storage = PersistentSafetyStorage::initialize(
    Storage::from(on_disk_storage),
    validator_author,
    consensus_key,
    waypoint,
    true,
);

// Step 2: Validator operates normally, advances to epoch 10, round 1000
safety_storage.set_safety_data(SafetyData::new(10, 1000, 900, 850, None, 950)).unwrap();
assert_eq!(safety_storage.safety_data().unwrap().epoch, 10);
assert_eq!(safety_storage.safety_data().unwrap().last_voted_round, 1000);

// Step 3: Operator decides to migrate to Vault for better security
// Operator updates config file:
// safety_rules:
//   backend:
//     type: vault
//     server: "https://vault.example.com"
//     token: ...

// Step 4: Operator restarts validator (but forgets to copy SafetyData to Vault)
let vault_storage = VaultStorage::new("https://vault.example.com", "token", ...);

// Step 5: Storage initialization runs
let config = SafetyRulesConfig {
    backend: SecureBackend::Vault(vault_config),
    initial_safety_rules_config: InitialSafetyRulesConfig::FromFile { ... },
    ...
};

let new_storage = storage(&config);
// Internal call to PersistentSafetyStorage::initialize() creates SafetyData(1, 0, 0, 0, None, 0)

// Step 6: Consensus initializes with current epoch 10
let epoch_change_proof = EpochChangeProof::for_epoch_10();
let mut safety_rules = SafetyRules::new(new_storage, false);
safety_rules.initialize(&epoch_change_proof).unwrap();

// Step 7: VULNERABILITY - Validator now at epoch 10 but last_voted_round = 0
let safety_data = safety_rules.consensus_state().unwrap().safety_data();
assert_eq!(safety_data.epoch, 10);  // Correct epoch
assert_eq!(safety_data.last_voted_round, 0);  // RESET TO 0 - DANGEROUS!

// Step 8: Validator can now equivocate
// Previously voted on round 500 with block_hash_A
// Can now vote again on round 500 with block_hash_B
// This violates consensus safety!
```

**Notes**

The vulnerability requires validator operator access to change configuration files and restart the validator. While this limits direct exploitability by external attackers, it represents a critical operational hazard during legitimate security upgrades. The lack of migration safeguards in the code creates a trap for operators performing recommended security improvements (migrating to HSM/Vault).

The fix should include both code-level validation to prevent silent safety data loss and operational tooling to guide safe migrations. The core issue is that the code treats "empty storage" as synonymous with "fresh initialization" rather than distinguishing "first-time setup" from "incomplete migration."

### Citations

**File:** consensus/safety-rules/src/persistent_safety_storage.rs (L33-61)
```rust
    pub fn initialize(
        mut internal_store: Storage,
        author: Author,
        consensus_private_key: bls12381::PrivateKey,
        waypoint: Waypoint,
        enable_cached_safety_data: bool,
    ) -> Self {
        // Initialize the keys and accounts
        Self::initialize_keys_and_accounts(&mut internal_store, author, consensus_private_key)
            .expect("Unable to initialize keys and accounts in storage");

        // Create the new persistent safety storage
        let safety_data = SafetyData::new(1, 0, 0, 0, None, 0);
        let mut persisent_safety_storage = Self {
            enable_cached_safety_data,
            cached_safety_data: Some(safety_data.clone()),
            internal_store,
        };

        // Initialize the safety data and waypoint
        persisent_safety_storage
            .set_safety_data(safety_data)
            .expect("Unable to initialize safety data");
        persisent_safety_storage
            .set_waypoint(&waypoint)
            .expect("Unable to initialize waypoint");

        persisent_safety_storage
    }
```

**File:** consensus/safety-rules/src/safety_rules_manager.rs (L44-77)
```rust
    } else {
        let storage =
            PersistentSafetyStorage::new(internal_storage, config.enable_cached_safety_data);

        let mut storage = if storage.author().is_ok() {
            storage
        } else if !matches!(
            config.initial_safety_rules_config,
            InitialSafetyRulesConfig::None
        ) {
            let identity_blob = config
                .initial_safety_rules_config
                .identity_blob()
                .expect("No identity blob in initial safety rules config");
            let waypoint = config.initial_safety_rules_config.waypoint();

            let backend = &config.backend;
            let internal_storage: Storage = backend.into();
            PersistentSafetyStorage::initialize(
                internal_storage,
                identity_blob
                    .account_address
                    .expect("AccountAddress needed for safety rules"),
                identity_blob
                    .consensus_private_key
                    .expect("Consensus key needed for safety rules"),
                waypoint,
                config.enable_cached_safety_data,
            )
        } else {
            panic!(
                "Safety rules storage is not initialized, provide an initial safety rules config"
            )
        };
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

**File:** consensus/safety-rules/src/safety_rules.rs (L283-303)
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
```

**File:** config/global-constants/src/lib.rs (L1-20)
```rust
// Copyright (c) Aptos Foundation
// Licensed pursuant to the Innovation-Enabling Source Code License, available at https://github.com/aptos-labs/aptos-core/blob/main/LICENSE

//! The purpose of this crate is to offer a single source of truth for the definitions of shared
//! constants within the codebase. This is useful because many different components within
//! Aptos often require access to global constant definitions (e.g., Safety Rules,
//! Key Manager, and Secure Storage). To avoid duplicating these definitions across crates
//! (and better allow these constants to be updated in a single location), we define them here.
#![forbid(unsafe_code)]

/// Definitions of global cryptographic keys (e.g., as held in secure storage)
pub const CONSENSUS_KEY: &str = "consensus";
pub const OWNER_ACCOUNT: &str = "owner_account";

/// Definitions of global data items (e.g., as held in secure storage)
pub const SAFETY_DATA: &str = "safety_data";
pub const WAYPOINT: &str = "waypoint";
pub const GENESIS_WAYPOINT: &str = "genesis-waypoint";

// TODO(Gas): double check if this right
```
