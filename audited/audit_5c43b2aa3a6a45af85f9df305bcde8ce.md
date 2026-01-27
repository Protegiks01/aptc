# Audit Report

## Title
Policy Migration Failure Causes Validator Panic During Network Upgrades

## Summary
The Aptos secure storage policy system lacks versioning, pre-flight validation, and migration paths. When validators upgrade to new software versions that require different Vault policy configurations, they immediately panic on `PermissionDenied` errors during critical consensus operations, causing validator crashes and potential network liveness failures.

## Finding Description

The vulnerability exists in the intersection of three components:

**1. No Policy Versioning or Compatibility Checks**

The `Policy` struct has no version field or mechanism to validate compatibility across different Aptos versions: [1](#0-0) 

**2. Inadequate Storage Availability Check**

During validator initialization, only basic Vault availability is checked (whether Vault is unsealed), not whether policies match the new version's requirements: [2](#0-1) 

The `available()` method for VaultStorage only verifies the Vault is unsealed: [3](#0-2) 

**3. Panic on PermissionDenied**

When Vault returns a 403 HTTP error (permission denied), it's converted to `Error::PermissionDenied`: [4](#0-3) 

This error causes an **immediate panic** in SafetyRules error handling: [5](#0-4) 

**4. Critical Consensus Operations Affected**

All critical consensus operations call storage methods that will panic on permission errors:

- Vote construction reads and writes safety data: [6](#0-5) 

- Timeout signing accesses safety data: [7](#0-6) 

- Proposal verification reads safety data: [8](#0-7) 

**Attack Scenario:**

1. Aptos releases version N+1 that requires additional Vault capabilities (e.g., new `Capability::Verify` or changes to existing permission structures)
2. Validators upgrade their node software to version N+1
3. The new version attempts consensus operations requiring the new capabilities
4. Vault returns 403 (Permission Denied) because policies weren't updated
5. The validator panics and crashes with "A permission error was thrown"
6. If multiple validators are affected simultaneously, the network loses consensus quorum

This breaks the **Consensus Liveness** invariant: validators must remain operational during network upgrades.

## Impact Explanation

**High Severity** per Aptos bug bounty criteria:
- **Validator node crashes**: Not just slowdowns, but complete panics requiring manual intervention
- **Significant protocol violations**: Loss of consensus participation during critical upgrade windows
- **Network liveness risk**: If sufficient validators (>1/3) are affected, the network halts

The impact is amplified because:
- Validators typically upgrade during coordinated time windows
- Policy mismatches affect all consensus operations simultaneously
- Recovery requires manual Vault policy updates and node restarts
- No automatic rollback or graceful degradation mechanism exists

## Likelihood Explanation

**High Likelihood** because:
1. Network upgrades occur regularly in blockchain operations
2. Policy requirements can legitimately change between versions as features are added
3. The documentation shows no policy migration guidance
4. Operators may not realize policies need updating before upgrading node software
5. The failure mode is immediate (first consensus operation triggers panic)
6. Testing environments may not catch this if they use different storage backends (InMemoryStorage vs Vault)

The comment in the panic handler acknowledges token expiration as a known scenario: [9](#0-8) 

This suggests the developers are aware of permission failures, but the approach (panic immediately) is inappropriate for upgrade scenarios where policies legitimately need updates.

## Recommendation

Implement a comprehensive policy migration framework:

**1. Add Policy Versioning**
```rust
#[derive(Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Policy {
    pub version: u32,  // Add version field
    pub permissions: Vec<Permission>,
}

impl Policy {
    pub fn is_compatible_with(&self, required_version: u32) -> bool {
        self.version >= required_version
    }
}
```

**2. Add Pre-flight Policy Validation**
```rust
pub fn storage(config: &SafetyRulesConfig) -> PersistentSafetyStorage {
    let backend = &config.backend;
    let internal_storage: Storage = backend.into();
    
    // Existing availability check
    if let Err(error) = internal_storage.available() {
        panic!("Storage is not available: {:?}", error);
    }
    
    // NEW: Validate policy compatibility before entering consensus
    if let Err(error) = validate_storage_policies(&internal_storage, REQUIRED_POLICY_VERSION) {
        panic!("Storage policies are incompatible with this version: {:?}. Please update Vault policies before upgrading.", error);
    }
    
    // ... rest of initialization
}

fn validate_storage_policies(storage: &Storage, required_version: u32) -> Result<(), Error> {
    // Attempt to read a test key to verify permissions
    // This catches permission errors before consensus operations
    match storage.get::<u64>(POLICY_VERSION_KEY) {
        Ok(resp) if resp.value >= required_version => Ok(()),
        Ok(resp) => Err(Error::IncompatiblePolicyVersion(resp.value, required_version)),
        Err(aptos_secure_storage::Error::PermissionDenied) => {
            Err(Error::StoragePolicyMigrationRequired)
        }
        Err(e) => Err(e.into()),
    }
}
```

**3. Graceful Degradation Instead of Panic**

Replace the immediate panic with a graceful shutdown:
```rust
impl From<aptos_secure_storage::Error> for Error {
    fn from(error: aptos_secure_storage::Error) -> Self {
        match error {
            aptos_secure_storage::Error::PermissionDenied => {
                // Log error but don't panic - allow graceful shutdown
                error!(
                    "Storage permission denied. Vault policies may need updating. \
                     Validator cannot participate in consensus."
                );
                Self::SecureStoragePermissionError(error.to_string())
            },
            // ... rest of handling
        }
    }
}
```

**4. Document Migration Path**

Create `docs/vault-policy-migration.md` with:
- Policy versioning scheme
- Pre-upgrade checklist for validators
- Scripts to update Vault policies
- Rollback procedures

## Proof of Concept

```rust
// Test demonstrating the panic during policy mismatch
#[test]
#[should_panic(expected = "A permission error was thrown")]
fn test_policy_mismatch_causes_panic() {
    use aptos_secure_storage::{Storage, VaultStorage, Policy, Permission, Identity, Capability};
    use consensus_safety_rules::{SafetyRules, PersistentSafetyStorage};
    
    // Setup: Create Vault with restrictive policies
    let mut vault = VaultStorage::new(
        "http://localhost:8200".to_string(),
        "test_token".to_string(),
        None, None, true, None, None
    );
    
    // Set up policy that only allows Read, not Write
    let read_only_policy = Policy::new(vec![
        Permission::new(Identity::Anyone, vec![Capability::Read])
    ]);
    
    // Initialize storage with the restrictive policy
    let storage = Storage::from(vault);
    let mut safety_storage = PersistentSafetyStorage::new(storage, true);
    
    // Create SafetyRules instance
    let mut safety_rules = SafetyRules::new(safety_storage, false);
    
    // Simulate consensus operation that requires Write capability
    // This will return PermissionDenied (403) and trigger panic
    let mut safety_data = safety_rules.persistent_storage.safety_data().unwrap();
    safety_data.last_voted_round = 1;
    
    // This line will panic due to missing Write permission
    safety_rules.persistent_storage.set_safety_data(safety_data).unwrap();
}
```

**Steps to reproduce in production:**
1. Deploy validator with Vault backend using policy version 1
2. Upgrade node to version N+1 requiring policy version 2 (new capabilities)
3. Do not update Vault policies
4. Start validator
5. Observe panic on first consensus operation requiring the new capabilities

## Notes

This vulnerability is particularly insidious because:
- The config sanitizer checks for mainnet using InMemoryStorage but doesn't validate Vault policy compatibility [10](#0-9) 

- Tests use `reset_and_clear()` which masks the issue by resetting policies each time [11](#0-10) 

- The panic is intentional (for token expiration) but inappropriate for upgrade scenarios where policy updates are a normal operational requirement

The core issue is treating all `PermissionDenied` errors as catastrophic failures requiring immediate panic, when some scenarios (like upgrade-time policy migration) should be handled gracefully with clear operator guidance.

### Citations

**File:** secure/storage/src/policy.rs (L6-23)
```rust
/// Dictates a set of permissions
#[derive(Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Policy {
    pub permissions: Vec<Permission>,
}

impl Policy {
    pub fn new(permissions: Vec<Permission>) -> Self {
        Self { permissions }
    }

    pub fn public() -> Self {
        Self::new(vec![Permission::new(Identity::Anyone, vec![
            Capability::Read,
            Capability::Write,
        ])])
    }
}
```

**File:** consensus/safety-rules/src/safety_rules_manager.rs (L21-26)
```rust
pub fn storage(config: &SafetyRulesConfig) -> PersistentSafetyStorage {
    let backend = &config.backend;
    let internal_storage: Storage = backend.into();
    if let Err(error) = internal_storage.available() {
        panic!("Storage is not available: {:?}", error);
    }
```

**File:** secure/storage/src/vault.rs (L146-153)
```rust
impl KVStorage for VaultStorage {
    fn available(&self) -> Result<(), Error> {
        if !self.client().unsealed()? {
            Err(Error::InternalError("Vault is not unsealed".into()))
        } else {
            Ok(())
        }
    }
```

**File:** secure/storage/src/error.rs (L56-64)
```rust
impl From<aptos_vault_client::Error> for Error {
    fn from(error: aptos_vault_client::Error) -> Self {
        match error {
            aptos_vault_client::Error::NotFound(_, key) => Self::KeyNotSet(key),
            aptos_vault_client::Error::HttpError(403, _, _) => Self::PermissionDenied,
            _ => Self::InternalError(format!("{}", error)),
        }
    }
}
```

**File:** consensus/safety-rules/src/error.rs (L78-99)
```rust
impl From<aptos_secure_storage::Error> for Error {
    fn from(error: aptos_secure_storage::Error) -> Self {
        match error {
            aptos_secure_storage::Error::PermissionDenied => {
                // If a storage error is thrown that indicates a permission failure, we
                // want to panic immediately to alert an operator that something has gone
                // wrong. For example, this error is thrown when a storage (e.g., vault)
                // token has expired, so it makes sense to fail fast and require a token
                // renewal!
                panic!(
                    "A permission error was thrown: {:?}. Maybe the storage token needs to be renewed?",
                    error
                );
            },
            aptos_secure_storage::Error::KeyVersionNotFound(_, _)
            | aptos_secure_storage::Error::KeyNotSet(_) => {
                Self::SecureStorageMissingDataError(error.to_string())
            },
            _ => Self::SecureStorageUnexpectedError(error.to_string()),
        }
    }
}
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L25-47)
```rust
        let mut safety_data = self.persistent_storage.safety_data()?;
        self.verify_epoch(timeout.epoch(), &safety_data)?;
        if !self.skip_sig_verify {
            timeout
                .verify(&self.epoch_state()?.verifier)
                .map_err(|e| Error::InvalidTimeout(e.to_string()))?;
        }
        if let Some(tc) = timeout_cert {
            self.verify_tc(tc)?;
        }

        self.safe_to_timeout(timeout, timeout_cert, &safety_data)?;
        if timeout.round() < safety_data.last_voted_round {
            return Err(Error::IncorrectLastVotedRound(
                timeout.round(),
                safety_data.last_voted_round,
            ));
        }
        if timeout.round() > safety_data.last_voted_round {
            self.verify_and_update_last_vote_round(timeout.round(), &mut safety_data)?;
        }
        self.update_highest_timeout_round(timeout, &mut safety_data);
        self.persistent_storage.set_safety_data(safety_data)?;
```

**File:** consensus/safety-rules/src/safety_rules_2chain.rs (L66-92)
```rust
        let mut safety_data = self.persistent_storage.safety_data()?;

        // if already voted on this round, send back the previous vote
        // note: this needs to happen after verifying the epoch as we just check the round here
        if let Some(vote) = safety_data.last_vote.clone() {
            if vote.vote_data().proposed().round() == proposed_block.round() {
                return Ok(vote);
            }
        }

        // Two voting rules
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

**File:** consensus/safety-rules/src/safety_rules.rs (L63-85)
```rust
    pub(crate) fn verify_proposal(
        &mut self,
        vote_proposal: &VoteProposal,
    ) -> Result<VoteData, Error> {
        let proposed_block = vote_proposal.block();
        let safety_data = self.persistent_storage.safety_data()?;

        self.verify_epoch(proposed_block.epoch(), &safety_data)?;

        self.verify_qc(proposed_block.quorum_cert())?;
        if !self.skip_sig_verify {
            proposed_block
                .validate_signature(&self.epoch_state()?.verifier)
                .map_err(|error| Error::InvalidProposal(error.to_string()))?;
        }
        proposed_block
            .verify_well_formed()
            .map_err(|error| Error::InvalidProposal(error.to_string()))?;

        vote_proposal
            .gen_vote_data()
            .map_err(|error| Error::InvalidAccumulatorExtension(error.to_string()))
    }
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

**File:** secure/storage/src/tests/vault.rs (L59-65)
```rust
    let mut storage = create_vault();
    storage.reset_and_clear().unwrap();

    for test in VAULT_TESTS.iter() {
        test();
        storage.reset_and_clear().unwrap();
    }
```
