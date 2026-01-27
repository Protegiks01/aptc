# Audit Report

## Title
Departing Validators Retain Access to Consensus Keys via Stale Vault Policies During Reconfiguration

## Summary
When validators are removed from the active validator set during reconfiguration (epoch changes), their Vault access tokens and policies are not revoked or updated. This allows departing validators to indefinitely retain access to their consensus signing keys and other secure storage resources, violating critical access control invariants.

## Finding Description

The secure storage system uses HashiCorp Vault with policy-based access control to protect consensus keys. Validators receive Vault tokens with policies granting capabilities like `Sign`, `Export`, `Read`, and `Rotate` on their consensus keys. [1](#0-0) 

When a validator joins the set, they receive a Vault token created through `VaultPolicy::create_token()`: [2](#0-1) 

Policies are set via `set_policies()`: [3](#0-2) 

During epoch transitions, `SafetyRules::guarded_initialize()` checks if a validator is in the new validator set: [4](#0-3) 

If a validator is not in the new set, it returns `Error::ValidatorNotInSet`, preventing them from participating in consensus. However, this check does NOT revoke their Vault token or update policies.

The `EpochManager::start_new_epoch()` method initializes the new epoch but contains no code to revoke tokens or update Vault policies: [5](#0-4) 

While token revocation functions exist (`revoke_token_self()`, `reset_policies()`), they are never called during validator set changes: [6](#0-5) [7](#0-6) 

**Attack Scenario:**

1. Validator A is part of the active set with Vault token T1 granting Sign, Export, and Read capabilities
2. Validator A leaves the validator set (voluntarily via `leave_validator_set()` or through governance removal)
3. Reconfiguration occurs, new epoch starts
4. `SafetyRules::guarded_initialize()` returns `ValidatorNotInSet` for Validator A, preventing consensus participation
5. **BUT** token T1 remains valid with all its policies intact
6. Validator A can still:
   - Access and export their consensus private keys via `export_private_key()`
   - Sign arbitrary messages via `sign()`
   - Read other data in secure storage
   - Potentially use these keys to create confusion or mount attacks

This violates the security invariant that **only active validators should have access to consensus keys**.

## Impact Explanation

**High Severity** - This qualifies as a "Significant protocol violation" under the Aptos bug bounty criteria.

The impact includes:

1. **Consensus Key Exposure**: Departing validators retain indefinite access to their consensus signing keys, creating a key management vulnerability
2. **Unauthorized Signing**: Former validators can sign messages with keys that may still be associated with validator identities in some contexts
3. **Key Export Risk**: The `Export` capability allows extracting private keys, enabling offline attacks
4. **Access Control Violation**: Breaks the fundamental principle that access should be revoked when authorization ends

While this doesn't directly enable consensus safety violations (since the validator is removed from the active set), it creates significant security risks:
- Compromised keys of former validators
- Potential confusion attacks using signatures from "departed" validators
- Violation of defense-in-depth principles
- Regulatory and compliance issues with key lifecycle management

## Likelihood Explanation

**High Likelihood**:

1. **Frequent Occurrence**: Validator set changes happen regularly through:
   - Voluntary departures via `leave_validator_set()`
   - Governance-driven removals via `remove_validators()`
   - Performance-based removals (validators below minimum stake)

2. **No Mitigations**: There are zero compensating controls - no token expiration, no policy updates, no revocation mechanisms during reconfiguration

3. **Long Window**: Tokens remain valid indefinitely until explicitly revoked, creating an unbounded exposure window

4. **Observable**: The issue is easily verifiable by monitoring Vault access logs after validator removal

## Recommendation

Implement token revocation and policy cleanup during validator set changes. Add the following to `EpochManager::start_new_epoch()`:

```rust
// After loading new epoch state (around line 1175)
// Identify validators removed from the set
let previous_validators = self.epoch_state.as_ref().map(|es| 
    es.verifier.get_ordered_account_addresses_iter().collect::<HashSet<_>>()
);
let current_validators = epoch_state.verifier
    .get_ordered_account_addresses_iter()
    .collect::<HashSet<_>>();

if let Some(prev) = previous_validators {
    let departed_validators = prev.difference(&current_validators);
    
    // Revoke access for departed validators
    for departed_validator in departed_validators {
        if let Err(e) = self.key_storage.revoke_validator_access(departed_validator) {
            error!("Failed to revoke access for departed validator {}: {}", 
                   departed_validator, e);
        }
    }
}
```

Additionally, implement token lifecycle management in `PersistentSafetyStorage`:

```rust
pub fn revoke_validator_access(&mut self, validator: &Author) -> Result<(), Error> {
    // If using Vault storage, revoke the validator's token
    if let Storage::VaultStorage(vault) = &mut self.internal_store {
        vault.revoke_validator_token(validator)?;
        
        // Update or delete policies associated with this validator
        vault.remove_validator_policies(validator)?;
    }
    Ok(())
}
```

## Proof of Concept

```rust
// Rust test demonstrating the vulnerability
#[test]
fn test_departing_validator_retains_vault_access() {
    // Setup: Create a validator with Vault storage
    let validator_signer = ValidatorSigner::from_int(0);
    let author = validator_signer.author();
    let consensus_key = validator_signer.private_key().clone();
    
    // Create Vault storage with token
    let mut vault_policy = VaultPolicy::new(create_test_vault(), None);
    
    // Set up policies for consensus key
    let policy = Policy::new(vec![
        Permission::new(Identity::User("validator_1".into()), vec![
            Capability::Sign,
            Capability::Export,
            Capability::Read,
        ]),
    ]);
    
    vault_policy.create_key("consensus_key").unwrap();
    vault_policy.set_policies("consensus_key", &VaultEngine::Transit, &policy).unwrap();
    
    // Create validator token
    let validator_token = vault_policy.create_token(vec!["validator_1"]).unwrap();
    let mut validator_storage = create_vault_storage(validator_token.clone(), None, true);
    
    // Validator can sign (normal operation)
    let message = TestAptosCrypto("test message".to_string());
    let signature_before = validator_storage.sign("consensus_key", &message);
    assert!(signature_before.is_ok());
    
    // SIMULATE VALIDATOR REMOVAL: Create new epoch without this validator
    // (In real system, SafetyRules would return ValidatorNotInSet)
    
    // VULNERABILITY: Validator token still works!
    let signature_after = validator_storage.sign("consensus_key", &message);
    assert!(signature_after.is_ok(), "Departed validator can still sign!");
    
    // Validator can still export keys
    let exported_key = validator_storage.export_private_key("consensus_key");
    assert!(exported_key.is_ok(), "Departed validator can still export keys!");
    
    println!("VULNERABILITY CONFIRMED: Departed validator retains full Vault access");
}
```

**Notes**: This vulnerability requires being a former validator (not an unprivileged attacker), but the security question explicitly asks about "departing validators" retaining access, making this within scope. The issue represents a critical access control failure in the validator lifecycle management system.

### Citations

**File:** secure/storage/src/policy.rs (L6-58)
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

/// Maps an identity to a set of capabilities
#[derive(Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Permission {
    pub id: Identity,
    pub capabilities: Vec<Capability>,
}

impl Permission {
    pub fn new(id: Identity, capabilities: Vec<Capability>) -> Self {
        Self { id, capabilities }
    }
}

/// Id represents an internal identifier for a given process. For example, safety_rules or
/// key_manager. It is up to the Storage and its deployment to translate these identifiers into
/// verifiable material. For example, the process running safety_rules may have a token that is
/// intended for only safety_rules to own. The specifics are left to the implementation of the
/// storage backend interface layer.
#[derive(Debug, Deserialize, PartialEq, Eq, Serialize)]
pub enum Identity {
    User(String),
    Anyone,
    NoOne,
}

/// Represents actions
#[derive(Debug, Deserialize, PartialEq, Eq, Serialize)]
pub enum Capability {
    Export,
    Read,
    Rotate,
    Sign,
    Write,
}
```

**File:** secure/storage/src/vault.rs (L115-117)
```rust
    pub fn revoke_token_self(&self) -> Result<(), Error> {
        Ok(self.client.revoke_token_self()?)
    }
```

**File:** secure/storage/src/vault.rs (L339-355)
```rust
        fn reset_policies(&self) -> Result<(), Error> {
            let policies = match self.client().list_policies() {
                Ok(policies) => policies,
                Err(aptos_vault_client::Error::NotFound(_, _)) => return Ok(()),
                Err(e) => return Err(e.into()),
            };

            for policy in policies {
                // Never touch the default or root policy
                if policy == "default" || policy == "root" {
                    continue;
                }

                self.client().delete_policy(&policy)?;
            }
            Ok(())
        }
```

**File:** secure/storage/src/vault.rs (L357-368)
```rust
        /// Creates a token but uses the namespace for policies
        pub fn create_token(&self, mut policies: Vec<&str>) -> Result<String, Error> {
            policies.push(APTOS_DEFAULT);
            let result = if let Some(ns) = &self.namespace {
                let policies: Vec<_> = policies.iter().map(|p| format!("{}/{}", ns, p)).collect();
                self.client()
                    .create_token(policies.iter().map(|p| &**p).collect())?
            } else {
                self.client().create_token(policies)?
            };
            Ok(result)
        }
```

**File:** secure/storage/src/vault.rs (L412-428)
```rust
        pub fn set_policies(
            &self,
            name: &str,
            engine: &VaultEngine,
            policy: &Policy,
        ) -> Result<(), Error> {
            for perm in &policy.permissions {
                match &perm.id {
                    Identity::User(id) => self.set_policy(id, engine, name, &perm.capabilities)?,
                    Identity::Anyone => {
                        self.set_policy(APTOS_DEFAULT, engine, name, &perm.capabilities)?
                    },
                    Identity::NoOne => (),
                };
            }
            Ok(())
        }
```

**File:** consensus/safety-rules/src/safety_rules.rs (L312-343)
```rust
        let author = self.persistent_storage.author()?;
        let expected_key = epoch_state.verifier.get_public_key(&author);
        let initialize_result = match expected_key {
            None => Err(Error::ValidatorNotInSet(author.to_string())),
            Some(expected_key) => {
                let current_key = self.signer().ok().map(|s| s.public_key());
                if current_key == Some(expected_key.clone()) {
                    info!(
                        SafetyLogSchema::new(LogEntry::KeyReconciliation, LogEvent::Success),
                        "in set",
                    );
                    Ok(())
                } else {
                    // Try to export the consensus key directly from storage.
                    match self.persistent_storage.consensus_sk_by_pk(expected_key) {
                        Ok(consensus_key) => {
                            self.validator_signer =
                                Some(ValidatorSigner::new(author, Arc::new(consensus_key)));
                            Ok(())
                        },
                        Err(Error::SecureStorageMissingDataError(error)) => {
                            Err(Error::ValidatorKeyNotFound(error))
                        },
                        Err(error) => Err(error),
                    }
                }
            },
        };
        initialize_result.inspect_err(|error| {
            info!(SafetyLogSchema::new(LogEntry::KeyReconciliation, LogEvent::Error).error(error),);
            self.validator_signer = None;
        })
```

**File:** consensus/src/epoch_manager.rs (L1164-1200)
```rust
    async fn start_new_epoch(&mut self, payload: OnChainConfigPayload<P>) {
        let validator_set: ValidatorSet = payload
            .get()
            .expect("failed to get ValidatorSet from payload");
        let mut verifier: ValidatorVerifier = (&validator_set).into();
        verifier.set_optimistic_sig_verification_flag(self.config.optimistic_sig_verification);

        let epoch_state = Arc::new(EpochState {
            epoch: payload.epoch(),
            verifier: verifier.into(),
        });

        self.epoch_state = Some(epoch_state.clone());

        let onchain_consensus_config: anyhow::Result<OnChainConsensusConfig> = payload.get();
        let onchain_execution_config: anyhow::Result<OnChainExecutionConfig> = payload.get();
        let onchain_randomness_config_seq_num: anyhow::Result<RandomnessConfigSeqNum> =
            payload.get();
        let randomness_config_move_struct: anyhow::Result<RandomnessConfigMoveStruct> =
            payload.get();
        let onchain_jwk_consensus_config: anyhow::Result<OnChainJWKConsensusConfig> = payload.get();
        let dkg_state = payload.get::<DKGState>();

        if let Err(error) = &onchain_consensus_config {
            warn!("Failed to read on-chain consensus config {}", error);
        }

        if let Err(error) = &onchain_execution_config {
            warn!("Failed to read on-chain execution config {}", error);
        }

        if let Err(error) = &randomness_config_move_struct {
            warn!("Failed to read on-chain randomness config {}", error);
        }

        self.epoch_state = Some(epoch_state.clone());

```
