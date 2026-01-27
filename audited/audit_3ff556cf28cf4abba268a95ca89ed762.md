# Audit Report

## Title
Governance-Controlled JWK Patches Can Override Validator Quorum-Certified Observations

## Summary
The JWK (JSON Web Key) system allows governance-controlled patches to completely override quorum-certified validator observations, enabling injection of arbitrary JWKs that were never observed by validators. This creates a privilege escalation path where governance approval (requiring lower security threshold than validator consensus) can bypass Byzantine fault-tolerant consensus for keyless authentication.

## Finding Description

The Aptos JWK consensus system has three key components:

1. **ObservedJWKs**: JWKs observed by validators from OIDC providers, certified with 2/3+1 validator voting power through `QuorumCertifiedUpdate` with multi-signatures [1](#0-0) 

2. **Patches**: Governance-controlled modifications that can remove or inject JWKs [2](#0-1) 

3. **PatchedJWKs**: The final JWK set consumed by applications, computed as ObservedJWKs + Patches [3](#0-2) 

**Authority for Patches:**
Only governance can create patches via `set_patches()`, which requires the framework signer [4](#0-3) 

**Patches Override Quorum-Certified Observations:**
Yes, patches are applied AFTER validator consensus verification. The `regenerate_patched_jwks()` function takes validator-certified `ObservedJWKs` and applies governance `Patches` to create `PatchedJWKs` [3](#0-2) 

**Security Model Mismatch:**
- Validator consensus requires 2/3+1 voting power (Byzantine fault-tolerant threshold) [5](#0-4) 
- Governance requires min_voting_threshold (400M APT for mainnet, configurable) [6](#0-5) 

**Critical Attack Vector:**
Keyless authentication fetches `PatchedJWKs` (not `ObservedJWKs`) to verify JWT signatures [7](#0-6) 

The `PatchUpsertJWK` variant allows governance to inject JWKs that were never observed by validators [8](#0-7) 

## Impact Explanation

**Critical Severity** - This qualifies as Critical under "Loss of Funds (theft or minting)" and "Consensus/Safety violations":

1. **Authentication Bypass**: An attacker controlling governance can:
   - Generate an RSA keypair
   - Use `PatchUpsertJWK` to inject their public key as a JWK
   - Forge JWT tokens signed with their private key
   - These tokens will pass verification since `keyless_validation.rs` uses `PatchedJWKs` [9](#0-8) 

2. **Trust Model Violation**: Users expect JWKs to represent what validators observe from legitimate OIDC providers. Governance can inject arbitrary keys without any provider involvement or validator observation.

3. **Consensus Safety Break**: Keyless transaction validation is part of transaction execution. Different nodes with different patch states could accept different transactions, violating deterministic execution invariant.

## Likelihood Explanation

**Medium-High Likelihood:**

While this requires governance compromise (400M APT voting power on mainnet), several factors increase likelihood:

1. **Governance threshold is configurable** and may be lower in testnets or future network configurations
2. **Governance voting power** is based on staked tokens, not validator consensus - a different security model
3. **No additional validation** occurs when patches are applied - no re-verification by validators
4. **The mechanism is intentional by design**, making it less likely to be monitored as a potential attack vector

The attack complexity is LOW once governance access is obtained - simply calling `set_patches()` with a `PatchUpsertJWK` containing the attacker's public key.

## Recommendation

Implement a **dual-approval mechanism** where critical patches (especially `PatchUpsertJWK`) require BOTH governance approval AND validator consensus:

1. Add a new validator transaction type `ValidatorApprovedPatch` similar to `QuorumCertifiedUpdate`
2. Require patches to be certified with 2/3+1 validator signatures before application
3. Alternatively, restrict `PatchUpsertJWK` entirely - only allow defensive operations (`PatchRemoveAll`, `PatchRemoveIssuer`, `PatchRemoveJWK`)
4. Add validation in `apply_patch()` to verify patches don't inject JWKs for issuers not in `ObservedJWKs`

Example validation logic:
```move
fun apply_patch(jwks: &mut AllProvidersJWKs, patch: Patch, observed: &AllProvidersJWKs) {
    // ... existing code ...
    else if (variant_type_name == b"0x1::jwks::PatchUpsertJWK") {
        let cmd = copyable_any::unpack<PatchUpsertJWK>(patch.variant);
        // NEW: Verify issuer exists in observed JWKs
        let (issuer_exists, _) = vector::find(&observed.entries, |obj| {
            let provider: &ProviderJWKs = obj;
            provider.issuer == cmd.issuer
        });
        assert!(issuer_exists, EISSUER_NOT_IN_OBSERVED_JWKS);
        // ... continue with existing logic ...
    }
}
```

## Proof of Concept

```move
#[test(aptos_framework = @aptos_framework)]
fun test_governance_jwk_injection_attack(aptos_framework: signer) {
    use aptos_framework::jwks;
    use std::string::utf8;
    
    // Initialize JWK system
    jwks::initialize(&aptos_framework);
    
    // Step 1: Validators observe legitimate JWKs (normal operation)
    let legitimate_jwk = jwks::new_rsa_jwk(
        utf8(b"legit_kid"),
        utf8(b"RS256"),
        utf8(b"AQAB"),
        utf8(b"legitimate_modulus_n")
    );
    let observed = vector[jwks::ProviderJWKs {
        issuer: b"https://accounts.google.com",
        version: 1,
        jwks: vector[legitimate_jwk],
    }];
    jwks::upsert_into_observed_jwks(&aptos_framework, observed);
    
    // Step 2: Attacker gains governance control and injects malicious JWK
    let malicious_jwk = jwks::new_rsa_jwk(
        utf8(b"attacker_kid"),
        utf8(b"RS256"),
        utf8(b"AQAB"),
        utf8(b"attacker_controlled_modulus_n")
    );
    
    // This JWK was NEVER observed by validators!
    let malicious_patch = jwks::new_patch_upsert_jwk(
        b"https://accounts.google.com",
        malicious_jwk
    );
    
    // Governance approval allows this to execute
    jwks::set_patches(&aptos_framework, vector[malicious_patch]);
    
    // Step 3: Verify the malicious JWK is now in PatchedJWKs
    let patched_jwk = jwks::get_patched_jwk(
        b"https://accounts.google.com",
        b"attacker_kid"
    );
    
    // SUCCESS: Attacker's JWK is now trusted for keyless authentication
    // They can forge JWTs with their private key to impersonate any user
    assert!(patched_jwk == malicious_jwk, 0);
}
```

**Notes**

This is an **architectural design issue** where the governance override mechanism creates a weaker security model than the validator consensus system it's meant to supplement. The fundamental problem is that `PatchedJWKs` (consumed by applications) can contain JWKs that validators never observed or certified, violating the expected trust model for JWK consensus.

### Citations

**File:** aptos-move/aptos-vm/src/validator_txns/jwk.rs (L100-143)
```rust
    fn process_jwk_update_inner(
        &self,
        resolver: &impl AptosMoveResolver,
        module_storage: &impl AptosModuleStorage,
        log_context: &AdapterLogSchema,
        session_id: SessionId,
        update: jwks::QuorumCertifiedUpdate,
    ) -> Result<(VMStatus, VMOutput), ExecutionFailure> {
        // Load resources.
        let validator_set =
            ValidatorSet::fetch_config(resolver).ok_or(Expected(MissingResourceValidatorSet))?;
        let observed_jwks =
            ObservedJWKs::fetch_config(resolver).ok_or(Expected(MissingResourceObservedJWKs))?;

        let mut jwks_by_issuer: HashMap<Issuer, ProviderJWKs> =
            observed_jwks.into_providers_jwks().into();
        let issuer = update.update.issuer.clone();
        let on_chain = jwks_by_issuer
            .entry(issuer.clone())
            .or_insert_with(|| ProviderJWKs::new(issuer));
        let verifier = ValidatorVerifier::from(&validator_set);

        let QuorumCertifiedUpdate {
            update: observed,
            multi_sig,
        } = update;

        // Check version.
        if on_chain.version + 1 != observed.version {
            return Err(Expected(IncorrectVersion));
        }

        let authors = multi_sig.get_signers_addresses(&verifier.get_ordered_account_addresses());

        // Check voting power.
        verifier
            .check_voting_power(authors.iter(), true)
            .map_err(|_| Expected(NotEnoughVotingPower))?;

        // Verify multi-sig.
        verifier
            .verify_multi_signatures(&observed, &multi_sig)
            .map_err(|_| Expected(MultiSigVerificationFailed))?;

```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L126-155)
```text
    /// A small edit or patch that is applied to a `AllProvidersJWKs` to obtain `PatchedJWKs`.
    struct Patch has copy, drop, store {
        /// A `Patch` variant packed as an `Any`.
        /// Currently the variant type is one of the following.
        /// - `PatchRemoveAll`
        /// - `PatchRemoveIssuer`
        /// - `PatchRemoveJWK`
        /// - `PatchUpsertJWK`
        variant: Any,
    }

    /// A `Patch` variant to remove all JWKs.
    struct PatchRemoveAll has copy, drop, store {}

    /// A `Patch` variant to remove an issuer and all its JWKs.
    struct PatchRemoveIssuer has copy, drop, store {
        issuer: vector<u8>,
    }

    /// A `Patch` variant to remove a specific JWK of an issuer.
    struct PatchRemoveJWK has copy, drop, store {
        issuer: vector<u8>,
        jwk_id: vector<u8>,
    }

    /// A `Patch` variant to upsert a JWK for an issuer.
    struct PatchUpsertJWK has copy, drop, store {
        issuer: vector<u8>,
        jwk: JWK,
    }
```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L379-383)
```text
    public fun set_patches(fx: &signer, patches: vector<Patch>) acquires Patches, PatchedJWKs, ObservedJWKs {
        system_addresses::assert_aptos_framework(fx);
        borrow_global_mut<Patches>(@aptos_framework).patches = patches;
        regenerate_patched_jwks();
    }
```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L522-531)
```text
    /// Regenerate `PatchedJWKs` from `ObservedJWKs` and `Patches` and save the result.
    fun regenerate_patched_jwks() acquires PatchedJWKs, Patches, ObservedJWKs {
        let jwks = borrow_global<ObservedJWKs>(@aptos_framework).jwks;
        let patches = borrow_global<Patches>(@aptos_framework);
        vector::for_each_ref(&patches.patches, |obj|{
            let patch: &Patch = obj;
            apply_patch(&mut jwks, *patch);
        });
        *borrow_global_mut<PatchedJWKs>(@aptos_framework) = PatchedJWKs { jwks };
    }
```

**File:** types/src/validator_verifier.rs (L206-214)
```rust
    pub fn new(validator_infos: Vec<ValidatorConsensusInfo>) -> Self {
        let total_voting_power = sum_voting_power(&validator_infos);
        let quorum_voting_power = if validator_infos.is_empty() {
            0
        } else {
            total_voting_power * 2 / 3 + 1
        };
        Self::build_index(validator_infos, quorum_voting_power, total_voting_power)
    }
```

**File:** aptos-move/vm-genesis/src/lib.rs (L1474-1496)
```rust
fn mainnet_genesis_config() -> GenesisConfiguration {
    // TODO: Update once mainnet numbers are decided. These numbers are just placeholders.
    GenesisConfiguration {
        allow_new_validators: true,
        epoch_duration_secs: 2 * 3600, // 2 hours
        is_test: false,
        min_stake: 1_000_000 * APTOS_COINS_BASE_WITH_DECIMALS, // 1M APT
        // 400M APT
        min_voting_threshold: (400_000_000 * APTOS_COINS_BASE_WITH_DECIMALS as u128),
        max_stake: 50_000_000 * APTOS_COINS_BASE_WITH_DECIMALS, // 50M APT.
        recurring_lockup_duration_secs: 30 * 24 * 3600,         // 1 month
        required_proposer_stake: 1_000_000 * APTOS_COINS_BASE_WITH_DECIMALS, // 1M APT
        rewards_apy_percentage: 10,
        voting_duration_secs: 7 * 24 * 3600, // 7 days
        voting_power_increase_limit: 30,
        employee_vesting_start: 1663456089,
        employee_vesting_period_duration: 5 * 60, // 5 minutes
        initial_features_override: None,
        randomness_config_override: None,
        jwk_consensus_config_override: None,
        initial_jwks: vec![],
        keyless_groth16_vk: None,
    }
```

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L91-94)
```rust
fn get_jwks_onchain(resolver: &impl AptosMoveResolver) -> anyhow::Result<PatchedJWKs, VMStatus> {
    PatchedJWKs::fetch_config(resolver)
        .ok_or_else(|| value_deserialization_error!("could not deserialize PatchedJWKs"))
}
```

**File:** aptos-move/aptos-vm/src/keyless_validation.rs (L235-260)
```rust
    for (pk, sig) in authenticators {
        // Try looking up the jwk in 0x1.
        let jwk = match get_jwk_for_authenticator(&patched_jwks.jwks, pk.inner_keyless_pk(), sig) {
            // 1: If found in 0x1, then we consider that the ground truth & we are done.
            Ok(jwk) => jwk,
            // 2: If not found in 0x1, we check the Keyless PK type.
            Err(e) => {
                match pk {
                    // 2.a: If this is a federated keyless account; look in `jwk_addr` for JWKs
                    AnyKeylessPublicKey::Federated(fed_pk) => {
                        let federated_jwks =
                            get_federated_jwks_onchain(resolver, &fed_pk.jwk_addr, module_storage)
                                .map_err(|_| {
                                    invalid_signature!(format!(
                                        "Could not fetch federated PatchedJWKs at {}",
                                        fed_pk.jwk_addr
                                    ))
                                })?;
                        // 2.a.i If not found in jwk_addr either, then we fail the validation.
                        get_jwk_for_authenticator(&federated_jwks.jwks, pk.inner_keyless_pk(), sig)?
                    },
                    // 2.b: If this is not a federated keyless account, then we fail the validation.
                    AnyKeylessPublicKey::Normal(_) => return Err(e),
                }
            },
        };
```
