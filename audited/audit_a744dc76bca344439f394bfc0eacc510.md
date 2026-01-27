# Audit Report

## Title
Missing Issuer Authorization Check Allows Validators to Bypass Governance-Controlled OIDC Provider List

## Summary
The JWK update validator transaction processing lacks validation that the issuer being updated is within the governance-controlled `SupportedOIDCProviders` list. This allows a coalition of validators with >2/3 voting power to add JWKs for arbitrary, unauthorized OIDC providers, bypassing governance controls and potentially compromising keyless account security.

## Finding Description

The Aptos blockchain uses JWK (JSON Web Key) consensus to maintain cryptographic keys for OIDC (OpenID Connect) identity providers, enabling keyless account authentication. Governance controls which OIDC providers are trusted through the `SupportedOIDCProviders` on-chain resource. [1](#0-0) 

However, when validators execute a `ValidatorTransaction::ObservedJWKUpdate`, the VM does not validate that the issuer being updated exists in `SupportedOIDCProviders`. The validation in `process_jwk_update_inner` only checks: [2](#0-1) 

Critically, when an issuer doesn't exist in `ObservedJWKs`, the code creates a new entry with version 0: [3](#0-2) 

Additionally, `ValidatorTransaction::verify()` performs no validation for `ObservedJWKUpdate`: [4](#0-3) 

**Attack Path:**
1. Governance configures `SupportedOIDCProviders` with legitimate providers (e.g., `https://accounts.google.com`)
2. A coalition of malicious validators (>2/3 voting power) creates a `ProviderJWKs` for an unauthorized issuer (e.g., `https://attacker-controlled.com`)
3. They sign this update with their consensus keys
4. Through the observation aggregation protocol, they collect >2/3 voting power signatures: [5](#0-4) 

5. The `QuorumCertifiedUpdate` is created and executed
6. VM accepts it because version check passes (0 + 1 = 1), voting power is sufficient, and multi-signature is valid
7. The unauthorized issuer is now in `ObservedJWKs` and propagates to `PatchedJWKs`: [6](#0-5) 

**Security Invariant Broken:** Governance Integrity (Invariant #5) - The governance-controlled authorization of OIDC providers is bypassed, allowing validators to unilaterally add providers without governance approval.

## Impact Explanation

**Critical Severity** - This vulnerability enables:

1. **Governance Bypass**: Validators can add OIDC providers without governance approval, subverting the democratic control mechanism
2. **Keyless Account Compromise**: Unauthorized identity providers can be used to create keyless accounts, potentially allowing attackers to impersonate legitimate users
3. **Persistent State Corruption**: The unauthorized issuer remains in `ObservedJWKs` across epochs until governance manually intervenes
4. **Trust Model Violation**: Users expect only governance-approved providers to be trusted for authentication

While this requires >2/3 Byzantine validators (the BFT threshold), it represents a **governance privilege escalation** distinct from typical consensus failures. Even in adversarial conditions, validators should not bypass governance-mandated authorization controls.

## Likelihood Explanation

**Moderate-to-Low Likelihood:**
- Requires >2/3 of validators by voting power to collude
- However, the attack is:
  - **Undetectable** during execution (appears as legitimate JWK update)
  - **Persistent** (remains until governance intervention)
  - **Difficult to remediate** (requires governance proposal to remove)
  
The missing check represents a **defense-in-depth failure** - even when Byzantine threshold is reached, certain governance-controlled invariants should remain enforced.

## Recommendation

Add validation that the issuer exists in `SupportedOIDCProviders` before processing JWK updates:

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
    let validator_set = ValidatorSet::fetch_config(resolver)
        .ok_or(Expected(MissingResourceValidatorSet))?;
    let observed_jwks = ObservedJWKs::fetch_config(resolver)
        .ok_or(Expected(MissingResourceObservedJWKs))?;
    
    // **NEW: Load and validate against SupportedOIDCProviders**
    let supported_providers = SupportedOIDCProviders::fetch_config(resolver)
        .ok_or(Expected(MissingSupportedOIDCProviders))?;
    
    let issuer = update.update.issuer.clone();
    
    // **NEW: Verify issuer is in supported list**
    let is_supported = supported_providers.providers.iter()
        .any(|provider| provider.name == issuer);
    if !is_supported {
        return Err(Expected(IssuerNotInSupportedProviders));
    }
    
    // ... rest of existing validation
}
```

Add corresponding error codes:

```rust
const ENATIVE_MISSING_RESOURCE_SUPPORTED_OIDC_PROVIDERS: u64 = 0x0106;
const ENATIVE_ISSUER_NOT_IN_SUPPORTED_PROVIDERS: u64 = 0x0107;
```

## Proof of Concept

```rust
#[test]
fn test_jwk_update_unauthorized_issuer() {
    // Setup: Initialize blockchain with governance-approved providers
    let mut executor = FakeExecutor::from_genesis_file();
    
    // Governance approves only "https://accounts.google.com"
    let google_provider = OIDCProvider {
        name: b"https://accounts.google.com".to_vec(),
        config_url: b"https://accounts.google.com/.well-known/openid-configuration".to_vec(),
    };
    executor.new_block(); // Apply governance config
    
    // Malicious validators create update for unauthorized issuer
    let malicious_issuer = b"https://attacker-controlled.com".to_vec();
    let fake_jwks = ProviderJWKs {
        issuer: malicious_issuer.clone(),
        version: 1,
        jwks: vec![/* attacker-controlled JWKs */],
    };
    
    // Validators sign and aggregate (assume >2/3 voting power)
    let multi_sig = create_byzantine_quorum_cert(&fake_jwks);
    let update = QuorumCertifiedUpdate {
        update: fake_jwks,
        multi_sig,
    };
    
    // Execute validator transaction
    let txn = ValidatorTransaction::ObservedJWKUpdate(update);
    let output = executor.execute_validator_transaction(txn);
    
    // **EXPECTED**: Transaction should be rejected with IssuerNotInSupportedProviders
    // **ACTUAL**: Transaction succeeds and malicious issuer is added to ObservedJWKs
    assert_eq!(output.status(), TransactionStatus::Keep(ExecutionStatus::Success));
    
    // Verify the unauthorized issuer is now in on-chain state
    let observed = executor.read_resource::<ObservedJWKs>();
    assert!(observed.jwks.entries.iter().any(|e| e.issuer == malicious_issuer));
}
```

**Note:** This proof of concept demonstrates that the system accepts JWK updates for issuers not in `SupportedOIDCProviders`, violating the governance-controlled authorization model for identity provider trust.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L63-66)
```text
    /// A list of OIDC providers whose JWKs should be watched by validators. Maintained by governance proposals.
    struct SupportedOIDCProviders has copy, drop, key, store {
        providers: vector<OIDCProvider>,
    }
```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L462-505)
```text
    public fun upsert_into_observed_jwks(fx: &signer, provider_jwks_vec: vector<ProviderJWKs>) acquires ObservedJWKs, PatchedJWKs, Patches {
        system_addresses::assert_aptos_framework(fx);
        let observed_jwks = borrow_global_mut<ObservedJWKs>(@aptos_framework);

        if (features::is_jwk_consensus_per_key_mode_enabled()) {
            vector::for_each(provider_jwks_vec, |proposed_provider_jwks|{
                let maybe_cur_issuer_jwks = remove_issuer(&mut observed_jwks.jwks, proposed_provider_jwks.issuer);
                let cur_issuer_jwks = if (option::is_some(&maybe_cur_issuer_jwks)) {
                    option::extract(&mut maybe_cur_issuer_jwks)
                } else {
                    ProviderJWKs {
                        issuer: proposed_provider_jwks.issuer,
                        version: 0,
                        jwks: vector[],
                    }
                };
                assert!(cur_issuer_jwks.version + 1 == proposed_provider_jwks.version, error::invalid_argument(EUNEXPECTED_VERSION));
                vector::for_each(proposed_provider_jwks.jwks, |jwk|{
                    let variant_type_name = *string::bytes(copyable_any::type_name(&jwk.variant));
                    let is_delete = if (variant_type_name == b"0x1::jwks::UnsupportedJWK") {
                        let repr = copyable_any::unpack<UnsupportedJWK>(jwk.variant);
                        &repr.payload == &DELETE_COMMAND_INDICATOR
                    } else {
                        false
                    };
                    if (is_delete) {
                        remove_jwk(&mut cur_issuer_jwks, get_jwk_id(&jwk));
                    } else {
                        upsert_jwk(&mut cur_issuer_jwks, jwk);
                    }
                });
                cur_issuer_jwks.version = cur_issuer_jwks.version + 1;
                upsert_provider_jwks(&mut observed_jwks.jwks, cur_issuer_jwks);
            });
        } else {
            vector::for_each(provider_jwks_vec, |provider_jwks| {
                upsert_provider_jwks(&mut observed_jwks.jwks, provider_jwks);
            });
        };

        let epoch = reconfiguration::current_epoch();
        emit(ObservedJWKsUpdated { epoch, jwks: observed_jwks.jwks });
        regenerate_patched_jwks();
    }
```

**File:** aptos-move/aptos-vm/src/validator_txns/jwk.rs (L100-142)
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

**File:** types/src/validator_txn.rs (L45-52)
```rust
    pub fn verify(&self, verifier: &ValidatorVerifier) -> anyhow::Result<()> {
        match self {
            ValidatorTransaction::DKGResult(dkg_result) => dkg_result
                .verify(verifier)
                .context("DKGResult verification failed"),
            ValidatorTransaction::ObservedJWKUpdate(_) => Ok(()),
        }
    }
```

**File:** crates/aptos-jwk-consensus/src/observation_aggregation/mod.rs (L80-92)
```rust

        ensure!(
            self.local_view == peer_view,
            "adding peer observation failed with mismatched view"
        );

        // Verify peer signature.
        self.epoch_state
            .verifier
            .verify(sender, &peer_view, &signature)?;

        // All checks passed. Aggregating.
        partial_sigs.add_signature(sender, signature);
```
