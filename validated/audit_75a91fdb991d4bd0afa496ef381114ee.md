# Audit Report

## Title
Epoch-Crossing JWK Updates Enable OIDC Provider Configuration State Divergence

## Summary
The JWK consensus mechanism lacks epoch validation for `ObservedJWKUpdate` validator transactions, allowing stale JWK updates from previous OIDC provider configurations to be applied after rapid config_url changes. This violates the protocol invariant that `ObservedJWKs` accurately reflects the current `SupportedOIDCProviders` configuration, potentially causing authentication failures in keyless account systems.

## Finding Description

The vulnerability exists in the asymmetric validation design between DKG and JWK validator transactions during epoch transitions when OIDC provider configurations change.

**Root Cause - Missing Epoch Metadata**: The `QuorumCertifiedUpdate` structure contains only JWK data and a multi-signature, with no epoch information: [1](#0-0) 

This contrasts with DKG transactions, which include epoch metadata in `DKGTranscriptMetadata`: [2](#0-1) 

**Validation Gap**: DKG transactions perform explicit epoch validation during VM processing: [3](#0-2) 

However, JWK validation in `process_jwk_update_inner()` only verifies version number, voting power, and multi-signature—with no epoch or configuration URL validation: [4](#0-3) 

**Missing Configuration Linkage**: The VM processing loads `ObservedJWKs` but does NOT load or validate against `SupportedOIDCProviders`, failing to ensure the JWKs match the current provider configuration: [5](#0-4) 

**Epoch Transition Behavior**: When OIDC provider configurations change via `upsert_oidc_provider_for_next_epoch()` followed by `reconfigure()`, the `on_new_epoch()` function only updates `SupportedOIDCProviders` without resetting or invalidating `ObservedJWKs`: [6](#0-5) 

**Attack Scenario**:
1. **Epoch N**: OIDC provider has `config_url = URL_A`, validators fetch JWKs and reach quorum on version 6
2. Validator transaction T is created and placed in the pool with `Topic::JWK_CONSENSUS`: [7](#0-6) 

3. Governance executes `upsert_oidc_provider_for_next_epoch()` with `config_url = URL_B` and triggers reconfiguration: [8](#0-7) 

4. Epoch transition occurs via `reconfiguration_with_dkg::finish()` which calls `jwks::on_new_epoch()`: [9](#0-8) 

5. **Epoch N+1** begins with `SupportedOIDCProviders` pointing to URL_B, but `ObservedJWKs` unchanged at version 5

6. If transaction T is pulled from the pool and processed (the pool uses only hash-based filtering, no epoch filtering): [10](#0-9) 

7. The update passes all validations despite being from URL_A, and `ObservedJWKs` is updated to version 6 with JWKs from URL_A

8. **State Divergence**: `SupportedOIDCProviders` shows URL_B but `ObservedJWKs` contains JWKs from URL_A

## Impact Explanation

This is a **Medium Severity** protocol invariant violation per Aptos bug bounty criteria for "Limited Protocol Violations" requiring manual intervention.

**Protocol Invariant Broken**: The system violates the fundamental invariant that on-chain `ObservedJWKs` reflects the JWKs from the current OIDC provider `config_url` specified in `SupportedOIDCProviders`. This breaks the assumed synchronization between these two critical authentication resources.

**Authentication Impact**:
- Applications using keyless authentication query `ObservedJWKs` to verify JWT signatures based on the `SupportedOIDCProviders` configuration
- State divergence causes JWT validation to operate on JWKs from the wrong provider URL
- In emergency scenarios where governance quickly switches from a compromised provider URL to a backup, the malicious JWKs could persist in `ObservedJWKs`

**Operational Impact**:
- Users may experience authentication failures (DoS) when their JWTs cannot be validated
- The system could accept JWTs signed with keys from an outdated or compromised provider
- Manual intervention would be required to detect and correct the state inconsistency

## Likelihood Explanation

**Moderate to High Likelihood** in production environments:

- **Triggering Condition**: Legitimate governance proposals updating OIDC provider configurations during active JWK consensus rounds
- **Common Scenarios**: 
  - Emergency response to compromised OIDC providers requiring immediate URL switches
  - Provider URL migrations (DNS changes, domain transfers)
  - Infrastructure updates requiring config_url modifications
- **No Malicious Intent Required**: The vulnerability triggers through normal operational actions, not attacks
- **Design Flaw, Not Race Condition**: The lack of epoch validation is a protocol design issue—validator transactions created in epoch N can be validly applied in epoch N+1 without any checks

While governance access is required to change configurations, the bug lies in the protocol's validation logic, not in governance compromise.

## Recommendation

Implement epoch validation for JWK validator transactions to match the DKG validation pattern:

1. **Add epoch field to `QuorumCertifiedUpdate`**:
   - Include epoch metadata similar to `DKGTranscriptMetadata`
   - Validators should sign the epoch along with the JWK update

2. **Implement epoch validation in VM processing**:
   - In `process_jwk_update_inner()`, fetch `ConfigurationResource` 
   - Validate that `update.epoch == config_resource.epoch()`
   - Return `EpochNotCurrent` error for mismatched epochs

3. **Add configuration consistency check**:
   - Load both `ObservedJWKs` and `SupportedOIDCProviders`
   - Verify the update's issuer exists in current `SupportedOIDCProviders`
   - Optionally validate the update was fetched from the current `config_url`

4. **Consider resetting ObservedJWKs on config changes**:
   - In `on_new_epoch()`, when `SupportedOIDCProviders` changes, consider invalidating or resetting affected issuers in `ObservedJWKs`

## Proof of Concept

A complete PoC would require:
1. Setting up a test governance proposal that changes OIDC provider config_url
2. Creating a JWK validator transaction before the epoch transition
3. Triggering reconfiguration
4. Demonstrating the validator transaction is accepted in the new epoch despite config mismatch

The vulnerability is evident from the code structure: the validation path in `process_jwk_update_inner()` lacks the epoch check present in `process_dkg_result_inner()`, and the transaction pool filtering mechanism provides no epoch-based protection for stale validator transactions crossing epoch boundaries.

### Citations

**File:** types/src/jwks/mod.rs (L303-307)
```rust
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, CryptoHasher, BCSCryptoHash)]
pub struct QuorumCertifiedUpdate {
    pub update: ProviderJWKs,
    pub multi_sig: AggregateSignature,
}
```

**File:** types/src/dkg/mod.rs (L28-32)
```rust
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq, CryptoHasher, BCSCryptoHash)]
pub struct DKGTranscriptMetadata {
    pub epoch: u64,
    pub author: AccountAddress,
}
```

**File:** aptos-move/aptos-vm/src/validator_txns/dkg.rs (L100-102)
```rust
        if dkg_node.metadata.epoch != config_resource.epoch() {
            return Err(Expected(EpochNotCurrent));
        }
```

**File:** aptos-move/aptos-vm/src/validator_txns/jwk.rs (L108-120)
```rust
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
```

**File:** aptos-move/aptos-vm/src/validator_txns/jwk.rs (L128-142)
```rust
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

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L317-330)
```text
    public fun upsert_oidc_provider_for_next_epoch(fx: &signer, name: vector<u8>, config_url: vector<u8>): Option<vector<u8>> acquires SupportedOIDCProviders {
        system_addresses::assert_aptos_framework(fx);

        let provider_set = if (config_buffer::does_exist<SupportedOIDCProviders>()) {
            config_buffer::extract_v2<SupportedOIDCProviders>()
        } else {
            *borrow_global<SupportedOIDCProviders>(@aptos_framework)
        };

        let old_config_url = remove_oidc_provider_internal(&mut provider_set, name);
        vector::push_back(&mut provider_set.providers, OIDCProvider { name, config_url });
        config_buffer::upsert(provider_set);
        old_config_url
    }
```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L366-376)
```text
    public(friend) fun on_new_epoch(framework: &signer) acquires SupportedOIDCProviders {
        system_addresses::assert_aptos_framework(framework);
        if (config_buffer::does_exist<SupportedOIDCProviders>()) {
            let new_config = config_buffer::extract_v2<SupportedOIDCProviders>();
            if (exists<SupportedOIDCProviders>(@aptos_framework)) {
                *borrow_global_mut<SupportedOIDCProviders>(@aptos_framework) = new_config;
            } else {
                move_to(framework, new_config);
            }
        }
    }
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L335-343)
```rust
                let txn = ValidatorTransaction::ObservedJWKUpdate(update.clone());
                let vtxn_guard =
                    self.vtxn_pool
                        .put(Topic::JWK_CONSENSUS(issuer.clone()), Arc::new(txn), None);
                state.consensus_state = ConsensusState::Finished {
                    vtxn_guard,
                    my_proposal: my_proposal.clone(),
                    quorum_certified: update.clone(),
                };
```

**File:** aptos-move/framework/aptos-framework/sources/reconfiguration_with_dkg.move (L46-61)
```text
    public(friend) fun finish(framework: &signer) {
        system_addresses::assert_aptos_framework(framework);
        dkg::try_clear_incomplete_session(framework);
        consensus_config::on_new_epoch(framework);
        execution_config::on_new_epoch(framework);
        gas_schedule::on_new_epoch(framework);
        std::version::on_new_epoch(framework);
        features::on_new_epoch(framework);
        jwk_consensus_config::on_new_epoch(framework);
        jwks::on_new_epoch(framework);
        keyless_account::on_new_epoch(framework);
        randomness_config_seqnum::on_new_epoch(framework);
        randomness_config::on_new_epoch(framework);
        randomness_api_v0_config::on_new_epoch(framework);
        reconfiguration::reconfigure();
    }
```

**File:** crates/validator-transaction-pool/src/lib.rs (L15-35)
```rust
pub enum TransactionFilter {
    PendingTxnHashSet(HashSet<HashValue>),
}

impl TransactionFilter {
    pub fn no_op() -> Self {
        Self::PendingTxnHashSet(HashSet::new())
    }
}

impl TransactionFilter {
    pub fn empty() -> Self {
        Self::PendingTxnHashSet(HashSet::new())
    }

    pub fn should_exclude(&self, txn: &ValidatorTransaction) -> bool {
        match self {
            TransactionFilter::PendingTxnHashSet(set) => set.contains(&txn.hash()),
        }
    }
}
```
