# Audit Report

## Title
Inconsistent Feature Flag Fallback Handling Creates Consensus Disagreement Risk During JWK Consensus Migration

## Summary
When `OnChainJWKConsensusConfig` is not yet initialized and the `Features` config fails to load, the consensus layer defaults JWK consensus to "Off" while the JWK manager component assumes it's "On" (via `Features::default()`). This inconsistency causes validator nodes to reject valid proposals containing `ObservedJWKUpdate` validator transactions, leading to consensus participation failures.

## Finding Description

During the migration period when `OnChainJWKConsensusConfig` is not yet initialized on-chain, the codebase has a fallback mechanism that constructs an equivalent config from the deprecated `Features` flag and `SupportedOIDCProviders`. [1](#0-0) 

However, when `Features` fails to load (due to deserialization errors, storage corruption, or database issues), two different code paths handle this failure inconsistently:

**Path 1: consensus/src/epoch_manager.rs (Round Manager)**

The consensus epoch manager uses `.ok()` to convert the Features loading error to `None`: [2](#0-1) 

This `None` value is then passed to the `From` implementation that defaults to `OnChainJWKConsensusConfig::Off` when Features is None: [3](#0-2) 

**Path 2: aptos-jwk-consensus/src/epoch_manager.rs (JWK Manager)**

The JWK epoch manager uses `unwrap_or_default()` when loading Features, which creates `Features::default()`: [4](#0-3) 

The `Features::default()` implementation enables all default features, including `JWK_CONSENSUS`: [5](#0-4) [6](#0-5) 

When the new config fails to load, this fallback path checks if JWK_CONSENSUS is enabled in Features: [7](#0-6) 

**Critical Consequence:**

When proposals containing `ObservedJWKUpdate` validator transactions arrive, the round manager validates them using `is_vtxn_expected()`: [8](#0-7) 

The validation checks whether the validator transaction type is expected based on the configuration: [9](#0-8) 

If `jwk_consensus_config` is incorrectly set to `Off` due to Features loading failure, the node will reject valid proposals with "unexpected validator txn" error, causing it to fail consensus participation.

## Impact Explanation

This qualifies as **High Severity** per Aptos bug bounty criteria:

- **Validator node slowdowns**: Affected nodes cannot participate in consensus when they reject proposals containing `ObservedJWKUpdate` transactions. The node must wait for epoch transition or manual intervention to recover.

- **Consensus participation failures**: Affected validators cannot vote on proposals containing JWK updates, reducing the effective voting power available for consensus and potentially impacting block finalization times.

- **Network partition risk**: If multiple validators experience Features loading failures simultaneously (e.g., during software upgrades with migration issues or storage corruption), a subset of the validator set could become unable to participate in consensus, potentially affecting network liveness.

The issue creates operational inconsistency where validators processing identical on-chain state diverge in their proposal acceptance decisions based on whether their local Features config loaded successfully.

## Likelihood Explanation

**Likelihood: Low to Medium**

The vulnerability requires two preconditions:
1. System in migration period (OnChainJWKConsensusConfig not yet initialized)
2. Features config fails loading (storage corruption, deserialization error, I/O failure)

While Features failures are uncommon in normal operation, they can occur during:
- Software upgrades with schema changes
- State sync issues causing incomplete config data  
- Storage corruption or hardware failures
- Race conditions during epoch transitions
- Migration deployment where OnChainJWKConsensusConfig rollout is incomplete

The inconsistency is deterministic once triggered - it will reliably cause the affected node to reject proposals. This is a **logic vulnerability** in error handling, not an attacker-exploitable issue.

## Recommendation

Use consistent error handling for Features loading in both code paths. The consensus epoch manager should use the same fallback behavior as the JWK manager:

```rust
// In consensus/src/epoch_manager.rs::equivalent_jwk_consensus_config_from_deprecated_resources
fn equivalent_jwk_consensus_config_from_deprecated_resources(
    payload: &OnChainConfigPayload<P>,
) -> OnChainJWKConsensusConfig {
    // Change from .ok() to .unwrap_or_default() for consistency
    let features = payload.get::<Features>().unwrap_or_default();
    let oidc_providers = payload.get::<SupportedOIDCProviders>().ok();
    OnChainJWKConsensusConfig::from((Some(features), oidc_providers))
}
```

Alternatively, both paths should explicitly handle the error case with the same default behavior, or log a warning and use a well-defined fallback strategy.

## Proof of Concept

The vulnerability can be demonstrated by:

1. Setting up a network in migration state (OnChainJWKConsensusConfig not initialized)
2. Simulating Features loading failure by corrupting the serialized Features resource
3. Observing that consensus epoch manager creates jwk_consensus_config = Off
4. Observing that JWK epoch manager starts with jwk_manager_should_run = true (if vtxn enabled)
5. When proposals with ObservedJWKUpdate arrive, round manager rejects them with "unexpected validator txn"
6. The affected node fails to participate in consensus for those proposals

The inconsistency is evident from code inspection without requiring a full reproduction, as the two paths demonstrably use different error handling strategies (`.ok()` vs `.unwrap_or_default()`) for the same configuration.

### Citations

**File:** consensus/src/epoch_manager.rs (L1223-1226)
```rust
        let jwk_consensus_config = onchain_jwk_consensus_config.unwrap_or_else(|_| {
            // `jwk_consensus_config` not yet initialized, falling back to the old configs.
            Self::equivalent_jwk_consensus_config_from_deprecated_resources(&payload)
        });
```

**File:** consensus/src/epoch_manager.rs (L1963-1969)
```rust
    fn equivalent_jwk_consensus_config_from_deprecated_resources(
        payload: &OnChainConfigPayload<P>,
    ) -> OnChainJWKConsensusConfig {
        let features = payload.get::<Features>().ok();
        let oidc_providers = payload.get::<SupportedOIDCProviders>().ok();
        OnChainJWKConsensusConfig::from((features, oidc_providers))
    }
```

**File:** types/src/on_chain_config/jwk_consensus_config.rs (L112-131)
```rust
impl From<(Option<Features>, Option<SupportedOIDCProviders>)> for OnChainJWKConsensusConfig {
    fn from(
        (features, supported_oidc_providers): (Option<Features>, Option<SupportedOIDCProviders>),
    ) -> Self {
        if let Some(features) = features {
            if features.is_enabled(FeatureFlag::JWK_CONSENSUS) {
                let oidc_providers = supported_oidc_providers
                    .unwrap_or_default()
                    .providers
                    .into_iter()
                    .filter_map(|deprecated| OIDCProvider::try_from(deprecated).ok())
                    .collect();
                OnChainJWKConsensusConfig::V1(ConfigV1 { oidc_providers })
            } else {
                OnChainJWKConsensusConfig::Off
            }
        } else {
            OnChainJWKConsensusConfig::Off
        }
    }
```

**File:** crates/aptos-jwk-consensus/src/epoch_manager.rs (L172-172)
```rust
        let features = payload.get::<Features>().unwrap_or_default();
```

**File:** crates/aptos-jwk-consensus/src/epoch_manager.rs (L177-194)
```rust
        let (jwk_manager_should_run, oidc_providers) = match jwk_consensus_config {
            Ok(config) => {
                let should_run =
                    config.jwk_consensus_enabled() && onchain_consensus_config.is_vtxn_enabled();
                let providers = config
                    .oidc_providers_cloned()
                    .into_iter()
                    .map(jwks::OIDCProvider::from)
                    .collect();
                (should_run, Some(SupportedOIDCProviders { providers }))
            },
            Err(_) => {
                //TODO: remove this case once the framework change of this commit is published.
                let should_run = features.is_enabled(FeatureFlag::JWK_CONSENSUS)
                    && onchain_consensus_config.is_vtxn_enabled();
                let providers = payload.get::<SupportedOIDCProviders>().ok();
                (should_run, providers)
            },
```

**File:** types/src/on_chain_config/aptos_features.rs (L171-221)
```rust
    pub fn default_features() -> Vec<Self> {
        vec![
            FeatureFlag::CODE_DEPENDENCY_CHECK,
            FeatureFlag::TREAT_FRIEND_AS_PRIVATE,
            FeatureFlag::SHA_512_AND_RIPEMD_160_NATIVES,
            FeatureFlag::APTOS_STD_CHAIN_ID_NATIVES,
            // Feature flag V6 is used to enable metadata v1 format and needs to stay on, even
            // if we enable a higher version.
            FeatureFlag::VM_BINARY_FORMAT_V6,
            FeatureFlag::VM_BINARY_FORMAT_V7,
            FeatureFlag::MULTI_ED25519_PK_VALIDATE_V2_NATIVES,
            FeatureFlag::BLAKE2B_256_NATIVE,
            FeatureFlag::RESOURCE_GROUPS,
            FeatureFlag::MULTISIG_ACCOUNTS,
            FeatureFlag::DELEGATION_POOLS,
            FeatureFlag::CRYPTOGRAPHY_ALGEBRA_NATIVES,
            FeatureFlag::BLS12_381_STRUCTURES,
            FeatureFlag::ED25519_PUBKEY_VALIDATE_RETURN_FALSE_WRONG_LENGTH,
            FeatureFlag::STRUCT_CONSTRUCTORS,
            FeatureFlag::PERIODICAL_REWARD_RATE_DECREASE,
            FeatureFlag::PARTIAL_GOVERNANCE_VOTING,
            FeatureFlag::_SIGNATURE_CHECKER_V2,
            FeatureFlag::STORAGE_SLOT_METADATA,
            FeatureFlag::CHARGE_INVARIANT_VIOLATION,
            FeatureFlag::DELEGATION_POOL_PARTIAL_GOVERNANCE_VOTING,
            FeatureFlag::APTOS_UNIQUE_IDENTIFIERS,
            FeatureFlag::GAS_PAYER_ENABLED,
            FeatureFlag::BULLETPROOFS_NATIVES,
            FeatureFlag::SIGNER_NATIVE_FORMAT_FIX,
            FeatureFlag::MODULE_EVENT,
            FeatureFlag::EMIT_FEE_STATEMENT,
            FeatureFlag::STORAGE_DELETION_REFUND,
            FeatureFlag::SIGNATURE_CHECKER_V2_SCRIPT_FIX,
            FeatureFlag::AGGREGATOR_V2_API,
            FeatureFlag::SAFER_RESOURCE_GROUPS,
            FeatureFlag::SAFER_METADATA,
            FeatureFlag::SINGLE_SENDER_AUTHENTICATOR,
            FeatureFlag::SPONSORED_AUTOMATIC_ACCOUNT_V1_CREATION,
            FeatureFlag::FEE_PAYER_ACCOUNT_OPTIONAL,
            FeatureFlag::AGGREGATOR_V2_DELAYED_FIELDS,
            FeatureFlag::CONCURRENT_TOKEN_V2,
            FeatureFlag::LIMIT_MAX_IDENTIFIER_LENGTH,
            FeatureFlag::OPERATOR_BENEFICIARY_CHANGE,
            FeatureFlag::BN254_STRUCTURES,
            FeatureFlag::RESOURCE_GROUPS_SPLIT_IN_VM_CHANGE_SET,
            FeatureFlag::COMMISSION_CHANGE_DELEGATION_POOL,
            FeatureFlag::WEBAUTHN_SIGNATURE,
            FeatureFlag::KEYLESS_ACCOUNTS,
            FeatureFlag::FEDERATED_KEYLESS,
            FeatureFlag::KEYLESS_BUT_ZKLESS_ACCOUNTS,
            FeatureFlag::JWK_CONSENSUS,
```

**File:** types/src/on_chain_config/aptos_features.rs (L287-297)
```rust
impl Default for Features {
    fn default() -> Self {
        let mut features = Features {
            features: vec![0; 5],
        };

        for feature in FeatureFlag::default_features() {
            features.enable(feature);
        }
        features
    }
```

**File:** consensus/src/round_manager.rs (L1126-1137)
```rust
        if let Some(vtxns) = proposal.validator_txns() {
            for vtxn in vtxns {
                let vtxn_type_name = vtxn.type_name();
                ensure!(
                    is_vtxn_expected(&self.randomness_config, &self.jwk_consensus_config, vtxn),
                    "unexpected validator txn: {:?}",
                    vtxn_type_name
                );
                vtxn.verify(self.epoch_state.verifier.as_ref())
                    .context(format!("{} verify failed", vtxn_type_name))?;
            }
        }
```

**File:** consensus/src/util/mod.rs (L15-24)
```rust
pub fn is_vtxn_expected(
    randomness_config: &OnChainRandomnessConfig,
    jwk_consensus_config: &OnChainJWKConsensusConfig,
    vtxn: &ValidatorTransaction,
) -> bool {
    match vtxn {
        ValidatorTransaction::DKGResult(_) => randomness_config.randomness_enabled(),
        ValidatorTransaction::ObservedJWKUpdate(_) => jwk_consensus_config.jwk_consensus_enabled(),
    }
}
```
