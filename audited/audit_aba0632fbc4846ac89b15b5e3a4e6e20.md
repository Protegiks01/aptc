# Audit Report

## Title
Consensus Fork Vulnerability During JWK Config Version Migration Due to Inconsistent Fallback Behavior

## Summary
When introducing a new version (V2) of `OnChainJWKConsensusConfig`, validators running different software versions will disagree on whether JWK consensus is enabled, causing them to reject each other's blocks and resulting in a consensus fork that requires manual intervention or hard fork to resolve.

## Finding Description

The `OnChainJWKConsensusConfig` enum uses a custom deserialization mechanism that returns an error for unknown variant types. When deserialization fails, the consensus layer falls back to checking deprecated `Features` and `SupportedOIDCProviders` resources to construct an equivalent config. [1](#0-0) [2](#0-1) 

The fallback mechanism constructs a config based on the deprecated `JWK_CONSENSUS` feature flag: [3](#0-2) 

**Attack Scenario:**

1. All validators initially run version N, which recognizes `Off` and `V1` variants
2. A new version N+1 is released introducing `V2(ConfigV2)` with new semantics (e.g., a toggle field to temporarily disable JWK consensus)
3. Some validators upgrade to N+1 while others remain on N
4. A governance proposal updates the on-chain config to `V2 { enabled: false }` to temporarily disable JWK consensus
5. At the next epoch boundary:
   - **Validators on N+1**: Successfully deserialize V2, `jwk_consensus_enabled()` returns `false`
   - **Validators on N**: Fail to deserialize V2 (unknown variant), fall back to checking `FeatureFlag::JWK_CONSENSUS`
   - If the deprecated feature flag is still enabled, the fallback creates `V1`, and `jwk_consensus_enabled()` returns `true`

6. The JWK manager on version N validators starts and produces `ObservedJWKUpdate` transactions: [4](#0-3) 

7. When a version N validator proposes a block containing `ObservedJWKUpdate` transactions, version N+1 validators reject it because they believe JWK consensus is disabled: [5](#0-4) [6](#0-5) 

**Critical Issue**: The validation uses `ensure!` which causes immediate proposal rejection with "unexpected validator txn" error. This breaks consensus safety because validators on different software versions cannot agree on valid blocks.

## Impact Explanation

**Severity: Critical** (up to $1,000,000 per Aptos Bug Bounty)

This vulnerability causes:
- **Consensus/Safety Violation**: Validators on different software versions reject each other's proposals, preventing the network from reaching consensus
- **Non-Recoverable Network Partition**: The network cannot progress until all validators converge on the same software version or the on-chain config is reverted
- **Hard Fork Requirement**: Requires coordinated intervention to either force all validators to the same version or revert the config change

The attack exploits the fundamental assumption that all validators will interpret on-chain configuration identically. By breaking this assumption during version migration, the network splits into incompatible factions.

## Likelihood Explanation

**Likelihood: High during any V2 introduction**

This will occur whenever:
1. A new config version (V2) is introduced with different `jwk_consensus_enabled()` semantics than the fallback produces
2. Validators upgrade in a staggered manner (standard practice for large validator sets)
3. A governance proposal updates the config to V2 before all validators upgrade
4. The deprecated `JWK_CONSENSUS` feature flag has not been synchronized with the new config intent

The scenario is realistic because:
- Validator upgrades are typically gradual to minimize risk
- Governance proposals can be executed independently of validator upgrade coordination
- The deprecated feature flag may remain enabled for backward compatibility
- No validation prevents proposing V2 configs when some validators haven't upgraded

## Recommendation

**Immediate Fix**: Implement version-safe deserialization with explicit fallback semantics:

```rust
fn deserialize_into_config(bytes: &[u8]) -> anyhow::Result<Self> {
    let variant = bcs::from_bytes::<MoveAny>(bytes)?;
    match variant.type_name.as_str() {
        ConfigOff::MOVE_TYPE_NAME => Ok(OnChainJWKConsensusConfig::Off),
        ConfigV1::MOVE_TYPE_NAME => {
            let config_v1 = Any::unpack::<ConfigV1>(ConfigV1::MOVE_TYPE_NAME, variant)
                .map_err(|e|anyhow!("OnChainJWKConsensusConfig deserialization failed with ConfigV1 unpack error: {e}"))?;
            Ok(OnChainJWKConsensusConfig::V1(config_v1))
        },
        // When V2 is added, include explicit forward-compatibility handling:
        // ConfigV2::MOVE_TYPE_NAME => { /* unpack V2 */ },
        _ => {
            // SAFE FALLBACK: Unknown variants default to Off to prevent fork
            warn!("Unknown JWKConsensusConfig variant: {}, defaulting to Off", variant.type_name);
            Ok(OnChainJWKConsensusConfig::Off)
        }
    }
}
```

**Long-term Solution**:
1. **Require Feature Flag Gating**: New config versions should be gated behind feature flags that enforce minimum validator version requirements
2. **Version Checking**: Implement on-chain version tracking to prevent config updates until sufficient validators support the new version
3. **Remove Deprecated Fallback**: Once all validators support `OnChainJWKConsensusConfig`, remove the fallback to deprecated resources entirely: [7](#0-6) 

4. **Semantic Compatibility**: Ensure all new config versions maintain semantic compatibility with fallback behavior during migration periods

## Proof of Concept

**Scenario Setup**:
1. Deploy network with all validators on version N
2. Set `JWKConsensusConfig` to `V1` and `FeatureFlag::JWK_CONSENSUS` enabled
3. Upgrade 50% of validators to version N+1 (with V2 support)
4. Submit governance proposal: `jwk_consensus_config::set_for_next_epoch(&framework, new_v2(false))`
5. Execute reconfiguration

**Expected Fork Behavior**:
```rust
// Version N+1 validators (after deserialization):
config.jwk_consensus_enabled() // returns false
// Block validation: rejects ObservedJWKUpdate transactions

// Version N validators (after fallback):
FeatureFlag::JWK_CONSENSUS.is_enabled() // returns true
config.jwk_consensus_enabled() // returns true (from V1 fallback)
// Block validation: expects ObservedJWKUpdate transactions

// Result: Consensus deadlock when N validator proposes with JWK txns
```

**Reproduction Steps**:
1. Create integration test simulating mixed-version validator set
2. Configure V2 deserialization to fail on old validators
3. Set conflicting JWK enabled state (V2=false, FeatureFlag=true)
4. Observe proposal rejection and consensus failure

The vulnerability is deterministic and will occur in any deployment following the described migration path without additional safeguards.

---

**Notes**: 
- This is a forward-looking vulnerability that doesn't exist in the current codebase (no V2 yet) but represents a critical design flaw in the migration strategy
- Similar issues may affect `OnChainRandomnessConfig` which also has V1/V2 variants, though its fallback behavior differs
- The fix requires both immediate code changes and process improvements for future config migrations

### Citations

**File:** types/src/on_chain_config/jwk_consensus_config.rs (L88-98)
```rust
    fn deserialize_into_config(bytes: &[u8]) -> anyhow::Result<Self> {
        let variant = bcs::from_bytes::<MoveAny>(bytes)?;
        match variant.type_name.as_str() {
            ConfigOff::MOVE_TYPE_NAME => Ok(OnChainJWKConsensusConfig::Off),
            ConfigV1::MOVE_TYPE_NAME => {
                let config_v1 = Any::unpack::<ConfigV1>(ConfigV1::MOVE_TYPE_NAME, variant).map_err(|e|anyhow!("OnChainJWKConsensusConfig deserialization failed with ConfigV1 unpack error: {e}"))?;
                Ok(OnChainJWKConsensusConfig::V1(config_v1))
            },
            _ => Err(anyhow!("unknown variant type")),
        }
    }
```

**File:** types/src/on_chain_config/jwk_consensus_config.rs (L112-132)
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
}
```

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

**File:** crates/aptos-jwk-consensus/src/epoch_manager.rs (L177-195)
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
        };
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
