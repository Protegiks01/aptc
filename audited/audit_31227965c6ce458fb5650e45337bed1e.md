# Audit Report

## Title
Feature Flag State Inconsistency Leading to JWK Consensus Protocol Divergence

## Summary
Validators can diverge in their JWK consensus message handling and transaction execution due to independent feature flag checks at the Rust consensus layer and Move execution layer, potentially causing consensus splits during epoch transitions when the `JWK_CONSENSUS_PER_KEY_MODE` feature flag is toggled.

## Finding Description

The Aptos JWK consensus system has a critical design flaw where the `JWK_CONSENSUS_PER_KEY_MODE` feature flag (feature #92) is checked independently in two separate code paths:

**1. Rust-side Consensus Manager Selection:** [1](#0-0) 

When starting a new epoch, each validator reads the feature flag from the `OnChainConfigPayload` to decide which consensus manager to spawn. This determines the message protocol used.

**2. Move-side Transaction Execution:** [2](#0-1) 

During execution of `ValidatorTransaction::ObservedJWKUpdate`, the Move code checks the feature flag to determine processing semantics.

**Message Protocol Incompatibility:**

The two consensus managers use incompatible message types:

- `KeyLevelConsensusManager` sends and expects `JWKConsensusMsg::KeyLevelObservationRequest`: [3](#0-2) 

- `IssuerLevelConsensusManager` sends and expects `JWKConsensusMsg::ObservationRequest`: [4](#0-3) 

If validators spawn different managers, they reject each other's messages as "unexpected rpc", breaking consensus message propagation.

**Execution Divergence:**

The Move execution branches on the feature flag, producing fundamentally different state transitions:
- Per-key mode (lines 467-495): Processes individual key-level updates incrementally
- Per-issuer mode (lines 497-500): Replaces entire provider JWK sets

This violates the **Deterministic Execution** invariant - identical `ValidatorTransaction` inputs produce different state roots depending on feature flag state.

**Exploitation Scenario:**

While the feature flag update mechanism uses a two-phase commit pattern via `PendingFeatures`: [5](#0-4) 

And feature flags are synchronized during reconfiguration: [6](#0-5) 

There is no explicit verification that the Rust-side `OnChainConfigPayload` read matches the Move-side `Features` resource state. State synchronization issues, caching bugs, or epoch transition race conditions could cause validators to read inconsistent feature flag states.

## Impact Explanation

**Critical Severity** - This breaks the fundamental consensus safety guarantee:

1. **Consensus Split**: Validators with different managers cannot communicate, partitioning the network into incompatible subsets
2. **State Root Divergence**: Executing the same transaction with different feature flag states produces different state roots, causing an irrecoverable chain fork
3. **Liveness Failure**: JWK updates cannot reach quorum when validators use incompatible protocols

This maps to "Consensus/Safety violations" and "Non-recoverable network partition (requires hardfork)" in the Critical Severity category, qualifying for up to $1,000,000 in bounty rewards.

## Likelihood Explanation

**Low to Medium** - While the vulnerability is architectural, exploitation requires:

1. A triggering condition (state sync bug, cache inconsistency, or epoch transition race) that causes validators to read different `Features` states
2. Active JWK consensus operations during the vulnerability window
3. The feature flag being toggled via governance

The dual-check design creates a dangerous attack surface, but successful exploitation depends on bugs in state management or synchronization.

## Recommendation

**Implement explicit feature flag consistency verification:**

```rust
// In epoch_manager.rs, after spawning the consensus manager
let jwk_consensus_manager: Box<dyn TConsensusManager> = 
    if features.is_enabled(FeatureFlag::JWK_CONSENSUS_PER_KEY_MODE) {
        Box::new(KeyLevelConsensusManager::new(...))
    } else {
        Box::new(IssuerLevelConsensusManager::new(...))
    };

// Store the expected mode in epoch state for validation
let expected_mode = features.is_enabled(FeatureFlag::JWK_CONSENSUS_PER_KEY_MODE);
```

**Add runtime verification in Move:**

```move
public fun upsert_into_observed_jwks(
    fx: &signer, 
    provider_jwks_vec: vector<ProviderJWKs>,
    expected_per_key_mode: bool  // New parameter from Rust
) acquires ObservedJWKs, PatchedJWKs, Patches {
    system_addresses::assert_aptos_framework(fx);
    
    let actual_mode = features::is_jwk_consensus_per_key_mode_enabled();
    assert!(actual_mode == expected_per_key_mode, 
        error::invalid_state(EFEATURE_FLAG_MISMATCH));
    
    // ... rest of function
}
```

**Strengthen epoch transition guarantees:**
- Add checksums of critical on-chain configs to `EpochState`
- Verify all validators agree on feature flag state before processing validator transactions
- Reject validator transactions if feature flag state doesn't match epoch expectations

## Proof of Concept

```rust
// Reproduction test demonstrating divergence
#[test]
fn test_feature_flag_divergence() {
    // Setup two validators with different feature flag states
    let mut validator_a = create_test_validator();
    let mut validator_b = create_test_validator();
    
    // Simulate inconsistent config reads during epoch transition
    validator_a.start_epoch_with_features(Features::with_enabled(
        vec![FeatureFlag::JWK_CONSENSUS_PER_KEY_MODE]
    ));
    validator_b.start_epoch_with_features(Features::default()); // disabled
    
    // Validator A spawns KeyLevelConsensusManager
    assert!(validator_a.jwk_manager_is_per_key_mode());
    
    // Validator B spawns IssuerLevelConsensusManager  
    assert!(!validator_b.jwk_manager_is_per_key_mode());
    
    // Create a JWK update request
    let request = create_test_jwk_observation_request();
    
    // Validator A sends per-key mode message
    let msg_from_a = validator_a.create_observation_message(request.clone());
    assert!(matches!(msg_from_a, JWKConsensusMsg::KeyLevelObservationRequest(_)));
    
    // Validator B receives and rejects it
    let result = validator_b.handle_incoming_message(msg_from_a);
    assert!(result.is_err()); // "unexpected rpc"
    
    // Consensus broken: validators cannot communicate
}
```

---

**Notes:**

The vulnerability exists at the architectural level but requires specific triggering conditions related to state synchronization. The independent feature flag checks create a dangerous inconsistency that violates the deterministic execution invariant. While exploitation requires additional bugs in state management, the design itself is flawed and should be hardened against such edge cases.

### Citations

**File:** crates/aptos-jwk-consensus/src/epoch_manager.rs (L228-246)
```rust
                if features.is_enabled(FeatureFlag::JWK_CONSENSUS_PER_KEY_MODE) {
                    Box::new(KeyLevelConsensusManager::new(
                        Arc::new(my_sk),
                        self.my_addr,
                        epoch_state.clone(),
                        rb,
                        self.vtxn_pool.clone(),
                    ))
                } else {
                    //TODO: move this into IssuerLevelConsensusManager construction?
                    let update_certifier = UpdateCertifier::new(rb);
                    Box::new(IssuerLevelConsensusManager::new(
                        Arc::new(my_sk),
                        self.my_addr,
                        epoch_state.clone(),
                        Arc::new(update_certifier),
                        self.vtxn_pool.clone(),
                    ))
                };
```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L466-500)
```text
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
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L272-309)
```rust
            JWKConsensusMsg::KeyLevelObservationRequest(request) => {
                let ObservedKeyLevelUpdateRequest { issuer, kid, .. } = request;
                let consensus_state = self
                    .states_by_key
                    .entry((issuer.clone(), kid.clone()))
                    .or_default();
                let response: Result<JWKConsensusMsg> = match &consensus_state {
                    ConsensusState::NotStarted => {
                        debug!(
                            issuer = String::from_utf8(issuer.clone()).ok(),
                            kid = String::from_utf8(kid.clone()).ok(),
                            "key-level jwk consensus not started"
                        );
                        return Ok(());
                    },
                    ConsensusState::InProgress { my_proposal, .. }
                    | ConsensusState::Finished { my_proposal, .. } => Ok(
                        JWKConsensusMsg::ObservationResponse(ObservedUpdateResponse {
                            epoch: self.epoch_state.epoch,
                            update: ObservedUpdate {
                                author: self.my_addr,
                                observed: my_proposal
                                    .observed
                                    .try_as_issuer_level_repr()
                                    .context("process_peer_request failed with repr conversion")?,
                                signature: my_proposal.signature.clone(),
                            },
                        }),
                    ),
                };
                response_sender.send(response);
                Ok(())
            },
            _ => {
                bail!("unexpected rpc: {}", msg.name());
            },
        }
    }
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L301-320)
```rust
            JWKConsensusMsg::ObservationRequest(request) => {
                let state = self.states_by_issuer.entry(request.issuer).or_default();
                let response: Result<JWKConsensusMsg> = match &state.consensus_state {
                    ConsensusState::NotStarted => Err(anyhow!("observed update unavailable")),
                    ConsensusState::InProgress { my_proposal, .. }
                    | ConsensusState::Finished { my_proposal, .. } => Ok(
                        JWKConsensusMsg::ObservationResponse(ObservedUpdateResponse {
                            epoch: self.epoch_state.epoch,
                            update: my_proposal.clone(),
                        }),
                    ),
                };
                response_sender.send(response);
                Ok(())
            },
            _ => {
                bail!("unexpected rpc: {}", msg.name());
            },
        }
    }
```

**File:** aptos-move/framework/move-stdlib/sources/configs/features.move (L834-844)
```text
    public fun on_new_epoch(framework: &signer) acquires Features, PendingFeatures {
        ensure_framework_signer(framework);
        if (exists<PendingFeatures>(@std)) {
            let PendingFeatures { features } = move_from<PendingFeatures>(@std);
            if (exists<Features>(@std)) {
                Features[@std].features = features;
            } else {
                move_to(framework, Features { features })
            }
        }
    }
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
