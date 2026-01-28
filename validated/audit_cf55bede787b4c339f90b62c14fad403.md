# Audit Report

## Title
JWK Consensus Version Mismatch Causes False Rejections and Consensus Liveness Failure

## Summary
The JWK consensus mechanism suffers from a race condition where validators with different on-chain state views due to asynchronous event propagation compute different version numbers for the same observed external JWK update. This causes strict equality checks to fail, preventing consensus from being reached during synchronization windows and causing validator slowdowns.

## Finding Description

The vulnerability exists in the JWK consensus aggregation logic where validators must reach agreement on observed external JWK changes from OIDC providers.

**Core Issue: Strict Equality Check Including Version Field**

When validators exchange JWK observations, the aggregation state performs a strict equality check that requires both the observed JWK content AND the version number to match: [1](#0-0) 

The `ProviderJWKs` struct derives `Eq` and `PartialEq`, causing the comparison to check ALL fields including the `version` field: [2](#0-1) 

**Version Computation Based on Local On-Chain State**

In PerIssuer mode, when a validator observes an external JWK change, it computes the version as the local on-chain version + 1: [3](#0-2) 

The `on_chain_version()` method returns the version from the locally cached on-chain state: [4](#0-3) 

In PerKey mode, the same pattern occurs where `base_version` is derived from local on-chain state: [5](#0-4) 

**Asynchronous On-Chain State Updates**

The local on-chain state is updated when validators receive `ObservedJWKsUpdated` events through asynchronous channels: [6](#0-5) 

These events are pushed through channels with inherent latency in the EpochManager: [7](#0-6) 

**Race Condition Scenario**

1. All validators start with on-chain version N
2. A JWK update commits as version N+1, emitting an `ObservedJWKsUpdated` event
3. Due to asynchronous event processing, Validator A receives and processes the event first (local state = N+1)
4. Validator B hasn't processed the event yet (local state = N)
5. An external OIDC provider rotates its keys
6. Both validators observe the same new external state via their JWKObservers
7. Validator A proposes: `ProviderJWKs { version: N+2, ... }`
8. Validator B proposes: `ProviderJWKs { version: N+1, ... }`
9. When they exchange observations, the equality check at line 82 fails: `N+2 != N+1`
10. Both validators reject each other's proposals, preventing quorum

The on-chain Move contract enforces strict sequential versioning, confirming that only correctly-versioned updates can eventually commit: [8](#0-7) 

However, this doesn't prevent the consensus problem—it ensures only the right version eventually succeeds, but validators cannot reach consensus during the synchronization window.

## Impact Explanation

This is a **High Severity** vulnerability per Aptos bug bounty criteria:

**Validator Node Slowdowns (High Severity)**: JWK consensus sessions repeatedly fail and retry during event synchronization windows, causing validator resource consumption and processing delays. The reliable broadcast mechanism uses exponential backoff: [9](#0-8) 

However, retrying cannot resolve version mismatches until all validators synchronize their on-chain state views.

**Significant Protocol Violation**: Validators observing identical external OIDC provider states should be able to certify those observations. The race condition violates this fundamental consensus guarantee—agreement fails not due to different observations but due to internal synchronization timing differences.

**Keyless Authentication Degradation**: When OIDC providers rotate keys, the network cannot promptly certify updates during synchronization windows, potentially breaking keyless account authentication for affected providers. JWKObservers poll every 10 seconds: [10](#0-9) 

This means repeated failures can span multiple observation cycles if event propagation remains delayed.

## Likelihood Explanation

**Likelihood: HIGH**

This vulnerability triggers under normal network conditions without requiring an attacker:

1. **Inherent Async Latency**: Event propagation through channels has unavoidable latency, especially during network congestion or validator load spikes
2. **State Sync Scenarios**: Validators catching up or at different blockchain heights will have stale on-chain state views
3. **Independent External Events**: OIDC providers rotate keys independently and unpredictably, with no coordination with blockchain event propagation
4. **Deterministic Race**: Whenever validators have different `on_chain_version` values and observe the same external JWK change, consensus will fail—this is not an edge case but a fundamental timing issue in the protocol design

## Recommendation

The version field should be computed from a globally synchronized reference rather than each validator's local on-chain cache. Potential solutions:

1. **Consensus-Driven Versioning**: Include the current epoch or block height in version computation rather than the local cache version
2. **Version-Agnostic Equality**: Modify the equality check to compare only the JWK content, not the version field, during aggregation
3. **Synchronization Barrier**: Ensure all validators process `ObservedJWKsUpdated` events before accepting new external observations

The recommended approach is option 2: modify `ObservationAggregationState::add()` to compare only the JWK content (`issuer` and `jwks` fields) while allowing version differences, then select the correct version during quorum certification.

## Proof of Concept

The race condition can be demonstrated through an integration test that:
1. Starts multiple validator nodes with synchronized initial state
2. Commits a JWK update (version N → N+1)
3. Delays event propagation to some validators
4. Triggers an external OIDC provider key rotation
5. Observes that validators with different local versions fail to reach consensus
6. Monitors retry attempts and resource consumption

The existing codebase structure confirms this scenario is possible without requiring modifications to validator behavior or network configuration.

**Notes**

This vulnerability represents a fundamental design flaw in the JWK consensus protocol where internal synchronization timing affects the ability to certify external observations. While the system eventually converges through retries and synchronization, the temporary liveness degradation qualifies as High severity under Aptos bug bounty criteria for "Validator Node Slowdowns" affecting consensus operations.

### Citations

**File:** crates/aptos-jwk-consensus/src/observation_aggregation/mod.rs (L81-84)
```rust
        ensure!(
            self.local_view == peer_view,
            "adding peer observation failed with mismatched view"
        );
```

**File:** types/src/jwks/mod.rs (L122-128)
```rust
#[derive(Clone, Default, Eq, PartialEq, Serialize, Deserialize, CryptoHasher, BCSCryptoHash)]
pub struct ProviderJWKs {
    #[serde(with = "serde_bytes")]
    pub issuer: Issuer,
    pub version: u64,
    pub jwks: Vec<JWKMoveStruct>,
}
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L117-124)
```rust
                    (Ok(issuer), Ok(config_url)) => Some(JWKObserver::spawn(
                        this.epoch_state.epoch,
                        this.my_addr,
                        issuer,
                        config_url,
                        Duration::from_secs(10),
                        local_observation_tx.clone(),
                    )),
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L140-143)
```rust
                jwk_updated = jwk_updated_rx.select_next_some() => {
                    let ObservedJWKsUpdated { jwks, .. } = jwk_updated;
                    this.reset_with_on_chain_state(jwks)
                },
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L197-201)
```rust
            let observed = ProviderJWKs {
                issuer: issuer.clone(),
                version: state.on_chain_version() + 1,
                jwks,
            };
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L377-381)
```rust
    pub fn on_chain_version(&self) -> u64 {
        self.on_chain
            .as_ref()
            .map_or(0, |provider_jwks| provider_jwks.version)
    }
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L138-143)
```rust
                        let update = KeyLevelUpdate {
                            issuer: issuer.clone(),
                            base_version: effectively_onchain.version,
                            kid: kid.clone(),
                            to_upsert: Some(y.clone()),
                        };
```

**File:** crates/aptos-jwk-consensus/src/epoch_manager.rs (L108-120)
```rust
    fn process_onchain_event(&mut self, notification: EventNotification) -> Result<()> {
        let EventNotification {
            subscribed_events, ..
        } = notification;
        for event in subscribed_events {
            if let Ok(jwk_event) = ObservedJWKsUpdated::try_from(&event) {
                if let Some(tx) = self.jwk_updated_event_txs.as_ref() {
                    let _ = tx.push((), jwk_event);
                }
            }
        }
        Ok(())
    }
```

**File:** aptos-move/framework/aptos-framework/sources/jwks.move (L478-478)
```text
                assert!(cur_issuer_jwks.version + 1 == proposed_provider_jwks.version, error::invalid_argument(EUNEXPECTED_VERSION));
```

**File:** crates/reliable-broadcast/src/lib.rs (L191-200)
```rust
                            Err(e) => {
                                log_rpc_failure(e, receiver);

                                let backoff_strategy = backoff_policies
                                    .get_mut(&receiver)
                                    .expect("should be present");
                                let duration = backoff_strategy.next().expect("should produce value");
                                rpc_futures
                                    .push(send_message(receiver, Some(duration)));
                            },
```
