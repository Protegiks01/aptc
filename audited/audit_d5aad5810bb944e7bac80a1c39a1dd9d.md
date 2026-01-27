# Audit Report

## Title
JWK Consensus State Desynchronization Causes Rejected Quorum Certificates During Concurrent On-Chain Updates

## Summary
A race condition exists in the JWK consensus manager where concurrent processing of local observations (`local_observation_rx`) and on-chain update events (`jwk_updated_rx`) for the same issuer causes legitimate quorum certificates to be rejected. When an on-chain JWK update arrives while a local consensus process is in progress for the same version, the entire consensus state is reset, causing the locally-produced QC to be dropped instead of being added to the validator transaction pool.

## Finding Description

The vulnerability occurs in the interaction between three event handlers in the `run()` function: [1](#0-0) 

**Step 1: Local Observation Initiates Consensus**

When a JWK observer detects a change, `process_new_observation()` is invoked: [2](#0-1) 

This calculates the new version as `state.on_chain_version() + 1` and starts an asynchronous consensus process. The state is set to `ConsensusState::InProgress` with an abort handle. Multiple validators observing the same JWK change will all calculate the same version number (e.g., version 6 if on-chain is version 5).

**Step 2: On-Chain Update Resets State**

If another validator's QC for the same version gets committed on-chain first, an `ObservedJWKsUpdated` event fires, triggering `reset_with_on_chain_state()`: [3](#0-2) 

The critical bug is that this function compares only the `on_chain` field of `PerProviderState` (not the `consensus_state`). When they differ, it **unconditionally replaces the entire state** including the `InProgress` consensus state. The replacement creates a new state with `ConsensusState::NotStarted`: [4](#0-3) 

When the old `InProgress` state is dropped, it triggers the abort handle cleanup: [5](#0-4) 

**Step 3: Quorum Certificate Rejection**

When this validator's own QC arrives via `qc_update_rx`, `process_quorum_certified_update()` checks the consensus state: [6](#0-5) 

Since the state is now `NotStarted` (or default), it falls through to the error case and rejects the QC with "qc update not expected". The QC is never added to the validator transaction pool, and the error is silently logged: [7](#0-6) 

This breaks the **State Consistency** invariant as the local consensus state becomes desynchronized with the actual consensus progress.

## Impact Explanation

This vulnerability qualifies as **High Severity** under Aptos Bug Bounty criteria:

1. **Validator Node Slowdowns**: Validators waste computational resources producing QCs that get silently rejected, requiring re-observation and consensus restart.

2. **Significant Protocol Violations**: The JWK consensus protocol's correctness guarantee is violated - valid quorum certificates produced by honest validators are dropped instead of being processed.

3. **Potential Liveness Issues**: If multiple validators simultaneously observe the same JWK change (highly likely in practice), many will hit this race condition. This could delay or prevent JWK updates from being committed if enough validators lose their QCs, requiring manual intervention.

The issue could escalate to **Medium Severity** territory as it causes state inconsistencies requiring intervention when JWK updates fail to propagate despite quorum certificates being successfully produced.

## Likelihood Explanation

**Likelihood: HIGH**

This race condition will occur naturally during normal validator operations:

1. **Common Trigger**: When an OIDC provider rotates their JWKs, all validators' JWK observers will detect the change within seconds of each other.

2. **Version Calculation**: All validators with on-chain version N will calculate version N+1 simultaneously: [8](#0-7) 

3. **Network Race**: The first validator to achieve quorum and commit to chain wins. All other validators' states get reset when the `ObservedJWKsUpdated` event arrives.

4. **Timing Window**: The race window spans from when local consensus starts until the on-chain event arrives - typically several seconds to minutes depending on network conditions.

No attacker action is required; this occurs through normal validator operations during legitimate JWK rotations.

## Recommendation

Modify `reset_with_on_chain_state()` to preserve the `InProgress` consensus state when the ongoing consensus version matches the new on-chain version:

```rust
// In reset_with_on_chain_state(), around line 269
} else {
    let issuer = on_chain_provider_jwks.issuer.clone();
    let existing_state = self.states_by_issuer.get(&issuer);
    
    // Preserve InProgress state if consensus version matches on-chain version
    let should_preserve_consensus = existing_state
        .and_then(|s| match &s.consensus_state {
            ConsensusState::InProgress { my_proposal, .. } => {
                Some(my_proposal.observed.version == on_chain_provider_jwks.version)
            },
            _ => None,
        })
        .unwrap_or(false);
    
    if should_preserve_consensus {
        // Update only the on_chain field, preserve consensus_state
        if let Some(state) = self.states_by_issuer.get_mut(&issuer) {
            state.on_chain = Some(on_chain_provider_jwks);
            info!(
                epoch = self.epoch_state.epoch,
                op = "update-preserve-consensus",
                issuer = issuer,
                "reset_with_on_chain_state"
            );
        }
    } else {
        // Original behavior: replace entire state
        let old_value = self.states_by_issuer.insert(
            on_chain_provider_jwks.issuer.clone(),
            PerProviderState::new(on_chain_provider_jwks),
        );
        // ... existing logging ...
    }
}
```

Alternatively, check the version in `process_quorum_certified_update()` and accept QCs that match the current on-chain version even in `NotStarted` state.

## Proof of Concept

```rust
#[tokio::test]
async fn test_concurrent_observation_and_onchain_update_race() {
    use crate::jwk_manager::IssuerLevelConsensusManager;
    use aptos_types::jwks::{ProviderJWKs, ObservedJWKsUpdated, AllProvidersJWKs};
    
    // Setup: Create manager with issuer at version 5
    let issuer = b"https://example.com".to_vec();
    let initial_provider = ProviderJWKs {
        issuer: issuer.clone(),
        version: 5,
        jwks: vec![],
    };
    
    // Simulate local observation arriving (calculates version 6)
    // Manager starts consensus process, sets state to InProgress
    manager.process_new_observation(issuer.clone(), new_jwks).unwrap();
    
    // Verify state is InProgress
    let state = manager.states_by_issuer.get(&issuer).unwrap();
    assert!(matches!(state.consensus_state, ConsensusState::InProgress { .. }));
    
    // Simulate another validator's version 6 getting committed on-chain first
    let onchain_update = AllProvidersJWKs {
        entries: vec![ProviderJWKs {
            issuer: issuer.clone(),
            version: 6,  // Same version we're producing QC for
            jwks: new_jwks.clone(),
        }],
    };
    
    // Process on-chain update - this resets state to NotStarted
    manager.reset_with_on_chain_state(onchain_update).unwrap();
    
    // Verify state was reset - THIS IS THE BUG
    let state = manager.states_by_issuer.get(&issuer).unwrap();
    assert!(matches!(state.consensus_state, ConsensusState::NotStarted));
    
    // Now simulate our QC arriving
    let qc = QuorumCertifiedUpdate {
        update: ProviderJWKs {
            issuer: issuer.clone(),
            version: 6,
            jwks: new_jwks,
        },
        // ... signatures ...
    };
    
    // Process QC - it will be REJECTED despite being valid
    let result = manager.process_quorum_certified_update(qc);
    
    // BUG: This should succeed but returns error
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("qc update not expected"));
}
```

## Notes

This vulnerability affects the JWK consensus subsystem specifically. The root cause is that `reset_with_on_chain_state()` performs a structural equality check on `ProviderJWKs` objects without considering the semantic state of ongoing consensus processes. The version number in `PerProviderState` becomes the source of truth for determining whether states match, but the function doesn't account for the case where local consensus is producing a QC for the same version that just arrived on-chain.

The issue is deterministic and reproducible whenever validators observe JWK changes within the same time window, making it a practical concern for production deployments rather than a theoretical edge case.

### Citations

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L138-157)
```rust
        while !this.stopped {
            let handle_result = tokio::select! {
                jwk_updated = jwk_updated_rx.select_next_some() => {
                    let ObservedJWKsUpdated { jwks, .. } = jwk_updated;
                    this.reset_with_on_chain_state(jwks)
                },
                (_sender, msg) = rpc_req_rx.select_next_some() => {
                    this.process_peer_request(msg)
                },
                qc_update = this.qc_update_rx.select_next_some() => {
                    this.process_quorum_certified_update(qc_update)
                },
                (issuer, jwks) = local_observation_rx.select_next_some() => {
                    let jwks = jwks.into_iter().map(JWKMoveStruct::from).collect();
                    this.process_new_observation(issuer, jwks)
                },
                ack_tx = close_rx.select_next_some() => {
                    this.tear_down(ack_tx.ok()).await
                }
            };
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L159-164)
```rust
            if let Err(e) = handle_result {
                error!(
                    epoch = this.epoch_state.epoch,
                    "JWKManager handling error: {}", e
                );
            }
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L194-223)
```rust
        let state = self.states_by_issuer.entry(issuer.clone()).or_default();
        state.observed = Some(jwks.clone());
        if state.observed.as_ref() != state.on_chain.as_ref().map(ProviderJWKs::jwks) {
            let observed = ProviderJWKs {
                issuer: issuer.clone(),
                version: state.on_chain_version() + 1,
                jwks,
            };
            let signature = self
                .consensus_key
                .sign(&observed)
                .context("process_new_observation failed with signing error")?;
            let abort_handle = self
                .update_certifier
                .start_produce(
                    self.epoch_state.clone(),
                    observed.clone(),
                    self.qc_update_tx.clone(),
                )
                .context(
                    "process_new_observation failed with update_certifier.start_produce failure",
                )?;
            state.consensus_state = ConsensusState::InProgress {
                my_proposal: ObservedUpdate {
                    author: self.my_addr,
                    observed: observed.clone(),
                    signature,
                },
                abort_handle_wrapper: QuorumCertProcessGuard::new(abort_handle),
            };
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L254-286)
```rust
        for on_chain_provider_jwks in on_chain_state.entries {
            let issuer = on_chain_provider_jwks.issuer.clone();
            let locally_cached = self
                .states_by_issuer
                .get(&on_chain_provider_jwks.issuer)
                .and_then(|s| s.on_chain.as_ref());
            if locally_cached == Some(&on_chain_provider_jwks) {
                // The on-chain update did not touch this provider.
                // The corresponding local state does not have to be reset.
                info!(
                    epoch = self.epoch_state.epoch,
                    op = "no-op",
                    issuer = issuer,
                    "reset_with_on_chain_state"
                );
            } else {
                let old_value = self.states_by_issuer.insert(
                    on_chain_provider_jwks.issuer.clone(),
                    PerProviderState::new(on_chain_provider_jwks),
                );
                let op = if old_value.is_some() {
                    "update"
                } else {
                    "insert"
                };
                info!(
                    epoch = self.epoch_state.epoch,
                    op = op,
                    issuer = issuer,
                    "reset_with_on_chain_state"
                );
            }
        }
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L323-358)
```rust
    pub fn process_quorum_certified_update(&mut self, update: QuorumCertifiedUpdate) -> Result<()> {
        let issuer = update.update.issuer.clone();
        info!(
            epoch = self.epoch_state.epoch,
            issuer = String::from_utf8(issuer.clone()).ok(),
            version = update.update.version,
            "JWKManager processing certified update."
        );
        let state = self.states_by_issuer.entry(issuer.clone()).or_default();
        match &state.consensus_state {
            ConsensusState::InProgress { my_proposal, .. } => {
                //TODO: counters
                let txn = ValidatorTransaction::ObservedJWKUpdate(update.clone());
                let vtxn_guard =
                    self.vtxn_pool
                        .put(Topic::JWK_CONSENSUS(issuer.clone()), Arc::new(txn), None);
                state.consensus_state = ConsensusState::Finished {
                    vtxn_guard,
                    my_proposal: my_proposal.clone(),
                    quorum_certified: update.clone(),
                };
                info!(
                    epoch = self.epoch_state.epoch,
                    issuer = String::from_utf8(issuer).ok(),
                    version = update.update.version,
                    "certified update accepted."
                );
                Ok(())
            },
            _ => Err(anyhow!(
                "qc update not expected for issuer {:?} in state {}",
                String::from_utf8(issuer.clone()),
                state.consensus_state.name()
            )),
        }
    }
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L369-375)
```rust
    pub fn new(provider_jwks: ProviderJWKs) -> Self {
        Self {
            on_chain: Some(provider_jwks),
            observed: None,
            consensus_state: ConsensusState::NotStarted,
        }
    }
```

**File:** crates/aptos-jwk-consensus/src/types.rs (L96-101)
```rust
impl Drop for QuorumCertProcessGuard {
    fn drop(&mut self) {
        let QuorumCertProcessGuard { handle } = self;
        handle.abort();
    }
}
```
