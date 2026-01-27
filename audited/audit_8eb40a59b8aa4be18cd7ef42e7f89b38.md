# Audit Report

## Title
JWK Consensus Liveness Failure Due to Premature Abort Handle Termination in Clone Operation

## Summary
The `ConsensusState::InProgress` enum variant in the JWK consensus system derives `Clone`, which creates a semantic inconsistency when cloned. Cloning creates a duplicate `QuorumCertProcessGuard` that shares the same `AbortHandle`, and when the clone is dropped, it prematurely terminates the active consensus process, causing permanent liveness failures in JWK updates.

## Finding Description

The vulnerability exists in how `ConsensusState<T>` is cloned in the per-key JWK consensus implementation. [1](#0-0) 

The `ConsensusState::InProgress` variant contains a `QuorumCertProcessGuard`, which wraps an `AbortHandle` and implements `Drop` to abort the consensus task when dropped. [2](#0-1) 

The critical bug occurs in `KeyLevelConsensusManager::maybe_start_consensus()` where the code clones the entire `ConsensusState` to check if consensus is already running: [3](#0-2) 

**Attack Flow:**
1. JWK observer detects a change and calls `maybe_start_consensus(update)`, starting a consensus process via `update_certifier.start_produce()` [4](#0-3) 
2. State transitions to `InProgress` with an active `AbortHandle` tracking the spawned async task
3. Observer is triggered again (normal periodic behavior), calls `maybe_start_consensus()` with the same update
4. Code clones the `InProgress` state at line 183 to check `my_proposal.observed.to_upsert == update.to_upsert`
5. Clone creates a duplicate `QuorumCertProcessGuard` with a cloned `AbortHandle` referencing the same task
6. Code returns early at line 193 since consensus already started
7. **Cloned state is dropped, triggering `Drop` implementation which calls `handle.abort()`**
8. The active consensus task is terminated mid-execution
9. The original state remains `InProgress` in the hashmap, but no task is running
10. JWK update never completes, causing permanent stall

This breaks the **consensus liveness invariant** - JWK updates must eventually complete when validators agree on observations.

## Impact Explanation

**Severity: High** (up to $50,000)

This vulnerability causes **significant protocol violations** and **validator node functionality degradation**:

- **JWK Consensus Liveness Failure**: Once triggered, the affected validator cannot complete JWK consensus for that (issuer, kid) pair indefinitely
- **Validator Transaction Pool Stall**: No `QuorumCertifiedUpdate` is produced, preventing validator transactions from being created
- **OpenID Connect Authentication Degradation**: JWK updates are critical for validating OIDC tokens; stalled updates prevent rotation of compromised keys
- **Network-Wide Impact**: If multiple validators experience this bug simultaneously (likely during periodic observations), the entire network's JWK consensus may stall

This meets the **High Severity** criteria: "Validator node slowdowns" and "Significant protocol violations" as the JWK consensus subsystem becomes non-functional.

## Likelihood Explanation

**Likelihood: High**

This bug will trigger with high probability during normal operation:

1. **Periodic Observation Pattern**: JWK observers call `process_new_observation()` periodically (every 10 seconds by default), which calls `maybe_start_consensus()` [5](#0-4) 

2. **Idempotent Update Detection**: When an observer detects the same change multiple times (e.g., upstream provider hasn't rotated keys yet), it will call `maybe_start_consensus()` with the same update

3. **No External Attack Required**: This is triggered by normal validator operation, not malicious input

4. **Deterministic Reproduction**: Any scenario where `maybe_start_consensus()` is called twice with the same update while consensus is `InProgress` will trigger the bug

5. **Silent Failure**: The bug manifests as a stalled consensus without error messages, making it difficult to diagnose

## Recommendation

Remove the `.cloned()` call and instead borrow the state to check the condition:

```rust
fn maybe_start_consensus(&mut self, update: KeyLevelUpdate) -> Result<()> {
    let consensus_already_started = match self
        .states_by_key
        .get(&(update.issuer.clone(), update.kid.clone()))
        // Remove .cloned() here - just borrow the reference
    {
        Some(ConsensusState::InProgress { my_proposal, .. })
        | Some(ConsensusState::Finished { my_proposal, .. }) => {
            my_proposal.observed.to_upsert == update.to_upsert
        },
        _ => false,
    };

    if consensus_already_started {
        return Ok(());
    }
    
    // ... rest of function
}
```

**Alternative Fix**: Remove the `Clone` derive from `ConsensusState` entirely, as cloning a state with an abort handle is semantically incorrect. The `PartialEq` and `Eq` implementations already ignore the `abort_handle_wrapper` field, indicating it shouldn't be cloned.

## Proof of Concept

```rust
#[cfg(test)]
mod test_clone_bug {
    use super::*;
    use aptos_types::jwks::{Issuer, KID, JWK};
    use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_consensus_abort_on_clone() {
        // Setup: Create a KeyLevelConsensusManager
        let mut manager = create_test_manager(); // helper function
        
        let issuer: Issuer = b"https://example.com".to_vec();
        let kid: KID = b"key1".to_vec();
        
        // Create a JWK update
        let jwk = JWK::new_for_testing(kid.clone(), /* ... */);
        
        // Simulate first observation - starts consensus
        manager.process_new_observation(issuer.clone(), vec![jwk.clone()])
            .expect("First observation should succeed");
        
        // Verify consensus is InProgress
        let state = manager.states_by_key.get(&(issuer.clone(), kid.clone()));
        assert!(matches!(state, Some(ConsensusState::InProgress { .. })));
        
        // Wait a bit to ensure task is running
        sleep(Duration::from_millis(50)).await;
        
        // Simulate second observation with same update - triggers bug
        manager.process_new_observation(issuer.clone(), vec![jwk.clone()])
            .expect("Second observation should succeed");
        
        // Wait for consensus to complete
        sleep(Duration::from_secs(5)).await;
        
        // BUG: Consensus should be Finished, but it's still InProgress
        // because the task was aborted when the cloned state was dropped
        let state = manager.states_by_key.get(&(issuer.clone(), kid.clone()));
        
        // This assertion will fail - consensus never completes
        assert!(matches!(state, Some(ConsensusState::Finished { .. })), 
                "Consensus should have completed but task was aborted");
    }
}
```

---

## Notes

This vulnerability is particularly insidious because:

1. **Silent Failure**: No error is logged when the abort occurs
2. **State Inconsistency**: The hashmap shows `InProgress` but no task is running
3. **Rust's Clone Semantics**: The `Clone` derive is correct from Rust's perspective (all fields implement `Clone`), but semantically incorrect for abort handles
4. **Similar Pattern in Per-Issuer Mode**: The per-issuer implementation doesn't clone the full state, only `my_proposal`, avoiding this bug [6](#0-5) 

The fundamental issue is that `QuorumCertProcessGuard` should not implement `Clone`, as cloning an RAII guard that cancels work on drop creates dangerous aliasing of cleanup responsibilities.

### Citations

**File:** crates/aptos-jwk-consensus/src/types.rs (L79-101)
```rust
#[derive(Clone, Debug)]
pub struct QuorumCertProcessGuard {
    pub handle: AbortHandle,
}

impl QuorumCertProcessGuard {
    pub fn new(handle: AbortHandle) -> Self {
        Self { handle }
    }

    #[cfg(test)]
    pub fn dummy() -> Self {
        let (handle, _) = AbortHandle::new_pair();
        Self { handle }
    }
}

impl Drop for QuorumCertProcessGuard {
    fn drop(&mut self) {
        let QuorumCertProcessGuard { handle } = self;
        handle.abort();
    }
}
```

**File:** crates/aptos-jwk-consensus/src/types.rs (L103-115)
```rust
#[derive(Debug, Clone)]
pub enum ConsensusState<T: Debug + Clone + Eq + PartialEq> {
    NotStarted,
    InProgress {
        my_proposal: T,
        abort_handle_wrapper: QuorumCertProcessGuard,
    },
    Finished {
        vtxn_guard: TxnGuard,
        my_proposal: T,
        quorum_certified: QuorumCertifiedUpdate,
    },
}
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L108-177)
```rust
    /// Triggered by an observation thread periodically.
    pub fn process_new_observation(&mut self, issuer: Issuer, jwks: Vec<JWK>) -> Result<()> {
        debug!(
            epoch = self.epoch_state.epoch,
            issuer = String::from_utf8(issuer.clone()).ok(),
            "Processing new observation."
        );
        let observed_jwks_by_kid: HashMap<KID, JWK> =
            jwks.into_iter().map(|jwk| (jwk.id(), jwk)).collect();
        let effectively_onchain = self
            .onchain_jwks
            .get(&issuer)
            .cloned()
            .unwrap_or_else(|| ProviderJWKsIndexed::new(issuer.clone()));
        let all_kids: HashSet<KID> = effectively_onchain
            .jwks
            .keys()
            .chain(observed_jwks_by_kid.keys())
            .cloned()
            .collect();
        for kid in all_kids {
            let onchain = effectively_onchain.jwks.get(&kid);
            let observed = observed_jwks_by_kid.get(&kid);
            match (onchain, observed) {
                (Some(x), Some(y)) => {
                    if x == y {
                        // No change, drop any in-progress consensus.
                        self.states_by_key.remove(&(issuer.clone(), kid.clone()));
                    } else {
                        // Update detected.
                        let update = KeyLevelUpdate {
                            issuer: issuer.clone(),
                            base_version: effectively_onchain.version,
                            kid: kid.clone(),
                            to_upsert: Some(y.clone()),
                        };
                        self.maybe_start_consensus(update)
                            .context("process_new_observation failed at upsert consensus init")?;
                    }
                },
                (None, Some(y)) => {
                    // Insert detected.
                    let update = KeyLevelUpdate {
                        issuer: issuer.clone(),
                        base_version: effectively_onchain.version,
                        kid: kid.clone(),
                        to_upsert: Some(y.clone()),
                    };
                    self.maybe_start_consensus(update)
                        .context("process_new_observation failed at upsert consensus init")?;
                },
                (Some(_), None) => {
                    // Delete detected.
                    let update = KeyLevelUpdate {
                        issuer: issuer.clone(),
                        base_version: effectively_onchain.version,
                        kid: kid.clone(),
                        to_upsert: None,
                    };
                    self.maybe_start_consensus(update)
                        .context("process_new_observation failed at deletion consensus init")?;
                },
                (None, None) => {
                    unreachable!("`kid` in `union(A, B)` but `kid` not in `A` and not in `B`?")
                },
            }
        }

        Ok(())
    }
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager_per_key.rs (L179-194)
```rust
    fn maybe_start_consensus(&mut self, update: KeyLevelUpdate) -> Result<()> {
        let consensus_already_started = match self
            .states_by_key
            .get(&(update.issuer.clone(), update.kid.clone()))
            .cloned()
        {
            Some(ConsensusState::InProgress { my_proposal, .. })
            | Some(ConsensusState::Finished { my_proposal, .. }) => {
                my_proposal.observed.to_upsert == update.to_upsert
            },
            _ => false,
        };

        if consensus_already_started {
            return Ok(());
        }
```

**File:** crates/aptos-jwk-consensus/src/update_certifier.rs (L48-83)
```rust
impl<ConsensusMode: TConsensusMode> TUpdateCertifier<ConsensusMode> for UpdateCertifier {
    fn start_produce(
        &self,
        epoch_state: Arc<EpochState>,
        payload: ProviderJWKs,
        qc_update_tx: aptos_channel::Sender<
            ConsensusMode::ConsensusSessionKey,
            QuorumCertifiedUpdate,
        >,
    ) -> anyhow::Result<AbortHandle> {
        ConsensusMode::log_certify_start(epoch_state.epoch, &payload);
        let rb = self.reliable_broadcast.clone();
        let epoch = epoch_state.epoch;
        let req = ConsensusMode::new_rb_request(epoch, &payload)
            .context("UpdateCertifier::start_produce failed at rb request construction")?;
        let agg_state = Arc::new(ObservationAggregationState::<ConsensusMode>::new(
            epoch_state,
            payload,
        ));
        let task = async move {
            let qc_update = rb.broadcast(req, agg_state).await.expect("cannot fail");
            ConsensusMode::log_certify_done(epoch, &qc_update);
            let session_key = ConsensusMode::session_key_from_qc(&qc_update);
            match session_key {
                Ok(key) => {
                    let _ = qc_update_tx.push(key, qc_update);
                },
                Err(e) => {
                    error!("JWK update QCed but could not identify the session key: {e}");
                },
            }
        };
        let (abort_handle, abort_registration) = AbortHandle::new_pair();
        tokio::spawn(Abortable::new(task, abort_registration));
        Ok(abort_handle)
    }
```

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L302-312)
```rust
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
```
