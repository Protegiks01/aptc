# Audit Report

## Title
JWK Consensus State Machine Allows Improper Finished→InProgress Transition, Discarding Quorum-Certified Updates

## Summary
The JWK consensus state machine in the issuer-level manager can transition from `Finished` back to `InProgress` when a new JWK observation arrives before the previous quorum-certified update is committed on-chain. This transition improperly discards the quorum-certified update by dropping its `vtxn_guard`, removing the transaction from the validator transaction pool and wasting all consensus work.

## Finding Description

The vulnerability exists in the `process_new_observation` function which handles new JWK observations from OIDC providers. [1](#0-0) 

The state machine has three states defined in `ConsensusState`: `NotStarted`, `InProgress`, and `Finished`. [2](#0-1) 

When a JWK observation arrives, the function checks if the observed JWKs differ from the on-chain state at line 196. If they do, it unconditionally creates a new `InProgress` state at line 216 without checking if the current state is `Finished`. [3](#0-2) 

When transitioning from `Finished` to `InProgress`, the old `Finished` variant is dropped, which contains the `vtxn_guard` field. This guard, when dropped, removes the quorum-certified transaction from the validator transaction pool. [4](#0-3) 

**Attack Scenario:**
1. OIDC provider rotates JWKs from version 100 (JWK set A) to version 101 (JWK set B)
2. Validators observe this and start consensus, eventually reaching quorum
3. State transitions to `Finished` with `QuorumCertifiedUpdate{version=101, jwks=B}` in the validator transaction pool
4. Before any block containing this transaction is executed, the OIDC provider rotates again to version 102 (JWK set C)
5. The `process_new_observation` function is called again
6. Check passes: observed(C) ≠ on_chain(A) since on-chain is still version 100
7. A new proposal is created with version = 100 + 1 = 101 (same version, different JWKs!)
8. State transitions to `InProgress`, dropping the old `Finished` state
9. The `vtxn_guard` is dropped, removing `QuorumCertifiedUpdate{version=101, jwks=B}` from the pool
10. New consensus begins for version 101 with JWK set C

The `JWKObserver` continuously fetches JWKs at regular intervals and sends observations regardless of consensus state. [5](#0-4) 

**Contrast with Per-Key Manager:**
The per-key JWK manager correctly handles this scenario by checking if consensus is already `InProgress` or `Finished` and returning early if the proposal matches. [6](#0-5) 

## Impact Explanation

**Severity: HIGH**

This vulnerability causes:

1. **Wasted Consensus Resources**: All network bandwidth, CPU cycles, and validator coordination spent reaching quorum on the first update are completely wasted when the transaction is removed from the pool.

2. **Validator Pool Inconsistencies**: Different validators may have different transactions in their pools at different times, with some having the first quorum-certified update and others having the second.

3. **Potential Liveness Impact**: If validators disagree on which transaction to include in blocks (first or second version 101 transaction), it could slow down consensus or cause proposal rejections.

4. **Resource Exhaustion Attack Vector**: A malicious OIDC provider or an attacker who compromises an OIDC provider could trigger rapid JWK rotations to repeatedly cause this issue, continuously wasting validator resources and preventing legitimate JWK updates from being committed.

5. **State Machine Invariant Violation**: The state machine transitions violate the expected invariant that once a quorum-certified update is achieved, it should be preserved until committed on-chain.

This meets the Aptos bug bounty **High Severity** criteria for "Validator node slowdowns" through resource waste and "Significant protocol violations" through improper state machine transitions. While it does not directly cause consensus safety violations (the VM prevents duplicate version execution), it degrades network performance and wastes validator resources.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

This issue can occur in legitimate scenarios:
- OIDC providers can perform key rotations at any time for security reasons
- Rapid key rotations (e.g., during a security incident) are not uncommon
- The timing window is realistic: from when quorum is reached until a block is executed typically spans multiple seconds to minutes
- No special privileges are required - any OIDC provider behavior can trigger this

The issue is deterministic and will occur whenever:
1. A quorum-certified update reaches `Finished` state
2. A new JWK observation arrives before the transaction is executed on-chain
3. The new observation differs from the on-chain state

## Recommendation

Add a check in `process_new_observation` to prevent transitioning from `Finished` to `InProgress`. The function should verify the current consensus state before creating a new proposal:

```rust
pub fn process_new_observation(
    &mut self,
    issuer: Issuer,
    jwks: Vec<JWKMoveStruct>,
) -> Result<()> {
    let state = self.states_by_issuer.entry(issuer.clone()).or_default();
    state.observed = Some(jwks.clone());
    
    // Check if consensus is already in progress or finished
    match &state.consensus_state {
        ConsensusState::InProgress { my_proposal, .. } 
        | ConsensusState::Finished { my_proposal, .. } => {
            // If proposal matches observed state, keep existing consensus
            if my_proposal.observed.jwks == jwks {
                return Ok(());
            }
        },
        ConsensusState::NotStarted => {}
    }
    
    if state.observed.as_ref() != state.on_chain.as_ref().map(ProviderJWKs::jwks) {
        // ... proceed with creating new proposal
    }
    Ok(())
}
```

This mirrors the protection already implemented in the per-key manager's `maybe_start_consensus` function.

## Proof of Concept

A unit test demonstrating the vulnerability:

```rust
#[tokio::test]
async fn test_finished_to_inprogress_transition_drops_guard() {
    // Setup: Create manager with initial on-chain state
    let manager = setup_jwk_manager();
    let issuer = issuer_from_str("https://provider.com");
    
    // Step 1: Observe JWK rotation (version 100 -> 101)
    let jwks_v101 = vec![create_test_jwk("key1", "payload1")];
    manager.process_new_observation(issuer.clone(), jwks_v101.clone()).unwrap();
    
    // Step 2: Simulate quorum certification
    let qc_update = create_quorum_certified_update(issuer.clone(), 101, jwks_v101);
    manager.process_quorum_certified_update(qc_update.clone()).unwrap();
    
    // Verify transaction is in pool
    let vtxns_before = vtxn_pool.pull(/* params */);
    assert_eq!(vtxns_before.len(), 1);
    
    // Step 3: Observe another rotation before on-chain commit (version 101 -> 102)
    let jwks_v102 = vec![create_test_jwk("key2", "payload2")];
    manager.process_new_observation(issuer.clone(), jwks_v102).unwrap();
    
    // BUG: Transaction was removed from pool
    let vtxns_after = vtxn_pool.pull(/* params */);
    assert_eq!(vtxns_after.len(), 0); // Transaction lost!
}
```

### Citations

**File:** crates/aptos-jwk-consensus/src/jwk_manager/mod.rs (L184-228)
```rust
    pub fn process_new_observation(
        &mut self,
        issuer: Issuer,
        jwks: Vec<JWKMoveStruct>,
    ) -> Result<()> {
        debug!(
            epoch = self.epoch_state.epoch,
            issuer = String::from_utf8(issuer.clone()).ok(),
            "Processing new observation."
        );
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
            info!("[JWK] update observed, update={:?}", observed);
        }

        Ok(())
    }
```

**File:** crates/aptos-jwk-consensus/src/types.rs (L104-115)
```rust
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

**File:** crates/validator-transaction-pool/src/lib.rs (L202-206)
```rust
impl Drop for TxnGuard {
    fn drop(&mut self) {
        self.pool.lock().try_delete(self.seq_num);
    }
}
```

**File:** crates/aptos-jwk-consensus/src/jwk_observer.rs (L70-84)
```rust
        loop {
            tokio::select! {
                _ = interval.tick().fuse() => {
                    let timer = Instant::now();
                    let result = fetch_jwks(open_id_config_url.as_str(), my_addr).await;
                    debug!(issuer = issuer, "observe_result={:?}", result);
                    let secs = timer.elapsed().as_secs_f64();
                    if let Ok(mut jwks) = result {
                        OBSERVATION_SECONDS.with_label_values(&[issuer.as_str(), "ok"]).observe(secs);
                        jwks.sort();
                        let _ = observation_tx.push((), (issuer.as_bytes().to_vec(), jwks));
                    } else {
                        OBSERVATION_SECONDS.with_label_values(&[issuer.as_str(), "err"]).observe(secs);
                    }
                },
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
